//! Shared control logic for attaching to a game and managing the DLL.
//!
//! Both the GUI (`TrainlabApp`) and the MCP server (`TrainlabMcpServer`) drive
//! the same setup loop — find the game, inject the DLL, connect to its
//! listener, ping it — so an LLM can do the whole attach/connect flow remotely
//! (Steam Deck / Steam machine use case). This module centralizes that logic
//! and the low-level framed request/response over the DLL fast channel.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::oneshot;

use trainlab_core::protocol::{self, Event, Message, Request, Response};

use crate::session::SharedSession;

static NEXT_SEQ: AtomicU64 = AtomicU64::new(1);

/// A thread-safe handle to the single persistent multiplexed IPC client.
#[derive(Clone)]
pub struct IpcClient {
    tx: std::sync::mpsc::Sender<(u64, Request, oneshot::Sender<Response>)>,
    event_tx: std::sync::mpsc::Sender<Event>,
}

static GLOBAL_CLIENT: Mutex<Option<(String, u16, IpcClient)>> = Mutex::new(None);

impl IpcClient {
    pub fn connect(
        host: String,
        port: u16,
        session: Option<SharedSession>,
    ) -> Result<Self, String> {
        use std::collections::HashMap;
        use std::io::{Read, Write};
        use std::net::ToSocketAddrs;

        let (tx, rx) = std::sync::mpsc::channel::<(u64, Request, oneshot::Sender<Response>)>();
        let (evt_tx, evt_rx) = std::sync::mpsc::channel::<Event>();
        let target_addr = format!("{host}:{port}");

        // If a session was provided, spawn an autonomous outbound bus subscriber
        // to forward CheatUpdated / Sync events and respond to OverlayReady
        if let Some(s) = &session {
            let session_clone = s.clone();
            let evt_tx_clone = evt_tx.clone();
            let mut bus_rx = if let Ok(s_guard) = s.lock() {
                s_guard.event_bus().subscribe()
            } else {
                return Err("session lock poisoned".into());
            };

            std::thread::Builder::new()
                .name("trainlab-ipc-bus-forwarder".into())
                .spawn(move || {
                    while let Ok(bus_event) = bus_rx.blocking_recv() {
                        match bus_event {
                            trainlab_core::event::BusEvent::Protocol(Event::OverlayReady) => {
                                // Overlay signaled readiness: REST-style push initial complete cheat set
                                let cheats = if let Ok(s_guard) = session_clone.lock() {
                                    s_guard.export_overlay_cheats()
                                } else {
                                    Vec::new()
                                };
                                let _ = evt_tx_clone.send(Event::SyncCheats { cheats });
                            }
                            trainlab_core::event::BusEvent::Session(
                                trainlab_core::event::SessionEvent::CheatUpdated { .. },
                            ) => {
                                // Incremental sync whenever cheats change
                                let cheats = if let Ok(s_guard) = session_clone.lock() {
                                    s_guard.export_overlay_cheats()
                                } else {
                                    Vec::new()
                                };
                                let _ = evt_tx_clone.send(Event::SyncCheats { cheats });
                            }
                            _ => {}
                        }
                    }
                })
                .ok();
        }

        // Spawn dedicated background socket supervisor and multiplexer thread
        std::thread::Builder::new()
            .name("trainlab-ipc-multiplexer".into())
            .spawn(move || {
                let mut pending_responses: HashMap<u64, oneshot::Sender<Response>> = HashMap::new();

                loop {
                    // Connect / Reconnect socket
                    let mut stream = match target_addr.to_socket_addrs() {
                        Ok(mut addrs) => {
                            if let Some(sock_addr) = addrs.next() {
                                match std::net::TcpStream::connect_timeout(
                                    &sock_addr,
                                    Duration::from_millis(1000),
                                ) {
                                    Ok(s) => s,
                                    Err(_) => {
                                        std::thread::sleep(Duration::from_millis(200));
                                        continue;
                                    }
                                }
                            } else {
                                std::thread::sleep(Duration::from_millis(500));
                                continue;
                            }
                        }
                        Err(_) => {
                            std::thread::sleep(Duration::from_millis(500));
                            continue;
                        }
                    };

                    let _ = stream.set_nodelay(true);
                    let mut reader_stream = match stream.try_clone() {
                        Ok(s) => s,
                        Err(_) => continue,
                    };

                    // Channel to receive frames from the inbound reader thread
                    let (inbound_tx, inbound_rx) = std::sync::mpsc::channel::<Message>();

                    // Spawn dedicated inbound reader thread on this TCP connection
                    let session_for_inbound = session.clone();
                    std::thread::Builder::new()
                        .name("trainlab-ipc-inbound".into())
                        .spawn(move || {
                            while let Ok(len_buf) = read_exact_array::<4>(&mut reader_stream) {
                                let len = u32::from_le_bytes(len_buf) as usize;
                                if len == 0 || len > 64 * 1024 * 1024 {
                                    break;
                                }
                                let mut body = vec![0u8; len];
                                if reader_stream.read_exact(&mut body).is_err() {
                                    break;
                                }
                                let mut full = Vec::with_capacity(4 + len);
                                full.extend_from_slice(&len_buf);
                                full.extend_from_slice(&body);
                                if let Ok(msg) = protocol::decode::<Message>(&full) {
                                    match msg {
                                        Message::Event(evt) => {
                                            // Publish directly onto the Session EventBus
                                            if let Some(s) = &session_for_inbound
                                                && let Ok(s_guard) = s.lock()
                                            {
                                                s_guard.publish_event(
                                                    trainlab_core::event::BusEvent::Protocol(evt),
                                                );
                                            }
                                        }
                                        Message::Response { .. }
                                            if inbound_tx.send(msg).is_err() =>
                                        {
                                            break;
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        })
                        .ok();

                    // Main write & dispatch loop for this active stream
                    'stream_loop: loop {
                        // 1. Drain and write any pending outbound events (from GUI -> DLL)
                        while let Ok(evt) = evt_rx.try_recv() {
                            let evt_msg = Message::Event(evt);
                            if let Ok(frame) = protocol::encode(&evt_msg)
                                && stream.write_all(&frame).is_err()
                            {
                                break 'stream_loop;
                            }
                        }

                        // 2. Process correlated responses from reader thread
                        while let Ok(msg) = inbound_rx.try_recv() {
                            if let Message::Response { id, resp } = msg
                                && let Some(sender) = pending_responses.remove(&id)
                            {
                                let _ = sender.send(resp);
                            }
                        }

                        // 3. Receive outbound requests with non-blocking try_recv / short timeout
                        match rx.recv_timeout(Duration::from_millis(10)) {
                            Ok((id, req, resp_tx)) => {
                                pending_responses.insert(id, resp_tx);
                                let msg = Message::Request { id, req };
                                if let Ok(frame) = protocol::encode(&msg) {
                                    if stream.write_all(&frame).is_err() {
                                        if let Some(sender) = pending_responses.remove(&id) {
                                            let _ = sender.send(Response::Error {
                                                message: "IPC write failed".into(),
                                            });
                                        }
                                        break 'stream_loop;
                                    }
                                } else if let Some(sender) = pending_responses.remove(&id) {
                                    let _ = sender.send(Response::Error {
                                        message: "protocol encode error".into(),
                                    });
                                }
                            }
                            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                                // Channel dropped, shut down
                                return;
                            }
                        }
                    }

                    // On stream disconnect, fail remaining pending responses
                    for (_, sender) in pending_responses.drain() {
                        let _ = sender.send(Response::Error {
                            message: "IPC socket disconnected".into(),
                        });
                    }
                }
            })
            .map_err(|e| format!("failed to spawn IPC multiplexer thread: {e}"))?;

        Ok(Self {
            tx,
            event_tx: evt_tx,
        })
    }

    pub fn request(&self, req: Request) -> Result<Response, String> {
        let seq = NEXT_SEQ.fetch_add(1, Ordering::Relaxed);
        let (resp_tx, mut resp_rx) = oneshot::channel();
        self.tx
            .send((seq, req, resp_tx))
            .map_err(|e| format!("IPC mailbox send failed: {e}"))?;

        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_millis(2500) {
            match resp_rx.try_recv() {
                Ok(resp) => return Ok(resp),
                Err(oneshot::error::TryRecvError::Empty) => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(oneshot::error::TryRecvError::Closed) => {
                    return Err("IPC channel closed".into());
                }
            }
        }
        Err("IPC request timed out".into())
    }

    pub fn emit_event(&self, event: Event) {
        let _ = self.event_tx.send(event);
    }
}

fn read_exact_array<const N: usize>(stream: &mut std::net::TcpStream) -> std::io::Result<[u8; N]> {
    use std::io::Read;
    let mut buf = [0u8; N];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

/// Send a request to the DLL listener at `(host, port)` via the single multiplexed channel.
pub fn request_at(
    host: &str,
    port: u16,
    req: &Request,
    session: Option<&SharedSession>,
) -> Result<Response, String> {
    let mut lock = GLOBAL_CLIENT.lock().unwrap();
    let client = match &*lock {
        Some((h, p, c)) if h == host && *p == port => c.clone(),
        _ => {
            let c = IpcClient::connect(host.to_string(), port, session.cloned())?;
            *lock = Some((host.to_string(), port, c.clone()));
            c
        }
    };
    drop(lock);
    client.request(req.clone())
}

/// Broadcast an Event to the DLL listener.
pub fn emit_event_to_dll(session: &SharedSession, event: Event) {
    let (host, port) = {
        if let Ok(s) = session.lock() {
            (s.dll_host().to_string(), s.dll_port())
        } else {
            return;
        }
    };
    let lock = GLOBAL_CLIENT.lock().unwrap();
    if let Some((h, p, c)) = &*lock
        && h == &host
        && *p == port
    {
        c.emit_event(event);
    }
}

/// Send a request to the DLL using the session's configured host/port.
pub fn request(session: &SharedSession, req: &Request) -> Result<Response, String> {
    let (host, port) = {
        let s = session
            .lock()
            .map_err(|_| "session lock poisoned".to_string())?;
        (s.dll_host().to_string(), s.dll_port())
    };
    request_at(&host, port, req, Some(session))
}

/// Ping the DLL at the given host/port. Returns the reported version and capabilities.
pub fn ping_at(
    host: &str,
    port: u16,
    session: Option<&SharedSession>,
) -> Result<(String, Vec<String>), String> {
    match request_at(host, port, &Request::Ping, session) {
        Ok(Response::Pong {
            version,
            capabilities,
        }) => {
            if let Some(s) = session
                && let Ok(mut s_guard) = s.lock()
            {
                s_guard.set_dll_capabilities(capabilities.clone());
            }
            Ok((version, capabilities))
        }
        Ok(Response::Error { message }) => Err(message),
        Ok(_) => Err("unexpected ping response".into()),
        Err(e) => Err(e),
    }
}

/// Ping the DLL using the session's host/port, updating connection state.
pub fn check_connection(session: &SharedSession) -> Result<String, String> {
    apply_defaults(session);
    let (host, port) = {
        let s = session
            .lock()
            .map_err(|_| "session lock poisoned".to_string())?;
        (s.dll_host().to_string(), s.dll_port())
    };
    match ping_at(&host, port, Some(session)) {
        Ok((v, caps)) => {
            if let Ok(mut s) = session.lock() {
                s.set_connected(true);
                s.set_inject_version(Some(v.clone()));
                s.set_dll_capabilities(caps);
            }
            Ok(v)
        }
        Err(e) => {
            if let Ok(mut s) = session.lock() {
                s.set_connected(false);
            }
            Err(e)
        }
    }
}

/// Set default host/port on the session if not already populated.
fn apply_defaults(session: &SharedSession) {
    if let Ok(mut s) = session.lock() {
        if s.dll_host().is_empty() {
            s.set_dll_host("127.0.0.1");
        }
        if s.dll_port() == 0 {
            s.set_dll_port(31337);
        }
    }
}

/// Disconnect the current session and clear stored connection state.
pub fn disconnect(session: &SharedSession) {
    if let Ok(mut s) = session.lock() {
        s.set_connected(false);
        s.set_game_pid(None);
    }
}

/// Scan for a running game matching `session.game_name()`, inject the DLL,
/// and connect to its listener. Returns the reported inject version.
pub fn find_inject_connect(session: &SharedSession) -> Result<String, String> {
    apply_defaults(session);
    let game_name = {
        let s = session
            .lock()
            .map_err(|_| "session lock poisoned".to_string())?;
        s.game_name().to_string()
    };
    if game_name.is_empty() {
        return Err("no game executable specified".into());
    }

    let pid = crate::inject::find_game(&game_name)
        .ok_or_else(|| format!("process '{game_name}' not found — is the game running?"))?;

    let dll_path = {
        let s = session
            .lock()
            .map_err(|_| "session lock poisoned".to_string())?;
        s.dll_path().to_string()
    };
    if dll_path.is_empty() {
        return Err("no DLL path specified".into());
    }

    crate::inject::inject_dll(pid, &dll_path)?;

    if let Ok(mut s) = session.lock() {
        s.set_game_pid(Some(pid));
    }

    let mut last_err = "DLL listener did not respond in time".to_string();
    for _ in 0..15 {
        std::thread::sleep(Duration::from_millis(150));
        match check_connection(session) {
            Ok(v) => {
                // Sync initial cheats snapshot immediately upon connect
                let cheats_dto = if let Ok(s) = session.lock() {
                    s.export_overlay_cheats()
                } else {
                    Vec::new()
                };
                let _ = request(session, &Request::SyncCheats { cheats: cheats_dto });
                return Ok(v);
            }
            Err(e) => last_err = e,
        }
    }

    Err(format!(
        "injection succeeded but connection failed: {last_err}"
    ))
}

/// Resolve the DLL path from relative name or standard fallback.
pub fn resolve_dll_path(input: &str) -> String {
    let has_sep = input.contains('/') || input.contains('\\');
    if has_sep {
        return input.to_string();
    }
    match std::env::current_exe() {
        Ok(exe) => match exe.parent() {
            Some(dir) => {
                if input == "trainlab_inject.dll" && dir.join("trainlab.dll").exists() {
                    dir.join("trainlab.dll").to_string_lossy().into_owned()
                } else {
                    dir.join(input).to_string_lossy().into_owned()
                }
            }
            None => input.to_string(),
        },
        Err(_) => input.to_string(),
    }
}

/// Perform the complete attach, inject, feature handshake, profile discovery/load,
/// and cheat synchronization pipeline. Shared across GUI, MCP, REST API, and auto-attach.
pub fn attach_and_initialize(
    session: &SharedSession,
    game_override: Option<&str>,
    auto_init: bool,
    source: &str,
) -> Result<String, String> {
    apply_defaults(session);

    // 1. Resolve game executable name
    let game_name = if let Some(g) = game_override {
        let trimmed = g.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    } else {
        None
    };

    let game_name = match game_name {
        Some(g) => g,
        None => {
            let cur = session
                .lock()
                .map_err(|_| "session lock poisoned".to_string())?
                .game_name()
                .to_string();
            if !cur.is_empty() {
                cur
            } else {
                let candidates = crate::inject::find_game_candidates();
                let profiles = crate::profile::discover_profiles();
                let mut detected = None;
                for cand in &candidates {
                    if let Some((_file, _p)) = crate::profile::find_profile_for_game(&profiles, &cand.name) {
                        detected = Some(cand.name.clone());
                        break;
                    }
                }
                if detected.is_none() && !candidates.is_empty() {
                    detected = Some(candidates[0].name.clone());
                }
                detected.ok_or_else(|| {
                    "no game executable specified and no running game candidate detected".to_string()
                })?
            }
        }
    };

    if let Ok(mut s) = session.lock() {
        s.set_game_name(game_name.clone());
        let current_dll = s.dll_path().to_string();
        if current_dll.is_empty() || current_dll == "trainlab_inject.dll" {
            let resolved = resolve_dll_path("trainlab_inject.dll");
            s.set_dll_path(resolved);
        } else {
            let resolved = resolve_dll_path(&current_dll);
            s.set_dll_path(resolved);
        }
        s.log_activity(source, format!("attaching and injecting into '{game_name}'..."));
    }

    // 2. Perform find & inject & TCP connect
    let version = find_inject_connect(session)?;

    if let Ok(mut s) = session.lock() {
        let attached_pid = s.game_pid();
        s.record_tracked_app(&game_name, attached_pid, None);
        s.log_activity(
            source,
            format!("connected, inject v{version} — initializing DLL via IPC..."),
        );
    }

    // 3. Auto-discover profile and prepare features handshake
    let mut matched_profile = None;
    if auto_init {
        let all_discovered = crate::profile::discover_all_profiles();
        for dp in &all_discovered {
            match dp {
                crate::profile::DiscoveredProfile::Valid { file, profile } => {
                    if profile.game.eq_ignore_ascii_case(&game_name) {
                        matched_profile = Some((file.clone(), profile.clone()));
                        break;
                    }
                }
                crate::profile::DiscoveredProfile::Invalid { file, error } => {
                    if file
                        .to_lowercase()
                        .contains(&game_name.to_lowercase().replace(".exe", ""))
                        && let Ok(mut s) = session.lock()
                    {
                        s.log_activity(
                            "PROFILE",
                            format!(
                                "WARNING: candidate profile '{file}' for '{game_name}' FAILED to parse: {error}"
                            ),
                        );
                    }
                }
            }
        }
    }

    let app_cfg = crate::config::AppConfig::load();
    let mut features = app_cfg.inject_features.clone();
    let dll_port = app_cfg.inject.dll_port;
    let mcp_port = app_cfg.server.mcp_port;
    if !features.network.ignore_ports.contains(&dll_port) {
        features.network.ignore_ports.push(dll_port);
    }
    if !features.network.ignore_ports.contains(&mcp_port) {
        features.network.ignore_ports.push(mcp_port);
    }

    if let Some((_, prof)) = &matched_profile {
        if let Some(render_cfg) = &prof.render {
            if let Ok(mut s) = session.lock() {
                s.log_activity(
                    source,
                    format!(
                        "RENDER: profile render block OVERRIDES app config — overlay={}, wndproc={}, xinput={} (profile values; app config ignored)",
                        render_cfg.overlay, render_cfg.hook_wndproc, render_cfg.xinput_hooks,
                    ),
                );
            }
            features.display.overlay = render_cfg.overlay;
            features.input.wndproc = render_cfg.hook_wndproc;
            features.input.xinput = render_cfg.xinput_hooks;
        }
        if let Some(net_cfg) = &prof.network {
            if let Some(en) = net_cfg.enabled {
                if !en {
                    features.network.winsock = false;
                    features.network.winhttp = false;
                    features.network.schannel = false;
                    features.network.steamworks = false;
                } else {
                    // Profile explicitly opted into network capture: enable requested hooks or default to true
                    features.network.winsock = net_cfg.winsock.unwrap_or(true);
                    features.network.winhttp = net_cfg.winhttp.unwrap_or(true);
                    features.network.schannel = net_cfg.schannel.unwrap_or(true);
                    features.network.steamworks = net_cfg.steamworks.unwrap_or(true);
                }
            }
            if let Some(ws) = net_cfg.winsock {
                features.network.winsock = ws;
            }
            if let Some(wh) = net_cfg.winhttp {
                features.network.winhttp = wh;
            }
            if let Some(sc) = net_cfg.schannel {
                features.network.schannel = sc;
            }
            if let Some(sw) = net_cfg.steamworks {
                features.network.steamworks = sw;
            }
            for p in &net_cfg.ignore_ports {
                if !features.network.ignore_ports.contains(p) {
                    features.network.ignore_ports.push(*p);
                }
            }
            for h in &net_cfg.ignore_hosts {
                if !features.network.ignore_hosts.contains(h) {
                    features.network.ignore_hosts.push(h.clone());
                }
            }
            if let Some(loopback) = net_cfg.capture_loopback {
                features.network.capture_loopback = loopback;
            }
        }
    }

    if let Ok(mut s) = session.lock() {
        s.log_activity(
            "NETWORK",
            format!(
                "Handshake features: winsock={}, winhttp={}, schannel={}, steamworks={}, ignore_ports={:?}, ignore_hosts={:?}",
                features.network.winsock,
                features.network.winhttp,
                features.network.schannel,
                features.network.steamworks,
                features.network.ignore_ports,
                features.network.ignore_hosts
            ),
        );
    }

    match request(session, &Request::InitializeSession { features }) {
        Ok(Response::SessionReady {
            capabilities,
            diagnostics,
        }) => {
            if let Ok(mut s) = session.lock() {
                s.set_dll_capabilities(capabilities.clone());
                s.set_network_hooks_enabled(
                    capabilities.contains(&"network_capture".to_string()),
                );
                s.log_activity(
                    source,
                    format!(
                        "DLL session initialized on {} ({}) | Input: {} | Active capabilities: [{}]",
                        diagnostics.target_os,
                        diagnostics.graphics_api,
                        diagnostics.input_subsystem,
                        capabilities.join(", ")
                    ),
                );
                if !diagnostics.detected_overlays.is_empty() {
                    s.log_activity(
                        source,
                        format!(
                            "Detected in-game overlays: {:?}",
                            diagnostics.detected_overlays
                        ),
                    );
                }
                if !diagnostics.loaded_network_modules.is_empty() {
                    s.log_activity(
                        source,
                        format!(
                            "Loaded game network modules: {:?}",
                            diagnostics.loaded_network_modules
                        ),
                    );
                }
            }

            if let Some((file, _)) = matched_profile {
                if let Ok(mut s) = session.lock() {
                    s.log_activity(
                        source,
                        format!("starting sequential profile initialization for '{file}'..."),
                    );
                }
                match crate::mcp::TrainlabMcpServer::with_session(session.clone())
                    .load_profile_by_name(&file, true)
                {
                    Ok(detail) => {
                        if let Ok(mut s) = session.lock() {
                            s.log_activity(source, format!("profile '{file}' loaded: {detail}"));
                        }
                    }
                    Err(e) => {
                        if let Ok(mut s) = session.lock() {
                            s.log_activity(source, format!("profile '{file}' load FAILED: {e}"));
                        }
                    }
                }
            }
        }
        _ => {
            if let Ok(mut s) = session.lock() {
                s.log_activity(source, "DLL session initialization completed (default)");
            }
        }
    }

    Ok(version)
}

/// Background worker that periodically polls for a target game process,
/// then automatically attaches, injects, and initializes.
pub fn spawn_auto_attach_worker(
    session: SharedSession,
    egui_ctx: Option<eframe::egui::Context>,
    target_game: Option<String>,
) {
    std::thread::Builder::new()
        .name("trainlab-auto-attach".into())
        .spawn(move || {
            tracing::info!(
                "Auto-attach worker started. Polling for target game process (target={:?})...",
                target_game
            );
            let start = std::time::Instant::now();
            let timeout = Duration::from_secs(90);

            // Brief initial pause to let process launch start
            std::thread::sleep(Duration::from_millis(1500));

            while start.elapsed() < timeout {
                if let Ok(s) = session.lock() {
                    if s.connected() {
                        tracing::info!("Auto-attach: session already connected, worker exiting.");
                        return;
                    }
                }

                let target = target_game.as_deref();
                match attach_and_initialize(&session, target, true, "AUTO-ATTACH") {
                    Ok(v) => {
                        tracing::info!("Auto-attach succeeded (inject v{v})!");
                        // Automatically background the trainer window now that injection, handshake,
                        // and profile cheats are loaded and primed.
                        if let Ok(mut s) = session.lock() {
                            s.request_window_cmd("hide");
                        }
                        // Assert foreground focus on the game window via the injected DLL
                        let _ = request(&session, &Request::FocusGameWindow);

                        if let Some(ctx) = &egui_ctx {
                            ctx.request_repaint();
                        }
                        return;
                    }
                    Err(e) => {
                        tracing::debug!("Auto-attach attempt: {e}");
                    }
                }

                std::thread::sleep(Duration::from_millis(1500));
            }
            tracing::warn!("Auto-attach worker timed out after 90 seconds.");
        })
        .ok();
}

