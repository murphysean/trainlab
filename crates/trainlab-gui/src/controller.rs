//! Shared control logic for attaching to a game and managing the DLL.
//!
//! Both the GUI (`TrainlabApp`) and the MCP server (`TrainlabMcpServer`) drive
//! the same setup loop — find the game, inject the DLL, connect to its
//! listener, ping it — so an LLM can do the whole attach/connect flow remotely
//! (Steam Deck / Steam machine use case). This module centralizes that logic
//! and the low-level framed request/response over the DLL fast channel.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
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
    pub fn connect(host: String, port: u16, session: Option<SharedSession>) -> Result<Self, String> {
        use std::io::{Read, Write};
        use std::net::ToSocketAddrs;
        use std::collections::HashMap;

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
                            trainlab_core::event::BusEvent::Session(trainlab_core::event::SessionEvent::CheatUpdated { .. }) => {
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
                                match std::net::TcpStream::connect_timeout(&sock_addr, Duration::from_millis(1000)) {
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
                                    match &msg {
                                        Message::Event(evt) => {
                                            // Publish directly onto the Session EventBus
                                            if let Some(s) = &session_for_inbound
                                                && let Ok(s_guard) = s.lock() {
                                                    s_guard.publish_event(trainlab_core::event::BusEvent::Protocol(evt.clone()));
                                                }
                                        }
                                        Message::Response { .. } => {
                                            if inbound_tx.send(msg).is_err() {
                                                break;
                                            }
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
                                && stream.write_all(&frame).is_err() {
                                    break 'stream_loop;
                                }
                        }

                        // 2. Process correlated responses from reader thread
                        while let Ok(msg) = inbound_rx.try_recv() {
                            if let Message::Response { id, resp } = msg
                                && let Some(sender) = pending_responses.remove(&id) {
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
                                            let _ = sender.send(Response::Error { message: "IPC write failed".into() });
                                        }
                                        break 'stream_loop;
                                    }
                                } else if let Some(sender) = pending_responses.remove(&id) {
                                    let _ = sender.send(Response::Error { message: "protocol encode error".into() });
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
                        let _ = sender.send(Response::Error { message: "IPC socket disconnected".into() });
                    }
                }
            })
            .map_err(|e| format!("failed to spawn IPC multiplexer thread: {e}"))?;

        Ok(Self { tx, event_tx: evt_tx })
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
pub fn request_at(host: &str, port: u16, req: &Request, session: Option<&SharedSession>) -> Result<Response, String> {
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
        && h == &host && *p == port {
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

/// Ping the DLL at the given host/port. Returns the reported version.
pub fn ping_at(host: &str, port: u16, session: Option<&SharedSession>) -> Result<String, String> {
    match request_at(host, port, &Request::Ping, session) {
        Ok(Response::Pong { version }) => Ok(version),
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
        Ok(v) => {
            if let Ok(mut s) = session.lock() {
                s.set_connected(true);
                s.set_inject_version(Some(v.clone()));
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

    Err(format!("injection succeeded but connection failed: {last_err}"))
}
