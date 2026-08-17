// Produce a GUI-subsystem Windows PE so no console window is spawned when the
// trainer runs under Wine/Proton (a console-subsystem exe gets a conhost window).
#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

//! # trainlab-gui
//!
//! A desktop GUI (built with `egui`/`eframe`) that connects to the injected
//! DLL and lets you:
//!
//! - Connect to a running `trainlab-inject` listener.
//! - Ping it to confirm it's alive.
//! - Read / write memory at arbitrary addresses.
//! - Run AOB pattern scans.
//! - Allocate / free code caves.
//! - List memory regions.
//!
//! This is the "control room" for your training sessions.

use eframe::egui;
use trainlab_core::protocol::{Request, Response};

use crate::session::{Cheat, CheatKind, SharedSession, SessionState};

mod mcp;
mod controller;
mod inject;
mod profile;
mod session;

fn main() -> eframe::Result<()> {
    tracing_subscriber::fmt::init();

    // One shared session state across the GUI and the MCP server. The GUI sets
    // `game_pid` when it injects the game; the MCP server reads it to open the
    // game process externally for scan-family tools (see D7).
    let session: SharedSession = std::sync::Arc::new(std::sync::Mutex::new(SessionState::new()));

    // Start the MCP server on a background tokio runtime. The GUI owns the
    // control flow; the MCP server runs alongside it so an agent can connect.
    // Bind to all interfaces (0.0.0.0) so a laptop/desktop can reach the
    // trainer over the network (e.g. Steam Deck / Steam machine use case).
    let mcp_host = std::env::var("TRAINLAB_MCP_HOST").unwrap_or_else(|_| "0.0.0.0".into());
    // Port for the MCP server, overridable via TRAINLAB_MCP_PORT.
    let mcp_port = std::env::var("TRAINLAB_MCP_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(MCP_DEFAULT_PORT);
    let mcp_session = session.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build MCP tokio runtime");
        rt.block_on(async {
            match mcp::serve(&mcp_host, mcp_port, mcp_session).await {
                Ok((url, ct)) => {
                    tracing::info!(%url, "MCP server ready");
                    // Keep the runtime alive until the process exits. `serve`
                    // returns immediately after spawning the axum task, so we
                    // must not let the runtime drop (which would kill the task).
                    ct.cancelled().await;
                }
                Err(e) => tracing::error!("failed to start MCP server: {e}"),
            }
        });
    });

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([900.0, 640.0]),
        ..Default::default()
    };
    eframe::run_native(
        "trainlab",
        options,
        Box::new(move |_cc| Box::new(TrainlabApp::with_session(session))),
    )
}

/// Default port for the MCP server.
const MCP_DEFAULT_PORT: u16 = 8123;

/// A single memory read/write operation shown in the UI.
#[derive(Default, Clone)]
struct MemOp {
    address: String,
    value: String,
    result: String,
}

/// A single AOB scan shown in the UI.
#[derive(Default, Clone)]
struct AobScan {
    pattern: String,
    result: String,
}

struct TrainlabApp {
    // Shared session state (game pid, markers, scan). Set by the GUI, read by
    // the MCP server.
    session: SharedSession,

    // Connection
    host: String,
    port: String,
    connected: bool,
    status: String,

    // Injection
    game_name: String,
    dll_path: String,
    game_candidates: Vec<inject::ProcessInfo>,

    // MCP server
    mcp_addr: String,

    // Panels
    mem_ops: Vec<MemOp>,
    aob_scans: Vec<AobScan>,
    regions: Vec<trainlab_core::protocol::RegionInfo>,
    log: Vec<String>,

    // Cheats panel: editable value strings keyed by cheat id, and a flag to
    // show the panel.
    cheat_values: std::collections::HashMap<u64, String>,
    show_cheats: bool,
}

impl Default for TrainlabApp {
    fn default() -> Self {
        Self::new(std::sync::Arc::new(std::sync::Mutex::new(SessionState::new())))
    }
}

impl TrainlabApp {
    fn new(session: SharedSession) -> Self {
        // The game executable to inject into. Overridable via TRAINLAB_GAME so
        // the trainer can target any game without recompiling (e.g. Unrailed2).
        let game_name = std::env::var("TRAINLAB_GAME").unwrap_or_else(|_| "Urbek.exe".into());
        Self {
            session,
            host: "127.0.0.1".into(),
            port: "31337".into(),
            connected: false,
            status: "not connected".into(),
            game_name,
            dll_path: "trainlab_inject.dll".into(),
            game_candidates: Vec::new(),
            mcp_addr: format!("127.0.0.1:{MCP_DEFAULT_PORT}"),
            mem_ops: vec![MemOp::default()],
            aob_scans: vec![AobScan::default()],
            regions: Vec::new(),
            log: Vec::new(),
            cheat_values: std::collections::HashMap::new(),
            show_cheats: true,
        }
    }

    /// Create the app with a fresh shared session (used by tests / defaults).
    fn with_session(session: SharedSession) -> Self {
        Self::new(session)
    }

    fn log(&mut self, msg: impl Into<String>) {
        self.log.push(msg.into());
        if self.log.len() > 500 {
            self.log.remove(0);
        }
    }

    /// Refresh the list of likely game processes for the dropdown.
    fn refresh_game_candidates(&mut self) {
        self.game_candidates = inject::find_game_candidates();
        self.log(format!(
            "found {} game candidate(s)",
            self.game_candidates.len()
        ));
    }

    /// Sync the GUI's editable connection fields into the shared session so
    /// the controller and MCP server use the same host/port/game/dll.
    fn sync_session(&self) {
        if let Ok(mut s) = self.session.lock() {
            s.set_dll_host(self.host.clone());
            s.set_dll_port(self.port.parse().unwrap_or(31337));
            s.set_game_name(self.game_name.clone());
            s.set_dll_path(self.dll_path.clone());
        }
    }

    /// Find the game process, inject the DLL, then connect to its listener.
    /// Routes through the shared controller so the MCP server can do the same
    /// flow remotely.
    fn inject_and_connect(&mut self) {
        self.sync_session();
        // Resolve the DLL path relative to this exe's directory so the DLL can
        // live side-by-side with the trainer.
        {
            let dll_path = resolve_dll_path(&self.dll_path);
            if let Ok(mut s) = self.session.lock() {
                s.set_dll_path(dll_path);
            }
        }
        match controller::find_inject_connect(&self.session) {
            Ok(version) => {
                self.log(format!("connected, inject v{version}"));
            }
            Err(e) => {
                self.log(format!("attach failed: {e}"));
                if let Ok(mut s) = self.session.lock() {
                    s.set_connected(false);
                }
            }
        }
    }

    /// Render the Session panel: markers, undo log, and pending (staged)
    /// mutations awaiting confirmation. This surfaces the state the agent
    /// manipulates via MCP, so the human can see and act on it.
    fn show_session_panel(&mut self, ui: &mut egui::Ui) {
        ui.heading("Session");
        // Snapshot session state to avoid holding the lock across UI.
        let (markers, undo, pending) = {
            let s = self.session.lock().unwrap();
            (
                s.list_markers().iter().map(|m| (m.label.clone(), m.address, m.note.clone())).collect::<Vec<_>>(),
                s.undo_len(),
                s.list_pending().iter().map(|p| (p.id, p.address, p.preview.clone())).collect::<Vec<_>>(),
            )
        };

        ui.horizontal(|ui| {
            ui.label(format!("{} marker(s)", markers.len()));
            ui.label(format!("{} undo entr(ies)", undo));
            ui.label(format!("{} pending op(s)", pending.len()));
        });

        if !markers.is_empty() {
            ui.separator();
            ui.label("Markers:");
            for (label, addr, note) in &markers {
                ui.horizontal(|ui| {
                    ui.label(format!("• {label} @ {addr:#x}"));
                    if let Some(n) = note {
                        ui.label(format!("({n})"));
                    }
                });
            }
        }

        if !pending.is_empty() {
            ui.separator();
            ui.label("Pending (staged) mutations — confirm or reject:");
            for (id, addr, preview) in &pending {
                ui.horizontal(|ui| {
                    ui.label(format!("[{id}] @ {addr:#x}"));
                    ui.label(preview);
                    if ui.button("Confirm").clicked() {
                        // Confirm applies the staged op (records undo).
                        let op = self.session.lock().unwrap().take_pending(*id);
                        if let Some(op) = op {
                            self.apply_pending(op);
                        }
                    }
                    if ui.button("Reject").clicked() {
                        self.session.lock().unwrap().take_pending(*id);
                        self.log(format!("rejected pending op {id}"));
                    }
                });
            }
        }
    }

    /// Apply a confirmed pending op: write bytes / install cave / undo.
    fn apply_pending(&mut self, op: session::PendingOp) {
        use session::PendingKind;
        match op.kind {
            PendingKind::Write { data } => {
                let r = self.request(&Request::Write { address: op.address, data });
                match r {
                    Some(Response::Write { bytes_written }) => {
                        self.log(format!("confirmed write @ {:#x} ({bytes_written} bytes)", op.address));
                    }
                    _ => self.log(format!("confirmed write @ {:#x} failed", op.address)),
                }
            }
            PendingKind::InstallCave { hook } => {
                let r = self.request(&Request::InstallCave { target: op.address, hook });
                match r {
                    Some(Response::CaveInstalled { cave, .. }) => {
                        self.log(format!("confirmed cave @ {:#x} (cave {cave:#x})", op.address));
                    }
                    _ => self.log(format!("confirmed cave @ {:#x} failed", op.address)),
                }
            }
            PendingKind::Undo { original_bytes } => {
                let r = self.request(&Request::Write { address: op.address, data: original_bytes });
                match r {
                    Some(Response::Write { bytes_written }) => {
                        self.log(format!("confirmed undo @ {:#x} ({bytes_written} bytes)", op.address));
                    }
                    _ => self.log(format!("confirmed undo @ {:#x} failed", op.address)),
                }
            }
        }
    }

    /// Send a request to the DLL and receive the response, or `None` on error.
    /// Routes through the shared controller.
    fn request(&mut self, req: &Request) -> Option<Response> {
        self.sync_session();
        match controller::request(&self.session, req) {
            Ok(r) => {
                if let Ok(mut s) = self.session.lock() {
                    s.set_connected(true);
                }
                Some(r)
            }
            Err(e) => {
                self.status = e;
                if let Ok(mut s) = self.session.lock() {
                    s.set_connected(false);
                }
                None
            }
        }
    }

    /// Render the Cheats panel: user-facing adjustable game options discovered
    /// by the agent. Value cheats show a live read + editable field + Apply;
    /// toggle cheats show an on/off switch.
    fn show_cheats_panel(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("Cheats");
            if ui.checkbox(&mut self.show_cheats, "show").changed() {
                // toggle panel visibility
            }
        });
        if !self.show_cheats {
            return;
        }
        ui.horizontal(|ui| {
            if ui.button("Clear all").clicked() {
                if let Ok(mut s) = self.session.lock() {
                    let ids: Vec<u64> = s.list_cheats().iter().map(|c| c.id).collect();
                    for id in ids {
                        s.remove_cheat(id);
                    }
                }
                self.cheat_values.clear();
            }
        });
        ui.separator();

        // Snapshot the cheats to avoid holding the lock across UI.
        let cheats: Vec<Cheat> = {
            let s = self.session.lock().unwrap();
            s.list_cheats().into_iter().cloned().collect()
        };

        if cheats.is_empty() {
            ui.label("No cheats yet. The agent adds them via 'add_cheat' (or set a marker).");
            return;
        }

        for cheat in &cheats {
            ui.horizontal(|ui| {
                match &cheat.kind {
                    CheatKind::Value { address, value_type } => {
                        // Live-read the current value.
                        let current = self
                            .request(&Request::Read {
                                address: *address,
                                len: value_type.size(),
                            })
                            .and_then(|r| match r {
                                Response::Read { data } => Some(data),
                                _ => None,
                            })
                            .map(|d| format_value(&d, *value_type))
                            .unwrap_or_else(|| "?".into());

                        ui.label(&cheat.label);
                        if let Some(n) = &cheat.note {
                            ui.label(format!("({n})"));
                        }
                        ui.label(format!("@ {address:#x}"));
                        ui.label(format!("now: {current}"));

                        // Editable field (persisted per cheat id).
                        let field = self
                            .cheat_values
                            .entry(cheat.id)
                            .or_insert_with(|| current.clone());
                        ui.text_edit_singleline(field);

                        if ui.button("Apply").clicked() {
                            // The user is the human confirmation: write directly.
                            let field_val = field.clone();
                            let data = parse_value_bytes(&field_val, *value_type);
                            match data {
                                Ok(bytes) => {
                                    let r = self.request(&Request::Write {
                                        address: *address,
                                        data: bytes,
                                    });
                                    match r {
                                        Some(Response::Write { bytes_written }) => {
                                            self.log(format!(
                                                "cheat '{}' set to {} ({bytes_written} bytes)",
                                                cheat.label, field_val
                                            ));
                                        }
                                        _ => self.log(format!(
                                            "cheat '{}' write failed",
                                            cheat.label
                                        )),
                                    }
                                }
                                Err(e) => self.log(format!("bad value for '{}': {e}", cheat.label)),
                            }
                        }
                    }
                    CheatKind::Toggle { target, enabled, .. } => {
                        let mut on = *enabled;
                        if ui.checkbox(&mut on, &cheat.label).changed() {
                            // Flip the toggle in the session; cave install/remove
                            // is handled by the agent via MCP (staged + confirmed).
                            if let Ok(mut s) = self.session.lock() {
                                s.set_cheat_toggle(cheat.id, on);
                            }
                            self.log(format!(
                                "toggle '{}' {} (cave @ {target:#x})",
                                cheat.label,
                                if on { "enabled" } else { "disabled" }
                            ));
                        }
                        ui.label(format!("@ {target:#x}"));
                    }
                }
            });
        }
    }
}

impl eframe::App for TrainlabApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Refresh connection display from the shared session (which the MCP
        // server may also update) so the GUI always reflects current state.
        if let Ok(s) = self.session.lock() {
            self.connected = s.connected();
            if !self.connected && self.status.is_empty() {
                self.status = "not connected".into();
            }
        }
        egui::TopBottomPanel::top("conn").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("Host:");
                ui.text_edit_singleline(&mut self.host);
                ui.label("Port:");
                ui.text_edit_singleline(&mut self.port);
                if ui.button("Connect").clicked() {
                    let req = Request::Ping;
                    match self.request(&req) {
                        Some(Response::Pong { version }) => {
                            self.log(format!("connected, inject v{version}"));
                        }
                        Some(Response::Error { message }) => {
                            self.log(format!("error: {message}"));
                        }
                        _ => {}
                    }
                }
                ui.separator();
                ui.colored_label(
                    if self.connected {
                        egui::Color32::GREEN
                    } else {
                        egui::Color32::RED
                    },
                    &self.status,
                );
            });
            ui.horizontal(|ui| {
                ui.label("Game:");
                ui.text_edit_singleline(&mut self.game_name);
                if ui.button("Scan for games").clicked() {
                    self.refresh_game_candidates();
                }
                ui.label("DLL:");
                ui.text_edit_singleline(&mut self.dll_path);
                if ui.button("Find & Inject").clicked() {
                    self.inject_and_connect();
                }
            });
            if !self.game_candidates.is_empty() {
                ui.horizontal(|ui| {
                    ui.label("Candidates:");
                    let names: Vec<String> = self
                        .game_candidates
                        .iter()
                        .map(|p| format!("{} (pid {})", p.name, p.pid))
                        .collect();
                    let mut sel = self
                        .game_candidates
                        .iter()
                        .position(|p| p.name == self.game_name)
                        .unwrap_or(0);
                    egui::ComboBox::from_id_source("game_candidates")
                        .selected_text(names.get(sel).cloned().unwrap_or_default())
                        .show_ui(ui, |ui| {
                            for (i, n) in names.iter().enumerate() {
                                if ui.selectable_value(&mut sel, i, n).clicked() {
                                    self.game_name = self.game_candidates[i].name.clone();
                                }
                            }
                        });
                });
            }
            ui.horizontal(|ui| {
                ui.label("MCP server:");
                ui.monospace(&self.mcp_addr);
                ui.label("(connect an agent here)");
            });
        });

        egui::SidePanel::left("nav")
            .resizable(true)
            .default_width(180.0)
            .show(ctx, |ui| {
                ui.heading("trainlab");
                ui.separator();
                ui.label("Panels:");
                // Simple tab state via a local enum stored in the app.
                // We'll just render all panels stacked for simplicity.
                ui.label("• Memory");
                ui.label("• AOB Scan");
                ui.label("• Regions");
                ui.label("• Log");
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            self.show_cheats_panel(ui);

            ui.separator();
            self.show_session_panel(ui);

            ui.separator();
            ui.heading("Memory");
            ui.horizontal(|ui| {
                if ui.button("Read").clicked() {
                    let ops: Vec<(usize, u64, usize)> = self
                        .mem_ops
                        .iter()
                        .enumerate()
                        .filter_map(|(i, op)| {
                            parse_addr(&op.address)
                                .ok()
                                .map(|addr| (i, addr, parse_len(&op.value).unwrap_or(16)))
                        })
                        .collect();
                    for (i, addr, len) in ops {
                        let result = match self.request(&Request::Read { address: addr, len }) {
                            Some(Response::Read { data }) => hexdump(&data),
                            Some(Response::Error { message }) => message,
                            _ => "no response".into(),
                        };
                        if let Some(op) = self.mem_ops.get_mut(i) {
                            op.result = result;
                        }
                    }
                }
                if ui.button("Write").clicked() {
                    let ops: Vec<(usize, u64, Vec<u8>)> = self
                        .mem_ops
                        .iter()
                        .enumerate()
                        .filter_map(|(i, op)| {
                            parse_addr(&op.address)
                                .ok()
                                .map(|addr| (i, addr, parse_bytes(&op.value)))
                        })
                        .collect();
                    for (i, addr, data) in ops {
                        let result = match self.request(&Request::Write { address: addr, data }) {
                            Some(Response::Write { bytes_written }) => {
                                format!("wrote {bytes_written} bytes")
                            }
                            Some(Response::Error { message }) => message,
                            _ => "no response".into(),
                        };
                        if let Some(op) = self.mem_ops.get_mut(i) {
                            op.result = result;
                        }
                    }
                }
                if ui.button("+").clicked() {
                    self.mem_ops.push(MemOp::default());
                }
            });
            for op in self.mem_ops.iter_mut() {
                ui.horizontal(|ui| {
                    ui.label("Addr:");
                    ui.text_edit_singleline(&mut op.address);
                    ui.label("Value:");
                    ui.text_edit_singleline(&mut op.value);
                });
                ui.label(&op.result);
            }

            ui.separator();
            ui.heading("AOB Scan");
            ui.horizontal(|ui| {
                if ui.button("Scan").clicked() {
                    let scans: Vec<(usize, Vec<Option<u8>>)> = self
                        .aob_scans
                        .iter()
                        .enumerate()
                        .filter_map(|(i, s)| {
                            let p = trainlab_core::aob::parse(&s.pattern);
                            if p.is_empty() {
                                None
                            } else {
                                Some((i, p))
                            }
                        })
                        .collect();
                    for (i, pattern) in scans {
                        let result = match self.request(&Request::ScanAob {
                            pattern,
                            start: None,
                            end: None,
                        }) {
                            Some(Response::ScanAob { matches }) => {
                                let shown: Vec<String> = matches
                                    .iter()
                                    .take(20)
                                    .map(|m| format!("0x{m:x}"))
                                    .collect();
                                format!("{} matches: {}", matches.len(), shown.join(", "))
                            }
                            Some(Response::Error { message }) => message,
                            _ => "no response".into(),
                        };
                        if let Some(scan) = self.aob_scans.get_mut(i) {
                            scan.result = result;
                        }
                    }
                }
                if ui.button("+").clicked() {
                    self.aob_scans.push(AobScan::default());
                }
            });
            for scan in self.aob_scans.iter_mut() {
                ui.horizontal(|ui| {
                    ui.label("Pattern:");
                    ui.text_edit_singleline(&mut scan.pattern);
                });
                ui.label(&scan.result);
            }

            ui.separator();
            ui.heading("Regions");
            if ui.button("List regions").clicked() {
                match self.request(&Request::ListRegions) {
                    Some(Response::ListRegions { regions }) => {
                        self.regions = regions;
                        self.log(format!("listed {} regions", self.regions.len()));
                    }
                    Some(Response::Error { message }) => self.log(message),
                    _ => {}
                }
            }
            egui::ScrollArea::vertical()
                .max_height(200.0)
                .show(ui, |ui| {
                    for r in &self.regions {
                        let perms = format!(
                            "{}{}{}",
                            if r.readable { "r" } else { "-" },
                            if r.writable { "w" } else { "-" },
                            if r.executable { "x" } else { "-" }
                        );
                        ui.monospace(format!(
                            "0x{:016x} - 0x{:016x}  {}  {}",
                            r.start,
                            r.end,
                            perms,
                            r.name.as_deref().unwrap_or("")
                        ));
                    }
                });

            ui.separator();
            ui.heading("Log");
            egui::ScrollArea::vertical()
                .max_height(120.0)
                .show(ui, |ui| {
                    for line in &self.log {
                        ui.monospace(line);
                    }
                });
        });
    }
}


/// Resolve the DLL path. If `input` is a bare file name (no separator), join
/// it with the directory containing this executable so the DLL can be shipped
/// side-by-side with the trainer. Absolute or relative paths are used as-is.
/// Format a little-endian byte slice as a value of the given type.
fn format_value(data: &[u8], vt: trainlab_core::scan::ValueType) -> String {
    use trainlab_core::scan::ValueType;
    match vt {
        ValueType::I32 => i32::from_le_bytes([data[0], data[1], data[2], data[3]]).to_string(),
        ValueType::U32 => u32::from_le_bytes([data[0], data[1], data[2], data[3]]).to_string(),
        ValueType::F32 => f32::from_le_bytes([data[0], data[1], data[2], data[3]]).to_string(),
        ValueType::I64 => i64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ])
        .to_string(),
        ValueType::U64 => u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ])
        .to_string(),
        ValueType::F64 => f64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ])
        .to_string(),
        ValueType::Ptr => u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ])
        .to_string(),
    }
}

/// Parse a decimal/float string into little-endian bytes for a value type.
fn parse_value_bytes(s: &str, vt: trainlab_core::scan::ValueType) -> Result<Vec<u8>, String> {
    use trainlab_core::scan::ValueType;
    let s = s.trim();
    match vt {
        ValueType::I32 => Ok(s.parse::<i32>().map_err(|e| e.to_string())?.to_le_bytes().to_vec()),
        ValueType::U32 => Ok(s.parse::<u32>().map_err(|e| e.to_string())?.to_le_bytes().to_vec()),
        ValueType::F32 => Ok(s.parse::<f32>().map_err(|e| e.to_string())?.to_le_bytes().to_vec()),
        ValueType::I64 => Ok(s.parse::<i64>().map_err(|e| e.to_string())?.to_le_bytes().to_vec()),
        ValueType::U64 => Ok(s.parse::<u64>().map_err(|e| e.to_string())?.to_le_bytes().to_vec()),
        ValueType::F64 => Ok(s.parse::<f64>().map_err(|e| e.to_string())?.to_le_bytes().to_vec()),
        ValueType::Ptr => Ok(s.parse::<u64>().map_err(|e| e.to_string())?.to_le_bytes().to_vec()),
    }
}

fn resolve_dll_path(input: &str) -> String {
    let has_sep = input.contains('/') || input.contains('\\');
    if has_sep {
        return input.to_string();
    }
    match std::env::current_exe() {
        Ok(exe) => match exe.parent() {
            Some(dir) => dir.join(input).to_string_lossy().into_owned(),
            None => input.to_string(),
        },
        Err(_) => input.to_string(),
    }
}
fn parse_addr(s: &str) -> Result<u64, std::num::ParseIntError> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
    } else {
        u64::from_str_radix(s, 16)
    }
}

fn parse_len(s: &str) -> Option<usize> {
    s.trim().parse::<usize>().ok()
}

/// Parse a value string as either a hex byte string ("48 8B 05") or a decimal
/// integer (which becomes a little-endian u64).
fn parse_bytes(s: &str) -> Vec<u8> {
    let s = s.trim();
    if s.is_empty() {
        return Vec::new();
    }
    // If it looks like a space-separated hex byte string, parse that.
    if s.contains(' ') || s.contains("0x") {
        let toks: Vec<&str> = s.split_whitespace().collect();
        if toks.iter().all(|t| t.len() <= 2 || t.starts_with("0x")) {
            let mut out = Vec::new();
            for t in toks {
                let t = t.strip_prefix("0x").unwrap_or(t);
                if let Ok(b) = u8::from_str_radix(t, 16) {
                    out.push(b);
                }
            }
            return out;
        }
    }
    // Otherwise treat as a decimal integer -> little-endian u64.
    if let Ok(v) = s.parse::<u64>() {
        return v.to_le_bytes().to_vec();
    }
    Vec::new()
}

fn hexdump(data: &[u8]) -> String {
    let mut out = String::new();
    for (i, b) in data.iter().enumerate() {
        if i > 0 && i % 16 == 0 {
            out.push('\n');
        }
        out.push_str(&format!("{b:02x} "));
    }
    out
}
