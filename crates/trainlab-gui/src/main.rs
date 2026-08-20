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
use trainlab_core::memory::ProcessMemory;
use trainlab_core::protocol::{Request, Response};

use crate::session::{Cheat, CheatKind, SharedSession, SessionState};

mod mcp;
mod controller;
mod inject;
mod profile;
mod session;



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

    // Cheats panel: editable value strings keyed by cheat id, and a flag to
    // show the panel.
    cheat_values: std::collections::HashMap<u64, String>,
    show_cheats: bool,

    // Value Search state
    scan_val: String,
    scan_val_max: String,
    scan_val_type: trainlab_core::scan::ValueType,
    scan_op_mode: ScanOpMode,
    // Active Tab state
    active_tab: ActiveTab,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanOpMode {
    Exact,
    Range,
    Changed,
    Unchanged,
    Increased,
    Decreased,
}

impl Default for ScanOpMode {
    fn default() -> Self {
        ScanOpMode::Exact
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveTab {
    Cheats,
    DiscoverScan,
    PointersOffsets,
}

impl Default for ActiveTab {
    fn default() -> Self {
        ActiveTab::Cheats
    }
}

impl Default for TrainlabApp {
    fn default() -> Self {
        Self::new(std::sync::Arc::new(std::sync::Mutex::new(SessionState::new())))
    }
}

impl TrainlabApp {
    fn new(session: SharedSession) -> Self {
        // The game executable to inject into. Overridable via TRAINLAB_GAME env var.
        let game_name = std::env::var("TRAINLAB_GAME").unwrap_or_default();
        let mut app = Self {
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
            cheat_values: std::collections::HashMap::new(),
            show_cheats: true,
            scan_val: "".into(),
            scan_val_max: "".into(),
            scan_val_type: trainlab_core::scan::ValueType::I32,
            scan_op_mode: ScanOpMode::Exact,
            active_tab: ActiveTab::Cheats,
        };
        app.auto_match_profile();
        app
    }

    /// Create the app with a fresh shared session (used by tests / defaults).
    fn with_session(session: SharedSession) -> Self {
        Self::new(session)
    }

    fn log(&mut self, msg: impl Into<String>) {
        if let Ok(mut s) = self.session.lock() {
            s.log_activity("UI", msg);
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
                    CheatKind::Button { commands } => {
                        if ui.button(format!("▶ {}", cheat.label)).clicked() {
                            self.log(format!("button '{}' clicked: running {} command(s)...", cheat.label, commands.len()));
                            self.run_cheat_commands(commands);
                        }
                        if let Some(n) = &cheat.note {
                            ui.label(format!("({n})"));
                        }
                    }
                }
            });
        }
    }

    /// Auto-discover running game processes and match against YAML cheat profiles.
    fn auto_match_profile(&mut self) {
        self.game_candidates = inject::find_game_candidates();
        let profiles = profile::discover_profiles();
        if profiles.is_empty() {
            return;
        }

        for cand in &self.game_candidates {
            if let Some((file, p)) = profile::find_profile_for_game(&profiles, &cand.name) {
                self.game_name = cand.name.clone();
                self.log(format!(
                    "auto-matched process '{}' to profile '{}' ({})",
                    cand.name, file, p.name
                ));
                break;
            }
        }
    }

    /// Execute a sequence of profile commands (for Button cheats).
    fn run_cheat_commands(&mut self, cmds: &[profile::ProfileCommand]) {
        for (idx, cmd) in cmds.iter().enumerate() {
            match cmd {
                profile::ProfileCommand::Write { address_ref, address, value, value_type } => {
                    let addr_str = address_ref.as_deref().or(address.as_deref()).unwrap_or("");
                    let parsed_addr = mcp::parse_addr_expr(&self.session, addr_str);
                    match parsed_addr {
                        Ok(addr) => {
                            let vt_str = value_type.as_deref().unwrap_or("i32");
                            if let Ok(vt) = mcp::parse_value_type(vt_str) {
                                if let Ok(bytes) = mcp::parse_value_bytes(value, vt) {
                                    let res = self.request(&Request::Write { address: addr, data: bytes });
                                    self.log(format!("cmd {idx}: write '{value}' ({vt_str}) to {addr_str} ({addr:#x}) -> {:?}", res.is_some()));
                                }
                            }
                        }
                        Err(e) => self.log(format!("cmd {idx}: bad address '{addr_str}': {e:?}")),
                    }
                }
                profile::ProfileCommand::InstallCave { target_ref, target, hook, payload } => {
                    let tgt_str = target_ref.as_deref().or(target.as_deref()).unwrap_or("");
                    let parsed_tgt = mcp::parse_addr_expr(&self.session, tgt_str);
                    match parsed_tgt {
                        Ok(target_addr) => {
                            if let Ok(payload_bytes) = mcp::parse_hex_bytes(payload) {
                                let cave_hook = match hook.as_str() {
                                    "override" => trainlab_core::cave_hook::CaveHook::Override { payload: payload_bytes, jump: trainlab_core::cave_hook::JumpStyle::Absolute },
                                    _ => trainlab_core::cave_hook::CaveHook::Trampoline { payload: payload_bytes, jump: trainlab_core::cave_hook::JumpStyle::Absolute },
                                };
                                let res = self.request(&Request::InstallCave { target: target_addr, hook: cave_hook });
                                self.log(format!("cmd {idx}: install cave at {tgt_str} ({target_addr:#x}) -> {:?}", res.is_some()));
                            }
                        }
                        Err(e) => self.log(format!("cmd {idx}: bad target '{tgt_str}': {e:?}")),
                    }
                }
                profile::ProfileCommand::AllocateString { content, kind } => {
                    self.log(format!("cmd {idx}: allocate string payload '{content}' ({kind})"));
                }
            }
        }
    }

    /// Render the interactive Value Search panel: supports first scan & refine ops
    /// (Exact, Range, Changed, Unchanged, Increased, Decreased) across value types (i32, u32, f32, i64, u64, f64, ptr).
    fn show_value_search_panel(&mut self, ui: &mut egui::Ui) {
        use trainlab_core::scan::{ScanOp, ValueType};

        ui.heading("🔍 Value Search & Refinement");
        ui.label("Search game memory for values (health, gold, ammo) and refine candidates live.");

        // Snapshot current scan state from shared session
        let (active_scan_info, match_count, matches_sample) = {
            let s = self.session.lock().unwrap();
            if let Some(scan) = s.scan() {
                let sample: Vec<(u64, f64)> = scan.matches().iter().take(50).cloned().collect();
                (Some(scan.value_type()), scan.len(), sample)
            } else {
                (None, 0, Vec::new())
            }
        };

        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.label("Value Type:");
                egui::ComboBox::from_id_source("scan_val_type")
                    .selected_text(format!("{:?}", self.scan_val_type))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.scan_val_type, ValueType::I32, "i32");
                        ui.selectable_value(&mut self.scan_val_type, ValueType::U32, "u32");
                        ui.selectable_value(&mut self.scan_val_type, ValueType::F32, "f32");
                        ui.selectable_value(&mut self.scan_val_type, ValueType::I64, "i64");
                        ui.selectable_value(&mut self.scan_val_type, ValueType::U64, "u64");
                        ui.selectable_value(&mut self.scan_val_type, ValueType::F64, "f64");
                        ui.selectable_value(&mut self.scan_val_type, ValueType::Ptr, "ptr");
                    });

                ui.separator();
                ui.label("Filter Mode:");
                egui::ComboBox::from_id_source("scan_op_mode")
                    .selected_text(match self.scan_op_mode {
                        ScanOpMode::Exact => "Exact Value",
                        ScanOpMode::Range => "Value Range [Min..Max]",
                        ScanOpMode::Changed => "Changed Value (≠ last)",
                        ScanOpMode::Unchanged => "Unchanged Value (= last)",
                        ScanOpMode::Increased => "Increased Value (> last)",
                        ScanOpMode::Decreased => "Decreased Value (< last)",
                    })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.scan_op_mode, ScanOpMode::Exact, "Exact Value");
                        ui.selectable_value(&mut self.scan_op_mode, ScanOpMode::Range, "Value Range [Min..Max]");
                        ui.selectable_value(&mut self.scan_op_mode, ScanOpMode::Changed, "Changed Value (≠ last)");
                        ui.selectable_value(&mut self.scan_op_mode, ScanOpMode::Unchanged, "Unchanged Value (= last)");
                        ui.selectable_value(&mut self.scan_op_mode, ScanOpMode::Increased, "Increased Value (> last)");
                        ui.selectable_value(&mut self.scan_op_mode, ScanOpMode::Decreased, "Decreased Value (< last)");
                    });
            });

            match self.scan_op_mode {
                ScanOpMode::Exact => {
                    ui.horizontal(|ui| {
                        ui.label("Value:");
                        ui.text_edit_singleline(&mut self.scan_val);
                    });
                }
                ScanOpMode::Range => {
                    ui.horizontal(|ui| {
                        ui.label("Min Value:");
                        ui.text_edit_singleline(&mut self.scan_val);
                        ui.label("Max Value:");
                        ui.text_edit_singleline(&mut self.scan_val_max);
                    });
                }
                _ => {}
            }

            ui.add_space(5.0);

            ui.horizontal(|ui| {
                // First Scan Button
                if ui.button("⚡ First Scan").clicked() {
                    let pid = {
                        let s = self.session.lock().unwrap();
                        s.game_pid()
                    };
                    if let Some(pid) = pid {
                        #[cfg(windows)]
                        let proc_res = trainlab_core::memory::WindowsProcess::open(pid);
                        #[cfg(not(windows))]
                        let proc_res: Result<trainlab_core::memory::LinuxProcess, String> = Ok(trainlab_core::memory::LinuxProcess::new(pid as i32));

                        match proc_res {
                            Ok(proc) => {
                                let regions = proc.regions().unwrap_or_default();
                                let op_res = match self.scan_op_mode {
                                    ScanOpMode::Exact => self.scan_val.trim().parse::<f64>().map(|v| ScanOp::Exact { value: v }).map_err(|e| e.to_string()),
                                    ScanOpMode::Range => {
                                        let min = self.scan_val.trim().parse::<f64>();
                                        let max = self.scan_val_max.trim().parse::<f64>();
                                        match (min, max) {
                                            (Ok(min), Ok(max)) => Ok(ScanOp::Range { min, max }),
                                            _ => Err("invalid min/max".to_string()),
                                        }
                                    }
                                    _ => Err("First scan requires an Exact or Range value".to_string()),
                                };

                                match op_res {
                                    Ok(op) => {
                                        let mut scan = trainlab_core::scan::Scan::new(self.scan_val_type);
                                        match scan.first_scan(&proc, &regions, op) {
                                            Ok(cnt) => {
                                                if let Ok(mut s) = self.session.lock() {
                                                    s.set_scan(scan);
                                                }
                                                self.log(format!("First scan found {cnt} candidate matches ({:?})", self.scan_val_type));
                                            }
                                            Err(e) => self.log(format!("First scan failed: {e}")),
                                        }
                                    }
                                    Err(msg) => self.log(format!("Scan error: {msg}")),
                                }
                            }
                            Err(e) => self.log(format!("Failed to open game process: {e}")),
                        }
                    } else {
                        self.log("No attached game PID; attach to a process first!");
                    }
                }

                // Next Scan / Refine Button
                if ui.button("🔍 Next Scan (Refine)").clicked() {
                    let pid = {
                        let s = self.session.lock().unwrap();
                        s.game_pid()
                    };
                    if let Some(pid) = pid {
                        #[cfg(windows)]
                        let proc_res = trainlab_core::memory::WindowsProcess::open(pid);
                        #[cfg(not(windows))]
                        let proc_res: Result<trainlab_core::memory::LinuxProcess, String> = Ok(trainlab_core::memory::LinuxProcess::new(pid as i32));

                        match proc_res {
                            Ok(proc) => {
                                let op_res = match self.scan_op_mode {
                                    ScanOpMode::Exact => self.scan_val.trim().parse::<f64>().map(|v| ScanOp::Exact { value: v }).map_err(|e| e.to_string()),
                                    ScanOpMode::Range => {
                                        let min = self.scan_val.trim().parse::<f64>();
                                        let max = self.scan_val_max.trim().parse::<f64>();
                                        match (min, max) {
                                            (Ok(min), Ok(max)) => Ok(ScanOp::Range { min, max }),
                                            _ => Err("invalid min/max".to_string()),
                                        }
                                    }
                                    ScanOpMode::Changed => Ok(ScanOp::Changed),
                                    ScanOpMode::Unchanged => Ok(ScanOp::Unchanged),
                                    ScanOpMode::Increased => Ok(ScanOp::Increased),
                                    ScanOpMode::Decreased => Ok(ScanOp::Decreased),
                                };

                                match op_res {
                                    Ok(op) => {
                                        let mut scan_to_refine = {
                                            let s = self.session.lock().unwrap();
                                            s.scan().cloned()
                                        };
                                        if let Some(mut scan) = scan_to_refine {
                                            match scan.refine(&proc, op) {
                                                Ok(cnt) => {
                                                    if let Ok(mut s) = self.session.lock() {
                                                        s.set_scan(scan);
                                                    }
                                                    self.log(format!("Refinement kept {cnt} matches"));
                                                }
                                                Err(e) => self.log(format!("Refinement failed: {e}")),
                                            }
                                        } else {
                                            self.log("No active scan set; perform a First Scan first!");
                                        }
                                    }
                                    Err(msg) => self.log(format!("Refine error: {msg}")),
                                }
                            }
                            Err(e) => self.log(format!("Failed to open game process: {e}")),
                        }
                    } else {
                        self.log("No attached game PID; attach to a process first!");
                    }
                }

                // Reset Scan Button
                if ui.button("🗑 Reset Scan").clicked() {
                    if let Ok(mut s) = self.session.lock() {
                        s.clear_scan();
                    }
                    self.log("Value search reset");
                }
            });
        });

        ui.add_space(10.0);

        // Display Active Scan Results
        ui.group(|ui| {
            if let Some(vt) = active_scan_info {
                ui.heading(format!("Scan Match Results ({match_count} total matches, type: {vt:?})"));
                if matches_sample.is_empty() {
                    ui.label("No active matches.");
                } else {
                    egui::ScrollArea::vertical()
                        .max_height(180.0)
                        .show(ui, |ui| {
                            for (addr, val) in &matches_sample {
                                ui.horizontal(|ui| {
                                    ui.monospace(format!("{addr:#018x}"));
                                    ui.label(format!("= {val}"));
                                    if ui.button("+ Add as Cheat").clicked() {
                                        let label = format!("Val @ {addr:#x}");
                                        if let Ok(mut s) = self.session.lock() {
                                            let cheat_id = s.add_cheat(
                                                &label,
                                                crate::session::CheatKind::Value {
                                                    address: *addr,
                                                    value_type: vt,
                                                },
                                                Some("Added from search UI".into()),
                                            );
                                            s.log_activity("UI", format!("added cheat '{label}' (id {cheat_id})"));
                                        }
                                    }
                                });
                            }
                        });
                }
            } else {
                ui.label("No active value search session. Select type, set filter, and hit 'First Scan'.");
            }
        });
    }
}

fn main() -> eframe::Result<()> {
    tracing_subscriber::fmt::init();

    // One shared session state across the GUI and the MCP server. The GUI sets
    // `game_pid` when it injects the game; the MCP server reads it to open the
    // game process externally for scan-family tools (see D7).
    let session: SharedSession = std::sync::Arc::new(std::sync::Mutex::new(SessionState::new()));

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([900.0, 640.0]),
        ..Default::default()
    };

    eframe::run_native(
        "trainlab",
        options,
        Box::new(move |cc| {
            let ctx = cc.egui_ctx.clone();

            // Start the MCP server on a background tokio runtime.
            let mcp_host = std::env::var("TRAINLAB_MCP_HOST").unwrap_or_else(|_| "0.0.0.0".into());
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
                    match mcp::serve(&mcp_host, mcp_port, mcp_session, Some(ctx)).await {
                        Ok((url, ct)) => {
                            tracing::info!(%url, "MCP server ready");
                            ct.cancelled().await;
                        }
                        Err(e) => tracing::error!("failed to start MCP server: {e}"),
                    }
                });
            });

            Box::new(TrainlabApp::with_session(session))
        }),
    )
}

impl eframe::App for TrainlabApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Check window OS focus state to ensure controller / navigation inputs
        // only affect the GUI when the trainer window is focused.
        let is_focused = ctx.input(|i| i.viewport().focused.unwrap_or(true));

        // Handle tab switching & controller navigation if the window is focused
        // and the user is NOT currently typing into a text field (ctx.wants_keyboard_input()).
        if is_focused && !ctx.wants_keyboard_input() {
            ctx.input(|i| {
                if i.key_pressed(egui::Key::PageDown) || i.key_pressed(egui::Key::Q) {
                    self.active_tab = match self.active_tab {
                        ActiveTab::Cheats => ActiveTab::PointersOffsets,
                        ActiveTab::DiscoverScan => ActiveTab::Cheats,
                        ActiveTab::PointersOffsets => ActiveTab::DiscoverScan,
                    };
                } else if i.key_pressed(egui::Key::PageUp) || i.key_pressed(egui::Key::E) {
                    self.active_tab = match self.active_tab {
                        ActiveTab::Cheats => ActiveTab::DiscoverScan,
                        ActiveTab::DiscoverScan => ActiveTab::PointersOffsets,
                        ActiveTab::PointersOffsets => ActiveTab::Cheats,
                    };
                }
            });
        }

        // Refresh connection display from the shared session (which the MCP
        // server may also update) so the GUI always reflects current state.
        if let Ok(s) = self.session.lock() {
            self.connected = s.connected();
            if self.connected {
                let ver = s.inject_version().unwrap_or("active");
                let game = s.game_name();
                self.status = format!("connected to {game} (v{ver})");
            } else {
                self.status = "not connected".into();
            }
        }

        // Top panel showing status bar and MCP server info
        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("trainlab");
                ui.separator();
                ui.label("Status:");
                ui.colored_label(
                    if self.connected {
                        egui::Color32::GREEN
                    } else {
                        egui::Color32::RED
                    },
                    &self.status,
                );

                ui.separator();
                if is_focused {
                    ui.colored_label(egui::Color32::LIGHT_BLUE, "🎯 Focused (Input Active)");
                } else {
                    ui.colored_label(egui::Color32::GRAY, "⏸ Unfocused (Input Muted)");
                }

                if self.connected {
                    ui.separator();
                    if ui.button("Disconnect").clicked() {
                        if let Ok(mut s) = self.session.lock() {
                            s.set_connected(false);
                        }
                        self.connected = false;
                        self.status = "disconnected".into();
                    }
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.monospace(&self.mcp_addr);
                    ui.label("MCP server:");
                });
            });
        });

        if !self.connected {
            // State 1: Welcome & Attach Screen
            egui::CentralPanel::default().show(ctx, |ui| {
                egui::ScrollArea::both().show(ui, |ui| {
                    ui.add_space(20.0);
                    ui.vertical_centered(|ui| {
                        ui.heading("Welcome to trainlab");
                        ui.label("The MCP-enabled control room for process memory analysis & injection.");
                    });
                    ui.add_space(20.0);

                    ui.group(|ui| {
                        ui.heading("MCP Server Status");
                        ui.label(format!("• Running on {}", self.mcp_addr));
                        ui.label("• Ready for AI agents & remote connections.");
                    });

                    ui.add_space(15.0);

                    ui.group(|ui| {
                        ui.heading("Attach & Inject Game");
                        ui.add_space(5.0);

                        ui.horizontal(|ui| {
                            ui.label("Target Game Exe:");
                            ui.text_edit_singleline(&mut self.game_name);
                            if ui.button("Scan running processes").clicked() {
                                self.refresh_game_candidates();
                                self.auto_match_profile();
                            }
                        });

                        if !self.game_candidates.is_empty() {
                            ui.horizontal(|ui| {
                                ui.label("Found Candidates:");
                                let names: Vec<String> = self
                                    .game_candidates
                                    .iter()
                                    .map(|p| format!("{} (pid {})", p.name, p.pid))
                                    .collect();
                                let mut sel = self
                                    .game_candidates
                                    .iter()
                                    .position(|p| p.name.eq_ignore_ascii_case(&self.game_name))
                                    .unwrap_or(0);
                                let selected_text = names.get(sel).cloned().unwrap_or_else(|| "-- select process --".into());
                                egui::ComboBox::from_id_source("game_candidates")
                                    .selected_text(selected_text)
                                    .show_ui(ui, |ui| {
                                        for (i, n) in names.iter().enumerate() {
                                            if ui.selectable_value(&mut sel, i, n).clicked() {
                                                if let Some(cand) = self.game_candidates.get(i) {
                                                    self.game_name = cand.name.clone();
                                                }
                                            }
                                        }
                                    });
                            });
                        }

                        ui.horizontal(|ui| {
                            ui.label("DLL Path:");
                            ui.text_edit_singleline(&mut self.dll_path);
                        });

                        ui.add_space(5.0);
                        if ui.button("🚀 Find & Inject DLL").clicked() {
                            self.inject_and_connect();
                        }
                    });

                    ui.add_space(15.0);

                    ui.group(|ui| {
                        ui.heading("Manual Listener Connection");
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
                        });
                    });

                    ui.add_space(15.0);
                    ui.heading("Activity Log");
                    let activity_log = self
                        .session
                        .lock()
                        .map(|s| s.list_activity_log())
                        .unwrap_or_default();
                    egui::ScrollArea::vertical()
                        .max_height(150.0)
                        .show(ui, |ui| {
                            for line in &activity_log {
                                if line.starts_with("UI:") {
                                    ui.colored_label(egui::Color32::LIGHT_BLUE, line);
                                } else if line.starts_with("MCP:") {
                                    ui.colored_label(egui::Color32::YELLOW, line);
                                } else {
                                    ui.monospace(line);
                                }
                            }
                        });
                });
            });
        } else {
            // State 2: Active Session (Tab Navigation)
            egui::SidePanel::left("nav")
                .resizable(true)
                .default_width(180.0)
                .show(ctx, |ui| {
                    ui.heading("Navigation");
                    ui.separator();
                    ui.selectable_value(&mut self.active_tab, ActiveTab::Cheats, "🎮 Cheats");
                    ui.selectable_value(&mut self.active_tab, ActiveTab::DiscoverScan, "🔍 Discover & Scan");
                    ui.selectable_value(&mut self.active_tab, ActiveTab::PointersOffsets, "🎯 Pointers & Offsets");
                });

            egui::CentralPanel::default().show(ctx, |ui| {
                egui::ScrollArea::both().show(ui, |ui| {
                    match self.active_tab {
                        ActiveTab::Cheats => {
                            self.show_cheats_panel(ui);
                            ui.separator();
                            self.show_session_panel(ui);
                        }
                        ActiveTab::DiscoverScan => {
                            self.show_value_search_panel(ui);
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
                            ui.heading("Memory Regions");
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
                        }
                        ActiveTab::PointersOffsets => {
                            ui.heading("Pointers & Offsets (Memory Inspection)");
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
                        }
                    }

                    ui.separator();
                    ui.heading("Activity Log");
                    let activity_log = self
                        .session
                        .lock()
                        .map(|s| s.list_activity_log())
                        .unwrap_or_default();
                    egui::ScrollArea::vertical()
                        .max_height(140.0)
                        .show(ui, |ui| {
                            for line in &activity_log {
                                if line.starts_with("UI:") {
                                    ui.colored_label(egui::Color32::LIGHT_BLUE, line);
                                } else if line.starts_with("MCP:") {
                                    ui.colored_label(egui::Color32::YELLOW, line);
                                } else {
                                    ui.monospace(line);
                                }
                            }
                        });
                });
            });
        }
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
