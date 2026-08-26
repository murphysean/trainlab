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

mod api;
mod asm;
mod event;
mod controller;
mod hotkeys;
mod inject;
mod mcp;
mod profile;
mod session;
mod xinput_poll;



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

/// Registered Win32 hotkey binding state.
#[derive(Debug, Clone)]
struct RegisteredHotkey {
    cheat_id: u64,
    spec: hotkeys::HotkeySpec,
    display: String,
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

    // Cheats panel: editable value strings keyed by cheat id, editable hotkey strings,
    // active Win32 registered hotkeys, and a flag to show the panel.
    cheat_values: std::collections::HashMap<u64, String>,
    cheat_values_cache: std::collections::HashMap<u64, (std::time::Instant, Option<Vec<u8>>)>,
    cheat_hotkey_inputs: std::collections::HashMap<u64, String>,
    registered_hotkeys: std::collections::HashMap<i32, RegisteredHotkey>,
    show_cheats: bool,

    // Value Search state
    scan_val: String,
    scan_val_max: String,
    scan_val_type: trainlab_core::scan::ValueType,
    scan_op_mode: ScanOpMode,
    // Run Applications state
    custom_app_path: String,
    custom_app_args: String,
    // Active Tab state
    active_tab: ActiveTab,
    // Auto-run profile init_commands on attach
    auto_init: bool,
    // Window visibility state for toggle hotkey
    window_visible: bool,
    // Last broadcasted overlay visibility mask to avoid 20 Hz event spam
    last_synced_mask: Option<bool>,
    // In-flight attachment / initialization indicator & lock
    is_attaching: std::sync::Arc<std::sync::atomic::AtomicBool>,
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
    MemoryScan,
    TaggedMarkers,
    PointersInspection,
    RunApplications,
    ActivityLog,
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
            cheat_values_cache: std::collections::HashMap::new(),
            cheat_hotkey_inputs: std::collections::HashMap::new(),
            registered_hotkeys: std::collections::HashMap::new(),
            show_cheats: true,
            scan_val: "".into(),
            scan_val_max: "".into(),
            scan_val_type: trainlab_core::scan::ValueType::I32,
            scan_op_mode: ScanOpMode::Exact,
            custom_app_path: "".into(),
            custom_app_args: "".into(),
            active_tab: ActiveTab::Cheats,
            auto_init: true,
            window_visible: true,
            last_synced_mask: None,
            is_attaching: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        app.auto_match_profile();
        app.sync_registered_hotkeys();
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
        if let Ok(mut s) = self.session.lock() {
            for proc in &self.game_candidates {
                s.record_tracked_app(&proc.name, Some(proc.pid), proc.path.as_deref());
            }
        }
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
    /// flow remotely. Runs on a background thread so the GUI UI never freezes.
    fn inject_and_connect(&mut self) {
        use std::sync::atomic::Ordering;
        if self.is_attaching.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            // Already an in-flight attach / injection operation running!
            return;
        }

        self.sync_session();
        let session = self.session.clone();
        let auto_init = self.auto_init;
        let game_name = self.game_name.clone();
        let dll_path = resolve_dll_path(&self.dll_path);
        let attaching_flag = self.is_attaching.clone();

        if let Ok(mut s) = self.session.lock() {
            s.set_dll_path(dll_path);
            s.log_activity("UI", "attaching and injecting in background...");
        }

        std::thread::spawn(move || {
            match controller::find_inject_connect(&session) {
                Ok(version) => {
                    if let Ok(mut s) = session.lock() {
                        let attached_pid = s.game_pid();
                        s.record_tracked_app(&game_name, attached_pid, None);
                        s.log_activity("UI", format!("connected, inject v{version} — awaiting DLL graphics & engine readiness..."));
                    }

                    // Explicit handshake: Wait for DLL graphics hooks / engine initialization to settle
                    match controller::request(&session, &Request::WaitForReady) {
                        Ok(Response::Ready { api, input_hook, present_hooked, frame_count, combo_count }) => {
                            if let Ok(mut s) = session.lock() {
                                s.log_activity("UI", format!("DLL ready: {api} | Input: {input_hook} (present hooked: {present_hooked}, {frame_count} frames, {combo_count} combos)"));
                            }
                        }
                        _ => {
                            if let Ok(mut s) = session.lock() {
                                s.log_activity("UI", "DLL ready handshake completed (default)");
                            }
                        }
                    }

                    if auto_init {
                        let profiles = profile::discover_profiles();
                        if let Some((file, _p)) = profile::find_profile_for_game(&profiles, &game_name) {
                            if let Ok(mut s) = session.lock() {
                                s.log_activity("UI", format!("starting sequential profile initialization for '{file}'..."));
                            }
                            match mcp::TrainlabMcpServer::with_session(session.clone()).load_profile_by_name(&file, true) {
                                Ok(detail) => {
                                    if let Ok(mut s) = session.lock() {
                                        s.log_activity("UI", format!("profile '{file}' loaded: {detail}"));
                                    }
                                }
                                Err(e) => {
                                    if let Ok(mut s) = session.lock() {
                                        s.log_activity("UI", format!("profile '{file}' load FAILED: {e}"));
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    if let Ok(mut s) = session.lock() {
                        s.log_activity("UI", format!("attach failed: {e}"));
                        s.set_connected(false);
                    }
                }
            }
            attaching_flag.store(false, Ordering::SeqCst);
        });
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
            ui.heading("📌 Saved Markers (Live Memory Inspector)");
            ui.label("Read and modify memory values live at any saved marker address:");

            let mut write_op: Option<(u64, String, trainlab_core::scan::ValueType)> = None;

            egui::Grid::new("markers_grid")
                .striped(true)
                .num_columns(6)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    ui.label(egui::RichText::new("Marker").strong());
                    ui.label(egui::RichText::new("Address").strong());
                    ui.label(egui::RichText::new("Live Value (i32)").strong());
                    ui.label(egui::RichText::new("Live Value (f32)").strong());
                    ui.label(egui::RichText::new("Live Value (ptr)").strong());
                    ui.label(egui::RichText::new("Write New Value").strong());
                    ui.end_row();

                    for (label, addr, note) in &markers {
                        ui.label(format!("${label}"));
                        ui.label(format!("{addr:#x}"));

                        // Read 8 bytes at marker address to display live interpretations (debounced cache)
                        let read_res = if *addr != 0 {
                            self.read_cached(*addr, 8)
                        } else {
                            None
                        };
                        match read_res {
                            Some(data) => {
                                let i32_val = if data.len() >= 4 {
                                    format!("{}", i32::from_le_bytes(data[..4].try_into().unwrap()))
                                } else { "-".into() };

                                let f32_val = if data.len() >= 4 {
                                    format!("{:.2}", f32::from_le_bytes(data[..4].try_into().unwrap()))
                                } else { "-".into() };

                                let ptr_val = if data.len() >= 8 {
                                    format!("{:#x}", u64::from_le_bytes(data[..8].try_into().unwrap()))
                                } else { "-".into() };

                                ui.label(i32_val);
                                ui.label(f32_val);
                                ui.label(ptr_val);
                            }
                            _ => {
                                ui.label("N/A");
                                ui.label("N/A");
                                ui.label("N/A");
                            }
                        }

                        // Editable input for writing to marker
                        let marker_edit_key = format!("marker_val_{label}");
                        let mut edit_val = self.cheat_values.get(&((*addr) as u64)).cloned().unwrap_or_default();
                        
                        ui.horizontal(|ui| {
                            let text_edit = ui.add(egui::TextEdit::singleline(&mut edit_val).hint_text("new value").desired_width(90.0));
                            if text_edit.changed() {
                                self.cheat_values.insert((*addr) as u64, edit_val.clone());
                            }
                            if ui.button("Write i32").clicked() {
                                write_op = Some((*addr, edit_val.clone(), trainlab_core::scan::ValueType::I32));
                            }
                            if ui.button("Write ptr").clicked() {
                                write_op = Some((*addr, edit_val.clone(), trainlab_core::scan::ValueType::Ptr));
                            }
                        });
                        ui.end_row();
                    }
                });

            // Perform write if user clicked Write i32 / Write ptr button
            if let Some((addr, val_str, vt)) = write_op {
                // Support writing another marker address or value expression
                let eval_val = match mcp::parse_addr_expr(&self.session, val_str.trim_start_matches('$')) {
                    Ok(a) => format!("{a:#x}"),
                    Err(_) => val_str.clone(),
                };
                if let Ok(bytes) = mcp::parse_value_bytes(&eval_val, vt) {
                    let res = self.request(&Request::Write { address: addr, data: bytes });
                    match res {
                        Some(Response::Write { bytes_written }) => {
                            self.log(format!("wrote '{eval_val}' to marker @ {addr:#x} ({bytes_written} bytes)"));
                        }
                        _ => self.log(format!("write to marker @ {addr:#x} failed")),
                    }
                } else {
                    self.log(format!("invalid value '{val_str}' for write"));
                }
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

    /// Cached live reads to avoid firing blocking TCP read requests on every UI frame.
    fn read_cached(&mut self, address: u64, len: usize) -> Option<Vec<u8>> {
        let now = std::time::Instant::now();
        if let Some((cached_time, cached_val)) = self.cheat_values_cache.get(&address) {
            if now.duration_since(*cached_time) < std::time::Duration::from_millis(250) {
                return cached_val.clone();
            }
        }
        let r = self.request(&Request::Read { address, len });
        let val = match r {
            Some(Response::Read { data }) => Some(data),
            _ => None,
        };
        self.cheat_values_cache.insert(address, (now, val.clone()));
        val
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
            PendingKind::InstallCave { hook, .. } => {
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
    fn show_cheats_panel(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.horizontal(|ui| {
            ui.heading("Cheats");
            if ui.checkbox(&mut self.show_cheats, "show").changed() {
                // toggle panel visibility
            }
            ui.separator();
            ui.checkbox(&mut self.auto_init, "Auto-run init on attach");

            // Display profile metadata if matched
            let profiles = profile::discover_profiles();
            if let Some((_file, p)) = profile::find_profile_for_game(&profiles, &self.game_name) {
                ui.separator();
                let mut meta = Vec::new();
                if let Some(gv) = &p.game_version {
                    meta.push(format!("Game v{gv}"));
                }
                if let Some(d) = &p.date {
                    meta.push(format!("📅 {d}"));
                }
                if !p.version.is_empty() {
                    meta.push(format!("Profile v{}", p.version));
                }
                if !meta.is_empty() {
                    ui.colored_label(egui::Color32::from_rgb(130, 200, 255), format!("({})", meta.join(" | ")));
                }
            }
        });
        if !self.show_cheats {
            return;
        }
        ui.horizontal(|ui| {
            if ui.button("⚡ Re-run Initialization").clicked() {
                let profiles = profile::discover_profiles();
                if let Some((file, _p)) = profile::find_profile_for_game(&profiles, &self.game_name) {
                    let session = self.session.clone();
                    let file_name = file.clone();
                    std::thread::spawn(move || {
                        match mcp::TrainlabMcpServer::with_session(session.clone()).load_profile_by_name(&file_name, true) {
                            Ok(detail) => {
                                if let Ok(mut s) = session.lock() {
                                    s.log_activity("UI", format!("re-populated cheats from profile '{file_name}': {detail}"));
                                }
                            }
                            Err(e) => {
                                if let Ok(mut s) = session.lock() {
                                    s.log_activity("UI", format!("re-run init FAILED: {e}"));
                                }
                            }
                        }
                    });
                }
            }
            if ui.button("Clear all").clicked() {
                if let Ok(mut s) = self.session.lock() {
                    let ids: Vec<u64> = s.list_cheats().iter().map(|c| c.id).collect();
                    for id in ids {
                        s.remove_cheat(id);
                    }
                    // T-150: Emit event for clearing all cheats.
                    s.event_bus().emit(crate::event::SessionEvent::ProfileLoaded {
                        name: String::new(),
                        game: String::new(),
                        cheats_count: 0,
                    });
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
                        // Live-read the current value (debounced cache).
                        let current = self
                            .read_cached(*address, value_type.size())
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
                                            // T-151: Emit CheatUpdated so SSE dashboard reflects the new value.
                                            if let Ok(s) = self.session.lock() {
                                                s.event_bus().emit(crate::event::SessionEvent::CheatUpdated {
                                                    id: cheat.id,
                                                    label: cheat.label.clone(),
                                                    enabled: None,
                                                    value: Some(field_val.clone()),
                                                });
                                            }
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
                    CheatKind::Toggle { target, hook, enabled, original_bytes, .. } => {
                        let mut on = *enabled;
                        if ui.checkbox(&mut on, &cheat.label).changed() {
                            // T-112: GUI toggle drives the real cave — install on enable, restore on disable.
                            if on {
                                // Enable: install the cave directly (user is the human confirmation).
                                let r = self.request(&Request::InstallCave {
                                    target: *target,
                                    hook: hook.clone(),
                                });
                                match r {
                                    Some(Response::CaveInstalled { cave, original, .. }) => {
                                        // Store original bytes for later disable.
                                        if let Ok(mut s) = self.session.lock() {
                                            s.set_toggle_cave_info(cheat.id, original.clone(), cave);
                                            s.set_cheat_toggle(cheat.id, true);
                                        }
                                        self.log(format!(
                                            "toggle '{}' ENABLED (cave @ {cave:#x}, target {target:#x})",
                                            cheat.label
                                        ));
                                    }
                                    _ => self.log(format!(
                                        "toggle '{}' enable FAILED (cave @ {target:#x})",
                                        cheat.label
                                    )),
                                }
                            } else {
                                // Disable: restore original bytes if we have them.
                                if !original_bytes.is_empty() {
                                    let r = self.request(&Request::Write {
                                        address: *target,
                                        data: original_bytes.clone(),
                                    });
                                    match r {
                                        Some(Response::Write { bytes_written }) => {
                                            if let Ok(mut s) = self.session.lock() {
                                                s.set_cheat_toggle(cheat.id, false);
                                            }
                                            self.log(format!(
                                                "toggle '{}' DISABLED (restored {bytes_written} bytes @ {target:#x})",
                                                cheat.label
                                            ));
                                        }
                                        _ => self.log(format!(
                                            "toggle '{}' disable FAILED (restore @ {target:#x})",
                                            cheat.label
                                        )),
                                    }
                                } else {
                                    // No original bytes stored — can't restore via GUI.
                                    // Try via the MCP toggle path (stages it).
                                    self.log(format!(
                                        "toggle '{}' disable: no stored original bytes; use MCP set_cheat_toggle",
                                        cheat.label
                                    ));
                                }
                            }
                        }
                        ui.label(format!("@ {target:#x}"));
                    }
                    CheatKind::Patch { target, patch_bytes, original_bytes, enabled, cave_ref } => {
                        let mut on = *enabled;
                        let desc = cave_ref.as_deref().unwrap_or("fast patch");
                        if ui.checkbox(&mut on, &cheat.label).changed() {
                            let bytes_to_write = if on { patch_bytes } else { original_bytes };
                            if !bytes_to_write.is_empty() {
                                let r = self.request(&Request::Write {
                                    address: *target,
                                    data: bytes_to_write.clone(),
                                });
                                match r {
                                    Some(Response::Write { bytes_written }) => {
                                        if let Ok(mut s) = self.session.lock() {
                                            s.set_cheat_toggle(cheat.id, on);
                                        }
                                        self.log(format!(
                                            "patch '{}' -> {} ({bytes_written} bytes @ {target:#x}, {desc})",
                                            cheat.label,
                                            if on { "ENABLED" } else { "DISABLED" }
                                        ));
                                    }
                                    _ => self.log(format!(
                                        "patch '{}' {} FAILED (@ {target:#x})",
                                        cheat.label,
                                        if on { "enable" } else { "disable" }
                                    )),
                                }
                            }
                        }
                        ui.label(format!("@ {target:#x} ({desc})"));
                    }
                    CheatKind::Button { commands } => {
                        if ui.button(format!("▶ {}", cheat.label)).clicked() {
                            self.log(format!("button '{}' clicked: running {} command(s)...", cheat.label, commands.len()));
                            let session = self.session.clone();
                            let label = cheat.label.clone();
                            let cmds = commands.clone();
                            std::thread::spawn(move || {
                                if let Err(e) = mcp::execute_profile_commands(&session, &cmds) {
                                    if let Ok(mut s) = session.lock() {
                                        s.log_activity("UI", format!("button '{label}' failed: {e}"));
                                    }
                                }
                            });
                        }
                        if let Some(n) = &cheat.note {
                            ui.label(format!("({n})"));
                        }
                    }
                }

                // Hotkey assignment input & button
                ui.separator();
                ui.label("Hotkey:");
                let hk_field = self
                    .cheat_hotkey_inputs
                    .entry(cheat.id)
                    .or_insert_with(|| cheat.hotkey.clone().unwrap_or_default());
                ui.add(egui::TextEdit::singleline(hk_field).hint_text("e.g. Num1, Shift+Alt+K"));

                if ui.button("Bind").clicked() {
                    let text = hk_field.trim().to_string();
                    if text.is_empty() {
                        if let Ok(mut s) = self.session.lock() {
                            s.set_cheat_hotkey(cheat.id, None);
                        }
                        self.sync_registered_hotkeys();
                        self.log(format!("cleared hotkey for '{}'", cheat.label));
                    } else {
                        match hotkeys::HotkeySpec::parse(&text) {
                            Ok(spec) => {
                                let display = spec.display_string();
                                if let Ok(mut s) = self.session.lock() {
                                    s.set_cheat_hotkey(cheat.id, Some(display.clone()));
                                }
                                *hk_field = display.clone();
                                self.sync_registered_hotkeys();
                                self.log(format!("bound '{}' to hotkey '{display}'", cheat.label));
                            }
                            Err(e) => {
                                self.log(format!("invalid hotkey format for '{}': {e}", cheat.label));
                            }
                        }
                    }
                }
            });
        }
    }

    /// Synchronize Win32 RegisteredHotKeys with the cheats configured in the session.
    fn sync_registered_hotkeys(&mut self) {
        #[cfg(target_os = "windows")]
        {
            let raw_hwnd = 0isize; // NULL HWND registers global hotkey for current thread message loop

            // Collect active hotkey targets from session cheats.
            let mut desired: std::collections::HashMap<i32, (u64, hotkeys::HotkeySpec, String)> = std::collections::HashMap::new();
            if let Ok(s) = self.session.lock() {
                for c in s.list_cheats() {
                    if let Some(hk_str) = &c.hotkey {
                        if let Ok(spec) = hotkeys::HotkeySpec::parse(hk_str) {
                            let id = c.id as i32 + 1000;
                            desired.insert(id, (c.id, spec, spec.display_string()));
                        }
                    }
                }
            }

            // Always register global window toggle hotkey ('J' key, ID 9999).
            if let Ok(spec) = hotkeys::HotkeySpec::parse("J") {
                desired.insert(9999, (0, spec, "J".into()));
            }

            // Unregister hotkeys no longer desired or updated.
            let current_ids: Vec<i32> = self.registered_hotkeys.keys().cloned().collect();
            for id in current_ids {
                if !desired.contains_key(&id) {
                    hotkeys::unregister_hotkey(raw_hwnd, id);
                    self.registered_hotkeys.remove(&id);
                }
            }

            // Register newly desired hotkeys.
            for (id, (cheat_id, spec, display)) in desired {
                if !self.registered_hotkeys.contains_key(&id) {
                    if let Ok(()) = hotkeys::register_hotkey(raw_hwnd, id, spec) {
                        self.registered_hotkeys.insert(
                            id,
                            RegisteredHotkey {
                                cheat_id,
                                spec,
                                display,
                            },
                        );
                    }
                }
            }
        }
    }

    /// Trigger a cheat by id (e.g. from hotkey or UI).
    fn trigger_cheat(&mut self, cheat_id: u64) {
        let (label, kind) = match self.session.lock() {
            Ok(s) => match s.get_cheat(cheat_id) {
                Some(c) => (c.label.clone(), c.kind.clone()),
                None => return,
            },
            Err(_) => return,
        };

        match kind {
            CheatKind::Toggle { target, hook, enabled, original_bytes, .. } => {
                // T-112: Hotkey toggle drives the real cave — install on enable, restore on disable.
                let new_state = !enabled;
                if new_state {
                    // Enable: install the cave.
                    let r = self.request(&Request::InstallCave {
                        target,
                        hook: hook.clone(),
                    });
                    match r {
                        Some(Response::CaveInstalled { cave, original, .. }) => {
                            if let Ok(mut s) = self.session.lock() {
                                s.set_toggle_cave_info(cheat_id, original.clone(), cave);
                                s.set_cheat_toggle(cheat_id, true);
                            }
                            self.log(format!(
                                "hotkey toggled '{}' -> ENABLED (cave @ {cave:#x}, target {target:#x})",
                                label
                            ));
                        }
                        _ => self.log(format!(
                            "hotkey toggle '{}' enable FAILED (cave @ {target:#x})",
                            label
                        )),
                    }
                } else {
                    // Disable: restore original bytes.
                    if !original_bytes.is_empty() {
                        let r = self.request(&Request::Write {
                            address: target,
                            data: original_bytes.clone(),
                        });
                        match r {
                            Some(Response::Write { bytes_written }) => {
                                if let Ok(mut s) = self.session.lock() {
                                    s.set_cheat_toggle(cheat_id, false);
                                }
                                self.log(format!(
                                    "hotkey toggled '{}' -> DISABLED (restored {bytes_written} bytes @ {target:#x})",
                                    label
                                ));
                            }
                            _ => self.log(format!(
                                "hotkey toggle '{}' disable FAILED (restore @ {target:#x})",
                                label
                            )),
                        }
                    } else {
                        self.log(format!(
                            "hotkey toggle '{}' disable: no stored original bytes; use MCP set_cheat_toggle",
                            label
                        ));
                    }
                }
            }
            CheatKind::Patch { target, patch_bytes, original_bytes, enabled, cave_ref } => {
                let new_state = !enabled;
                let desc = cave_ref.as_deref().unwrap_or("fast patch");
                let bytes_to_write = if new_state { patch_bytes } else { original_bytes };
                if !bytes_to_write.is_empty() {
                    let r = self.request(&Request::Write {
                        address: target,
                        data: bytes_to_write,
                    });
                    match r {
                        Some(Response::Write { bytes_written }) => {
                            if let Ok(mut s) = self.session.lock() {
                                s.set_cheat_toggle(cheat_id, new_state);
                            }
                            self.log(format!(
                                "hotkey toggled patch '{}' -> {} ({bytes_written} bytes @ {target:#x}, {desc})",
                                label,
                                if new_state { "ENABLED" } else { "DISABLED" }
                            ));
                        }
                        _ => self.log(format!(
                            "hotkey toggle patch '{}' {} FAILED (@ {target:#x})",
                            label,
                            if new_state { "enable" } else { "disable" }
                        )),
                    }
                }
            }
            CheatKind::Button { commands } => {
                self.log(format!("hotkey triggered button '{}': running {} command(s)...", label, commands.len()));
                if let Err(e) = self.run_cheat_commands(&commands) {
                    self.log(format!("hotkey button '{}' failed: {e}", label));
                }
            }
            CheatKind::Value { address, value_type } => {
                // For value cheats, re-apply the value currently in the edit box if present.
                if let Some(val_str) = self.cheat_values.get(&cheat_id).cloned() {
                    if let Ok(bytes) = parse_value_bytes(&val_str, value_type) {
                        let r = self.request(&Request::Write {
                            address,
                            data: bytes,
                        });
                        match r {
                            Some(Response::Write { bytes_written }) => {
                                self.log(format!("hotkey applied '{}' = {val_str} ({bytes_written} bytes)", label));
                            }
                            _ => self.log(format!("hotkey apply for '{}' failed", label)),
                        }
                    }
                }
            }
        }
    }

    /// Auto-discover running game processes and match against YAML cheat profiles.
    fn auto_match_profile(&mut self) {
        self.game_candidates = inject::find_game_candidates();
        if let Ok(mut s) = self.session.lock() {
            for proc in &self.game_candidates {
                s.record_tracked_app(&proc.name, Some(proc.pid), proc.path.as_deref());
            }
        }
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

    /// Execute a sequence of profile commands.
    /// Returns Ok(()) if all commands succeed, or Err(msg) on the first failure (aborting sequence).
    fn run_cheat_commands(&mut self, cmds: &[profile::ProfileCommand]) -> Result<(), String> {
        mcp::execute_profile_commands(&self.session, cmds)
    }

    /// Allocate string memory in target game process and write bytes.
    fn allocate_string_in_game(&self, content: &str, kind: &str) -> Result<(u64, usize), String> {
        let mut bytes = content.as_bytes().to_vec();
        let kind_lower = kind.trim().to_lowercase();
        let is_c_like = matches!(kind_lower.as_str(), "c" | "json" | "yaml" | "xml" | "js" | "config");
        if is_c_like && !bytes.ends_with(&[0]) {
            bytes.push(0);
        }
        let len = bytes.len();
        let pid = {
            let s = self.session.lock().map_err(|_| "session lock poisoned".to_string())?;
            s.game_pid().ok_or_else(|| "no attached game process".to_string())?
        };

        #[cfg(windows)]
        {
            use windows_sys::Win32::System::Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
            let proc_handle = unsafe {
                windows_sys::Win32::System::Threading::OpenProcess(
                    windows_sys::Win32::System::Threading::PROCESS_VM_OPERATION
                        | windows_sys::Win32::System::Threading::PROCESS_VM_WRITE
                        | windows_sys::Win32::System::Threading::PROCESS_VM_READ,
                    0,
                    pid,
                )
            };
            if proc_handle.is_null() {
                return Err("failed to open process for allocation".into());
            }
            let ptr = unsafe {
                VirtualAllocEx(proc_handle, std::ptr::null(), len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
            };
            unsafe { windows_sys::Win32::Foundation::CloseHandle(proc_handle); }
            if ptr.is_null() {
                return Err("VirtualAllocEx failed".into());
            }
            let alloc_addr = ptr as u64;

            // Write bytes
            let proc = trainlab_core::memory::WindowsProcess::open(pid).map_err(|e| e.to_string())?;
            proc.write(alloc_addr, &bytes).map_err(|e| e.to_string())?;
            Ok((alloc_addr, len))
        }
        #[cfg(not(windows))]
        {
            let _ = pid;
            let _ = bytes;
            Ok((0x10000u64, len))
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
                                                None,
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

    // Check if startup delay is requested via TRAINLAB_STARTUP_DELAY env var
    if let Ok(delay_str) = std::env::var("TRAINLAB_STARTUP_DELAY") {
        if let Ok(delay_secs) = delay_str.parse::<u64>() {
            if delay_secs > 0 {
                tracing::info!("trainlab-gui delaying window startup for {delay_secs} seconds...");
                std::thread::sleep(std::time::Duration::from_secs(delay_secs));
            }
        }
    }

    // One shared session state across the GUI and the MCP server. The GUI sets
    // `game_pid` when it injects the game; the MCP server reads it to open the
    // game process externally for scan-family tools (see D7).
    let session: SharedSession = std::sync::Arc::new(std::sync::Mutex::new(SessionState::new()));

    // Detect launch environment: Gamescope / Steam Deck handheld mode vs Standard Desktop
    let is_gamescope = std::env::var("GAMESCOPE_WAYLAND_DISPLAY").is_ok()
        || std::env::var("SteamGamepadUI").is_ok()
        || std::env::var("STEAM_DECK").is_ok()
        || std::env::var("TRAINLAB_FULLSCREEN").map(|v| v == "1" || v == "true").unwrap_or(false);

    let viewport_builder = egui::ViewportBuilder::default()
        .with_title("trainlab")
        .with_inner_size([1280.0, 800.0])
        .with_min_inner_size([800.0, 540.0]);

    let viewport_builder = if is_gamescope {
        // Dedicated display / Gamescope mode: expand edge-to-edge without letterboxing
        viewport_builder.with_fullscreen(true).with_maximized(true)
    } else {
        // Desktop windowing mode: natural 1280x800 floating window
        viewport_builder.with_maximized(false)
    };

    let options = eframe::NativeOptions {
        viewport: viewport_builder,
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
            let event_ctx = cc.egui_ctx.clone();
            let event_session = session.clone();
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .expect("failed to build MCP tokio runtime");
                rt.block_on(async {
                    // Spawn decoupled event listener task that triggers GUI repaints upon any event.
                    // For WindowVisibility events, also apply Win32 ShowWindow directly so the command
                    // works even when the window is hidden/minimized and eframe's update() isn't running.
                    let mut rx = {
                        let s = event_session.lock().unwrap();
                        s.event_bus().subscribe()
                    };
                    tokio::spawn(async move {
                        while let Ok(evt) = rx.recv().await {
                            // Always request a repaint to keep UI live
                            event_ctx.request_repaint();

                            // Forward relevant session mutations as protocol::Event to the DLL
                            match &evt {
                                crate::event::SessionEvent::CheatUpdated { id, enabled, value, .. } => {
                                    if let Some(en) = enabled {
                                        controller::emit_event_to_dll(&event_session, trainlab_core::protocol::Event::CheatToggled { id: *id, enabled: *en });
                                    }
                                    if let Some(val_str) = value {
                                        let bytes = if let Ok(n) = val_str.parse::<i64>() {
                                            Some(n.to_le_bytes().to_vec())
                                        } else {
                                            None
                                        };
                                        controller::emit_event_to_dll(&event_session, trainlab_core::protocol::Event::CheatValueChanged {
                                            id: *id,
                                            value_str: val_str.clone(),
                                            pinned_bytes: bytes,
                                        });
                                    }
                                }
                                crate::event::SessionEvent::ProfileLoaded { .. } => {
                                    let cheats_dto = if let Ok(s) = event_session.lock() {
                                        s.export_overlay_cheats()
                                    } else {
                                        Vec::new()
                                    };
                                    controller::emit_event_to_dll(&event_session, trainlab_core::protocol::Event::SyncCheats { cheats: cheats_dto });
                                }
                                _ => {}
                            }

                            // Handle window visibility directly via Win32 so it works
                            // even when the window is backgrounded / hidden.
                            #[cfg(windows)]
                            if let crate::event::SessionEvent::WindowVisibility { command } = &evt {
                                use windows_sys::Win32::UI::WindowsAndMessaging::{
                                    FindWindowA, SetForegroundWindow, ShowWindow,
                                    EnumWindows, GetWindowTextA,
                                    SW_HIDE, SW_RESTORE, SW_SHOW,
                                };
                                use windows_sys::Win32::Foundation::{BOOL, LPARAM, HWND};

                                unsafe {
                                    // Helper: Find top-level trainlab window by title
                                    unsafe extern "system" fn enum_win_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
                                        let mut buf = [0u8; 128];
                                        let len = unsafe { GetWindowTextA(hwnd, buf.as_mut_ptr(), buf.len() as i32) };
                                        if len > 0 {
                                            let title = String::from_utf8_lossy(&buf[..len as usize]);
                                            if title.to_lowercase().contains("trainlab") {
                                                unsafe {
                                                    *(lparam as *mut HWND) = hwnd;
                                                }
                                                return 0; // stop enumeration
                                            }
                                        }
                                        1 // continue
                                    }

                                    let mut found_hwnd: HWND = std::ptr::null_mut();
                                    // Try FindWindowA with class NULL and title "trainlab" first
                                    let mut hwnd = FindWindowA(
                                        std::ptr::null(),
                                        b"trainlab\0".as_ptr(),
                                    );
                                    if hwnd.is_null() {
                                        // Fall back to enumerating top-level windows
                                        EnumWindows(Some(enum_win_proc), &mut found_hwnd as *mut _ as LPARAM);
                                        hwnd = found_hwnd;
                                    }

                                    if !hwnd.is_null() {
                                        if command == "hide" {
                                            ShowWindow(hwnd, SW_HIDE);
                                        } else {
                                            ShowWindow(hwnd, SW_SHOW);
                                            ShowWindow(hwnd, SW_RESTORE);
                                            SetForegroundWindow(hwnd);
                                        }
                                    }
                                }
                            }
                        }
                    });

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

#[cfg(windows)]
fn is_trainer_focused() -> Option<bool> {
    use windows_sys::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowThreadProcessId};
    use windows_sys::Win32::System::Threading::GetCurrentProcessId;
    unsafe {
        let fg_hwnd = GetForegroundWindow();
        if fg_hwnd.is_null() {
            return None;
        }
        let mut fg_pid: u32 = 0;
        GetWindowThreadProcessId(fg_hwnd, &mut fg_pid);
        let my_pid = GetCurrentProcessId();
        Some(fg_pid == my_pid)
    }
}

#[cfg(not(windows))]
fn is_trainer_focused() -> Option<bool> {
    None
}

impl eframe::App for TrainlabApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Keep UI active and responsive to background thread status updates (20 Hz repaint cadence)
        ctx.request_repaint_after(std::time::Duration::from_millis(50));

        // Check window OS focus state to ensure controller / navigation inputs
        // only affect the GUI when the trainer window is focused.
        // Prefer Win32 foreground PID check if available, falling back to egui viewport focus.
        let is_focused = is_trainer_focused().unwrap_or_else(|| ctx.input(|i| i.viewport().focused.unwrap_or(true)));

        // Sync focus/visibility state to injected DLL so XInput controller inputs
        // are masked from the background game only when state transitions.
        if self.connected {
            let active_mask = is_focused && self.window_visible;
            if self.last_synced_mask != Some(active_mask) {
                self.last_synced_mask = Some(active_mask);
                controller::emit_event_to_dll(&self.session, trainlab_core::protocol::Event::OverlayVisibilityChanged {
                    visible: active_mask,
                });
            }
        }

        // Process remote window visibility commands from REST API / MCP / Web Dashboard
        if let Ok(mut s) = self.session.lock() {
            if let Some(cmd) = s.take_window_cmd() {
                if cmd == "show" {
                    s.log_activity("GUI", "executing remote 'show' window command");
                    self.window_visible = true;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                } else if cmd == "hide" {
                    s.log_activity("GUI", "executing remote 'hide' window command");
                    self.window_visible = false;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
                }
            }
        }

        // Poll Win32 WM_HOTKEY message queue for global hotkeys (works even when window is hidden/unmapped)
        if let Some(hotkey_id) = hotkeys::poll_wm_hotkey() {
            if hotkey_id == 9999 { // ID 9999 is the global window-toggle key ('J')
                self.window_visible = !self.window_visible;
                if self.window_visible {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                } else {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
                }
            } else if let Some(reg) = self.registered_hotkeys.get(&hotkey_id) {
                let cheat_id = reg.cheat_id;
                self.trigger_cheat(cheat_id);
            }
        }

        // T-163: The global hotkey (ID 9999, 'J') already handles window toggle.
        // The focused 'J' handler was removed to prevent double-toggle.

        // Handle keyboard tab switching (PageUp/PageDown, Q/E) when user is not typing in a text field.
        if !ctx.wants_keyboard_input() {
            ctx.input(|i| {
                if i.key_pressed(egui::Key::Escape) {
                    self.window_visible = false;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
                } else if i.key_pressed(egui::Key::PageDown) || i.key_pressed(egui::Key::Q) {
                    self.active_tab = match self.active_tab {
                        ActiveTab::Cheats => ActiveTab::MemoryScan,
                        ActiveTab::MemoryScan => ActiveTab::TaggedMarkers,
                        ActiveTab::TaggedMarkers => ActiveTab::PointersInspection,
                        ActiveTab::PointersInspection => ActiveTab::RunApplications,
                        ActiveTab::RunApplications => ActiveTab::ActivityLog,
                        ActiveTab::ActivityLog => ActiveTab::Cheats,
                    };
                } else if i.key_pressed(egui::Key::PageUp) || i.key_pressed(egui::Key::E) {
                    self.active_tab = match self.active_tab {
                        ActiveTab::Cheats => ActiveTab::ActivityLog,
                        ActiveTab::MemoryScan => ActiveTab::Cheats,
                        ActiveTab::TaggedMarkers => ActiveTab::MemoryScan,
                        ActiveTab::PointersInspection => ActiveTab::TaggedMarkers,
                        ActiveTab::RunApplications => ActiveTab::PointersInspection,
                        ActiveTab::ActivityLog => ActiveTab::RunApplications,
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

                ui.separator();
                if ui.button("👁 Background Me (Esc to restore)").clicked() {
                    self.window_visible = false;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
                }

                if self.connected {
                    ui.separator();
                    if ui.button("Disconnect").clicked() {
                        if let Ok(mut s) = self.session.lock() {
                            s.set_connected(false);
                            s.set_game_pid(None);
                            s.clear_cheats();
                            s.clear_markers();
                        }
                        self.connected = false;
                        self.status = "disconnected".into();
                        self.refresh_game_candidates();
                        self.auto_match_profile();
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

                        ui.add_space(3.0);
                        ui.checkbox(&mut self.auto_init, "Auto-run profile initialization commands on connect");

                        ui.add_space(5.0);
                        let attaching = self.is_attaching.load(std::sync::atomic::Ordering::Relaxed);
                        if attaching {
                            ui.horizontal(|ui| {
                                ui.spinner();
                                ui.colored_label(egui::Color32::LIGHT_BLUE, "⏳ Injecting & Initializing Profile in background...");
                            });
                        } else {
                            if ui.button("🚀 Find & Inject DLL").clicked() {
                                self.inject_and_connect();
                            }
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
                    ui.selectable_value(&mut self.active_tab, ActiveTab::MemoryScan, "🔍 Memory Scanning");
                    ui.selectable_value(&mut self.active_tab, ActiveTab::TaggedMarkers, "📌 Tagged Markers");
                    ui.selectable_value(&mut self.active_tab, ActiveTab::PointersInspection, "🎯 Pointers & Inspection");
                    ui.selectable_value(&mut self.active_tab, ActiveTab::RunApplications, "🚀 Applications");
                    ui.selectable_value(&mut self.active_tab, ActiveTab::ActivityLog, "📋 Activity Log");
                });

            egui::CentralPanel::default().show(ctx, |ui| {
                egui::ScrollArea::both().show(ui, |ui| {
                    match self.active_tab {
                        ActiveTab::Cheats => {
                            self.show_cheats_panel(ui, ctx);
                        }
                        ActiveTab::MemoryScan => {
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
                        }
                        ActiveTab::TaggedMarkers => {
                            self.show_session_panel(ui);
                        }
                        ActiveTab::PointersInspection => {
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
                                                format!("{bytes_written} bytes written")
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
                        ActiveTab::RunApplications => {
                            self.show_run_applications_panel(ui);
                        }
                        ActiveTab::ActivityLog => {
                            ui.heading("📋 Activity & Event Log");
                            ui.label("Full history of human UI actions and MCP agent commands executed in this session:");
                            ui.add_space(5.0);

                            let activity_log = self
                                .session
                                .lock()
                                .map(|s| s.list_activity_log())
                                .unwrap_or_default();
                            egui::ScrollArea::both()
                                .max_height(500.0)
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
                        }
                    }
                });
            });
        }
    }
}

impl TrainlabApp {
    /// Render the Applications & Binary Launcher panel.
    fn show_run_applications_panel(&mut self, ui: &mut egui::Ui) {
        ui.heading("🚀 Applications & Process Launcher");
        ui.label("Launch helper processes, anticheat bypasses, or restart target game binaries directly from trainlab.");
        ui.add_space(10.0);

        ui.group(|ui| {
            ui.heading("Run Application by Path");
            ui.add_space(5.0);
            ui.horizontal(|ui| {
                ui.label("Binary Path:");
                ui.text_edit_singleline(&mut self.custom_app_path);
            });
            ui.horizontal(|ui| {
                ui.label("Arguments (opt):");
                ui.text_edit_singleline(&mut self.custom_app_args);
            });
            ui.add_space(5.0);
            if ui.button("🚀 Launch Application").clicked() {
                let path = self.custom_app_path.trim().to_string();
                let args: Vec<String> = self.custom_app_args.split_whitespace().map(|s| s.to_string()).collect();
                if !path.is_empty() {
                    let res = if let Ok(mut s) = self.session.lock() {
                        s.launch_application(&path, &args)
                    } else {
                        Err("session lock poisoned".into())
                    };
                    match res {
                        Ok(pid) => {
                            self.log(format!("launched '{path}' (PID {pid})"));
                        }
                        Err(e) => {
                            self.log(format!("launch failed: {e}"));
                        }
                    }
                }
            }
        });

        ui.add_space(15.0);

        let tracked = self.session.lock().map(|s| s.list_tracked_apps()).unwrap_or_default();
        let profiles = profile::discover_profiles();

        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.heading(format!("Tracked Session Binaries & Processes ({})", tracked.len()));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("🔄 Scan Running Processes").clicked() {
                        self.refresh_game_candidates();
                    }
                });
            });
            ui.label("Binaries discovered during process scans or launched in this session:");
            ui.add_space(5.0);

            if tracked.is_empty() {
                ui.horizontal(|ui| {
                    ui.colored_label(egui::Color32::GRAY, "No tracked binaries in session.");
                    if ui.button("Scan running processes now").clicked() {
                        self.refresh_game_candidates();
                    }
                });
            } else {
                egui::ScrollArea::vertical().max_height(250.0).show(ui, |ui| {
                    for app in &tracked {
                        ui.horizontal(|ui| {
                            ui.label(format!("• {}", app.name));
                            if let Some(pid) = app.pid {
                                ui.colored_label(egui::Color32::LIGHT_GREEN, format!("(PID {pid})"));
                            }
                            if let Some(path) = &app.path {
                                ui.monospace(path);
                            }
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                let launch_target = app.path.as_deref().unwrap_or(&app.name).to_string();
                                if ui.button("▶ Re-Launch").clicked() {
                                    if let Ok(mut s) = self.session.lock() {
                                        let _ = s.launch_application(&launch_target, &[]);
                                    }
                                }
                            });
                        });
                    }
                });
            }
        });

        if !profiles.is_empty() {
            ui.add_space(15.0);
            ui.group(|ui| {
                ui.heading(format!("Game Profiles Known to Trainlab ({})", profiles.len()));
                ui.label("Games with configured YAML cheat tables ready to launch & attach:");
                ui.add_space(5.0);

                egui::ScrollArea::vertical().max_height(200.0).show(ui, |ui| {
                    for (file, prof) in &profiles {
                        ui.horizontal(|ui| {
                            ui.label(format!("🎮 {}", prof.name));
                            ui.colored_label(egui::Color32::LIGHT_BLUE, format!("({})", prof.game));
                            ui.monospace(file);

                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                let game_exe = prof.game.clone();
                                if ui.button("🚀 Launch Game").clicked() {
                                    if let Ok(mut s) = self.session.lock() {
                                        let _ = s.launch_application(&game_exe, &[]);
                                    }
                                }
                            });
                        });
                    }
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
    // T-161: Guard against short reads — show "?" if data is too short.
    let need = vt.size();
    if data.len() < need {
        return "?".to_string();
    }
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
