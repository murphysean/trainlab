//! Session state for the trainlab MCP server.
//!
//! Per design decisions D7 and D8, the *Trainer* (not the LLM) holds session
//! state: labeled markers for addresses that persist across turns, and an undo
//! log that records the original bytes of every mutation so it can be reverted.
//!
//! This state lives in an `Arc<Mutex<SessionState>>` shared by the MCP server
//! handler, so an agent can set markers, list them, and (once mutating tools
//! exist) record/apply undo operations.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};
use crate::{cave_hook, protocol, scan};

/// The semantic kind of a [`Marker`], describing what the marked address represents.
///
/// Used by tools such as `pointer_chase` to determine whether the base address
/// should be dereferenced (pointer slot) or used directly (live object instance).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MarkerKind {
    /// A pointer slot — the marker address holds a pointer value that must be
    /// dereferenced to reach the object. This is the traditional CE
    /// `module+offset` starting point. (default)
    #[default]
    Pointer,
    /// A live object instance — the marker address IS the object base and
    /// offsets are applied directly without a prior dereference. Set this when
    /// you have found the actual struct/class instance address (e.g. via AOB
    /// + follow, or pointer_scan result).
    Object,
    /// A contiguous memory buffer or allocation (strings, ring buffers, heaps).
    /// `size` is typically set alongside this kind.
    Buffer,
    /// Code / function entry point, trampoline, or hook site.
    Code,
}

impl MarkerKind {
    /// Returns `true` for the default `Pointer` variant (used to skip serialization).
    pub fn is_pointer(&self) -> bool {
        *self == MarkerKind::Pointer
    }
}

/// A labeled address (or address region) the agent persists across turns (D7).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Marker {
    pub address: u64,
    /// Optional byte size of the marked region.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<usize>,
    /// Semantic kind describing what the marked address represents.
    /// Defaults to `Pointer` for backward compatibility.
    #[serde(default, skip_serializing_if = "MarkerKind::is_pointer")]
    pub kind: MarkerKind,
    /// Optional reference to a named [`StructDef`] describing the layout at
    /// this address. Only meaningful when `kind == Object`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub struct_type: Option<String>,
    pub label: String,
    pub note: Option<String>,
}

impl Marker {
    /// Returns the end address if this is a region marker (exclusive: address + size).
    pub fn end_address(&self) -> Option<u64> {
        self.size.map(|s| self.address.saturating_add(s as u64))
    }
}

/// A user-facing, adjustable game option ("cheat") discovered by the agent and
/// surfaced in the GUI's Cheats panel.
///
/// Two kinds:
/// - **Value**: a typed value at an address the user can edit and apply (e.g.
///   set "wood" to 999). The GUI writes it directly (the user is the human
///   confirmation); the MCP `set_cheat_value` stages it through the D8 gate.
/// - **Toggle**: a code-cave hook (e.g. god mode) the user can switch on/off.
#[derive(Debug, Clone)]
pub struct Cheat {
    /// Unique id assigned by the session (monotonic).
    pub id: u64,
    /// Display label (e.g. "wood", "god mode").
    pub label: String,
    /// The kind of cheat.
    pub kind: CheatKind,
    /// Optional grouping/category name (e.g. "In Menu", "In Session", "Player", "Weapons").
    pub group: Option<String>,
    /// Optional hotkey string binding (e.g. "Num 1", "Shift+Alt+K").
    pub hotkey: Option<String>,
    /// Whether this cheat is hidden from user-facing GUI and overlay.
    pub hidden: bool,
    /// Optional human note / description.
    pub note: Option<String>,
}

/// A field inside a clustered struct cheat.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StructField {
    /// Field name / label (e.g. "Health", "Shield", "Mining Speed").
    pub label: String,
    /// Offset expression relative to base or nested bracket expression (e.g. "0x08", "[+0x10] + 0x14").
    pub offset_expr: String,
    /// Value type of this field (i32, f32, etc.).
    pub value_type: crate::scan::ValueType,
}

/// A named struct/object type definition — a reusable layout catalog entry.
///
/// Registered in the session's `struct_defs` map and optionally exported to
/// profiles so that markers, cheats, and tools can reference layouts by type
/// name instead of re-specifying field lists on every call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StructDef {
    /// The unique type name, e.g. "ShipEntity", "PlayerData", "SelectionManager".
    pub name: String,
    /// Total byte size of the struct, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<usize>,
    /// Fields defined within this struct.
    #[serde(default)]
    pub fields: Vec<StructField>,
    /// Optional human note / source comment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// The kind of a cheat.
#[derive(Debug, Clone)]
pub enum CheatKind {
    /// A typed value at an address the user can edit and apply.
    Value {
        /// The address of the value in game memory.
        address: u64,
        /// The value type (i32, f32, etc.).
        value_type: crate::scan::ValueType,
        /// Optional symbolic expression (e.g. "[[[$player_base+0x8]+0x10]+0x14]").
        address_expr: Option<String>,
    },
    /// A clustered struct cheat holding multiple typed fields anchored to a base address/marker.
    Struct {
        /// Base address of the struct instance.
        base_address: u64,
        /// Base marker expression (e.g. "$player_base").
        base_expr: String,
        /// The fields within this struct.
        fields: Vec<StructField>,
    },
    /// A code-cave hook the user can toggle on/off (dynamic install/uninstall).
    Toggle {
        /// The cave hook to install/remove.
        hook: crate::cave_hook::CaveHook,
        /// The target instruction address the cave redirects.
        target: u64,
        /// Whether the toggle is currently active.
        enabled: bool,
        /// Original bytes at the target before the cave was installed.
        /// Populated when the cave is confirmed/installed so it can be
        /// restored on disable. Empty if no cave is currently installed.
        #[allow(dead_code)]
        original_bytes: Vec<u8>,
        /// The allocated cave address (from CaveInstalled response).
        /// Zero if no cave is currently installed.
        #[allow(dead_code)]
        cave_addr: u64,
    },
    /// A pre-allocated / pre-configured code patch toggle (zero-alloc fast toggle).
    /// Used for games like DRG: Survivor where caves are allocated at startup with named markers,
    /// and the toggle simply writes `patch_bytes` (on) or `original_bytes` (off) to `target`.
    Patch {
        /// Target code address to patch.
        target: u64,
        /// Bytes to write when toggled ON (e.g. 5-byte/7-byte jump or NOPs).
        patch_bytes: Vec<u8>,
        /// Original bytes to restore when toggled OFF.
        original_bytes: Vec<u8>,
        /// Whether the patch is currently active.
        enabled: bool,
        /// Optional named cave marker or description.
        cave_ref: Option<String>,
    },
    /// An action button that runs a sequence of commands when clicked.
    Button {
        /// Sequence of commands to execute.
        commands: Vec<crate::profile::ProfileCommand>,
    },
}

/// A single undoable mutation: the original bytes at an address.
///
/// Undoing means writing `original_bytes` back to `address`. The undo log is
/// a safety contract (D8): every write/cave operation snapshots original bytes
/// and can be reverted.
#[derive(Debug, Clone)]
pub struct UndoEntry {
    /// Unique id assigned by the session (monotonic).
    pub id: u64,
    pub address: u64,
    pub original_bytes: Vec<u8>,
    pub description: String,
}

/// A staged, uncommitted mutation awaiting human confirmation (D8).
///
/// Mutating MCP tools (`write` / `install_cave` / `undo`) no longer apply
/// immediately: they stage a [`PendingOp`] and return its id + a human-readable
/// preview. A separate `confirm_op` tool applies it (recording an undo entry);
/// `reject_op` discards it. This is the confirmation gate — an agent *proposes*,
/// a human *confirms*.
#[derive(Debug, Clone)]
pub struct PendingOp {
    /// Unique id assigned by the session (monotonic).
    pub id: u64,
    /// The address the mutation targets.
    pub address: u64,
    /// The kind of pending mutation.
    pub kind: PendingKind,
    /// Human-readable preview of what will happen (shown to the user for
    /// confirmation).
    pub preview: String,
    /// Optional cheat id associated with this op (used by toggle cheats
    /// so confirm_op can update the cheat's enabled state + cave info).
    pub cheat_id: Option<u64>,
}

/// The kind of a staged mutation.
#[derive(Debug, Clone)]
pub enum PendingKind {
    /// Write raw bytes to `address`.
    Write { data: Vec<u8> },
    /// Install a code-cave hook at `address`.
    InstallCave {
        hook: cave_hook::CaveHook,
        marker: Option<String>,
        label_offsets: std::collections::HashMap<String, u64>,
    },
    /// Revert a previously-applied mutation by writing `original_bytes` back.
    Undo { original_bytes: Vec<u8> },
}

impl PendingKind {
    /// A short human-readable name for the kind (used in previews/logs).
    pub fn kind_text(&self) -> &'static str {
        match self {
            PendingKind::Write { .. } => "write",
            PendingKind::InstallCave { .. } => "install_cave",
            PendingKind::Undo { .. } => "undo",
        }
    }
}

/// Origin kind of a client / consumer connecting to the session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientKind {
    Gui,
    Mcp { agent_name: Option<String> },
    Web { session_id: String },
    Cli,
    Overlay,
    Internal,
}

/// An isolated handle/state for an active connection or consumer.
#[derive(Debug)]
pub struct ClientContext {
    /// Unique context ID (e.g., "mcp-claude-1", "web-tab-42", "gui-main").
    pub id: String,
    /// Origin kind.
    pub kind: ClientKind,
    /// Context-scoped active memory scan (so different web tabs or agents don't overwrite each other).
    pub scan: Option<scan::Scan>,
    /// Private event subscriber channel.
    pub event_rx: tokio::sync::broadcast::Receiver<crate::event::BusEvent>,
}

impl ClientContext {
    pub fn new(id: impl Into<String>, kind: ClientKind, event_bus: &crate::event::EventBus) -> Self {
        Self {
            id: id.into(),
            kind,
            scan: None,
            event_rx: event_bus.subscribe(),
        }
    }
}

/// Explicit lifecycle state of the target game process and injector connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[derive(Default)]
pub enum SessionLifecycle {
    /// No target game process is selected.
    #[default]
    Idle,
    /// A target game process is identified; external memory ops (Read/WriteProcessMemory) are active.
    TargetAttached {
        pid: u32,
        exe_name: String,
    },
    /// DLL injected into game process; IPC listener initialized.
    Injected {
        pid: u32,
        exe_name: String,
        dll_path: String,
    },
    /// Live fast-channel IPC connection active (caves, capture rings, overlay active).
    Connected {
        pid: u32,
        exe_name: String,
        dll_version: Option<String>,
    },
    /// Target process terminated or crashed.
    TargetLost {
        pid: u32,
        exe_name: String,
    },
}


/// A tracked memory allocation inside the target process memory (caves, scratch, strings).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllocatedBuffer {
    pub address: u64,
    pub size: usize,
    pub description: String,
    pub marker: Option<String>,
}

/// A summary of reasons why the current session is dirty (holding live modifications/allocations).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DirtyReport {
    /// Active enabled cheats (caves or patches).
    pub active_cheats: Vec<String>,
    /// Unreverted mutations in the undo log.
    pub unreverted_undo_count: usize,
    /// Pending unconfirmed operations.
    pub pending_op_count: usize,
    /// Unfreed memory allocations.
    pub active_allocations: Vec<AllocatedBuffer>,
    /// Active register captures.
    pub active_captures: Vec<u64>,
    /// Active breakpoints / watchpoints.
    pub active_breakpoints: Vec<u64>,
    /// In-progress profile load or initialization operation.
    pub operation_in_progress: Option<String>,
}

impl DirtyReport {
    pub fn is_dirty(&self) -> bool {
        !self.active_cheats.is_empty()
            || self.unreverted_undo_count > 0
            || self.pending_op_count > 0
            || !self.active_allocations.is_empty()
            || !self.active_captures.is_empty()
            || !self.active_breakpoints.is_empty()
            || self.operation_in_progress.is_some()
    }

    pub fn summary(&self) -> String {
        let mut reasons = Vec::new();
        if let Some(op) = &self.operation_in_progress {
            reasons.push(format!("operation '{op}' is currently in progress"));
        }
        if !self.active_cheats.is_empty() {
            reasons.push(format!("{} active cheat(s) enabled: [{}]", self.active_cheats.len(), self.active_cheats.join(", ")));
        }
        if self.unreverted_undo_count > 0 {
            reasons.push(format!("{} unreverted mutation(s) in undo log", self.unreverted_undo_count));
        }
        if self.pending_op_count > 0 {
            reasons.push(format!("{} pending staged mutation(s)", self.pending_op_count));
        }
        if !self.active_allocations.is_empty() {
            reasons.push(format!("{} unfreed memory allocation(s)", self.active_allocations.len()));
        }
        if !self.active_captures.is_empty() {
            reasons.push(format!("{} active register capture(s)", self.active_captures.len()));
        }
        if !self.active_breakpoints.is_empty() {
            reasons.push(format!("{} active breakpoint(s)", self.active_breakpoints.len()));
        }
        if reasons.is_empty() {
            "session is clean".to_string()
        } else {
            reasons.join("; ")
        }
    }
}

/// The shared, mutable session state.
#[derive(Debug, Default)]
pub struct SessionState {
    /// Explicit lifecycle state of the session.
    lifecycle: SessionLifecycle,
    /// Active operation or profile load/initialization in progress.
    operation_in_progress: Option<String>,
    /// Markers keyed by label (case-sensitive).
    markers: BTreeMap<String, Marker>,
    /// Named struct/object type definitions (type catalog), keyed by type name.
    struct_defs: BTreeMap<String, StructDef>,
    /// Undo log in the order mutations were made.
    undo_log: Vec<UndoEntry>,
    /// Monotonic counter for undo ids.
    #[allow(dead_code)] // used by record_undo (mutating tools)
    next_undo_id: u64,
    /// Pending (staged, unconfirmed) mutations awaiting human confirmation (D8).
    pending_ops: Vec<PendingOp>,
    /// Monotonic counter for pending-op ids.
    next_pending_id: u64,
    /// The active value scan (match set), if one is in progress.
    scan: Option<scan::Scan>,
    /// The game process PID that the MCP server opens externally for
    /// scan-family tools (set by the GUI when it finds/injects the game).
    game_pid: Option<u32>,
    /// DLL fast-channel host (set by GUI/controller, read by MCP + controller).
    dll_host: String,
    /// DLL fast-channel port (default 31337).
    dll_port: u16,
    /// True if we have a live connection to the DLL listener.
    connected: bool,
    /// The game executable name the user/agent targeted (e.g. "Unrailed2.exe").
    game_name: String,
    /// The DLL path used for injection.
    dll_path: String,
    /// The DLL's reported version string, once connected.
    inject_version: Option<String>,
    /// User-facing adjustable game options ("cheats") discovered by the agent.
    cheats: Vec<Cheat>,
    /// Monotonic counter for cheat ids.
    next_cheat_id: u64,
    /// Tracked allocations (strings, raw memory buffers) made inside the game process.
    allocated_buffers: Vec<AllocatedBuffer>,
    /// Tracked active passive register capture IDs.
    active_captures: BTreeSet<u64>,
    /// Tracked active code breakpoints or watchpoint targets.
    active_breakpoints: BTreeSet<u64>,
    /// Tracked applications & binaries discovered during process scans or launched manually.
    tracked_apps: Vec<DiscoveredApp>,
    /// Active profile name.
    profile_name: Option<String>,
    /// Active profile version.
    profile_version: Option<String>,
    /// Active profile game version.
    profile_game_version: Option<String>,
    /// Active profile author.
    profile_author: Option<String>,
    /// Active profile date.
    profile_date: Option<String>,
    /// Advertised capabilities reported by the injected DLL over IPC.
    dll_capabilities: Vec<String>,
    /// Network traffic capture log (ring buffer capped at capacity).
    network_packets: Vec<crate::protocol::NetworkPacketDto>,
    /// Capacity limit for in-memory network packet ring buffer.
    network_packets_capacity: usize,
    /// Next monotonic ID for captured network packets.
    next_network_packet_id: u64,
    /// Whether network traffic interception hooks are enabled.
    network_hooks_enabled: bool,
    /// Active setup steps currently associated with the session.
    setup_steps: Vec<crate::profile::SetupStep>,
    /// Active initialization commands associated with the session.
    init_commands: Option<Vec<crate::profile::ProfileCommand>>,
    /// Active render configuration associated with the session.
    profile_render: Option<crate::profile::RenderConfig>,
    /// Pending window command requested remotely via REST API or MCP ("show" or "hide").
    pending_window_cmd: Option<String>,
    /// Active dynamic memory pins maintained by the session.
    pins: Vec<crate::protocol::PinSpec>,
    /// Monotonic counter for pin ids.
    next_pin_id: u64,
    /// Unified activity log (sourced as "UI: ..." or "MCP: ...").
    activity_log: Vec<String>,
    /// Decoupled event bus for publishing session mutations.
    event_bus: crate::event::EventBus,
}

/// A tracked application or binary discovered in process scans or launched via trainlab.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DiscoveredApp {
    pub name: String,
    pub pid: Option<u32>,
    pub path: Option<String>,
    pub last_seen: String,
}

impl SessionState {
    /// Create and register a new client context with its own private event subscriber.
    pub fn create_context(&mut self, id: impl Into<String>, kind: ClientKind) -> ClientContext {
        let id_str = id.into();
        self.log_activity(&id_str, format!("client context created ({:?})", kind));
        ClientContext::new(id_str, kind, &self.event_bus)
    }

    /// Check if the session is currently dirty (holds live modifications, active caves, or unfreed buffers).
    pub fn check_dirty(&self) -> DirtyReport {
        let active_cheats: Vec<String> = self.cheats.iter().filter_map(|c| {
            match &c.kind {
                CheatKind::Toggle { enabled, .. } if *enabled => Some(format!("#{} '{}' (toggle)", c.id, c.label)),
                CheatKind::Patch { enabled, .. } if *enabled => Some(format!("#{} '{}' (patch)", c.id, c.label)),
                _ => None,
            }
        }).collect();

        DirtyReport {
            active_cheats,
            unreverted_undo_count: self.undo_log.len(),
            pending_op_count: self.pending_ops.len(),
            active_allocations: self.allocated_buffers.clone(),
            active_captures: self.active_captures.iter().cloned().collect(),
            active_breakpoints: self.active_breakpoints.iter().cloned().collect(),
            operation_in_progress: self.operation_in_progress.clone(),
        }
    }

    /// Check what operation is currently in progress, if any.
    pub fn operation_in_progress(&self) -> Option<&str> {
        self.operation_in_progress.as_deref()
    }

    /// Set or clear the active operation in progress (e.g. profile loading or DLL initialization).
    pub fn set_operation_in_progress(&mut self, op: Option<String>) {
        self.operation_in_progress = op;
    }

    /// Record a memory buffer allocation made inside the target process.
    pub fn record_allocation(&mut self, address: u64, size: usize, description: impl Into<String>, marker: Option<String>) {
        self.allocated_buffers.push(AllocatedBuffer {
            address,
            size,
            description: description.into(),
            marker,
        });
    }

    /// Remove a recorded memory buffer allocation.
    pub fn remove_allocation(&mut self, address: u64) -> Option<AllocatedBuffer> {
        let idx = self.allocated_buffers.iter().position(|a| a.address == address)?;
        Some(self.allocated_buffers.remove(idx))
    }

    /// List all tracked memory allocations in the target process.
    pub fn list_allocations(&self) -> &[AllocatedBuffer] {
        &self.allocated_buffers
    }

    /// Record an active register capture ID.
    pub fn record_capture(&mut self, id: u64) {
        self.active_captures.insert(id);
    }

    /// Remove a register capture ID upon uninstallation.
    pub fn remove_capture(&mut self, id: u64) {
        self.active_captures.remove(&id);
    }

    /// Record an active breakpoint or watchpoint address.
    pub fn record_breakpoint(&mut self, address: u64) {
        self.active_breakpoints.insert(address);
    }

    /// Clear all active breakpoints / watchpoints.
    pub fn clear_all_breakpoints(&mut self) {
        self.active_breakpoints.clear();
    }

    /// Access the current session lifecycle state.
    pub fn lifecycle(&self) -> &SessionLifecycle {
        &self.lifecycle
    }

    /// Update the session lifecycle state and broadcast an event.
    pub fn set_lifecycle(&mut self, lifecycle: SessionLifecycle) {
        let state_name = match &lifecycle {
            SessionLifecycle::Idle => "idle",
            SessionLifecycle::TargetAttached { .. } => "target_attached",
            SessionLifecycle::Injected { .. } => "injected",
            SessionLifecycle::Connected { .. } => "connected",
            SessionLifecycle::TargetLost { .. } => "target_lost",
        };
        let pid = match &lifecycle {
            SessionLifecycle::TargetAttached { pid, .. }
            | SessionLifecycle::Injected { pid, .. }
            | SessionLifecycle::Connected { pid, .. }
            | SessionLifecycle::TargetLost { pid, .. } => Some(*pid),
            SessionLifecycle::Idle => None,
        };
        let exe = match &lifecycle {
            SessionLifecycle::TargetAttached { exe_name, .. }
            | SessionLifecycle::Injected { exe_name, .. }
            | SessionLifecycle::Connected { exe_name, .. }
            | SessionLifecycle::TargetLost { exe_name, .. } => exe_name.clone(),
            SessionLifecycle::Idle => String::new(),
        };

        self.lifecycle = lifecycle;
        self.event_bus.emit_session(crate::event::SessionEvent::LifecycleChanged {
            state: state_name.to_string(),
            pid,
            exe,
        });
    }

    /// Validate if the target process is still running; transitions to TargetLost if it terminated.
    pub fn validate_target_alive(&mut self) -> bool {
        if let Some(pid) = self.game_pid() {
            let is_alive = crate::process::is_pid_alive(pid);
            if !is_alive {
                let exe = self.game_name.clone();
                self.log_activity("SYSTEM", format!("target process '{exe}' (PID {pid}) terminated"));
                self.set_lifecycle(SessionLifecycle::TargetLost { pid, exe_name: exe });
                self.game_pid = None;
                self.connected = false;
                return false;
            }
            return true;
        }
        false
    }
    /// Publish an arbitrary event onto the session event bus.
    pub fn publish_event(&self, event: crate::event::BusEvent) {
        self.event_bus.emit(event);
    }

    /// Log an activity entry tagged by source (e.g., "UI", "MCP").
    pub fn log_activity(&mut self, source: &str, msg: impl Into<String>) {
        let msg_str = msg.into();
        let formatted = format!("[{source}] {msg_str}");

        // 1. Print to stdout so Steam / Wine logs capture all activity
        println!("{formatted}");

        // 2. Append to trainlab_session.log on disk (available via HTTP download)
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("trainlab_session.log")
            .and_then(|mut f| {
                use std::io::Write;
                writeln!(f, "{formatted}")
            });

        self.activity_log.push(formatted.clone());
        if self.activity_log.len() > 1000 {
            self.activity_log.remove(0);
        }
        
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        self.publish_event(crate::event::BusEvent::Log(crate::event::LogEvent {
            source: source.to_string(),
            message: msg_str,
            timestamp_ms: now_ms,
        }));
        self.publish_event(crate::event::BusEvent::Session(crate::event::SessionEvent::ActivityLogged { entry: formatted }));
    }

    /// Access the event bus for subscribing or emitting events.
    pub fn event_bus(&self) -> &crate::event::EventBus {
        &self.event_bus
    }

    /// Retrieve a snapshot of the current activity log entries.
    pub fn list_activity_log(&self) -> Vec<String> {
        self.activity_log.clone()
    }

    /// Request a window visibility command ("show" or "hide").
    pub fn request_window_cmd(&mut self, cmd: impl Into<String>) {
        let cmd_str = cmd.into();
        self.log_activity("WINDOW", format!("remote requested window command: {cmd_str}"));
        self.event_bus.emit_session(crate::event::SessionEvent::WindowVisibility { command: cmd_str.clone() });
        self.pending_window_cmd = Some(cmd_str);
    }

    /// Pop any pending window command for execution by the GUI thread loop.
    pub fn take_window_cmd(&mut self) -> Option<String> {
        self.pending_window_cmd.take()
    }

    /// Record or update a discovered application in the session tracking list.
    pub fn record_tracked_app(&mut self, name: &str, pid: Option<u32>, path: Option<&str>) {
        let name_str = name.trim().to_string();
        let path_str = path.map(|p| p.trim().to_string());
        let now = chrono::Local::now().format("%H:%M:%S").to_string();

        if let Some(existing) = self.tracked_apps.iter_mut().find(|a| a.name.eq_ignore_ascii_case(&name_str)) {
            if pid.is_some() { existing.pid = pid; }
            if path_str.is_some() { existing.path = path_str; }
            existing.last_seen = now;
        } else {
            self.tracked_apps.push(DiscoveredApp {
                name: name_str,
                pid,
                path: path_str,
                last_seen: now,
            });
        }
    }

    /// Retrieve a list of all tracked applications.
    pub fn list_tracked_apps(&self) -> Vec<DiscoveredApp> {
        self.tracked_apps.clone()
    }

    /// Launch an application binary by path or name with optional arguments.
    pub fn launch_application(&mut self, app_path: &str, args: &[String]) -> Result<u32, String> {
        let app_path = app_path.trim();
        if app_path.is_empty() {
            return Err("application path cannot be empty".into());
        }

        self.log_activity("LAUNCH", format!("launching binary '{app_path}' with args {:?}", args));

        let mut cmd = std::process::Command::new(app_path);
        cmd.args(args);
        let child = cmd.spawn().map_err(|e| format!("failed to spawn '{app_path}': {e}"))?;
        let pid = child.id();

        let name = std::path::Path::new(app_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(app_path)
            .to_string();

        self.record_tracked_app(&name, Some(pid), Some(app_path));
        self.log_activity("LAUNCH", format!("successfully spawned '{name}' (PID {pid})"));

        self.event_bus.emit_session(crate::event::SessionEvent::AppLaunched {
            name: name.clone(),
            path: app_path.to_string(),
            pid: Some(pid),
        });

        Ok(pid)
    }
    /// Set the game process PID that scan-family tools target.
    pub fn set_game_pid(&mut self, pid: Option<u32>) {
        self.game_pid = pid;
        if let Some(p) = pid {
            if matches!(self.lifecycle, SessionLifecycle::Idle | SessionLifecycle::TargetLost { .. }) {
                let name = self.game_name.clone();
                self.set_lifecycle(SessionLifecycle::TargetAttached {
                    pid: p,
                    exe_name: name,
                });
            }
        } else if matches!(self.lifecycle, SessionLifecycle::TargetAttached { .. } | SessionLifecycle::Connected { .. }) {
            self.set_lifecycle(SessionLifecycle::Idle);
        }
    }

    /// Get the game process PID.
    pub fn game_pid(&self) -> Option<u32> {
        self.game_pid
    }

    /// Set the DLL fast-channel host.
    pub fn set_dll_host(&mut self, host: impl Into<String>) {
        self.dll_host = host.into();
    }

    /// Get the DLL fast-channel host.
    pub fn dll_host(&self) -> &str {
        &self.dll_host
    }

    /// Set the DLL fast-channel port.
    pub fn set_dll_port(&mut self, port: u16) {
        self.dll_port = port;
    }

    /// Get the DLL fast-channel port.
    pub fn dll_port(&self) -> u16 {
        self.dll_port
    }

    /// Mark whether we're connected to the DLL.
    pub fn set_connected(&mut self, connected: bool) {
        self.connected = connected;
        if connected {
            if let Some(pid) = self.game_pid {
                self.set_lifecycle(SessionLifecycle::Connected {
                    pid,
                    exe_name: self.game_name.clone(),
                    dll_version: self.inject_version.clone(),
                });
            }
        } else if matches!(self.lifecycle, SessionLifecycle::Connected { .. }) {
            if let Some(pid) = self.game_pid {
                self.set_lifecycle(SessionLifecycle::TargetAttached {
                    pid,
                    exe_name: self.game_name.clone(),
                });
            } else {
                self.set_lifecycle(SessionLifecycle::Idle);
            }
        }
        self.event_bus.emit_session(crate::event::SessionEvent::ConnectionChanged {
            connected,
            game_name: self.game_name.clone(),
        });
    }

    /// Whether we have a live connection to the DLL.
    pub fn connected(&self) -> bool {
        self.connected
    }

    /// Record the target game name.
    pub fn set_game_name(&mut self, name: impl Into<String>) {
        let name_str = name.into();
        self.game_name = name_str.clone();
        if let SessionLifecycle::TargetAttached { pid, .. } = self.lifecycle {
            self.set_lifecycle(SessionLifecycle::TargetAttached { pid, exe_name: name_str });
        }
    }

    /// Get the target game name.
    pub fn game_name(&self) -> &str {
        &self.game_name
    }

    /// Record the DLL path used for injection.
    pub fn set_dll_path(&mut self, path: impl Into<String>) {
        self.dll_path = path.into();
    }

    /// Get the DLL path.
    pub fn dll_path(&self) -> &str {
        &self.dll_path
    }

    /// Record the DLL's reported version.
    pub fn set_inject_version(&mut self, version: Option<String>) {
        self.inject_version = version;
    }

    /// Get the DLL's reported version.
    pub fn inject_version(&self) -> Option<&str> {
        self.inject_version.as_deref()
    }

    /// Record the capabilities advertised by the DLL.
    pub fn set_dll_capabilities(&mut self, capabilities: Vec<String>) {
        self.dll_capabilities = capabilities;
    }

    /// Retrieve the capabilities advertised by the DLL.
    pub fn dll_capabilities(&self) -> &[String] {
        &self.dll_capabilities
    }

    /// Check whether the connected DLL advertises a given capability (e.g. "network_capture").
    pub fn has_capability(&self, cap: &str) -> bool {
        self.dll_capabilities.iter().any(|c| c.eq_ignore_ascii_case(cap))
    }

    /// Record a captured network packet into the session ring buffer.
    pub fn record_network_packet(&mut self, mut packet: crate::protocol::NetworkPacketDto) -> u64 {
        if packet.id == 0 {
            self.next_network_packet_id = self.next_network_packet_id.saturating_add(1);
            packet.id = self.next_network_packet_id;
        } else if packet.id >= self.next_network_packet_id {
            self.next_network_packet_id = packet.id + 1;
        }

        let cap = if self.network_packets_capacity == 0 { 2000 } else { self.network_packets_capacity };
        if self.network_packets.len() >= cap {
            self.network_packets.remove(0);
        }
        let id = packet.id;
        self.network_packets.push(packet);
        id
    }

    /// List captured network packets with optional filtering and pagination.
    pub fn list_network_packets(
        &self,
        limit: Option<usize>,
        offset: Option<usize>,
        filter_proto: Option<crate::protocol::PacketKind>,
        filter_endpoint: Option<&str>,
    ) -> (Vec<crate::protocol::NetworkPacketDto>, usize) {
        let ep_lower = filter_endpoint.map(|e| e.trim().to_lowercase());
        let filtered: Vec<crate::protocol::NetworkPacketDto> = self.network_packets.iter().filter(|p| {
            if let Some(proto) = filter_proto {
                if p.kind != proto {
                    return false;
                }
            }
            if let Some(ref ep) = ep_lower {
                if !ep.is_empty() {
                    let remote_match = p.remote_endpoint.as_deref().map_or(false, |r| r.to_lowercase().contains(ep));
                    let local_match = p.local_endpoint.as_deref().map_or(false, |l| l.to_lowercase().contains(ep));
                    let url_match = p.url.as_deref().map_or(false, |u| u.to_lowercase().contains(ep));
                    if !remote_match && !local_match && !url_match {
                        return false;
                    }
                }
            }
            true
        }).cloned().collect();

        let total = filtered.len();
        let off = offset.unwrap_or(0);
        let lim = limit.unwrap_or(50);

        let slice = filtered.into_iter().skip(off).take(lim).collect();
        (slice, total)
    }

    /// Clear the network packet ring buffer. Returns the count of cleared packets.
    pub fn clear_network_packets(&mut self) -> usize {
        let count = self.network_packets.len();
        self.network_packets.clear();
        count
    }

    /// Check if network hooks are enabled.
    pub fn network_hooks_enabled(&self) -> bool {
        self.network_hooks_enabled
    }

    /// Enable or disable network traffic hooks.
    pub fn set_network_hooks_enabled(&mut self, enabled: bool) {
        self.network_hooks_enabled = enabled;
    }

    /// Set active profile metadata and setup steps.
    pub fn set_active_profile(&mut self, profile: &crate::profile::GameProfile) {
        self.profile_name = Some(profile.name.clone());
        self.profile_version = Some(profile.version.clone());
        self.profile_game_version = profile.game_version.clone();
        self.profile_author = profile.author.clone();
        self.profile_date = profile.date.clone();
        self.setup_steps = profile.setup.clone();
        self.init_commands = profile.init_commands.clone();
        self.profile_render = profile.render.clone();
    }

    /// Access active setup steps.
    pub fn setup_steps(&self) -> &[crate::profile::SetupStep] {
        &self.setup_steps
    }

    /// Set active setup steps.
    pub fn set_setup_steps(&mut self, steps: Vec<crate::profile::SetupStep>) {
        self.setup_steps = steps;
    }

    /// Access active profile metadata.
    pub fn profile_name(&self) -> Option<&str> {
        self.profile_name.as_deref()
    }
    pub fn profile_version(&self) -> Option<&str> {
        self.profile_version.as_deref()
    }
    pub fn profile_game_version(&self) -> Option<&str> {
        self.profile_game_version.as_deref()
    }
    pub fn profile_author(&self) -> Option<&str> {
        self.profile_author.as_deref()
    }
    pub fn profile_date(&self) -> Option<&str> {
        self.profile_date.as_deref()
    }
    pub fn init_commands(&self) -> Option<&[crate::profile::ProfileCommand]> {
        self.init_commands.as_deref()
    }
    pub fn profile_render(&self) -> Option<&crate::profile::RenderConfig> {
        self.profile_render.as_ref()
    }

    pub fn new() -> Self {
        Self::default()
    }

    /// Set (create or overwrite) a marker by label.
    pub fn set_marker(
        &mut self,
        label: &str,
        address: u64,
        note: Option<&str>,
    ) -> Result<(), String> {
        self.set_marker_region(label, address, None, note)
    }

    /// Set (create or overwrite) a marker by label with an optional region size.
    pub fn set_marker_region(
        &mut self,
        label: &str,
        address: u64,
        size: Option<usize>,
        note: Option<&str>,
    ) -> Result<(), String> {
        self.set_marker_full(label, address, size, MarkerKind::default(), None, note)
    }

    /// Set (create or overwrite) a marker with full metadata including semantic kind and struct type.
    pub fn set_marker_full(
        &mut self,
        label: &str,
        address: u64,
        size: Option<usize>,
        kind: MarkerKind,
        struct_type: Option<String>,
        note: Option<&str>,
    ) -> Result<(), String> {
        let label = label.trim().to_string();
        if label.is_empty() {
            return Err("marker label cannot be empty".into());
        }
        self.markers.insert(
            label.clone(),
            Marker {
                address,
                size,
                kind,
                struct_type,
                label: label.clone(),
                note: note.map(|s| s.to_string()),
            },
        );
        self.event_bus.emit_session(crate::event::SessionEvent::MarkerSet {
            name: label.clone(),
            address: match size {
                Some(sz) => format!("{address:#x}..{:#x} (+{sz:#x})", address.saturating_add(sz as u64)),
                None => format!("{address:#x}"),
            },
            note: note.map(|s| s.to_string()),
        });
        Ok(())
    }

    /// Get a marker by label.
    pub fn get_marker(&self, label: &str) -> Option<&Marker> {
        self.markers.get(label.trim())
    }

    /// List all markers sorted by label.
    pub fn list_markers(&self) -> Vec<&Marker> {
        self.markers.values().collect()
    }

    /// Remove a marker by label; returns the removed marker if it existed.
    pub fn remove_marker(&mut self, label: &str) -> Option<Marker> {
        self.markers.remove(label.trim())
    }

    /// Clear all markers.
    pub fn clear_markers(&mut self) {
        self.markers.clear();
    }

    /// Register or overwrite a named struct definition in the type catalog.
    pub fn register_struct_def(&mut self, def: StructDef) {
        self.struct_defs.insert(def.name.clone(), def);
    }

    /// Get a struct definition by type name.
    pub fn get_struct_def(&self, name: &str) -> Option<&StructDef> {
        self.struct_defs.get(name.trim())
    }

    /// List all registered struct definitions sorted by name.
    pub fn list_struct_defs(&self) -> Vec<&StructDef> {
        self.struct_defs.values().collect()
    }

    /// Remove a struct definition by name; returns it if it existed.
    pub fn remove_struct_def(&mut self, name: &str) -> Option<StructDef> {
        self.struct_defs.remove(name.trim())
    }

    /// Record a mutation and return its undo id.
    #[allow(dead_code)] // used once mutating tools exist (T-030+)
    pub fn record_undo(&mut self, address: u64, original_bytes: Vec<u8>, description: String) -> u64 {
        let id = self.next_undo_id;
        self.next_undo_id += 1;
        self.undo_log.push(UndoEntry {
            id,
            address,
            original_bytes,
            description,
        });
        id
    }

    /// Look up an undo entry by id without removing it.
    pub fn get_undo(&self, id: u64) -> Option<&UndoEntry> {
        self.undo_log.iter().find(|e| e.id == id)
    }

    /// Peek at the most recent undo entry without removing it.
    pub fn peek_undo_last(&self) -> Option<&UndoEntry> {
        self.undo_log.last()
    }

    /// Remove and return the most recent undo entry (for reverting it).
    #[allow(dead_code)] // used once mutating tools exist (T-030+)
    pub fn pop_undo_last(&mut self) -> Option<UndoEntry> {
        self.undo_log.pop()
    }

    /// Remove and return a specific undo entry by id (for reverting it).
    #[allow(dead_code)] // used once mutating tools exist (T-030+)
    pub fn pop_undo(&mut self, id: u64) -> Option<UndoEntry> {
        let idx = self.undo_log.iter().position(|e| e.id == id)?;
        Some(self.undo_log.remove(idx))
    }

    /// Remove any undo entries recorded for `address` when the site has been restored.
    pub fn remove_undo_for_target(&mut self, address: u64) {
        self.undo_log.retain(|e| e.address != address);
    }

    /// Get a slice of all recorded undo entries.
    pub fn undo_log(&self) -> &[UndoEntry] {
        &self.undo_log
    }

    /// Find the most recent recorded original bytes for a target address.
    pub fn find_undo_for_target(&self, address: u64) -> Option<Vec<u8>> {
        self.undo_log
            .iter()
            .rev()
            .find(|u| u.address == address && !u.original_bytes.is_empty())
            .map(|u| u.original_bytes.clone())
    }

    /// Number of recorded undo entries.
    #[allow(dead_code)] // used once mutating tools exist
    pub fn undo_len(&self) -> usize {
        self.undo_log.len()
    }

    /// Stage a mutation for later confirmation. Returns its pending id.
    ///
    /// This does *not* apply anything; the caller is expected to show the
    /// returned [`PendingOp`] (its `preview`) to a human for approval before
    /// applying via `confirm_pending`. See D8.
    pub fn stage_op(
        &mut self,
        address: u64,
        kind: PendingKind,
        preview: String,
    ) -> u64 {
        self.stage_op_with_cheat(address, kind, preview, None)
    }

    /// Stage a mutation with an optional associated cheat id (used by toggle
    /// cheats so confirm_op can update the cheat's enabled state + cave info).
    pub fn stage_op_with_cheat(
        &mut self,
        address: u64,
        kind: PendingKind,
        preview: String,
        cheat_id: Option<u64>,
    ) -> u64 {
        let id = self.next_pending_id;
        self.next_pending_id += 1;
        self.pending_ops.push(PendingOp {
            id,
            address,
            kind,
            preview,
            cheat_id,
        });
        id
    }

    /// Peek at a staged (pending) op by id without removing it.
    /// Used by confirm_op to avoid consuming the op before the DLL call succeeds.
    pub fn peek_pending(&self, id: u64) -> Option<&PendingOp> {
        self.pending_ops.iter().find(|p| p.id == id)
    }

    /// Look up a staged (pending) op by id without removing it.
    #[allow(dead_code)] // used by callers/tests; kept for API completeness
    pub fn get_pending(&self, id: u64) -> Option<&PendingOp> {
        self.pending_ops.iter().find(|p| p.id == id)
    }

    /// List all staged (pending) ops awaiting confirmation.
    pub fn list_pending(&self) -> Vec<&PendingOp> {
        self.pending_ops.iter().collect()
    }

    /// Remove and return a staged op by id (used to confirm or reject it).
    pub fn take_pending(&mut self, id: u64) -> Option<PendingOp> {
        let idx = self.pending_ops.iter().position(|p| p.id == id)?;
        Some(self.pending_ops.remove(idx))
    }

    /// Add a cheat and return its id.
    pub fn add_cheat(
        &mut self,
        label: &str,
        kind: CheatKind,
        hotkey: Option<&str>,
        note: Option<&str>,
    ) -> u64 {
        self.add_cheat_group(label, kind, None, hotkey, false, note)
    }

    /// Add a cheat with explicit hidden flag and return its id.
    pub fn add_cheat_ext(
        &mut self,
        label: &str,
        kind: CheatKind,
        hotkey: Option<&str>,
        hidden: bool,
        note: Option<&str>,
    ) -> u64 {
        self.add_cheat_group(label, kind, None, hotkey, hidden, note)
    }

    /// Add a cheat with an optional grouping category and hidden flag.
    pub fn add_cheat_group(
        &mut self,
        label: &str,
        kind: CheatKind,
        group: Option<&str>,
        hotkey: Option<&str>,
        hidden: bool,
        note: Option<&str>,
    ) -> u64 {
        let id = self.next_cheat_id;
        self.next_cheat_id += 1;
        self.cheats.push(Cheat {
            id,
            label: label.trim().to_string(),
            kind,
            group: group.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
            hotkey: hotkey.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
            hidden,
            note: note.map(|s| s.to_string()),
        });
        id
    }

    /// Set a cheat's hotkey string.
    pub fn set_cheat_hotkey(&mut self, id: u64, hotkey: Option<String>) -> bool {
        if let Some(c) = self.cheats.iter_mut().find(|c| c.id == id) {
            c.hotkey = hotkey.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
            return true;
        }
        false
    }

    /// Get a cheat by id.
    pub fn get_cheat(&self, id: u64) -> Option<&Cheat> {
        self.cheats.iter().find(|c| c.id == id)
    }

    /// List all cheats.
    pub fn list_cheats(&self) -> Vec<&Cheat> {
        self.cheats.iter().collect()
    }

    /// Remove a cheat by id; returns it if it existed.
    pub fn remove_cheat(&mut self, id: u64) -> Option<Cheat> {
        let idx = self.cheats.iter().position(|c| c.id == id)?;
        Some(self.cheats.remove(idx))
    }

    /// Clear all cheats from the session.
    pub fn clear_cheats(&mut self) {
        self.cheats.clear();
        self.next_cheat_id = 0;
    }

    /// Set a toggle cheat's enabled state (used by the GUI/MCP to flip a cave or patch).
    pub fn set_cheat_toggle(&mut self, id: u64, enabled: bool) -> bool {
        if let Some(c) = self.cheats.iter_mut().find(|c| c.id == id) {
            let label = c.label.clone();
            match &mut c.kind {
                CheatKind::Toggle { enabled: e, .. } => {
                    *e = enabled;
                    self.event_bus.emit_session(crate::event::SessionEvent::CheatUpdated {
                        id,
                        label,
                        enabled: Some(enabled),
                        value: None,
                    });
                    return true;
                }
                CheatKind::Patch { enabled: e, .. } => {
                    *e = enabled;
                    self.event_bus.emit_session(crate::event::SessionEvent::CheatUpdated {
                        id,
                        label,
                        enabled: Some(enabled),
                        value: None,
                    });
                    return true;
                }
                _ => {}
            }
        }
        false
    }

    /// Update a toggle cheat's cave installation info (original bytes + cave address).
    /// Called after a cave is successfully installed for this toggle.
    pub fn set_toggle_cave_info(&mut self, id: u64, original_bytes: Vec<u8>, cave_addr: u64) -> bool {
        if let Some(c) = self.cheats.iter_mut().find(|c| c.id == id)
            && let CheatKind::Toggle { original_bytes: ob, cave_addr: ca, .. } = &mut c.kind {
                *ob = original_bytes;
                *ca = cave_addr;
                return true;
            }
        false
    }

    /// Get a toggle cheat's cave restore info (original bytes, target address).
    /// Returns None if the cheat is not a toggle or has no cave installed.
    pub fn get_toggle_restore_info(&self, id: u64) -> Option<(Vec<u8>, u64)> {
        let c = self.cheats.iter().find(|c| c.id == id)?;
        match &c.kind {
            CheatKind::Toggle { original_bytes, target, enabled, .. } => {
                if *enabled && !original_bytes.is_empty() {
                    Some((original_bytes.clone(), *target))
                } else {
                    None
                }
            }
            CheatKind::Patch { original_bytes, target, enabled, .. } => {
                if *enabled && !original_bytes.is_empty() {
                    Some((original_bytes.clone(), *target))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Export session cheats as lightweight DTOs for the in-game overlay.
    pub fn export_overlay_cheats(&self) -> Vec<protocol::OverlayCheatDto> {
        self.cheats
            .iter()
            .filter(|c| !c.hidden)
            .map(|c| {
                let (address, kind_str, enabled) = match &c.kind {
                    CheatKind::Value { address, .. } => (*address, "value".to_string(), false),
                    CheatKind::Struct { base_address, .. } => (*base_address, "struct".to_string(), false),
                    CheatKind::Toggle { target, enabled, .. } => (*target, "toggle".to_string(), *enabled),
                    CheatKind::Patch { target, enabled, .. } => (*target, "toggle".to_string(), *enabled),
                    CheatKind::Button { .. } => (0, "button".to_string(), false),
                };
                crate::protocol::OverlayCheatDto {
                    id: c.id,
                    label: c.label.clone(),
                    address,
                    kind_str,
                    enabled,
                    current_value: None,
                    group: c.group.clone(),
                    hotkey: c.hotkey.clone(),
                    pinned_bytes: None,
                }
            })
            .collect()
    }

    /// Set the active value scan.
    pub fn set_scan(&mut self, scan: crate::scan::Scan) {
        let count = scan.len();
        let vt = format!("{:?}", scan.value_type());
        self.scan = Some(scan);
        self.event_bus.emit_session(crate::event::SessionEvent::ScanUpdated {
            count,
            value_type: vt,
        });
    }

    /// Get a mutable reference to the active scan, if any.
    pub fn scan_mut(&mut self) -> Option<&mut crate::scan::Scan> {
        self.scan.as_mut()
    }

    /// Get a reference to the active scan, if any.
    #[allow(dead_code)] // used by future tools
    pub fn scan(&self) -> Option<&crate::scan::Scan> {
        self.scan.as_ref()
    }

    /// Clear the active scan.
    #[allow(dead_code)] // used by future tools
    pub fn clear_scan(&mut self) {
        self.scan = None;
    }

    /// Add or register a dynamic value pin in the session.
    pub fn add_pin(&mut self, label: impl Into<String>, ops: Vec<crate::protocol::PinOp>, provider: crate::protocol::PinProvider) -> u64 {
        self.next_pin_id = self.next_pin_id.saturating_add(1);
        let id = self.next_pin_id;
        let pin = crate::protocol::PinSpec {
            id,
            label: label.into(),
            enabled: true,
            ops,
            provider,
        };
        self.pins.push(pin);
        id
    }

    /// List all active pins.
    pub fn list_pins(&self) -> &[crate::protocol::PinSpec] {
        &self.pins
    }

    /// Get a pin by ID.
    pub fn get_pin(&self, id: u64) -> Option<&crate::protocol::PinSpec> {
        self.pins.iter().find(|p| p.id == id)
    }

    /// Remove a pin by ID. Returns true if removed.
    pub fn remove_pin(&mut self, id: u64) -> bool {
        if let Some(pos) = self.pins.iter().position(|p| p.id == id) {
            self.pins.remove(pos);
            true
        } else {
            false
        }
    }

    /// Clear all active pins.
    pub fn clear_pins(&mut self) {
        self.pins.clear();
    }
}

/// A shared handle to session state.
pub type SharedSession = Arc<Mutex<SessionState>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_set_get_remove() {
        let mut s = SessionState::new();
        assert!(s.set_marker("wood", 0x1234, Some("wood stock")).is_ok());
        let m = s.get_marker("wood").expect("marker exists");
        assert_eq!(m.address, 0x1234);
        assert_eq!(m.note.as_deref(), Some("wood stock"));

        // Overwrite
        s.set_marker("wood", 0x5678, None).unwrap();
        assert_eq!(s.get_marker("wood").unwrap().address, 0x5678);

        // Remove
        assert!(s.remove_marker("wood").is_some());
        assert!(s.get_marker("wood").is_none());

        // Empty label rejected
        assert!(s.set_marker("  ", 0, None).is_err());
    }

    #[test]
    fn undo_log_records_and_pops() {
        let mut s = SessionState::new();
        let id1 = s.record_undo(0x100, vec![0xAA], "write wood".into());
        let id2 = s.record_undo(0x200, vec![0xBB, 0xCC], "patch hp".into());
        assert_eq!(s.undo_len(), 2);

        // ids are distinct and monotonic
        assert_ne!(id1, id2);
        assert!(id2 > id1);

        // peek last without removing
        assert_eq!(s.peek_undo_last().unwrap().address, 0x200);
        assert_eq!(s.undo_len(), 2);

        // pop by id
        let e = s.pop_undo(id1).expect("entry exists");
        assert_eq!(e.original_bytes, vec![0xAA]);
        assert_eq!(s.undo_len(), 1);

        // pop last
        let e = s.pop_undo_last().unwrap();
        assert_eq!(e.address, 0x200);
        assert_eq!(s.undo_len(), 0);
        assert!(s.pop_undo_last().is_none());
    }

    #[test]
    fn pending_ops_stage_list_take() {
        use crate::cave_hook::CaveHook;
        let mut s = SessionState::new();
        // No pending ops to start.
        assert!(s.list_pending().is_empty());
        // Stage two ops; ids are distinct and monotonic.
        let id1 = s.stage_op(0x100, PendingKind::Write { data: vec![0xAA] }, "write 1 byte".into());
        let id2 = s.stage_op(
            0x200,
            PendingKind::InstallCave {
                hook: CaveHook::Trampoline {
                    payload: vec![],
                    jump: crate::cave_hook::JumpStyle::Absolute,
                },
                marker: None,
                label_offsets: std::collections::HashMap::new(),
            },
            "install cave".into(),
        );
        assert_ne!(id1, id2);
        assert!(id2 > id1);
        assert_eq!(s.list_pending().len(), 2);

        // Look up by id.
        let p = s.get_pending(id1).expect("pending exists");
        assert_eq!(p.address, 0x100);

        // take_pending removes it.
        let taken = s.take_pending(id1).expect("taken");
        assert_eq!(taken.kind.kind_text(), "write");
        assert_eq!(s.list_pending().len(), 1);
        assert!(s.get_pending(id1).is_none());

        // take_pending on a missing id returns None.
        assert!(s.take_pending(999).is_none());
    }

    #[test]
    fn connection_state_defaults_and_updates() {
        let mut s = SessionState::new();
        // Defaults.
        assert_eq!(s.dll_host(), "");
        assert_eq!(s.dll_port(), 0);
        assert!(!s.connected());
        assert_eq!(s.game_name(), "");
        assert_eq!(s.dll_path(), "");
        assert!(s.inject_version().is_none());

        // Update.
        s.set_dll_host("127.0.0.1");
        s.set_dll_port(31337);
        s.set_connected(true);
        s.set_game_name("Unrailed2.exe");
        s.set_dll_path("trainlab_inject.dll");
        s.set_inject_version(Some("0.1.0".into()));

        assert_eq!(s.dll_host(), "127.0.0.1");
        assert_eq!(s.dll_port(), 31337);
        assert!(s.connected());
        assert_eq!(s.game_name(), "Unrailed2.exe");
        assert_eq!(s.dll_path(), "trainlab_inject.dll");
        assert_eq!(s.inject_version(), Some("0.1.0"));

        s.set_connected(false);
        assert!(!s.connected());
    }

    #[test]
    fn cheats_add_list_remove_toggle() {
        use crate::cave_hook::CaveHook;
        use crate::scan::ValueType;
        let mut s = SessionState::new();
        assert!(s.list_cheats().is_empty());

        // Value cheat.
        let id1 = s.add_cheat(
            "wood",
            CheatKind::Value {
                address: 0x100,
                value_type: ValueType::I32,
                address_expr: None,
            },
            None,
            Some("wood stock"),
        );
        // Toggle cheat.
        let id2 = s.add_cheat(
            "god mode",
            CheatKind::Toggle {
                hook: CaveHook::Trampoline {
                    payload: vec![],
                    jump: crate::cave_hook::JumpStyle::Absolute,
                },
                target: 0x200,
                enabled: false,
                original_bytes: Vec::new(),
                cave_addr: 0,
            },
            None,
            None,
        );
        assert_ne!(id1, id2);
        assert_eq!(s.list_cheats().len(), 2);

        // get_cheat.
        let c = s.get_cheat(id1).expect("cheat exists");
        assert_eq!(c.label, "wood");
        assert_eq!(c.note.as_deref(), Some("wood stock"));

        // Toggle flip.
        assert!(s.set_cheat_toggle(id2, true));
        let c2 = s.get_cheat(id2).unwrap();
        match &c2.kind {
            CheatKind::Toggle { enabled, .. } => assert!(*enabled),
            _ => panic!("expected toggle"),
        }
        // set_cheat_toggle on a value cheat returns false.
        assert!(!s.set_cheat_toggle(id1, true));

        // remove_cheat.
        assert!(s.remove_cheat(id1).is_some());
        assert_eq!(s.list_cheats().len(), 1);
        assert!(s.get_cheat(id1).is_none());
        assert!(s.remove_cheat(999).is_none());
    }

    #[test]
    fn shared_session_is_send_sync() {
        let shared: SharedSession = Arc::new(Mutex::new(SessionState::new()));
        {
            let mut s = shared.lock().unwrap();
            s.set_marker("a", 1, None).unwrap();
        }
        let m = shared.lock().unwrap().get_marker("a").cloned().unwrap();
        assert_eq!(m.address, 1);
    }

    #[tokio::test]
    async fn test_client_context_and_lifecycle_state_machine() {
        let mut s = SessionState::new();
        assert_eq!(*s.lifecycle(), SessionLifecycle::Idle);

        // Register client contexts
        let mut ctx_mcp = s.create_context("mcp-agent-1", ClientKind::Mcp { agent_name: Some("test-bot".into()) });
        let ctx_web = s.create_context("web-session-42", ClientKind::Web { session_id: "tab-1".into() });

        assert_eq!(ctx_mcp.id, "mcp-agent-1");
        assert_eq!(ctx_web.id, "web-session-42");

        // Target attached
        s.set_game_name("DRGSurvivor.exe");
        s.set_game_pid(Some(12345));
        assert_eq!(
            *s.lifecycle(),
            SessionLifecycle::TargetAttached {
                pid: 12345,
                exe_name: "DRGSurvivor.exe".into()
            }
        );

        // Connected to DLL
        s.set_inject_version(Some("0.1.0".into()));
        s.set_connected(true);
        assert_eq!(
            *s.lifecycle(),
            SessionLifecycle::Connected {
                pid: 12345,
                exe_name: "DRGSurvivor.exe".into(),
                dll_version: Some("0.1.0".into())
            }
        );

        // Contexts receive broadcast events
        let mut got_lifecycle = false;
        while let Ok(event) = ctx_mcp.event_rx.recv().await {
            if let crate::event::BusEvent::Session(crate::event::SessionEvent::LifecycleChanged { state, pid, exe }) = event {
                assert_eq!(state, "target_attached");
                assert_eq!(pid, Some(12345));
                assert_eq!(exe, "DRGSurvivor.exe");
                got_lifecycle = true;
                break;
            }
        }
        assert!(got_lifecycle);

        // Test context-scoped scans
        assert!(ctx_mcp.scan.is_none());
        assert!(ctx_web.scan.is_none());
    }

    #[test]
    fn marker_kind_defaults_to_pointer() {
        let mut s = SessionState::new();
        s.set_marker("ptr", 0x1000, None).unwrap();
        let m = s.get_marker("ptr").unwrap();
        assert_eq!(m.kind, MarkerKind::Pointer);
        assert!(m.struct_type.is_none());
    }

    #[test]
    fn marker_kind_object_with_struct_type() {
        let mut s = SessionState::new();
        s.set_marker_full("sel_mgr", 0x2000, None, MarkerKind::Object, Some("SelectionManager".into()), Some("live instance")).unwrap();
        let m = s.get_marker("sel_mgr").unwrap();
        assert_eq!(m.kind, MarkerKind::Object);
        assert_eq!(m.struct_type.as_deref(), Some("SelectionManager"));
        assert_eq!(m.note.as_deref(), Some("live instance"));
    }

    #[test]
    fn marker_kind_buffer_auto() {
        let mut s = SessionState::new();
        s.set_marker_full("heap", 0x3000, Some(0x100000), MarkerKind::Buffer, None, None).unwrap();
        let m = s.get_marker("heap").unwrap();
        assert_eq!(m.kind, MarkerKind::Buffer);
        assert_eq!(m.size, Some(0x100000));
    }

    #[test]
    fn struct_def_registry_roundtrip() {
        let mut s = SessionState::new();
        assert!(s.list_struct_defs().is_empty());

        s.register_struct_def(StructDef {
            name: "ShipEntity".into(),
            size: Some(0x200),
            fields: vec![
                StructField { label: "Health".into(), offset_expr: "0x38".into(), value_type: crate::scan::ValueType::F32 },
                StructField { label: "Shield".into(), offset_expr: "0x40".into(), value_type: crate::scan::ValueType::F32 },
            ],
            note: Some("main ship struct".into()),
        });
        s.register_struct_def(StructDef {
            name: "PlayerData".into(),
            size: None,
            fields: vec![],
            note: None,
        });

        assert_eq!(s.list_struct_defs().len(), 2);

        let def = s.get_struct_def("ShipEntity").unwrap();
        assert_eq!(def.size, Some(0x200));
        assert_eq!(def.fields.len(), 2);
        assert_eq!(def.fields[0].label, "Health");

        // Overwrite
        s.register_struct_def(StructDef { name: "ShipEntity".into(), size: Some(0x210), fields: vec![], note: None });
        assert_eq!(s.get_struct_def("ShipEntity").unwrap().size, Some(0x210));

        // Remove
        assert!(s.remove_struct_def("PlayerData").is_some());
        assert!(s.get_struct_def("PlayerData").is_none());
        assert_eq!(s.list_struct_defs().len(), 1);
    }

    #[test]
    fn test_session_network_packet_recording_and_filtering() {
        use crate::protocol::{NetworkPacketDto, PacketDirection, PacketKind};
        let mut s = SessionState::new();

        s.set_dll_capabilities(vec!["memory".into(), "network_capture".into()]);
        assert!(s.has_capability("network_capture"));
        assert!(s.has_capability("MEMORY"));
        assert!(!s.has_capability("unknown_cap"));

        let p1 = NetworkPacketDto {
            id: 0,
            timestamp_ms: 1000,
            kind: PacketKind::Udp,
            direction: PacketDirection::Outbound,
            local_endpoint: Some("127.0.0.1:5000".into()),
            remote_endpoint: Some("192.168.1.1:27015".into()),
            url: None,
            headers: None,
            payload_len: 32,
            payload_preview: vec![1, 2, 3],
            artifact_file: None,
            staged_ptr: None,
        };

        let p2 = NetworkPacketDto {
            id: 0,
            timestamp_ms: 2000,
            kind: PacketKind::Http,
            direction: PacketDirection::Inbound,
            local_endpoint: Some("127.0.0.1:5001".into()),
            remote_endpoint: Some("api.gamebackend.com:443".into()),
            url: Some("https://api.gamebackend.com/v1/auth".into()),
            headers: Some("Content-Type: application/json".into()),
            payload_len: 128,
            payload_preview: b"{\"token\":\"xyz\"}".to_vec(),
            artifact_file: None,
            staged_ptr: None,
        };

        let id1 = s.record_network_packet(p1);
        let id2 = s.record_network_packet(p2);
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);

        // Filter by protocol
        let (udp_packets, total_udp) = s.list_network_packets(None, None, Some(PacketKind::Udp), None);
        assert_eq!(total_udp, 1);
        assert_eq!(udp_packets.len(), 1);
        assert_eq!(udp_packets[0].id, 1);

        // Filter by endpoint / URL
        let (api_packets, total_api) = s.list_network_packets(None, None, None, Some("gamebackend"));
        assert_eq!(total_api, 1);
        assert_eq!(api_packets.len(), 1);
        assert_eq!(api_packets[0].kind, PacketKind::Http);

        // Clear log
        assert_eq!(s.clear_network_packets(), 2);
        let (all, total) = s.list_network_packets(None, None, None, None);
        assert_eq!(total, 0);
        assert!(all.is_empty());
    }
}

