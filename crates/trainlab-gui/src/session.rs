//! Session state for the trainlab MCP server.
//!
//! Per design decisions D7 and D8, the *Trainer* (not the LLM) holds session
//! state: labeled markers for addresses that persist across turns, and an undo
//! log that records the original bytes of every mutation so it can be reverted.
//!
//! This state lives in an `Arc<Mutex<SessionState>>` shared by the MCP server
//! handler, so an agent can set markers, list them, and (once mutating tools
//! exist) record/apply undo operations.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// A labeled address the agent persists across turns (D7).
#[derive(Debug, Clone)]
pub struct Marker {
    pub address: u64,
    pub label: String,
    pub note: Option<String>,
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
    /// Optional human note / description.
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
        value_type: trainlab_core::scan::ValueType,
    },
    /// A code-cave hook the user can toggle on/off.
    Toggle {
        /// The cave hook to install/remove.
        hook: trainlab_core::cave_hook::CaveHook,
        /// The target instruction address the cave redirects.
        target: u64,
        /// Whether the toggle is currently active.
        enabled: bool,
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
}

/// The kind of a staged mutation.
#[derive(Debug, Clone)]
pub enum PendingKind {
    /// Write raw bytes to `address`.
    Write { data: Vec<u8> },
    /// Install a code-cave hook at `address`.
    InstallCave {
        hook: trainlab_core::cave_hook::CaveHook,
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

/// The shared, mutable session state.
#[derive(Debug, Default)]
pub struct SessionState {
    /// Markers keyed by label (case-sensitive).
    markers: BTreeMap<String, Marker>,
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
    scan: Option<trainlab_core::scan::Scan>,
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
    /// Unified activity log (sourced as "UI: ..." or "MCP: ...").
    activity_log: Vec<String>,
}

impl SessionState {
    /// Log an activity entry tagged by source (e.g., "UI", "MCP").
    pub fn log_activity(&mut self, source: &str, msg: impl Into<String>) {
        let entry = format!("{source}: {}", msg.into());
        self.activity_log.push(entry);
        if self.activity_log.len() > 500 {
            self.activity_log.remove(0);
        }
    }

    /// Retrieve a snapshot of the current activity log entries.
    pub fn list_activity_log(&self) -> Vec<String> {
        self.activity_log.clone()
    }
    /// Set the game process PID that scan-family tools target.
    pub fn set_game_pid(&mut self, pid: u32) {
        self.game_pid = Some(pid);
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
    }

    /// Whether we have a live connection to the DLL.
    pub fn connected(&self) -> bool {
        self.connected
    }

    /// Record the target game name.
    pub fn set_game_name(&mut self, name: impl Into<String>) {
        self.game_name = name.into();
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
        let label = label.trim().to_string();
        if label.is_empty() {
            return Err("marker label cannot be empty".into());
        }
        self.markers.insert(
            label.clone(),
            Marker {
                address,
                label: label.clone(),
                note: note.map(|s| s.to_string()),
            },
        );
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
        let id = self.next_pending_id;
        self.next_pending_id += 1;
        self.pending_ops.push(PendingOp {
            id,
            address,
            kind,
            preview,
        });
        id
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
    pub fn add_cheat(&mut self, label: &str, kind: CheatKind, note: Option<&str>) -> u64 {
        let id = self.next_cheat_id;
        self.next_cheat_id += 1;
        self.cheats.push(Cheat {
            id,
            label: label.trim().to_string(),
            kind,
            note: note.map(|s| s.to_string()),
        });
        id
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

    /// Set a toggle cheat's enabled state (used by the GUI/MCP to flip a cave).
    pub fn set_cheat_toggle(&mut self, id: u64, enabled: bool) -> bool {
        if let Some(c) = self.cheats.iter_mut().find(|c| c.id == id) {
            if let CheatKind::Toggle { enabled: e, .. } = &mut c.kind {
                *e = enabled;
                return true;
            }
        }
        false
    }

    /// Set the active value scan.
    pub fn set_scan(&mut self, scan: trainlab_core::scan::Scan) {
        self.scan = Some(scan);
    }

    /// Get a mutable reference to the active scan, if any.
    pub fn scan_mut(&mut self) -> Option<&mut trainlab_core::scan::Scan> {
        self.scan.as_mut()
    }

    /// Get a reference to the active scan, if any.
    #[allow(dead_code)] // used by future tools
    pub fn scan(&self) -> Option<&trainlab_core::scan::Scan> {
        self.scan.as_ref()
    }

    /// Clear the active scan.
    #[allow(dead_code)] // used by future tools
    pub fn clear_scan(&mut self) {
        self.scan = None;
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
        use trainlab_core::cave_hook::CaveHook;
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
                    jump: trainlab_core::cave_hook::JumpStyle::Absolute,
                },
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
        use trainlab_core::cave_hook::CaveHook;
        use trainlab_core::scan::ValueType;
        let mut s = SessionState::new();
        assert!(s.list_cheats().is_empty());

        // Value cheat.
        let id1 = s.add_cheat(
            "wood",
            CheatKind::Value {
                address: 0x100,
                value_type: ValueType::I32,
            },
            Some("wood stock"),
        );
        // Toggle cheat.
        let id2 = s.add_cheat(
            "god mode",
            CheatKind::Toggle {
                hook: CaveHook::Trampoline {
                    payload: vec![],
                    jump: trainlab_core::cave_hook::JumpStyle::Absolute,
                },
                target: 0x200,
                enabled: false,
            },
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
}
