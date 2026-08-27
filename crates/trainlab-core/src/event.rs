//! Isolated Event Bus for `trainlab-gui`.
//!
//! Provides a decoupled `tokio::sync::broadcast` pub/sub channel for all session events.
//! Mutating operations (cheats, markers, profile, scan, log, window) emit typed
//! `SessionEvent`s onto the bus. Independent subscribers (native egui UI, SSE web stream)
//! consume these events asynchronously.

use serde::Serialize;
use tokio::sync::broadcast;

/// Typed event representing any session state mutation.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum SessionEvent {
    /// A cheat's toggle state or value was updated.
    CheatUpdated {
        id: u64,
        label: String,
        enabled: Option<bool>,
        value: Option<String>,
    },
    /// A tagged memory marker was added or updated.
    MarkerSet {
        name: String,
        address: String,
        note: Option<String>,
    },
    /// A memory scan was initiated or refined.
    ScanUpdated {
        count: usize,
        value_type: String,
    },
    /// A cheat profile was loaded.
    ProfileLoaded {
        name: String,
        game: String,
        cheats_count: usize,
    },
    /// A new activity log entry was appended.
    ActivityLogged {
        entry: String,
    },
    /// A window visibility request was issued ("show" or "hide").
    WindowVisibility {
        command: String,
    },
    /// Connection state changed (connected / disconnected).
    ConnectionChanged {
        connected: bool,
        game_name: String,
    },
    /// Session lifecycle state changed (Idle, TargetAttached, Injected, Connected, TargetLost).
    LifecycleChanged {
        state: String,
        pid: Option<u32>,
        exe: String,
    },
    /// An application / binary was launched.
    AppLaunched {
        name: String,
        path: String,
        pid: Option<u32>,
    },
}

/// Event bus holding the broadcast sender.
#[derive(Debug, Clone)]
pub struct EventBus {
    sender: broadcast::Sender<SessionEvent>,
}

impl Default for EventBus {
    fn default() -> Self {
        let (sender, _) = broadcast::channel(256);
        Self { sender }
    }
}

impl EventBus {
    /// Create a new EventBus with default capacity.
    pub fn new() -> Self {
        Self::default()
    }

    /// Emit an event onto the bus. Silently succeeds if there are no active subscribers.
    pub fn emit(&self, event: SessionEvent) {
        let _ = self.sender.send(event);
    }

    /// Subscribe to receiving events from the bus.
    pub fn subscribe(&self) -> broadcast::Receiver<SessionEvent> {
        self.sender.subscribe()
    }
}
