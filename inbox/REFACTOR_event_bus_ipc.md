# Refactor: Unified Event Bus & Autonomous IPC

**Status:** ✅ RESOLVED & VALIDATED (2026-09-01)

## Context

This document captures the design and implementation for refactoring the
IPC fast-channel and session event bus into a clean, decoupled architecture.

**Problem being solved:** Overlay button clicks from the in-game DLL were not
reaching the GUI reliably because the DLL's outbound event queue was flushed
reactively. The IPC connection was coupled directly to the egui render loop
rather than running autonomously, and the session lacked a unified bus for arbitrary
and wire events.

---

## 1. Design Goals

1. **The IPC worker is fully autonomous.** It runs independently of the egui
   frame loop in Tokio tasks — connecting, reading, writing, and reconnecting on its own
   schedule regardless of whether the GUI is rendering or idle.

2. **All inter-component communication flows through the session event bus.**
   No component calls another component directly. The GUI does not call
   `execute_profile_commands` synchronously inside the IPC listener. The IPC worker does not call `trigger_cheat`.
   They publish and subscribe to `BusEvent`.

3. **REST/Pull-on-Demand + Incremental Sync.**
   The DLL signals `Event::OverlayReady` when its present hooks and overlay are live.
   The GUI sees `OverlayReady` on the bus and sends the full `SyncCheats` snapshot.
   Incremental updates (`CheatAdded`, `CheatToggled`, `CheatRemoved`) stream as events afterwards.

4. **The DLL pushes events proactively.** The DLL does not wait to be polled.
   A dedicated push thread in the DLL drains `OUTBOUND_EVENTS` on its own
   cadence (~16ms) and writes `Message::Event` frames unsolicited.

5. **No tokio in the DLL.** `trainlab-inject` is a `cdylib` injected into an
   arbitrary game process. Bundling a tokio runtime risks conflicting with the
   game's own threads and signal handlers. All DLL threading uses `std::thread`.

6. **`SessionState` is the single shared truth.** Every subscriber (egui,
   MCP, REST/SSE, IPC worker) reads from the session bus. No parallel state.

---

## 2. Unified Bus Event Type

Replace `EventBus`'s `broadcast<SessionEvent>` with `broadcast<BusEvent>`.

```rust
// trainlab-core/src/event.rs

/// A log entry emitted whenever session activity is recorded.
#[derive(Debug, Clone, Serialize)]
pub struct LogEvent {
    pub source: String,    // e.g. "UI", "OVERLAY", "MCP", "IPC"
    pub message: String,
    pub timestamp_ms: u64, // unix millis
}

/// The unified event type carried on the session bus.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BusEvent {
    /// High-level session state mutation (cheat toggled, marker set, etc.)
    Session(SessionEvent),
    /// Raw wire event from the DLL / overlay (CheatTriggered, SyncCheats, OverlayReady, etc.)
    Protocol(trainlab_core::protocol::Event),
    /// Activity log entry.
    Log(LogEvent),
}
```

`EventBus` becomes `broadcast::Sender<BusEvent>`. `emit()` / `subscribe()`
stay the same shape, just typed to `BusEvent`.

**Mapping into `SessionState`:**

```rust
impl SessionState {
    /// Publish any event onto the bus. This is the single entry point
    /// for all bus traffic.
    pub fn publish_event(&self, event: BusEvent) {
        self.event_bus.emit(event);
    }

    /// Convenience: publish a log entry and append to the internal log vec.
    pub fn log_activity(&mut self, source: &str, msg: impl Into<String>) {
        let msg = msg.into();
        self.activity_log.push(format!("[{source}] {msg}"));
        self.publish_event(BusEvent::Log(LogEvent {
            source: source.into(),
            message: msg,
            timestamp_ms: unix_millis_now(),
        }));
    }
}
```

---

## 3. DLL Side: Proactive Push Thread & OverlayReady

**Protocol additions / cleanups:**
- Add `Event::OverlayReady`
- Remove `Request::PollEvents` and `Response::Events`

**DLL Push Thread:**
In `handle_connection`, spawn a dedicated push thread owning a cloned stream half:

```rust
let mut push_stream = stream.try_clone()?;
thread::Builder::new()
    .name("trainlab-inject-push".into())
    .spawn(move || {
        loop {
            let events = render::overlay::drain_outbound_events();
            for evt in events {
                let msg = Message::Event(evt);
                if let Ok(frame) = protocol::encode(&msg) {
                    if push_stream.write_all(&frame).is_err() {
                        return; // socket closed
                    }
                }
            }
            thread::sleep(Duration::from_millis(16)); // ~60Hz drain cadence
        }
    });
```

**Overlay Readiness Signal:**
When the overlay initializes or present hook first runs, enqueue `Event::OverlayReady` into `OUTBOUND_EVENTS`.

**Remove `tokio` from `trainlab-inject/Cargo.toml`.**

---

## 4. GUI Side: Tokio IPC Tasks

Replace the blocking std-thread multiplexer with Tokio tasks:

### 4a. IPC Reader Task
Reads incoming length-prefixed `Message` frames:
- `Message::Event(evt)` -> publishes `BusEvent::Protocol(evt)` to session bus.
- `Message::Response { id, resp }` -> sends response to pending oneshot channel.

### 4b. IPC Writer Task & Outbound Bus Subscriber
- Drains `tokio::sync::mpsc::UnboundedReceiver<(u64, Request)>` and writes request frames.
- Subscribes to `SessionState::event_bus()`:
  - When `BusEvent::Protocol(Event::OverlayReady)` is seen:
    Queries `session.export_overlay_cheats()` and writes `Message::Event(Event::SyncCheats { cheats })` to the DLL stream.
  - When `BusEvent::Session(SessionEvent::CheatUpdated { .. })` is seen:
    Pushes incremental cheat update or resyncs.

---

## 5. egui Update Loop

Add `bus_rx: broadcast::Receiver<BusEvent>` to `TrainlabApp`.
In `update()`, non-blocking drain via `try_recv()`:

```rust
while let Ok(evt) = self.bus_rx.try_recv() {
    match evt {
        BusEvent::Protocol(Event::CheatTriggered { id }) => {
            self.trigger_cheat(id);
        }
        BusEvent::Protocol(Event::CheatToggled { id, enabled }) => {
            self.trigger_cheat_set(id, enabled);
        }
        BusEvent::Log(_) => {
            ctx.request_repaint();
        }
        BusEvent::Session(SessionEvent::ConnectionChanged { connected, .. }) => {
            self.connected = connected;
        }
        _ => {}
    }
}
```

---

## 6. Implementation Steps

1. **`trainlab-core`**:
   - Update `event.rs`: add `LogEvent`, `BusEvent`, update `EventBus`.
   - Update `protocol.rs`: add `Event::OverlayReady`, remove `PollEvents`/`Events`.
   - Update `session.rs`: add `publish_event()`, route `log_activity()` and mutations through `publish_event()`.
2. **`trainlab-inject`**:
   - Remove `tokio` from `Cargo.toml`.
   - Update `lib.rs`: spawn proactive push thread, remove `PollEvents` handler, emit `OverlayReady` on ready.
3. **`trainlab-gui`**:
   - Refactor `controller.rs` into autonomous Tokio tasks publishing to bus.
   - Refactor `main.rs` to subscribe to `bus_rx` and drain in `update()`.
4. **Build & Verify**:
   - `cargo test --all`
   - `cargo build --release --target x86_64-pc-windows-gnu --package trainlab-gui --package trainlab-inject`
   - Deploy to Steam Machine (`192.168.254.143`)
