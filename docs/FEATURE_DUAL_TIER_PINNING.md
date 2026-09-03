# Feature: Dual-Tier Value Pinning Architecture

## 1. Overview
Value Pinning refers to continually enforcing or maintaining a game value or relationship across game cycles (e.g. keeping health frozen at max, setting ammo = clip_max + 1, or syncing one marker to another).

Trainlab implements a **dual-tier pinning architecture**:
1. **Tier 1: In-Process On-Frame Render Hook Pinning (`trainlab-inject`)** (Primary / Optimal)
   - Executes synchronously on the game thread inside `IDXGISwapChain::Present` (60 / 120 / 144+ Hz).
   - Zero IPC latency, zero syscall context-switch overhead, and race-free writes before frame presentation.
   - Guarded by atomic pointer/sanity assertions to immediately abort individual pin passes if pointers go null (e.g. on respawn or scene transition).
2. **Tier 2: External Periodic Timer Pinning (`trainlab-gui`)** (Fallback)
   - Executes on a dedicated background timer thread inside `trainlab-gui` at a user-configurable frequency (`gui.pin_rate_hz`, default 30-60 Hz).
   - Uses cross-process memory primitives (`ReadProcessMemory` / `WriteProcessMemory` or Wine proc mem).
   - Serves as the fallback whenever the target game process has no active DXGI render hook (e.g. headless tests, OpenGL/Vulkan without hook, or when overlay is blacklisted).
3. **Dynamic Provider Selection**:
   - Whenever a pin is created or updated (via GUI, Profile, REST API, or MCP tool), the runtime automatically inspects the target capabilities.
   - If the injected DLL advertises `frame_pinning` (or active render hook), the pin is offloaded to the DLL via `Request::SyncPins`.
   - Otherwise, the GUI's local timer loop takes ownership of executing the pin.

---

## 2. Specification & Instruction Set

Each pin is represented by a `PinSpec` composed of ordered `PinOp` micro-instructions:

```rust
pub struct PinSpec {
    pub id: u64,
    pub label: String,
    pub enabled: bool,
    pub ops: Vec<PinOp>,
}

pub enum PinOp {
    /// Safeguard assert: if address is 0x0 or fails condition, abort remaining ops in this pin
    AssertNotNull { address: u64 },
    AssertEqual { address: u64, value_type: ValueType, expected: f64 },

    /// Constant write: write byte slice to address
    WriteConstant { address: u64, data: Vec<u8> },

    /// Copy / Arithmetic: dst = src (or dst = src + addend, dst = max(dst, src))
    CopyValue {
        src_address: u64,
        dst_address: u64,
        value_type: ValueType,
        addend: Option<f64>,
        max_only: bool,
    },

    /// Dereference a pointer into a temporary register slot for chained offsets
    Dereference { src_ptr_address: u64, dst_scratch_index: usize, offset: i64 },
}
```

---

## 3. Configuration

Configured in `config.yaml`:

```yaml
gui:
  pin_rate_hz: 30              # Fallback external GUI timer rate (default 30 Hz)

inject_features:
  display:
    overlay: true              # When enabled, Present hooks empower Tier 1 on-frame pinning
```

---

## 4. MCP & REST API Tools

- **MCP Tools**:
  - `pin_value(address, value, value_type, label)`: Freeze an address to a constant value.
  - `pin_copy(src, dst, value_type, addend, max_only, label)`: Dynamically sync dst with src every frame.
  - `unpin(id)` / `clear_pins()`: Remove active pins.
  - `list_pins()`: View active pins, execution counts, provider (`InProcessFrame` vs `ExternalTimer`), and last execution status.
- **REST API Endpoints**:
  - `GET /api/pins`: List current active pins and execution telemetry.
  - `POST /api/pins`: Register or update a pin.
  - `DELETE /api/pins/:id`: Remove a pin.
