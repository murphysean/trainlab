//! Wire protocol shared between the injected DLL and the GUI/scanner.
//!
//! Messages are serialized with `bincode` and framed with a 4-byte little
//! endian length prefix, then sent over a local TCP socket. Keeping the
//! protocol in `trainlab-core` means the GUI and the injected DLL can never
//! drift out of sync.

use serde::{Deserialize, Serialize};

/// Envelope for multiplexed messages across the single full-duplex IPC connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    /// Request sent from GUI/Client to DLL with a unique correlation sequence ID.
    Request { id: u64, req: Request },
    /// Response returned from DLL to GUI/Client matching the request's sequence ID.
    Response { id: u64, resp: Response },
    /// Asynchronous event broadcasted across the event bus.
    Event(Event),
    /// Legacy/Asynchronous notification pushed from DLL to GUI.
    Notification(Notification),
}

/// Granular discrete events broadcasted between DLL, Desktop GUI, and Web/Agent interfaces.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Event {
    /// A new cheat was registered in the session.
    CheatAdded { cheat: OverlayCheatDto },
    /// A cheat's toggle state changed.
    CheatToggled { id: u64, enabled: bool },
    /// A button cheat or action was triggered (e.g. from in-game overlay).
    CheatTriggered { id: u64 },
    /// A cheat's value or pinned target changed.
    CheatValueChanged { id: u64, value_str: String, pinned_bytes: Option<Vec<u8>> },
    /// A cheat was removed from the session.
    CheatRemoved { id: u64 },
    /// Full snapshot sync of all active cheats.
    SyncCheats { cheats: Vec<OverlayCheatDto> },
    /// Overlay visibility changed.
    OverlayVisibilityChanged { visible: bool },
    /// Activity log entry broadcast.
    ActivityLogged { message: String },
    /// Remote request to show/hide the standalone GUI window ("show" / "hide" / "toggle").
    WindowCommand { command: String },
    /// Injected DLL overlay is initialized and ready to receive cheats.
    OverlayReady,
    /// Real-time captured network packet event from Winsock/WinHTTP hooks.
    NetworkPacket(NetworkPacketDto),
    /// Acknowledge packet receipt and notify DLL to free any staged buffer in game memory.
    AcknowledgePacket { id: u64, discard: bool },
}

/// Asynchronous push notification types emitted by the injected DLL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Notification {
    /// In-game overlay cheat toggled directly via controller or on-screen overlay.
    OverlayCheatToggled { id: u64, enabled: bool },
    /// In-game overlay window visibility toggled (e.g. Select + Start).
    OverlayVisibilityChanged { visible: bool },
    /// Game state or render hook lifecycle notification.
    Log { level: String, message: String },
}

/// A single request sent from the GUI/scanner to the injected DLL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    /// Ping the DLL to confirm it is alive and report its version.
    Ping,
    /// Read `len` bytes from the game process at `address`.
    Read { address: u64, len: usize },
    /// Write `data` into the game process at `address`.
    Write { address: u64, data: Vec<u8> },
    /// Scan the game's readable memory for an AOB pattern.
    ScanAob {
        /// The pattern, with `??` wildcards already resolved to `None`.
        pattern: Vec<Option<u8>>,
        /// Optional start address (defaults to lowest readable region).
        start: Option<u64>,
        /// Optional end address (defaults to highest readable region).
        end: Option<u64>,
    },
    /// Allocate a block of memory inside the game process (a code cave).
    Allocate { size: usize, executable: bool },
    /// Free a previously allocated block.
    Free { address: u64 },
    /// Install a code cave hook at `target`: allocate executable memory, build
    /// a cave body per `hook` semantics, patch the first whole instructions of
    /// `target` (instruction-aligned length >= a `jmp`) with an absolute `jmp`
    /// into the cave, and save the original bytes. Returns a handle (the cave
    /// address).
    InstallCave {
        /// Address of the instruction to redirect.
        target: u64,
        /// The hook to install: `trampoline` (transparent, replays stolen
        /// instructions, payload optional) or `override` (skips stolen, runs
        /// payload). Payload is hex shellcode bytes.
        hook: crate::cave_hook::CaveHook,
    },
    /// List readable memory regions of the game process.
    ListRegions,
    /// Perform a first value scan over the game's readable regions.
    ///
    /// The DLL runs the scan in-process (fast, direct memory access) and
    /// returns the match set. The GUI stores it in session state (D7).
    Scan {
        /// The value type to scan for.
        value_type: crate::scan::ValueType,
        /// Byte alignment for candidate addresses (0/1 = any).
        alignment: usize,
        /// The narrowing operation (Exact/Range) for the first scan.
        op: crate::scan::ScanOp,
    },
    /// Narrow an existing match set by re-reading each address.
    ///
    /// The GUI sends the current match set; the DLL re-reads each address and
    /// returns the narrowed set.
    Next {
        /// The value type of the scan.
        value_type: crate::scan::ValueType,
        /// The current match set as `(address, last_value)` pairs.
        matches: Vec<(u64, f64)>,
        /// The narrowing operation.
        op: crate::scan::ScanOp,
    },
    /// Reverse-reference scan: find addresses whose pointer value points into
    /// the range `[lo, hi]`.
    PointerScan {
        lo: u64,
        hi: u64,
    },
    /// Resolve a known pointer chain against the game's live memory.
    PointerChase {
        base: u64,
        offsets: Vec<u64>,
    },
    /// Arm a hardware watchpoint (DR0/DR7) on `address` so that when the game
    /// *writes* that location we capture the writing code's registers (T-028).
    ///
    /// When `one_shot` is true the watchpoint is disarmed after the first hit
    /// and the caller receives a `WatchHit`. When false it stays armed and the
    /// caller is expected to poll for hits via a later `WatchHit` (or clear it).
    WatchWrites {
        address: u64,
        len: usize,
        one_shot: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mechanism: Option<String>,
    },
    /// Arm a lightweight single-fire software breakpoint (int3 `0xCC`) on a
    /// code address. When execution reaches `address` we capture registers and
    /// a stack trace, restore the original byte, and (unless `one_shot` is
    /// false) re-arm. The hit is reported as a [`Response::WatchHit`] (T-029).
    BreakOnCode {
        address: u64,
        one_shot: bool,
    },
    /// Arm a **non-stalling, passive register capture** at a code address.
    ///
    /// Installs a transparent trampoline at `target` that records the value of
    /// `spec.reg` into a DLL-owned ring buffer each time the site executes,
    /// then replays the stolen instructions and jumps back — the game never
    /// stops. The recorded values are read back with
    /// [`Request::ReadCaptures`]. This is the register-anchor primitive for
    /// reproducing a resource address across sessions without re-scanning.
    ///
    /// `capacity` (default 32) is the number of entries the ring keeps.
    /// `disarm` (default true) makes the payload capture at most once and then
    /// set the ring's disarmed flag (one_shot / stop_on_match).
    CaptureReg {
        target: u64,
        spec: crate::capture::CaptureRegSpec,
        capacity: usize,
        disarm: bool,
    },
    // The `spec.gate` field carries the decoupled "capture X only when register
    // Y compares Z" gate (reg, cmp, value/min/max). A gate with a register that
    // needs a range uses const_a/const_b in the ring header; `whole` uses x87
    // frndint. If `disarm` is set, the payload records at most one entry and
    // flips the ring's disarmed flag, so a second execution short-circuits.
    /// Read back the entries recorded by a `CaptureReg` capture.
    ReadCaptures { id: u64 },
    /// Restore the original bytes at a `CaptureReg` target and free the
    /// scratch ring. No residual patch.
    UninstallCapture { id: u64 },
    /// Disarm any active watchpoint or breakpoint and restore any patched bytes.
    ClearBreakpoints,
    /// Poll for a hit from an armed watchpoint/breakpoint that fired since the
    /// last poll. Returns `None` if none is pending.
    PollHit,
    /// Query the status of in-game render loop hooking (DXGI/DX9/OpenGL) and input capture.
    GetRenderStatus,
    /// Wait until the injected DLL has completed graphics/hook setup and is fully ready.
    WaitForReady,
    /// Set the visibility of the in-game cheat overlay.
    SetOverlayVisible { visible: bool },
    /// Sync active cheats from GUI to the in-game overlay & pinning loop.
    SyncCheats { cheats: Vec<OverlayCheatDto> },
    /// Configure or initialize in-game render and input hooks via IPC.
    ConfigureRender {
        /// Whether to hook Present/EndScene for in-game overlay rendering.
        overlay: bool,
        /// Whether to install WndProc hooks for message handling/hotkeys.
        hook_wndproc: bool,
        /// Whether to initialize controller polling hooks.
        xinput_hooks: bool,
    },
    /// Retrieve captured network packets from the DLL ring buffer or session log.
    GetNetworkLog {
        limit: Option<usize>,
        offset: Option<usize>,
        filter_proto: Option<PacketKind>,
        filter_endpoint: Option<String>,
    },
    /// Clear the captured network packets buffer.
    ClearNetworkLog,
    /// Configure or toggle network traffic interception.
    ConfigureNetworkHook {
        enabled: bool,
        /// Ports to explicitly ignore (e.g. trainer IPC port, MCP port).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        ignore_ports: Vec<u16>,
        /// Whether to capture loopback (127.0.0.1 / ::1 / localhost) traffic. Defaults to false.
        #[serde(default)]
        capture_loopback: bool,
    },
    /// Initialize the injected DLL session with requested features and filters (consolidated capability handshake).
    InitializeSession {
        features: InjectFeaturesConfig,
    },
    /// Sync active dynamic memory pins to the injected DLL's frame-cadence loop.
    SyncPins {
        pins: Vec<PinSpec>,
    },
    /// Clear all active dynamic memory pins in the injected DLL.
    ClearPins,
}

/// The response to a [`Request`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    /// Reply to [`Request::Ping`]. Includes version and advertised DLL capabilities.
    Pong {
        version: String,
        #[serde(default)]
        capabilities: Vec<String>,
    },
    /// Reply to [`Request::Read`].
    Read { data: Vec<u8> },
    /// Reply to [`Request::Write`].
    Write { bytes_written: usize },
    /// Reply to [`Request::ScanAob`].
    ScanAob { matches: Vec<u64> },
    /// Reply to [`Request::Allocate`].
    Allocate { address: u64 },
    /// Reply to [`Request::Free`].
    Free { ok: bool },
    /// Reply to [`Request::InstallCave`]. Carries the cave address (a handle)
    /// and the original bytes that were overwritten (for undo).
    CaveInstalled {
        /// The allocated cave address (the handle).
        cave: u64,
        /// The target call site that was patched.
        target: u64,
        /// The original bytes that were overwritten at `target`.
        original: Vec<u8>,
    },
    /// Reply to [`Request::ListRegions`].
    ListRegions { regions: Vec<RegionInfo> },
    /// Reply to [`Request::Scan`] or [`Request::Next`].
    ScanResult { matches: Vec<(u64, f64)> },
    /// Reply to [`Request::PointerScan`].
    PointerScan { matches: Vec<(u64, u64)> },
    /// Reply to [`Request::PointerChase`].
    PointerChase { hops: Vec<u64> },
    /// Reply to [`Request::WatchWrites`] or [`Request::BreakOnCode`] once the
    /// watchpoint/breakpoint has actually fired. Carries the captured register
    /// state plus (for breakpoints) a stack trace.
    WatchHit {
        rip: u64,
        rax: u64,
        rbx: u64,
        rcx: u64,
        rdx: u64,
        rsi: u64,
        rdi: u64,
        rsp: u64,
        rbp: u64,
        /// Human-readable description of the event.
        description: String,
        /// Stack trace as formatted hex addresses (T-029 breakpoints only).
        stack: Vec<String>,
    },
    /// Reply to [`Request::WatchWrites`] / [`Request::BreakOnCode`] confirming
    /// the hardware/software breakpoint is now armed.
    WatchArmed,
    /// Reply to [`Request::BreakOnCode`] confirming the int3 breakpoint is armed.
    BreakArmed,
    /// Reply to [`Request::ClearBreakpoints`].
    BreakpointsCleared,
    /// Reply to [`Request::PollHit`]. `hit` is `Some` if a watchpoint/breakpoint
    /// fired since the last poll.
    PollHit {
        hit: Option<WatchHitInfo>,
        #[serde(default)]
        hits: Vec<WatchHitInfo>,
    },
    /// Reply to [`Request::CaptureReg`]. `id` identifies the capture for
    /// [`Request::ReadCaptures`] / [`Request::UninstallCapture`]; `scratch` is
    /// the DLL-allocated ring buffer address (readable via `read`); `target`
    /// and `original` are the patched site for undo.
    CaptureInstalled {
        id: u64,
        scratch: u64,
        target: u64,
        original: Vec<u8>,
    },
    /// Reply to [`Request::ReadCaptures`]: the recorded entries, oldest first,
    /// plus whether the capture has disarmed itself (one_shot / stop_on_match
    /// fired).
    ReadCaptures {
        entries: Vec<CaptureEntry>,
        disarmed: bool,
    },
    /// Reply to [`Request::UninstallCapture`].
    CaptureUninstalled { id: u64 },
    /// Reply to [`Request::GetRenderStatus`].
    RenderStatus {
        /// Detected graphics API (e.g. "DXGI (Direct3D 11/12)", "Direct3D 9", "OpenGL", "None").
        api: String,
        /// Whether the frame presentation function (e.g. Present / EndScene) is actively hooked.
        present_hooked: bool,
        /// Whether the game's window procedure is hooked for keyboard/mouse input capture.
        wndproc_hooked: bool,
        /// Total number of rendered frames intercepted since injection.
        frame_count: u64,
        /// Whether the in-game overlay is currently visible.
        overlay_visible: bool,
        /// Name of active input hook subsystem (e.g. "SDL2 GameController", "XInput", "DirectInput8", "RawInput (WM_INPUT)").
        input_hook: String,
        /// Total number of controller / hotkey combo toggle events recorded.
        combo_count: u64,
        /// Third-party overlays detected in-process (e.g. Steam, OBS, Discord, RTSS).
        detected_overlays: Vec<String>,
    },
    /// Reply to [`Request::WaitForReady`] confirming the injected DLL is fully initialized.
    Ready {
        api: String,
        input_hook: String,
        present_hooked: bool,
        frame_count: u64,
        combo_count: u64,
    },
    /// Reply to [`Request::SetOverlayVisible`].
    OverlayVisibilitySet { visible: bool },
    /// Reply to [`Request::SyncCheats`].
    CheatsSynced { count: usize },
    /// Reply to [`Request::ConfigureRender`].
    RenderConfigured {
        overlay: bool,
        hook_wndproc: bool,
        xinput_hooks: bool,
    },
    /// Reply to [`Request::GetNetworkLog`].
    NetworkLog {
        packets: Vec<NetworkPacketDto>,
        total_captured: usize,
    },
    /// Reply to [`Request::ClearNetworkLog`].
    NetworkLogCleared { cleared: usize },
    /// Reply to [`Request::ConfigureNetworkHook`].
    NetworkHookConfigured { enabled: bool },
    /// Reply to [`Request::InitializeSession`] with advertised capabilities and environment diagnostics.
    SessionReady {
        capabilities: Vec<String>,
        diagnostics: EnvironmentDiagnostics,
    },
    /// Reply to [`Request::SyncPins`].
    PinsSynced { count: usize },
    /// Reply to [`Request::ClearPins`].
    PinsCleared,
    /// An error occurred while handling the request.
    Error { message: String },
}

/// Injected DLL feature enablement configuration (permissive/opt-out defaults).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectFeaturesConfig {
    #[serde(default)]
    pub display: DisplayFeatures,
    #[serde(default)]
    pub input: InputFeatures,
    #[serde(default)]
    pub network: NetworkFeatures,
    #[serde(default)]
    pub memory: MemoryFeatures,
}

impl Default for InjectFeaturesConfig {
    fn default() -> Self {
        Self {
            display: DisplayFeatures::default(),
            input: InputFeatures::default(),
            network: NetworkFeatures::default(),
            memory: MemoryFeatures::default(),
        }
    }
}

/// Display and rendering hook features.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisplayFeatures {
    /// In-game DXGI/Present swapchain overlay rendering. Default: true.
    #[serde(default = "default_true")]
    pub overlay: bool,
}

impl Default for DisplayFeatures {
    fn default() -> Self {
        Self { overlay: true }
    }
}

/// Input interception features.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputFeatures {
    /// Window message hook for keyboard hotkeys (WndProc). Default: true.
    #[serde(default = "default_true")]
    pub wndproc: bool,
    /// XInput gamepad polling hook for controller navigation. Default: true.
    #[serde(default = "default_true")]
    pub xinput: bool,
}

impl Default for InputFeatures {
    fn default() -> Self {
        Self {
            wndproc: true,
            xinput: true,
        }
    }
}

/// Network traffic interception features.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkFeatures {
    /// Winsock socket hook (`send`, `recv`, `sendto`, `recvfrom`). Default: true.
    #[serde(default = "default_true")]
    pub winsock: bool,
    /// WinHTTP API hook (`WinHttpSendRequest`, `WinHttpReadData`). Default: true.
    #[serde(default = "default_true")]
    pub winhttp: bool,
    /// SChannel TLS/HTTPS plaintext hook (`EncryptMessage`, `DecryptMessage`). Default: true.
    #[serde(default = "default_true")]
    pub schannel: bool,
    /// Whether to capture loopback (127.0.0.1 / localhost) traffic. Default: false.
    #[serde(default = "default_false")]
    pub capture_loopback: bool,
    /// Ports to ignore from capture (e.g. internal IPC or MCP ports).
    #[serde(default)]
    pub ignore_ports: Vec<u16>,
}

impl Default for NetworkFeatures {
    fn default() -> Self {
        Self {
            winsock: true,
            winhttp: true,
            schannel: true,
            capture_loopback: false,
            ignore_ports: Vec::new(),
        }
    }
}

/// Memory scanning, debugging, and value enforcement features.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryFeatures {
    /// In-process frame-cadence value pinning in render loop. Default: true.
    #[serde(default = "default_true")]
    pub frame_pinning: bool,
    /// Page guard & hardware debug register watchpoints. Default: true.
    #[serde(default = "default_true")]
    pub watchpoints: bool,
    /// Single-fire software breakpoints (`int3`). Default: true.
    #[serde(default = "default_true")]
    pub breakpoints: bool,
    /// Passive non-stalling register capture trampolines. Default: true.
    #[serde(default = "default_true")]
    pub trampoline_capture: bool,
}

impl Default for MemoryFeatures {
    fn default() -> Self {
        Self {
            frame_pinning: true,
            watchpoints: true,
            breakpoints: true,
            trampoline_capture: true,
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

/// Runtime diagnostics reported by the injected DLL upon initialization.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EnvironmentDiagnostics {
    pub target_os: String,
    pub graphics_api: String,
    pub input_subsystem: String,
    pub loaded_network_modules: Vec<String>,
    pub detected_overlays: Vec<String>,
    pub watchpoints_supported: bool,
}

/// A value pinning specification executed every cadence (frame in DLL or timer in GUI).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PinSpec {
    pub id: u64,
    pub label: String,
    pub enabled: bool,
    pub ops: Vec<PinOp>,
    #[serde(default)]
    pub provider: PinProvider,
}

/// Execution provider for a pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PinProvider {
    /// Optimal: inside injected DLL on render frame presentation.
    #[default]
    InProcessFrame,
    /// Fallback: external GUI background timer loop.
    ExternalTimer,
}

/// Individual micro-instruction executed sequentially within a pin cadence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PinOp {
    /// Safeguard: assert address is not null (0x0). If 0x0, abort remainder of this pin's ops.
    AssertNotNull { address: u64 },
    /// Constant write: write bytes to target address.
    WriteConstant { address: u64, data: Vec<u8> },
    /// Dynamic copy / arithmetic write: `dst = src` or `dst = src + addend`.
    CopyValue {
        src_address: u64,
        dst_address: u64,
        value_type: crate::scan::ValueType,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        addend: Option<f64>,
        #[serde(default)]
        max_only: bool,
    },
}

/// A serialized cheat representation sent to the injected in-game overlay.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OverlayCheatDto {
    pub id: u64,
    pub label: String,
    pub address: u64,
    pub kind_str: String, // "toggle", "value", "button"
    pub enabled: bool,
    pub current_value: Option<String>,
    pub group: Option<String>,
    pub hotkey: Option<String>,
    pub pinned_bytes: Option<Vec<u8>>,
}

/// A single register value captured by a `CaptureReg` capture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureEntry {
    /// Sequence number (0-based, increments each capture).
    pub seq: u64,
    /// The captured register value, decoded per the spec's `value_type`.
    pub reg_value: f64,
    /// The value as a raw 64-bit word (always present, un-decoded).
    pub raw: u64,
    /// The return address captured alongside (the instruction that was
    /// executing when the site hit — i.e. `target`).
    pub rip: u64,
    /// The gate register's value at capture time, decoded per the spec's
    /// `value_type` (0.0 if the capture is ungated).
    pub gate_value: f64,
    /// Whether the game is still running (captures are passive; always true).
    pub captured_at: u64,
}

/// A memory region description, used by [`Request::ListRegions`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionInfo {
    pub start: u64,
    pub end: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    /// Human-readable label if known (e.g. a mapped file name).
    pub name: Option<String>,
}

/// The captured register + stack state of a watchpoint/breakpoint hit.
///
/// Shared payload for [`Response::WatchHit`] and [`Response::PollHit`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchHitInfo {
    pub rip: u64,
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    /// Human-readable description of the event.
    pub description: String,
    /// Stack trace as formatted hex addresses (breakpoints only).
    pub stack: Vec<String>,
}

/// Serialize a message into a length-prefixed frame.
pub fn encode<T: Serialize>(msg: &T) -> Result<Vec<u8>, bincode::Error> {
    let body = bincode::serialize(msg)?;
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Deserialize a length-prefixed frame.
pub fn decode<T: for<'de> Deserialize<'de>>(frame: &[u8]) -> Result<T, bincode::Error> {
    if frame.len() < 4 {
        return Err(bincode::ErrorKind::SizeLimit.into());
    }
    let len = u32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    if frame.len() < 4 + len {
        return Err(bincode::ErrorKind::SizeLimit.into());
    }
    bincode::deserialize(&frame[4..4 + len])
}

/// Protocol classification of captured network packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PacketKind {
    Tcp,
    Udp,
    Http,
}

impl PacketKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            PacketKind::Tcp => "tcp",
            PacketKind::Udp => "udp",
            PacketKind::Http => "http",
        }
    }
}

/// Direction of network traffic relative to the game process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PacketDirection {
    Inbound,
    Outbound,
}

impl PacketDirection {
    pub fn as_str(&self) -> &'static str {
        match self {
            PacketDirection::Inbound => "inbound",
            PacketDirection::Outbound => "outbound",
        }
    }
}

/// A structured representation of a captured network packet or HTTP request/response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkPacketDto {
    pub id: u64,
    pub timestamp_ms: u64,
    pub kind: PacketKind,
    pub direction: PacketDirection,
    pub local_endpoint: Option<String>,
    pub remote_endpoint: Option<String>,
    pub url: Option<String>,
    pub headers: Option<String>,
    pub payload_len: usize,
    /// Truncated preview bytes for wire transport / lightweight inspection (e.g. up to 256 bytes).
    pub payload_preview: Vec<u8>,
    /// Optional relative path or URL to full dumped payload if offloaded to disk.
    pub artifact_file: Option<String>,
    /// Address in target game memory where full un-truncated payload is staged (if > 256 bytes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub staged_ptr: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_packet_roundtrip() {
        let packet = NetworkPacketDto {
            id: 42,
            timestamp_ms: 1725300000,
            kind: PacketKind::Udp,
            direction: PacketDirection::Outbound,
            local_endpoint: Some("127.0.0.1:54321".into()),
            remote_endpoint: Some("192.168.1.100:27015".into()),
            url: None,
            headers: None,
            payload_len: 12,
            payload_preview: vec![0xde, 0xad, 0xbe, 0xef],
            artifact_file: Some("captures/packet_42.bin".into()),
            staged_ptr: Some(0x7ff70000),
        };

        let msg = Message::Event(Event::NetworkPacket(packet.clone()));
        let encoded = encode(&msg).expect("failed to encode NetworkPacket event");
        let decoded: Message = decode(&encoded).expect("failed to decode NetworkPacket event");

        if let Message::Event(Event::NetworkPacket(p)) = decoded {
            assert_eq!(p, packet);
        } else {
            panic!("expected NetworkPacket event");
        }
    }

    #[test]
    fn test_pong_capabilities_roundtrip() {
        let pong = Response::Pong {
            version: "0.1.0".into(),
            capabilities: vec!["memory".into(), "network_capture".into()],
        };
        let encoded = encode(&pong).expect("failed to encode Pong");
        let decoded: Response = decode(&encoded).expect("failed to decode Pong");

        if let Response::Pong { version, capabilities } = decoded {
            assert_eq!(version, "0.1.0");
            assert_eq!(capabilities, vec!["memory", "network_capture"]);
        } else {
            panic!("expected Pong response");
        }
    }
}

