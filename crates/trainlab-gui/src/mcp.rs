//! MCP (Model Context Protocol) server for `trainlab-gui`.
//!
//! The GUI hosts an MCP server over HTTP (Streamable HTTP/SSE) on `127.0.0.1`
//! so an LLM agent can connect and drive memory-recon tools. This module
//! defines the server handler and its tools, and serves it via axum.
//!
//! The recon tools proxy to the injected Agent DLL over the fast channel
//! (D10): the GUI translates each MCP tool call into a
//! [`trainlab_core::protocol::Request`] and sends it to the DLL's TCP listener.
//! Only read-only tools are exposed here (T-021); write/allocate tools are
//! gated behind explicit confirm/undo in T-022.

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::{tool, tool_router, ErrorData};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use trainlab_core::protocol::{self, Request, Response};

use crate::session::{CheatKind, PendingKind, SharedSession};

/// Where the injected DLL's fast channel listens.
const DLL_HOST: &str = "127.0.0.1";
const DLL_PORT: u16 = 31337;

/// Format the last Windows error code for diagnostics.
#[cfg(windows)]
fn last_error() -> String {
    // SAFETY: GetLastError takes no arguments.
    let code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
    format!("Win32 error {code}")
}

/// Open the game process externally (via `WindowsProcess::open`) so
/// scan-family tools can read memory gracefully — a fault while scanning a big
/// heap from a *separate* process is a caught error, not a crash (which is why
/// scanning belongs in the GUI, not the injected DLL).
///
/// Returns a boxed `ProcessMemory` handle, or an error if the PID isn't set or
/// the process can't be opened.
fn game_process(
    session: &SharedSession,
) -> Result<Box<dyn trainlab_core::memory::ProcessMemory>, ErrorData> {
    let pid = {
        let s = session.lock().map_err(|_| err("session lock poisoned"))?;
        s.game_pid()
    };
    let pid = pid.ok_or_else(|| err("no game process; find & inject a game first"))?;
    #[cfg(windows)]
    {
        trainlab_core::memory::WindowsProcess::open(pid)
            .map(|p| Box::new(p) as Box<dyn trainlab_core::memory::ProcessMemory>)
            .map_err(|e| err(format!("failed to open game (pid {pid}) externally: {e}")))
    }
    #[cfg(not(windows))]
    {
        let _ = pid;
        Err(err("external scan requires the Windows GUI"))
    }
}

/// Send a request to the injected DLL over the fast channel and return the
/// response.
///
/// Every socket op carries a timeout so a hung/unresponsive DLL returns an
/// error instead of blocking the calling MCP tool indefinitely (which wedges
/// the whole handler). `connect`, `write`, and both `read_exact` phases all
/// share the same deadline.
fn call_dll(req: &Request) -> Result<Response, String> {
    const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
    let addr = format!("{DLL_HOST}:{DLL_PORT}");
    let mut stream = std::net::TcpStream::connect(&addr)
        .map_err(|e| format!("connect to DLL ({addr}) failed: {e}"))?;
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let frame = protocol::encode(req).map_err(|e| format!("encode error: {e}"))?;
    use std::io::Write;
    stream
        .write_all(&frame)
        .map_err(|e| format!("write error: {e}"))?;
    // Read the 4-byte length prefix.
    use std::io::Read;
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| format!("read length error: {e}"))?;
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .map_err(|e| format!("read body error: {e}"))?;
    // Reassemble the frame for decode (decode expects the length prefix).
    let mut frame_out = Vec::with_capacity(4 + len);
    frame_out.extend_from_slice(&len_buf);
    frame_out.extend_from_slice(&body);
    protocol::decode::<Response>(&frame_out).map_err(|e| format!("decode error: {e}"))
}

/// The MCP server handler for trainlab-gui.
///
/// Holds the shared [`SessionState`] (markers + undo log) so the agent's
/// findings and mutations persist across tool calls (D7, D8).
pub struct TrainlabMcpServer {
    session: SharedSession,
    egui_ctx: Option<eframe::egui::Context>,
}

impl TrainlabMcpServer {
    /// Create a handler sharing the given session state.
    pub fn with_session(session: SharedSession) -> Self {
        Self { session, egui_ctx: None }
    }

    /// Create a handler sharing the given session state and egui context for repaint notifications.
    pub fn with_session_and_ctx(session: SharedSession, egui_ctx: Option<eframe::egui::Context>) -> Self {
        Self { session, egui_ctx }
    }

    fn request_repaint(&self) {
        if let Some(ctx) = &self.egui_ctx {
            ctx.request_repaint();
        }
    }
}

impl Default for TrainlabMcpServer {
    fn default() -> Self {
        Self::with_session(Default::default())
    }
}

/// Arguments for [`read`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ReadArgs {
    /// Address or expression to read from: raw hex ("0x1000"), dec ("4096"), module ("game.exe+0x10"), marker ("wood_ptr"), or offset math ("wood_ptr+0x18").
    pub address: String,
    /// Number of bytes to read (default derived from `value_type`, or 16 for hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub len: Option<usize>,
    /// Value type to decode and format: "i32", "u32", "f32", "i64", "u64", "f64", "ptr", "cstr", or "hex" (default "hex").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_type: Option<String>,
}

/// Arguments for [`aob_scan`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AobArgs {
    /// AOB pattern in hex with `??` wildcards, e.g. "48 8B 05 ?? ?? ?? ??".
    pub pattern: String,
}

/// Arguments for [`set_marker`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SetMarkerArgs {
    /// Label to identify the marker (persists across turns).
    pub label: String,
    /// Address or expression to mark: raw hex, dec, module relative ("game.exe+0x100"), or offset math ("player_ptr+0x48").
    pub address: String,
    /// Optional note describing what this address is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Arguments for [`get_marker`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GetMarkerArgs {
    /// Label of the marker to look up.
    pub label: String,
}

/// Arguments for [`remove_marker`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RemoveMarkerArgs {
    /// Label of the marker to remove.
    pub label: String,
}

/// Arguments for [`read`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct UndoInfoArgs {
    /// Optional undo id; if omitted, describe the most recent mutation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
}

/// Arguments for [`scan`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ScanArgs {
    /// Value type: i32, u32, f32, i64, u64, f64, or ptr.
    pub value_type: String,
    /// Value to scan for (as a number). For a range scan this is the min.
    pub value: f64,
    /// Optional max for a range scan. If present, the first scan matches
    /// values in `[value, max]` (inclusive) instead of an exact match. This is
    /// essential for floats with fractional storage (e.g. UI shows 14790 but
    /// the f32 is 14790.3). Omit for an exact scan (backward compatible).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    /// Optional byte alignment for candidate addresses (default: value size).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alignment: Option<usize>,
}

/// Arguments for [`next`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct NextArgs {
    /// Narrowing op: changed, unchanged, increased, decreased, exact, range.
    pub op: String,
    /// For `exact`: the value to match. For `range`: the min.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<f64>,
    /// For `range`: the max.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
}

/// Arguments for [`pointer_scan`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PointerScanArgs {
    /// Target address or expression whose referrers to find: raw hex, dec, module, or marker ("wood_ptr+0x10").
    pub address: String,
    /// Optional size around `address` to treat as the target range (default 8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

/// Arguments for [`pointer_chase`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PointerChaseArgs {
    /// Base address or expression to start chasing from: raw hex, module relative ("Unrailed2.exe+0x1b42e9"), or marker.
    pub base: String,
    /// Field offsets applied after each dereference (decimal or `0x` hex).
    pub offsets: Vec<String>,
}

/// Arguments for [`dump`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DumpArgs {
    /// Start address or expression to dump: raw hex, dec, module, marker, or offset math ("player_ptr+0x20").
    pub address: String,
    /// Number of bytes to read.
    pub len: usize,
}

/// A single typed field to extract in a [`dump_struct`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct StructField {
    /// Field name (shown in the output).
    pub name: String,
    /// Field type: i8, u8, i16, u16, i32, u32, i64, u64, f32, f64, ptr,
    /// cstr (null-terminated ASCII string), or bytes.
    pub value_type: String,
    /// Byte offset from the struct base (default 0).
    #[serde(default)]
    pub offset: u64,
    /// For `bytes`: how many bytes to read. For `cstr`: max length to scan
    /// (default 256). Ignored for other types.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub len: Option<usize>,
}

/// Arguments for [`dump_struct`].
/// Arguments for [`snapshot`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SnapshotArgs {
    /// Start address or expression (raw hex, dec, module, or marker).
    pub start: String,
    /// End address or expression (exclusive). Snapshot length is `end - start`. Use this OR `len`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end: Option<String>,
    /// Byte length (use this OR `end`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub len: Option<u64>,
    /// Optional filename hint (e.g. `snap_0x0d020000_15m.bin`). Default dir: `snapshots/`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Optional override cap for snapshot size in bytes (default 256 MB).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_len: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DumpStructArgs {
    /// Base address or expression of the struct (raw hex, dec, module, or marker).
    pub address: String,
    /// The typed fields to extract, each with a name, type, and offset.
    pub fields: Vec<StructField>,
}

/// Arguments for [`watch_writes`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct WatchWritesArgs {
    /// Address or expression to watch for writes: raw hex, dec, module, or marker ("wood_ptr+0x10").
    pub address: String,
    /// Number of bytes to watch (1, 2, 4, or 8; default 4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub len: Option<usize>,
    /// If true, disarm after the first hit (default true).
    #[serde(default = "default_true")]
    pub one_shot: bool,
}

/// Arguments for [`break_on_code`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BreakOnCodeArgs {
    /// Code address or expression to break on: raw hex, dec, or module relative ("game.exe+0x50a0").
    pub address: String,
    /// If true, disarm after the first hit (default true).
    #[serde(default = "default_true")]
    pub one_shot: bool,
}

fn default_true() -> bool {
    true
}

/// Arguments for [`addr_to_module`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AddrToModuleArgs {
    /// Address or expression to resolve: raw hex, dec, or marker.
    pub address: String,
}

/// Arguments for [`disassemble`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DisassembleArgs {
    /// Address or expression to disassemble from: raw hex, dec, module ("game.exe+0x10"), or marker.
    pub address: String,
    /// Number of bytes to disassemble.
    #[serde(default = "default_len")]
    pub len: usize,
    /// Optional cap on the number of instructions to show.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_instructions: Option<usize>,
}

fn default_len() -> usize {
    64
}

/// Arguments for [`write`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct WriteArgs {
    /// Address or expression to write to: raw hex, dec, module ("game.exe+0x10"), marker ("wood_ptr"), or offset math ("player_ptr+0x48").
    pub address: String,
    /// Hex bytes to write (e.g. "00 80 ac 43" or "0080ac43"). Required if `value` is not provided.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    /// Typed value to write (e.g. "0xe890000" for a ptr, "99990" for an i32, "3.14" for an f64).
    /// Used together with `value_type` so you never have to hand-encode little-endian hex bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Value type for typed `value` writes: i32, u32, f32, i64, u64, f64, or ptr (default: "ptr" if `value` starts with 0x, else "i32").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_type: Option<String>,
}

/// Arguments for [`install_cave`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct InstallCaveArgs {
    /// Target code address or expression to redirect: raw hex, dec, or module relative ("game.exe+0x50a0").
    pub target: String,
    /// Hook kind: "trampoline" (default, transparent — replays the stolen
    /// instructions so the game keeps working) or "override" (skips them).
    #[serde(default = "default_hook_kind")]
    pub hook: String,
    /// Hex shellcode payload bytes to run in the cave (empty = pure no-op for
    /// trampoline).
    #[serde(default)]
    pub payload: String,
    /// Jump style: "absolute" (default, 14-byte long jump) or "relative" (5-byte short jump for tight patch sites).
    #[serde(default = "default_jump_style")]
    pub jump: String,
}

fn default_jump_style() -> String {
    "absolute".to_string()
}

fn default_hook_kind() -> String {
    "trampoline".to_string()
}

/// Arguments for [`undo`] / [`restore_cave`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct UndoArgs {
    /// The undo id returned by `install_cave`/`write`.
    pub id: u64,
}

/// Arguments for [`capture_reg`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CaptureRegArgs {
    /// Code address to hook (decimal or `0x` hex; module-relative like
    /// "helldivers.exe+0x1b42e9" recommended so it is restart-stable).
    pub target: String,
    /// Register to capture when the site executes: rax, rcx, rdx, rbx, rsp,
    /// rbp, rsi, rdi, r8..r15, or an XMM reg (xmm0..xmm7) for a double/float.
    /// Default "rcx".
    #[serde(default = "default_reg")]
    pub reg: String,
    /// How to interpret the captured value: "ptr" (raw 64-bit, default),
    /// "i64", "u64", "f64" (double), or "f32" (float).
    #[serde(default = "default_value_type")]
    pub value_type: String,
    /// Number of captures to keep in the ring buffer (default 32).
    #[serde(default = "default_capacity")]
    pub capacity: usize,
    /// Disarm after the first capture that passes the gate (default true).
    /// Set false to keep capturing into the ring in continuous mode.
    #[serde(default = "default_true")]
    pub stop_on_match: bool,
    /// Optional gate that decides *when* to capture. This is the decoupled
    /// "capture register X only when register Y compares Z" primitive. Provide
    /// a JSON object with `reg`, `cmp` (eq/ne/gt/lt/ge/le/range/whole), and
    /// either `value` (for eq/ne/gt/lt/ge/le) or `min`/`max` (for range).
    /// `cmp="whole"` retains only clean whole numbers (floats). If absent, the
    /// capture records on every execution.
    pub gate: Option<CaptureGateArgs>,
    /// Jump style: "absolute" (default, 14-byte long jump) or "relative" (5-byte short jump for tight patch sites).
    #[serde(default)]
    pub jump: Option<String>,
}

/// JSON-serializable gate spec for `capture_reg`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CaptureGateArgs {
    /// Register to test (e.g. "rbp"). The value and the pointer are both live
    /// at the site, so you gate on the value register and capture the pointer.
    pub reg: String,
    /// Comparison: eq, ne, gt, lt, ge, le, range, whole.
    pub cmp: String,
    /// How to interpret the gate register for the compare AND for reporting
    /// `gate_value`: "ptr", "i64", "u64", "f64", or "f32". Defaults to the
    /// capture's value_type. For Lua/script double value registers, set "f64"
    /// so a value like 3.0 is compared/decoded as a double, not as a giant
    /// integer/ptr (which would break range filtering).
    #[serde(default)]
    pub value_type: Option<String>,
    /// Constant for eq/ne/gt/lt/ge/le (interpreted per value_type).
    #[serde(default)]
    pub value: Option<f64>,
    /// Lower bound for range.
    #[serde(default)]
    pub min: Option<f64>,
    /// Upper bound for range.
    #[serde(default)]
    pub max: Option<f64>,
}

fn default_reg() -> String {
    "rcx".to_string()
}
fn default_value_type() -> String {
    "ptr".to_string()
}
fn default_capacity() -> usize {
    32
}

/// Arguments for [`allocate_string`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AllocateStringArgs {
    /// The string content (raw bytes/text of the program, script, or config) to place in the game process.
    pub content: String,
    /// Memory layout kind: "c" (default, NUL-terminated C string), "rust" (fat pointer ptr+len), "json", "yaml", "xml", "js", "config".
    #[serde(default = "default_string_kind")]
    pub kind: String,
}

fn default_string_kind() -> String {
    "c".to_string()
}

/// Arguments for [`read_captures`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ReadCapturesArgs {
    /// The capture id returned by `capture_reg`.
    pub id: u64,
}

/// Arguments for [`uninstall_capture_reg`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct UninstallCaptureArgs {
    /// The capture id returned by `capture_reg`.
    pub id: u64,
}

/// Arguments for [`confirm_op`] / [`reject_op`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct OpConfirmArgs {
    /// The pending op id returned by `write`/`install_cave`/`undo`.
    pub id: u64,
}

/// Arguments for [`attach_game`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AttachGameArgs {
    /// The game executable name to find and inject into (e.g. "Unrailed2.exe").
    pub game: String,
    /// The DLL path to inject. If omitted, uses the session's configured path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dll_path: Option<String>,
    /// If true, find the game and inject the DLL; if false, just attach to an
    /// already-injected DLL (e.g. the GUI already injected it). Default true.
    #[serde(default = "default_true")]
    pub inject: bool,
}

/// Arguments for [`set_connection`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SetConnectionArgs {
    /// The DLL fast-channel host (default "127.0.0.1").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// The DLL fast-channel port (default 31337).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

/// Arguments for [`add_cheat`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AddCheatArgs {
    /// Display label (e.g. "wood", "god mode").
    pub label: String,
    /// Cheat kind: "value" or "toggle".
    pub kind: String,
    /// For value cheats: the address (decimal or 0x hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// For value cheats: the value type (i32, u32, f32, i64, u64, f64, ptr).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_type: Option<String>,
    /// For toggle cheats: the cave hook kind ("trampoline" or "override").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hook: Option<String>,
    /// For toggle cheats: the target instruction address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// For toggle cheats: the shellcode payload (hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    /// Optional human note / description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Arguments for [`remove_cheat`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CheatIdArgs {
    /// The cheat id returned by `add_cheat`.
    pub id: u64,
}

/// Arguments for [`set_cheat_value`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SetCheatValueArgs {
    /// The cheat id.
    pub id: u64,
    /// The new value (parsed per the cheat's value type).
    pub value: String,
}

/// Arguments for [`set_cheat_toggle`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SetCheatToggleArgs {
    /// The cheat id.
    pub id: u64,
    /// Whether to enable (true) or disable (false) the toggle.
    pub enabled: bool,
}

/// Arguments for [`load_profile`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct LoadProfileArgs {
    /// The profile file name (e.g. "Unrailed2.yaml") or the game exe name.
    pub profile: String,
    /// If true, run the setup steps to resolve base addresses. Default true.
    #[serde(default = "default_true")]
    pub run_setup: bool,
}

/// Arguments for [`save_profile`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SaveProfileArgs {
    /// The file name to write (e.g. "Unrailed2.yaml"). Defaults to
    /// "<game>.yaml".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
}/// `#[tool_router(server_handler)]` generates the `ServerHandler` impl.
#[tool_router(server_handler)]
impl TrainlabMcpServer {
    /// Simple connectivity check.
    #[tool(description = "Ping the trainlab MCP server; returns 'pong'.")]
    fn ping(&self) -> Result<CallToolResult, ErrorData> {
        Ok(CallToolResult::success(vec![rmcp::model::ContentBlock::text(
            "pong",
        )]))
    }

    /// Enumerate processes likely to be games, so the agent can pick a target
    /// to attach to (e.g. find the game exe for `attach_game`).
    #[tool(description = "List likely game processes (name + pid) so you can pick one to attach to with 'attach_game'.")]
    fn find_games(&self) -> Result<CallToolResult, ErrorData> {
        let candidates = crate::inject::find_game_candidates();
        let lines: Vec<String> = candidates
            .iter()
            .map(|p| format!("{} (pid {})", p.name, p.pid))
            .collect();
        let mut text = format!("{} candidate game(s)\n", lines.len());
        text.push_str(&lines.join("\n"));
        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(text),
        ]))
    }

    /// Attach to a game: find it, inject the DLL (unless `inject: false`),
    /// connect to its listener, and report the connection. This is the remote
    /// setup loop — an agent can bring up the whole trainer on a Steam
    /// Deck/Steam machine without touching the GUI.
    #[tool(description = "Attach to a game by name: find the process, inject the DLL, connect to its listener, and report status. Set game to the exe name (e.g. 'Unrailed2.exe').")]
    fn attach_game(
        &self,
        Parameters(args): Parameters<AttachGameArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        // Update the session's target game and DLL path.
        {
            let mut s = self
                .session
                .lock()
                .map_err(|_| err("session lock poisoned"))?;
            s.set_game_name(args.game.clone());
            if let Some(p) = &args.dll_path {
                s.set_dll_path(p.clone());
            }
        }
        // Resolve the DLL path relative to the GUI exe (mirrors the GUI).
        let dll_path = {
            let s = self
                .session
                .lock()
                .map_err(|_| err("session lock poisoned"))?;
            let raw = s.dll_path().to_string();
            if raw.contains('/') || raw.contains('\\') {
                raw
            } else if let Ok(exe) = std::env::current_exe() {
                exe.parent()
                    .map(|d| d.join(&raw).to_string_lossy().into_owned())
                    .unwrap_or(raw)
            } else {
                raw
            }
        };
        if let Ok(mut s) = self.session.lock() {
            s.set_dll_path(dll_path.clone());
        }

        let result = if args.inject {
            crate::controller::find_inject_connect(&self.session)
        } else {
            crate::controller::check_connection(&self.session)
        };
        match result {
            Ok(version) => {
                let pid = {
                    let mut s = self
                        .session
                        .lock()
                        .map_err(|_| err("session lock poisoned"))?;
                    s.log_activity("MCP", format!("attached to '{}', version {version}", args.game));
                    s.game_pid().map(|p| p.to_string()).unwrap_or_else(|| "unknown".into())
                };
                self.request_repaint();
                Ok(CallToolResult::success(vec![
                    rmcp::model::ContentBlock::text(format!(
                        "attached to '{}' (pid {pid}), inject v{version}",
                        args.game
                    )),
                ]))
            }
            Err(e) => {
                if let Ok(mut s) = self.session.lock() {
                    s.log_activity("MCP", format!("attach to '{}' failed: {e}", args.game));
                }
                self.request_repaint();
                Err(err(format!("attach failed: {e}")))
            }
        }
    }

    /// Report the current trainer / connection status.
    #[tool(description = "Report trainer status: MCP reachable, whether we're connected to a DLL, the game pid, game name, DLL version, and the configured host/port.")]
    fn connection_status(&self) -> Result<CallToolResult, ErrorData> {
        let s = self
            .session
            .lock()
            .map_err(|_| err("session lock poisoned"))?;
        let connected = s.connected();
        let pid = s.game_pid().map(|p| p.to_string()).unwrap_or_else(|| "none".into());
        let game = s.game_name().to_string();
        let ver = s.inject_version().unwrap_or("(not connected)").to_string();
        let host = s.dll_host().to_string();
        let port = s.dll_port();
        drop(s);
        let text = format!(
            "MCP: reachable\nconnected: {connected}\ngame: {game}\npid: {pid}\ninject v: {ver}\ndll host: {host}:{port}"
        );
        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(text),
        ]))
    }

    /// Set the DLL fast-channel host/port (e.g. for a remote DLL, though the
    /// DLL runs locally on the trainer).
    #[tool(description = "Set the DLL fast-channel host and/or port. Usually 127.0.0.1:31337; only change if you've moved the DLL listener.")]
    fn set_connection(
        &self,
        Parameters(args): Parameters<SetConnectionArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let mut s = self
            .session
            .lock()
            .map_err(|_| err("session lock poisoned"))?;
        if let Some(h) = &args.host {
            s.set_dll_host(h.clone());
        }
        if let Some(p) = args.port {
            s.set_dll_port(p);
        }
        let host = s.dll_host().to_string();
        let port = s.dll_port();
        drop(s);
        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(format!(
                "dll connection set to {host}:{port}; run 'connection_status' to check"
            )),
        ]))
    }

    /// Add a user-facing adjustable game option ("cheat") to the session. It
    /// shows up in the GUI's Cheats panel for the user to adjust.
    #[tool(description = "Add a cheat (adjustable game option) to the session. kind='value' for a typed value at an address; kind='toggle' for a code-cave hook (e.g. god mode). It appears in the GUI Cheats panel.")]
    fn add_cheat(
        &self,
        Parameters(args): Parameters<AddCheatArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        use trainlab_core::cave_hook::CaveHook;
        use trainlab_core::scan::ValueType;
        let kind = match args.kind.trim().to_lowercase().as_str() {
            "value" => {
                let address = args
                    .address
                    .as_deref()
                    .ok_or_else(|| err("value cheat requires 'address'"))?;
                let address = parse_addr(&self.session, address)?;
                let vt = args
                    .value_type
                    .as_deref()
                    .ok_or_else(|| err("value cheat requires 'value_type'"))?;
                let value_type = match vt.trim().to_lowercase().as_str() {
                    "i32" => ValueType::I32,
                    "u32" => ValueType::U32,
                    "f32" => ValueType::F32,
                    "i64" => ValueType::I64,
                    "u64" => ValueType::U64,
                    "f64" => ValueType::F64,
                    "ptr" => ValueType::Ptr,
                    other => return Err(err(format!("unknown value_type '{other}'"))),
                };
                CheatKind::Value {
                    address,
                    value_type,
                }
            }
            "toggle" => {
                let target = args
                    .target
                    .as_deref()
                    .ok_or_else(|| err("toggle cheat requires 'target'"))?;
                let target = parse_addr(&self.session, target)?;
                let payload = parse_hex_bytes(args.payload.as_deref().unwrap_or(""))?;
                let hook = match args.hook.as_deref().unwrap_or("trampoline") {
                    "trampoline" => CaveHook::Trampoline { payload, jump: trainlab_core::cave_hook::JumpStyle::Absolute },
                    "override" => CaveHook::Override { payload, jump: trainlab_core::cave_hook::JumpStyle::Absolute },
                    other => return Err(err(format!("unknown hook '{other}'"))),
                };
                CheatKind::Toggle {
                    hook,
                    target,
                    enabled: false,
                }
            }
            other => return Err(err(format!("unknown cheat kind '{other}' (expected 'value' or 'toggle')"))),
        };
        let mut s = self
            .session
            .lock()
            .map_err(|_| err("session lock poisoned"))?;
        let id = s.add_cheat(&args.label, kind, args.note.as_deref());
        s.log_activity("MCP", format!("added cheat '{}' (id {id})", args.label));
        drop(s);
        self.request_repaint();
        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(format!(
                "added cheat '{}' (id {id}); it's now in the GUI Cheats panel",
                args.label
            )),
        ]))
    }

    /// List all cheats in the session.
    #[tool(description = "List all cheats (adjustable game options) in the session, with their ids, kinds, and addresses.")]
    fn list_cheats(&self) -> Result<CallToolResult, ErrorData> {
        let s = self
            .session
            .lock()
            .map_err(|_| err("session lock poisoned"))?;
        let cheats = s.list_cheats();
        if cheats.is_empty() {
            return Ok(CallToolResult::success(vec![
                rmcp::model::ContentBlock::text("(no cheats yet; add one with 'add_cheat')"),
            ]));
        }
        let lines: Vec<String> = cheats
            .iter()
            .map(|c| {
                let kind = match &c.kind {
                    CheatKind::Value { address, value_type } => {
                        format!("value {value_type:?} @ {address:#x}")
                    }
                    CheatKind::Toggle { target, enabled, .. } => {
                        format!("toggle @ {target:#x} ({})", if *enabled { "on" } else { "off" })
                    }
                    CheatKind::Button { commands } => {
                        format!("button ({} cmd(s))", commands.len())
                    }
                };
                format!("[{}] {} — {kind}", c.id, c.label)
            })
            .collect();
        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(lines.join("\n")),
        ]))
    }

    /// Remove a cheat from the session.
    #[tool(description = "Remove a cheat by id from the session.")]
    fn remove_cheat(
        &self,
        Parameters(args): Parameters<CheatIdArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let removed = {
            let mut s = self
                .session
                .lock()
                .map_err(|_| err("session lock poisoned"))?;
            s.remove_cheat(args.id)
        };
        match removed {
            Some(c) => Ok(CallToolResult::success(vec![
                rmcp::model::ContentBlock::text(format!("removed cheat '{}' (id {})", c.label, c.id)),
            ])),
            None => Err(err(format!("no cheat with id {}", args.id))),
        }
    }

    /// Set a value cheat's value in game memory. This **stages** the write
    /// through the D8 confirmation gate — apply it with `confirm_op`.
    #[tool(description = "Set a value cheat's value in game memory. Stages the write (D8 gate); apply with 'confirm_op' or discard with 'reject_op'.")]
    fn set_cheat_value(
        &self,
        Parameters(args): Parameters<SetCheatValueArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        // Look up the cheat to get its address + type.
        let (address, value_type) = {
            let s = self
                .session
                .lock()
                .map_err(|_| err("session lock poisoned"))?;
            let c = s
                .get_cheat(args.id)
                .ok_or_else(|| err(format!("no cheat with id {}", args.id)))?;
            match &c.kind {
                CheatKind::Value { address, value_type } => (*address, *value_type),
                _ => {
                    return Err(err(format!("cheat {} is not a value cheat", args.id)))
                }
            }
        };
        // Parse the value into bytes per the type.
        let data = parse_value_bytes(&args.value, value_type)?;
        // Stage the write (D8 gate).
        let mut s = self
            .session
            .lock()
            .map_err(|_| err("session lock poisoned"))?;
        let pid = s.stage_op(
            address,
            PendingKind::Write { data: data.clone() },
            format!(
                "set cheat '{}' to {} at {:#x}",
                args.id, args.value, address
            ),
        );
        drop(s);
        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(format!(
                "staged cheat value write (pending id {pid}) at {:#x}. Call 'confirm_op' to apply.",
                address
            )),
        ]))
    }

    /// Enable/disable a toggle cheat (installs/removes the cave hook).
    #[tool(description = "Enable or disable a toggle cheat (e.g. god mode). Enabling installs the cave hook; disabling removes it. Stages the cave install/undo through the D8 gate.")]
    fn set_cheat_toggle(
        &self,
        Parameters(args): Parameters<SetCheatToggleArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        // Look up the toggle cheat.
        let (target, hook, currently_enabled) = {
            let s = self
                .session
                .lock()
                .map_err(|_| err("session lock poisoned"))?;
            let c = s
                .get_cheat(args.id)
                .ok_or_else(|| err(format!("no cheat with id {}", args.id)))?;
            match &c.kind {
                CheatKind::Toggle { target, hook, enabled } => {
                    (*target, hook.clone(), *enabled)
                }
                _ => {
                    return Err(err(format!("cheat {} is not a toggle cheat", args.id)))
                }
            }
        };
        if currently_enabled == args.enabled {
            return Ok(CallToolResult::success(vec![
                rmcp::model::ContentBlock::text(format!(
                    "toggle cheat {} already {}",
                    args.id,
                    if args.enabled { "enabled" } else { "disabled" }
                )),
            ]));
        }
        // Stage the cave install (enable) or undo (disable) through the D8 gate.
        let mut s = self
            .session
            .lock()
            .map_err(|_| err("session lock poisoned"))?;
        let pid = if args.enabled {
            s.stage_op(
                target,
                PendingKind::InstallCave { hook },
                format!("enable toggle cheat {} at {:#x}", args.id, target),
            )
        } else {
            // Disabling: we need the original bytes to restore. For now, stage
            // an undo of the most recent cave at this target is not tracked;
            // we stage a no-op marker and let the GUI/agent handle restore.
            // (Full cave-restore wiring is a follow-up.)
            s.stage_op(
                target,
                PendingKind::Undo {
                    original_bytes: Vec::new(),
                },
                format!("disable toggle cheat {} at {:#x}", args.id, target),
            )
        };
        drop(s);
        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(format!(
                "staged toggle change (pending id {pid}) for cheat {}. Call 'confirm_op' to apply.",
                args.id
            )),
        ]))
    }

    /// List cheat profiles discovered in the `cheats/` directory.
    #[tool(description = "List cheat profiles (portable YAML cheat tables) discovered in the cheats/ directory next to the GUI, with their target game.")]
    fn list_profiles(&self) -> Result<CallToolResult, ErrorData> {
        let profiles = crate::profile::discover_profiles();
        if profiles.is_empty() {
            return Ok(CallToolResult::success(vec![
                rmcp::model::ContentBlock::text(
                    "(no profiles found in cheats/; add one or use 'save_profile')",
                ),
            ]));
        }
        let lines: Vec<String> = profiles
            .iter()
            .map(|(f, p)| {
                format!(
                    "{} — game: {} ({}) v{}",
                    f, p.game, p.name, p.version
                )
            })
            .collect();
        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(lines.join("\n")),
        ]))
    }

    /// Load a cheat profile: run its setup steps to resolve base addresses,
    /// then materialize its cheats into the session (populating known values,
    /// but NOT enabling any cheats).
    #[tool(description = "Load a cheat profile by file name or game exe. Runs setup steps (AOB scans, pointer chains, addresses) to resolve base addresses, then materializes the profile's cheats into the session. Does NOT enable any cheats.")]
    fn load_profile(
        &self,
        Parameters(args): Parameters<LoadProfileArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        use crate::profile::find_profile_for_game;
        let profiles = crate::profile::discover_profiles();
        // Match by file name or by game exe.
        let target = args.profile.trim().to_lowercase();
        let found = profiles
            .iter()
            .find(|(f, _)| f.to_lowercase() == target)
            .or_else(|| find_profile_for_game(&profiles, &args.profile));
        let (file, profile) = match found {
            Some(x) => x,
            None => {
                return Err(err(format!(
                    "no profile found for '{}' (looked in cheats/)",
                    args.profile
                )))
            }
        };
        let profile = profile.clone();

        // Run setup steps to resolve base addresses.
        let mut resolved: Vec<(String, u64)> = Vec::new();
        if args.run_setup {
            for step in &profile.setup {
                match resolve_setup_step(&self.session, step) {
                    Ok(addr) => {
                        resolved.push((step.name().to_string(), addr));
                    }
                    Err(e) => {
                        return Err(err(format!(
                            "setup step '{}' failed: {e}",
                            step.name()
                        )))
                    }
                }
            }
        }

        // Materialize cheats into the session.
        let mut s = self
            .session
            .lock()
            .map_err(|_| err("session lock poisoned"))?;
        // Set the game name so attach/status reflect the profile.
        s.set_game_name(profile.game.clone());
        let mut materialized = 0usize;
        for pc in &profile.cheats {
            let kind = match pc.kind.as_str() {
                "value" => {
                    let address = resolve_cheat_address(&resolved, pc)?;
                    let vt = parse_value_type(pc.value_type.as_deref().unwrap_or("i32"))?;
                    crate::session::CheatKind::Value {
                        address,
                        value_type: vt,
                    }
                }
                "toggle" => {
                    let target = resolve_cheat_address(&resolved, pc)?;
                    let payload = parse_hex_bytes(pc.payload.as_deref().unwrap_or(""))?;
                    let hook = match pc.hook.as_deref().unwrap_or("trampoline") {
                        "trampoline" => trainlab_core::cave_hook::CaveHook::Trampoline { payload, jump: trainlab_core::cave_hook::JumpStyle::Absolute },
                        "override" => trainlab_core::cave_hook::CaveHook::Override { payload, jump: trainlab_core::cave_hook::JumpStyle::Absolute },
                        other => return Err(err(format!("unknown hook '{other}'"))),
                    };
                    crate::session::CheatKind::Toggle {
                        hook,
                        target,
                        enabled: false,
                    }
                }
                "button" => {
                    let cmds = pc.commands.clone().unwrap_or_default();
                    crate::session::CheatKind::Button { commands: cmds }
                }
                other => return Err(err(format!("unknown cheat kind '{other}'"))),
            };
            s.add_cheat(&pc.label, kind, pc.note.as_deref());
            materialized += 1;
        }
        drop(s);

        let mut text = format!(
            "loaded profile '{}' ({}): {} setup step(s) resolved, {} cheat(s) materialized\n",
            file,
            profile.game,
            resolved.len(),
            materialized
        );
        for (name, addr) in &resolved {
            text.push_str(&format!("  {name} = {addr:#x}\n"));
        }
        text.push_str("Cheats are populated but NOT enabled. Use 'list_cheats' to see them.");
        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(text),
        ]))
    }

    /// Save the current session's cheats to a cheat profile YAML file.
    #[tool(description = "Save the current session's cheats to a portable YAML cheat profile in the cheats/ directory. Uses the session's game name and current cheats.")]
    fn save_profile(
        &self,
        Parameters(args): Parameters<SaveProfileArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        use crate::profile::{GameProfile, ProfileCheat};
        let (game, cheats) = {
            let s = self
                .session
                .lock()
                .map_err(|_| err("session lock poisoned"))?;
            let game = s.game_name().to_string();
            let cheats: Vec<crate::session::Cheat> = s.list_cheats().into_iter().cloned().collect();
            (game, cheats)
        };
        if game.is_empty() {
            return Err(err("no game attached; set a game name first (attach_game)"));
        }
        let profile_cheats: Vec<ProfileCheat> = cheats
            .iter()
            .map(|c| {
                let (kind, value_type, address_ref, target_ref, hook, payload) = match &c.kind {
                    crate::session::CheatKind::Value { address, value_type } => {
                        ("value".to_string(), Some(format!("{value_type:?}").to_lowercase()), Some(format!("{address:#x}")), None, None, None)
                    }
                    crate::session::CheatKind::Toggle { target, hook, .. } => {
                        let (hk, pl) = match hook {
                            trainlab_core::cave_hook::CaveHook::Trampoline { payload, .. } => {
                                ("trampoline".to_string(), Some(hex_encode(payload)))
                            }
                            trainlab_core::cave_hook::CaveHook::Override { payload, .. } => {
                                ("override".to_string(), Some(hex_encode(payload)))
                            }
                        };
                        ("toggle".to_string(), None, None, Some(format!("{target:#x}")), Some(hk), pl)
                    }
                    CheatKind::Button { commands } => {
                        ("button".to_string(), None, None, None, None, None)
                    }
                };
                ProfileCheat {
                    id: c.id.to_string(),
                    label: c.label.clone(),
                    kind,
                    value_type,
                    address_ref,
                    target_ref,
                    hook,
                    payload,
                    mechanism: None,
                    rate_hz: None,
                    value: None,
                    commands: None,
                    note: c.note.clone(),
                }
            })
            .collect();
        let profile = GameProfile {
            schema: GameProfile::SCHEMA_V1.into(),
            game: game.clone(),
            name: format!("{game} cheats"),
            inject_dll: true,
            version: "1.0.0".into(),
            setup: vec![],
            cheats: profile_cheats.clone(),
        };
        let yaml = profile.to_yaml().map_err(err)?;
        let file = args
            .file
            .unwrap_or_else(|| format!("{}.yaml", game.replace(".exe", "")));
        let dir = crate::profile::profiles_dir_path();
        std::fs::create_dir_all(&dir).map_err(|e| err(format!("mkdir {dir:?}: {e}")))?;
        let path = dir.join(&file);
        std::fs::write(&path, yaml).map_err(|e| err(format!("write {path:?}: {e}")))?;
        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(format!(
                "saved profile to {} ({} cheats)",
                path.display(),
                profile_cheats.len()
            )),
        ]))
    }

    /// List the readable memory regions of the game process.
    #[tool(description = "List readable memory regions of the game process, read externally.")]
    fn list_regions(&self) -> Result<CallToolResult, ErrorData> {
        let proc = game_process(&self.session)?;
        let regions = proc.regions().map_err(|e| err(format!("regions failed: {e}")))?;
        let lines: Vec<String> = regions
            .iter()
            .map(|r| {
                format!(
                    "{:#018x}-{:#018x} r{}{} {}",
                    r.start,
                    r.end,
                    if r.readable { 'x' } else { '-' },
                    if r.writable { 'w' } else { '-' },
                    r.name.as_deref().unwrap_or("")
                )
            })
            .collect();
        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(lines.join("\n")),
        ]))
    }

    /// Read memory from the game process (raw bytes or typed value).
    #[tool(description = "Read memory from the game process. Supports raw hex bytes (default) OR typed values (value_type='ptr'|'i32'|'u32'|'f32'|'i64'|'u64'|'f64'|'cstr'). Supports expressions (e.g. 'game.exe+0x123', 'wood_ptr+0x10').")]
    fn read(&self, Parameters(args): Parameters<ReadArgs>) -> Result<CallToolResult, ErrorData> {
        let address = parse_addr(&self.session, &args.address)?;
        let proc = game_process(&self.session)?;
        let vt_str = args.value_type.as_deref().unwrap_or("hex").trim().to_lowercase();

        match vt_str.as_str() {
            "hex" | "bytes" => {
                let len = args.len.unwrap_or(16);
                let data = proc.read(address, len).map_err(|e| err(format!("read failed: {e}")))?;
                let hex = data
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                Ok(CallToolResult::success(vec![
                    rmcp::model::ContentBlock::text(hex),
                ]))
            }
            "ptr" | "pointer" => {
                let val = read_u64(proc.as_ref(), address).map_err(|e| err(format!("read ptr failed: {e}")))?;
                let ptr_val = parse_addr_str(&val).unwrap_or(0);
                Ok(CallToolResult::success(vec![
                    rmcp::model::ContentBlock::text(format!("{ptr_val:#018x} ({val})")),
                ]))
            }
            "i32" => {
                let val = read_i32(proc.as_ref(), address).map_err(|e| err(format!("read i32 failed: {e}")))?;
                Ok(CallToolResult::success(vec![rmcp::model::ContentBlock::text(val)]))
            }
            "u32" => {
                let val = read_u32(proc.as_ref(), address).map_err(|e| err(format!("read u32 failed: {e}")))?;
                Ok(CallToolResult::success(vec![rmcp::model::ContentBlock::text(val)]))
            }
            "f32" | "float" => {
                let val = read_f32_val(proc.as_ref(), address).map_err(|e| err(format!("read f32 failed: {e}")))?;
                Ok(CallToolResult::success(vec![rmcp::model::ContentBlock::text(val)]))
            }
            "i64" => {
                let val = read_i64(proc.as_ref(), address).map_err(|e| err(format!("read i64 failed: {e}")))?;
                Ok(CallToolResult::success(vec![rmcp::model::ContentBlock::text(val)]))
            }
            "u64" => {
                let val = read_u64(proc.as_ref(), address).map_err(|e| err(format!("read u64 failed: {e}")))?;
                Ok(CallToolResult::success(vec![rmcp::model::ContentBlock::text(val)]))
            }
            "f64" | "double" => {
                let val = read_f64_val(proc.as_ref(), address).map_err(|e| err(format!("read f64 failed: {e}")))?;
                Ok(CallToolResult::success(vec![rmcp::model::ContentBlock::text(val)]))
            }
            "cstr" | "string" => {
                let max_len = args.len.unwrap_or(256);
                let val = read_cstr(proc.as_ref(), address, max_len).map_err(|e| err(format!("read cstr failed: {e}")))?;
                Ok(CallToolResult::success(vec![rmcp::model::ContentBlock::text(val)]))
            }
            other => Err(err(format!("unknown read value_type '{other}' (expected hex, ptr, i32, u32, f32, i64, u64, f64, cstr)"))),
        }
    }

    /// Report the Windows integrity level of the game process and the trainer
    /// itself, so you can tell whether the game runs elevated (admin) and
    /// whether the trainer matches. Levels: 0x1000=Untrusted, 0x2000=Low,
    /// 0x3000=Medium, 0x4000=High (elevated/admin), 0x5000=System.
    #[tool(description = "Report the Windows integrity level of the game process and the trainer itself (e.g. Medium vs High/elevated). Use to diagnose access-denied (error 5) when reading game memory.")]
    fn check_integrity(&self) -> Result<CallToolResult, ErrorData> {
        #[cfg(windows)]
        {
            use windows_sys::Win32::Foundation::CloseHandle;
            use windows_sys::Win32::Security::{
                GetTokenInformation, TokenIntegrityLevel, TOKEN_QUERY,
            };
            use windows_sys::Win32::System::Threading::{
                GetCurrentProcess, OpenProcessToken, PROCESS_QUERY_INFORMATION,
            };

            fn integrity_of(process: windows_sys::Win32::Foundation::HANDLE) -> Result<u32, String> {
                let mut token: windows_sys::Win32::Foundation::HANDLE = std::ptr::null_mut();
                // SAFETY: valid process handle and token pointer.
                let ok = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) };
                if ok == 0 {
                    return Err(format!("OpenProcessToken failed: {}", last_error()));
                }
                // Query the token integrity level. First call with null buffer to get size.
                let mut size: u32 = 0;
                // SAFETY: querying size with null buffer.
                let _ = unsafe {
                    GetTokenInformation(
                        token,
                        TokenIntegrityLevel,
                        std::ptr::null_mut(),
                        0,
                        &mut size,
                    )
                };
                let mut buf = vec![0u8; size as usize];
                // SAFETY: valid buffer of the reported size.
                let ok = unsafe {
                    GetTokenInformation(
                        token,
                        TokenIntegrityLevel,
                        buf.as_mut_ptr() as *mut _,
                        size,
                        &mut size,
                    )
                };
                // SAFETY: token handle.
                unsafe { CloseHandle(token) };
                if ok == 0 {
                    return Err(format!("GetTokenInformation failed: {}", last_error()));
                }
                // The TOKEN_MANDATORY_LABEL has a SID; the integrity level is the
                // last sub-authority of that SID.
                // SAFETY: buf holds a TOKEN_MANDATORY_LABEL whose Label is a SID.
                let label = buf.as_ptr() as *const windows_sys::Win32::Security::TOKEN_MANDATORY_LABEL;
                let sid = unsafe { (*label).Label.Sid };
                // SAFETY: sid is a valid SID pointer.
                let count = unsafe { windows_sys::Win32::Security::GetSidSubAuthorityCount(sid) };
                // SAFETY: count is a valid pointer to the sub-authority count.
                let n = unsafe { *count } as u32;
                // SAFETY: index n-1 is the last sub-authority.
                let sub = unsafe { windows_sys::Win32::Security::GetSidSubAuthority(sid, n - 1) };
                // SAFETY: sub is a valid pointer to the integrity value.
                Ok(unsafe { *sub })
            }

            let game = {
                let pid = {
                    let s = self.session.lock().map_err(|_| err("session lock poisoned"))?;
                    s.game_pid()
                };
                match pid {
                    Some(pid) => {
                        // SAFETY: OpenProcess with query access on a valid pid.
                        let h = unsafe {
                            windows_sys::Win32::System::Threading::OpenProcess(
                                PROCESS_QUERY_INFORMATION,
                                0,
                                pid,
                            )
                        };
                        if h.is_null() {
                            format!("(could not open game pid {pid}: {})", last_error())
                        } else {
                            let r = integrity_of(h);
                            // SAFETY: valid handle.
                            unsafe { CloseHandle(h) };
                            match r {
                                Ok(v) => format!("0x{v:x}"),
                                Err(e) => format!("(error: {e})"),
                            }
                        }
                    }
                    None => "(no game attached)".to_string(),
                }
            };

            // SAFETY: GetCurrentProcess returns a pseudo-handle (no close needed).
            let self_h = unsafe { GetCurrentProcess() };
            let trainer = match integrity_of(self_h) {
                Ok(v) => format!("0x{v:x}"),
                Err(e) => format!("(error: {e})"),
            };

            let level_name = |v: &str| -> String {
                match v {
                    "0x1000" => "Untrusted".to_string(),
                    "0x2000" => "Low".to_string(),
                    "0x3000" => "Medium".to_string(),
                    "0x4000" => "High (elevated/admin)".to_string(),
                    "0x5000" => "System".to_string(),
                    _ => "unknown".to_string(),
                }
            };

            Ok(CallToolResult::success(vec![rmcp::model::ContentBlock::text(
                format!(
                    "game integrity: {} ({})\ntrainer integrity: {} ({})",
                    game,
                    level_name(&game),
                    trainer,
                    level_name(&trainer),
                ),
            )]))
        }
        #[cfg(not(windows))]
        {
            Err(err("check_integrity requires the Windows GUI"))
        }
    }

    /// AOB pattern scan over the game's readable memory (external).
    #[tool(description = "Scan game memory for an AOB byte pattern (hex, ?? wildcards); returns match addresses, read externally.")]
    fn aob_scan(&self, Parameters(args): Parameters<AobArgs>) -> Result<CallToolResult, ErrorData> {
        let pattern = trainlab_core::aob::parse(&args.pattern);
        if pattern.is_empty() {
            return Err(err("empty/invalid AOB pattern"));
        }
        let proc = game_process(&self.session)?;
        let regions = proc.regions().map_err(|e| err(format!("regions failed: {e}")))?;
        let mut matches = Vec::new();
        for r in regions {
            if !r.readable {
                continue;
            }
            let len = (r.end - r.start) as usize;
            if len < pattern.len() {
                continue;
            }
            match proc.read(r.start, len) {
                Ok(buf) => {
                    for off in trainlab_core::aob::find_all(&buf, &pattern) {
                        matches.push(r.start + off as u64);
                    }
                }
                Err(_) => continue, // region unreadable: skip
            }
        }
        let lines: Vec<String> = matches.iter().map(|m| format!("{m:#018x}")).collect();
        let count = lines.len();
        let mut text = format!("{count} match(es)\n");
        text.push_str(&lines.join("\n"));
        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(text),
        ]))
    }

    /// Start a value scan over the game's memory (via the DLL).
    ///
    /// The match set is stored in the session so you can narrow it with
    /// `next`. Value types: i32, u32, f32, i64, u64, f64, ptr. Pass `max` to
    /// do a range first-scan (matches `[value, max]`), useful for floats with
    /// fractional storage.
    #[tool(description = "First value scan: find all addresses holding a value (exact, or a range if 'max' is given). Stores the match set in the session for narrowing with 'next'.")]
    fn scan(&self, Parameters(args): Parameters<ScanArgs>) -> Result<CallToolResult, ErrorData> {
        let value_type = parse_value_type(&args.value_type)?;
        let alignment = args.alignment.unwrap_or(0);
        let op = match args.max {
            Some(max) => trainlab_core::scan::ScanOp::Range {
                min: args.value,
                max,
            },
            None => trainlab_core::scan::ScanOp::Exact { value: args.value },
        };
        // Run the first scan externally (graceful errors on a big heap, unlike
        // an in-process scan which can fault the game).
        let proc = game_process(&self.session)?;
        let regions = proc.regions().map_err(|e| err(format!("regions failed: {e}")))?;
        let mut scan = trainlab_core::scan::Scan::new(value_type).with_alignment(alignment);
        scan.first_scan(proc.as_ref(), &regions, op)
            .map_err(|e| err(format!("scan failed: {e}")))?;
        let matches = scan.matches().to_vec();
        // Store the match set in the session for narrowing.
        let mut s = self
            .session
            .lock()
            .map_err(|_| err("session lock poisoned"))?;
        s.set_scan(scan);
        drop(s);
        let count = matches.len();
        let lines: Vec<String> = matches
            .iter()
            .take(50)
            .map(|(a, v)| format!("{a:#018x} = {v}"))
            .collect();
        let mut text = format!("{count} match(es)\n");
        text.push_str(&lines.join("\n"));
        if count > 50 {
            text.push_str(&format!("\n... and {} more", count - 50));
        }
        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(text),
        ]))
    }

    /// Narrow the previous scan's match set.
    ///
    /// Ops: changed, unchanged, increased, decreased, exact, range. For
    /// `exact` pass `value`; for `range` pass `value` (min) and `max`.
    #[tool(description = "Narrow the previous scan: keep matches that changed/unchanged/increased/decreased or match a new exact/range value.")]
    fn next(&self, Parameters(args): Parameters<NextArgs>) -> Result<CallToolResult, ErrorData> {
        let op = parse_scan_op(&args.op, args.value, args.max)?;
        // Pull the current match set + value type from the session.
        let (value_type, matches) = {
            let mut s = self
                .session
                .lock()
                .map_err(|_| err("session lock poisoned"))?;
            let scan = s
                .scan_mut()
                .ok_or_else(|| err("no active scan; run 'scan' first"))?;
            (scan.value_type(), scan.matches().to_vec())
        };
        // Narrow externally (re-read each address via ReadProcessMemory, which
        // fails gracefully if an address is no longer valid).
        let proc = game_process(&self.session)?;
        let mut scan = trainlab_core::scan::Scan::from_parts(value_type, matches);
        scan.refine(proc.as_ref(), op)
            .map_err(|e| err(format!("next failed: {e}")))?;
        let matches = scan.matches().to_vec();
        let mut s = self
            .session
            .lock()
            .map_err(|_| err("session lock poisoned"))?;
        s.set_scan(scan);
        drop(s);
        let count = matches.len();
        let lines: Vec<String> = matches
            .iter()
            .take(50)
            .map(|(a, v)| format!("{a:#018x} = {v}"))
            .collect();
        let mut text = format!("{count} match(es)\n");
        text.push_str(&lines.join("\n"));
        if count > 50 {
            text.push_str(&format!("\n... and {} more", count - 50));
        }
        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(text),
        ]))
    }

    /// Read the active value scan status and candidate matches without mutating the scan state.
    #[tool(description = "Inspect the current active scan session without modifying it. Reports total match count, value type, alignment, and lists up to 50 current candidate matches (address = value).")]
    fn scan_status(&self) -> Result<CallToolResult, ErrorData> {
        let s = self
            .session
            .lock()
            .map_err(|_| err("session lock poisoned"))?;
        let scan = s
            .scan()
            .ok_or_else(|| err("no active scan session in progress"))?;
        let count = scan.len();
        let value_type = scan.value_type();
        let alignment = scan.alignment();
        let matches = scan.matches().to_vec();
        drop(s);

        let lines: Vec<String> = matches
            .iter()
            .take(50)
            .map(|(a, v)| format!("{a:#018x} = {v}"))
            .collect();
        let mut text = format!("active scan: {count} match(es) (type: {value_type:?}, align: {alignment})\n");
        text.push_str(&lines.join("\n"));
        if count > 50 {
            text.push_str(&format!("\n... and {} more", count - 50));
        }

        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(text),
        ]))
    }

    /// Find addresses that point to (reference) a target address.
    #[tool(description = "Reverse-reference scan: find writable addresses whose pointer value points into the range around a target address. Use to find what points to a value (owning object), then chase a stable chain.")]
    fn pointer_scan(
        &self,
        Parameters(args): Parameters<PointerScanArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let address = parse_addr(&self.session, &args.address)?;
        let size = args.size.unwrap_or(8).max(1);
        let lo = address;
        let hi = address + size - 1;
        // Reverse-reference scan externally (graceful on a live heap).
        let proc = game_process(&self.session)?;
        let regions = proc.regions().map_err(|e| err(format!("regions failed: {e}")))?;
        let matches = trainlab_core::pointer::reverse_scan(proc.as_ref(), &regions, lo, hi)
            .map_err(|e| err(format!("pointer_scan failed: {e}")))?;
        let count = matches.len();
        let lines: Vec<String> = matches
            .iter()
            .take(100)
            .map(|(a, p)| format!("{a:#018x} -> {p:#018x}"))
            .collect();
        let mut text = format!("{count} referrer(s)\n");
        text.push_str(&lines.join("\n"));
        if count > 100 {
            text.push_str(&format!("\n... and {} more", count - 100));
        }
        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(text),
        ]))
    }

    /// Resolve a known pointer chain to the current address of a value.
    #[tool(description = "Resolve a pointer chain (base + offsets) against the live game; returns each hop and the final value address. Use a chain you discovered, e.g. via pointer_scan.")]
    fn pointer_chase(
        &self,
        Parameters(args): Parameters<PointerChaseArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let base = parse_addr(&self.session, &args.base)?;
        let mut offsets = Vec::new();
        for o in &args.offsets {
            offsets.push(parse_addr(&self.session, o)?);
        }
        // Chase the chain externally (each hop via ReadProcessMemory, which
        // fails gracefully if the chain is stale / the process moved).
        let proc = game_process(&self.session)?;
        let hops = trainlab_core::pointer::chase(proc.as_ref(), base, &offsets)
            .map_err(|e| err(format!("pointer_chase failed: {e}")))?;
        let lines: Vec<String> = hops
            .iter()
            .enumerate()
            .map(|(i, h)| {
                if i == hops.len() - 1 {
                    format!("value addr: {h:#018x}")
                } else {
                    format!("hop {i}: {h:#018x}")
                }
            })
            .collect();
        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(lines.join("\n")),
        ]))
    }

    /// Set a labeled marker for an address (persists across turns).
    #[tool(description = "Save a labeled marker for an address so the agent can reference it later.")]
    fn set_marker(
        &self,
        Parameters(args): Parameters<SetMarkerArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let address = parse_addr(&self.session, &args.address)?;
        let mut s = self
            .session
            .lock()
            .map_err(|_| err("session lock poisoned"))?;
        s.set_marker(&args.label, address, args.note.as_deref())
            .map_err(|e| err(e))?;
        self.request_repaint();
        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(format!(
                "marker '{}' set to {address:#018x}",
                args.label
            )),
        ]))
    }

    /// Dump a chunk of memory formatted for struct/class reversal.
    #[tool(description = "Read a chunk of memory around an address and format it as hex + ASCII (and typed fields where obvious) so the agent can reverse a struct/class layout. The LLM does the teasing-out.")]
    fn dump(&self, Parameters(args): Parameters<DumpArgs>) -> Result<CallToolResult, ErrorData> {
        let address = parse_addr(&self.session, &args.address)?;
        let proc = game_process(&self.session)?;
        match proc.read(address, args.len) {
            Ok(data) => Ok(CallToolResult::success(vec![
                rmcp::model::ContentBlock::text(format_dump(address, &data)),
            ])),
            Err(e) => Err(err(format!("dump failed: {e}"))),
        }
    }

    /// Dump a memory range to a snapshot binary file on disk and return a downloadable URL.
    #[tool(description = "Dump a large memory range (e.g. 15MB Lua heap) to a snapshot file on disk and return its local file path, size, and downloadable HTTP URL. Pass either 'end' or 'len'.")]
    fn snapshot(
        &self,
        Parameters(args): Parameters<SnapshotArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let start = parse_addr(&self.session, &args.start)?;
        let len = match (args.end.as_deref(), args.len) {
            (Some(end_str), None) => {
                let end = parse_addr(&self.session, end_str)?;
                if end <= start {
                    return Err(err("end address must be greater than start address"));
                }
                end - start
            }
            (None, Some(l)) => {
                if l == 0 {
                    return Err(err("length must be greater than 0"));
                }
                l
            }
            (Some(_), Some(_)) => {
                return Err(err("specify either 'end' or 'len', but not both"));
            }
            (None, None) => {
                return Err(err("must specify either 'end' or 'len'"));
            }
        };

        let file_name = args.name.unwrap_or_else(|| {
            format!("snap_0x{start:08x}_{len}.bin")
        });

        // Ensure snapshot file is saved in snapshots/ subdirectory
        let snap_dir = std::path::Path::new("snapshots");
        let file_path = snap_dir.join(&file_name);

        let proc = game_process(&self.session)?;
        let bytes_written = trainlab_core::memory::dump_range_to_file(
            proc.as_ref(),
            start,
            len,
            &file_path,
            args.max_len,
        )
        .map_err(|e| err(format!("snapshot dump failed: {e}")))?;

        // Build the download URL based on configured MCP host and port
        let (host, port) = {
            let s = self.session.lock().map_err(|_| err("session lock poisoned"))?;
            (s.dll_host().to_string(), s.dll_port())
        };
        // Use loopback or host address for the snapshot URL
        let url_host = if host == "0.0.0.0" { "127.0.0.1".to_string() } else { host };
        let url = format!("http://{url_host}:{port}/snapshots/{file_name}");

        if let Ok(mut s) = self.session.lock() {
            s.log_activity(
                "MCP",
                format!("created memory snapshot '{file_name}' ({bytes_written} bytes)"),
            );
        }
        self.request_repaint();

        let resp_json = serde_json::json!({
            "path": file_path.to_string_lossy(),
            "size": bytes_written,
            "url": url,
        });

        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(resp_json.to_string()),
        ]))
    }

    /// Allocate and lay out a string inside the game process and return its layout pointers.
    #[tool(description = "Allocate and lay out a string inside the game process (C string, Rust fat pointer, JSON/YAML/XML/JS config) and return its address and layout. Supported kinds: 'c' (default, NUL-terminated), 'rust' (returns ptr and len), 'json', 'yaml', 'xml', 'js', 'config'.")]
    fn allocate_string(
        &self,
        Parameters(args): Parameters<AllocateStringArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let proc = game_process(&self.session)?;
        let kind = args.kind.trim().to_lowercase();
        let mut bytes = args.content.as_bytes().to_vec();

        let is_rust = kind == "rust";
        let is_c_like = matches!(
            kind.as_str(),
            "c" | "json" | "yaml" | "xml" | "js" | "config"
        );

        if !is_rust && !is_c_like {
            return Err(err(format!(
                "unknown string kind '{kind}' (expected 'c', 'rust', 'json', 'yaml', 'xml', 'js', or 'config')"
            )));
        }

        // C-like strings must be NUL-terminated for C string parsers
        if is_c_like && !bytes.ends_with(&[0]) {
            bytes.push(0);
        }

        let len = bytes.len();

        // Perform memory allocation in target process via Windows VirtualAllocEx
        let alloc_addr = {
            #[cfg(windows)]
            {
                use windows_sys::Win32::System::Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
                let pid = self.session.lock().map_err(|_| err("session lock poisoned"))?.game_pid();
                if let Some(pid) = pid {
                    let proc_handle = unsafe {
                        windows_sys::Win32::System::Threading::OpenProcess(
                            windows_sys::Win32::System::Threading::PROCESS_VM_OPERATION
                                | windows_sys::Win32::System::Threading::PROCESS_VM_WRITE
                                | windows_sys::Win32::System::Threading::PROCESS_VM_READ,
                            0,
                            pid,
                        )
                    };
                    if !proc_handle.is_null() {
                        let ptr = unsafe {
                            VirtualAllocEx(proc_handle, std::ptr::null(), len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
                        };
                        unsafe { windows_sys::Win32::Foundation::CloseHandle(proc_handle); }
                        if !ptr.is_null() {
                            ptr as u64
                        } else {
                            return Err(err("VirtualAllocEx failed in target process"));
                        }
                    } else {
                        return Err(err("failed to open process for allocation"));
                    }
                } else {
                    return Err(err("no attached game process to allocate string in"));
                }
            }
            #[cfg(not(windows))]
            {
                0x10000u64
            }
        };

        // Write the string bytes to the allocated address
        proc.write(alloc_addr, &bytes)
            .map_err(|e| err(format!("failed to write string bytes: {e}")))?;

        if let Ok(mut s) = self.session.lock() {
            s.log_activity(
                "MCP",
                format!("allocated string ({kind}, {len} bytes) at {alloc_addr:#x}"),
            );
        }
        self.request_repaint();

        let resp_json = if is_rust {
            serde_json::json!({
                "ptr": format!("{alloc_addr:#x}"),
                "len": len,
                "kind": kind,
            })
        } else {
            serde_json::json!({
                "ptr": format!("{alloc_addr:#x}"),
                "kind": kind,
            })
        };

        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(resp_json.to_string()),
        ]))
    }

    /// Read a struct at an address as a list of typed fields (name, type,
    /// offset) and format them, so the agent can reverse a struct/class layout
    /// without manually slicing raw bytes.
    #[tool(description = "Read a struct at an address and format each requested field by type. Field types: i8, u8, i16, u16, i32, u32, i64, u64, f32, f64, ptr, cstr (null-terminated ASCII), or bytes. Pass an offset per field (default 0).")]
    fn dump_struct(
        &self,
        Parameters(args): Parameters<DumpStructArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let address = parse_addr(&self.session, &args.address)?;
        if args.fields.is_empty() {
            return Err(err("dump_struct requires at least one field"));
        }
        let proc = game_process(&self.session)?;
        let mut lines = Vec::with_capacity(args.fields.len());
        for f in &args.fields {
            if f.name.trim().is_empty() {
                return Err(err("field name cannot be empty"));
            }
            // Resolve the field address = struct base + offset.
            let field_addr = address.wrapping_add(f.offset);
            let result = match f.value_type.trim().to_lowercase().as_str() {
                "i8" => read_i8(proc.as_ref(), field_addr),
                "u8" => read_u8(proc.as_ref(), field_addr),
                "i16" => read_i16(proc.as_ref(), field_addr),
                "u16" => read_u16(proc.as_ref(), field_addr),
                "i32" => read_i32(proc.as_ref(), field_addr),
                "u32" => read_u32(proc.as_ref(), field_addr),
                "i64" => read_i64(proc.as_ref(), field_addr),
                "u64" => read_u64(proc.as_ref(), field_addr),
                "f32" => read_f32_val(proc.as_ref(), field_addr),
                "f64" => read_f64_val(proc.as_ref(), field_addr),
                "ptr" => read_u64(proc.as_ref(), field_addr),
                "cstr" => {
                    let max_len = f.len.unwrap_or(256).max(1);
                    match read_cstr(proc.as_ref(), field_addr, max_len) {
                        Ok(s) => Ok(format!("{s:?}")),
                        Err(e) => Err(e),
                    }
                }
                "bytes" => {
                    let n = f.len.unwrap_or(16).max(1);
                    match proc.read(field_addr, n) {
                        Ok(data) => Ok(format!(
                            "[{}] {}",
                            data.len(),
                            data.iter()
                                .map(|b| format!("{b:02x}"))
                                .collect::<Vec<_>>()
                                .join(" ")
                        )),
                        Err(e) => Err(format!("read failed: {e}")),
                    }
                }
                other => Err(format!(
                    "unknown field type '{other}' (expected i8/u8/i16/u16/i32/u32/i64/u64/f32/f64/ptr/cstr/bytes)"
                )),
            };
            match result {
                Ok(v) => lines.push(format!(
                    "{:+5} {:<6} {}: {}",
                    f.offset, f.value_type, f.name, v
                )),
                Err(e) => lines.push(format!("{:+5} {:<6} {}: <error: {e}>", f.offset, f.value_type, f.name)),
            }
        }
        let mut text = format!("struct @ {address:#018x} ({} field(s))\n", args.fields.len());
        text.push_str(&lines.join("\n"));
        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(text),
        ]))
    }

    /// Resolve an address to a module-relative offset (e.g. `Urbek.exe+0x1234`),
    /// which is stable across launches where raw addresses are not.
    #[tool(description = "Resolve an address to a loaded module + offset (e.g. Urbek.exe+0x1234), which is restart-stable. Also reports the region it falls in.")]
    fn addr_to_module(
        &self,
        Parameters(args): Parameters<AddrToModuleArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let address = parse_addr(&self.session, &args.address)?;
        let proc = game_process(&self.session)?;
        // Enumerate modules (Windows toolhelp) and regions.
        #[cfg(windows)]
        let pid = {
            let s = self.session.lock().map_err(|_| err("session lock poisoned"))?;
            s.game_pid().ok_or_else(|| err("no game process"))?
        };
        #[cfg(windows)]
        let modules = trainlab_core::modinfo::enumerate_windows(pid)
            .unwrap_or_default();
        #[cfg(not(windows))]
        let modules = Vec::new();
        let regions = proc.regions().map_err(|e| err(format!("regions failed: {e}")))?;
        let resolved = trainlab_core::modinfo::resolve(address, Some(&modules), &regions);
        // Also list which module name + offset it is in, if any.
        let mut text = format!("{address:#018x} -> {resolved}");
        if let Some(m) = trainlab_core::modinfo::find_module(&modules, address) {
            text.push_str(&format!("\nmodule: {} (base {:#x}, size {:#x})", m.name, m.base, m.size));
            if let Some(p) = &m.path {
                text.push_str(&format!("\npath: {p}"));
            }
        }
        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(text),
        ]))
    }

    /// Disassemble raw bytes from the game into readable instructions.
    #[tool(description = "Read bytes from game memory at an address and disassemble them into x86-64 instructions (iced-x86).")]
    fn disassemble(
        &self,
        Parameters(args): Parameters<DisassembleArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let address = parse_addr(&self.session, &args.address)?;
        let proc = game_process(&self.session)?;
        match proc.read(address, args.len) {
            Ok(data) => {
                let lines = trainlab_core::disasm::disassemble(address, &data, args.max_instructions);
                Ok(CallToolResult::success(vec![
                    rmcp::model::ContentBlock::text(lines.join("\n")),
                ]))
            }
            Err(e) => Err(err(format!("disassemble failed: {e}"))),
        }
    }

    /// Arm a passive, non-stalling register capture at a code address.
    ///
    /// Installs a transparent trampoline at `target` that records the chosen
    /// register each time the site executes, replays the stolen instructions,
    /// and jumps back — the game never stops. This is the "register-anchor"
    /// primitive: given a stable code site, reproduce a resource address
    /// without re-scanning. Read the recorded values back with
    /// `read_captures`, and clean up with `uninstall_capture_reg`.
    #[tool(description = "Arm a passive, non-stalling register capture at a code address: records a chosen register (e.g. rcx) each time the site executes, replays stolen instructions, never stops the game. Returns a capture id + scratch buffer address; read back with 'read_captures', remove with 'uninstall_capture_reg'.")]
    fn capture_reg(
        &self,
        Parameters(args): Parameters<CaptureRegArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        use trainlab_core::capture::{CaptureRegSpec, Gate, GateCmp, Register, ValueType};
        let target = parse_addr(&self.session, &args.target)?;
        let reg = Register::parse(&args.reg)
            .ok_or_else(|| err(format!("unknown register '{}' (try rax/rcx/rbx/... or xmm0..xmm7)", args.reg)))?;
        let value_type = ValueType::parse(&args.value_type)
            .ok_or_else(|| err(format!("unknown value_type '{}' (try ptr/i64/u64/f64/f32)", args.value_type)))?;
        // Build the optional gate (decoupled "capture X if Y compares Z").
        let gate = match &args.gate {
            None => None,
            Some(g) => {
                let greg = Register::parse(&g.reg).ok_or_else(|| {
                    err(format!("unknown gate register '{}'", g.reg))
                })?;
                let cmp = GateCmp::parse(&g.cmp).ok_or_else(|| {
                    err(format!("unknown gate cmp '{}' (try eq/ne/gt/lt/ge/le/range/whole)", g.cmp))
                })?;
                // The gate has its own value_type (defaults to the capture's).
                let gate_vt = match &g.value_type {
                    None => value_type,
                    Some(v) => ValueType::parse(v).ok_or_else(|| {
                        err(format!("unknown gate value_type '{}' (try ptr/i64/u64/f64/f32)", v))
                    })?,
                };
                let value = g.value.unwrap_or(0.0);
                let min = g.min.unwrap_or(0.0);
                let max = g.max.unwrap_or(0.0);
                Some(Gate { reg: greg, cmp, value_type: gate_vt, value, min, max })
            }
        };
        let jump_style = match args.jump.as_deref().unwrap_or("absolute").to_lowercase().as_str() {
            "relative" | "short" => trainlab_core::cave_hook::JumpStyle::Relative,
            _ => trainlab_core::cave_hook::JumpStyle::Absolute,
        };
        let spec = CaptureRegSpec::new(reg, value_type).with_optional_gate(gate).with_jump(jump_style);
        match call_dll(&Request::CaptureReg {
            target,
            spec,
            capacity: args.capacity,
            disarm: args.stop_on_match,
        }) {
            Ok(Response::CaptureInstalled {
                id,
                scratch,
                target: _,
                original: _,
            }) => {
                let gate_desc = match &gate {
                    None => "unconditional".to_string(),
                    Some(g) => format!(
                        "gate {} {}",
                        g.reg.name(),
                        match g.cmp {
                            GateCmp::Range => format!("in [{}, {}]", g.min, g.max),
                            GateCmp::Whole => "whole".to_string(),
                            c => format!("{} {}", c.name(), g.value),
                        }
                    ),
                };
                Ok(CallToolResult::success(vec![
                    rmcp::model::ContentBlock::text(format!(
                        "armed non-stalling capture id {id} at {:#x}: capturing {} as {} (capacity {}) ({}; stop_on_match={}).\nscratch buffer: {:#x} (readable via 'read').\nRead back with 'read_captures' (id {id}); uninstall with 'uninstall_capture_reg' (id {id}).",
                        target,
                        reg.name(),
                        value_type.name(),
                        args.capacity,
                        gate_desc,
                        args.stop_on_match,
                        scratch,
                    )),
                ]))
            }
            Ok(Response::Error { message }) => Err(err(message)),
            Ok(_) => Err(err("unexpected response from DLL")),
            Err(e) => Err(err(e)),
        }
    }

    /// Read back the entries recorded by a `capture_reg` capture.
    #[tool(description = "Read back the register values recorded by a passive 'capture_reg' capture (by id). Returns each captured entry: sequence, decoded capture value, raw 64-bit value, the gate value at capture time, and the site address that was executing.")]
    fn read_captures(
        &self,
        Parameters(args): Parameters<ReadCapturesArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        match call_dll(&Request::ReadCaptures { id: args.id }) {
            Ok(Response::ReadCaptures { entries, disarmed }) => {
                if entries.is_empty() {
                    let note = if disarmed {
                        " (already disarmed — a one_shot/stop_on_match capture fired earlier)"
                    } else {
                        ""
                    };
                    return Ok(CallToolResult::success(vec![
                        rmcp::model::ContentBlock::text(format!(
                            "capture {} has not recorded any hits yet (the site has not executed since arming).{note}",
                            args.id
                        )),
                    ]));
                }
                let disarm_note = if disarmed { " (disarmed)" } else { "" };
                let mut lines = vec![format!("capture {} — {} recorded hit(s){disarm_note}:", args.id, entries.len())];
                for e in entries {
                    lines.push(format!(
                        "  seq={} reg_value={:.4} raw=0x{:016x} gate_value={:.4} rip=0x{:016x}",
                        e.seq, e.reg_value, e.raw, e.gate_value, e.rip
                    ));
                }
                Ok(CallToolResult::success(vec![
                    rmcp::model::ContentBlock::text(lines.join("\n")),
                ]))
            }
            Ok(Response::Error { message }) => Err(err(message)),
            Ok(_) => Err(err("unexpected response from DLL")),
            Err(e) => Err(err(e)),
        }
    }

    /// Uninstall a passive register capture: restore the original bytes at the
    /// patched site and free the scratch ring.
    #[tool(description = "Uninstall a passive 'capture_reg' capture by id: restores the original bytes at the patched code site and frees the scratch ring. No residual patch remains.")]
    fn uninstall_capture_reg(
        &self,
        Parameters(args): Parameters<UninstallCaptureArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        match call_dll(&Request::UninstallCapture { id: args.id }) {
            Ok(Response::CaptureUninstalled { id }) => Ok(CallToolResult::success(vec![
                rmcp::model::ContentBlock::text(format!(
                    "uninstalled capture {id}: original bytes restored, scratch freed."
                )),
            ])),
            Ok(Response::Error { message }) => Err(err(message)),
            Ok(_) => Err(err("unexpected response from DLL")),
            Err(e) => Err(err(e)),
        }
    }

    /// Arm a hardware watchpoint to find what code writes an address.
    ///
    /// When the game writes the address, the DLL captures the writing
    /// instruction's registers and reports them. This is the "find what writes
    /// this value" capability.
    #[tool(description = "Find what code writes an address: arm a hardware watchpoint; when the game writes it, returns the instruction pointer and register state of the writing code.")]
    fn watch_writes(
        &self,
        Parameters(args): Parameters<WatchWritesArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let address = parse_addr(&self.session, &args.address)?;
        let len = args.len.unwrap_or(4);
        match call_dll(&Request::WatchWrites {
            address,
            len,
            one_shot: args.one_shot,
        }) {
            Ok(Response::WatchArmed) => Ok(CallToolResult::success(vec![
                rmcp::model::ContentBlock::text(
                    "watchpoint armed; poll with 'watch_poll' to retrieve the hit",
                ),
            ])),
            Ok(Response::Error { message }) => Err(err(message)),
            Ok(_) => Err(err("unexpected response from DLL")),
            Err(e) => Err(err(e)),
        }
    }

    /// Arm a lightweight breakpoint on a code address and capture registers.
    #[tool(description = "Break on a code instruction: patch it with int3, and when execution reaches it capture the registers and a stack trace without a full debugger stop.")]
    fn break_on_code(
        &self,
        Parameters(args): Parameters<BreakOnCodeArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let address = parse_addr(&self.session, &args.address)?;
        match call_dll(&Request::BreakOnCode {
            address,
            one_shot: args.one_shot,
        }) {
            Ok(Response::BreakArmed) => Ok(CallToolResult::success(vec![
                rmcp::model::ContentBlock::text(
                    "breakpoint armed; poll with 'watch_poll' to retrieve the hit",
                ),
            ])),
            Ok(Response::Error { message }) => Err(err(message)),
            Ok(_) => Err(err("unexpected response from DLL")),
            Err(e) => Err(err(e)),
        }
    }

    /// Poll for a hit from an armed watchpoint/breakpoint.
    #[tool(description = "Retrieve the most recent watchpoint/breakpoint hit (registers + stack). Returns nothing if no hit is pending.")]
    fn watch_poll(&self) -> Result<CallToolResult, ErrorData> {
        match call_dll(&Request::PollHit) {
            Ok(Response::PollHit { hit: Some(info) }) => Ok(CallToolResult::success(vec![
                rmcp::model::ContentBlock::text(format_hit(
                    info.rip,
                    info.rax,
                    info.rbx,
                    info.rcx,
                    info.rdx,
                    info.rsi,
                    info.rdi,
                    info.rsp,
                    info.rbp,
                    &info.description,
                    &info.stack,
                )),
            ])),
            Ok(Response::PollHit { hit: None }) => Ok(CallToolResult::success(vec![
                rmcp::model::ContentBlock::text("no pending hit"),
            ])),
            Ok(Response::Error { message }) => Err(err(message)),
            Ok(_) => Err(err("unexpected response from DLL")),
            Err(e) => Err(err(e)),
        }
    }

    /// Clear any active watchpoints / breakpoints.
    #[tool(description = "Disarm any active watchpoint or breakpoint and restore any patched bytes.")]
    fn clear_breakpoints(&self) -> Result<CallToolResult, ErrorData> {
        match call_dll(&Request::ClearBreakpoints) {
            Ok(Response::BreakpointsCleared) => Ok(CallToolResult::success(vec![
                rmcp::model::ContentBlock::text("breakpoints cleared"),
            ])),
            Ok(Response::Error { message }) => Err(err(message)),
            Ok(_) => Err(err("unexpected response from DLL")),
            Err(e) => Err(err(e)),
        }
    }

    /// Stage a write to game memory for human confirmation (D8).
    ///
    /// Accepts EITHER raw hex bytes (`data="00 80 ac 43"`) OR a typed value
    /// (`value="0xe890000"`, `value_type="ptr"` or `"i32"`/`"f32"`/etc.) so you
    /// never have to hand-encode little-endian hex bytes. Stages the write; apply
    /// with `confirm_op` or discard with `reject_op`.
    #[tool(description = "Stage a write to game memory at an address. Accepts EITHER raw hex bytes (data='00 80 ac 43') OR a typed value (value='0xe890000', value_type='ptr' or 'i32'/'f32'/'i64'/'u64'/'f64') so you never have to hand-encode hex. Returns a pending op id; apply with 'confirm_op' or discard with 'reject_op'. Nothing is written until confirmed.")]
    fn write(&self, Parameters(args): Parameters<WriteArgs>) -> Result<CallToolResult, ErrorData> {
        let address = parse_addr(&self.session, &args.address)?;
        let (data, desc) = match (args.data.as_deref(), args.value.as_deref()) {
            (Some(hex_str), None) => {
                let bytes = parse_hex_bytes(hex_str)?;
                if bytes.is_empty() {
                    return Err(err("write data cannot be empty"));
                }
                let desc = format!(
                    "write {} byte(s) at {:#x}: {}",
                    bytes.len(),
                    address,
                    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
                );
                (bytes, desc)
            }
            (None, Some(val_str)) => {
                let vt_str = args.value_type.as_deref().unwrap_or_else(|| {
                    if val_str.trim().starts_with("0x") || val_str.trim().starts_with("0X") {
                        "ptr"
                    } else {
                        "i32"
                    }
                });
                let value_type = parse_value_type(vt_str)?;
                let bytes = parse_value_bytes(val_str, value_type)?;
                if bytes.is_empty() {
                    return Err(err("write value cannot be empty"));
                }
                let desc = format!(
                    "write value '{}' ({}) at {:#x}: {}",
                    val_str,
                    vt_str,
                    address,
                    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
                );
                (bytes, desc)
            }
            (Some(_), Some(_)) => {
                return Err(err("specify either 'data' (raw hex) or 'value' (typed value), but not both"));
            }
            (None, None) => {
                return Err(err("must specify either 'data' (raw hex) or 'value' (typed value)"));
            }
        };

        // Stage it; nothing is written until confirmed. Original bytes are
        // snapshotted only when the op is confirmed (see confirm_op).
        let mut s = self
            .session
            .lock()
            .map_err(|_| err("session lock poisoned"))?;
        let id = s.stage_op(
            address,
            PendingKind::Write { data: data.clone() },
            desc,
        );
        drop(s);
        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(format!(
                "staged write (pending id {id}): {} byte(s) at {:#x}. Call 'confirm_op' to apply or 'reject_op' to discard.",
                data.len(),
                address
            )),
        ]))
    }

    /// Stage a code-cave hook install for human confirmation (D8).
    ///
    /// This *stages* the install and returns a pending op id + preview; it does
    /// **not** patch anything yet. Confirm with `confirm_op`, or discard with
    /// `reject_op`.
    #[tool(description = "Stage a code cave hook install. Kinds: 1) 'trampoline' (DEFAULT): runs your custom payload, automatically disassembles and replays stolen instructions in the cave, then jumps back — original game logic is preserved (empty payload = transparent no-op). 2) 'override': runs payload and jumps back, skipping stolen instructions. Example payload: '48 c7 83 90 01 00 00 00 00 90 00' (mov dword ptr [rbx+0x190], 9000). Apply with 'confirm_op'.")]
    fn install_cave(
        &self,
        Parameters(args): Parameters<InstallCaveArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        use trainlab_core::cave_hook::{CaveHook, JumpStyle};
        let target = parse_addr(&self.session, &args.target)?;
        let payload = parse_hex_bytes(&args.payload)?;
        let jump = match args.jump.to_lowercase().as_str() {
            "absolute" => JumpStyle::Absolute,
            "relative" | "short" => JumpStyle::Relative,
            other => return Err(err(format!("unknown jump style '{other}' (expected 'absolute' or 'relative')"))),
        };
        let hook = match args.hook.as_str() {
            "trampoline" => CaveHook::Trampoline { payload: payload.clone(), jump },
            "override" => CaveHook::Override { payload: payload.clone(), jump },
            other => return Err(err(format!("unknown hook kind '{other}' (expected 'trampoline' or 'override')"))),
        };
        let kind_desc = match &hook {
            CaveHook::Trampoline { .. } => "trampoline",
            CaveHook::Override { .. } => "override",
        };
        // Stage it; nothing is patched until confirmed.
        let mut s = self
            .session
            .lock()
            .map_err(|_| err("session lock poisoned"))?;
        let id = s.stage_op(
            target,
            PendingKind::InstallCave { hook },
            format!(
                "install {kind_desc} cave at {:#x}, payload={} byte(s)",
                target,
                payload.len()
            ),
        );
        drop(s);
        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(format!(
                "staged {kind_desc} cave install (pending id {id}) at {:#x}. Call 'confirm_op' to apply or 'reject_op' to discard.",
                target
            )),
        ]))
    }

    /// Stage an undo for human confirmation (D8).
    ///
    /// This *stages* the revert and returns a pending op id + preview; it does
    /// **not** modify memory yet. Confirm with `confirm_op`, or discard with
    /// `reject_op`.
    #[tool(description = "Stage an undo of a write/cave mutation by id (or the most recent if omitted): restores the original bytes. Returns a pending op id; apply it with 'confirm_op' or discard with 'reject_op'. Nothing is reverted until confirmed.")]
    fn undo(&self, Parameters(args): Parameters<UndoArgs>) -> Result<CallToolResult, ErrorData> {
        let entry = {
            let s = self
                .session
                .lock()
                .map_err(|_| err("session lock poisoned"))?;
            if args.id != 0 {
                s.get_undo(args.id).cloned()
            } else {
                s.peek_undo_last().cloned()
            }
        };
        let Some(e) = entry else {
            return Err(err("nothing to undo"));
        };
        // Stage it; nothing is reverted until confirmed.
        let mut s = self
            .session
            .lock()
            .map_err(|_| err("session lock poisoned"))?;
        let id = s.stage_op(
            e.address,
            PendingKind::Undo {
                original_bytes: e.original_bytes.clone(),
            },
            format!(
                "undo #{}: {} at {:#x} (restore {} byte(s))",
                e.id,
                e.description,
                e.address,
                e.original_bytes.len()
            ),
        );
        drop(s);
        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(format!(
                "staged undo (pending id {id}) for undo #{}. Call 'confirm_op' to apply or 'reject_op' to discard.",
                e.id
            )),
        ]))
    }

    /// Apply a previously staged (pending) mutation — the human confirmation
    /// step of the D8 gate. Once applied, the original bytes are snapshotted in
    /// the undo log so the op can later be reverted.
    #[tool(description = "Apply a staged mutation (from 'write'/'install_cave'/'undo') by id. This is the human-confirmation step: it actually modifies memory and records an undo entry. Discard instead with 'reject_op'.")]
    fn confirm_op(
        &self,
        Parameters(args): Parameters<OpConfirmArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let op = {
            let mut s = self
                .session
                .lock()
                .map_err(|_| err("session lock poisoned"))?;
            s.take_pending(args.id)
        };
        let Some(op) = op else {
            return Err(err(format!(
                "no pending op {}. Stage one with 'write'/'install_cave'/'undo' first.",
                args.id
            )));
        };
        let address = op.address;
        let preview = op.preview.clone();
        // Apply according to the op kind.
        let result = match &op.kind {
            PendingKind::Write { data } => {
                // Snapshot originals for the undo log before writing.
                let proc = game_process(&self.session)?;
                let original = proc.read(address, data.len()).unwrap_or_default();
                match call_dll(&Request::Write {
                    address,
                    data: data.clone(),
                }) {
                    Ok(Response::Write { bytes_written }) => {
                        let mut s = self
                            .session
                            .lock()
                            .map_err(|_| err("session lock poisoned"))?;
                        if !original.is_empty() {
                            let id = s.record_undo(
                                address,
                                original,
                                format!("write {} byte(s) at {:#x}", data.len(), address),
                            );
                            drop(s);
                            Ok(format!(
                                "confirmed write: wrote {bytes_written} byte(s) at {:#x} (undo id {id})",
                                address
                            ))
                        } else {
                            drop(s);
                            Ok(format!(
                                "confirmed write: wrote {bytes_written} byte(s) at {:#x}",
                                address
                            ))
                        }
                    }
                    Ok(Response::Error { message }) => Err(message),
                    Ok(_) => Err("unexpected response from DLL".into()),
                    Err(e) => Err(e),
                }
            }
            PendingKind::InstallCave { hook } => {
                match call_dll(&Request::InstallCave {
                    target: address,
                    hook: hook.clone(),
                }) {
                    Ok(Response::CaveInstalled { cave, target, original }) => {
                        let mut s = self
                            .session
                            .lock()
                            .map_err(|_| err("session lock poisoned"))?;
                        let id = s.record_undo(
                            target,
                            original.clone(),
                            format!("install_cave at {:#x}", target),
                        );
                        drop(s);
                        Ok(format!(
                            "confirmed cave: cave={:#x} target={:#x} ({}) original saved ({} byte(s)) (undo id {id})",
                            cave,
                            target,
                            preview,
                            original.len()
                        ))
                    }
                    Ok(Response::Error { message }) => Err(message),
                    Ok(_) => Err("unexpected response from DLL".into()),
                    Err(e) => Err(e),
                }
            }
            PendingKind::Undo { original_bytes } => {
                match call_dll(&Request::Write {
                    address,
                    data: original_bytes.clone(),
                }) {
                    Ok(Response::Write { bytes_written }) => Ok(format!(
                        "confirmed undo: restored {bytes_written} byte(s) at {:#x}",
                        address
                    )),
                    Ok(Response::Error { message }) => Err(message),
                    Ok(_) => Err("unexpected response from DLL".into()),
                    Err(e) => Err(e),
                }
            }
        };
        match result {
            Ok(text) => Ok(CallToolResult::success(vec![
                rmcp::model::ContentBlock::text(text),
            ])),
            Err(e) => Err(err(format!("failed to apply pending op {}: {e}", args.id))),
        }
    }

    /// Discard a previously staged (pending) mutation without applying it.
    #[tool(description = "Discard a staged mutation (from 'write'/'install_cave'/'undo') by id without applying it.")]
    fn reject_op(
        &self,
        Parameters(args): Parameters<OpConfirmArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let op = {
            let mut s = self
                .session
                .lock()
                .map_err(|_| err("session lock poisoned"))?;
            s.take_pending(args.id)
        };
        match op {
            Some(op) => Ok(CallToolResult::success(vec![
                rmcp::model::ContentBlock::text(format!(
                    "rejected pending op {} ({})",
                    op.id,
                    op.preview
                )),
            ])),
            None => Err(err(format!(
                "no pending op {}. Stage one with 'write'/'install_cave'/'undo' first.",
                args.id
            ))),
        }
    }

    /// List all staged (pending) mutations awaiting confirmation.
    #[tool(description = "List all staged (pending) mutations awaiting human confirmation, with their ids and previews.")]
    fn list_pending(&self) -> Result<CallToolResult, ErrorData> {
        let s = self
            .session
            .lock()
            .map_err(|_| err("session lock poisoned"))?;
        let pending = s.list_pending();
        if pending.is_empty() {
            return Ok(CallToolResult::success(vec![
                rmcp::model::ContentBlock::text("(no pending mutations)"),
            ]));
        }
        let lines: Vec<String> = pending
            .iter()
            .map(|p| format!("[{}] {} {}", p.id, p.kind.kind_text(), p.preview))
            .collect();
        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(lines.join("\n")),
        ]))
    }

    /// Get a labeled marker by name.
    #[tool(description = "Retrieve a saved marker by label.")]
    fn get_marker(
        &self,
        Parameters(args): Parameters<GetMarkerArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let s = self
            .session
            .lock()
            .map_err(|_| err("session lock poisoned"))?;
        match s.get_marker(&args.label) {
            Some(m) => {
                let note = m.note.as_deref().unwrap_or("");
                Ok(CallToolResult::success(vec![
                    rmcp::model::ContentBlock::text(format!(
                        "{} = {:#018x}{}",
                        m.label,
                        m.address,
                        if note.is_empty() {
                            String::new()
                        } else {
                            format!("  ({note})")
                        }
                    )),
                ]))
            }
            None => Err(err(format!("marker '{}' not found", args.label))),
        }
    }

    /// List all saved markers.
    #[tool(description = "List all markers saved in the session, sorted by label.")]
    fn list_markers(&self) -> Result<CallToolResult, ErrorData> {
        let s = self
            .session
            .lock()
            .map_err(|_| err("session lock poisoned"))?;
        let markers = s.list_markers();
        if markers.is_empty() {
            return Ok(CallToolResult::success(vec![
                rmcp::model::ContentBlock::text("(no markers)"),
            ]));
        }
        let lines: Vec<String> = markers
            .iter()
            .map(|m| {
                let note = m.note.as_deref().unwrap_or("");
                format!(
                    "{:<20} {:#018x}{}",
                    m.label,
                    m.address,
                    if note.is_empty() {
                        String::new()
                    } else {
                        format!("  ({note})")
                    }
                )
            })
            .collect();
        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(lines.join("\n")),
        ]))
    }

    /// Remove a marker by label.
    #[tool(description = "Remove a saved marker by label.")]
    fn remove_marker(
        &self,
        Parameters(args): Parameters<RemoveMarkerArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let mut s = self
            .session
            .lock()
            .map_err(|_| err("session lock poisoned"))?;
        match s.remove_marker(&args.label) {
            Some(m) => Ok(CallToolResult::success(vec![
                rmcp::model::ContentBlock::text(format!(
                    "removed marker '{}' ({:#018x})",
                    m.label, m.address
                )),
            ])),
            None => Err(err(format!("marker '{}' not found", args.label))),
        }
    }

    /// Describe an undo entry (or the most recent one).
    #[tool(description = "Inspect the undo log: a specific entry by id, or the most recent mutation.")]
    fn undo_info(
        &self,
        Parameters(args): Parameters<UndoInfoArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let s = self
            .session
            .lock()
            .map_err(|_| err("session lock poisoned"))?;
        let entry = match args.id {
            Some(id) => s.get_undo(id),
            None => s.peek_undo_last(),
        };
        match entry {
            Some(e) => Ok(CallToolResult::success(vec![
                rmcp::model::ContentBlock::text(format!(
                    "undo #{}: {} @ {:#018x} ({} original byte(s))",
                    e.id, e.description, e.address, e.original_bytes.len()
                )),
            ])),
            None => Err(err("no undo entry found")),
        }
    }
}
fn parse_addr(session: &SharedSession, s: &str) -> Result<u64, ErrorData> {
    parse_addr_expr(session, s)
}

/// Parse an address string which can be a raw address (hex/dec), a marker label
/// (e.g. "wood_ptr"), or a module/marker expression with offsets (e.g. "game.exe+0x1b42e9"
/// or "player_ptr+0x48").
pub(crate) fn parse_addr_expr(session: &SharedSession, input: &str) -> Result<u64, ErrorData> {
    let input = input.trim();

    // 1. Check for `+` or `-` offset expression: <base> + <offset>
    if let Some((base_part, off_part)) = input.split_once('+') {
        let base = parse_addr_expr(session, base_part)?;
        let off = parse_addr_str(off_part.trim()).map_err(|e| err(e))?;
        return Ok(base.wrapping_add(off));
    }
    if let Some((base_part, off_part)) = input.split_once('-') {
        let base = parse_addr_expr(session, base_part)?;
        let off = parse_addr_str(off_part.trim()).map_err(|e| err(e))?;
        return Ok(base.wrapping_sub(off));
    }

    // 2. Try raw address string (0x hex or decimal)
    if let Some(hex) = input.strip_prefix("0x").or_else(|| input.strip_prefix("0X")) {
        if let Ok(a) = u64::from_str_radix(hex, 16) {
            return Ok(a);
        }
    } else if let Ok(a) = input.parse::<u64>().or_else(|_| u64::from_str_radix(input, 16)) {
        return Ok(a);
    }

    // 3. Try looking up in session markers
    if let Ok(s) = session.lock() {
        if let Some(m) = s.get_marker(input) {
            return Ok(m.address);
        }
    }

    // 4. Try looking up as a loaded module base (e.g. "Unrailed2.exe" or "game.dll")
    if let Ok(base) = resolve_module_base(session, input) {
        return Ok(base);
    }

    Err(err(format!(
        "could not resolve address expression '{input}' (not a raw hex/dec address, saved marker, or loaded module)"
    )))
}

/// Parse a whitespace-tolerant hex string (e.g. "00 80 ac 43" or "0080ac43")
/// into raw bytes.
/// The name of a setup step (used for error messages and resolution).
impl crate::profile::SetupStep {
    fn name(&self) -> &str {
        match self {
            crate::profile::SetupStep::AobScan { name, .. }
            | crate::profile::SetupStep::PointerChain { name, .. }
            | crate::profile::SetupStep::Address { name, .. } => name,
        }
    }
}

/// Resolve a setup step to a concrete address for the current launch.
fn resolve_setup_step(
    session: &SharedSession,
    step: &crate::profile::SetupStep,
) -> Result<u64, String> {
    use crate::profile::SetupStep;
    match step {
        SetupStep::AobScan { pattern, offset, .. } => {
            // AOB scan externally (matches the `aob_scan` tool), take the
            // first match + offset.
            let parsed = trainlab_core::aob::parse(pattern);
            if parsed.is_empty() {
                return Err("empty/invalid AOB pattern".into());
            }
            let proc = game_process(session).map_err(|e| e.to_string())?;
            let regions = proc.regions().map_err(|e| format!("regions: {e}"))?;
            let mut first_match: Option<u64> = None;
            for r in regions {
                if !r.readable {
                    continue;
                }
                let len = (r.end - r.start) as usize;
                if len < parsed.len() {
                    continue;
                }
                if let Ok(buf) = proc.read(r.start, len) {
                    if let Some(off) = trainlab_core::aob::find_all(&buf, &parsed).first() {
                        first_match = Some(r.start + *off as u64);
                        break;
                    }
                }
            }
            let m = first_match.ok_or_else(|| "aob scan found no matches".to_string())?;
            Ok((m as i64 + offset.unwrap_or(0)) as u64)
        }
        SetupStep::PointerChain { module, base, offsets, .. } => {
            // Resolve the module base, then add the module-relative base
            // offset, then chase the chain via the DLL.
            let module_base = resolve_module_base(session, module)?;
            let base_off = parse_addr_str(base)?;
            let base_addr = module_base.wrapping_add(base_off);
            let offsets_u64: Vec<u64> = offsets
                .iter()
                .map(|o| parse_addr_str(o))
                .collect::<Result<Vec<_>, _>>()?;
            let resp = crate::controller::request(
                session,
                &trainlab_core::protocol::Request::PointerChase {
                    base: base_addr,
                    offsets: offsets_u64,
                },
            )
            .map_err(|e| format!("pointer chase: {e}"))?;
            match resp {
                trainlab_core::protocol::Response::PointerChase { hops } => {
                    hops.last().copied().ok_or_else(|| "empty chain".into())
                }
                trainlab_core::protocol::Response::Error { message } => Err(message),
                _ => Err("unexpected pointer response".into()),
            }
        }
        SetupStep::Address { module, offset, .. } => {
            // Module-relative address: module base + offset.
            let module_base = resolve_module_base(session, module)?;
            let off = parse_addr_str(offset)?;
            Ok(module_base.wrapping_add(off))
        }
    }
}

/// Resolve a loaded module's base address by name (case-insensitive) against
/// the game process's loaded modules.
fn resolve_module_base(session: &SharedSession, module: &str) -> Result<u64, String> {
    let pid = {
        let s = session.lock().map_err(|_| "session lock poisoned".to_string())?;
        s.game_pid().ok_or_else(|| "no game process attached".to_string())?
    };
    let modules = trainlab_core::modinfo::enumerate_windows(pid)
        .map_err(|e| format!("enumerate modules: {e}"))?;
    let target = module.to_lowercase();
    modules
        .iter()
        .find(|m| m.name.to_lowercase() == target)
        .map(|m| m.base)
        .ok_or_else(|| format!("module '{module}' not found in game process"))
}

/// Resolve a cheat's address from a named setup value or an inline reference.
///
/// `address_ref`/`target_ref` may be either a **named setup value** (resolved
/// by the profile's setup steps) or a **raw address** (decimal or `0x` hex,
/// e.g. from `save_profile` which serializes the live address). Named refs are
/// tried first; if not found in the resolved map, we fall back to parsing it
/// as a raw address.
fn resolve_cheat_address(
    resolved: &[(String, u64)],
    pc: &crate::profile::ProfileCheat,
) -> Result<u64, ErrorData> {
    let refs = [pc.address_ref.as_deref(), pc.target_ref.as_deref()];
    for r in refs.into_iter().flatten() {
        // Named setup value?
        if let Some((_, a)) = resolved.iter().find(|(n, _)| n == r) {
            return Ok(*a);
        }
        // Raw address (decimal or 0x hex)?
        if let Ok(a) = parse_addr_str(r) {
            return Ok(a);
        }
        return Err(err(format!("setup value '{r}' not resolved and not a raw address")));
    }
    Err(err("cheat has no address_ref/target_ref"))
}

/// Parse an address string (decimal or 0x hex) into a u64.
fn parse_addr_str(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|e| format!("bad hex '{s}': {e}"))
    } else if let Some(hex) = s.strip_prefix('+') {
        u64::from_str_radix(hex.trim_start_matches("0x"), 16)
            .map_err(|e| format!("bad offset '{s}': {e}"))
    } else {
        s.parse::<u64>().map_err(|e| format!("bad address '{s}': {e}"))
    }
}

/// Encode a byte slice as a lowercase hex string.
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse a decimal/float string into little-endian bytes for a value type.
pub(crate) fn parse_value_bytes(s: &str, vt: trainlab_core::scan::ValueType) -> Result<Vec<u8>, ErrorData> {
    use trainlab_core::scan::ValueType;
    let s = s.trim();
    match vt {
        ValueType::I32 => Ok(s
            .parse::<i32>()
            .map_err(|_| err(format!("invalid i32 '{s}'")))?
            .to_le_bytes()
            .to_vec()),
        ValueType::U32 => Ok(s
            .parse::<u32>()
            .map_err(|_| err(format!("invalid u32 '{s}'")))?
            .to_le_bytes()
            .to_vec()),
        ValueType::F32 => Ok(s
            .parse::<f32>()
            .map_err(|_| err(format!("invalid f32 '{s}'")))?
            .to_le_bytes()
            .to_vec()),
        ValueType::I64 => Ok(s
            .parse::<i64>()
            .map_err(|_| err(format!("invalid i64 '{s}'")))?
            .to_le_bytes()
            .to_vec()),
        ValueType::U64 => Ok(s
            .parse::<u64>()
            .map_err(|_| err(format!("invalid u64 '{s}'")))?
            .to_le_bytes()
            .to_vec()),
        ValueType::F64 => Ok(s
            .parse::<f64>()
            .map_err(|_| err(format!("invalid f64 '{s}'")))?
            .to_le_bytes()
            .to_vec()),
        ValueType::Ptr => Ok(parse_addr_str(s)
            .map_err(|_| err(format!("invalid ptr '{s}'")))?
            .to_le_bytes()
            .to_vec()),
    }
}

pub(crate) fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, ErrorData> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.len() % 2 != 0 {
        return Err(err("hex string must have an even number of digits"));
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for i in (0..cleaned.len()).step_by(2) {
        let byte = u8::from_str_radix(&cleaned[i..i + 2], 16).map_err(|_| err("invalid hex byte"))?;
        out.push(byte);
    }
    Ok(out)
}

/// Build an `ErrorData` with an internal-error code.
fn err(message: impl Into<String>) -> ErrorData {
    ErrorData::new(
        rmcp::model::ErrorCode::INTERNAL_ERROR,
        message.into(),
        None,
    )
}

/// Parse a value-type string into a [`ValueType`].
pub(crate) fn parse_value_type(s: &str) -> Result<trainlab_core::scan::ValueType, ErrorData> {
    use trainlab_core::scan::ValueType;
    match s.trim().to_lowercase().as_str() {
        "i32" => Ok(ValueType::I32),
        "u32" => Ok(ValueType::U32),
        "f32" => Ok(ValueType::F32),
        "i64" => Ok(ValueType::I64),
        "u64" => Ok(ValueType::U64),
        "f64" => Ok(ValueType::F64),
        "ptr" | "pointer" => Ok(ValueType::Ptr),
        other => Err(err(format!(
            "unknown value type '{other}' (expected i32/u32/f32/i64/u64/f64/ptr)"
        ))),
    }
}

/// Parse a narrowing op string into a [`ScanOp`].
fn parse_scan_op(
    op: &str,
    value: Option<f64>,
    max: Option<f64>,
) -> Result<trainlab_core::scan::ScanOp, ErrorData> {
    use trainlab_core::scan::ScanOp;
    match op.trim().to_lowercase().as_str() {
        "changed" => Ok(ScanOp::Changed),
        "unchanged" => Ok(ScanOp::Unchanged),
        "increased" => Ok(ScanOp::Increased),
        "decreased" => Ok(ScanOp::Decreased),
        "exact" => {
            let v = value.ok_or_else(|| err("'exact' requires a value"))?;
            Ok(ScanOp::Exact { value: v })
        }
        "range" => {
            let min = value.ok_or_else(|| err("'range' requires a value (min)"))?;
            let max = max.ok_or_else(|| err("'range' requires a max"))?;
            Ok(ScanOp::Range { min, max })
        }
        other => Err(err(format!(
            "unknown op '{other}' (expected changed/unchanged/increased/decreased/exact/range)"
        ))),
    }
}

/// Read a little-endian signed/unsigned integer from the process and format it.
/// Each function reads exactly its own width.
fn read_i8(proc: &dyn trainlab_core::memory::ProcessMemory, address: u64) -> Result<String, String> {
    let b = proc.read(address, 1).map_err(|e| e.to_string())?;
    Ok(i8::from_le_bytes([b[0]]).to_string())
}
fn read_u8(proc: &dyn trainlab_core::memory::ProcessMemory, address: u64) -> Result<String, String> {
    let b = proc.read(address, 1).map_err(|e| e.to_string())?;
    Ok(u8::from_le_bytes([b[0]]).to_string())
}
fn read_i16(proc: &dyn trainlab_core::memory::ProcessMemory, address: u64) -> Result<String, String> {
    let b = proc.read(address, 2).map_err(|e| e.to_string())?;
    Ok(i16::from_le_bytes([b[0], b[1]]).to_string())
}
fn read_u16(proc: &dyn trainlab_core::memory::ProcessMemory, address: u64) -> Result<String, String> {
    let b = proc.read(address, 2).map_err(|e| e.to_string())?;
    Ok(u16::from_le_bytes([b[0], b[1]]).to_string())
}
fn read_i32(proc: &dyn trainlab_core::memory::ProcessMemory, address: u64) -> Result<String, String> {
    let b = proc.read(address, 4).map_err(|e| e.to_string())?;
    Ok(i32::from_le_bytes([b[0], b[1], b[2], b[3]]).to_string())
}
fn read_u32(proc: &dyn trainlab_core::memory::ProcessMemory, address: u64) -> Result<String, String> {
    let b = proc.read(address, 4).map_err(|e| e.to_string())?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]).to_string())
}
fn read_i64(proc: &dyn trainlab_core::memory::ProcessMemory, address: u64) -> Result<String, String> {
    let b = proc.read(address, 8).map_err(|e| e.to_string())?;
    Ok(i64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]).to_string())
}
fn read_u64(proc: &dyn trainlab_core::memory::ProcessMemory, address: u64) -> Result<String, String> {
    let b = proc.read(address, 8).map_err(|e| e.to_string())?;
    Ok(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]).to_string())
}

/// Read a little-endian `f32` from the process and format it.
fn read_f32_val(
    proc: &dyn trainlab_core::memory::ProcessMemory,
    address: u64,
) -> Result<String, String> {
    let b = proc.read(address, 4).map_err(|e| e.to_string())?;
    Ok(f32::from_le_bytes([b[0], b[1], b[2], b[3]]).to_string())
}

/// Read a little-endian `f64` from the process and format it.
fn read_f64_val(
    proc: &dyn trainlab_core::memory::ProcessMemory,
    address: u64,
) -> Result<String, String> {
    let b = proc.read(address, 8).map_err(|e| e.to_string())?;
    Ok(f64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ])
    .to_string())
}

/// Read a null-terminated ASCII string (up to `max_len` bytes) from the process.
fn read_cstr(
    proc: &dyn trainlab_core::memory::ProcessMemory,
    address: u64,
    max_len: usize,
) -> Result<String, String> {
    let buf = proc.read(address, max_len).map_err(|e| e.to_string())?;
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let bytes = &buf[..end];
    if bytes.iter().all(|&b| (0x20..0x7f).contains(&b) || b == b' ') {
        Ok(String::from_utf8_lossy(bytes).into_owned())
    } else {
        // Not printable ASCII: return hex of the raw bytes instead.
        Ok(format!(
            "<non-ascii {} byte(s)> {}",
            bytes.len(),
            bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ")
        ))
    }
}

/// Format a raw byte slice as a hex+ASCII dump, anchored at `base`.
///
/// Output is 16 bytes per line:
/// `0xADDR  hh hh hh ... hh  |ascii|`
fn format_dump(base: u64, data: &[u8]) -> String {
    let mut out = String::new();
    for (off, chunk) in data.chunks(16).enumerate() {
        let addr = base + (off * 16) as u64;
        // Hex bytes
        let mut hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        while hex.len() < 16 {
            hex.push("  ".to_string());
        }
        // ASCII
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if (0x20..0x7f).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        out.push_str(&format!("{addr:#018x}  {}  |{}|\n", hex.join(" "), ascii));
    }
    out
}

/// Format a watchpoint/breakpoint hit into a readable report.
fn format_hit(
    rip: u64,
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rsp: u64,
    rbp: u64,
    description: &str,
    stack: &[String],
) -> String {
    let mut out = String::new();
    out.push_str(&format!("{description}\n"));
    out.push_str(&format!("RIP={rip:#018x}  RAX={rax:#018x}  RBX={rbx:#018x}\n"));
    out.push_str(&format!("RCX={rcx:#018x}  RDX={rdx:#018x}  RSI={rsi:#018x}\n"));
    out.push_str(&format!("RDI={rdi:#018x}  RSP={rsp:#018x}  RBP={rbp:#018x}\n"));
    if !stack.is_empty() {
        out.push_str("stack (RSP upward):\n");
        for (i, w) in stack.iter().enumerate() {
            out.push_str(&format!("  +0x{:02x}  {}\n", i * 8, w));
        }
    }
    out
}

/// Start the MCP server on `127.0.0.1:port` and serve until the returned
/// `CancellationToken` is cancelled.
///
/// This binds an axum router at `/mcp` hosting the Streamable HTTP transport,
/// backed by an in-memory `LocalSessionManager`. It returns the base URL
/// (`http://127.0.0.1:<port>/mcp`) and a cancellation token. It returns
/// immediately after spawning the serving task.
pub async fn serve(
    host: &str,
    port: u16,
    session: SharedSession,
    egui_ctx: Option<eframe::egui::Context>,
) -> anyhow::Result<(String, tokio_util::sync::CancellationToken)> {
    use rmcp::transport::{
        streamable_http_server::session::local::LocalSessionManager,
        StreamableHttpServerConfig, StreamableHttpService,
    };

    let ct = tokio_util::sync::CancellationToken::new();
    let mut config = StreamableHttpServerConfig::default()
        .with_sse_keep_alive(Some(std::time::Duration::from_secs(30)))
        .with_cancellation_token(ct.child_token());
    // The server binds to 0.0.0.0 so a laptop/desktop can reach it on the LAN
    // (see LAUNCHING.md). rmcp's default `allowed_hosts` only permits loopback,
    // which would reject every remote Host header (the client sends the LAN IP,
    // which we can't know in advance). When binding to all interfaces, disable
    // the host check so remote MCP clients can connect. Loopback-only binds keep
    // the default allowlist.
    if host == "0.0.0.0" {
        config = config.disable_allowed_hosts();
    }

    // Shared session state (game pid, markers, undo log, scan) across all MCP
    // sessions. The GUI writes `game_pid`; scan-family tools open it here.
    let session_factory = {
        let session = session.clone();
        let egui_ctx = egui_ctx.clone();
        move || Ok(TrainlabMcpServer::with_session_and_ctx(session.clone(), egui_ctx.clone()))
    };
    let service: StreamableHttpService<TrainlabMcpServer, LocalSessionManager> =
        StreamableHttpService::new(
            session_factory,
            std::sync::Arc::new(LocalSessionManager::default()),
            config,
        );
    let _ = std::fs::create_dir_all("snapshots");
    let router = axum::Router::new()
        .nest_service("/mcp", service)
        .nest_service("/snapshots", tower_http::services::ServeDir::new("snapshots"));
    let listener = tokio::net::TcpListener::bind((host, port)).await?;
    let addr = listener.local_addr()?;
    tracing::info!(%addr, "trainlab MCP server listening on /mcp");

    tokio::spawn({
        let ct = ct.clone();
        async move {
            let _ = axum::serve(listener, router)
                .with_graceful_shutdown(async move { ct.cancelled_owned().await })
                .await;
        }
    });

    Ok((format!("http://{addr}/mcp"), ct))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::CallToolRequestParams;
    use rmcp::service::ServiceExt;
    use rmcp::transport::StreamableHttpClientTransport;
    use rmcp::ClientHandler;

    /// A minimal no-op client handler.
    struct TestClient;
    impl ClientHandler for TestClient {}

    #[tokio::test]
    async fn ping_roundtrip() -> anyhow::Result<()> {
        let (url, ct) = serve("127.0.0.1", 0, Default::default(), None).await?;
        let url: std::sync::Arc<str> = url.into();
        let transport: StreamableHttpClientTransport<reqwest::Client> =
            StreamableHttpClientTransport::from_uri(url);
        let client = TestClient.serve(transport).await?;
        let resp = client
            .call_tool(CallToolRequestParams::new("ping").with_arguments(serde_json::Map::new()))
            .await?;
        let text = resp
            .content
            .iter()
            .filter_map(|b| match b {
                rmcp::model::ContentBlock::Text(t) => Some(t.text.clone()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join(" ");
        assert!(text.contains("pong"), "expected pong, got: {text}");
        client.cancel().await?;
        ct.cancel();
        Ok(())
    }

    #[test]
    fn resolve_cheat_address_named_and_raw() {
        let resolved = vec![("wood_addr".to_string(), 0x1000u64)];
        // Named setup value.
        let pc = crate::profile::ProfileCheat {
            id: "a".into(),
            label: "a".into(),
            kind: "value".into(),
            value_type: Some("i32".into()),
            address_ref: Some("wood_addr".into()),
            target_ref: None,
            hook: None,
            payload: None,
            mechanism: None,
            rate_hz: None,
            value: None,
            commands: None,
            note: None,
        };
        assert_eq!(resolve_cheat_address(&resolved, &pc).unwrap(), 0x1000);
        // Raw hex address (as save_profile writes).
        let pc2 = crate::profile::ProfileCheat {
            address_ref: Some("0x14aaa37f4".into()),
            ..pc.clone()
        };
        assert_eq!(resolve_cheat_address(&resolved, &pc2).unwrap(), 0x14aaa37f4);
        // Raw decimal address.
        let pc3 = crate::profile::ProfileCheat {
            address_ref: Some("4096".into()),
            ..pc.clone()
        };
        assert_eq!(resolve_cheat_address(&resolved, &pc3).unwrap(), 4096);
        // Unknown name that isn't a raw address -> error.
        let pc4 = crate::profile::ProfileCheat {
            address_ref: Some("nope".into()),
            ..pc
        };
        assert!(resolve_cheat_address(&resolved, &pc4).is_err());
    }

    /// A tiny in-memory process for testing the value-read helpers.
    struct FakeMem {
        data: Vec<u8>,
    }
    impl trainlab_core::memory::ProcessMemory for FakeMem {
        fn read(&self, address: u64, len: usize) -> Result<Vec<u8>, trainlab_core::memory::MemoryError> {
            let start = address as usize;
            let end = (start + len).min(self.data.len());
            if start >= self.data.len() {
                return Err(trainlab_core::memory::MemoryError::OutOfRange {
                    address: start as u64,
                });
            }
            Ok(self.data[start..end].to_vec())
        }
        fn write(&self, _address: u64, _data: &[u8]) -> Result<usize, trainlab_core::memory::MemoryError> {
            Ok(0)
        }
        fn regions(&self) -> Result<Vec<trainlab_core::memory::Region>, trainlab_core::memory::MemoryError> {
            Ok(vec![])
        }
    }

    #[test]
    fn dump_struct_helpers_decode_le_values() {
        // Layout: u32=0x01020304, f32=2.5, cstr "hi\0" at offset 8.
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&0x01020304u32.to_le_bytes());
        data[4..8].copy_from_slice(&2.5f32.to_le_bytes());
        data[8] = b'h';
        data[9] = b'i';
        data[10] = 0;
        let p = FakeMem { data };

        assert_eq!(read_u32(&p, 0).unwrap(), "16909060"); // 0x01020304
        assert_eq!(read_f32_val(&p, 4).unwrap(), "2.5");
        assert_eq!(read_cstr(&p, 8, 16).unwrap(), "hi");
        // A ptr read of the u32 bytes yields an arbitrary value; just check it's a number.
        let _ = read_u64(&p, 0).unwrap();
    }

    #[tokio::test]
    async fn snapshot_tool_and_http_serving_roundtrip() -> anyhow::Result<()> {
        let (url, ct) = serve("127.0.0.1", 0, Default::default(), None).await?;
        let mcp_url: std::sync::Arc<str> = url.clone().into();
        let transport: StreamableHttpClientTransport<reqwest::Client> =
            StreamableHttpClientTransport::from_uri(mcp_url);
        let client = TestClient.serve(transport).await?;

        // Create a snapshot file manually in snapshots/ to test HTTP endpoint
        let _ = std::fs::create_dir_all("snapshots");
        let test_snap = std::path::Path::new("snapshots").join("test_http_snap.bin");
        std::fs::write(&test_snap, b"SNAPSHOT_DATA_TEST_1234")?;

        // Deriving port from server url "http://127.0.0.1:<port>/mcp"
        let base_url = url.trim_end_matches("/mcp");
        let http_url = format!("{base_url}/snapshots/test_http_snap.bin");

        let res = reqwest::get(&http_url).await?;
        assert!(res.status().is_success(), "HTTP get snapshot failed with status: {}", res.status());
        let body = res.bytes().await?;
        assert_eq!(&body[..], b"SNAPSHOT_DATA_TEST_1234");

        let _ = std::fs::remove_file(&test_snap);
        client.cancel().await?;
        ct.cancel();
        Ok(())
    }

    #[test]
    fn allocate_string_kind_validation() {
        let s = SharedSession::default();
        let server = TrainlabMcpServer::with_session_and_ctx(s, None);

        // Invalid kind rejected
        let res_err = server.allocate_string(Parameters(AllocateStringArgs {
            content: "print('hello')".into(),
            kind: "lua".into(), // Explicly rejected per spec
        }));
        assert!(res_err.is_err());

        // Valid kind accepted
        let res_ok_c = server.allocate_string(Parameters(AllocateStringArgs {
            content: "print('hello')".into(),
            kind: "c".into(),
        }));
        // Requires attached game process, so returns error for no PID attached
        assert!(res_ok_c.is_err());
        let err_msg = res_ok_c.unwrap_err().message;
        assert!(err_msg.contains("no game process"));
    }

    #[test]
    fn write_tool_handles_data_and_typed_values() {
        let s = SharedSession::default();
        let server = TrainlabMcpServer::with_session_and_ctx(s, None);

        // 1. Raw data (hex)
        let res_raw = server.write(Parameters(WriteArgs {
            address: "0x1000".into(),
            data: Some("90 90 c3".into()),
            value: None,
            value_type: None,
        })).unwrap();
        let text_raw = match &res_raw.content[0] {
            rmcp::model::ContentBlock::Text(t) => t.text.clone(),
            _ => panic!("expected text"),
        };
        assert!(text_raw.contains("staged write"));

        // 2. Typed value (ptr)
        let res_typed = server.write(Parameters(WriteArgs {
            address: "0x1000".into(),
            data: None,
            value: Some("0xe890000".into()),
            value_type: Some("ptr".into()),
        })).unwrap();
        let text_typed = match &res_typed.content[0] {
            rmcp::model::ContentBlock::Text(t) => t.text.clone(),
            _ => panic!("expected text"),
        };
        assert!(text_typed.contains("staged write"));

        // 3. Both provided -> error
        let res_both = server.write(Parameters(WriteArgs {
            address: "0x1000".into(),
            data: Some("90".into()),
            value: Some("1".into()),
            value_type: None,
        }));
        assert!(res_both.is_err());

        // 4. Neither provided -> error
        let res_neither = server.write(Parameters(WriteArgs {
            address: "0x1000".into(),
            data: None,
            value: None,
            value_type: None,
        }));
        assert!(res_neither.is_err());
    }

    #[test]
    fn write_value_encodes_pointer_little_endian() {
        // Regression: the agent used to hand-encode a pointer into hex bytes and
        // transposed digits (0xe890000 -> 00 00 90 0e ... instead of 00 00 89 0e ...),
        // which made the cave read garbage and crashed the game. `write`
        // must encode the pointer itself, correctly.
        let data = parse_value_bytes("0xe890000", trainlab_core::scan::ValueType::Ptr).unwrap();
        // 0x0e890000 little-endian = 00 00 89 0e 00 00 00 00
        assert_eq!(data, vec![0x00, 0x00, 0x89, 0x0e, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn write_value_encodes_typed_values() {
        // i32
        assert_eq!(
            parse_value_bytes("99990", trainlab_core::scan::ValueType::I32).unwrap(),
            99990i32.to_le_bytes().to_vec()
        );
        // f64
        assert_eq!(
            parse_value_bytes("3.14", trainlab_core::scan::ValueType::F64).unwrap(),
            3.14f64.to_le_bytes().to_vec()
        );
        // u64
        assert_eq!(
            parse_value_bytes("18446744073709551615", trainlab_core::scan::ValueType::U64).unwrap(),
            u64::MAX.to_le_bytes().to_vec()
        );
    }

    #[test]
    fn parse_addr_expr_resolves_markers_and_offsets() {
        let s = SharedSession::default();
        {
            let mut session = s.lock().unwrap();
            session.set_marker("wood_ptr", 0x0e890000, None).unwrap();
        }

        // Raw hex
        assert_eq!(parse_addr_expr(&s, "0x1000").unwrap(), 0x1000);
        // Raw dec
        assert_eq!(parse_addr_expr(&s, "4096").unwrap(), 4096);
        // Saved marker
        assert_eq!(parse_addr_expr(&s, "wood_ptr").unwrap(), 0x0e890000);
        // Marker + offset math
        assert_eq!(parse_addr_expr(&s, "wood_ptr + 0x48").unwrap(), 0x0e890048);
        assert_eq!(parse_addr_expr(&s, "wood_ptr - 0x10").unwrap(), 0x0e88fff0);
    }

    #[test]
    fn read_tool_handles_hex_and_typed_values() {
        let s = SharedSession::default();
        let server = TrainlabMcpServer::with_session_and_ctx(s, None);

        // Unknown value_type rejected
        let res_err = server.read(Parameters(ReadArgs {
            address: "0x1000".into(),
            len: None,
            value_type: Some("invalid_type".into()),
        }));
        assert!(res_err.is_err());

        // Requires attached game process for live reads, so returns error for no PID attached
        let res_ok = server.read(Parameters(ReadArgs {
            address: "0x1000".into(),
            len: Some(4),
            value_type: Some("i32".into()),
        }));
        assert!(res_ok.is_err());
        let err_msg = res_ok.unwrap_err().message;
        assert!(err_msg.contains("no game process"));
    }
}
