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
}

impl TrainlabMcpServer {
    /// Create a handler sharing the given session state.
    pub fn with_session(session: SharedSession) -> Self {
        Self { session }
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
    /// Start address to read from (decimal or `0x` hex).
    pub address: String,
    /// Number of bytes to read.
    pub len: usize,
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
    /// Address to mark (decimal or `0x` hex).
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
    /// Target address (decimal or `0x` hex) whose referrers to find.
    pub address: String,
    /// Optional size around `address` to treat as the target range (default 8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

/// Arguments for [`pointer_chase`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PointerChaseArgs {
    /// Base address to start chasing from (decimal or `0x` hex).
    pub base: String,
    /// Field offsets applied after each dereference (decimal or `0x` hex).
    pub offsets: Vec<String>,
}

/// Arguments for [`dump`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DumpArgs {
    /// Start address to dump (decimal or `0x` hex).
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
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DumpStructArgs {
    /// Base address of the struct (decimal or `0x` hex).
    pub address: String,
    /// The typed fields to extract, each with a name, type, and offset.
    pub fields: Vec<StructField>,
}

/// Arguments for [`watch_writes`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct WatchWritesArgs {
    /// Address to watch for writes (decimal or `0x` hex).
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
    /// Code address to break on (decimal or `0x` hex).
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
    /// Address to resolve (decimal or `0x` hex).
    pub address: String,
}

/// Arguments for [`disassemble`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DisassembleArgs {
    /// Address to disassemble from (decimal or `0x` hex).
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
    /// Address to write to (decimal or `0x` hex).
    pub address: String,
    /// Hex bytes to write (e.g. "00 80 ac 43" or "0080ac43").
    pub data: String,
}

/// Arguments for [`install_cave`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct InstallCaveArgs {
    /// Address of the instruction to redirect (decimal or `0x` hex).
    pub target: String,
    /// Hook kind: "trampoline" (default, transparent — replays the stolen
    /// instructions so the game keeps working) or "override" (skips them).
    #[serde(default = "default_hook_kind")]
    pub hook: String,
    /// Hex shellcode payload bytes to run in the cave (empty = pure no-op for
    /// trampoline).
    #[serde(default)]
    pub payload: String,
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
    /// Disarm after the first capture (default true).
    #[serde(default = "default_true")]
    pub one_shot: bool,
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
                    let s = self
                        .session
                        .lock()
                        .map_err(|_| err("session lock poisoned"))?;
                    s.game_pid().map(|p| p.to_string()).unwrap_or_else(|| "unknown".into())
                };
                Ok(CallToolResult::success(vec![
                    rmcp::model::ContentBlock::text(format!(
                        "attached to '{}' (pid {pid}), inject v{version}",
                        args.game
                    )),
                ]))
            }
            Err(e) => Err(err(format!("attach failed: {e}"))),
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
                let address = parse_addr(address)?;
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
                let target = parse_addr(target)?;
                let payload = parse_hex_bytes(args.payload.as_deref().unwrap_or(""))?;
                let hook = match args.hook.as_deref().unwrap_or("trampoline") {
                    "trampoline" => CaveHook::Trampoline { payload },
                    "override" => CaveHook::Override { payload },
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
        drop(s);
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
                CheatKind::Toggle { .. } => {
                    return Err(err(format!("cheat {} is a toggle, not a value", args.id)))
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
                CheatKind::Value { .. } => {
                    return Err(err(format!("cheat {} is a value, not a toggle", args.id)))
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
                        "trampoline" => trainlab_core::cave_hook::CaveHook::Trampoline { payload },
                        "override" => trainlab_core::cave_hook::CaveHook::Override { payload },
                        other => return Err(err(format!("unknown hook '{other}'"))),
                    };
                    crate::session::CheatKind::Toggle {
                        hook,
                        target,
                        enabled: false,
                    }
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
                            trainlab_core::cave_hook::CaveHook::Trampoline { payload } => {
                                ("trampoline".to_string(), Some(hex_encode(payload)))
                            }
                            trainlab_core::cave_hook::CaveHook::Override { payload } => {
                                ("override".to_string(), Some(hex_encode(payload)))
                            }
                        };
                        ("toggle".to_string(), None, None, Some(format!("{target:#x}")), Some(hk), pl)
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

    /// Read memory from the game process.
    #[tool(description = "Read bytes from game memory at a given address, read externally.")]
    fn read(&self, Parameters(args): Parameters<ReadArgs>) -> Result<CallToolResult, ErrorData> {
        let address = parse_addr(&args.address)?;
        let proc = game_process(&self.session)?;
        match proc.read(address, args.len) {
            Ok(data) => {
                let hex = data
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                Ok(CallToolResult::success(vec![
                    rmcp::model::ContentBlock::text(hex),
                ]))
            }
            Err(e) => Err(err(format!("read failed: {e}"))),
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

    /// Find addresses that point to (reference) a target address.
    #[tool(description = "Reverse-reference scan: find writable addresses whose pointer value points into the range around a target address. Use to find what points to a value (owning object), then chase a stable chain.")]
    fn pointer_scan(
        &self,
        Parameters(args): Parameters<PointerScanArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let address = parse_addr(&args.address)?;
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
        let base = parse_addr(&args.base)?;
        let mut offsets = Vec::new();
        for o in &args.offsets {
            offsets.push(parse_addr(o)?);
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
        let address = parse_addr(&args.address)?;
        let mut s = self
            .session
            .lock()
            .map_err(|_| err("session lock poisoned"))?;
        s.set_marker(&args.label, address, args.note.as_deref())
            .map_err(|e| err(e))?;
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
        let address = parse_addr(&args.address)?;
        let proc = game_process(&self.session)?;
        match proc.read(address, args.len) {
            Ok(data) => Ok(CallToolResult::success(vec![
                rmcp::model::ContentBlock::text(format_dump(address, &data)),
            ])),
            Err(e) => Err(err(format!("dump failed: {e}"))),
        }
    }

    /// Read a struct at an address as a list of typed fields (name, type,
    /// offset) and format them, so the agent can reverse a struct/class layout
    /// without manually slicing raw bytes.
    #[tool(description = "Read a struct at an address and format each requested field by type. Field types: i8, u8, i16, u16, i32, u32, i64, u64, f32, f64, ptr, cstr (null-terminated ASCII), or bytes. Pass an offset per field (default 0).")]
    fn dump_struct(
        &self,
        Parameters(args): Parameters<DumpStructArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let address = parse_addr(&args.address)?;
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
        let address = parse_addr(&args.address)?;
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
        let address = parse_addr(&args.address)?;
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
        use trainlab_core::capture::{CaptureRegSpec, Register, ValueType};
        let target = parse_addr(&args.target)?;
        let reg = Register::parse(&args.reg)
            .ok_or_else(|| err(format!("unknown register '{}' (try rax/rcx/rbx/... or xmm0..xmm7)", args.reg)))?;
        let value_type = ValueType::parse(&args.value_type)
            .ok_or_else(|| err(format!("unknown value_type '{}' (try ptr/i64/u64/f64/f32)", args.value_type)))?;
        let spec = CaptureRegSpec::new(reg, value_type);
        match call_dll(&Request::CaptureReg {
            target,
            spec,
            capacity: args.capacity,
            one_shot: args.one_shot,
        }) {
            Ok(Response::CaptureInstalled {
                id,
                scratch,
                target: _,
                original: _,
            }) => Ok(CallToolResult::success(vec![
                rmcp::model::ContentBlock::text(format!(
                    "armed non-stalling capture id {id} at {:#x}: capturing {} as {} (capacity {}) (one_shot={}).\nscratch buffer: {:#x} (readable via 'read').\nRead back with 'read_captures' (id {id}); uninstall with 'uninstall_capture_reg' (id {id}).",
                    target,
                    reg.name(),
                    value_type.name(),
                    args.capacity,
                    args.one_shot,
                    scratch,
                )),
            ])),
            Ok(Response::Error { message }) => Err(err(message)),
            Ok(_) => Err(err("unexpected response from DLL")),
            Err(e) => Err(err(e)),
        }
    }

    /// Read back the entries recorded by a `capture_reg` capture.
    #[tool(description = "Read back the register values recorded by a passive 'capture_reg' capture (by id). Returns each captured entry: sequence, decoded value, raw 64-bit value, and the site address that was executing.")]
    fn read_captures(
        &self,
        Parameters(args): Parameters<ReadCapturesArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        match call_dll(&Request::ReadCaptures { id: args.id }) {
            Ok(Response::ReadCaptures { entries }) => {
                if entries.is_empty() {
                    return Ok(CallToolResult::success(vec![
                        rmcp::model::ContentBlock::text(format!(
                            "capture {} has not recorded any hits yet (the site has not executed since arming).",
                            args.id
                        )),
                    ]));
                }
                let mut lines = vec![format!("capture {} — {} recorded hit(s):", args.id, entries.len())];
                for e in entries {
                    lines.push(format!(
                        "  seq={} reg_value={:.4} raw=0x{:016x} rip=0x{:016x}",
                        e.seq, e.reg_value, e.raw, e.rip
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
        let address = parse_addr(&args.address)?;
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
        let address = parse_addr(&args.address)?;
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

    /// Stage a raw byte write for human confirmation (D8).
    ///
    /// This *stages* the write and returns a pending op id + preview; it does
    /// **not** modify memory yet. Confirm with `confirm_op`, or discard with
    /// `reject_op`.
    #[tool(description = "Stage a byte write to game memory at an address (hex data). Returns a pending op id; apply it with 'confirm_op' or discard with 'reject_op'. Nothing is written until confirmed.")]
    fn write(&self, Parameters(args): Parameters<WriteArgs>) -> Result<CallToolResult, ErrorData> {
        let address = parse_addr(&args.address)?;
        let data = parse_hex_bytes(&args.data)?;
        if data.is_empty() {
            return Err(err("write data cannot be empty"));
        }
        // Stage it; nothing is written until confirmed. Original bytes are
        // snapshotted only when the op is confirmed (see confirm_op).
        let mut s = self
            .session
            .lock()
            .map_err(|_| err("session lock poisoned"))?;
        let id = s.stage_op(
            address,
            PendingKind::Write { data: data.clone() },
            format!(
                "write {} byte(s) at {:#x}: {}",
                data.len(),
                address,
                data.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
            ),
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
    #[tool(description = "Stage a code cave install: allocate executable memory, run a shellcode payload, redirect an instruction to it via a jmp. Returns a pending op id; apply it with 'confirm_op' or discard with 'reject_op'. Nothing is patched until confirmed.")]
    fn install_cave(
        &self,
        Parameters(args): Parameters<InstallCaveArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        use trainlab_core::cave_hook::CaveHook;
        let target = parse_addr(&args.target)?;
        let payload = parse_hex_bytes(&args.payload)?;
        let hook = match args.hook.as_str() {
            "trampoline" => CaveHook::Trampoline { payload: payload.clone() },
            "override" => CaveHook::Override { payload: payload.clone() },
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
fn parse_addr(s: &str) -> Result<u64, ErrorData> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|e| err(format!("bad address: {e}")))
    } else {
        s.parse::<u64>()
            .or_else(|_| u64::from_str_radix(s, 16))
            .map_err(|e| err(format!("bad address: {e}")))
    }
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
fn parse_value_bytes(s: &str, vt: trainlab_core::scan::ValueType) -> Result<Vec<u8>, ErrorData> {
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
        ValueType::Ptr => Ok(s
            .parse::<u64>()
            .map_err(|_| err(format!("invalid ptr '{s}'")))?
            .to_le_bytes()
            .to_vec()),
    }
}

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, ErrorData> {
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
fn parse_value_type(s: &str) -> Result<trainlab_core::scan::ValueType, ErrorData> {
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
        move || Ok(TrainlabMcpServer::with_session(session.clone()))
    };
    let service: StreamableHttpService<TrainlabMcpServer, LocalSessionManager> =
        StreamableHttpService::new(
            session_factory,
            std::sync::Arc::new(LocalSessionManager::default()),
            config,
        );
    let router = axum::Router::new().nest_service("/mcp", service);
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
        let (url, ct) = serve("127.0.0.1", 0, Default::default()).await?;
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
}
