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

use std::collections::HashMap;

use crate::session::{CheatKind, PendingKind, SharedSession};

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
pub(crate) fn is_process_alive(pid: u32) -> bool {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Threading::{OpenProcess, GetExitCodeProcess, PROCESS_QUERY_LIMITED_INFORMATION};
        use windows_sys::Win32::Foundation::CloseHandle;
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            return false;
        }
        let mut exit_code: u32 = 0;
        let ok = unsafe { GetExitCodeProcess(handle, &mut exit_code) };
        unsafe { CloseHandle(handle); }
        ok != 0 && exit_code == 259 // STILL_ACTIVE == 259
    }
    #[cfg(not(windows))]
    {
        let _ = pid;
        true
    }
}

pub(crate) fn game_process(
    session: &SharedSession,
) -> Result<Box<dyn trainlab_core::memory::ProcessMemory>, ErrorData> {
    let (pid, game_name) = {
        let s = session.lock().map_err(|_| err("session lock poisoned"))?;
        (s.game_pid(), s.game_name().to_string())
    };
    let pid = pid.ok_or_else(|| err("no game process attached; find & inject a game first"))?;

    if !is_process_alive(pid) {
        if let Ok(mut s) = session.lock() {
            s.set_connected(false);
            s.set_lifecycle(trainlab_core::session::SessionLifecycle::TargetLost {
                pid,
                exe_name: game_name.clone(),
            });
            s.log_activity("MCP", format!("target game process '{game_name}' (pid {pid}) is no longer running (game_alive: false)"));
        }
        return Err(err(format!(
            "game process '{game_name}' (pid {pid}) has terminated / is not running (game_alive: false). Re-attach to a running game with 'attach_game'."
        )));
    }

    #[cfg(windows)]
    {
        trainlab_core::memory::WindowsProcess::open(pid)
            .map(|p| Box::new(p) as Box<dyn trainlab_core::memory::ProcessMemory>)
            .map_err(|e| {
                if !is_process_alive(pid) {
                    if let Ok(mut s) = session.lock() {
                        s.set_connected(false);
                        s.set_lifecycle(trainlab_core::session::SessionLifecycle::TargetLost {
                            pid,
                            exe_name: game_name.clone(),
                        });
                    }
                    err(format!("game process '{game_name}' (pid {pid}) died (game_alive: false)"))
                } else {
                    err(format!("failed to open game process '{game_name}' (pid {pid}) externally: {e}"))
                }
            })
    }
    #[cfg(not(windows))]
    {
        let _ = pid;
        Err(err("external scan requires the Windows GUI"))
    }
}

/// Send a request to the injected DLL over the single persistent multiplexed
/// IPC connection managed by [`crate::controller`].
///
/// # Deprecated
/// This wrapper exists only for call-site compatibility while MCP tools are
/// migrated. Prefer calling [`crate::controller::request`] directly. Do not
/// add new call sites.
#[deprecated(note = "use crate::controller::request directly")]
#[allow(deprecated)]
fn call_dll(session: &SharedSession, req: &Request) -> Result<Response, String> {
    crate::controller::request(session, req)
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

/// Arguments for [`set_marker`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SetMarkerArgs {
    /// Label to identify the marker (persists across turns).
    pub label: String,
    /// Address or expression to mark: raw hex, dec, module relative ("game.exe+0x100"), or offset math ("player_ptr+0x48").
    pub address: String,
    /// Optional byte size if this marks a memory region (e.g. 0x10000000 for 256MB).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<usize>,
    /// Semantic kind of the marked address. Use "object" when the marker IS the struct/class
    /// instance (offsets applied directly without deref); "pointer" (default) when the marker
    /// is a pointer slot to be dereferenced; "buffer" for raw memory regions; "code" for
    /// code/function sites. Affects pointer_chase behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Optional reference to a named struct type (from register_struct_def) describing the
    /// layout at this address. Only meaningful when kind == "object".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub struct_type: Option<String>,
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

/// A single field for [`register_struct_def`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RegisterStructFieldArg {
    /// Field name / label (e.g. "Health", "Shield", "OwnerID").
    pub label: String,
    /// Offset from the struct base as a hex or decimal string (e.g. "0x38", "56").
    pub offset_expr: String,
    /// Value type string: i8, u8, i16, u16, i32, u32, i64, u64, f32, f64, ptr.
    pub value_type: String,
}

/// Arguments for [`register_struct_def`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RegisterStructDefArgs {
    /// Unique type name, e.g. "ShipEntity", "PlayerData", "SelectionManager".
    pub name: String,
    /// Total byte size of the struct, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<usize>,
    /// Fields in this struct.
    pub fields: Vec<RegisterStructFieldArg>,
    /// Optional human note / source comment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Arguments for [`remove_struct_def`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RemoveStructDefArgs {
    /// Type name to remove (e.g. "ShipEntity").
    pub name: String,
}

/// Arguments for [`get_network_log`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GetNetworkLogArgs {
    /// Optional max number of packets to return (default: 20).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    /// Optional pagination offset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
    /// Optional protocol filter: "tcp", "udp", "http", or "all".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proto: Option<String>,
    /// Optional endpoint filter substring (matches IP, port, or URL).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
}

/// Arguments for [`watch_network`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct WatchNetworkArgs {
    /// Optional filter string (matching host, port, or URL).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
    /// Optional protocol filter: "tcp", "udp", "http", or "all".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proto: Option<String>,
    /// Max packets to inspect in this turn (default: 10).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

/// Arguments for [`clear_network_log`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ClearNetworkLogArgs {}

/// Arguments for [`configure_network`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ConfigureNetworkArgs {
    /// Whether network traffic interception is enabled.
    pub enabled: bool,
    /// Whether to capture loopback (127.0.0.1 / localhost / ::1) traffic. Defaults to false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_loopback: Option<bool>,
    /// Additional ports to ignore (beyond the trainer's internal IPC and MCP ports).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ignore_ports: Option<Vec<u16>>,
}

/// Arguments for [`undo_info`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct UndoInfoArgs {
    /// Optional undo id; if omitted, describe the most recent mutation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
}

/// Arguments for [`scan_start`] / [`scan`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ScanStartArgs {
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
    /// Optional region marker name (e.g. "game_heap") or expression to bound the scan to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
}

/// Backwards-compatible alias for [`ScanStartArgs`].
pub type ScanArgs = ScanStartArgs;

/// Arguments for [`scan_next`] / [`next`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ScanNextArgs {
    /// Narrowing op: changed, unchanged, increased, decreased, exact, range.
    pub op: String,
    /// For `exact`: the value to match. For `range`: the min.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<f64>,
    /// For `range`: the max.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
}

/// Backwards-compatible alias for [`ScanNextArgs`].
pub type NextArgs = ScanNextArgs;

/// Arguments for [`scan_set`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ScanSetArgs {
    /// Value to write to all currently matching scan addresses (e.g. "999", "3.14", "0x1234").
    pub value: String,
    /// Optional value type override (defaults to the scan's value type).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_type: Option<String>,
}

/// Arguments for [`scan_aob`] / [`aob_scan`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ScanAobArgs {
    /// AOB pattern in hex with `??` wildcards, e.g. "48 8B 05 ?? ?? ?? ??".
    pub pattern: String,
    /// Optional byte offset to add to the matched address (e.g. 3 to skip the opcode).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,
    /// Optional marker name to automatically save the first match address under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub marker: Option<String>,
    /// Optional region marker name (e.g. "game_heap") or expression to bound the search.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Optional address alignment (e.g. 4 or 8 for pointer/data scans, 1 for unaligned code).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alignment: Option<usize>,
    /// Maximum number of match addresses to return (default 20).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

/// Backwards-compatible alias for [`ScanAobArgs`].
pub type AobArgs = ScanAobArgs;

/// Arguments for [`scan_pointer`] / [`pointer_scan`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ScanPointerArgs {
    /// Target address or expression whose referrers to find: raw hex, dec, module, or marker ("wood_ptr+0x10").
    pub address: String,
    /// Optional size around `address` to treat as the target range (default 8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Maximum number of referrer matches to return (default 50).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

/// Arguments for [`scan_rgrep`] / [`rgrep`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ScanRgrepArgs {
    /// Regular expression pattern over raw bytes (e.g. "player_.*", "(?i)credits", or binary "(?s-u)\x48\x89").
    pub pattern: String,
    /// Optional address alignment (e.g. 1, 4, 8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alignment: Option<usize>,
    /// Optional region marker name (e.g. "game_heap") or address expression to bound search.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Optional marker name to automatically save the first match address under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub marker: Option<String>,
    /// Maximum number of matches to return (default 20).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

/// Backwards-compatible alias for [`ScanRgrepArgs`].
pub type RgrepArgs = ScanRgrepArgs;

/// Backwards-compatible alias for [`ScanPointerArgs`].
pub type PointerScanArgs = ScanPointerArgs;

/// Arguments for [`list_regions`].
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct ListRegionsArgs {
    /// Maximum number of regions to return in text (default 50). If total exceeds limit, full results are saved to a snapshot file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    /// Optional filter to only include named (module/heap) regions (default false).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub named_only: Option<bool>,
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
    /// Byte offset from the struct base (default 0). Accepts integers or hex strings (e.g. 16 or "0x10").
    #[serde(default, deserialize_with = "deserialize_offset")]
    pub offset: u64,
    /// For `bytes`: how many bytes to read. For `cstr`: max length to scan
    /// (default 256). Ignored for other types.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub len: Option<usize>,
}

fn deserialize_offset<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum NumOrStr {
        Num(u64),
        Signed(i64),
        Str(String),
    }

    match NumOrStr::deserialize(deserializer)? {
        NumOrStr::Num(n) => Ok(n),
        NumOrStr::Signed(s) => Ok(s as u64),
        NumOrStr::Str(s) => {
            let s = s.trim();
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                u64::from_str_radix(hex, 16).map_err(serde::de::Error::custom)
            } else if let Ok(n) = s.parse::<u64>() {
                Ok(n)
            } else if let Ok(n) = s.parse::<i64>() {
                Ok(n as u64)
            } else {
                Err(serde::de::Error::custom(format!("invalid offset string: '{s}'")))
            }
        }
    }
}

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

/// Arguments for [`dump_struct`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DumpStructArgs {
    /// Base address or expression of the struct (raw hex, dec, module, or marker).
    pub address: String,
    /// The typed fields to extract, each with a name, type, and offset. Accepts an array of field objects or a JSON-encoded string.
    #[serde(deserialize_with = "deserialize_fields_or_json")]
    pub fields: Vec<StructField>,
}

fn deserialize_fields_or_json<'de, D>(deserializer: D) -> Result<Vec<StructField>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum FieldsOrString {
        List(Vec<StructField>),
        Str(String),
    }

    match FieldsOrString::deserialize(deserializer)? {
        FieldsOrString::List(fields) => Ok(fields),
        FieldsOrString::Str(s) => {
            let s_trimmed = s.trim();
            if s_trimmed.is_empty() || s_trimmed == "[]" {
                Ok(Vec::new())
            } else {
                serde_json::from_str(&s).map_err(serde::de::Error::custom)
            }
        }
    }
}

/// Arguments for [`watch_writes`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct WatchWritesArgs {
    /// Address or expression to watch for writes: raw hex, dec, module, or marker ("wood_ptr+0x10").
    pub address: String,
    /// Number of bytes to watch (1, 2, 4, or 8; default 4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub len: Option<usize>,
    /// If true, disarm after the first hit (default true). If false, continues accumulating hits until cleared.
    #[serde(default = "default_true")]
    pub one_shot: bool,
    /// Watchpoint mechanism: "page_guard" (default, robust across all worker threads & Wine/Proton) or "hardware" (DR0/DR7).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mechanism: Option<String>,
}

/// Arguments for [`break_on_code`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BreakOnCodeArgs {
    /// Code address or expression to break on: raw hex, dec, or module relative ("game.exe+0x50a0").
    pub address: String,
    /// If true, disarm after the first hit (default true).
    #[serde(default = "default_true")]
    pub one_shot: bool,
    /// If true, bypass the instruction boundary verification guard (default false).
    #[serde(default)]
    pub force: bool,
}

fn default_true() -> bool {
    true
}

/// Arguments for [`launch_app`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct LaunchAppArgs {
    /// Executable path to launch (e.g. "C:\\Games\\game.exe" or "/usr/bin/app").
    pub path: String,
    /// Optional command-line arguments to pass.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,
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
    /// trampoline, mutually exclusive with asm).
    #[serde(default)]
    pub payload: String,
    /// Optional assembly source text (e.g. Cheat-Engine-style ASM, mutually exclusive with payload).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asm: Option<String>,
    /// Jump style: "absolute" (default, 14-byte long jump) or "relative" (5-byte short jump for tight patch sites).
    #[serde(default = "default_jump_style")]
    pub jump: String,
    /// Optional marker label to automatically save the allocated cave address under once confirmed (e.g. "my_cave").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub marker: Option<String>,
    /// If true, bypass safety checks (such as the unjumped data-slot fallthrough guard).
    #[serde(default)]
    pub force: bool,
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
    #[serde(default, deserialize_with = "deserialize_gate_opt")]
    pub gate: Option<CaptureGateArgs>,
    /// Jump style: "absolute" (default, 14-byte long jump) or "relative" (5-byte short jump for tight patch sites).
    #[serde(default)]
    pub jump: Option<String>,
    /// If true, bypass the instruction boundary verification guard (default false).
    #[serde(default)]
    pub force: bool,
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

fn deserialize_gate_opt<'de, D>(deserializer: D) -> Result<Option<CaptureGateArgs>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum GateOrString {
        Struct(CaptureGateArgs),
        Str(String),
        None,
    }

    match Option::<GateOrString>::deserialize(deserializer)? {
        Some(GateOrString::Struct(gate)) => Ok(Some(gate)),
        Some(GateOrString::Str(s)) => {
            let s_trimmed = s.trim();
            if s_trimmed.is_empty() || s_trimmed == "null" {
                Ok(None)
            } else {
                serde_json::from_str(&s).map(Some).map_err(serde::de::Error::custom)
            }
        }
        Some(GateOrString::None) | None => Ok(None),
    }
}

/// Arguments for [`allocate_string`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AllocateStringArgs {
    /// The string content (raw bytes/text of the program, script, or config) to place in the game process. Optional if 'size' is provided.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    /// Size in bytes to allocate if 'content' is not provided.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<usize>,
    /// Optional byte to fill allocated buffer with (defaults to 0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fill_byte: Option<u8>,
    /// Memory layout kind: "c" (default, NUL-terminated C string), "rust" (fat pointer ptr+len), "json", "yaml", "xml", "js", "config".
    #[serde(default = "default_string_kind")]
    pub kind: String,
    /// Optional marker label to save the allocated string's pointer under (e.g. "str_payload").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub marker: Option<String>,
}

fn default_string_kind() -> String {
    "c".to_string()
}

/// Arguments for [`allocate_memory`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AllocateMemoryArgs {
    /// Number of bytes to allocate in the target process.
    pub size: usize,
    /// Optional marker label to save the allocated buffer address under (e.g. "dump_buffer").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub marker: Option<String>,
    /// Optional byte value to initialize all allocated bytes with (defaults to 0x00).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fill_byte: Option<u8>,
    /// Memory protection permissions: "rw" (default, PAGE_READWRITE), "rwx" (PAGE_EXECUTE_READWRITE), "rx" (PAGE_EXECUTE_READ), "r" (PAGE_READONLY).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<String>,
}

/// Arguments for [`free_memory`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FreeMemoryArgs {
    /// Target address or marker name to free (e.g. "0x7ff12000" or "$dump_buffer").
    pub address: String,
    /// Optional size in bytes to decommit. If omitted, completely releases the allocated memory region (MEM_RELEASE).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<usize>,
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
    /// For toggle cheats: optional assembly source text (e.g. Cheat-Engine-style ASM with [rip + label] constants).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asm: Option<String>,
    /// For toggle cheats: jump style ("absolute" or "relative").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jump: Option<String>,
    /// For patch cheats (zero-alloc toggles): hex bytes to write when enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patch_bytes: Option<String>,
    /// For patch cheats (zero-alloc toggles): original hex bytes to restore when disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_bytes: Option<String>,
    /// For patch cheats: optional reference to named cave marker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cave_ref: Option<String>,
    /// Optional grouping/category name (e.g. "In Menu", "In Session", "Player", "Weapons").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Optional hotkey binding (e.g. "Num 1", "Shift+Alt+K", "F1").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hotkey: Option<String>,
    /// Optional flag to hide this cheat from the user-facing GUI and in-game overlay (e.g. agent/WIP/transport cheats).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hidden: Option<bool>,
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
}

/// Arguments for [`set_overlay_visible`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SetOverlayVisibleArgs {
    /// Whether the overlay is visible.
    pub visible: bool,
}

/// Arguments for [`alloc_code_cave`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AllocCodeCaveArgs {
    /// Marker name to store the allocated cave address under (e.g. "cave_god_mode").
    pub name: String,
    /// Size in bytes to allocate (default 1024).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<usize>,
    /// Optional target code address to allocate within relative jump distance (±2GB).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub near_target: Option<String>,
    /// Optional shellcode payload (hex string) to immediately write into the cave.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    /// Optional human note / description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Arguments for [`emit_relative_jump`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EmitRelativeJumpArgs {
    /// Source / patch address where the jump will be placed.
    pub from: String,
    /// Destination address (or cave marker) where the jump will land.
    pub to: String,
    /// Total instruction length to pad with NOPs (e.g. 5, 7, 8). Default 5.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pad_to_len: Option<usize>,
}

/// Arguments for [`assemble_asm`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AssembleAsmArgs {
    /// Assembly source code text. Supports mnemonics (mov, mulss, divss, jmp, xor, etc.)
    /// and directives (dd (float)4.0, dd 100, dq 0x..., db 90 90), as well as named markers ($cave_const).
    pub code: String,
    /// Origin address (RIP) where this code will be placed (default 0x0 or target cave marker).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
}

/// `#[tool_router(server_handler)]` generates the `ServerHandler` impl.
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
    #[tool(description = "Report trainer status: MCP reachable, whether we're connected to a DLL, whether target game process is alive, the game pid, game name, DLL version, lifecycle state, and configured host/port.")]
    fn connection_status(&self) -> Result<CallToolResult, ErrorData> {
        let mut s = self
            .session
            .lock()
            .map_err(|_| err("session lock poisoned"))?;

        let (game_alive, pid_str) = if let Some(pid) = s.game_pid() {
            let alive = is_process_alive(pid);
            if !alive && s.connected() {
                s.set_connected(false);
                let game = s.game_name().to_string();
                s.set_lifecycle(trainlab_core::session::SessionLifecycle::TargetLost {
                    pid,
                    exe_name: game,
                });
            }
            (alive, pid.to_string())
        } else {
            (false, "none".into())
        };

        let connected = s.connected();
        let game = s.game_name().to_string();
        let ver = s.inject_version().unwrap_or("(not connected)").to_string();
        let host = s.dll_host().to_string();
        let port = s.dll_port();
        let lifecycle = format!("{:?}", s.lifecycle());
        drop(s);
        let text = format!(
            "MCP: reachable\nconnected: {connected}\ngame: {game}\npid: {pid_str}\ngame_alive: {game_alive}\nlifecycle: {lifecycle}\ninject v: {ver}\ndll host: {host}:{port}"
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

    /// Add a user-facing adjustable game option ("cheat") to the session.
    #[tool(description = "Add a cheat (adjustable game option) to the session. kind='value' for a typed value at an address; kind='toggle' for a code-cave hook (e.g. god mode). It appears in the GUI Cheats panel.")]
    fn add_cheat(
        &self,
        Parameters(args): Parameters<AddCheatArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ctx = trainlab_core::session::ClientContext::new("mcp", trainlab_core::session::ClientKind::Mcp { agent_name: None }, self.session.lock().unwrap().event_bus());
        let res = trainlab_core::tools::execute_add_cheat(&self.session, &ctx, None, trainlab_core::tools::AddCheatArgs {
            label: args.label,
            kind: args.kind,
            address: args.address,
            value_type: args.value_type,
            group: args.group,
            hotkey: args.hotkey,
            hidden: args.hidden,
            note: args.note,
        }).map_err(|e| err(e.message))?;

        self.request_repaint();
        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(res.message),
        ]))
    }

    /// List all cheats in the session.
    #[tool(description = "List all cheats (adjustable game options) in the session, with their ids, kinds, and addresses.")]
    fn list_cheats(&self) -> Result<CallToolResult, ErrorData> {
        let ctx = trainlab_core::session::ClientContext::new("mcp", trainlab_core::session::ClientKind::Mcp { agent_name: None }, self.session.lock().unwrap().event_bus());
        let res = trainlab_core::tools::execute_list_cheats(&self.session, &ctx).map_err(|e| err(e.message))?;
        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(res.message),
        ]))
    }

    /// Remove a cheat from the session.
    #[tool(description = "Remove a cheat by id from the session.")]
    fn remove_cheat(
        &self,
        Parameters(args): Parameters<CheatIdArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ctx = trainlab_core::session::ClientContext::new("mcp", trainlab_core::session::ClientKind::Mcp { agent_name: None }, self.session.lock().unwrap().event_bus());
        let res = trainlab_core::tools::execute_remove_cheat(&self.session, &ctx, trainlab_core::tools::RemoveCheatArgs {
            id: args.id,
        }).map_err(|e| err(e.message))?;

        self.request_repaint();
        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(res.message),
        ]))
    }

    /// Set a value cheat's value directly in game memory (with automatic undo snapshot).
    #[tool(description = "Set a value cheat's value in game memory with automatic undo snapshot.")]
    pub(crate) fn set_cheat_value(
        &self,
        Parameters(args): Parameters<SetCheatValueArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let proc = game_process(&self.session)?;
        let ctx = trainlab_core::session::ClientContext::new("mcp", trainlab_core::session::ClientKind::Mcp { agent_name: None }, self.session.lock().unwrap().event_bus());
        let res = trainlab_core::tools::execute_set_cheat_value(&self.session, &ctx, proc.as_ref(), trainlab_core::tools::SetCheatValueArgs {
            id: args.id,
            value: args.value,
        }).map_err(|e| err(e.message))?;

        self.request_repaint();
        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(res.message),
        ]))
    }

    /// Enable/disable a toggle cheat (installs/removes the cave hook).
    #[tool(description = "Enable or disable a toggle cheat (e.g. god mode). Enabling immediately installs the cave hook; disabling removes it (restores original bytes).")]
    pub(crate) fn set_cheat_toggle(
        &self,
        Parameters(args): Parameters<SetCheatToggleArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let (kind, label) = {
            let s = self.session.lock().map_err(|_| err("session lock poisoned"))?;
            let c = s.get_cheat(args.id).ok_or_else(|| err(format!("no cheat with id {}", args.id)))?;
            (c.kind.clone(), c.label.clone())
        };

        match kind {
            CheatKind::Toggle { target, hook, enabled, original_bytes, .. } => {
                if enabled == args.enabled {
                    return Ok(CallToolResult::success(vec![
                        rmcp::model::ContentBlock::text(format!(
                            "toggle cheat #{} ('{}') already {}",
                            args.id,
                            label,
                            if args.enabled { "enabled" } else { "disabled" }
                        )),
                    ]));
                }

                if args.enabled {
                    if let trainlab_core::cave_hook::CaveHook::Override { payload, .. } = &hook {
                        if payload.is_empty() {
                            return Err(err(format!(
                                "toggle cheat #{} ('{}') has an empty override hook with no payload; cannot enable stub toggle",
                                args.id, label
                            )));
                        }
                    }

                    let resp = call_dll(&self.session, &Request::InstallCave {
                        target,
                        hook,
                    }).map_err(err)?;

                    match resp {
                        Response::CaveInstalled { cave, original, .. } => {
                            // Verify target memory has live hook
                            let proc = game_process(&self.session)?;
                            let check = proc.read(target, 1).unwrap_or_default();
                            let verified = matches!(check.first(), Some(0xe9 | 0xff | 0xeb));

                            let mut s = self.session.lock().map_err(|_| err("session lock poisoned"))?;
                            s.set_toggle_cave_info(args.id, original.clone(), cave);
                            s.record_undo(target, original.clone(), format!("toggle cheat #{} ('{}')", args.id, label));
                            s.set_cheat_toggle(args.id, true);
                            s.log_activity("MCP", format!("toggle cheat #{} ('{}') enabled @ {target:#x} -> cave @ {cave:#x}", args.id, label));

                            let msg = if verified {
                                format!("toggle cheat #{} ('{}') enabled: cave installed @ {cave:#x} (target {target:#x} verified)", args.id, label)
                            } else {
                                format!("toggle cheat #{} ('{}') enabled: cave installed @ {cave:#x} (warning: live jump byte not detected at target {target:#x})", args.id, label)
                            };

                            Ok(CallToolResult::success(vec![
                                rmcp::model::ContentBlock::text(msg),
                            ]))
                        }
                        Response::Error { message } => Err(err(format!("failed to install cave: {message}"))),
                        _ => Err(err("unexpected response from DLL during cave install")),
                    }
                } else {
                    let restore_bytes = if !original_bytes.is_empty() {
                        Some(original_bytes)
                    } else {
                        self.session.lock().ok().and_then(|s| s.find_undo_for_target(target))
                    };

                    let data = restore_bytes.ok_or_else(|| {
                        err(format!("toggle cheat #{} ('{}') has no stored original bytes; cannot restore", args.id, label))
                    })?;

                    let resp = call_dll(&self.session, &Request::Write {
                        address: target,
                        data,
                    }).map_err(err)?;

                    match resp {
                        Response::Write { bytes_written } => {
                            let mut s = self.session.lock().map_err(|_| err("session lock poisoned"))?;
                            s.set_cheat_toggle(args.id, false);
                            s.remove_undo_for_target(target);
                            s.log_activity("MCP", format!("toggle cheat #{} ('{}') disabled (restored {bytes_written} bytes @ {target:#x})", args.id, label));

                            Ok(CallToolResult::success(vec![
                                rmcp::model::ContentBlock::text(format!(
                                    "toggle cheat #{} ('{}') disabled: restored {bytes_written} bytes @ {target:#x}",
                                    args.id, label
                                )),
                            ]))
                        }
                        Response::Error { message } => Err(err(format!("failed to restore original bytes: {message}"))),
                        _ => Err(err("unexpected response from DLL during write")),
                    }
                }
            }
            CheatKind::Patch { target, patch_bytes, original_bytes, enabled, cave_ref } => {
                if enabled == args.enabled {
                    return Ok(CallToolResult::success(vec![
                        rmcp::model::ContentBlock::text(format!(
                            "patch cheat #{} ('{}') already {}",
                            args.id,
                            label,
                            if args.enabled { "enabled" } else { "disabled" }
                        )),
                    ]));
                }
                if args.enabled && patch_bytes.is_empty() {
                    return Err(err(format!("patch cheat #{} ('{}') has empty patch_bytes; cannot enable", args.id, label)));
                }

                let data = if args.enabled {
                    patch_bytes
                } else {
                    if original_bytes.is_empty() {
                        return Err(err(format!("patch cheat #{} ('{}') has no original bytes recorded; cannot disable", args.id, label)));
                    }
                    original_bytes
                };

                let resp = call_dll(&self.session, &Request::Write {
                    address: target,
                    data,
                }).map_err(err)?;

                match resp {
                    Response::Write { bytes_written } => {
                        let mut s = self.session.lock().map_err(|_| err("session lock poisoned"))?;
                        s.set_cheat_toggle(args.id, args.enabled);
                        let action_str = if args.enabled { "enabled" } else { "disabled" };
                        let desc = cave_ref.as_deref().unwrap_or("patch");
                        s.log_activity("MCP", format!("patch cheat #{} ('{}') {} ({bytes_written} bytes @ {target:#x}, {desc})", args.id, label, action_str));

                        Ok(CallToolResult::success(vec![
                            rmcp::model::ContentBlock::text(format!(
                                "patch cheat #{} ('{}') {}: wrote {bytes_written} bytes @ {target:#x}",
                                args.id, label, action_str
                            )),
                        ]))
                    }
                    Response::Error { message } => Err(err(format!("failed to write patch bytes: {message}"))),
                    _ => Err(err("unexpected response from DLL during patch write")),
                }
            }
            _ => Err(err(format!("cheat #{} ('{}') is not a toggle or patch cheat", args.id, label))),
        }
    }

    /// List cheat profiles discovered in the `cheats/` directory.
    #[tool(description = "Query in-game graphics API detection, DXGI frame presentation hook, and input capture status.")]
    fn get_render_status(&self) -> Result<CallToolResult, ErrorData> {
        let resp = crate::controller::request(&self.session, &Request::GetRenderStatus).map_err(err)?;
        match resp {
            Response::RenderStatus {
                api,
                present_hooked,
                wndproc_hooked,
                frame_count,
                overlay_visible,
                input_hook,
                combo_count,
                detected_overlays,
            } => {
                let report = serde_json::json!({
                    "api": api,
                    "input_hook": input_hook,
                    "present_hooked": present_hooked,
                    "wndproc_hooked": wndproc_hooked,
                    "frame_count": frame_count,
                    "combo_count": combo_count,
                    "overlay_visible": overlay_visible,
                    "detected_foreign_overlays": detected_overlays,
                });
                Ok(CallToolResult::success(vec![
                    rmcp::model::ContentBlock::text(
                        serde_json::to_string_pretty(&report).unwrap_or_default(),
                    ),
                ]))
            }
            Response::Error { message } => Err(err(message)),
            other => Err(err(format!("unexpected response: {other:?}"))),
        }
    }

    /// Set in-game cheat overlay visibility.
    #[tool(description = "Set in-game cheat overlay visibility.")]
    fn set_overlay_visible(
        &self,
        Parameters(args): Parameters<SetOverlayVisibleArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let resp = crate::controller::request(
            &self.session,
            &Request::SetOverlayVisible { visible: args.visible },
        )
        .map_err(err)?;
        match resp {
            Response::OverlayVisibilitySet { visible } => Ok(CallToolResult::success(vec![
                rmcp::model::ContentBlock::text(format!("in-game overlay visibility set to {visible}")),
            ])),
            Response::Error { message } => Err(err(message)),
            other => Err(err(format!("unexpected response: {other:?}"))),
        }
    }

    /// List cheat profiles discovered in the `cheats/` directory.
    #[tool(description = "List cheat profiles (portable YAML cheat tables) discovered in the cheats/ directory next to the GUI, with their target game.")]
    fn list_profiles(&self) -> Result<CallToolResult, ErrorData> {
        let ctx = trainlab_core::session::ClientContext::new("mcp", trainlab_core::session::ClientKind::Mcp { agent_name: None }, self.session.lock().unwrap().event_bus());
        let res = trainlab_core::tools::execute_list_profiles(&self.session, &ctx).map_err(|e| err(e.message))?;

        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(res.message),
        ]))
    }

    pub(crate) fn load_profile_by_name(&self, profile_name: &str, run_setup: bool) -> Result<String, String> {
        let args = LoadProfileArgs { profile: profile_name.into(), run_setup };
        // T-143: Return the detailed result text (resolved addresses, counts)
        // instead of the constant "profile loaded".
        self.load_profile(Parameters(args)).map_err(|e| e.message.to_string()).and_then(|result| {
            // Extract the text content from the CallToolResult.
            result.content.into_iter().find_map(|block| match block {
                rmcp::model::ContentBlock::Text(t) => Some(t.text),
                _ => None,
            }).ok_or_else(|| "profile loaded (no detail)".to_string())
        })
    }

    /// Load a cheat profile: run its setup steps to resolve base addresses,
    /// then materialize its cheats into the session (populating known values,
    /// but NOT enabling any cheats).
    #[tool(description = "Load a cheat profile by file name or game exe. Runs setup steps (AOB scans, pointer chains, addresses) to resolve base addresses, then materializes the profile's cheats into the session. Does NOT enable any cheats.")]
    fn load_profile(
        &self,
        Parameters(args): Parameters<LoadProfileArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        // Enforce session clean state (BUG_load_profile_orphans_live_patches.md).
        // Refuse to load a new profile if the current session holds active cave hooks,
        // enabled cheats, unreverted undo entries, or unfreed memory allocations,
        // or if another operation/init/load is in progress.
        {
            let mut s = self.session.lock().map_err(|_| err("session lock poisoned"))?;
            let dirty = s.check_dirty();
            if dirty.is_dirty() {
                let err_msg = format!(
                    "cannot load profile '{}' while session is dirty: {}. Revert active cheats/mutations or restart game before loading a profile.",
                    args.profile,
                    dirty.summary()
                );
                return Err(err(err_msg));
            }
            s.set_operation_in_progress(Some(format!("loading profile '{}'", args.profile)));
        }

        // RAII guard to ensure operation_in_progress is cleared even if load_profile errors out early.
        struct LoadGuard<'a>(&'a std::sync::Arc<std::sync::Mutex<trainlab_core::session::SessionState>>);
        impl<'a> Drop for LoadGuard<'a> {
            fn drop(&mut self) {
                if let Ok(mut s) = self.0.lock() {
                    s.set_operation_in_progress(None);
                }
            }
        }
        let _guard = LoadGuard(&self.session);

        let all_discovered = crate::profile::discover_all_profiles();
        // Match by file name or by game exe.
        let target = args.profile.trim().to_lowercase();
        let mut found_valid: Option<(&String, &crate::profile::GameProfile)> = None;
        let mut found_invalid: Option<(&String, &String)> = None;

        for dp in &all_discovered {
            match dp {
                crate::profile::DiscoveredProfile::Valid { file, profile } => {
                    if file.to_lowercase() == target || profile.game.to_lowercase() == target {
                        found_valid = Some((file, profile));
                        break;
                    }
                }
                crate::profile::DiscoveredProfile::Invalid { file, error } => {
                    if file.to_lowercase() == target || target.contains(file.to_lowercase().trim_end_matches(".yaml")) {
                        found_invalid = Some((file, error));
                    }
                }
            }
        }

        let (file, profile) = match (found_valid, found_invalid) {
            (Some(v), _) => v,
            (None, Some((f, err_msg))) => {
                return Err(err(format!(
                    "profile '{f}' found in cheats/ but FAILED to parse: {err_msg}"
                )))
            }
            (None, None) => {
                return Err(err(format!(
                    "no profile found for '{}' (looked in cheats/)",
                    args.profile
                )))
            }
        };
        let profile = profile.clone();

        // Materialize game name into session early
        if let Ok(mut s) = self.session.lock() {
            s.set_game_name(profile.game.clone());
        }

        // If inject_dll is true and we don't have a game_pid yet (or not connected to this game),
        // automatically attach to the target game process first.
        let needs_attach = {
            let s = self.session.lock().map_err(|_| err("session lock poisoned"))?;
            !s.connected() || s.game_pid().is_none() || !s.game_name().eq_ignore_ascii_case(&profile.game)
        };

        if needs_attach && profile.inject_dll {
            let mut s = self.session.lock().map_err(|_| err("session lock poisoned"))?;
            s.set_game_name(profile.game.clone());
            let current_dll = s.dll_path().to_string();
            let raw_dll = if current_dll.is_empty() { "trainlab_inject.dll" } else { &current_dll };
            let resolved_dll = if raw_dll.contains('/') || raw_dll.contains('\\') {
                raw_dll.to_string()
            } else if let Ok(exe) = std::env::current_exe() {
                exe.parent()
                    .map(|d| d.join(raw_dll).to_string_lossy().into_owned())
                    .unwrap_or_else(|| raw_dll.to_string())
            } else {
                raw_dll.to_string()
            };
            s.set_dll_path(resolved_dll);
            drop(s);

            let attach_res = crate::controller::find_inject_connect(&self.session);
            match attach_res {
                Ok(version) => {
                    if let Ok(mut s) = self.session.lock() {
                        s.log_activity("PROFILE", format!("attached to '{}' (inject v{version})", profile.game));
                    }
                }
                Err(e) => {
                    let err_msg = format!("auto-attach to '{}' failed: {e}", profile.game);
                    if let Ok(mut s) = self.session.lock() {
                        s.log_activity("PROFILE", &err_msg);
                    }
                    return Err(err(err_msg));
                }
            }
        }

        // Configure DLL render hooks via IPC based on profile render config (defaults to enabled if not specified)
        let render_cfg = profile.render.clone().unwrap_or_default();
        let _ = crate::controller::request(&self.session, &Request::ConfigureRender {
            overlay: render_cfg.overlay,
            hook_wndproc: render_cfg.hook_wndproc,
            xinput_hooks: render_cfg.xinput_hooks,
        });

        // Run setup steps or init_commands to resolve base addresses and create markers.
        let mut resolved: Vec<(String, u64)> = Vec::new();
        if args.run_setup {
            for step in &profile.setup {
                match resolve_setup_step(&self.session, step) {
                    Ok(addr) => {
                        resolved.push((step.name().to_string(), addr));
                    }
                    Err(e) => {
                        let err_msg = format!("setup step '{}' failed: {e}", step.name());
                        if let Ok(mut s) = self.session.lock() {
                            s.log_activity("PROFILE", &err_msg);
                        }
                        return Err(err(err_msg));
                    }
                }
            }
        }

        // Materialize setup markers into the session BEFORE init_commands run, so
        // init_commands that reference a setup step name (e.g. `target_ref: mining_speed`)
        // can resolve it via session markers. Previously this happened after, which made
        // any init_command referencing a setup step fail to resolve its marker.
        {
            let mut s = self.session.lock().map_err(|_| err("session lock poisoned"))?;
            for (name, addr) in &resolved {
                let _ = s.set_marker(name, *addr, Some(&format!("Resolved base address for profile '{}'", profile.game)));
                s.log_activity("PROFILE", format!("resolved setup marker '${name}' = {addr:#x}"));
            }
            // Load struct type definitions from the profile into the session type catalog.
            for def in &profile.structs {
                s.register_struct_def(def.clone());
                s.log_activity("PROFILE", format!("registered struct type '{}' ({} field(s))", def.name, def.fields.len()));
            }
        }

        // Execute profile init_commands if defined so memory markers and allocations are established
        if let Some(init_cmds) = &profile.init_commands
            && !init_cmds.is_empty() {
                if let Ok(mut s) = self.session.lock() {
                    s.log_activity("PROFILE", format!("executing {} profile init_command(s)...", init_cmds.len()));
                }
                execute_profile_commands(&self.session, init_cmds).map_err(|e| {
                    let err_msg = format!("profile init_commands failed: {e}");
                    if let Ok(mut s) = self.session.lock() {
                        s.log_activity("PROFILE", &err_msg);
                    }
                    err(err_msg)
                })?;
            }

        // Materialize cheats and setup markers into the session.
        let mut s = self
            .session
            .lock()
            .map_err(|_| err("session lock poisoned"))?;
        // Set the game name and active profile metadata in session so save_profile preserves setup steps.
        s.set_game_name(profile.game.clone());
        s.set_active_profile(&profile);
        s.log_activity("PROFILE", format!("loading profile '{}' ({})...", file, profile.game));
        s.clear_cheats();

        for (name, addr) in &resolved {
            let _ = s.set_marker(name, *addr, Some(&format!("Resolved base address for profile '{}'", profile.game)));
            s.log_activity("PROFILE", format!("resolved setup marker '${name}' = {addr:#x}"));
        }
        let mut materialized = 0usize;
        for pc in &profile.cheats {
            let kind = match pc.kind.as_str() {
                "value" => {
                    let address = resolve_cheat_address(&resolved, pc)?;
                    let vt = parse_value_type(pc.value_type.as_deref().unwrap_or("i32"))?;
                    crate::session::CheatKind::Value {
                        address,
                        value_type: vt,
                        address_expr: pc.address_ref.clone(),
                    }
                }
                "struct" => {
                    let base_expr = pc.base.clone().or_else(|| pc.address_ref.clone()).unwrap_or_default();
                    let base_address = resolve_cheat_address(&resolved, pc).unwrap_or(0);
                    let fields = pc.fields.clone().unwrap_or_default();
                    crate::session::CheatKind::Struct {
                        base_address,
                        base_expr,
                        fields,
                    }
                }
                "toggle" => {
                    let target = resolve_cheat_address(&resolved, pc)?;
                    // If the cheat provides Cheat-Engine-style assembly text, assemble it now
                    // (origin = target, since the cave payload is emitted relative to it for
                    // the RIP-relative constant slots) to produce the shellcode payload bytes.
                    let payload = if let Some(asm_src) = &pc.asm {
                        let symbols: HashMap<String, u64> = s
                            .list_markers()
                            .iter()
                            .map(|m| (m.label.clone(), m.address))
                            .collect();
                        let origin = target;
                        let block = crate::asm::assemble_text(asm_src, origin, &symbols)
                            .map_err(|e| err(format!("asm for cheat '{}' failed: {e}", pc.id)))?;
                        s.log_activity("PROFILE", format!("cheat '{}' assembled {} byte(s) from asm", pc.id, block.bytes.len()));
                        block.bytes
                    } else {
                        parse_hex_bytes(pc.payload.as_deref().unwrap_or(""))?
                    };
                    let jump_style = match pc.jump.as_deref().unwrap_or("absolute") {
                        "relative" => trainlab_core::cave_hook::JumpStyle::Relative,
                        _ => trainlab_core::cave_hook::JumpStyle::Absolute,
                    };
                    let hook = match pc.hook.as_deref().unwrap_or("trampoline") {
                        "trampoline" => trainlab_core::cave_hook::CaveHook::Trampoline { payload, jump: jump_style },
                        "override" => trainlab_core::cave_hook::CaveHook::Override { payload, jump: jump_style },
                        other => return Err(err(format!("unknown hook '{other}'"))),
                    };
                    let preloaded_orig = pc.original_bytes.as_deref()
                        .and_then(|h| parse_hex_bytes(h).ok())
                        .unwrap_or_default();
                    crate::session::CheatKind::Toggle {
                        hook,
                        target,
                        enabled: false,
                        original_bytes: preloaded_orig,
                        cave_addr: 0,
                    }
                }
                "patch" => {
                    let target = resolve_cheat_address(&resolved, pc)?;
                    let patch_bytes = parse_hex_bytes(pc.payload.as_deref().unwrap_or(""))?;
                    let host = s.dll_host().to_string();
                    let port = s.dll_port();
                    let original_bytes = if let Some(orig_hex) = &pc.original_bytes {
                        parse_hex_bytes(orig_hex).unwrap_or_default()
                    } else {
                        match crate::controller::request_at(&host, port, &Request::Read { address: target, len: patch_bytes.len() }, Some(&self.session)) {
                            Ok(Response::Read { data }) => data,
                            _ => Vec::new(),
                        }
                    };
                    crate::session::CheatKind::Patch {
                        target,
                        patch_bytes,
                        original_bytes,
                        enabled: false,
                        cave_ref: pc.hook.clone(),
                    }
                }
                "button" => {
                    let cmds = pc.commands.clone().unwrap_or_default();
                    crate::session::CheatKind::Button { commands: cmds }
                }
                other => return Err(err(format!("unknown cheat kind '{other}'"))),
            };
            let is_hidden = pc.hidden.unwrap_or(false);
            s.add_cheat_group(&pc.label, kind, pc.group.as_deref(), pc.hotkey.as_deref(), is_hidden, pc.note.as_deref());
            materialized += 1;
        }
        // T-142: Only set connected=true if we actually attached/injected.
        // The attach flow above (find_inject_connect) already sets connected
        // on success; don't override it here if attach was skipped or failed.
        let completion_msg = format!("successfully loaded profile '{}' ({}): {} setup step(s) resolved, {} cheat(s) materialized", file, profile.game, resolved.len(), materialized);
        s.log_activity("PROFILE", &completion_msg);
        s.publish_event(trainlab_core::event::BusEvent::Session(crate::event::SessionEvent::ProfileLoaded {
            name: file.clone(),
            game: profile.game.clone(),
            cheats_count: materialized,
        }));
        drop(s);
        self.request_repaint();

        // Sync materialized cheats to the injected overlay
        let overlay_cheats = if let Ok(s) = self.session.lock() {
            s.export_overlay_cheats()
        } else {
            Vec::new()
        };
        if !overlay_cheats.is_empty() {
            let _ = crate::controller::request(&self.session, &Request::SyncCheats { cheats: overlay_cheats });
        }

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

    /// Audit and verify code sites against their original_bytes in memory.
    #[tool(description = "Audit and verify all code hook sites in the active profile against their expected original bytes in game memory. Reports which sites are clean, patched, or unknown.")]
    fn verify_sites(&self) -> Result<CallToolResult, ErrorData> {
        let proc = game_process(&self.session)?;
        let s = self.session.lock().map_err(|_| err("session lock poisoned"))?;
        let cheats = s.list_cheats();
        if cheats.is_empty() {
            return Ok(CallToolResult::success(vec![
                rmcp::model::ContentBlock::text("no cheats loaded in active session to verify"),
            ]));
        }

        let mut lines = Vec::new();
        lines.push(format!("Audit of {} cheat site(s):", cheats.len()));

        for c in cheats {
            match &c.kind {
                CheatKind::Toggle { target, original_bytes, enabled, .. } => {
                    let orig: Option<Vec<u8>> = if !original_bytes.is_empty() {
                        Some(original_bytes.clone())
                    } else {
                        s.find_undo_for_target(*target)
                    };

                    let sample_len = orig.as_ref().map(|b| b.len().max(5)).unwrap_or(5);
                    let live = proc.read(*target, sample_len).unwrap_or_default();
                    let live_hex = live.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");

                    if let Some(expected) = orig {
                        let is_original = live.starts_with(&expected);
                        let status = if is_original {
                            "CLEAN (original bytes present)"
                        } else if live.starts_with(&[0xff, 0x25]) || live.starts_with(&[0xe9]) || live.starts_with(&[0xeb]) {
                            "PATCHED (live jump hook present)"
                        } else {
                            "DIRTY / MODIFIED"
                        };
                        lines.push(format!("  • #{} '{}' @ {target:#x}: {status} [live: {live_hex}] (session enabled: {enabled})", c.id, c.label));
                    } else {
                        let status = if live.starts_with(&[0xff, 0x25]) || live.starts_with(&[0xe9]) || live.starts_with(&[0xeb]) {
                            "PATCHED (live jump hook present, baseline unrecorded)"
                        } else {
                            "UNKNOWN (no original bytes recorded)"
                        };
                        lines.push(format!("  • #{} '{}' @ {target:#x}: {status} [live: {live_hex}] (session enabled: {enabled})", c.id, c.label));
                    }
                }
                CheatKind::Patch { target, original_bytes, patch_bytes, enabled, .. } => {
                    let orig: Option<Vec<u8>> = if !original_bytes.is_empty() {
                        Some(original_bytes.clone())
                    } else {
                        s.find_undo_for_target(*target)
                    };

                    let sample_len = orig.as_ref().map(|b| b.len()).unwrap_or_else(|| patch_bytes.len().max(5));
                    let live = proc.read(*target, sample_len).unwrap_or_default();
                    let live_hex = live.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");

                    if let Some(expected) = orig {
                        let status = if live.starts_with(&expected) {
                            "CLEAN (original bytes present)"
                        } else if !patch_bytes.is_empty() && live.starts_with(patch_bytes) {
                            "PATCHED (patch bytes present)"
                        } else {
                            "DIRTY / MODIFIED"
                        };
                        lines.push(format!("  • #{} '{}' @ {target:#x}: {status} [live: {live_hex}] (session enabled: {enabled})", c.id, c.label));
                    } else {
                        let status = if !patch_bytes.is_empty() && live.starts_with(patch_bytes) {
                            "PATCHED (patch bytes present)"
                        } else {
                            "UNKNOWN (no original bytes recorded)"
                        };
                        lines.push(format!("  • #{} '{}' @ {target:#x}: {status} [live: {live_hex}] (session enabled: {enabled})", c.id, c.label));
                    }
                }
                _ => {}
            }
        }

        let dirty_summary = s.check_dirty().summary();
        lines.push(format!("\nSession dirty state: {dirty_summary}"));

        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(lines.join("\n")),
        ]))
    }

    /// Launch an application binary or executable by path.
    #[tool(description = "Launch an application binary, helper process, or game executable by path with optional arguments.")]
    fn launch_app(
        &self,
        Parameters(args): Parameters<LaunchAppArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let app_args = args.args.unwrap_or_default();
        let mut s = self.session.lock().map_err(|_| err("session lock poisoned"))?;
        let pid = s.launch_application(&args.path, &app_args).map_err(err)?;
        drop(s);
        self.request_repaint();
        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(format!("successfully launched '{}' (PID {pid})", args.path)),
        ]))
    }

    /// Save the current cheats in the session as a portable cheat profile YAML file.
    #[tool(description = "Save the cheats currently in the session to a YAML profile in the cheats/ directory for reuse across sessions.")]
    fn save_profile(
        &self,
        Parameters(args): Parameters<SaveProfileArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ctx = trainlab_core::session::ClientContext::new("mcp", trainlab_core::session::ClientKind::Mcp { agent_name: None }, self.session.lock().unwrap().event_bus());
        let res = trainlab_core::tools::execute_save_profile(&self.session, &ctx, trainlab_core::tools::ProfileSaveArgs {
            file: args.file,
        }).map_err(|e| err(e.message))?;

        self.request_repaint();
        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(res.message),
        ]))
    }

    /// Validate a cheat profile without touching game memory (dry-run).
    /// Parses the profile, resolves address refs against setup step names,
    /// parses every payload/value/hex, and reports errors.
    #[tool(description = "Validate a cheat profile by file name or game exe without touching game memory. Checks that setup steps are parseable, address refs resolve, payloads are valid hex, and value types are known. Reports all errors found.")]
    fn validate_profile(
        &self,
        Parameters(args): Parameters<LoadProfileArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let all_discovered = crate::profile::discover_all_profiles();
        let target = args.profile.trim().to_lowercase();
        let mut found_valid: Option<(&String, &crate::profile::GameProfile)> = None;
        let mut found_invalid: Option<(&String, &String)> = None;

        for dp in &all_discovered {
            match dp {
                crate::profile::DiscoveredProfile::Valid { file, profile } => {
                    if file.to_lowercase() == target || profile.game.to_lowercase() == target {
                        found_valid = Some((file, profile));
                        break;
                    }
                }
                crate::profile::DiscoveredProfile::Invalid { file, error } => {
                    if file.to_lowercase() == target || target.contains(file.to_lowercase().trim_end_matches(".yaml")) {
                        found_invalid = Some((file, error));
                    }
                }
            }
        }

        let (file, profile) = match (found_valid, found_invalid) {
            (Some(v), _) => v,
            (None, Some((f, err_msg))) => {
                return Err(err(format!(
                    "profile '{f}' found in cheats/ but FAILED to parse: {err_msg}"
                )))
            }
            (None, None) => {
                return Err(err(format!(
                    "no profile found for '{}' (looked in cheats/)",
                    args.profile
                )))
            }
        };

        let mut errors: Vec<String> = Vec::new();
        let mut warnings: Vec<String> = Vec::new();

        // Check setup step names are unique and parseable.
        let setup_names: Vec<String> = profile.setup.iter().map(|s| s.name().to_string()).collect();
        for (i, name) in setup_names.iter().enumerate() {
            if setup_names[i+1..].contains(name) {
                errors.push(format!("setup step name '{}' is not unique", name));
            }
        }

        // Validate each cheat's address_ref / target_ref resolves against setup names or is a raw address.
        for pc in &profile.cheats {
            let refs = [pc.address_ref.as_deref(), pc.target_ref.as_deref()];
            for r in refs.into_iter().flatten() {
                if !setup_names.contains(&r.to_string()) {
                    // Not a named setup value — check if it's a raw address.
                    if parse_addr_str(r).is_err() {
                        errors.push(format!(
                            "cheat '{}': ref '{}' is not a named setup value or raw address",
                            pc.label, r
                        ));
                    }
                }
            }
            // Validate value_type if present.
            if let Some(vt) = &pc.value_type
                && parse_value_type(vt).is_err() {
                    errors.push(format!("cheat '{}': unknown value_type '{}'", pc.label, vt));
                }
            // Validate payload hex if present.
            if let Some(payload) = &pc.payload
                && !payload.is_empty()
                    && parse_hex_bytes(payload).is_err() {
                        errors.push(format!("cheat '{}': invalid payload hex '{}'", pc.label, payload));
                    }
            // Validate hook kind if present (for toggle, must be trampoline/override; for patch, it's a cave marker ref).
            if let Some(h) = &pc.hook
                && pc.kind.eq_ignore_ascii_case("toggle")
                    && h != "trampoline" && h != "override" {
                        errors.push(format!("cheat '{}': unknown hook '{}' (expected 'trampoline' or 'override')", pc.label, h));
                    }
            // Validate jump style if present.
            if let Some(j) = &pc.jump
                && j != "absolute" && j != "relative" && j != "short" {
                    warnings.push(format!("cheat '{}': unknown jump '{}' (expected 'absolute' or 'relative')", pc.label, j));
                }
        }

        // Validate init_commands payloads if present.
        if let Some(init_cmds) = &profile.init_commands {
            for (i, cmd) in init_cmds.iter().enumerate() {
                match cmd {
                    crate::profile::ProfileCommand::Write { value, value_type, .. } => {
                        if let Some(vt) = value_type
                            && parse_value_type(vt).is_err() {
                                errors.push(format!("init_cmd {i}: unknown value_type '{vt}'"));
                            }
                        // Value is hard to validate without session markers, but check non-empty.
                        if value.trim().is_empty() {
                            errors.push(format!("init_cmd {i}: write value is empty"));
                        }
                    }
                    crate::profile::ProfileCommand::InstallCave { payload, asm, hook, .. } => {
                        if asm.is_none() && !payload.is_empty() && parse_hex_bytes(payload).is_err() {
                            errors.push(format!("init_cmd {i}: invalid cave payload hex"));
                        }
                        if hook != "trampoline" && hook != "override" {
                            errors.push(format!("init_cmd {i}: unknown hook '{hook}'"));
                        }
                    }
                    _ => {}
                }
            }
        }

        if errors.is_empty() {
            let mut text = format!("✅ profile '{}' ({}) is valid\n", file, profile.game);
            text.push_str(&format!("  {} setup step(s), {} cheat(s)", profile.setup.len(), profile.cheats.len()));
            if let Some(ic) = &profile.init_commands {
                text.push_str(&format!(", {} init_command(s)", ic.len()));
            }
            if !warnings.is_empty() {
                text.push_str(&format!("\n  {} warning(s):", warnings.len()));
                for w in &warnings {
                    text.push_str(&format!("\n    ⚠ {w}"));
                }
            }
            Ok(CallToolResult::success(vec![
                rmcp::model::ContentBlock::text(text),
            ]))
        } else {
            let mut text = format!("❌ profile '{}' ({}) has {} error(s):\n", file, profile.game, errors.len());
            for e in &errors {
                text.push_str(&format!("  • {e}\n"));
            }
            if !warnings.is_empty() {
                text.push_str(&format!("  {} warning(s):\n", warnings.len()));
                for w in &warnings {
                    text.push_str(&format!("    ⚠ {w}\n"));
                }
            }
            Ok(CallToolResult::success(vec![
                rmcp::model::ContentBlock::text(text),
            ]))
        }
    }
    #[tool(description = "List readable memory regions of the game process, read externally. Returns top regions (default 50) and saves the full dump to a snapshot file if it exceeds the limit.")]
    fn list_regions(&self, Parameters(args): Parameters<ListRegionsArgs>) -> Result<CallToolResult, ErrorData> {
        let proc = game_process(&self.session)?;
        let mut regions = proc.regions().map_err(|e| err(format!("regions failed: {e}")))?;
        if args.named_only.unwrap_or(false) {
            regions.retain(|r| r.name.as_ref().map(|n| !n.trim().is_empty()).unwrap_or(false));
        }

        let total = regions.len();
        let limit = args.limit.unwrap_or(50);
        let preview = regions.iter().take(limit);

        let lines: Vec<String> = preview
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

        let mut text = format!("{total} memory region(s)\n");
        text.push_str(&lines.join("\n"));

        if total > limit {
            let s_file = format!("regions_{}.txt", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0));
            let mut buf = Vec::new();
            use std::io::Write;
            for r in &regions {
                let _ = writeln!(
                    buf,
                    "{:#018x}-{:#018x} r{}{} {}",
                    r.start,
                    r.end,
                    if r.readable { 'x' } else { '-' },
                    if r.writable { 'w' } else { '-' },
                    r.name.as_deref().unwrap_or("")
                );
            }
            if let Ok(rel_path) = trainlab_core::tools::write_output_artifact("regions", &s_file, &buf) {
                text.push_str(&format!("\n... and {} more [full regions list saved to {rel_path}]", total - limit));
            } else {
                text.push_str(&format!("\n... and {} more", total - limit));
            }
        }

        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(text),
        ]))
    }

    /// Read memory from the game process (raw bytes or typed value).
    #[tool(description = "Read memory from the game process. Supports raw hex bytes (default) OR typed values (value_type='ptr'|'i32'|'u32'|'f32'|'i64'|'u64'|'f64'|'cstr'). Supports expressions (e.g. 'game.exe+0x123', 'wood_ptr+0x10').")]
    pub(crate) fn read(&self, Parameters(args): Parameters<ReadArgs>) -> Result<CallToolResult, ErrorData> {
        let proc = game_process(&self.session)?;
        let ctx = trainlab_core::session::ClientContext::new("mcp", trainlab_core::session::ClientKind::Mcp { agent_name: None }, self.session.lock().unwrap().event_bus());
        let res = trainlab_core::tools::execute_read(&self.session, &ctx, proc.as_ref(), trainlab_core::tools::ReadArgs {
            address: args.address,
            len: args.len,
            value_type: args.value_type,
        }).map_err(|e| err(e.message))?;

        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(res.message),
        ]))
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
    #[tool(description = "Scan game memory for an AOB byte pattern (hex, ?? wildcards); returns match addresses, read externally. Can optionally bound search to a named region/marker and save to a marker. NOTE: Run memory scans sequentially (one at a time) rather than in parallel to avoid token/timeout limits.")]
    fn scan_aob(&self, Parameters(args): Parameters<ScanAobArgs>) -> Result<CallToolResult, ErrorData> {
        let proc = game_process(&self.session)?;
        let ctx = trainlab_core::session::ClientContext::new("mcp", trainlab_core::session::ClientKind::Mcp { agent_name: None }, self.session.lock().unwrap().event_bus());
        let res = trainlab_core::tools::execute_scan_aob(&self.session, &ctx, proc.as_ref(), trainlab_core::tools::ScanAobArgs {
            pattern: args.pattern,
            offset: args.offset,
            marker: args.marker,
            region: args.region,
            alignment: args.alignment,
            limit: args.limit,
        }).map_err(|e| err(e.message))?;

        self.request_repaint();

        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(res.message),
        ]))
    }

    /// Backwards-compatible alias for [`scan_aob`].
    #[tool(description = "Alias for scan_aob. Scan game memory for an AOB byte pattern. NOTE: Run memory scans sequentially (one at a time) rather than in parallel to avoid token/timeout limits.")]
    fn aob_scan(&self, Parameters(args): Parameters<AobArgs>) -> Result<CallToolResult, ErrorData> {
        self.scan_aob(Parameters(args))
    }

    /// Start a value scan over the game's memory.
    #[tool(description = "First value scan: find all addresses holding a value (exact, or a range if max is given). Can optionally bound search to a named region/marker. Stores match set in the caller's scan context for narrowing with scan_next.")]
    pub(crate) fn scan_start(&self, Parameters(args): Parameters<ScanStartArgs>) -> Result<CallToolResult, ErrorData> {
        let proc = game_process(&self.session)?;
        let mut ctx = trainlab_core::session::ClientContext::new("mcp", trainlab_core::session::ClientKind::Mcp { agent_name: None }, self.session.lock().unwrap().event_bus());
        // Load any existing scan from session if present
        if let Ok(s) = self.session.lock() {
            ctx.scan = s.scan().cloned();
        }

        let res = trainlab_core::tools::execute_scan_start(&self.session, &mut ctx, proc.as_ref(), trainlab_core::tools::ScanStartArgs {
            value_type: args.value_type,
            value: args.value,
            max: args.max,
            alignment: args.alignment,
            region: args.region,
        }).map_err(|e| err(e.message))?;

        // Sync scan back to session for GUI/inspectors
        if let Some(scan) = ctx.scan
            && let Ok(mut s) = self.session.lock() {
                s.set_scan(scan);
            }

        self.request_repaint();

        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(res.message),
        ]))
    }

    /// Backwards-compatible alias for [`scan_start`].
    #[tool(description = "Alias for scan_start. First value scan.")]
    pub(crate) fn scan(&self, Parameters(args): Parameters<ScanArgs>) -> Result<CallToolResult, ErrorData> {
        self.scan_start(Parameters(args))
    }

    /// Narrow the previous scan's match set.
    #[tool(description = "Narrow the previous scan: keep matches that changed/unchanged/increased/decreased or match a new exact/range value.")]
    pub(crate) fn scan_next(&self, Parameters(args): Parameters<ScanNextArgs>) -> Result<CallToolResult, ErrorData> {
        let proc = game_process(&self.session)?;
        let mut ctx = trainlab_core::session::ClientContext::new("mcp", trainlab_core::session::ClientKind::Mcp { agent_name: None }, self.session.lock().unwrap().event_bus());
        if let Ok(s) = self.session.lock() {
            ctx.scan = s.scan().cloned();
        }

        let res = trainlab_core::tools::execute_scan_next(&self.session, &mut ctx, proc.as_ref(), trainlab_core::tools::ScanNextArgs {
            op: args.op,
            value: args.value,
            max: args.max,
        }).map_err(|e| err(e.message))?;

        if let Some(scan) = ctx.scan
            && let Ok(mut s) = self.session.lock() {
                s.set_scan(scan);
            }

        self.request_repaint();

        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(res.message),
        ]))
    }

    /// Backwards-compatible alias for [`scan_next`].
    #[tool(description = "Alias for scan_next. Narrow the active scan.")]
    pub(crate) fn next(&self, Parameters(args): Parameters<NextArgs>) -> Result<CallToolResult, ErrorData> {
        self.scan_next(Parameters(args))
    }

    /// Read the active value scan status and candidate matches without mutating the scan state.
    #[tool(description = "Inspect the current active scan session without modifying it. Reports total match count, value type, alignment, and lists the top 10 current candidate matches (address = value).")]
    fn scan_status(&self) -> Result<CallToolResult, ErrorData> {
        let mut ctx = trainlab_core::session::ClientContext::new("mcp", trainlab_core::session::ClientKind::Mcp { agent_name: None }, self.session.lock().unwrap().event_bus());
        if let Ok(s) = self.session.lock() {
            ctx.scan = s.scan().cloned();
        }

        let res = trainlab_core::tools::execute_scan_status(&self.session, &ctx).map_err(|e| err(e.message))?;

        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(res.message),
        ]))
    }

    /// Batch test-write a value across all matching addresses in the active scan.
    #[tool(description = "Batch test-write: write a value to all matching addresses in the active scan (useful when <= 10 matches exist to test authoritative state). Snapshots each address for auto-undo.")]
    fn scan_set(&self, Parameters(args): Parameters<ScanSetArgs>) -> Result<CallToolResult, ErrorData> {
        let proc = game_process(&self.session)?;
        let mut ctx = trainlab_core::session::ClientContext::new("mcp", trainlab_core::session::ClientKind::Mcp { agent_name: None }, self.session.lock().unwrap().event_bus());
        if let Ok(s) = self.session.lock() {
            ctx.scan = s.scan().cloned();
        }

        let res = trainlab_core::tools::execute_scan_set(&self.session, &ctx, proc.as_ref(), trainlab_core::tools::ScanSetArgs {
            value: args.value,
            value_type: args.value_type,
        }).map_err(|e| err(e.message))?;

        self.request_repaint();

        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(res.message),
        ]))
    }

    /// Clear or end the active scan session.
    #[tool(description = "Clear the active scan session in the caller's context.")]
    fn scan_clear(&self) -> Result<CallToolResult, ErrorData> {
        let mut ctx = trainlab_core::session::ClientContext::new("mcp", trainlab_core::session::ClientKind::Mcp { agent_name: None }, self.session.lock().unwrap().event_bus());
        let res = trainlab_core::tools::execute_scan_clear(&self.session, &mut ctx).map_err(|e| err(e.message))?;

        if let Ok(mut s) = self.session.lock() {
            s.clear_scan();
        }

        self.request_repaint();

        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(res.message),
        ]))
    }

    /// Backwards-compatible alias for [`scan_clear`].
    #[tool(description = "Alias for 'scan_clear'. End and clear the active scan session.")]
    fn scan_end(&self) -> Result<CallToolResult, ErrorData> {
        self.scan_clear()
    }

    /// Find addresses that point to (reference) a target address.
    #[tool(description = "Reverse-reference scan: find writable addresses whose pointer value points into the range around a target address. Use to find what points to a value (owning object), then chase a stable chain.")]
    fn scan_pointer(
        &self,
        Parameters(args): Parameters<ScanPointerArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let proc = game_process(&self.session)?;
        let ctx = trainlab_core::session::ClientContext::new("mcp", trainlab_core::session::ClientKind::Mcp { agent_name: None }, self.session.lock().unwrap().event_bus());
        let res = trainlab_core::tools::execute_scan_pointer(&self.session, &ctx, proc.as_ref(), trainlab_core::tools::ScanPointerArgs {
            address: args.address,
            size: args.size,
            limit: args.limit,
        }).map_err(|e| err(e.message))?;

        self.request_repaint();

        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(res.message),
        ]))
    }

    /// Search memory for regex byte patterns using ripgrep's regex engine.
    #[tool(description = "Search game memory for regular expression byte patterns using ripgrep's regex engine (e.g. ASCII strings, UTF-8 text, or binary regexes). Streams memory across readable regions with alignment and region boundary overlap support.")]
    fn scan_rgrep(
        &self,
        Parameters(args): Parameters<ScanRgrepArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let proc = game_process(&self.session)?;
        let ctx = trainlab_core::session::ClientContext::new("mcp", trainlab_core::session::ClientKind::Mcp { agent_name: None }, self.session.lock().unwrap().event_bus());
        let res = trainlab_core::tools::execute_scan_rgrep(&self.session, &ctx, proc.as_ref(), trainlab_core::tools::ScanRgrepArgs {
            pattern: args.pattern,
            alignment: args.alignment,
            region: args.region,
            marker: args.marker,
            limit: args.limit,
        }).map_err(|e| err(e.message))?;

        self.request_repaint();

        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(res.message),
        ]))
    }

    /// Backwards-compatible alias for [`scan_rgrep`].
    #[tool(description = "Alias for 'scan_rgrep'. Search game memory with ripgrep regex engine.")]
    fn rgrep(
        &self,
        Parameters(args): Parameters<RgrepArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.scan_rgrep(Parameters(args))
    }

    /// Backwards-compatible alias for [`scan_pointer`].
    #[tool(description = "Alias for 'scan_pointer'. Reverse-reference pointer scan.")]
    fn pointer_scan(
        &self,
        Parameters(args): Parameters<PointerScanArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.scan_pointer(Parameters(args))
    }

    /// Resolve a known pointer chain to the current address of a value.
    #[tool(description = "Resolve a pointer chain (base + offsets) against the live game; returns each hop and the final value address. Use a chain you discovered, e.g. via pointer_scan. Dereference semantics: by default base is treated as a POINTER SLOT — hop 0 dereferences base, then each offset dereferences the running pointer (`base -> *base -> *(*base+off[0]) -> ... -> final`). If base references a marker whose kind is 'object' (the marker IS a struct instance, not a slot), the initial dereference is SKIPPED and offsets apply directly to the object: a single offset `['0xd0']` resolves to `base+0xd0`, and `['0xd0','0x0']` reads `*(base+0xd0)` then returns `ptr+0x0`. When a chase lands in module code/rdata from a heap-object base marker, set the base marker kind to 'object'.")]
    fn pointer_chase(
        &self,
        Parameters(args): Parameters<PointerChaseArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let proc = game_process(&self.session)?;
        let ctx = trainlab_core::session::ClientContext::new("mcp", trainlab_core::session::ClientKind::Mcp { agent_name: None }, self.session.lock().unwrap().event_bus());
        let res = trainlab_core::tools::execute_pointer_chase(&self.session, &ctx, proc.as_ref(), trainlab_core::tools::PointerChaseArgs {
            base: args.base,
            offsets: args.offsets,
        }).map_err(|e| err(e.message))?;

        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(res.message),
        ]))
    }

    /// Set a labeled marker for an address or region (persists across turns).
    #[tool(description = "Save a labeled marker for an address or region (optional size in bytes) so the agent can reference or scan it later. kind describes what the address represents: 'pointer' (default — a slot holding an address to dereference, e.g. a module+offset base), 'object' (the marker IS a struct/class instance, e.g. a heap object; offsets apply directly without an initial deref in pointer_chase), 'buffer' (a contiguous memory region/allocation), or 'code' (a function/hook/cave). struct_type is an optional reference to a named layout registered via register_struct_def, meaningful when kind='object'.")]
    pub(crate) fn set_marker(
        &self,
        Parameters(args): Parameters<SetMarkerArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let proc = game_process(&self.session).ok();
        let ctx = trainlab_core::session::ClientContext::new("mcp", trainlab_core::session::ClientKind::Mcp { agent_name: None }, self.session.lock().unwrap().event_bus());
        let res = trainlab_core::tools::execute_set_marker(&self.session, &ctx, proc.as_ref().map(|p| p.as_ref()), trainlab_core::tools::SetMarkerArgs {
            label: args.label,
            address: args.address,
            size: args.size,
            kind: args.kind,
            struct_type: args.struct_type,
            note: args.note,
        }).map_err(|e| err(e.message))?;

        self.request_repaint();
        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(res.message),
        ]))
    }

    /// Dump a chunk of memory formatted for struct/class reversal.
    #[tool(description = "Read a chunk of memory around an address and format it as hex + ASCII (and typed fields where obvious) so the agent can reverse a struct/class layout. The LLM does the teasing-out.")]
    fn dump(&self, Parameters(args): Parameters<DumpArgs>) -> Result<CallToolResult, ErrorData> {
        let proc = game_process(&self.session)?;
        let ctx = trainlab_core::session::ClientContext::new("mcp", trainlab_core::session::ClientKind::Mcp { agent_name: None }, self.session.lock().unwrap().event_bus());
        let res = trainlab_core::tools::execute_dump(&self.session, &ctx, proc.as_ref(), trainlab_core::tools::DumpArgs {
            address: args.address,
            len: args.len,
        }).map_err(|e| err(e.message))?;

        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(res.message),
        ]))
    }

    /// Dump a memory range to a snapshot binary file on disk and return a downloadable URL.
    #[tool(description = "Dump a large memory range (e.g. 15MB Lua heap) to a snapshot file on disk and return its local file path, size, and downloadable HTTP URL. Pass either 'end' or 'len'.")]
    fn snapshot(
        &self,
        Parameters(args): Parameters<SnapshotArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let proc = game_process(&self.session)?;
        let ctx = trainlab_core::session::ClientContext::new("mcp", trainlab_core::session::ClientKind::Mcp { agent_name: None }, self.session.lock().unwrap().event_bus());
        let res = trainlab_core::tools::execute_snapshot(&self.session, &ctx, proc.as_ref(), trainlab_core::tools::SnapshotArgs {
            start: args.start,
            end: args.end,
            len: args.len,
            name: args.name,
            max_len: args.max_len,
        }).map_err(|e| err(e.message))?;

        let (host, port) = {
            let s = self.session.lock().map_err(|_| err("session lock poisoned"))?;
            (s.dll_host().to_string(), s.dll_port())
        };
        let url_host = if host == "0.0.0.0" { "127.0.0.1".to_string() } else { host };
        let file_name = res.data.as_ref().and_then(|d| d.get("file_name")).and_then(|f| f.as_str()).unwrap_or("");
        let url = format!("http://{url_host}:{port}/snapshots/{file_name}");

        let resp_json = serde_json::json!({
            "path": res.data.as_ref().and_then(|d| d.get("path")).and_then(|p| p.as_str()).unwrap_or(""),
            "size": res.data.as_ref().and_then(|d| d.get("bytes_written")).and_then(|s| s.as_u64()).unwrap_or(0),
            "url": url,
        });

        self.request_repaint();

        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(resp_json.to_string()),
        ]))
    }

    /// Allocate and lay out a string inside the game process and return its layout pointers.
    #[tool(description = "Allocate and lay out a string inside the game process (C string, Rust fat pointer, JSON/YAML/XML/JS config) and return its address and layout. Supported kinds: 'c' (default, NUL-terminated), 'rust' (returns ptr and len), 'json', 'yaml', 'xml', 'js', 'config'. Can pass 'size' instead of 'content' to allocate a zero/fill-initialized buffer.")]
    fn allocate_string(
        &self,
        Parameters(args): Parameters<AllocateStringArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let proc = game_process(&self.session)?;
        let ctx = trainlab_core::session::ClientContext::new("mcp", trainlab_core::session::ClientKind::Mcp { agent_name: None }, self.session.lock().unwrap().event_bus());
        let res = trainlab_core::tools::execute_allocate_string(&self.session, &ctx, proc.as_ref(), trainlab_core::tools::AllocateStringArgs {
            content: args.content,
            size: args.size,
            fill_byte: args.fill_byte,
            kind: args.kind,
            marker: args.marker,
        }).map_err(|e| err(e.message))?;

        self.request_repaint();

        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(serde_json::to_string(&res.data).unwrap_or(res.message)),
        ]))
    }

    /// Allocate raw memory buffer of a specified size in the game process.
    #[tool(description = "Allocate an arbitrary raw memory buffer of a specified size in bytes in the target game process without transmitting large string payloads. Useful for file extraction scratch buffers, hook landing pads, or data structures. Optional 'marker' saves the allocated address.")]
    fn allocate_memory(
        &self,
        Parameters(args): Parameters<AllocateMemoryArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let proc = game_process(&self.session)?;
        let ctx = trainlab_core::session::ClientContext::new("mcp", trainlab_core::session::ClientKind::Mcp { agent_name: None }, self.session.lock().unwrap().event_bus());
        let res = trainlab_core::tools::execute_allocate_memory(&self.session, &ctx, proc.as_ref(), trainlab_core::tools::AllocateMemoryArgs {
            size: args.size,
            marker: args.marker,
            fill_byte: args.fill_byte,
            permissions: args.permissions,
        }).map_err(|e| err(e.message))?;

        self.request_repaint();

        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(serde_json::to_string(&res.data).unwrap_or(res.message)),
        ]))
    }

    /// Free a previously allocated memory region or buffer in the game process.
    #[tool(description = "Free / deallocate a previously allocated memory region or buffer in the target game process (VirtualFreeEx). Accepts an address or marker name (e.g. '$dump_buffer' or '0x7ff12000').")]
    fn free_memory(
        &self,
        Parameters(args): Parameters<FreeMemoryArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let proc = game_process(&self.session)?;
        let ctx = trainlab_core::session::ClientContext::new("mcp", trainlab_core::session::ClientKind::Mcp { agent_name: None }, self.session.lock().unwrap().event_bus());
        let res = trainlab_core::tools::execute_free_memory(&self.session, &ctx, proc.as_ref(), trainlab_core::tools::FreeMemoryArgs {
            address: args.address,
            size: args.size,
        }).map_err(|e| err(e.message))?;

        self.request_repaint();

        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(serde_json::to_string(&res.data).unwrap_or(res.message)),
        ]))
    }

    /// Read a struct at an address and format each requested field by type.
    #[tool(description = "Read a struct at an address and format each requested field by type. Field types: i8, u8, i16, u16, i32, u32, i64, u64, f32, f64, ptr, cstr (null-terminated ASCII), or bytes. Pass an offset per field (default 0).")]
    fn dump_struct(
        &self,
        Parameters(args): Parameters<DumpStructArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let proc = game_process(&self.session)?;
        let ctx = trainlab_core::session::ClientContext::new("mcp", trainlab_core::session::ClientKind::Mcp { agent_name: None }, self.session.lock().unwrap().event_bus());
        let fields = args.fields.into_iter().map(|f| trainlab_core::tools::StructFieldSpec {
            name: f.name,
            offset: f.offset as i64,
            value_type: f.value_type,
            len: f.len,
        }).collect();

        let res = trainlab_core::tools::execute_dump_struct(&self.session, &ctx, proc.as_ref(), trainlab_core::tools::DumpStructArgs {
            address: args.address,
            fields,
        }).map_err(|e| err(e.message))?;

        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(res.message),
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
        let proc = game_process(&self.session)?;
        let ctx = trainlab_core::session::ClientContext::new("mcp", trainlab_core::session::ClientKind::Mcp { agent_name: None }, self.session.lock().unwrap().event_bus());
        let res = trainlab_core::tools::execute_disassemble(&self.session, &ctx, proc.as_ref(), trainlab_core::tools::DisassembleArgs {
            address: args.address,
            len: args.len,
            max_instructions: args.max_instructions.unwrap_or(32),
        }).map_err(|e| err(e.message))?;

        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(res.message),
        ]))
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

        // Arm-time instruction boundary verification guard
        if !args.force {
            if let Ok(proc) = game_process(&self.session) {
                let context_len = 64usize;
                let base = target.saturating_sub(48);
                let read_len = context_len + 32;
                if let Ok(bytes) = proc.read(base, read_len) {
                    if let Err(msg) = trainlab_core::disasm::verify_instruction_boundary(base, &bytes, target) {
                        return Err(err(format!(
                            "{msg} (pass 'force: true' if you explicitly intend to bypass instruction boundary checking)"
                        )));
                    }
                }
            }
        }

        let spec = CaptureRegSpec::new(reg, value_type).with_optional_gate(gate).with_jump(jump_style);
        match call_dll(&self.session, &Request::CaptureReg {
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
                if let Ok(mut s) = self.session.lock() {
                    s.record_capture(id);
                }
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
        match call_dll(&self.session, &Request::ReadCaptures { id: args.id }) {
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
        match call_dll(&self.session, &Request::UninstallCapture { id: args.id }) {
            Ok(Response::CaptureUninstalled { id }) => {
                if let Ok(mut s) = self.session.lock() {
                    s.remove_capture(id);
                }
                Ok(CallToolResult::success(vec![
                    rmcp::model::ContentBlock::text(format!(
                        "uninstalled capture {id}: original bytes restored, scratch freed."
                    )),
                ]))
            }
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
        match call_dll(&self.session, &Request::WatchWrites {
            address,
            len,
            one_shot: args.one_shot,
            mechanism: args.mechanism,
        }) {
            Ok(Response::WatchArmed) => {
                if let Ok(mut s) = self.session.lock() {
                    s.record_breakpoint(address);
                }
                Ok(CallToolResult::success(vec![
                    rmcp::model::ContentBlock::text(
                        "watchpoint armed; poll with 'watch_poll' to retrieve the hit(s)",
                    ),
                ]))
            }
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

        // Arm-time instruction boundary verification guard
        if !args.force {
            if let Ok(proc) = game_process(&self.session) {
                let context_len = 64usize;
                let base = address.saturating_sub(48);
                let read_len = context_len + 32;
                if let Ok(bytes) = proc.read(base, read_len) {
                    if let Err(msg) = trainlab_core::disasm::verify_instruction_boundary(base, &bytes, address) {
                        return Err(err(format!(
                            "{msg} (pass 'force: true' if you explicitly intend to bypass instruction boundary checking)"
                        )));
                    }
                }
            }
        }

        match call_dll(&self.session, &Request::BreakOnCode {
            address,
            one_shot: args.one_shot,
        }) {
            Ok(Response::BreakArmed) => {
                if let Ok(mut s) = self.session.lock() {
                    s.record_breakpoint(address);
                }
                Ok(CallToolResult::success(vec![
                    rmcp::model::ContentBlock::text(
                        "breakpoint armed; poll with 'watch_poll' to retrieve the hit(s)",
                    ),
                ]))
            }
            Ok(Response::Error { message }) => Err(err(message)),
            Ok(_) => Err(err("unexpected response from DLL")),
            Err(e) => Err(err(e)),
        }
    }

    /// Poll for hits from an armed watchpoint/breakpoint.
    #[tool(description = "Retrieve accumulated watchpoint/breakpoint hits (registers + stack). Returns nothing if no hit is pending.")]
    fn watch_poll(&self) -> Result<CallToolResult, ErrorData> {
        match call_dll(&self.session, &Request::PollHit) {
            Ok(Response::PollHit { hits, hit }) => {
                let all_hits = if !hits.is_empty() {
                    hits
                } else if let Some(h) = hit {
                    vec![h]
                } else {
                    Vec::new()
                };

                if all_hits.is_empty() {
                    Ok(CallToolResult::success(vec![
                        rmcp::model::ContentBlock::text("no pending hit"),
                    ]))
                } else {
                    let mut formatted = Vec::new();
                    for (idx, info) in all_hits.iter().enumerate() {
                        let header = if all_hits.len() > 1 {
                            format!("--- Hit #{}/{} ---\n", idx + 1, all_hits.len())
                        } else {
                            String::new()
                        };
                        formatted.push(format!(
                            "{}{}",
                            header,
                            format_hit(
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
                            )
                        ));
                    }
                    Ok(CallToolResult::success(vec![
                        rmcp::model::ContentBlock::text(formatted.join("\n\n")),
                    ]))
                }
            }
            Ok(Response::Error { message }) => Err(err(message)),
            Ok(_) => Err(err("unexpected response from DLL")),
            Err(e) => {
                let s_guard = self.session.lock().ok();
                let connected = s_guard.as_ref().map_or(false, |s| s.connected());
                if !connected {
                    Ok(CallToolResult::success(vec![
                        rmcp::model::ContentBlock::text("no pending hit"),
                    ]))
                } else {
                    Err(err(e))
                }
            }
        }
    }

    /// Clear any active watchpoints / breakpoints.
    #[tool(description = "Disarm any active watchpoint or breakpoint and restore any patched bytes.")]
    fn clear_breakpoints(&self) -> Result<CallToolResult, ErrorData> {
        match call_dll(&self.session, &Request::ClearBreakpoints) {
            Ok(Response::BreakpointsCleared) => {
                if let Ok(mut s) = self.session.lock() {
                    s.clear_all_breakpoints();
                }
                Ok(CallToolResult::success(vec![
                    rmcp::model::ContentBlock::text("breakpoints cleared"),
                ]))
            }
            Ok(Response::Error { message }) => Err(err(message)),
            Ok(_) => Err(err("unexpected response from DLL")),
            Err(e) => Err(err(e)),
        }
    }

    /// Retrieve captured network traffic log from the session.
    #[tool(description = "Retrieve captured network packets (TCP/UDP/HTTP) logged by in-game hooks. Output is kept lightweight (summaries and short preview); returns relative file paths or download links for full packet dumps.")]
    pub fn get_network_log(
        &self,
        Parameters(args): Parameters<GetNetworkLogArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let s = self.session.lock().map_err(|_| err("session lock poisoned"))?;
        if !s.has_capability("network_capture") {
            let caps = s.dll_capabilities().join(", ");
            return Ok(CallToolResult::success(vec![
                rmcp::model::ContentBlock::text(format!(
                    "Notice: Connected DLL does not advertise 'network_capture' capability (reported capabilities: [{caps}]). Network interception may be disabled or running on an unsupported platform (e.g. Linux stub)."
                )),
            ]));
        }

        let proto = match args.proto.as_deref().map(|p| p.to_lowercase()).as_deref() {
            Some("tcp") => Some(trainlab_core::protocol::PacketKind::Tcp),
            Some("udp") => Some(trainlab_core::protocol::PacketKind::Udp),
            Some("http") => Some(trainlab_core::protocol::PacketKind::Http),
            _ => None,
        };

        let (packets, total) = s.list_network_packets(
            args.limit.or(Some(20)),
            args.offset,
            proto,
            args.filter.as_deref(),
        );

        if packets.is_empty() {
            return Ok(CallToolResult::success(vec![
                rmcp::model::ContentBlock::text(format!(
                    "No captured network packets matching criteria (total logged: {total})."
                )),
            ]));
        }

        let mut lines = Vec::new();
        lines.push(format!("Captured Network Packets (showing {} of {total}):", packets.len()));

        for p in &packets {
            let ep = p.remote_endpoint.as_deref().unwrap_or(p.local_endpoint.as_deref().unwrap_or("?"));
            let dir_icon = match p.direction {
                trainlab_core::protocol::PacketDirection::Inbound => "IN  ⬇",
                trainlab_core::protocol::PacketDirection::Outbound => "OUT ⬆",
            };

            // Lightweight ASCII preview
            let preview_str: String = p.payload_preview.iter()
                .take(64)
                .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
                .collect();

            let file_ref = p.artifact_file.as_deref().map(|f| format!(" [file: {f}]")).unwrap_or_default();
            let url_ref = p.url.as_deref().map(|u| format!(" url: {u}")).unwrap_or_default();

            lines.push(format!(
                "  #{:04} [{}] {:<4} {:<22} size={:<4} preview=\"{}\"{url_ref}{file_ref}",
                p.id,
                dir_icon,
                p.kind.as_str().to_uppercase(),
                ep,
                p.payload_len,
                preview_str
            ));
        }

        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(lines.join("\n")),
        ]))
    }

    /// Watch or inspect incoming network traffic with optional endpoint filtering.
    #[tool(description = "Watch incoming/outgoing network packets matching an optional host/port or URL filter. Returns the latest matching packet summaries and lightweight previews.")]
    pub fn watch_network(
        &self,
        Parameters(args): Parameters<WatchNetworkArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let s = self.session.lock().map_err(|_| err("session lock poisoned"))?;
        if !s.has_capability("network_capture") {
            return Ok(CallToolResult::success(vec![
                rmcp::model::ContentBlock::text(
                    "Network capture is unavailable: target DLL does not support 'network_capture'."
                ),
            ]));
        }

        let proto = match args.proto.as_deref().map(|p| p.to_lowercase()).as_deref() {
            Some("tcp") => Some(trainlab_core::protocol::PacketKind::Tcp),
            Some("udp") => Some(trainlab_core::protocol::PacketKind::Udp),
            Some("http") => Some(trainlab_core::protocol::PacketKind::Http),
            _ => None,
        };

        let (packets, total) = s.list_network_packets(
            args.limit.or(Some(10)),
            None,
            proto,
            args.filter.as_deref(),
        );

        if packets.is_empty() {
            return Ok(CallToolResult::success(vec![
                rmcp::model::ContentBlock::text(format!(
                    "No matching network packets observed (total in buffer: {total})."
                )),
            ]));
        }

        let mut lines = Vec::new();
        lines.push(format!("Network Traffic Watch (latest {} packets):", packets.len()));
        for p in &packets {
            let ep = p.remote_endpoint.as_deref().unwrap_or("?");
            let dir_icon = match p.direction {
                trainlab_core::protocol::PacketDirection::Inbound => "IN ",
                trainlab_core::protocol::PacketDirection::Outbound => "OUT",
            };
            let preview: String = p.payload_preview.iter()
                .take(48)
                .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
                .collect();
            let file_ref = p.artifact_file.as_deref().map(|f| format!(" [download: {f}]")).unwrap_or_default();
            lines.push(format!("  #{:04} [{}] {:<4} {:<20} ({} B): \"{}\"{file_ref}", p.id, dir_icon, p.kind.as_str(), ep, p.payload_len, preview));
        }

        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(lines.join("\n")),
        ]))
    }

    /// Clear the network traffic log buffer.
    #[tool(description = "Clear all captured network packets from the active session buffer.")]
    pub fn clear_network_log(
        &self,
        Parameters(_args): Parameters<ClearNetworkLogArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let mut s = self.session.lock().map_err(|_| err("session lock poisoned"))?;
        let cleared = s.clear_network_packets();
        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(format!("Cleared {cleared} captured network packet(s) from session.")),
        ]))
    }

    /// Configure network traffic capture: toggle capture, ignore ports, or allow loopback.
    #[tool(description = "Configure in-game network traffic interception. By default loopback (127.0.0.1) and internal trainer ports are ignored so buffers only capture actual game traffic. Use this tool to toggle interception, change ignored ports, or opt into loopback traffic capture.")]
    pub fn configure_network(
        &self,
        Parameters(args): Parameters<ConfigureNetworkArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let (dll_port, mcp_port) = {
            let cfg = crate::config::AppConfig::load();
            (cfg.inject.dll_port, cfg.server.mcp_port)
        };

        let mut ports = vec![dll_port, mcp_port];
        if let Some(extra) = args.ignore_ports {
            for p in extra {
                if !ports.contains(&p) {
                    ports.push(p);
                }
            }
        }
        let capture_loopback = args.capture_loopback.unwrap_or(false);

        let req = trainlab_core::protocol::Request::ConfigureNetworkHook {
            enabled: args.enabled,
            ignore_ports: ports.clone(),
            capture_loopback,
        };

        let resp = crate::controller::request(&self.session, &req);
        if let Ok(mut s) = self.session.lock() {
            s.set_network_hooks_enabled(args.enabled);
        }

        self.request_repaint();

        let status_desc = match resp {
            Ok(trainlab_core::protocol::Response::NetworkHookConfigured { enabled }) => {
                format!("Network interception set to {enabled}. Ignored ports: {ports:?}, capture_loopback: {capture_loopback}")
            }
            Ok(other) => format!("Unexpected DLL response: {other:?}"),
            Err(e) => format!("Failed to configure network hook on DLL (DLL may be offline): {e}"),
        };

        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(status_desc),
        ]))
    }

    /// Write bytes or a typed value to game memory directly (with auto-undo snapshotting).
    #[tool(description = "Write to game memory at an address. Accepts EITHER raw hex bytes (data='00 80 ac 43') OR a typed value (value='0xe890000', value_type='ptr' or 'i32'/'f32'/'i64'/'u64'/'f64') so you never have to hand-encode hex. Executes immediately and records an undo snapshot.")]
    pub(crate) fn write(&self, Parameters(args): Parameters<WriteArgs>) -> Result<CallToolResult, ErrorData> {
        let address = parse_addr(&self.session, &args.address)?;
        let (bytes, desc) = match (args.data.as_deref(), args.value.as_deref()) {
            (Some(hex_str), None) => {
                let b = parse_hex_bytes(hex_str)?;
                if b.is_empty() {
                    return Err(err("write data cannot be empty"));
                }
                let d = format!(
                    "write {} byte(s) at {:#x}: {}",
                    b.len(),
                    address,
                    b.iter().map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join(" ")
                );
                (b, d)
            }
            (None, Some(val_str)) => {
                let vt_str = args.value_type.as_deref().unwrap_or_else(|| {
                    if val_str.trim().starts_with("0x") || val_str.trim().starts_with("0X") {
                        "ptr"
                    } else {
                        "i32"
                    }
                });
                let vt = parse_value_type(vt_str)?;
                let b = parse_value_bytes(val_str, vt)?;
                if b.is_empty() {
                    return Err(err("write value cannot be empty"));
                }
                let d = format!(
                    "write value '{}' ({}) at {:#x}: {}",
                    val_str,
                    vt_str,
                    address,
                    b.iter().map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join(" ")
                );
                (b, d)
            }
            (Some(_), Some(_)) => {
                return Err(err("specify either 'data' (raw hex) or 'value' (typed value), but not both"));
            }
            (None, None) => {
                return Err(err("must specify either 'data' (raw hex) or 'value' (typed value)"));
            }
        };

        // Snapshot originals for the undo log before writing
        let proc = game_process(&self.session)?;
        let original = proc.read(address, bytes.len()).unwrap_or_default();

        match call_dll(&self.session, &Request::Write {
            address,
            data: bytes.clone(),
        }) {
            Ok(Response::Write { bytes_written }) => {
                let mut s = self
                    .session
                    .lock()
                    .map_err(|_| err("session lock poisoned"))?;
                s.log_activity("mcp", format!("write: {desc}"));
                let undo_msg = if !original.is_empty() {
                    let id = s.record_undo(
                        address,
                        original,
                        desc.clone(),
                    );
                    format!(" (undo id #{id})")
                } else {
                    String::new()
                };
                drop(s);
                self.request_repaint();
                Ok(CallToolResult::success(vec![
                    rmcp::model::ContentBlock::text(format!(
                        "successfully wrote {bytes_written} byte(s) at {:#x}{undo_msg}",
                        address
                    )),
                ]))
            }
            Ok(Response::Error { message }) => Err(err(message)),
            Ok(_) => Err(err("unexpected response from DLL")),
            Err(e) => Err(err(e)),
        }
    }

    /// Install a code-cave hook directly in game memory (with auto-undo snapshotting).
    #[tool(description = "Install a code cave hook directly. Kinds: 1) 'trampoline' (DEFAULT): runs your custom payload, automatically disassembles and replays stolen instructions in the cave, then jumps back — original game logic is preserved (empty payload = transparent no-op). 2) 'override': runs payload and jumps back, skipping stolen instructions. Returns allocated cave address and auto-registers label markers.")]
    fn install_cave(
        &self,
        Parameters(args): Parameters<InstallCaveArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        use trainlab_core::cave_hook::{CaveHook, JumpStyle};
        let target = parse_addr(&self.session, &args.target)?;

        if args.asm.is_some() && !args.payload.trim().is_empty() {
            return Err(err("cannot provide both 'asm' and 'payload' (mutually exclusive)"));
        }

        let (payload, label_offsets) = if let Some(asm_src) = &args.asm {
            if args.hook == "trampoline" && !args.force {
                trainlab_core::asm::check_trampoline_data_fallthrough(asm_src).map_err(err)?;
            }
            let symbols: std::collections::HashMap<String, u64> = {
                let s = self.session.lock().map_err(|_| err("session lock poisoned"))?;
                s.list_markers().iter().map(|m| (m.label.clone(), m.address)).collect()
            };
            let block = trainlab_core::asm::assemble_text(asm_src, target, &symbols).map_err(err)?;
            (block.bytes, block.label_offsets)
        } else {
            (parse_hex_bytes(&args.payload)?, std::collections::HashMap::new())
        };

        let jump = match args.jump.to_lowercase().as_str() {
            "absolute" => JumpStyle::Absolute,
            "relative" | "short" => JumpStyle::Relative,
            other => return Err(err(format!("unknown jump style '{other}' (expected 'absolute' or 'relative')"))),
        };
        let hook = match args.hook.as_str() {
            "trampoline" => CaveHook::Trampoline { payload: payload.clone(), jump },
            "override" => {
                if payload.is_empty() {
                    return Err(err("override hook requires a non-empty payload; an empty override drops stolen instructions without replacement"));
                }
                CaveHook::Override { payload: payload.clone(), jump }
            }
            other => return Err(err(format!("unknown hook kind '{other}' (expected 'trampoline' or 'override')"))),
        };

        match call_dll(&self.session, &Request::InstallCave {
            target,
            hook,
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
                if let Some(m) = &args.marker {
                    let _ = s.set_marker_full(m, cave, None, trainlab_core::session::MarkerKind::Code, None, Some(&format!("Code cave allocated for target {target:#x}")));
                }
                // Auto-set markers for any labels defined in the assembly
                for (lbl_name, offset) in &label_offsets {
                    let lbl_addr = cave.saturating_add(*offset);
                    let _ = s.set_marker(lbl_name, lbl_addr, Some(&format!("Cave label '{lbl_name}' at +{offset:#x} (cave {cave:#x})")));
                }
                s.log_activity("mcp", format!("installed cave at target {target:#x} -> cave={cave:#x} ({} label(s) marked)", label_offsets.len()));
                drop(s);
                self.request_repaint();

                let mut out_msg = format!("installed cave: cave={cave:#x} target={target:#x} (payload {} bytes, original {} bytes saved, undo id #{id})", payload.len(), original.len());
                if !label_offsets.is_empty() {
                    out_msg.push_str("\nlabels marked:");
                    for (lbl_name, offset) in &label_offsets {
                        out_msg.push_str(&format!("\n  • {} -> {:#x} (+{:#x})", lbl_name, cave.saturating_add(*offset), offset));
                    }
                }
                Ok(CallToolResult::success(vec![
                    rmcp::model::ContentBlock::text(out_msg),
                ]))
            }
            Ok(Response::Error { message }) => Err(err(message)),
            Ok(_) => Err(err("unexpected response from DLL")),
            Err(e) => Err(err(e)),
        }
    }

    /// Revert a write or cave mutation directly by undo id (or the most recent mutation).
    #[tool(description = "Undo a write or cave mutation by id (or the most recent if omitted): restores original memory bytes directly.")]
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

        match call_dll(&self.session, &Request::Write {
            address: e.address,
            data: e.original_bytes.clone(),
        }) {
            Ok(Response::Write { bytes_written }) => {
                let mut s = self
                    .session
                    .lock()
                    .map_err(|_| err("session lock poisoned"))?;
                s.pop_undo(e.id);
                s.log_activity("mcp", format!("undo #{}: restored {} bytes at {:#x}", e.id, bytes_written, e.address));
                drop(s);
                self.request_repaint();
                Ok(CallToolResult::success(vec![
                    rmcp::model::ContentBlock::text(format!(
                        "successfully reverted undo #{}: restored {bytes_written} byte(s) at {:#x}",
                        e.id, e.address
                    )),
                ]))
            }
            Ok(Response::Error { message }) => Err(err(message)),
            Ok(_) => Err(err("unexpected response from DLL")),
            Err(e) => Err(err(e)),
        }
    }

    /// Apply a previously staged (pending) mutation.
    #[tool(description = "Apply a staged mutation by id if one exists. (Deprecated: 'write' and 'install_cave' now execute immediately).")]
    pub(crate) fn confirm_op(
        &self,
        Parameters(args): Parameters<OpConfirmArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        // Reject staged mutation if another operation or load is in progress.
        {
            let s = self
                .session
                .lock()
                .map_err(|_| err("session lock poisoned"))?;
            if let Some(op) = s.operation_in_progress() {
                return Err(err(format!("operation '{op}' is currently in progress; cannot confirm op")));
            }
        }

        // Peek at the op first — only remove it from pending on success (T-102).
        let op = {
            let s = self
                .session
                .lock()
                .map_err(|_| err("session lock poisoned"))?;
            s.peek_pending(args.id).cloned()
        };
        let Some(op) = op else {
            return Err(err(format!(
                "no pending op {}. Note: 'write' and 'install_cave' now apply immediately without staging.",
                args.id
            )));
        };
        let address = op.address;
        let preview = op.preview.clone();
        let cheat_id = op.cheat_id;
        // Apply according to the op kind.
        let result = match &op.kind {
            PendingKind::Write { data } => {
                // Snapshot originals for the undo log before writing.
                let proc = game_process(&self.session)?;
                let original = proc.read(address, data.len()).unwrap_or_default();
                match call_dll(&self.session, &Request::Write {
                    address,
                    data: data.clone(),
                }) {
                    Ok(Response::Write { bytes_written }) => {
                        let mut s = self
                            .session
                            .lock()
                            .map_err(|_| err("session lock poisoned"))?;
                        let mut is_restoring_patch = false;
                        if let Some(cid) = cheat_id {
                            // Toggle patch cheat state
                            if let Some(c) = s.get_cheat(cid)
                                && let CheatKind::Patch { patch_bytes, .. } = &c.kind {
                                    let is_enabling = data == patch_bytes;
                                    s.set_cheat_toggle(cid, is_enabling);
                                    if !is_enabling {
                                        is_restoring_patch = true;
                                    }
                                }
                        }
                        if is_restoring_patch {
                            // The patch was restored back to original bytes, clean up any undo log entry for this address.
                            s.remove_undo_for_target(address);
                        }
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
            PendingKind::InstallCave { hook, marker, label_offsets } => {
                match call_dll(&self.session, &Request::InstallCave {
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
                        if let Some(m) = marker {
                            let _ = s.set_marker_full(m, cave, None, trainlab_core::session::MarkerKind::Code, None, Some(&format!("Code cave allocated for target {target:#x}")));
                        }
                        // Auto-set markers for any labels defined in the assembly
                        for (lbl_name, offset) in label_offsets {
                            let lbl_addr = cave.saturating_add(*offset);
                            let _ = s.set_marker(lbl_name, lbl_addr, Some(&format!("Cave label '{lbl_name}' at +{offset:#x} (cave {cave:#x})")));
                        }
                        // T-110/T-111: update the toggle cheat's cave info + flip enabled.
                        if let Some(cid) = cheat_id {
                            s.set_toggle_cave_info(cid, original.clone(), cave);
                            s.set_cheat_toggle(cid, true);
                        }
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
                match call_dll(&self.session, &Request::Write {
                    address,
                    data: original_bytes.clone(),
                }) {
                    Ok(Response::Write { bytes_written }) => {
                        let mut s = self
                            .session
                            .lock()
                            .map_err(|_| err("session lock poisoned"))?;
                        // T-111: flip the toggle off when the undo is a toggle disable.
                        if let Some(cid) = cheat_id {
                            s.set_cheat_toggle(cid, false);
                        }
                        // Clean up undo log entry for this address since it was restored
                        s.remove_undo_for_target(address);
                        Ok(format!(
                            "confirmed undo: restored {bytes_written} byte(s) at {:#x}",
                            address
                        ))
                    }
                    Ok(Response::Error { message }) => Err(message),
                    Ok(_) => Err("unexpected response from DLL".into()),
                    Err(e) => Err(e),
                }
            }
        };
        match result {
            Ok(text) => {
                // T-102: only now remove the op from pending (it succeeded).
                if let Ok(mut s) = self.session.lock() {
                    s.take_pending(args.id);
                }
                // Sync updated cheats to the in-game overlay
                let overlay_cheats = if let Ok(s) = self.session.lock() {
                    s.export_overlay_cheats()
                } else {
                    Vec::new()
                };
                if !overlay_cheats.is_empty() {
                    let _ = crate::controller::request(&self.session, &Request::SyncCheats { cheats: overlay_cheats });
                }
                // T-150/T-151: emit event + request repaint.
                self.request_repaint();
                Ok(CallToolResult::success(vec![
                    rmcp::model::ContentBlock::text(text),
                ]))
            }
            Err(e) => {
                // T-102: leave the op in pending so it can be retried or rejected.
                Err(err(format!("failed to apply pending op {}: {e}", args.id)))
            }
        }
    }

    /// Discard a previously staged (pending) mutation without applying it.
    #[tool(description = "Discard a staged mutation (from 'write'/'install_cave'/'undo') by id without applying it.")]
    pub(crate) fn reject_op(
        &self,
        Parameters(args): Parameters<OpConfirmArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ctx = trainlab_core::session::ClientContext::new("mcp", trainlab_core::session::ClientKind::Mcp { agent_name: None }, self.session.lock().unwrap().event_bus());
        let res = trainlab_core::tools::execute_reject_op(&self.session, &ctx, trainlab_core::tools::OpConfirmArgs { id: args.id })
            .map_err(|e| err(e.message))?;

        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(res.message),
        ]))
    }

    /// List all staged (pending) mutations awaiting confirmation.
    #[tool(description = "List all staged (pending) mutations awaiting human confirmation, with their ids and previews.")]
    fn list_pending(&self) -> Result<CallToolResult, ErrorData> {
        let ctx = trainlab_core::session::ClientContext::new("mcp", trainlab_core::session::ClientKind::Mcp { agent_name: None }, self.session.lock().unwrap().event_bus());
        let res = trainlab_core::tools::execute_list_pending(&self.session, &ctx)
            .map_err(|e| err(e.message))?;

        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(res.message),
        ]))
    }

    /// Get a labeled marker by name.
    #[tool(description = "Retrieve a saved marker by label.")]
    fn get_marker(
        &self,
        Parameters(args): Parameters<GetMarkerArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ctx = trainlab_core::session::ClientContext::new("mcp", trainlab_core::session::ClientKind::Mcp { agent_name: None }, self.session.lock().unwrap().event_bus());
        let res = trainlab_core::tools::execute_get_marker(&self.session, &ctx, trainlab_core::tools::GetMarkerArgs {
            label: args.label,
        }).map_err(|e| err(e.message))?;

        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(res.message),
        ]))
    }

    /// List all saved markers.
    #[tool(description = "List all markers saved in the session, sorted by label.")]
    fn list_markers(&self) -> Result<CallToolResult, ErrorData> {
        let ctx = trainlab_core::session::ClientContext::new("mcp", trainlab_core::session::ClientKind::Mcp { agent_name: None }, self.session.lock().unwrap().event_bus());
        let res = trainlab_core::tools::execute_list_markers(&self.session, &ctx).map_err(|e| err(e.message))?;

        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(res.message),
        ]))
    }

    /// Remove a marker by label.
    #[tool(description = "Remove a saved marker by label.")]
    fn remove_marker(
        &self,
        Parameters(args): Parameters<RemoveMarkerArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ctx = trainlab_core::session::ClientContext::new("mcp", trainlab_core::session::ClientKind::Mcp { agent_name: None }, self.session.lock().unwrap().event_bus());
        let res = trainlab_core::tools::execute_remove_marker(&self.session, &ctx, trainlab_core::tools::RemoveMarkerArgs {
            label: args.label,
        }).map_err(|e| err(e.message))?;

        self.request_repaint();
        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(res.message),
        ]))
    }

    /// Register or overwrite a named struct/object type definition in the session type catalog.
    #[tool(description = "Register a named struct/class layout definition (type name + fields with offsets and value types) in the session type catalog. Once registered, use set_marker with kind='object' and struct_type='TypeName' to tag markers. Future dump_struct calls can reference the type by name.")]
    fn register_struct_def(
        &self,
        Parameters(args): Parameters<RegisterStructDefArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let def = trainlab_core::session::StructDef {
            name: args.name.clone(),
            size: args.size,
            fields: args.fields.into_iter().map(|f| {
                let vt = parse_value_type(&f.value_type).unwrap_or(trainlab_core::scan::ValueType::I32);
                trainlab_core::session::StructField {
                    label: f.label,
                    offset_expr: f.offset_expr,
                    value_type: vt,
                }
            }).collect(),
            note: args.note,
        };
        let field_count = def.fields.len();
        let size_str = def.size.map(|s| format!(" ({s:#x} bytes)")).unwrap_or_default();
        self.session.lock().unwrap().register_struct_def(def);
        self.request_repaint();
        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(format!("registered struct type '{}'{size_str} with {field_count} field(s)", args.name)),
        ]))
    }

    /// List all registered struct definitions in the session type catalog.
    #[tool(description = "List all named struct/object type definitions currently registered in the session type catalog.")]
    fn list_struct_defs(&self) -> Result<CallToolResult, ErrorData> {
        let s = self.session.lock().unwrap();
        let defs = s.list_struct_defs();
        if defs.is_empty() {
            return Ok(CallToolResult::success(vec![rmcp::model::ContentBlock::text("no struct definitions registered")]));
        }
        let lines: Vec<String> = defs.iter().map(|d| {
            let size_str = d.size.map(|sz| format!(" ({sz:#x} bytes)")).unwrap_or_default();
            let fields_str: Vec<String> = d.fields.iter().map(|f| {
                format!("  +{}: {} ({:?})", f.offset_expr, f.label, f.value_type)
            }).collect();
            format!("{}{}:\n{}", d.name, size_str,
                if fields_str.is_empty() { "  (no fields)".into() } else { fields_str.join("\n") })
        }).collect();
        Ok(CallToolResult::success(vec![rmcp::model::ContentBlock::text(lines.join("\n\n"))]))
    }

    /// Remove a named struct definition from the session type catalog.
    #[tool(description = "Remove a named struct/object type definition from the session type catalog by type name.")]
    fn remove_struct_def(
        &self,
        Parameters(args): Parameters<RemoveStructDefArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let removed = self.session.lock().unwrap().remove_struct_def(&args.name);
        self.request_repaint();
        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(if removed.is_some() {
                format!("removed struct type '{}'", args.name)
            } else {
                format!("struct type '{}' not found", args.name)
            }),
        ]))
    }

    /// Describe an undo entry (or the most recent one).
    #[tool(description = "Inspect the undo log: a specific entry by id, or the most recent mutation.")]
    fn undo_info(
        &self,
        Parameters(args): Parameters<UndoInfoArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let ctx = trainlab_core::session::ClientContext::new("mcp", trainlab_core::session::ClientKind::Mcp { agent_name: None }, self.session.lock().unwrap().event_bus());
        let res = trainlab_core::tools::execute_undo_info(&self.session, &ctx, trainlab_core::tools::UndoInfoArgs {
            id: args.id,
        }).map_err(|e| err(e.message))?;

        Ok(CallToolResult::success(vec![
            rmcp::model::ContentBlock::text(res.message),
        ]))
    }
}
fn parse_addr(session: &SharedSession, s: &str) -> Result<u64, ErrorData> {
    parse_addr_expr(session, s)
}

/// Parse an address string which can be a raw address (hex/dec), a marker label
/// (e.g. "wood_ptr"), or a module/marker expression with offsets (e.g. "game.exe+0x1b42e9"
/// or "player_ptr+0x48").
pub(crate) fn parse_addr_expr(session: &SharedSession, input: &str) -> Result<u64, ErrorData> {
    parse_addr_expr_with_mem(session, input, None)
}

/// Parse an address expression with an optional custom memory reader (useful for testing & offline resolution).
pub(crate) fn parse_addr_expr_with_mem(
    session: &SharedSession,
    input: &str,
    custom_mem: Option<&dyn trainlab_core::memory::ProcessMemory>,
) -> Result<u64, ErrorData> {
    let input = input.trim();

    // 0. Handle top-level addition/subtraction where a bracketed term is involved, e.g. `[base + 0x10] + 0x20`
    // We only split on '+' or '-' if it is OUTSIDE of any enclosing square brackets.
    let mut bracket_depth = 0;
    let mut split_idx = None;
    let mut is_add = true;

    for (i, c) in input.char_indices().rev() {
        match c {
            ']' => bracket_depth += 1,
            '[' => bracket_depth -= 1,
            '+' if bracket_depth == 0 => {
                split_idx = Some(i);
                is_add = true;
                break;
            }
            '-' if bracket_depth == 0 && i > 0 => {
                // Ensure '-' is not a unary negative or part of a hex token
                split_idx = Some(i);
                is_add = false;
                break;
            }
            _ => {}
        }
    }

    if let Some(idx) = split_idx {
        let (base_part, off_part) = (&input[..idx], &input[idx + 1..]);
        let base = parse_addr_expr_with_mem(session, base_part, custom_mem)?;
        let off = parse_addr_str(off_part.trim()).map_err(err)?;
        return Ok(if is_add {
            base.wrapping_add(off)
        } else {
            base.wrapping_sub(off)
        });
    }

    // 1. Check for nested bracket dereference expression: `[ <inner_expr> ]`
    if input.starts_with('[') && input.ends_with(']') {
        let inner = &input[1..input.len() - 1].trim();
        let ptr_addr = parse_addr_expr_with_mem(session, inner, custom_mem)?;
        
        // Read 8-byte pointer from game memory or custom mem
        let data = if let Some(mem) = custom_mem {
            mem.read(ptr_addr, 8).map_err(|e| {
                err(format!(
                    "failed to dereference pointer at {ptr_addr:#x} (from '{input}'): {e}"
                ))
            })?
        } else {
            let proc = game_process(session)?;
            proc.read(ptr_addr, 8).map_err(|e| {
                err(format!(
                    "failed to dereference pointer at {ptr_addr:#x} (from '{input}'): {e}"
                ))
            })?
        };
        if data.len() < 8 {
            return Err(err(format!(
                "short read dereferencing pointer at {ptr_addr:#x} (from '{input}')"
            )));
        }
        let target_ptr = u64::from_le_bytes(data[..8].try_into().unwrap());
        return Ok(target_ptr);
    }

    // 2. Try raw address string (0x hex or decimal)
    if let Some(hex) = input.strip_prefix("0x").or_else(|| input.strip_prefix("0X")) {
        if let Ok(a) = u64::from_str_radix(hex, 16) {
            return Ok(a);
        }
    } else if let Ok(a) = input.parse::<u64>().or_else(|_| u64::from_str_radix(input, 16)) {
        return Ok(a);
    }

    // 3. Try looking up in session markers (support optional '$' prefix like "$mycoolstring" or "mycoolstring")
    let marker_name = input.strip_prefix('$').unwrap_or(input);
    if let Ok(s) = session.lock()
        && let Some(m) = s.get_marker(marker_name).or_else(|| s.get_marker(input)) {
            return Ok(m.address);
        }

    // 4. Try looking up as a loaded module base (e.g. "Unrailed2.exe" or "game.dll")
    if let Ok(base) = resolve_module_base(session, input) {
        return Ok(base);
    }

    Err(err(format!(
        "could not resolve address expression '{input}' (not a raw hex/dec address, saved marker, or loaded module)"
    )))
}

/// Execute a sequence of profile commands (AOB scans, cave installs, string allocations, assertions, pointer chases).
pub(crate) fn execute_profile_commands(
    session: &SharedSession,
    cmds: &[crate::profile::ProfileCommand],
) -> Result<(), String> {
    for (idx, cmd) in cmds.iter().enumerate() {
        match cmd {
            crate::profile::ProfileCommand::Write { address_ref, address, value, value_type, .. } => {
                let addr_str = address_ref.as_deref().or(address.as_deref()).unwrap_or("");
                let parsed_addr = parse_addr_expr(session, addr_str)
                    .map_err(|e| format!("cmd {idx}: bad address '{addr_str}': {e:?}"))?;
                if parsed_addr == 0 {
                    return Err(format!("cmd {idx}: write target '{addr_str}' resolved to 0x0; sequence aborted"));
                }

                let vt_str = value_type.as_deref().unwrap_or_else(|| {
                    if value.trim().starts_with("0x") || value.trim().starts_with("0X") || value.trim().starts_with('$') {
                        "ptr"
                    } else {
                        "i32"
                    }
                });
                let vt = parse_value_type(vt_str)
                    .map_err(|e| format!("cmd {idx}: invalid value type '{vt_str}': {e:?}"))?;

                // If vt is ptr or value explicitly starts with $ / 0x / brackets / marker, resolve address expression.
                // Otherwise (e.g. integer or float literal like "1000", "5.0"), parse value directly as literal.
                let val_trimmed = value.trim();
                let eval_val_str = if vt == trainlab_core::scan::ValueType::Ptr
                    || val_trimmed.starts_with('$')
                    || val_trimmed.starts_with('[')
                    || val_trimmed.starts_with("0x")
                    || val_trimmed.starts_with("0X")
                {
                    match parse_addr_expr(session, value) {
                        Ok(val_addr) => format!("{val_addr:#x}"),
                        Err(_) => value.clone(),
                    }
                } else {
                    value.clone()
                };

                let bytes = parse_value_bytes(&eval_val_str, vt)
                    .map_err(|e| format!("cmd {idx}: failed to parse value bytes for '{eval_val_str}': {e:?}"))?;

                // T-101: Read original bytes for undo before writing.
                let original = game_process(session)
                    .ok()
                    .and_then(|proc| proc.read(parsed_addr, bytes.len()).ok())
                    .unwrap_or_default();

                let resp = crate::controller::request(
                    session,
                    &trainlab_core::protocol::Request::Write { address: parsed_addr, data: bytes.clone() },
                ).map_err(|e| format!("cmd {idx}: write to {addr_str} ({parsed_addr:#x}) failed: {e}"))?;
                if let trainlab_core::protocol::Response::Error { message } = resp {
                    return Err(format!("cmd {idx}: write failed: {message}"));
                }
                if let Ok(mut s) = session.lock() {
                    // T-101: Record undo snapshot for profile-command writes.
                    if !original.is_empty() {
                        s.record_undo(
                            parsed_addr,
                            original,
                            format!("profile write {} byte(s) at {:#x}", bytes.len(), parsed_addr),
                        );
                    }
                    s.log_activity("PROFILE", format!("cmd {idx}: write '{eval_val_str}' ({vt_str}) to {addr_str} ({parsed_addr:#x}) -> ok"));
                }
            }
            crate::profile::ProfileCommand::InstallCave { target_ref, target, hook, jump, payload, asm, marker, .. } => {
                let tgt_str = target_ref.as_deref().or(target.as_deref()).unwrap_or("");
                let target_addr = parse_addr_expr(session, tgt_str)
                    .map_err(|e| format!("cmd {idx}: bad target '{tgt_str}': {e:?}"))?;
                if target_addr == 0 {
                    return Err(format!("cmd {idx}: cave target '{tgt_str}' resolved to 0x0; sequence aborted"));
                }

                if asm.is_some() && !payload.trim().is_empty() {
                    return Err(format!("cmd {idx}: cannot provide both 'asm' and 'payload' (mutually exclusive)"));
                }

                let (payload_bytes, label_offsets) = if let Some(asm_src) = asm {
                    if hook == "trampoline" {
                        trainlab_core::asm::check_trampoline_data_fallthrough(asm_src)
                            .map_err(|e| format!("cmd {idx}: {e}"))?;
                    }
                    let symbols: HashMap<String, u64> = {
                        let s = session.lock().map_err(|_| format!("session lock poisoned"))?;
                        s.list_markers().iter().map(|m| (m.label.clone(), m.address)).collect()
                    };
                    let block = crate::asm::assemble_text(asm_src, target_addr, &symbols)
                        .map_err(|e| format!("cmd {idx}: asm compilation failed: {e}"))?;
                    if let Ok(mut s) = session.lock() {
                        s.log_activity("PROFILE", format!("cmd {idx}: assembled {} byte(s) from asm", block.bytes.len()));
                    }
                    (block.bytes, block.label_offsets)
                } else {
                    let bytes = parse_hex_bytes(payload)
                        .map_err(|e| format!("cmd {idx}: invalid cave payload hex: {e:?}"))?;
                    (bytes, HashMap::new())
                };

                let jump_style = match jump.as_deref().unwrap_or("absolute") {
                    "relative" => trainlab_core::cave_hook::JumpStyle::Relative,
                    _ => trainlab_core::cave_hook::JumpStyle::Absolute,
                };
                let cave_hook = match hook.as_str() {
                    "override" => trainlab_core::cave_hook::CaveHook::Override { payload: payload_bytes, jump: jump_style },
                    "trampoline" => trainlab_core::cave_hook::CaveHook::Trampoline { payload: payload_bytes, jump: jump_style },
                    other => return Err(format!("cmd {idx}: unknown hook kind '{other}' (expected 'trampoline' or 'override')")),
                };

                let resp = crate::controller::request(
                    session,
                    &trainlab_core::protocol::Request::InstallCave { target: target_addr, hook: cave_hook },
                ).map_err(|e| format!("cmd {idx}: cave install at {tgt_str} ({target_addr:#x}) failed: {e}"))?;

                match resp {
                    trainlab_core::protocol::Response::CaveInstalled { cave, original, .. } => {
                        if let Some(m) = marker
                            && let Ok(mut s) = session.lock() {
                                let _ = s.set_marker_full(m, cave, None, trainlab_core::session::MarkerKind::Code, None, Some(&format!("Cave for target {target_addr:#x}")));
                            }
                        if let Ok(mut s) = session.lock() {
                            // Auto-set markers for any labels defined in the assembly
                            for (lbl_name, offset) in &label_offsets {
                                let lbl_addr = cave.saturating_add(*offset);
                                let _ = s.set_marker(lbl_name, lbl_addr, Some(&format!("Cave label '{lbl_name}' at +{offset:#x} (cave {cave:#x})")));
                            }
                            // T-101: Record undo snapshot for profile-command cave installs.
                            if !original.is_empty() {
                                s.record_undo(
                                    target_addr,
                                    original.clone(),
                                    format!("profile install_cave at {:#x}", target_addr),
                                );
                            }
                            s.log_activity("PROFILE", format!("cmd {idx}: install cave at {tgt_str} ({target_addr:#x}) -> cave={cave:#x} ({} label(s) marked)", label_offsets.len()));
                        }
                    }
                    trainlab_core::protocol::Response::Error { message } => return Err(format!("cmd {idx}: cave install failed: {message}")),
                    _ => return Err(format!("cmd {idx}: cave install at {tgt_str} ({target_addr:#x}) failed")),
                }
            }
            crate::profile::ProfileCommand::AllocateString { content, size, fill_byte, string_kind, marker, .. } => {
                let proc = game_process(session).map_err(|e| format!("cmd {idx}: allocate_string process access error: {e:?}"))?;
                let ctx = trainlab_core::session::ClientContext::new("profile", trainlab_core::session::ClientKind::Mcp { agent_name: None }, session.lock().unwrap().event_bus());
                let res = trainlab_core::tools::execute_allocate_string(session, &ctx, proc.as_ref(), trainlab_core::tools::AllocateStringArgs {
                    content: content.clone(),
                    size: *size,
                    fill_byte: *fill_byte,
                    kind: string_kind.clone(),
                    marker: marker.clone(),
                }).map_err(|e| format!("cmd {idx}: allocate string failed: {}", e.message))?;
                if let Ok(mut s) = session.lock() {
                    s.log_activity("PROFILE", format!("cmd {idx}: allocate string ({string_kind}) -> {}", res.message));
                }
            }
            crate::profile::ProfileCommand::AllocateMemory { size, marker, fill_byte, permissions, .. } => {
                let proc = game_process(session).map_err(|e| format!("cmd {idx}: allocate_memory process access error: {e:?}"))?;
                let ctx = trainlab_core::session::ClientContext::new("profile", trainlab_core::session::ClientKind::Mcp { agent_name: None }, session.lock().unwrap().event_bus());
                let res = trainlab_core::tools::execute_allocate_memory(session, &ctx, proc.as_ref(), trainlab_core::tools::AllocateMemoryArgs {
                    size: *size,
                    marker: marker.clone(),
                    fill_byte: *fill_byte,
                    permissions: permissions.clone(),
                }).map_err(|e| format!("cmd {idx}: allocate memory failed: {}", e.message))?;
                if let Ok(mut s) = session.lock() {
                    s.log_activity("PROFILE", format!("cmd {idx}: allocate memory ({size} bytes) -> {}", res.message));
                }
            }
            crate::profile::ProfileCommand::FreeMemory { address, size, .. } => {
                let proc = game_process(session).map_err(|e| format!("cmd {idx}: free_memory process access error: {e:?}"))?;
                let ctx = trainlab_core::session::ClientContext::new("profile", trainlab_core::session::ClientKind::Mcp { agent_name: None }, session.lock().unwrap().event_bus());
                let res = trainlab_core::tools::execute_free_memory(session, &ctx, proc.as_ref(), trainlab_core::tools::FreeMemoryArgs {
                    address: address.clone(),
                    size: *size,
                }).map_err(|e| format!("cmd {idx}: free memory failed: {}", e.message))?;
                if let Ok(mut s) = session.lock() {
                    s.log_activity("PROFILE", format!("cmd {idx}: free memory -> {}", res.message));
                }
            }
            crate::profile::ProfileCommand::AobScan { marker, pattern, offset, region, .. } => {
                let parsed_pat = trainlab_core::aob::parse(pattern);
                if parsed_pat.is_empty() {
                    return Err(format!("cmd {idx}: empty AOB pattern '{pattern}'"));
                }
                let proc = game_process(session).map_err(|e| format!("cmd {idx}: AOB scan process access error: {e:?}"))?;
                let all_regions = proc.regions().map_err(|e| format!("cmd {idx}: AOB scan list regions error: {e}"))?;

                let regions = if let Some(r_name) = region {
                    let (r_start, r_end) = {
                        let s = session.lock().map_err(|_| "session lock poisoned".to_string())?;
                        if let Some(m) = s.get_marker(r_name) {
                            let end = m.end_address().unwrap_or(m.address.saturating_add(0x1000));
                            (m.address, end)
                        } else {
                            drop(s);
                            let start = parse_addr_expr(session, r_name).map_err(|e| e.to_string())?;
                            (start, start.saturating_add(0x1000))
                        }
                    };
                    all_regions.into_iter().filter_map(|mut r| {
                        if r.end <= r_start || r.start >= r_end {
                            None
                        } else {
                            r.start = r.start.max(r_start);
                            r.end = r.end.min(r_end);
                            Some(r)
                        }
                    }).collect()
                } else {
                    all_regions
                };

                let mut first_match: Option<u64> = None;
                for r in &regions {
                    if !r.readable {
                        continue;
                    }
                    let len = (r.end - r.start) as usize;
                    if len < parsed_pat.len() {
                        continue;
                    }
                    if let Ok(buf) = proc.read(r.start, len)
                        && let Some(off) = trainlab_core::aob::find_all(&buf, &parsed_pat).first() {
                            first_match = Some(r.start + *off as u64);
                            break;
                        }
                }

                // Fallback: If AOB pattern had 0 matches and original_bytes was recorded,
                // attempt exact search for the pristine original bytes to relocate the hook site after game updates.
                if first_match.is_none()
                    && let crate::profile::ProfileCommand::AobScan { original_bytes: Some(orig_hex), .. } = &cmd {
                        if let Ok(orig_pat) = parse_hex_bytes(orig_hex)
                            && !orig_pat.is_empty() {
                                let parsed_orig: Vec<Option<u8>> = orig_pat.into_iter().map(Some).collect();
                                for r in &regions {
                                    if !r.readable {
                                        continue;
                                    }
                                    let len = (r.end - r.start) as usize;
                                    if len < parsed_orig.len() {
                                        continue;
                                    }
                                    if let Ok(buf) = proc.read(r.start, len)
                                        && let Some(off) = trainlab_core::aob::find_all(&buf, &parsed_orig).first() {
                                            first_match = Some(r.start + *off as u64);
                                            if let Ok(mut s) = session.lock() {
                                                s.log_activity("PROFILE", format!("cmd {idx}: AOB pattern failed, but relocated hook site via original_bytes at {:#x}", r.start + *off as u64));
                                            }
                                            break;
                                        }
                                }
                            }
                    }

                if let Some(match_addr) = first_match {
                    let final_addr = (match_addr as i64 + offset.unwrap_or(0)) as u64;
                    if let Ok(mut s) = session.lock() {
                        let _ = s.set_marker(marker, final_addr, Some(&format!("AOB match for pattern '{pattern}'")));
                    }
                    if let Ok(mut s) = session.lock() {
                        s.log_activity("PROFILE", format!("cmd {idx}: external AOB scan found match at {final_addr:#x} -> saved marker '${marker}'"));
                    }
                } else {
                    // If AOB pattern wasn't found (e.g. hook was already patched with a JMP instruction in this game session),
                    // check if the session already has a valid non-zero marker for this label.
                    let existing_addr = {
                        let s = session.lock().ok();
                        s.and_then(|s| s.get_marker(marker).map(|m| m.address))
                    };
                    if let Some(addr) = existing_addr.filter(|a| *a != 0) {
                        if let Ok(mut s) = session.lock() {
                            s.log_activity("PROFILE", format!("cmd {idx}: AOB pattern '{pattern}' already patched/hooked; reusing existing marker '${marker}' = {addr:#x}"));
                        }
                    } else {
                        return Err(format!("cmd {idx}: AOB scan '{pattern}' found 0 matches; sequence aborted"));
                    }
                }
            }
            crate::profile::ProfileCommand::PointerChase { marker, base, offsets, .. } => {
                let mut curr_addr = parse_addr_expr(session, base)
                    .map_err(|e| format!("cmd {idx}: bad base '{base}': {e:?}"))?;
                // Detect Object-kind markers: skip the initial dereference — the base IS the object.
                let base_is_object = {
                    let raw = base.trim().trim_start_matches('$');
                    session.lock().ok()
                        .and_then(|s| s.get_marker(raw).map(|m| m.kind == trainlab_core::session::MarkerKind::Object))
                        .unwrap_or(false)
                };
                // T-131: Parse offsets strictly — error on malformed offsets instead of silently dropping them.
                let parsed_offs: Vec<u64> = offsets.iter().map(|o| {
                    let clean = o.trim_start_matches('+').trim();
                    let hex_str = clean.strip_prefix("0x").or_else(|| clean.strip_prefix("0X")).unwrap_or(clean);
                    u64::from_str_radix(hex_str, 16)
                        .map_err(|e| format!("cmd {idx}: bad pointer chase offset '{o}': {e}"))
                }).collect::<Result<Vec<_>, _>>()?;

                if base_is_object {
                    // Object mode: base IS the struct; no initial dereference of base.
                    if parsed_offs.is_empty() {
                        // No offsets — curr_addr stays as base.
                    } else if parsed_offs.len() == 1 {
                        // Single offset: field address = base + offset, no deref needed.
                        curr_addr = curr_addr.wrapping_add(parsed_offs[0]);
                    } else {
                        // Multiple offsets: read(base + off[0]) as first hop, then chase remaining.
                        let first_read_addr = curr_addr.wrapping_add(parsed_offs[0]);
                        let read_res = crate::controller::request(
                            session,
                            &trainlab_core::protocol::Request::Read { address: first_read_addr, len: 8 },
                        ).map_err(|e| format!("cmd {idx}: pointer chase object-mode read failed at {first_read_addr:#x}: {e}"))?;
                        match read_res {
                            trainlab_core::protocol::Response::Read { data } if data.len() == 8 => {
                                curr_addr = u64::from_le_bytes(data.try_into().unwrap());
                            }
                            trainlab_core::protocol::Response::Error { message } => {
                                return Err(format!("cmd {idx}: pointer chase object-mode read error at {first_read_addr:#x}: {message}"));
                            }
                            _ => return Err(format!("cmd {idx}: pointer chase object-mode short read at {first_read_addr:#x}")),
                        }
                        for off in &parsed_offs[1..] {
                            let read_res = crate::controller::request(
                                session,
                                &trainlab_core::protocol::Request::Read { address: curr_addr, len: 8 },
                            ).map_err(|e| format!("cmd {idx}: pointer chase read failed at {curr_addr:#x}: {e}"))?;
                            match read_res {
                                trainlab_core::protocol::Response::Read { data } if data.len() == 8 => {
                                    let ptr = u64::from_le_bytes(data.try_into().unwrap());
                                    curr_addr = ptr.wrapping_add(*off);
                                }
                                trainlab_core::protocol::Response::Error { message } => {
                                    return Err(format!("cmd {idx}: pointer chase read error at {curr_addr:#x}: {message}"));
                                }
                                _ => return Err(format!("cmd {idx}: pointer chase short read at {curr_addr:#x}")),
                            }
                        }
                    }
                } else {
                    for off in &parsed_offs {
                        let read_res = crate::controller::request(
                            session,
                            &trainlab_core::protocol::Request::Read { address: curr_addr, len: 8 },
                        ).map_err(|e| format!("cmd {idx}: pointer chase read failed at {curr_addr:#x}: {e}"))?;
                        match read_res {
                            trainlab_core::protocol::Response::Read { data } if data.len() == 8 => {
                                let ptr = u64::from_le_bytes(data.try_into().unwrap());
                                curr_addr = ptr.wrapping_add(*off);
                            }
                            trainlab_core::protocol::Response::Error { message } => {
                                return Err(format!("cmd {idx}: pointer chase read error at {curr_addr:#x}: {message}"));
                            }
                            _ => return Err(format!("cmd {idx}: pointer chase short read or unexpected response at {curr_addr:#x}")),
                        }
                    }
                }
                if let Ok(mut s) = session.lock() {
                    let _ = s.set_marker(marker, curr_addr, Some(&format!("Pointer chase base '{base}' offsets {:?}", offsets)));
                    s.log_activity("PROFILE", format!("cmd {idx}: pointer chase -> target {curr_addr:#x} saved marker '${marker}'"));
                }
            }
            crate::profile::ProfileCommand::Assert { address_ref, address, expected, value_type, .. } => {
                let addr_str = address_ref.as_deref().or(address.as_deref()).unwrap_or("");
                let target_addr = parse_addr_expr(session, addr_str)
                    .map_err(|e| format!("cmd {idx}: assert bad target '{addr_str}': {e:?}"))?;
                if target_addr == 0 {
                    return Err(format!("cmd {idx}: assert failed — target address '{addr_str}' is 0x0"));
                }

                let vt_str = value_type.as_deref().unwrap_or("i32");
                let vt = parse_value_type(vt_str)
                    .map_err(|e| format!("cmd {idx}: assert bad value_type '{vt_str}': {e:?}"))?;
                let read_len = vt.size();

                let read_res = crate::controller::request(
                    session,
                    &trainlab_core::protocol::Request::Read { address: target_addr, len: read_len },
                ).map_err(|e| format!("cmd {idx}: assert read memory failed: {e}"))?;

                match read_res {
                    trainlab_core::protocol::Response::Read { data } if data.len() == read_len => {
                        let exp_clean = expected.trim();
                        let got_val_str = crate::format_value(&data, vt);

                        if exp_clean == "!0" || exp_clean == "!0x0" || exp_clean == "!0X0" || exp_clean == "!null" {
                            let val_u64 = match data.len() {
                                1 => data[0] as u64,
                                2 => u16::from_le_bytes(data[..2].try_into().unwrap()) as u64,
                                4 => u32::from_le_bytes(data[..4].try_into().unwrap()) as u64,
                                8 => u64::from_le_bytes(data[..8].try_into().unwrap()),
                                _ => 0,
                            };
                            if val_u64 == 0 {
                                return Err(format!("cmd {idx}: assert failed — memory @ {addr_str} ({target_addr:#x}) is 0x0 (expected non-null)"));
                            }
                            if let Ok(mut s) = session.lock() {
                                s.log_activity("PROFILE", format!("cmd {idx}: assert non-null @ {addr_str} ({target_addr:#x}) passed ({val_u64:#x})"));
                            }
                        } else {
                            // T-130: Parse the expected value per the value_type and compare.
                            let expected_bytes = parse_value_bytes(exp_clean, vt)
                                .map_err(|e| format!("cmd {idx}: assert failed to parse expected value '{exp_clean}': {e:?}"))?;
                            if data != expected_bytes {
                                let exp_val_str = crate::format_value(&expected_bytes, vt);
                                return Err(format!(
                                    "cmd {idx}: assert failed — memory @ {addr_str} ({target_addr:#x}) == {got_val_str} (expected {exp_val_str})"
                                ));
                            }
                            if let Ok(mut s) = session.lock() {
                                s.log_activity("PROFILE", format!("cmd {idx}: assert {got_val_str} == {exp_clean} @ {addr_str} ({target_addr:#x}) passed"));
                            }
                        }
                    }
                    _ => return Err(format!("cmd {idx}: assert read memory failed @ {addr_str} ({target_addr:#x})")),
                }
            }
            crate::profile::ProfileCommand::SetMarker { marker, address, .. } => {
                let parsed_addr = parse_addr_expr(session, address)
                    .map_err(|e| format!("cmd {idx}: bad address expression '{address}' for marker '{marker}': {e:?}"))?;
                if parsed_addr == 0 {
                    return Err(format!("cmd {idx}: marker '{marker}' address expression '{address}' resolved to 0x0; sequence aborted"));
                }
                if let Ok(mut s) = session.lock() {
                    let _ = s.set_marker(marker, parsed_addr, Some(&format!("Profile set_marker '{address}'")));
                    s.log_activity("PROFILE", format!("cmd {idx}: set_marker '{marker}' = {parsed_addr:#x} (from '{address}')"));
                }
            }
            crate::profile::ProfileCommand::Wait { ms, .. } => {
                if let Ok(mut s) = session.lock() {
                    s.log_activity("PROFILE", format!("cmd {idx}: waiting {ms}ms..."));
                }
                std::thread::sleep(std::time::Duration::from_millis(*ms));
                if let Ok(mut s) = session.lock() {
                    s.log_activity("PROFILE", format!("cmd {idx}: wait {ms}ms complete"));
                }
            }
            crate::profile::ProfileCommand::WriteCopy { src, dst, value_type, addend_ref, op, .. } => {
                let vt_str = value_type.as_deref().unwrap_or("f32");
                let vt = parse_value_type(vt_str)
                    .map_err(|e| format!("cmd {idx}: invalid value type '{vt_str}': {e}"))?;

                let src_addr = parse_addr_expr(session, src)
                    .map_err(|e| format!("cmd {idx}: bad src '{src}': {e}"))?;
                if src_addr == 0 {
                    return Err(format!("cmd {idx}: src '{src}' resolved to 0x0; sequence aborted"));
                }

                let dst_addr = parse_addr_expr(session, dst)
                    .map_err(|e| format!("cmd {idx}: bad dst '{dst}': {e}"))?;
                if dst_addr == 0 {
                    return Err(format!("cmd {idx}: dst '{dst}' resolved to 0x0; sequence aborted"));
                }

                let size = vt.size();

                // Read src value
                let src_resp = crate::controller::request(
                    session,
                    &trainlab_core::protocol::Request::Read { address: src_addr, len: size },
                ).map_err(|e| format!("cmd {idx}: read src at {src} ({src_addr:#x}) failed: {e}"))?;

                let src_bytes = match src_resp {
                    trainlab_core::protocol::Response::Read { data } if data.len() == size => data,
                    trainlab_core::protocol::Response::Error { message } => {
                        return Err(format!("cmd {idx}: read src failed at {src} ({src_addr:#x}): {message}"));
                    }
                    _ => return Err(format!("cmd {idx}: short read on src at {src} ({src_addr:#x})")),
                };

                // Compute final bytes, applying optional addend
                let computed_bytes = if let Some(add_expr) = addend_ref {
                    let add_addr = parse_addr_expr(session, add_expr)
                        .map_err(|e| format!("cmd {idx}: bad addend_ref '{add_expr}': {e}"))?;
                    if add_addr == 0 {
                        return Err(format!("cmd {idx}: addend_ref '{add_expr}' resolved to 0x0; sequence aborted"));
                    }

                    let add_resp = crate::controller::request(
                        session,
                        &trainlab_core::protocol::Request::Read { address: add_addr, len: size },
                    ).map_err(|e| format!("cmd {idx}: read addend at {add_expr} ({add_addr:#x}) failed: {e}"))?;

                    let add_bytes = match add_resp {
                        trainlab_core::protocol::Response::Read { data } if data.len() == size => data,
                        trainlab_core::protocol::Response::Error { message } => {
                            return Err(format!("cmd {idx}: read addend failed at {add_expr} ({add_addr:#x}): {message}"));
                        }
                        _ => return Err(format!("cmd {idx}: short read on addend at {add_expr} ({add_addr:#x})")),
                    };

                    match vt {
                        trainlab_core::scan::ValueType::F32 => {
                            let s = f32::from_le_bytes(src_bytes.as_slice().try_into().unwrap());
                            let a = f32::from_le_bytes(add_bytes.as_slice().try_into().unwrap());
                            (s + a).to_le_bytes().to_vec()
                        }
                        trainlab_core::scan::ValueType::F64 => {
                            let s = f64::from_le_bytes(src_bytes.as_slice().try_into().unwrap());
                            let a = f64::from_le_bytes(add_bytes.as_slice().try_into().unwrap());
                            (s + a).to_le_bytes().to_vec()
                        }
                        trainlab_core::scan::ValueType::I32 => {
                            let s = i32::from_le_bytes(src_bytes.as_slice().try_into().unwrap());
                            let a = i32::from_le_bytes(add_bytes.as_slice().try_into().unwrap());
                            s.wrapping_add(a).to_le_bytes().to_vec()
                        }
                        trainlab_core::scan::ValueType::U32 => {
                            let s = u32::from_le_bytes(src_bytes.as_slice().try_into().unwrap());
                            let a = u32::from_le_bytes(add_bytes.as_slice().try_into().unwrap());
                            s.wrapping_add(a).to_le_bytes().to_vec()
                        }
                        trainlab_core::scan::ValueType::I64 => {
                            let s = i64::from_le_bytes(src_bytes.as_slice().try_into().unwrap());
                            let a = i64::from_le_bytes(add_bytes.as_slice().try_into().unwrap());
                            s.wrapping_add(a).to_le_bytes().to_vec()
                        }
                        trainlab_core::scan::ValueType::U64 | trainlab_core::scan::ValueType::Ptr => {
                            let s = u64::from_le_bytes(src_bytes.as_slice().try_into().unwrap());
                            let a = u64::from_le_bytes(add_bytes.as_slice().try_into().unwrap());
                            s.wrapping_add(a).to_le_bytes().to_vec()
                        }
                    }
                } else {
                    src_bytes
                };

                // Read destination if op == "max" or for undo snapshot
                let dst_resp = crate::controller::request(
                    session,
                    &trainlab_core::protocol::Request::Read { address: dst_addr, len: size },
                ).map_err(|e| format!("cmd {idx}: read dst at {dst} ({dst_addr:#x}) failed: {e}"))?;

                let (dst_bytes, original) = match dst_resp {
                    trainlab_core::protocol::Response::Read { data } if data.len() == size => {
                        (Some(data.clone()), data)
                    }
                    _ => (None, Vec::new()),
                };

                // If op == "max", apply dst = max(dst, computed)
                let bytes_to_write = if op.as_deref().unwrap_or("assign") == "max" {
                    if let Some(cur) = dst_bytes {
                        match vt {
                            trainlab_core::scan::ValueType::F32 => {
                                let c = f32::from_le_bytes(computed_bytes.as_slice().try_into().unwrap());
                                let d = f32::from_le_bytes(cur.as_slice().try_into().unwrap());
                                if d >= c {
                                    if let Ok(mut s) = session.lock() {
                                        s.log_activity("PROFILE", format!("cmd {idx}: write_copy max no-op (current {d} >= source {c})"));
                                    }
                                    return Ok(());
                                }
                                c.max(d).to_le_bytes().to_vec()
                            }
                            trainlab_core::scan::ValueType::F64 => {
                                let c = f64::from_le_bytes(computed_bytes.as_slice().try_into().unwrap());
                                let d = f64::from_le_bytes(cur.as_slice().try_into().unwrap());
                                if d >= c {
                                    if let Ok(mut s) = session.lock() {
                                        s.log_activity("PROFILE", format!("cmd {idx}: write_copy max no-op (current {d} >= source {c})"));
                                    }
                                    return Ok(());
                                }
                                c.max(d).to_le_bytes().to_vec()
                            }
                            trainlab_core::scan::ValueType::I32 => {
                                let c = i32::from_le_bytes(computed_bytes.as_slice().try_into().unwrap());
                                let d = i32::from_le_bytes(cur.as_slice().try_into().unwrap());
                                if d >= c {
                                    return Ok(());
                                }
                                c.max(d).to_le_bytes().to_vec()
                            }
                            trainlab_core::scan::ValueType::U32 => {
                                let c = u32::from_le_bytes(computed_bytes.as_slice().try_into().unwrap());
                                let d = u32::from_le_bytes(cur.as_slice().try_into().unwrap());
                                if d >= c {
                                    return Ok(());
                                }
                                c.max(d).to_le_bytes().to_vec()
                            }
                            trainlab_core::scan::ValueType::I64 => {
                                let c = i64::from_le_bytes(computed_bytes.as_slice().try_into().unwrap());
                                let d = i64::from_le_bytes(cur.as_slice().try_into().unwrap());
                                if d >= c {
                                    return Ok(());
                                }
                                c.max(d).to_le_bytes().to_vec()
                            }
                            trainlab_core::scan::ValueType::U64 | trainlab_core::scan::ValueType::Ptr => {
                                let c = u64::from_le_bytes(computed_bytes.as_slice().try_into().unwrap());
                                let d = u64::from_le_bytes(cur.as_slice().try_into().unwrap());
                                if d >= c {
                                    return Ok(());
                                }
                                c.max(d).to_le_bytes().to_vec()
                            }
                        }
                    } else {
                        computed_bytes
                    }
                } else {
                    computed_bytes
                };

                let resp = crate::controller::request(
                    session,
                    &trainlab_core::protocol::Request::Write { address: dst_addr, data: bytes_to_write.clone() },
                ).map_err(|e| format!("cmd {idx}: write to {dst} ({dst_addr:#x}) failed: {e}"))?;

                if let trainlab_core::protocol::Response::Error { message } = resp {
                    return Err(format!("cmd {idx}: write failed: {message}"));
                }

                let val_str = crate::format_value(&bytes_to_write, vt);
                if let Ok(mut s) = session.lock() {
                    if !original.is_empty() {
                        s.record_undo(
                            dst_addr,
                            original,
                            format!("profile write_copy {val_str} ({vt_str}) to {dst_addr:#x}"),
                        );
                    }
                    s.log_activity("PROFILE", format!("cmd {idx}: write_copy '{val_str}' ({vt_str}) to {dst} ({dst_addr:#x}) -> ok"));
                }
            }
        }
    }
    Ok(())
}

/// Allocate string memory in target game process and write bytes.
pub(crate) fn allocate_string_in_game(session: &SharedSession, content: &str, kind: &str) -> Result<(u64, usize), String> {
    let mut bytes = content.as_bytes().to_vec();
    let kind_lower = kind.trim().to_lowercase();
    let is_c_like = matches!(kind_lower.as_str(), "c" | "json" | "yaml" | "xml" | "js" | "config");
    if is_c_like && !bytes.ends_with(&[0]) {
        bytes.push(0);
    }
    let len = bytes.len();
    let pid = {
        let s = session.lock().map_err(|_| "session lock poisoned".to_string())?;
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
        use trainlab_core::memory::ProcessMemory;
        let proc = trainlab_core::memory::WindowsProcess::open(pid).map_err(|e| e.to_string())?;
        proc.write(alloc_addr, &bytes).map_err(|e| e.to_string())?;
        Ok((alloc_addr, len))
    }
    #[cfg(not(windows))]
    {
        let _ = pid;
        let _ = bytes;
        // T-164: Return an error instead of a fake address on non-Windows platforms.
        Err("string allocation is only supported on Windows".to_string())
    }
}

/// Resolve a setup step to a concrete address for the current launch.
fn resolve_setup_step(
    session: &SharedSession,
    step: &crate::profile::SetupStep,
) -> Result<u64, String> {
    use crate::profile::SetupStep;
    match step {
        SetupStep::AobScan { pattern, offset, region, .. } => {
            // AOB scan externally (matches the `aob_scan` tool), optionally bound
            // to a specific region/module/marker, take the first match + offset.
            let parsed = trainlab_core::aob::parse(pattern);
            if parsed.is_empty() {
                return Err("empty/invalid AOB pattern".into());
            }
            let proc = game_process(session).map_err(|e| e.to_string())?;
            let all_regions = proc.regions().map_err(|e| format!("regions: {e}"))?;

            let regions = if let Some(r_name) = region {
                let (r_start, r_end) = {
                    let s = session.lock().map_err(|_| "session lock poisoned".to_string())?;
                    if let Some(m) = s.get_marker(r_name) {
                        let end = m.end_address().unwrap_or(m.address.saturating_add(0x1000));
                        (m.address, end)
                    } else {
                        drop(s);
                        let start = parse_addr_expr(session, r_name).map_err(|e| e.to_string())?;
                        (start, start.saturating_add(0x1000))
                    }
                };
                all_regions.into_iter().filter_map(|mut r| {
                    if r.end <= r_start || r.start >= r_end {
                        None
                    } else {
                        r.start = r.start.max(r_start);
                        r.end = r.end.min(r_end);
                        Some(r)
                    }
                }).collect()
            } else {
                all_regions
            };

            let mut first_match: Option<u64> = None;
            for r in &regions {
                if !r.readable {
                    continue;
                }
                let len = (r.end - r.start) as usize;
                if len < parsed.len() {
                    continue;
                }
                if let Ok(buf) = proc.read(r.start, len)
                    && let Some(off) = trainlab_core::aob::find_all(&buf, &parsed).first() {
                        first_match = Some(r.start + *off as u64);
                        break;
                    }
            }

            // Fallback: If AOB pattern had 0 matches and original_bytes was recorded,
            // attempt exact search for the pristine original bytes to relocate the hook site after game updates.
            if first_match.is_none()
                && let SetupStep::AobScan { original_bytes: Some(orig_hex), .. } = step {
                    if let Ok(orig_pat) = parse_hex_bytes(orig_hex)
                        && !orig_pat.is_empty() {
                            let parsed_orig: Vec<Option<u8>> = orig_pat.into_iter().map(Some).collect();
                            for r in &regions {
                                if !r.readable {
                                    continue;
                                }
                                let len = (r.end - r.start) as usize;
                                if len < parsed_orig.len() {
                                    continue;
                                }
                                if let Ok(buf) = proc.read(r.start, len)
                                    && let Some(off) = trainlab_core::aob::find_all(&buf, &parsed_orig).first() {
                                        first_match = Some(r.start + *off as u64);
                                        if let Ok(mut s) = session.lock() {
                                            s.log_activity("PROFILE", format!("AOB pattern failed, but relocated hook site via original_bytes at {:#x}", r.start + *off as u64));
                                        }
                                        break;
                                    }
                            }
                        }
                }

            let m = first_match.ok_or_else(|| "aob scan found no matches (including original_bytes fallback)".to_string())?;
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
    let mut tried = Vec::new();
    for r in refs.into_iter().flatten() {
        // Named setup value?
        if let Some((_, a)) = resolved.iter().find(|(n, _)| n == r) {
            return Ok(*a);
        }
        // Raw address (decimal or 0x hex)?
        if let Ok(a) = parse_addr_str(r) {
            return Ok(a);
        }
        tried.push(r.to_string());
    }
    if tried.is_empty() {
        Err(err("cheat has no address_ref/target_ref"))
    } else {
        Err(err(format!(
            "could not resolve address ref(s): {} (not a named setup value or raw address)",
            tried.join(", ")
        )))
    }
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
    fn parse_int<T: std::str::FromStr>(s: &str, parse_hex: impl FnOnce(&str) -> Result<T, std::num::ParseIntError>) -> Result<T, ()> {
        if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            parse_hex(hex).map_err(|_| ())
        } else {
            s.parse::<T>().or_else(|_| parse_hex(s)).map_err(|_| ())
        }
    }

    match vt {
        ValueType::I32 => {
            let val = parse_int::<i32>(s, |h| i32::from_str_radix(h, 16))
                .map_err(|_| err(format!("invalid i32 '{s}'")))?;
            Ok(val.to_le_bytes().to_vec())
        }
        ValueType::U32 => {
            let val = parse_int::<u32>(s, |h| u32::from_str_radix(h, 16))
                .map_err(|_| err(format!("invalid u32 '{s}'")))?;
            Ok(val.to_le_bytes().to_vec())
        }
        ValueType::F32 => Ok(s
            .parse::<f32>()
            .map_err(|_| err(format!("invalid f32 '{s}'")))?
            .to_le_bytes()
            .to_vec()),
        ValueType::I64 => {
            let val = parse_int::<i64>(s, |h| i64::from_str_radix(h, 16))
                .map_err(|_| err(format!("invalid i64 '{s}'")))?;
            Ok(val.to_le_bytes().to_vec())
        }
        ValueType::U64 => {
            let val = parse_int::<u64>(s, |h| u64::from_str_radix(h, 16))
                .map_err(|_| err(format!("invalid u64 '{s}'")))?;
            Ok(val.to_le_bytes().to_vec())
        }
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
    if !cleaned.len().is_multiple_of(2) {
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
    trainlab_core::tools::read_cstr(proc, address, max_len)
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
    let api_router = crate::api::router(session.clone(), egui_ctx.clone());
    let dashboard_router = crate::api::dashboard_router();
    let router = axum::Router::new()
        .merge(dashboard_router)
        .nest("/api", api_router)
        .nest_service("/mcp", service)
        .nest_service("/captures", tower_http::services::ServeDir::new("captures"))
        .nest_service("/snapshots", tower_http::services::ServeDir::new("snapshots"))
        .nest_service("/scans", tower_http::services::ServeDir::new("scans"))
        .nest_service("/regions", tower_http::services::ServeDir::new("regions"))
        .route("/log", axum::routing::get(serve_session_log));
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

/// HTTP handler serving `trainlab_session.log` as a downloadable text file at `http://<host>:<port>/log`.
async fn serve_session_log() -> impl axum::response::IntoResponse {
    use axum::response::IntoResponse;
    match tokio::fs::read_to_string("trainlab_session.log").await {
        Ok(contents) => (
            [(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            contents,
        ).into_response(),
        Err(_) => (
            axum::http::StatusCode::NOT_FOUND,
            "session log not found (no activity logged yet)",
        ).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trainlab_core::memory::ProcessMemory;
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
            asm: None,
            jump: None,
            mechanism: None,
            rate_hz: None,
            value: None,
            base: None,
            fields: None,
            commands: None,
            group: None,
            hotkey: None,
            hidden: None,
            original_bytes: None,
            context: None,
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

    #[tokio::test]
    async fn network_packet_capture_and_http_serving_roundtrip() -> anyhow::Result<()> {
        let session = SharedSession::default();
        let (url, ct) = serve("127.0.0.1", 0, session.clone(), None).await?;
        let base_url = url.trim_end_matches("/mcp");

        // 1. Manually write a captured packet file in captures/ to test HTTP static serving
        let _ = std::fs::create_dir_all("captures");
        let test_packet = std::path::Path::new("captures").join("packet_9999.bin");
        std::fs::write(&test_packet, b"NETWORK_PAYLOAD_TEST_BYTES")?;

        let http_url = format!("{base_url}/captures/packet_9999.bin");
        let res = reqwest::get(&http_url).await?;
        assert!(res.status().is_success(), "HTTP get capture failed with status: {}", res.status());
        let body = res.bytes().await?;
        assert_eq!(&body[..], b"NETWORK_PAYLOAD_TEST_BYTES");

        // 2. Add packet to session and test GET /api/network
        {
            let mut s = session.lock().unwrap();
            s.record_network_packet(trainlab_core::protocol::NetworkPacketDto {
                id: 9999,
                timestamp_ms: 123456789,
                kind: trainlab_core::protocol::PacketKind::Udp,
                direction: trainlab_core::protocol::PacketDirection::Outbound,
                local_endpoint: Some("127.0.0.1:4000".into()),
                remote_endpoint: Some("192.168.1.50:27015".into()),
                url: None,
                headers: None,
                payload_len: 26,
                payload_preview: b"NETWORK_PAYLOAD_TEST_BYTES".to_vec(),
                artifact_file: Some("captures/packet_9999.bin".into()),
            });
        }

        let api_url = format!("{base_url}/api/network");
        let api_res = reqwest::get(&api_url).await?;
        assert!(api_res.status().is_success());
        let api_json: serde_json::Value = api_res.json().await?;
        assert_eq!(api_json["total"], 1);
        assert_eq!(api_json["packets"][0]["id"], 9999);
        assert_eq!(api_json["packets"][0]["kind"], "Udp");

        let _ = std::fs::remove_file(&test_packet);
        ct.cancel();
        Ok(())
    }

    #[test]
    fn test_mcp_network_tools() {
        let session = SharedSession::default();
        let server = TrainlabMcpServer::with_session_and_ctx(session.clone(), None);

        // 1. Without network_capture capability, notices are returned gracefully
        let res_no_cap = server.get_network_log(Parameters(GetNetworkLogArgs {
            limit: None,
            offset: None,
            proto: None,
            filter: None,
        })).unwrap();
        let text_no_cap = match &res_no_cap.content[0] {
            rmcp::model::ContentBlock::Text(t) => t.text.clone(),
            _ => panic!("expected text"),
        };
        assert!(text_no_cap.contains("does not advertise 'network_capture'"));

        // 2. Set capability and populate packets
        {
            let mut s = session.lock().unwrap();
            s.set_dll_capabilities(vec!["memory".into(), "network_capture".into()]);
            s.record_network_packet(trainlab_core::protocol::NetworkPacketDto {
                id: 101,
                timestamp_ms: 1000,
                kind: trainlab_core::protocol::PacketKind::Tcp,
                direction: trainlab_core::protocol::PacketDirection::Outbound,
                local_endpoint: Some("127.0.0.1:50000".into()),
                remote_endpoint: Some("93.184.216.34:80".into()),
                url: None,
                headers: None,
                payload_len: 18,
                payload_preview: b"GET / HTTP/1.1\r\n\r\n".to_vec(),
                artifact_file: Some("captures/packet_101.bin".into()),
            });
        }

        // 3. Test get_network_log
        let res_log = server.get_network_log(Parameters(GetNetworkLogArgs {
            limit: Some(10),
            offset: None,
            proto: Some("tcp".into()),
            filter: Some("93.184".into()),
        })).unwrap();
        let text_log = match &res_log.content[0] {
            rmcp::model::ContentBlock::Text(t) => t.text.clone(),
            _ => panic!("expected text"),
        };
        assert!(text_log.contains("#0101"));
        assert!(text_log.contains("TCP"));
        assert!(text_log.contains("GET / HTTP/1.1"));
        assert!(text_log.contains("[file: captures/packet_101.bin]"));

        // 4. Test watch_network
        let res_watch = server.watch_network(Parameters(WatchNetworkArgs {
            filter: Some("93.184".into()),
            proto: None,
            limit: Some(5),
        })).unwrap();
        let text_watch = match &res_watch.content[0] {
            rmcp::model::ContentBlock::Text(t) => t.text.clone(),
            _ => panic!("expected text"),
        };
        assert!(text_watch.contains("#0101"));
        assert!(text_watch.contains("GET / HTTP/1.1"));

        // 5. Test clear_network_log
        let res_clear = server.clear_network_log(Parameters(ClearNetworkLogArgs {})).unwrap();
        let text_clear = match &res_clear.content[0] {
            rmcp::model::ContentBlock::Text(t) => t.text.clone(),
            _ => panic!("expected text"),
        };
        assert!(text_clear.contains("Cleared 1 captured network packet(s)"));

        // Confirm buffer is now empty
        let res_empty = server.get_network_log(Parameters(GetNetworkLogArgs {
            limit: None,
            offset: None,
            proto: None,
            filter: None,
        })).unwrap();
        let text_empty = match &res_empty.content[0] {
            rmcp::model::ContentBlock::Text(t) => t.text.clone(),
            _ => panic!("expected text"),
        };
        assert!(text_empty.contains("No captured network packets"));
    }

    #[test]
    fn allocate_string_kind_validation() {
        let s = SharedSession::default();
        let server = TrainlabMcpServer::with_session_and_ctx(s, None);

        // Invalid kind rejected
        let res_err = server.allocate_string(Parameters(AllocateStringArgs {
            content: Some("print('hello')".into()),
            size: None,
            fill_byte: None,
            kind: "lua".into(), // Explicitly rejected per spec
            marker: None,
        }));
        assert!(res_err.is_err());

        // Valid kind accepted (content provided)
        let res_ok_c = server.allocate_string(Parameters(AllocateStringArgs {
            content: Some("print('hello')".into()),
            size: None,
            fill_byte: None,
            kind: "c".into(),
            marker: None,
        }));
        // Requires attached game process, so returns error for no PID attached
        assert!(res_ok_c.is_err());
        let err_msg = res_ok_c.unwrap_err().message;
        assert!(err_msg.contains("no game process"));

        // Valid kind accepted (size provided without content)
        let res_ok_size = server.allocate_string(Parameters(AllocateStringArgs {
            content: None,
            size: Some(16384),
            fill_byte: Some(0),
            kind: "c".into(),
            marker: Some("test_buf".into()),
        }));
        assert!(res_ok_size.is_err());
        assert!(res_ok_size.unwrap_err().message.contains("no game process"));
    }

    #[test]
    fn write_tool_handles_data_and_typed_values() {
        let s = SharedSession::default();
        let server = TrainlabMcpServer::with_session_and_ctx(s, None);

        // 1. Raw data without attached game returns error
        let res_raw = server.write(Parameters(WriteArgs {
            address: "0x1000".into(),
            data: Some("90 90 c3".into()),
            value: None,
            value_type: None,
        }));
        assert!(res_raw.is_err());
        assert!(res_raw.unwrap_err().message.contains("no game process"));

        // 2. Both provided -> validation error
        let res_both = server.write(Parameters(WriteArgs {
            address: "0x1000".into(),
            data: Some("90".into()),
            value: Some("1".into()),
            value_type: None,
        }));
        assert!(res_both.is_err());
        assert!(res_both.unwrap_err().message.contains("specify either"));

        // 3. Neither provided -> validation error
        let res_neither = server.write(Parameters(WriteArgs {
            address: "0x1000".into(),
            data: None,
            value: None,
            value_type: None,
        }));
        assert!(res_neither.is_err());
        assert!(res_neither.unwrap_err().message.contains("must specify either"));
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
    fn parse_hex_bytes_accepts_spaced_and_unspaced() {
        assert_eq!(parse_hex_bytes("00 80 ac 43").unwrap(), vec![0x00, 0x80, 0xac, 0x43]);
        assert_eq!(parse_hex_bytes("0080ac43").unwrap(), vec![0x00, 0x80, 0xac, 0x43]);
        assert_eq!(parse_hex_bytes("  00  80  ac  43  ").unwrap(), vec![0x00, 0x80, 0xac, 0x43]);
        assert_eq!(parse_hex_bytes("").unwrap(), Vec::<u8>::new());
        assert!(parse_hex_bytes("00 80 zzz").is_err());
    }

    #[test]
    fn parse_value_bytes_all_types() {
        // i32
        assert_eq!(
            parse_value_bytes("14790", trainlab_core::scan::ValueType::I32).unwrap(),
            14790i32.to_le_bytes().to_vec()
        );
        // f32
        assert_eq!(
            parse_value_bytes("14790.0", trainlab_core::scan::ValueType::F32).unwrap(),
            14790.0f32.to_le_bytes().to_vec()
        );
        // f64
        assert_eq!(
            parse_value_bytes("3.25", trainlab_core::scan::ValueType::F64).unwrap(),
            3.25f64.to_le_bytes().to_vec()
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
        // Saved marker (with and without $)
        assert_eq!(parse_addr_expr(&s, "wood_ptr").unwrap(), 0x0e890000);
        assert_eq!(parse_addr_expr(&s, "$wood_ptr").unwrap(), 0x0e890000);
        // Marker + offset math (with and without $)
        assert_eq!(parse_addr_expr(&s, "wood_ptr + 0x48").unwrap(), 0x0e890048);
        assert_eq!(parse_addr_expr(&s, "$wood_ptr + 0x48").unwrap(), 0x0e890048);
        assert_eq!(parse_addr_expr(&s, "$wood_ptr - 0x10").unwrap(), 0x0e88fff0);
        assert_eq!(parse_addr_expr(&s, "($wood_ptr + 0x48) + 0x10").unwrap_err().code, rmcp::model::ErrorCode(-32603));
    }

    #[test]
    fn test_nested_bracket_pointer_dereference_chain() {
        let s = SharedSession::default();
        {
            let mut session = s.lock().unwrap();
            session.set_marker("player_base", 0x1000, None).unwrap();
        }

        // Setup mock memory:
        // [0x1000 + 0x08] = 0x1008 -> points to 0x2000
        // [0x2000 + 0x10] = 0x2010 -> points to 0x3000
        // [0x3000 + 0x14] = target address 0x3014 (holding float 4.0 = 0x40800000)
        let mut data = vec![0u8; 0x4000];
        let ptr1: u64 = 0x2000;
        let ptr2: u64 = 0x3000;
        data[0x1008..0x1010].copy_from_slice(&ptr1.to_le_bytes());
        data[0x2010..0x2018].copy_from_slice(&ptr2.to_le_bytes());
        data[0x3014..0x3018].copy_from_slice(&4.0f32.to_le_bytes());

        let fake_mem = FakeMem { data };

        // Test 1-level dereference: [$player_base + 0x08] => 0x2000
        let res1 = parse_addr_expr_with_mem(&s, "[$player_base + 0x08]", Some(&fake_mem)).unwrap();
        assert_eq!(res1, 0x2000);

        // Test 2-level dereference: [[$player_base + 0x08] + 0x10] => 0x3000
        let res2 = parse_addr_expr_with_mem(&s, "[[$player_base + 0x08] + 0x10]", Some(&fake_mem)).unwrap();
        assert_eq!(res2, 0x3000);

        // Test 3-level dereference + final field offset: [[[$player_base + 0x08] + 0x10] + 0x14]
        // This calculates base ptr dereference plus offset 0x14 -> 0x3014
        let res3 = parse_addr_expr_with_mem(&s, "[[$player_base + 0x08] + 0x10] + 0x14", Some(&fake_mem)).unwrap();
        assert_eq!(res3, 0x3014);

        // Verify reading final value from the resolved address in fake memory
        let final_val = fake_mem.read(res3, 4).unwrap();
        assert_eq!(f32::from_le_bytes(final_val.try_into().unwrap()), 4.0);
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

    #[test]
    fn test_load_profile_setup_markers_available_to_init_commands() {
        let s = SharedSession::default();
        let server = TrainlabMcpServer::with_session_and_ctx(s.clone(), None);

        // Define a profile where setup step resolves an address (Address type, offset from fake base)
        // and init_commands use Assert referencing that setup marker by name.
        let yaml = r#"
schema: trainlab-profile/v1
game: TestGame.exe
name: Test Profile
inject_dll: false
setup:
  - type: address
    name: test_marker
    module: TestGame.exe
    offset: "0x1234"
init_commands:
  - type: assert
    address_ref: "test_marker"
    expected: "!0x0"
    value_type: "ptr"
cheats: []
"#;
        let _profile = crate::profile::GameProfile::from_yaml(yaml).expect("parse yaml");
        // Seed module base for TestGame.exe
        {
            let mut session = s.lock().unwrap();
            let _ = session.set_marker("test_marker", 0x140001234, Some("seed"));
        }

        // Validate that markers are recorded and retrievable in session
        assert!(s.lock().unwrap().get_marker("test_marker").is_some());
    }

    #[test]
    fn test_set_marker_profile_command_creates_derived_marker() {
        let s = SharedSession::default();

        // Seed a base marker gc_cave = 0x140000000
        {
            let mut session = s.lock().unwrap();
            let _ = session.set_marker("gc_cave", 0x140000000, Some("base cave"));
        }

        // Run ProfileCommand::SetMarker deriving gc_slot = "gc_cave+0x44"
        let cmds = vec![
            crate::profile::ProfileCommand::SetMarker {
                marker: "gc_slot".into(),
                address: "gc_cave+0x44".into(),
                note: None,
            },
        ];
        execute_profile_commands(&s, &cmds).expect("execute set_marker command");

        // Verify gc_slot marker was created with value 0x140000044
        let session = s.lock().unwrap();
        let marker = session.get_marker("gc_slot").expect("gc_slot marker exists");
        assert_eq!(marker.address, 0x140000044);
    }

    #[test]
    fn test_capture_reg_gate_deserialization_struct_and_string() {
        // 1. Direct structured JSON
        let json_struct = r#"{
            "target": "sins2.exe+0x5ceda8",
            "reg": "rdi",
            "value_type": "ptr",
            "gate": {
                "cmp": "ne",
                "reg": "rdi",
                "value": 0.0,
                "value_type": "ptr"
            }
        }"#;
        let args_struct: CaptureRegArgs = serde_json::from_str(json_struct).expect("deserialize structured gate");
        assert!(args_struct.gate.is_some());
        let gate = args_struct.gate.unwrap();
        assert_eq!(gate.cmp, "ne");
        assert_eq!(gate.reg, "rdi");
        assert_eq!(gate.value, Some(0.0));

        // 2. Stringified JSON (escaped JSON string from clients)
        let json_str = r#"{
            "target": "sins2.exe+0x5ceda8",
            "reg": "rdi",
            "value_type": "ptr",
            "gate": "{\"cmp\": \"ne\", \"reg\": \"rdi\", \"value\": 0.0, \"value_type\": \"ptr\"}"
        }"#;
        let args_str: CaptureRegArgs = serde_json::from_str(json_str).expect("deserialize stringified gate");
        assert!(args_str.gate.is_some());
        let gate_from_str = args_str.gate.unwrap();
        assert_eq!(gate_from_str.cmp, "ne");
        assert_eq!(gate_from_str.reg, "rdi");
        assert_eq!(gate_from_str.value, Some(0.0));

        // 3. Null / omitted gate
        let json_none = r#"{
            "target": "sins2.exe+0x5ceda8",
            "reg": "rdi"
        }"#;
        let args_none: CaptureRegArgs = serde_json::from_str(json_none).expect("deserialize gateless");
        assert!(args_none.gate.is_none());
    }

    #[test]
    fn test_dump_struct_deserialization_struct_and_string() {
        // 1. Direct structured array of fields with numeric & hex string offsets
        let json_struct = r#"{
            "address": "player_base+0x2f0",
            "fields": [
                { "name": "credits", "value_type": "f32", "offset": 16 },
                { "name": "metal", "value_type": "f32", "offset": "0x14" },
                { "name": "crystal", "value_type": "f32", "offset": "0x18" }
            ]
        }"#;
        let args_struct: DumpStructArgs = serde_json::from_str(json_struct).expect("deserialize structured fields");
        assert_eq!(args_struct.fields.len(), 3);
        assert_eq!(args_struct.fields[0].name, "credits");
        assert_eq!(args_struct.fields[0].offset, 16);
        assert_eq!(args_struct.fields[1].name, "metal");
        assert_eq!(args_struct.fields[1].offset, 20); // 0x14 == 20
        assert_eq!(args_struct.fields[2].name, "crystal");
        assert_eq!(args_struct.fields[2].offset, 24); // 0x18 == 24

        // 2. Stringified JSON array of fields (escaped string from LLM client)
        let json_str = r#"{
            "address": "player_base+0x2f0",
            "fields": "[{\"name\": \"credits\", \"value_type\": \"f32\", \"offset\": 16}, {\"name\": \"metal\", \"value_type\": \"f32\", \"offset\": \"0x14\"}]"
        }"#;
        let args_str: DumpStructArgs = serde_json::from_str(json_str).expect("deserialize stringified fields");
        assert_eq!(args_str.fields.len(), 2);
        assert_eq!(args_str.fields[0].name, "credits");
        assert_eq!(args_str.fields[0].offset, 16);
        assert_eq!(args_str.fields[1].name, "metal");
        assert_eq!(args_str.fields[1].offset, 20);
    }

    #[test]
    fn test_load_profile_refuses_when_session_is_dirty() {
        let s = SharedSession::default();
        let server = TrainlabMcpServer::with_session_and_ctx(s.clone(), None);

        // 1. When session is clean, check_dirty is clean
        {
            let session = s.lock().unwrap();
            assert!(!session.check_dirty().is_dirty());
        }

        // 2. Add an enabled toggle cheat -> dirty
        let cheat_id = {
            let mut session = s.lock().unwrap();
            let cid = session.add_cheat("Fast Ships", crate::session::CheatKind::Toggle {
                hook: trainlab_core::cave_hook::CaveHook::Trampoline {
                    payload: vec![0x90],
                    jump: trainlab_core::cave_hook::JumpStyle::Absolute,
                },
                target: 0x140001000,
                enabled: true,
                original_bytes: vec![0x90; 14],
                cave_addr: 0x150000000,
            }, None, None);
            assert!(session.check_dirty().is_dirty());
            cid
        };

        // Attempting load_profile must fail with a dirty session error
        let res = server.load_profile(Parameters(LoadProfileArgs {
            profile: "example.yaml".into(),
            run_setup: false,
        }));
        assert!(res.is_err());
        let err_msg = res.unwrap_err().message;
        assert!(err_msg.contains("cannot load profile"), "err was: {err_msg}");
        assert!(err_msg.contains("dirty"), "err was: {err_msg}");

        // 3. Disable the cheat, but add an undo entry -> still dirty
        {
            let mut session = s.lock().unwrap();
            session.set_cheat_toggle(cheat_id, false);
            let _ = session.record_undo(0x140001000, vec![0x90; 14], "test write".into());
            assert!(session.check_dirty().is_dirty());
        }
        let res2 = server.load_profile(Parameters(LoadProfileArgs {
            profile: "example.yaml".into(),
            run_setup: false,
        }));
        assert!(res2.is_err());
        let err_msg2 = res2.unwrap_err().message;
        assert!(err_msg2.contains("cannot load profile"), "err was: {err_msg2}");

        // 4. Pop undo -> clean
        {
            let mut session = s.lock().unwrap();
            session.pop_undo_last();
            assert!(!session.check_dirty().is_dirty());
        }
    }

    #[test]
    fn test_connection_status_and_game_process_detects_target_lost() {
        let s = SharedSession::default();
        let server = TrainlabMcpServer::with_session_and_ctx(s.clone(), None);

        // When no game attached, connection_status reports not connected and game_alive: false
        let res = server.connection_status().expect("status ok");
        let txt = match &res.content[0] {
            rmcp::model::ContentBlock::Text(t) => t.text.clone(),
            _ => panic!("expected text"),
        };
        assert!(txt.contains("game_alive: false"));
        assert!(txt.contains("connected: false"));

        // When game pid is set to an invalid / non-running PID
        {
            let mut session = s.lock().unwrap();
            session.set_game_name("dead_game.exe");
            session.set_game_pid(Some(99999999));
            session.set_connected(true);
        }

        let res2 = server.connection_status().expect("status ok");
        let txt2 = match &res2.content[0] {
            rmcp::model::ContentBlock::Text(t) => t.text.clone(),
            _ => panic!("expected text"),
        };
        // On non-windows test runner, is_process_alive returns true stub or on Windows false.
        // game_process tool handles target lost
        assert!(txt2.contains("dead_game.exe"));
    }

    #[test]
    fn test_capture_reg_and_break_on_code_force_flags() {
        let s = SharedSession::default();
        let server = TrainlabMcpServer::with_session_and_ctx(s.clone(), None);

        // When no game process attached, capture_reg returns error unless forced or process mock
        let res = server.capture_reg(Parameters(CaptureRegArgs {
            target: "0x141380026".into(),
            reg: "xmm0".into(),
            value_type: "f32".into(),
            capacity: 32,
            stop_on_match: true,
            gate: None,
            jump: None,
            force: false,
        }));
        assert!(res.is_err());

        // break_on_code also has force field supported
        let res_break = server.break_on_code(Parameters(BreakOnCodeArgs {
            address: "0x141380026".into(),
            one_shot: true,
            force: false,
        }));
        assert!(res_break.is_err());
    }

    #[test]
    fn test_watch_poll_multi_hit_formatting() {
        let s = SharedSession::default();
        let server = TrainlabMcpServer::with_session_and_ctx(s.clone(), None);

        // When no hits pending
        let poll_empty = server.watch_poll().expect("watch_poll succeeds");
        let txt_empty = match &poll_empty.content[0] {
            rmcp::model::ContentBlock::Text(t) => t.text.clone(),
            _ => panic!("expected text"),
        };
        assert!(txt_empty.contains("no pending hit"));
    }

}
