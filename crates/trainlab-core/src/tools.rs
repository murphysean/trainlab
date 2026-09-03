//! Universal, presentation-agnostic tool definitions and execution handlers.
//!
//! Every client (MCP server, REST API, Web dashboard, egui GUI, CLI) invokes these
//! exact same tools with typed arguments and receives structured results.

use serde::{Deserialize, Serialize};
use std::path::Path;
use crate::expr::{format_value, parse_addr_expr_custom, parse_hex_bytes, parse_value_bytes, parse_value_type};
use crate::memory::ProcessMemory;
use crate::session::{CheatKind, ClientContext, SharedSession};

/// Result of executing a tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl ToolResult {
    pub fn success(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
            data: None,
        }
    }

    pub fn with_data(msg: impl Into<String>, data: serde_json::Value) -> Self {
        Self {
            message: msg.into(),
            data: Some(data),
        }
    }
}

/// Typed tool error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolError {
    pub message: String,
}

impl std::fmt::Display for ToolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ToolError {}

pub fn err(msg: impl Into<String>) -> ToolError {
    ToolError {
        message: msg.into(),
    }
}

// ---------------------------------------------------------------------------
// Tool Arguments (Group 1: Memory & Reverse Engineering)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadArgs {
    pub address: String,
    pub len: Option<usize>,
    pub value_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteArgs {
    pub address: String,
    pub data: Option<String>,
    pub value: Option<String>,
    pub value_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpArgs {
    pub address: String,
    pub len: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructFieldSpec {
    pub name: String,
    pub offset: i64,
    pub value_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub len: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpStructArgs {
    pub address: String,
    pub fields: Vec<StructFieldSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotArgs {
    pub start: String,
    pub end: Option<String>,
    pub len: Option<u64>,
    pub name: Option<String>,
    pub max_len: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllocateStringArgs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fill_byte: Option<u8>,
    #[serde(default = "default_string_kind")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub marker: Option<String>,
}

fn default_string_kind() -> String {
    "c".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllocateMemoryArgs {
    pub size: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub marker: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fill_byte: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreeMemoryArgs {
    pub address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddrToModuleArgs {
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassembleArgs {
    pub address: String,
    pub len: usize,
    pub max_instructions: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStartArgs {
    pub value_type: String,
    pub value: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alignment: Option<usize>,
    /// Optional region marker name (e.g. "game_heap") or address expression to bound the scan to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanNextArgs {
    pub op: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSetArgs {
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanAobArgs {
    pub pattern: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub marker: Option<String>,
    /// Optional region marker name (e.g. "game_heap") or address expression to bound the search.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Optional address alignment (e.g. 4 or 8 for pointer/data scans, 1 for unaligned code).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alignment: Option<usize>,
    /// Maximum number of match addresses to return in structured output (default 20).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanPointerArgs {
    pub address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Maximum number of referrer matches to return (default 50).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Maximum number of matches to return in structured output (default 20).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetMarkerArgs {
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveMarkerArgs {
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveCheatArgs {
    pub id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UndoInfoArgs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UndoRevertArgs {
    pub id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetMarkerArgs {
    pub label: String,
    pub address: String,
    /// Optional byte size if this marks a memory region (e.g. 0x10000000).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<usize>,
    /// Semantic kind: "pointer" (default), "object", "buffer", or "code".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Optional struct type name reference (only meaningful when kind == "object").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub struct_type: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PointerChaseArgs {
    pub base: String,
    pub offsets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddCheatArgs {
    pub label: String,
    pub kind: String,
    pub address: Option<String>,
    pub value_type: Option<String>,
    pub group: Option<String>,
    pub hotkey: Option<String>,
    pub hidden: Option<bool>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetCheatValueArgs {
    pub id: u64,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetCheatToggleArgs {
    pub id: u64,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileLoadArgs {
    pub file: String,
    #[serde(default = "default_true")]
    pub run_setup: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileSaveArgs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageWriteArgs {
    pub address: String,
    pub data: Option<String>,
    pub value: Option<String>,
    pub value_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallCaveArgs {
    pub target: String,
    pub hook: String,
    #[serde(default)]
    pub payload: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asm: Option<String>,
    #[serde(default = "default_absolute")]
    pub jump: String,
    pub marker: Option<String>,
}

fn default_absolute() -> String {
    "absolute".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssembleAsmArgs {
    pub code: String,
    pub origin: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllocCodeCaveArgs {
    pub name: String,
    pub size: Option<usize>,
    pub payload: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmitRelativeJumpArgs {
    pub from: String,
    pub to: String,
    pub pad_to_len: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureGateSpec {
    pub reg: String,
    pub cmp: String,
    pub value_type: Option<String>,
    pub value: Option<f64>,
    pub min: Option<f64>,
    pub max: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureRegArgs {
    pub target: String,
    pub reg: String,
    pub value_type: String,
    pub capacity: usize,
    pub stop_on_match: bool,
    pub gate: Option<CaptureGateSpec>,
    pub jump: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadCapturesArgs {
    pub id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UninstallCaptureArgs {
    pub id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchWritesArgs {
    pub address: String,
    pub len: Option<usize>,
    pub one_shot: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakOnCodeArgs {
    pub address: String,
    pub one_shot: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetOverlayVisibleArgs {
    pub visible: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpConfirmArgs {
    pub id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UndoArgs {
    #[serde(default)]
    pub id: u64,
}

fn default_true() -> bool {
    true
}

// ---------------------------------------------------------------------------
// Universal Memory Read Helpers
// ---------------------------------------------------------------------------

pub fn read_u8(proc: &dyn ProcessMemory, addr: u64) -> Result<String, String> {
    let data = proc.read(addr, 1).map_err(|e| e.to_string())?;
    Ok(data[0].to_string())
}

pub fn read_i8(proc: &dyn ProcessMemory, addr: u64) -> Result<String, String> {
    let data = proc.read(addr, 1).map_err(|e| e.to_string())?;
    Ok((data[0] as i8).to_string())
}

pub fn read_u16(proc: &dyn ProcessMemory, addr: u64) -> Result<String, String> {
    let data = proc.read(addr, 2).map_err(|e| e.to_string())?;
    Ok(u16::from_le_bytes(data[..2].try_into().unwrap()).to_string())
}

pub fn read_i16(proc: &dyn ProcessMemory, addr: u64) -> Result<String, String> {
    let data = proc.read(addr, 2).map_err(|e| e.to_string())?;
    Ok(i16::from_le_bytes(data[..2].try_into().unwrap()).to_string())
}

pub fn read_u32(proc: &dyn ProcessMemory, addr: u64) -> Result<String, String> {
    let data = proc.read(addr, 4).map_err(|e| e.to_string())?;
    Ok(u32::from_le_bytes(data[..4].try_into().unwrap()).to_string())
}

pub fn read_i32(proc: &dyn ProcessMemory, addr: u64) -> Result<String, String> {
    let data = proc.read(addr, 4).map_err(|e| e.to_string())?;
    Ok(i32::from_le_bytes(data[..4].try_into().unwrap()).to_string())
}

pub fn read_u64(proc: &dyn ProcessMemory, addr: u64) -> Result<String, String> {
    let data = proc.read(addr, 8).map_err(|e| e.to_string())?;
    Ok(u64::from_le_bytes(data[..8].try_into().unwrap()).to_string())
}

pub fn read_i64(proc: &dyn ProcessMemory, addr: u64) -> Result<String, String> {
    let data = proc.read(addr, 8).map_err(|e| e.to_string())?;
    Ok(i64::from_le_bytes(data[..8].try_into().unwrap()).to_string())
}

pub fn read_f32_val(proc: &dyn ProcessMemory, addr: u64) -> Result<String, String> {
    let data = proc.read(addr, 4).map_err(|e| e.to_string())?;
    Ok(f32::from_le_bytes(data[..4].try_into().unwrap()).to_string())
}

pub fn read_f64_val(proc: &dyn ProcessMemory, addr: u64) -> Result<String, String> {
    let data = proc.read(addr, 8).map_err(|e| e.to_string())?;
    Ok(f64::from_le_bytes(data[..8].try_into().unwrap()).to_string())
}

pub fn read_cstr(proc: &dyn ProcessMemory, addr: u64, max_len: usize) -> Result<String, String> {
    if addr == 0 {
        return Ok(String::new());
    }
    let max = max_len.min(65536);
    let data = proc.read(addr, max).map_err(|e| e.to_string())?;
    if data.is_empty() || data[0] == 0 {
        return Ok(String::new());
    }
    let (slice, has_nul) = match data.iter().position(|&b| b == 0) {
        Some(pos) => (&data[..pos], true),
        None => (&data[..], false),
    };
    if slice.is_empty() {
        return Ok(String::new());
    }
    if slice.iter().all(|&b| (0x20..=0x7e).contains(&b) || b == b'\t' || b == b'\n' || b == b'\r') {
        if slice.len() > 1024 {
            // Write oversized string to a snapshot file
            let file_name = format!("cstr_{addr:#x}_{}.txt", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0));
            let preview = String::from_utf8_lossy(&slice[..256]);
            if let Ok(rel_path) = write_output_artifact("snapshots", &file_name, slice) {
                Ok(format!("{preview}... [{} bytes total, saved to {rel_path}]", slice.len()))
            } else {
                Ok(format!("{preview}... [{} bytes total]", slice.len()))
            }
        } else {
            Ok(String::from_utf8_lossy(slice).into_owned())
        }
    } else {
        // Binary / non-printable: if no null terminator or raw binary, save full snapshot and return preview
        let file_name = format!("bin_{addr:#x}_{}.bin", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0));
        let display_len = slice.len().min(32);
        let hex_preview = slice[..display_len]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        let nul_note = if !has_nul { " (no null terminator found)" } else { "" };
        if let Ok(rel_path) = write_output_artifact("snapshots", &file_name, slice) {
            Ok(format!("<non-ascii {} bytes{nul_note}> {hex_preview}... [saved to {rel_path}]", slice.len()))
        } else {
            Ok(format!("<non-ascii {} bytes{nul_note}> {hex_preview}...", slice.len()))
        }
    }
}


/// Format a memory buffer as hex + ASCII text view.
pub fn format_dump(base_address: u64, data: &[u8]) -> String {
    let mut out = String::new();
    for (chunk_idx, chunk) in data.chunks(16).enumerate() {
        let addr = base_address + (chunk_idx * 16) as u64;
        let mut hex_part = String::new();
        let mut ascii_part = String::new();

        for (i, &b) in chunk.iter().enumerate() {
            if i == 8 {
                hex_part.push(' ');
            }
            hex_part.push_str(&format!("{b:02x} "));
            if b.is_ascii_graphic() || b == b' ' {
                ascii_part.push(b as char);
            } else {
                ascii_part.push('.');
            }
        }

        // Pad short lines
        let missing = 16 - chunk.len();
        if missing > 0 {
            for i in 0..missing {
                if chunk.len() + i == 8 {
                    hex_part.push(' ');
                }
                hex_part.push_str("   ");
            }
        }

        out.push_str(&format!("{addr:#018x}  {hex_part:<49} |{ascii_part}|\n"));
    }
    out
}

/// Write an oversized tool output to a specific subfolder (e.g. `scans/`, `regions/`, `snapshots/`)
/// and enforce a FIFO quota (max 50 files per directory) to prevent disk/context bloat.
pub fn write_output_artifact(subdir: &str, file_name: &str, content: &[u8]) -> std::io::Result<String> {
    let dir = std::path::Path::new(subdir);
    let _ = std::fs::create_dir_all(dir);
    
    // Auto-clean: keep at most 50 files in this directory to avoid disk clutter
    if let Ok(entries) = std::fs::read_dir(dir) {
        let mut files: Vec<(std::time::SystemTime, std::path::PathBuf)> = entries
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
            .filter_map(|e| {
                let path = e.path();
                let modified = e.metadata().and_then(|m| m.modified()).unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                Some((modified, path))
            })
            .collect();

        if files.len() >= 50 {
            files.sort_by_key(|(m, _)| *m);
            // Delete oldest entries down to 40 files
            let to_remove = files.len().saturating_sub(40);
            for (_, path) in files.iter().take(to_remove) {
                let _ = std::fs::remove_file(path);
            }
        }
    }

    let file_path = dir.join(file_name);
    let mut f = std::fs::File::create(&file_path)?;
    use std::io::Write;
    f.write_all(content)?;
    Ok(format!("{subdir}/{file_name}"))
}

// ---------------------------------------------------------------------------
// Universal Tool Dispatchers
// ---------------------------------------------------------------------------


/// Evaluate an address expression against session markers and loaded modules.
pub fn eval_addr_expr(
    session: &SharedSession,
    input: &str,
    mem: Option<&dyn ProcessMemory>,
) -> Result<u64, ToolError> {
    let s = session.lock().map_err(|_| err("session lock poisoned"))?;
    let resolve_marker = |name: &str| s.get_marker(name).map(|m| m.address);
    let resolve_module = |name: &str| {
        if let Some(pid) = s.game_pid() {
            #[cfg(windows)]
            {
                if let Ok(modules) = crate::modinfo::enumerate_windows(pid) {
                    let target = name.to_lowercase();
                    return modules.iter().find(|m| m.name.to_lowercase() == target).map(|m| m.base);
                }
            }
            #[cfg(not(windows))]
            {
                let _ = pid;
            }
        }
        None
    };
    parse_addr_expr_custom(input, mem, &resolve_marker, &resolve_module).map_err(err)
}

/// Execute a memory read operation.
pub fn execute_read(
    session: &SharedSession,
    ctx: &ClientContext,
    mem: &dyn ProcessMemory,
    args: ReadArgs,
) -> Result<ToolResult, ToolError> {
    let target_addr = eval_addr_expr(session, &args.address, Some(mem))?;
    let vt_str = args.value_type.as_deref().unwrap_or("hex").trim().to_lowercase();

    match vt_str.as_str() {
        "hex" | "bytes" => {
            let len = args.len.unwrap_or(16);
            let bytes = mem.read(target_addr, len).map_err(|e| err(e.to_string()))?;
            if bytes.iter().all(|&b| b == 0) {
                let msg = format!("all 0s ({} bytes @ {target_addr:#x})", bytes.len());
                return Ok(ToolResult::with_data(
                    msg,
                    serde_json::json!({
                        "address": target_addr,
                        "all_zero": true,
                        "bytes_read": bytes.len(),
                        "client_id": ctx.id,
                    }),
                ));
            }
            if bytes.len() > 512 {
                let file_name = format!("read_hex_{target_addr:#x}_{}.bin", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0));
                let preview = bytes[..64].iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
                let rel_path = write_output_artifact("snapshots", &file_name, &bytes).unwrap_or_else(|_| format!("snapshots/{file_name}"));
                let text = format!("{preview}... [{} bytes total, saved to {rel_path}]", bytes.len());
                Ok(ToolResult::with_data(
                    text,
                    serde_json::json!({
                        "address": target_addr,
                        "bytes_read": bytes.len(),
                        "snapshot_file": rel_path,
                        "client_id": ctx.id,
                    }),
                ))
            } else {
                let hex = bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
                Ok(ToolResult::with_data(
                    hex.clone(),
                    serde_json::json!({
                        "address": target_addr,
                        "hex": hex,
                        "bytes_read": bytes.len(),
                        "client_id": ctx.id,
                    }),
                ))
            }
        }
        "ptr" | "pointer" => {
            let val = read_u64(mem, target_addr).map_err(err)?;
            let ptr_val: u64 = val.parse().unwrap_or(0);
            let text = format!("{ptr_val:#018x} ({val})");
            Ok(ToolResult::with_data(
                text.clone(),
                serde_json::json!({
                    "address": target_addr,
                    "ptr": format!("{ptr_val:#018x}"),
                    "raw": val,
                    "client_id": ctx.id,
                }),
            ))
        }
        "cstr" | "string" => {
            let max_len = args.len.unwrap_or(256);
            let val = read_cstr(mem, target_addr, max_len).map_err(err)?;
            Ok(ToolResult::with_data(
                val.clone(),
                serde_json::json!({
                    "address": target_addr,
                    "value": val,
                    "value_type": "cstr",
                    "client_id": ctx.id,
                }),
            ))
        }
        other => {
            let vt = parse_value_type(other).map_err(err)?;
            let read_len = vt.size();
            let bytes = mem.read(target_addr, read_len).map_err(|e| err(e.to_string()))?;
            let formatted = format_value(&bytes, vt);
            Ok(ToolResult::with_data(
                formatted.clone(),
                serde_json::json!({
                    "address": target_addr,
                    "value": formatted,
                    "value_type": other,
                    "bytes_read": read_len,
                    "client_id": ctx.id,
                }),
            ))
        }
    }
}

/// Execute a direct memory write operation (with automatic undo snapshotting per D8).
pub fn execute_write(
    session: &SharedSession,
    ctx: &ClientContext,
    mem: &dyn ProcessMemory,
    args: WriteArgs,
) -> Result<ToolResult, ToolError> {
    let target_addr = eval_addr_expr(session, &args.address, Some(mem))?;

    let (bytes, desc) = if let Some(val_str) = &args.value {
        let vt_str = args.value_type.as_deref().unwrap_or("i32");
        let vt = parse_value_type(vt_str).map_err(err)?;
        let data = parse_value_bytes(val_str, vt).map_err(err)?;
        (data, format!("write {val_str} ({vt_str}) @ {target_addr:#x}"))
    } else if let Some(hex_data) = &args.data {
        let data = parse_hex_bytes(hex_data).map_err(err)?;
        if data.is_empty() {
            return Err(err("write data cannot be empty"));
        }
        (data.clone(), format!("write {} byte(s) @ {target_addr:#x}", data.len()))
    } else {
        return Err(err("either 'value' (with value_type) or 'data' (hex) must be provided"));
    };

    // Pre-mutation snapshot for automatic undo
    let original = mem.read(target_addr, bytes.len()).unwrap_or_default();

    // Perform direct write
    mem.write(target_addr, &bytes).map_err(|e| err(format!("write failed: {e}")))?;

    let mut s = session.lock().map_err(|_| err("session lock poisoned"))?;
    let undo_id = if !original.is_empty() {
        Some(s.record_undo(target_addr, original, desc.clone()))
    } else {
        None
    };

    s.log_activity(&ctx.id, format!("wrote {} byte(s) @ {target_addr:#x} (undo: {:?})", bytes.len(), undo_id));

    let undo_msg = match undo_id {
        Some(id) => format!(" (undo id #{id} recorded)"),
        None => String::new(),
    };

    Ok(ToolResult::with_data(
        format!("successfully applied {desc}{undo_msg}"),
        serde_json::json!({
            "address": target_addr,
            "bytes_written": bytes.len(),
            "undo_id": undo_id,
            "client_id": ctx.id,
        }),
    ))
}

/// Execute a memory dump for struct / class reversal.
pub fn execute_dump(
    session: &SharedSession,
    ctx: &ClientContext,
    mem: &dyn ProcessMemory,
    args: DumpArgs,
) -> Result<ToolResult, ToolError> {
    let target_addr = eval_addr_expr(session, &args.address, Some(mem))?;
    let data = mem.read(target_addr, args.len).map_err(|e| err(format!("dump failed: {e}")))?;

    if data.iter().all(|&b| b == 0) {
        return Ok(ToolResult::with_data(
            format!("all 0s ({} bytes @ {target_addr:#x})", data.len()),
            serde_json::json!({
                "address": target_addr,
                "all_zero": true,
                "bytes_read": data.len(),
                "client_id": ctx.id,
            }),
        ));
    }

    if data.len() > 1024 {
        let _ = std::fs::create_dir_all("snapshots");
        let file_name = format!("dump_{target_addr:#x}_{}.txt", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0));
        let file_path = format!("snapshots/{file_name}");
        let full_text = format_dump(target_addr, &data);
        if let Ok(mut f) = std::fs::File::create(&file_path) {
            use std::io::Write;
            let _ = f.write_all(full_text.as_bytes());
        }
        let preview = format_dump(target_addr, &data[..256]);
        let text = format!("{preview}\n... [{} bytes total, full dump saved to snapshots/{file_name}]", data.len());
        Ok(ToolResult::with_data(
            text,
            serde_json::json!({
                "address": target_addr,
                "bytes_read": data.len(),
                "snapshot_file": file_name,
                "client_id": ctx.id,
            }),
        ))
    } else {
        let text = format_dump(target_addr, &data);
        Ok(ToolResult::with_data(
            text,
            serde_json::json!({
                "address": target_addr,
                "bytes_read": data.len(),
                "client_id": ctx.id,
            }),
        ))
    }
}

/// Execute a multi-field typed struct inspection.
pub fn execute_dump_struct(
    session: &SharedSession,
    ctx: &ClientContext,
    mem: &dyn ProcessMemory,
    args: DumpStructArgs,
) -> Result<ToolResult, ToolError> {
    let address = eval_addr_expr(session, &args.address, Some(mem))?;
    if args.fields.is_empty() {
        return Err(err("dump_struct requires at least one field"));
    }

    let mut lines = Vec::with_capacity(args.fields.len());
    let mut field_results = Vec::new();

    for f in &args.fields {
        if f.name.trim().is_empty() {
            return Err(err("field name cannot be empty"));
        }
        let field_addr = (address as i64).wrapping_add(f.offset) as u64;
        let result = match f.value_type.trim().to_lowercase().as_str() {
            "i8" => read_i8(mem, field_addr),
            "u8" => read_u8(mem, field_addr),
            "i16" => read_i16(mem, field_addr),
            "u16" => read_u16(mem, field_addr),
            "i32" => read_i32(mem, field_addr),
            "u32" => read_u32(mem, field_addr),
            "i64" => read_i64(mem, field_addr),
            "u64" => read_u64(mem, field_addr),
            "f32" => read_f32_val(mem, field_addr),
            "f64" => read_f64_val(mem, field_addr),
            "ptr" => read_u64(mem, field_addr),
            "cstr" => {
                let max_len = f.len.unwrap_or(256).max(1);
                read_cstr(mem, field_addr, max_len).map(|s| format!("{s:?}"))
            }
            "bytes" => {
                let n = f.len.unwrap_or(16).max(1);
                mem.read(field_addr, n)
                    .map(|d| format!("[{}] {}", d.len(), d.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")))
                    .map_err(|e| e.to_string())
            }
            other => Err(format!("unknown field type '{other}'")),
        };

        match &result {
            Ok(v) => {
                lines.push(format!("{:+5} {:<6} {}: {}", f.offset, f.value_type, f.name, v));
                field_results.push(serde_json::json!({
                    "name": f.name,
                    "offset": f.offset,
                    "address": field_addr,
                    "value_type": f.value_type,
                    "value": v,
                }));
            }
            Err(e) => {
                lines.push(format!("{:+5} {:<6} {}: <error: {e}>", f.offset, f.value_type, f.name));
                field_results.push(serde_json::json!({
                    "name": f.name,
                    "offset": f.offset,
                    "address": field_addr,
                    "value_type": f.value_type,
                    "error": e,
                }));
            }
        }
    }

    let mut text = format!("struct @ {address:#018x} ({} field(s))\n", args.fields.len());
    text.push_str(&lines.join("\n"));

    Ok(ToolResult::with_data(
        text,
        serde_json::json!({
            "base_address": address,
            "fields": field_results,
            "client_id": ctx.id,
        }),
    ))
}

/// Execute a large memory range snapshot to disk.
pub fn execute_snapshot(
    session: &SharedSession,
    ctx: &ClientContext,
    mem: &dyn ProcessMemory,
    args: SnapshotArgs,
) -> Result<ToolResult, ToolError> {
    let start = eval_addr_expr(session, &args.start, Some(mem))?;
    let len = match (args.end.as_deref(), args.len) {
        (Some(end_str), None) => {
            let end = eval_addr_expr(session, end_str, Some(mem))?;
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
        (Some(_), Some(_)) => return Err(err("specify either 'end' or 'len', but not both")),
        (None, None) => return Err(err("must specify either 'end' or 'len'")),
    };

    let file_name = args.name.unwrap_or_else(|| format!("snap_0x{start:08x}_{len}.bin"));
    let snap_dir = Path::new("snapshots");
    let file_path = snap_dir.join(&file_name);

    let bytes_written = crate::memory::dump_range_to_file(mem, start, len, &file_path, args.max_len)
        .map_err(|e| err(format!("snapshot dump failed: {e}")))?;

    if let Ok(mut s) = session.lock() {
        s.log_activity(&ctx.id, format!("created snapshot '{}' ({} bytes)", file_path.display(), bytes_written));
    }

    Ok(ToolResult::with_data(
        format!("created snapshot '{}' ({} bytes at {start:#x})", file_path.display(), bytes_written),
        serde_json::json!({
            "file_name": file_name,
            "path": file_path.to_string_lossy(),
            "start": start,
            "len": len,
            "bytes_written": bytes_written,
            "client_id": ctx.id,
        }),
    ))
}

/// Execute disassembly of memory instructions.
pub fn execute_disassemble(
    session: &SharedSession,
    ctx: &ClientContext,
    mem: &dyn ProcessMemory,
    args: DisassembleArgs,
) -> Result<ToolResult, ToolError> {
    let address = eval_addr_expr(session, &args.address, Some(mem))?;
    let data = mem.read(address, args.len).map_err(|e| err(format!("disassemble read failed: {e}")))?;
    let lines = crate::disasm::disassemble(address, &data, Some(args.max_instructions));

    Ok(ToolResult::with_data(
        lines.join("\n"),
        serde_json::json!({
            "address": address,
            "instructions": lines,
            "client_id": ctx.id,
        }),
    ))
}

/// Execute string allocation inside the target process memory.
pub fn execute_allocate_string(
    session: &SharedSession,
    ctx: &ClientContext,
    mem: &dyn ProcessMemory,
    args: AllocateStringArgs,
) -> Result<ToolResult, ToolError> {
    let kind = args.kind.trim().to_lowercase();
    let is_rust = kind == "rust";
    let is_c_like = matches!(kind.as_str(), "c" | "json" | "yaml" | "xml" | "js" | "config");

    if !is_rust && !is_c_like {
        return Err(err(format!("unknown string kind '{kind}' (expected 'c', 'rust', 'json', 'yaml', 'xml', 'js', or 'config')")));
    }

    let mut bytes = if let Some(content) = args.content {
        content.into_bytes()
    } else if let Some(size) = args.size {
        let fill = args.fill_byte.unwrap_or(0);
        vec![fill; size]
    } else {
        return Err(err("either 'content' or 'size' must be provided for allocate_string"));
    };

    if is_c_like && !bytes.ends_with(&[0]) {
        bytes.push(0);
    }
    let len = bytes.len();

    #[cfg(windows)]
    let alloc_addr = {
        use windows_sys::Win32::System::Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
        let pid = {
            let s = session.lock().map_err(|_| err("session lock poisoned"))?;
            s.game_pid().ok_or_else(|| err("no attached game process to allocate string in"))?
        };
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
            return Err(err("failed to open process for allocation"));
        }
        let ptr = unsafe {
            VirtualAllocEx(proc_handle, std::ptr::null(), len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        };
        unsafe { windows_sys::Win32::Foundation::CloseHandle(proc_handle); }
        if ptr.is_null() {
            return Err(err("VirtualAllocEx failed in target process"));
        }
        ptr as u64
    };

    #[cfg(not(windows))]
    {
        let _ = session;
        let _ = ctx;
        let _ = mem;
        let _ = len;
        return Err(err("string allocation is only supported on Windows"));
    }

    #[cfg(windows)]
    {
        mem.write(alloc_addr, &bytes).map_err(|e| err(format!("failed to write string bytes: {e}")))?;

        if let Ok(mut s) = session.lock() {
            s.log_activity(&ctx.id, format!("allocated string ({kind}, {len} bytes) at {alloc_addr:#x}"));
            s.record_allocation(alloc_addr, len, format!("string ({kind})"), args.marker.clone());
            if let Some(m) = &args.marker {
                let _ = s.set_marker_full(m, alloc_addr, Some(len), crate::session::MarkerKind::Buffer, None, Some(&format!("Allocated string ('{kind}', {len} bytes)")));
            }
        }

        Ok(ToolResult::with_data(
            format!("allocated string at {alloc_addr:#x}"),
            serde_json::json!({
                "ptr": format!("{alloc_addr:#x}"),
                "address": alloc_addr,
                "len": len,
                "kind": kind,
                "client_id": ctx.id,
            }),
        ))
    }
}

/// Execute arbitrary memory buffer allocation in target process.
pub fn execute_allocate_memory(
    session: &SharedSession,
    ctx: &ClientContext,
    mem: &dyn ProcessMemory,
    args: AllocateMemoryArgs,
) -> Result<ToolResult, ToolError> {
    if args.size == 0 {
        return Err(err("size must be greater than 0"));
    }
    let size = args.size;

    #[cfg(windows)]
    let (alloc_addr, prot_flags) = {
        use windows_sys::Win32::System::Memory::{
            VirtualAllocEx, MEM_COMMIT, MEM_RESERVE,
            PAGE_READWRITE, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ, PAGE_READONLY
        };
        let prot = match args.permissions.as_deref().unwrap_or("rw").trim().to_lowercase().as_str() {
            "rwx" | "wx" | "exec_rw" => PAGE_EXECUTE_READWRITE,
            "rx" | "exec_r" => PAGE_EXECUTE_READ,
            "r" | "ro" => PAGE_READONLY,
            _ => PAGE_READWRITE,
        };

        let pid = {
            let s = session.lock().map_err(|_| err("session lock poisoned"))?;
            s.game_pid().ok_or_else(|| err("no attached game process to allocate memory in"))?
        };
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
            return Err(err("failed to open process for allocation"));
        }
        let ptr = unsafe {
            VirtualAllocEx(proc_handle, std::ptr::null(), size, MEM_COMMIT | MEM_RESERVE, prot)
        };
        unsafe { windows_sys::Win32::Foundation::CloseHandle(proc_handle); }
        if ptr.is_null() {
            return Err(err("VirtualAllocEx failed in target process"));
        }
        (ptr as u64, prot)
    };

    #[cfg(not(windows))]
    {
        let _ = session;
        let _ = ctx;
        let _ = mem;
        let _ = size;
        return Err(err("memory allocation is only supported on Windows"));
    }

    #[cfg(windows)]
    {
        if let Some(fill) = args.fill_byte {
            let buf = vec![fill; size];
            let _ = mem.write(alloc_addr, &buf);
        }

        if let Ok(mut s) = session.lock() {
            s.log_activity(&ctx.id, format!("allocated memory ({size} bytes) at {alloc_addr:#x}"));
            s.record_allocation(alloc_addr, size, "raw memory buffer", args.marker.clone());
            if let Some(m) = &args.marker {
                let _ = s.set_marker_full(m, alloc_addr, Some(size), crate::session::MarkerKind::Buffer, None, Some(&format!("Allocated memory buffer ({size} bytes)")));
            }
        }

        Ok(ToolResult::with_data(
            format!("allocated {size} bytes at {alloc_addr:#x}"),
            serde_json::json!({
                "ptr": format!("{alloc_addr:#x}"),
                "address": alloc_addr,
                "size": size,
                "client_id": ctx.id,
            }),
        ))
    }
}

/// Free a previously allocated memory buffer or string in target process.
pub fn execute_free_memory(
    session: &SharedSession,
    ctx: &ClientContext,
    mem: &dyn ProcessMemory,
    args: FreeMemoryArgs,
) -> Result<ToolResult, ToolError> {
    let target_addr = eval_addr_expr(session, &args.address, Some(mem))?;
    if target_addr == 0 {
        return Err(err("cannot free null address 0x0"));
    }

    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Memory::{VirtualFreeEx, MEM_RELEASE, MEM_DECOMMIT};
        let pid = {
            let s = session.lock().map_err(|_| err("session lock poisoned"))?;
            s.game_pid().ok_or_else(|| err("no attached game process to free memory in"))?
        };
        let proc_handle = unsafe {
            windows_sys::Win32::System::Threading::OpenProcess(
                windows_sys::Win32::System::Threading::PROCESS_VM_OPERATION,
                0,
                pid,
            )
        };
        if proc_handle.is_null() {
            return Err(err("failed to open process to free memory"));
        }

        // MEM_RELEASE requires size to be 0
        let (free_size, free_type) = if let Some(s) = args.size {
            (s, MEM_DECOMMIT)
        } else {
            (0, MEM_RELEASE)
        };

        let res = unsafe {
            VirtualFreeEx(proc_handle, target_addr as *mut _, free_size, free_type)
        };
        unsafe { windows_sys::Win32::Foundation::CloseHandle(proc_handle); }

        if res == 0 {
            return Err(err(format!("VirtualFreeEx failed for address {target_addr:#x}")));
        }

        if let Ok(mut s) = session.lock() {
            s.remove_allocation(target_addr);
            s.log_activity(&ctx.id, format!("freed memory at {target_addr:#x}"));
        }

        Ok(ToolResult::with_data(
            format!("freed memory at {target_addr:#x}"),
            serde_json::json!({
                "freed_address": target_addr,
                "address": format!("{target_addr:#x}"),
                "client_id": ctx.id,
            }),
        ))
    }

    #[cfg(not(windows))]
    {
        let _ = session;
        let _ = ctx;
        let _ = target_addr;
        Err(err("free_memory is only supported on Windows"))
    }
}

/// Start a new value memory scan within the caller's `ClientContext`.
pub fn execute_scan_start(
    session: &SharedSession,
    ctx: &mut ClientContext,
    mem: &dyn ProcessMemory,
    args: ScanStartArgs,
) -> Result<ToolResult, ToolError> {
    let vt = parse_value_type(&args.value_type).map_err(err)?;
    let alignment = args.alignment.unwrap_or(0);
    let op = match args.max {
        Some(max) => crate::scan::ScanOp::Range {
            min: args.value,
            max,
        },
        None => crate::scan::ScanOp::Exact { value: args.value },
    };

    let regions = {
        let all_regions = mem.regions().map_err(|e| err(format!("regions failed: {e}")))?;
        if let Some(r_name) = &args.region {
            let (r_start, r_end) = {
                let s = session.lock().map_err(|_| err("session lock poisoned"))?;
                if let Some(m) = s.get_marker(r_name) {
                    let end = m.end_address().unwrap_or(m.address.saturating_add(0x1000));
                    (m.address, end)
                } else {
                    drop(s);
                    // Try evaluating as address expression
                    let start = eval_addr_expr(session, r_name, Some(mem))?;
                    (start, start.saturating_add(0x1000))
                }
            };
            let filtered: Vec<_> = all_regions
                .into_iter()
                .filter_map(|mut r| {
                    if r.end <= r_start || r.start >= r_end {
                        None
                    } else {
                        r.start = r.start.max(r_start);
                        r.end = r.end.min(r_end);
                        Some(r)
                    }
                })
                .collect();
            if filtered.is_empty() {
                return Err(err(format!("specified region '{r_name}' ({r_start:#x}..{r_end:#x}) contains no readable memory pages")));
            }
            filtered
        } else {
            all_regions
        }
    };
    let mut scan = crate::scan::Scan::new(vt).with_alignment(alignment);
    scan.first_scan(mem, &regions, op).map_err(|e| err(format!("scan failed: {e}")))?;

    let count = scan.len();
    let top_matches: Vec<(u64, f64)> = scan.matches().iter().take(10).copied().collect();

    // Store active scan in this client context
    ctx.scan = Some(scan);

    if let Ok(mut s) = session.lock() {
        s.log_activity(&ctx.id, format!("started value scan ({:?}): {count} match(es)", vt));
    }

    let mut lines = Vec::new();
    for (a, v) in &top_matches {
        lines.push(format!("{a:#018x} = {v}"));
    }

    let mut text = format!("scan started: {count} match(es) (type: {vt:?})\n");
    text.push_str(&lines.join("\n"));
    if count > 10 {
        text.push_str(&format!("\n... and {} more (use 'scan_status' to view)", count - 10));
    }

    Ok(ToolResult::with_data(
        text,
        serde_json::json!({
            "count": count,
            "value_type": format!("{vt:?}"),
            "top_matches": top_matches.iter().map(|(a, v)| serde_json::json!({ "address": a, "value": v })).collect::<Vec<_>>(),
            "client_id": ctx.id,
        }),
    ))
}

/// Narrow/refine the active value memory scan within the caller's `ClientContext`.
pub fn execute_scan_next(
    session: &SharedSession,
    ctx: &mut ClientContext,
    mem: &dyn ProcessMemory,
    args: ScanNextArgs,
) -> Result<ToolResult, ToolError> {
    use crate::scan::ScanOp;
    let op = match args.op.trim().to_lowercase().as_str() {
        "changed" => ScanOp::Changed,
        "unchanged" => ScanOp::Unchanged,
        "increased" => ScanOp::Increased,
        "decreased" => ScanOp::Decreased,
        "exact" => {
            let v = args.value.ok_or_else(|| err("'exact' requires 'value'"))?;
            ScanOp::Exact { value: v }
        }
        "range" => {
            let min = args.value.ok_or_else(|| err("'range' requires 'value' (min)"))?;
            let max = args.max.ok_or_else(|| err("'range' requires 'max'"))?;
            ScanOp::Range { min, max }
        }
        other => return Err(err(format!("unknown scan op '{other}' (expected changed, unchanged, increased, decreased, exact, range)"))),
    };

    let scan = ctx.scan.as_mut().ok_or_else(|| err("no active scan in this context; run 'scan_start' first"))?;
    scan.refine(mem, op).map_err(|e| err(format!("refine failed: {e}")))?;

    let count = scan.len();
    let vt = scan.value_type();
    let top_matches: Vec<(u64, f64)> = scan.matches().iter().take(10).copied().collect();

    if let Ok(mut s) = session.lock() {
        s.log_activity(&ctx.id, format!("narrowed scan: {count} match(es) remaining"));
    }

    let mut lines = Vec::new();
    for (a, v) in &top_matches {
        lines.push(format!("{a:#018x} = {v}"));
    }

    let mut text = format!("scan refined: {count} match(es) remaining\n");
    text.push_str(&lines.join("\n"));
    if count > 10 {
        text.push_str(&format!("\n... and {} more", count - 10));
    }

    Ok(ToolResult::with_data(
        text,
        serde_json::json!({
            "count": count,
            "value_type": format!("{vt:?}"),
            "top_matches": top_matches.iter().map(|(a, v)| serde_json::json!({ "address": a, "value": v })).collect::<Vec<_>>(),
            "client_id": ctx.id,
        }),
    ))
}

/// Inspect the status and top 10 candidate matches of the active scan.
pub fn execute_scan_status(
    _session: &SharedSession,
    ctx: &ClientContext,
) -> Result<ToolResult, ToolError> {
    let scan = ctx.scan.as_ref().ok_or_else(|| err("no active scan in this context"))?;
    let count = scan.len();
    let vt = scan.value_type();
    let align = scan.alignment();
    let top_matches: Vec<(u64, f64)> = scan.matches().iter().take(10).copied().collect();

    let mut lines = Vec::new();
    for (a, v) in &top_matches {
        lines.push(format!("{a:#018x} = {v}"));
    }

    let mut text = format!("active scan: {count} match(es) (type: {vt:?}, align: {align})\n");
    text.push_str(&lines.join("\n"));
    if count > 10 {
        text.push_str(&format!("\n... and {} more", count - 10));
    }

    Ok(ToolResult::with_data(
        text,
        serde_json::json!({
            "count": count,
            "value_type": format!("{vt:?}"),
            "alignment": align,
            "top_matches": top_matches.iter().map(|(a, v)| serde_json::json!({ "address": a, "value": v })).collect::<Vec<_>>(),
            "client_id": ctx.id,
        }),
    ))
}

/// Batch test-write a value across all matching addresses in the active scan.
pub fn execute_scan_set(
    session: &SharedSession,
    ctx: &ClientContext,
    mem: &dyn ProcessMemory,
    args: ScanSetArgs,
) -> Result<ToolResult, ToolError> {
    let scan = ctx.scan.as_ref().ok_or_else(|| err("no active scan in this context; run 'scan_start' first"))?;
    let matches = scan.matches().to_vec();
    if matches.is_empty() {
        return Err(err("active scan has 0 matches to write to"));
    }

    let vt = if let Some(vt_str) = &args.value_type {
        parse_value_type(vt_str).map_err(err)?
    } else {
        scan.value_type()
    };

    let data = parse_value_bytes(&args.value, vt).map_err(err)?;
    let mut updated = 0;
    let mut undo_ids = Vec::new();

    let mut s = session.lock().map_err(|_| err("session lock poisoned"))?;

    for &(addr, _) in &matches {
        let orig = mem.read(addr, data.len()).unwrap_or_default();
        if mem.write(addr, &data).is_ok() {
            updated += 1;
            if !orig.is_empty() {
                let id = s.record_undo(addr, orig, format!("scan_set {} to {addr:#x}", args.value));
                undo_ids.push(id);
            }
        }
    }

    s.log_activity(&ctx.id, format!("scan_set: wrote {} to {} candidate addresses", args.value, updated));

    Ok(ToolResult::with_data(
        format!("scan_set: successfully wrote '{}' to {} address(es) (recorded {} undo snapshots)", args.value, updated, undo_ids.len()),
        serde_json::json!({
            "updated_count": updated,
            "value": args.value,
            "undo_ids": undo_ids,
            "client_id": ctx.id,
        }),
    ))
}

/// Clear the active scan in the caller's context.
pub fn execute_scan_clear(
    session: &SharedSession,
    ctx: &mut ClientContext,
) -> Result<ToolResult, ToolError> {
    let was_active = ctx.scan.is_some();
    ctx.scan = None;

    if let Ok(mut s) = session.lock() {
        s.log_activity(&ctx.id, "cleared active scan");
    }

    Ok(ToolResult::with_data(
        if was_active { "scan cleared" } else { "no active scan was present" },
        serde_json::json!({
            "cleared": was_active,
            "client_id": ctx.id,
        }),
    ))
}

/// Search readable process memory for an AOB pattern.
pub fn execute_scan_aob(
    session: &SharedSession,
    ctx: &ClientContext,
    mem: &dyn ProcessMemory,
    args: ScanAobArgs,
) -> Result<ToolResult, ToolError> {
    let parsed_pat = crate::aob::parse(&args.pattern);
    if parsed_pat.is_empty() {
        return Err(err("empty or invalid AOB pattern"));
    }

    let regions = {
        let all_regions = mem.regions().map_err(|e| err(format!("regions failed: {e}")))?;
        if let Some(r_name) = &args.region {
            let (r_start, r_end) = {
                let s = session.lock().map_err(|_| err("session lock poisoned"))?;
                if let Some(m) = s.get_marker(r_name) {
                    let end = m.end_address().unwrap_or(m.address.saturating_add(0x1000));
                    (m.address, end)
                } else {
                    drop(s);
                    let start = eval_addr_expr(session, r_name, Some(mem))?;
                    (start, start.saturating_add(0x1000))
                }
            };
            let filtered: Vec<_> = all_regions
                .into_iter()
                .filter_map(|mut r| {
                    if r.end <= r_start || r.start >= r_end {
                        None
                    } else {
                        r.start = r.start.max(r_start);
                        r.end = r.end.min(r_end);
                        Some(r)
                    }
                })
                .collect();
            if filtered.is_empty() {
                return Err(err(format!("specified region '{r_name}' ({r_start:#x}..{r_end:#x}) contains no readable memory pages")));
            }
            filtered
        } else {
            all_regions
        }
    };
    let alignment = args.alignment.unwrap_or(0);
    let mut matches = Vec::new();
    let mut total_bytes = 0u64;
    let mut regions_scanned = 0usize;

    for r in &regions {
        if !r.readable {
            continue;
        }
        let len = (r.end - r.start) as usize;
        if len < parsed_pat.len() {
            continue;
        }
        regions_scanned += 1;
        total_bytes += len as u64;
        let hits = mem.scan_region_aob(r, &parsed_pat, alignment, args.offset);
        matches.extend(hits);
    }

    let count = matches.len();

    if let Some(m) = &args.marker
        && let Some(&first) = matches.first()
            && let Ok(mut s) = session.lock() {
                let _ = s.set_marker(m, first, Some(&format!("AOB match for '{}'", args.pattern)));
            }

    if let Ok(mut s) = session.lock() {
        s.log_activity(&ctx.id, format!("AOB scan '{}': {count} match(es) across {regions_scanned} region(s)", args.pattern));
    }

    let mb_scanned = (total_bytes as f64) / (1024.0 * 1024.0);
    let limit = args.limit.unwrap_or(20);
    let preview_matches: Vec<u64> = matches.iter().copied().take(limit).collect();
    let lines: Vec<String> = preview_matches.iter().map(|m| format!("{m:#018x}")).collect();
    let mut text = format!("{count} match(es) (scanned {regions_scanned} region(s), {mb_scanned:.1} MB)\n");
    text.push_str(&lines.join("\n"));
    
    let mut scan_file = None;
    if count > limit {
        let s_file = format!("aob_scan_{}.json", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0));
        let full_json = serde_json::json!({
            "count": count,
            "pattern": args.pattern,
            "alignment": alignment,
            "matches": matches,
        });
        if let Ok(rel_path) = write_output_artifact("scans", &s_file, full_json.to_string().as_bytes()) {
            scan_file = Some(rel_path.clone());
            text.push_str(&format!("\n... and {} more [full matches saved to {rel_path}]", count - limit));
        } else {
            text.push_str(&format!("\n... and {} more", count - limit));
        }
    }

    Ok(ToolResult::with_data(
        text,
        serde_json::json!({
            "count": count,
            "regions_scanned": regions_scanned,
            "mb_scanned": mb_scanned,
            "matches": preview_matches,
            "scan_file": scan_file,
            "client_id": ctx.id,
        }),
    ))
}

/// Search for pointers referencing a target address.
pub fn execute_scan_pointer(
    session: &SharedSession,
    ctx: &ClientContext,
    mem: &dyn ProcessMemory,
    args: ScanPointerArgs,
) -> Result<ToolResult, ToolError> {
    let address = eval_addr_expr(session, &args.address, Some(mem))?;
    let size = args.size.unwrap_or(8).max(1);
    let lo = address;
    let hi = address.saturating_add(size).saturating_sub(1);

    let regions = mem.regions().map_err(|e| err(format!("regions failed: {e}")))?;
    let matches = crate::pointer::reverse_scan(mem, &regions, lo, hi)
        .map_err(|e| err(format!("pointer_scan failed: {e}")))?;

    let count = matches.len();
    let limit = args.limit.unwrap_or(50);
    let preview_matches: Vec<(u64, u64)> = matches.iter().copied().take(limit).collect();
    let lines: Vec<String> = preview_matches.iter().map(|(a, p)| format!("{a:#018x} -> {p:#018x}")).collect();
    let mut text = format!("{count} referrer(s)\n");
    text.push_str(&lines.join("\n"));
    
    let mut scan_file = None;
    if count > limit {
        let s_file = format!("pointer_scan_{address:#x}_{}.json", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0));
        let full_json = serde_json::json!({
            "count": count,
            "target": address,
            "referrers": matches.iter().map(|(a, p)| serde_json::json!({ "address": a, "points_to": p })).collect::<Vec<_>>(),
        });
        if let Ok(rel_path) = write_output_artifact("scans", &s_file, full_json.to_string().as_bytes()) {
            scan_file = Some(rel_path.clone());
            text.push_str(&format!("\n... and {} more [full results saved to {rel_path}]", count - limit));
        } else {
            text.push_str(&format!("\n... and {} more", count - limit));
        }
    }

    if let Ok(mut s) = session.lock() {
        s.log_activity(&ctx.id, format!("pointer scan for {address:#x}: {count} referrer(s)"));
    }

    Ok(ToolResult::with_data(
        text,
        serde_json::json!({
            "count": count,
            "target": address,
            "referrers": preview_matches.iter().map(|(a, p)| serde_json::json!({ "address": a, "points_to": p })).collect::<Vec<_>>(),
            "scan_file": scan_file,
            "client_id": ctx.id,
        }),
    ))
}

/// Search readable process memory for regular expression byte matches using ripgrep's regex engine.
pub fn execute_scan_rgrep(
    session: &SharedSession,
    ctx: &ClientContext,
    mem: &dyn ProcessMemory,
    args: ScanRgrepArgs,
) -> Result<ToolResult, ToolError> {
    let re = regex::bytes::RegexBuilder::new(&args.pattern)
        .unicode(false)
        .build()
        .map_err(|e| err(format!("invalid regex pattern '{}': {e}", args.pattern)))?;

    let regions = {
        let all_regions = mem.regions().map_err(|e| err(format!("regions failed: {e}")))?;
        if let Some(r_name) = &args.region {
            let (r_start, r_end) = {
                let s = session.lock().map_err(|_| err("session lock poisoned"))?;
                if let Some(m) = s.get_marker(r_name) {
                    let end = m.end_address().unwrap_or(m.address.saturating_add(0x1000));
                    (m.address, end)
                } else {
                    drop(s);
                    let start = eval_addr_expr(session, r_name, Some(mem))?;
                    (start, start.saturating_add(0x1000))
                }
            };
            let filtered: Vec<_> = all_regions
                .into_iter()
                .filter_map(|mut r| {
                    if r.end <= r_start || r.start >= r_end {
                        None
                    } else {
                        r.start = r.start.max(r_start);
                        r.end = r.end.min(r_end);
                        Some(r)
                    }
                })
                .collect();
            if filtered.is_empty() {
                return Err(err(format!("specified region '{r_name}' ({r_start:#x}..{r_end:#x}) contains no readable memory pages")));
            }
            filtered
        } else {
            all_regions
        }
    };

    let alignment = args.alignment.unwrap_or(0);
    let mut matches: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut total_bytes = 0u64;
    let mut regions_scanned = 0usize;

    for r in &regions {
        if !r.readable {
            continue;
        }
        let len = (r.end - r.start) as usize;
        if len == 0 {
            continue;
        }
        regions_scanned += 1;
        total_bytes += len as u64;
        let hits = mem.scan_region_regex(r, &re, alignment);
        matches.extend(hits);
    }

    let count = matches.len();

    if let Some(m) = &args.marker
        && let Some((first_addr, _)) = matches.first()
            && let Ok(mut s) = session.lock() {
                let _ = s.set_marker(m, *first_addr, Some(&format!("Regex match for '{}'", args.pattern)));
            }

    if let Ok(mut s) = session.lock() {
        s.log_activity(&ctx.id, format!("rgrep scan '{}': {count} match(es) across {regions_scanned} region(s)", args.pattern));
    }

    let mb_scanned = (total_bytes as f64) / (1024.0 * 1024.0);
    let limit = args.limit.unwrap_or(20);
    let preview_matches: Vec<&(u64, Vec<u8>)> = matches.iter().take(limit).collect();
    
    let mut lines = Vec::new();
    for (addr, bytes) in &preview_matches {
        let hex_str = bytes.iter().take(16).map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
        let ascii_str: String = bytes.iter().take(32).map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' }).collect();
        lines.push(format!("{addr:#018x}: [{hex_str}] \"{ascii_str}\""));
    }

    let mut text = format!("{count} match(es) (scanned {regions_scanned} region(s), {mb_scanned:.1} MB)\n");
    text.push_str(&lines.join("\n"));

    let mut scan_file = None;
    if count > limit {
        let s_file = format!("rgrep_scan_{}.json", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0));
        let full_json = serde_json::json!({
            "count": count,
            "pattern": args.pattern,
            "alignment": alignment,
            "matches": matches.iter().map(|(a, b)| serde_json::json!({
                "address": format!("{a:#x}"),
                "bytes": b.iter().map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join(" "),
            })).collect::<Vec<_>>(),
        });
        if let Ok(rel_path) = write_output_artifact("scans", &s_file, full_json.to_string().as_bytes()) {
            scan_file = Some(rel_path.clone());
            text.push_str(&format!("\n... and {} more [full matches saved to {rel_path}]", count - limit));
        } else {
            text.push_str(&format!("\n... and {} more", count - limit));
        }
    }

    Ok(ToolResult::with_data(
        text,
        serde_json::json!({
            "count": count,
            "regions_scanned": regions_scanned,
            "mb_scanned": mb_scanned,
            "matches": preview_matches.iter().map(|(a, b)| serde_json::json!({
                "address": a,
                "len": b.len(),
            })).collect::<Vec<_>>(),
            "scan_file": scan_file,
            "client_id": ctx.id,
        }),
    ))
}


/// Execute a pointer chase operation.
pub fn execute_pointer_chase(
    session: &SharedSession,
    ctx: &ClientContext,
    mem: &dyn ProcessMemory,
    args: PointerChaseArgs,
) -> Result<ToolResult, ToolError> {
    let base = eval_addr_expr(session, &args.base, Some(mem))?;
    // Check if the base expression resolves to an Object-kind marker. If so,
    // skip the initial dereference — the base IS the object instance.
    let base_is_object = {
        let raw = args.base.trim().trim_start_matches('$');
        session.lock().ok()
            .and_then(|s| s.get_marker(raw).map(|m| m.kind == crate::session::MarkerKind::Object))
            .unwrap_or(false)
    };
    let mut offsets = Vec::new();
    for o in &args.offsets {
        offsets.push(eval_addr_expr(session, o, Some(mem))?)
    }

    let hops = if base_is_object {
        crate::pointer::chase_object(mem, base, &offsets).map_err(|e| err(e.to_string()))?
    } else {
        crate::pointer::chase(mem, base, &offsets).map_err(|e| err(e.to_string()))?
    };
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

    let final_addr = hops.last().copied().unwrap_or(base);
    let mode_note = if base_is_object { " (object mode: no initial deref)" } else { "" };

    Ok(ToolResult::with_data(
        format!("{}{}", lines.join("\n"), mode_note),
        serde_json::json!({
            "base": base,
            "base_is_object": base_is_object,
            "hops": hops,
            "resolved_address": final_addr,
            "client_id": ctx.id,
        }),
    ))
}

/// Set a labeled marker in the session.
pub fn execute_set_marker(
    session: &SharedSession,
    ctx: &ClientContext,
    mem: Option<&dyn ProcessMemory>,
    args: SetMarkerArgs,
) -> Result<ToolResult, ToolError> {
    let target_addr = eval_addr_expr(session, &args.address, mem)?;
    let kind = match args.kind.as_deref() {
        Some("object") => crate::session::MarkerKind::Object,
        Some("buffer") => crate::session::MarkerKind::Buffer,
        Some("code")   => crate::session::MarkerKind::Code,
        _              => crate::session::MarkerKind::Pointer,
    };
    let mut s = session.lock().map_err(|_| err("session lock poisoned"))?;
    s.set_marker_full(&args.label, target_addr, args.size, kind, args.struct_type.clone(), args.note.as_deref()).map_err(err)?;
    let size_msg = match args.size {
        Some(sz) => format!(" (region: {target_addr:#x}..{:#x}, {sz:#x} bytes)", target_addr.saturating_add(sz as u64)),
        None => String::new(),
    };
    let kind_msg = if kind != crate::session::MarkerKind::Pointer {
        format!(" [{kind:?}]")
    } else {
        String::new()
    };
    s.log_activity(&ctx.id, format!("saved marker '${}' = {target_addr:#x}{size_msg}{kind_msg}", args.label));

    Ok(ToolResult::with_data(
        format!("saved marker '${}' = {target_addr:#x}{size_msg}{kind_msg}", args.label),
        serde_json::json!({
            "label": args.label,
            "address": target_addr,
            "size": args.size,
            "kind": format!("{kind:?}").to_lowercase(),
            "struct_type": args.struct_type,
            "end_address": args.size.map(|sz| target_addr.saturating_add(sz as u64)),
            "client_id": ctx.id,
        }),
    ))
}

/// Retrieve a saved marker by label.
pub fn execute_get_marker(
    session: &SharedSession,
    ctx: &ClientContext,
    args: GetMarkerArgs,
) -> Result<ToolResult, ToolError> {
    let s = session.lock().map_err(|_| err("session lock poisoned"))?;
    match s.get_marker(&args.label) {
        Some(m) => {
            let note = m.note.as_deref().unwrap_or("");
            let region_str = match m.size {
                Some(sz) => format!("..{:#x} (+{sz:#x})", m.address.saturating_add(sz as u64)),
                None => String::new(),
            };
            let kind_str = match m.kind {
                crate::session::MarkerKind::Pointer => String::new(),
                crate::session::MarkerKind::Object  => " [object]".to_string(),
                crate::session::MarkerKind::Buffer  => " [buffer]".to_string(),
                crate::session::MarkerKind::Code    => " [code]".to_string(),
            };
            let type_str = m.struct_type.as_deref().map(|t| format!(" <{t}>")).unwrap_or_default();
            let text = format!("{} = {:#018x}{}{}{}{}", m.label, m.address, region_str, kind_str, type_str,
                if note.is_empty() { String::new() } else { format!("  ({note})") });
            Ok(ToolResult::with_data(
                text,
                serde_json::json!({
                    "label": m.label,
                    "address": m.address,
                    "size": m.size,
                    "kind": format!("{:?}", m.kind).to_lowercase(),
                    "struct_type": m.struct_type,
                    "end_address": m.end_address(),
                    "note": m.note,
                    "client_id": ctx.id,
                }),
            ))
        }
        None => Err(err(format!("marker '{}' not found", args.label))),
    }
}

/// List all saved markers in the session.
pub fn execute_list_markers(
    session: &SharedSession,
    ctx: &ClientContext,
) -> Result<ToolResult, ToolError> {
    let s = session.lock().map_err(|_| err("session lock poisoned"))?;
    let markers = s.list_markers();
    if markers.is_empty() {
        return Ok(ToolResult::with_data(
            "(no markers)",
            serde_json::json!({ "markers": [], "client_id": ctx.id }),
        ));
    }
    let lines: Vec<String> = markers
        .iter()
        .map(|m| {
            let note = m.note.as_deref().unwrap_or("");
            let region_str = match m.size {
                Some(sz) => format!("..{:#x} (+{sz:#x})", m.address.saturating_add(sz as u64)),
                None => String::new(),
            };
            let kind_str = match m.kind {
                crate::session::MarkerKind::Pointer => String::new(),
                crate::session::MarkerKind::Object  => " [object]".to_string(),
                crate::session::MarkerKind::Buffer  => " [buffer]".to_string(),
                crate::session::MarkerKind::Code    => " [code]".to_string(),
            };
            let type_str = m.struct_type.as_deref().map(|t| format!(" <{t}>")).unwrap_or_default();
            format!("{:<20} {:#018x}{}{}{}{}", m.label, m.address, region_str, kind_str, type_str,
                if note.is_empty() { String::new() } else { format!("  ({note})") })
        })
        .collect();

    Ok(ToolResult::with_data(
        lines.join("\n"),
        serde_json::json!({
            "markers": markers.iter().map(|m| serde_json::json!({
                "label": m.label,
                "address": m.address,
                "size": m.size,
                "kind": format!("{:?}", m.kind).to_lowercase(),
                "struct_type": m.struct_type,
                "end_address": m.end_address(),
                "note": m.note,
            })).collect::<Vec<_>>(),
            "client_id": ctx.id,
        }),
    ))
}

/// Remove a saved marker by label.
pub fn execute_remove_marker(
    session: &SharedSession,
    ctx: &ClientContext,
    args: RemoveMarkerArgs,
) -> Result<ToolResult, ToolError> {
    let mut s = session.lock().map_err(|_| err("session lock poisoned"))?;
    match s.remove_marker(&args.label) {
        Some(m) => {
            s.log_activity(&ctx.id, format!("removed marker '${}' ({:#018x})", m.label, m.address));
            Ok(ToolResult::with_data(
                format!("removed marker '${}' ({:#018x})", m.label, m.address),
                serde_json::json!({
                    "label": m.label,
                    "address": m.address,
                    "client_id": ctx.id,
                }),
            ))
        }
        None => Err(err(format!("marker '{}' not found", args.label))),
    }
}

/// Inspect the undo log for a specific entry or the most recent mutation.
pub fn execute_undo_info(
    session: &SharedSession,
    ctx: &ClientContext,
    args: UndoInfoArgs,
) -> Result<ToolResult, ToolError> {
    let s = session.lock().map_err(|_| err("session lock poisoned"))?;
    let entry = match args.id {
        Some(id) => s.get_undo(id),
        None => s.peek_undo_last(),
    };
    match entry {
        Some(e) => Ok(ToolResult::with_data(
            format!("undo #{}: {} @ {:#018x} ({} original byte(s))", e.id, e.description, e.address, e.original_bytes.len()),
            serde_json::json!({
                "id": e.id,
                "description": e.description,
                "address": e.address,
                "bytes_len": e.original_bytes.len(),
                "client_id": ctx.id,
            }),
        )),
        None => Err(err("no undo entry found")),
    }
}

/// Revert a mutation directly by undo ID or the most recent mutation.
pub fn execute_undo_revert(
    session: &SharedSession,
    ctx: &ClientContext,
    mem: &dyn ProcessMemory,
    args: UndoRevertArgs,
) -> Result<ToolResult, ToolError> {
    let entry = {
        let s = session.lock().map_err(|_| err("session lock poisoned"))?;
        s.get_undo(args.id).cloned()
    };
    let entry = entry.ok_or_else(|| err(format!("undo entry #{} not found", args.id)))?;

    // Write back original bytes
    mem.write(entry.address, &entry.original_bytes)
        .map_err(|e| err(format!("failed to revert memory at {:#x}: {e}", entry.address)))?;

    let mut s = session.lock().map_err(|_| err("session lock poisoned"))?;
    s.pop_undo(entry.id);
    s.log_activity(&ctx.id, format!("reverted undo #{}: {}", entry.id, entry.description));

    Ok(ToolResult::with_data(
        format!("successfully reverted undo #{}: {} (restored {} bytes @ {:#x})", entry.id, entry.description, entry.original_bytes.len(), entry.address),
        serde_json::json!({
            "id": entry.id,
            "address": entry.address,
            "restored_bytes": entry.original_bytes.len(),
            "client_id": ctx.id,
        }),
    ))
}

/// Add a cheat to the session.
pub fn execute_add_cheat(
    session: &SharedSession,
    ctx: &ClientContext,
    mem: Option<&dyn ProcessMemory>,
    args: AddCheatArgs,
) -> Result<ToolResult, ToolError> {
    let cheat_kind = match args.kind.to_lowercase().as_str() {
        "value" => {
            let addr_str = args.address.ok_or_else(|| err("value cheat requires 'address'"))?;
            let target_addr = eval_addr_expr(session, &addr_str, mem)?;
            let vt = parse_value_type(args.value_type.as_deref().unwrap_or("i32")).map_err(err)?;
            CheatKind::Value {
                address: target_addr,
                value_type: vt,
                address_expr: Some(addr_str),
            }
        }
        other => return Err(err(format!("unsupported cheat kind: '{other}' (expected 'value')"))),
    };

    let mut s = session.lock().map_err(|_| err("session lock poisoned"))?;
    let is_hidden = args.hidden.unwrap_or(false);
    let id = s.add_cheat_group(&args.label, cheat_kind, args.group.as_deref(), args.hotkey.as_deref(), is_hidden, args.note.as_deref());
    let group_str = match &args.group {
        Some(g) => format!(" [group: '{g}']"),
        None => String::new(),
    };
    s.log_activity(&ctx.id, format!("added cheat '{}' (id {id}{group_str}{})", args.label, if is_hidden { ", hidden" } else { "" }));

    Ok(ToolResult::with_data(
        format!("added cheat '{}' (id {id}{group_str})", args.label),
        serde_json::json!({
            "id": id,
            "label": args.label,
            "group": args.group,
            "client_id": ctx.id,
        }),
    ))
}

/// List all cheats in the session.
pub fn execute_list_cheats(
    session: &SharedSession,
    ctx: &ClientContext,
) -> Result<ToolResult, ToolError> {
    let s = session.lock().map_err(|_| err("session lock poisoned"))?;
    let cheats = s.list_cheats();
    if cheats.is_empty() {
        return Ok(ToolResult::with_data(
            "(no cheats yet)",
            serde_json::json!({ "cheats": [], "client_id": ctx.id }),
        ));
    }
    let lines: Vec<String> = cheats
        .iter()
        .map(|c| {
            let group_tag = match &c.group {
                Some(g) => format!(" [{g}]"),
                None => String::new(),
            };
            let kind = match &c.kind {
                CheatKind::Value { address, value_type, address_expr } => {
                    if let Some(expr) = address_expr {
                        format!("value {value_type:?} @ {expr} ({address:#x})")
                    } else {
                        format!("value {value_type:?} @ {address:#x}")
                    }
                }
                CheatKind::Struct { base_address, base_expr, fields } => {
                    format!("struct ({base_expr} @ {base_address:#x}) [{} field(s)]", fields.len())
                }
                CheatKind::Toggle { target, enabled, .. } => {
                    format!("toggle @ {target:#x} ({})", if *enabled { "on" } else { "off" })
                }
                CheatKind::Patch { target, enabled, cave_ref, .. } => {
                    let desc = cave_ref.as_deref().unwrap_or("fast patch");
                    format!("patch @ {target:#x} ({}, {desc})", if *enabled { "on" } else { "off" })
                }
                CheatKind::Button { commands } => {
                    format!("button ({} cmd(s))", commands.len())
                }
            };
            format!("[{}]{} {} — {kind}", c.id, group_tag, c.label)
        })
        .collect();

    Ok(ToolResult::with_data(
        lines.join("\n"),
        serde_json::json!({
            "cheats": cheats.iter().map(|c| {
                let enabled = match &c.kind {
                    CheatKind::Toggle { enabled, .. } | CheatKind::Patch { enabled, .. } => Some(*enabled),
                    _ => None,
                };
                serde_json::json!({ "id": c.id, "label": c.label, "group": c.group, "enabled": enabled })
            }).collect::<Vec<_>>(),
            "client_id": ctx.id,
        }),
    ))
}

/// Enable or disable a toggle or patch cheat (stages mutation through pending ops).
pub fn execute_set_cheat_toggle(
    session: &SharedSession,
    ctx: &ClientContext,
    args: SetCheatToggleArgs,
) -> Result<ToolResult, ToolError> {
    use crate::session::PendingKind;

    let kind = {
        let s = session
            .lock()
            .map_err(|_| err("session lock poisoned"))?;
        let c = s
            .get_cheat(args.id)
            .ok_or_else(|| err(format!("no cheat with id {}", args.id)))?;
        c.kind.clone()
    };

    match kind {
        CheatKind::Toggle { target, hook, enabled, original_bytes, .. } => {
            if enabled == args.enabled {
                return Ok(ToolResult::with_data(
                    format!(
                        "toggle cheat {} already {}",
                        args.id,
                        if args.enabled { "enabled" } else { "disabled" }
                    ),
                    serde_json::json!({
                        "id": args.id,
                        "enabled": enabled,
                        "client_id": ctx.id,
                    }),
                ));
            }
            if args.enabled {
                match &hook {
                    crate::cave_hook::CaveHook::Override { payload, .. } if payload.is_empty() => {
                        return Err(err(format!(
                            "toggle cheat #{} has an empty override hook with no payload; cannot enable stub toggle",
                            args.id
                        )));
                    }
                    _ => {}
                }
            }

            let mut s = session
                .lock()
                .map_err(|_| err("session lock poisoned"))?;
            let pid = if args.enabled {
                s.stage_op_with_cheat(
                    target,
                    PendingKind::InstallCave { hook, marker: None, label_offsets: std::collections::HashMap::new() },
                    format!("enable toggle cheat {} at {:#x}", args.id, target),
                    Some(args.id),
                )
            } else {
                if original_bytes.is_empty() {
                    return Err(err(format!(
                        "toggle cheat {} has no stored original bytes; cannot restore",
                        args.id
                    )));
                }
                s.stage_op_with_cheat(
                    target,
                    PendingKind::Undo { original_bytes },
                    format!("disable toggle cheat {} at {:#x}", args.id, target),
                    Some(args.id),
                )
            };
            s.log_activity(&ctx.id, format!("staged toggle change (pending id {pid}) for cheat {}", args.id));
            drop(s);

            Ok(ToolResult::with_data(
                format!(
                    "staged toggle change (pending id {pid}) for cheat {}. Call 'confirm_op' to apply.",
                    args.id
                ),
                serde_json::json!({
                    "pending_id": pid,
                    "id": args.id,
                    "enabled": args.enabled,
                    "client_id": ctx.id,
                }),
            ))
        }
        CheatKind::Patch { target, patch_bytes, original_bytes, enabled, cave_ref } => {
            if enabled == args.enabled {
                return Ok(ToolResult::with_data(
                    format!(
                        "patch cheat {} already {}",
                        args.id,
                        if args.enabled { "enabled" } else { "disabled" }
                    ),
                    serde_json::json!({
                        "id": args.id,
                        "enabled": enabled,
                        "client_id": ctx.id,
                    }),
                ));
            }
            let desc = cave_ref.as_deref().unwrap_or("fast patch");
            if args.enabled && patch_bytes.is_empty() {
                return Err(err(format!(
                    "patch cheat #{} has empty patch_bytes; cannot enable stub patch",
                    args.id
                )));
            }
            let data = if args.enabled { patch_bytes } else { original_bytes };
            let mut s = session
                .lock()
                .map_err(|_| err("session lock poisoned"))?;
            let pid = s.stage_op_with_cheat(
                target,
                PendingKind::Write { data },
                format!("{} patch cheat {} at {:#x} ({desc})", if args.enabled { "enable" } else { "disable" }, args.id, target),
                Some(args.id),
            );
            s.log_activity(&ctx.id, format!("staged patch toggle (pending id {pid}) for cheat {}", args.id));
            drop(s);

            Ok(ToolResult::with_data(
                format!(
                    "staged patch toggle (pending id {pid}) for cheat {}. Call 'confirm_op' to apply.",
                    args.id
                ),
                serde_json::json!({
                    "pending_id": pid,
                    "id": args.id,
                    "enabled": args.enabled,
                    "client_id": ctx.id,
                }),
            ))
        }
        _ => Err(err(format!("cheat {} is not a toggle or patch cheat", args.id))),
    }
}

/// Remove a cheat by ID.
pub fn execute_remove_cheat(
    session: &SharedSession,
    ctx: &ClientContext,
    args: RemoveCheatArgs,
) -> Result<ToolResult, ToolError> {
    let mut s = session.lock().map_err(|_| err("session lock poisoned"))?;
    match s.remove_cheat(args.id) {
        Some(c) => {
            s.log_activity(&ctx.id, format!("removed cheat '{}' (id {})", c.label, c.id));
            Ok(ToolResult::with_data(
                format!("removed cheat '{}' (id {})", c.label, c.id),
                serde_json::json!({
                    "id": c.id,
                    "label": c.label,
                    "client_id": ctx.id,
                }),
            ))
        }
        None => Err(err(format!("no cheat with id {}", args.id))),
    }
}

/// Directly set a value cheat's target memory (with auto-undo).
pub fn execute_set_cheat_value(
    session: &SharedSession,
    ctx: &ClientContext,
    mem: &dyn ProcessMemory,
    args: SetCheatValueArgs,
) -> Result<ToolResult, ToolError> {
    let (target_addr, value_type) = {
        let (expr_opt, addr_fallback, vt) = {
            let s = session.lock().map_err(|_| err("session lock poisoned"))?;
            let c = s.get_cheat(args.id).ok_or_else(|| err(format!("no cheat with id {}", args.id)))?;
            match &c.kind {
                CheatKind::Value { address, value_type, address_expr } => (address_expr.clone(), *address, *value_type),
                _ => return Err(err(format!("cheat {} is not a value cheat", args.id))),
            }
        };
        let target = if let Some(expr) = &expr_opt {
            eval_addr_expr(session, expr, Some(mem)).unwrap_or(addr_fallback)
        } else {
            addr_fallback
        };
        (target, vt)
    };

    let data = parse_value_bytes(&args.value, value_type).map_err(err)?;
    let orig = mem.read(target_addr, data.len()).unwrap_or_default();

    mem.write(target_addr, &data).map_err(|e| err(format!("failed to write cheat value: {e}")))?;

    let mut s = session.lock().map_err(|_| err("session lock poisoned"))?;
    let undo_id = if !orig.is_empty() {
        Some(s.record_undo(target_addr, orig, format!("set cheat #{} to {}", args.id, args.value)))
    } else {
        None
    };

    s.log_activity(&ctx.id, format!("set cheat #{} value to '{}' @ {target_addr:#x}", args.id, args.value));

    Ok(ToolResult::with_data(
        format!("set cheat #{} value to '{}' @ {target_addr:#x}", args.id, args.value),
        serde_json::json!({
            "id": args.id,
            "address": target_addr,
            "value": args.value,
            "undo_id": undo_id,
            "client_id": ctx.id,
        }),
    ))
}

/// List cheat profiles discovered on disk.
pub fn execute_list_profiles(
    _session: &SharedSession,
    ctx: &ClientContext,
) -> Result<ToolResult, ToolError> {
    let all_profiles = crate::profile::discover_all_profiles();
    if all_profiles.is_empty() {
        return Ok(ToolResult::with_data(
            "(no profiles found in cheats/)",
            serde_json::json!({ "profiles": [], "client_id": ctx.id }),
        ));
    }
    let mut lines = Vec::new();
    let mut json_list = Vec::new();

    for dp in &all_profiles {
        match dp {
            crate::profile::DiscoveredProfile::Valid { file, profile } => {
                lines.push(format!("{} — game: {} ({}) v{}", file, profile.game, profile.name, profile.version));
                json_list.push(serde_json::json!({
                    "file": file,
                    "valid": true,
                    "game": profile.game,
                    "name": profile.name,
                    "version": profile.version,
                }));
            }
            crate::profile::DiscoveredProfile::Invalid { file, error } => {
                lines.push(format!("{} — UNPARSEABLE / INVALID: {}", file, error));
                json_list.push(serde_json::json!({
                    "file": file,
                    "valid": false,
                    "error": error,
                }));
            }
        }
    }

    Ok(ToolResult::with_data(
        lines.join("\n"),
        serde_json::json!({
            "profiles": json_list,
            "client_id": ctx.id,
        }),
    ))
}

/// Save current cheats in session to a portable YAML profile.
pub fn execute_save_profile(
    session: &SharedSession,
    ctx: &ClientContext,
    args: ProfileSaveArgs,
) -> Result<ToolResult, ToolError> {
    use std::collections::HashMap;
    use crate::profile::{GameProfile, ProfileCheat};

    let (game, profile_cheats, setup_steps, profile_meta) = {
        let s = session.lock().map_err(|_| err("session lock poisoned"))?;
        let game = s.game_name().to_string();
        if game.is_empty() {
            return Err(err("cannot save profile: session has no target game attached"));
        }

        // Build a lookup map of address -> marker name so cheats can reference setup steps symbolically
        let markers = s.list_markers();
        let mut addr_to_marker: HashMap<u64, String> = HashMap::new();
        for m in markers {
            addr_to_marker.insert(m.address, m.label.clone());
        }

        let setup_steps = s.setup_steps().to_vec();

        let cheats = s.list_cheats();
        let profile_cheats: Vec<ProfileCheat> = cheats
            .iter()
            .map(|c| {
                let (kind, value_type, address_ref, target_ref, hook, payload, base, fields, orig_bytes) = match &c.kind {
                    CheatKind::Value { address, value_type, address_expr } => {
                        let addr_ref = address_expr.clone().or_else(|| addr_to_marker.get(address).cloned()).unwrap_or_else(|| format!("{address:#x}"));
                        ("value".to_string(), Some(format!("{value_type:?}").to_lowercase()), Some(addr_ref), None, None, None, None, None, None)
                    }
                    CheatKind::Struct { base_address, base_expr, fields } => {
                        let b = if base_expr.is_empty() {
                            addr_to_marker.get(base_address).cloned().unwrap_or_else(|| format!("{base_address:#x}"))
                        } else {
                            base_expr.clone()
                        };
                        ("struct".to_string(), None, None, None, None, None, Some(b), Some(fields.clone()), None)
                    }
                    CheatKind::Toggle { target, hook, original_bytes, .. } => {
                        let (hk, pl) = match hook {
                            crate::cave_hook::CaveHook::Trampoline { payload, .. } => {
                                ("trampoline".to_string(), Some(payload.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")))
                            }
                            crate::cave_hook::CaveHook::Override { payload, .. } => {
                                ("override".to_string(), Some(payload.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")))
                            }
                        };
                        let orig = if !original_bytes.is_empty() {
                            Some(original_bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" "))
                        } else {
                            None
                        };
                        let tgt_ref = addr_to_marker.get(target).cloned().unwrap_or_else(|| format!("{target:#x}"));
                        ("toggle".to_string(), None, None, Some(tgt_ref), Some(hk), pl, None, None, orig)
                    }
                    CheatKind::Patch { target, patch_bytes, cave_ref, original_bytes, .. } => {
                        let orig = if !original_bytes.is_empty() {
                            Some(original_bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" "))
                        } else {
                            None
                        };
                        let tgt_ref = addr_to_marker.get(target).cloned().unwrap_or_else(|| format!("{target:#x}"));
                        ("patch".to_string(), None, None, Some(tgt_ref), cave_ref.clone(), Some(patch_bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")), None, None, orig)
                    }
                    CheatKind::Button { .. } => {
                        ("button".to_string(), None, None, None, None, None, None, None, None)
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
                    asm: None,
                    jump: None,
                    mechanism: None,
                    rate_hz: None,
                    value: None,
                    base,
                    fields,
                    commands: match &c.kind {
                        CheatKind::Button { commands } => Some(commands.clone()),
                        _ => None,
                    },
                    group: c.group.clone(),
                    hotkey: c.hotkey.clone(),
                    hidden: if c.hidden { Some(true) } else { None },
                    original_bytes: orig_bytes,
                    context: None,
                    note: c.note.clone(),
                }
            })
            .collect();

        let profile_name = s.profile_name().map(|n| n.to_string()).unwrap_or_else(|| format!("{game} cheats"));
        let profile_version = s.profile_version().map(|v| v.to_string()).unwrap_or_else(|| "1.0.0".into());
        let game_version = s.profile_game_version().map(|v| v.to_string());
        let author = s.profile_author().map(|a| a.to_string());
        let date = s.profile_date().map(|d| d.to_string());
        let init_commands = s.init_commands().map(|c| c.to_vec());
        let profile_render = s.profile_render().cloned();

        (game, profile_cheats, setup_steps, (profile_name, profile_version, game_version, author, date, init_commands, profile_render))
    };

    let (name, version, game_version, author, date, init_commands, render) = profile_meta;

    let profile = GameProfile {
        schema: GameProfile::SCHEMA_V1.into(),
        game: game.clone(),
        name,
        inject_dll: true,
        version,
        game_version,
        date,
        author,
        setup: setup_steps,
        structs: vec![],
        init_commands,
        render,
        cheats: profile_cheats.clone(),
    };

    let yaml = profile.to_yaml().map_err(err)?;
    let file = args.file.unwrap_or_else(|| format!("{}.yaml", game.replace(".exe", "")));
    let dir = crate::profile::profiles_dir_path();
    std::fs::create_dir_all(&dir).map_err(|e| err(format!("mkdir {dir:?}: {e}")))?;
    let path = dir.join(&file);
    std::fs::write(&path, yaml).map_err(|e| err(format!("write {path:?}: {e}")))?;

    if let Ok(mut s) = session.lock() {
        s.log_activity(&ctx.id, format!("saved profile to {} ({} cheats)", path.display(), profile_cheats.len()));
    }

    Ok(ToolResult::with_data(
        format!("saved profile to {} ({} cheats)", path.display(), profile_cheats.len()),
        serde_json::json!({
            "path": path.to_string_lossy(),
            "cheats_count": profile_cheats.len(),
            "client_id": ctx.id,
        }),
    ))
}

/// Calculate relative jump bytes (E9 rel32) from patch site to target/cave, padded with NOPs up to pad_to_len.
pub fn execute_emit_relative_jump(
    session: &SharedSession,
    ctx: &ClientContext,
    mem: Option<&dyn ProcessMemory>,
    args: EmitRelativeJumpArgs,
) -> Result<ToolResult, ToolError> {
    let from = eval_addr_expr(session, &args.from, mem)?;
    let to = eval_addr_expr(session, &args.to, mem)?;
    let pad_len = args.pad_to_len.unwrap_or(5).max(5);

    // RIP at the end of the 5-byte E9 instruction is (from + 5)
    let rel_i64 = (to as i64) - (from as i64 + 5);
    if rel_i64 < (i32::MIN as i64) || rel_i64 > (i32::MAX as i64) {
        return Err(err(format!(
            "relative jump distance ({rel_i64} bytes) exceeds 32-bit ±2GB range between {from:#x} and {to:#x}"
        )));
    }
    let rel_i32 = rel_i64 as i32;
    let mut bytes = vec![0xE9u8];
    bytes.extend_from_slice(&rel_i32.to_le_bytes());

    while bytes.len() < pad_len {
        bytes.push(0x90); // NOP padding
    }

    let hex_str = bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
    let text = format!(
        "relative jump from {from:#x} to {to:#x} (padded to {pad_len} bytes):\nhex: \"{hex_str}\""
    );

    Ok(ToolResult::with_data(
        text,
        serde_json::json!({
            "from": from,
            "to": to,
            "pad_len": pad_len,
            "hex": hex_str,
            "bytes": bytes,
            "client_id": ctx.id,
        }),
    ))
}

/// Assemble human-readable x86-64 assembly source into machine code bytes (iced-x86).
pub fn execute_assemble_asm(
    session: &SharedSession,
    ctx: &ClientContext,
    mem: Option<&dyn ProcessMemory>,
    args: AssembleAsmArgs,
) -> Result<ToolResult, ToolError> {
    let mut symbols = std::collections::HashMap::new();
    if let Ok(s) = session.lock() {
        for m in s.list_markers() {
            symbols.insert(m.label.clone(), m.address);
            symbols.insert(m.label.to_lowercase(), m.address);
        }
    }

    let origin_rip = if let Some(orig) = &args.origin {
        eval_addr_expr(session, orig, mem)?
    } else {
        0
    };

    let assembled = crate::asm::assemble_text(&args.code, origin_rip, &symbols)
        .map_err(err)?;

    let disasm_lines = crate::disasm::disassemble(origin_rip, &assembled.bytes, Some(50));

    // If origin_rip is non-zero, automatically set markers for defined labels
    if origin_rip != 0 && !assembled.label_offsets.is_empty() {
        if let Ok(mut s) = session.lock() {
            for (lbl_name, offset) in &assembled.label_offsets {
                let lbl_addr = origin_rip.saturating_add(*offset);
                let _ = s.set_marker(lbl_name, lbl_addr, Some(&format!("Label from assembly at +{offset:#x}")));
            }
        }
    }

    let mut output = format!(
        "assembled {} byte(s) (origin {origin_rip:#x}):\nhex: \"{}\"\n",
        assembled.bytes.len(),
        assembled.hex,
    );

    if !assembled.label_offsets.is_empty() {
        output.push_str("\nlabels:\n");
        let mut sorted_labels: Vec<_> = assembled.label_offsets.iter().collect();
        sorted_labels.sort_by_key(|(_, off)| *off);
        for (lbl, off) in sorted_labels {
            let addr = origin_rip.saturating_add(*off);
            output.push_str(&format!("  • {lbl} -> +{off:#x} ({addr:#x})\n"));
        }
    }

    output.push_str(&format!("\ndisassembled:\n{}", disasm_lines.join("\n")));

    Ok(ToolResult::with_data(
        output,
        serde_json::json!({
            "bytes": assembled.bytes,
            "hex": assembled.hex,
            "instruction_count": assembled.instruction_count,
            "origin": origin_rip,
            "labels": assembled.label_offsets,
            "disassembly": disasm_lines,
            "client_id": ctx.id,
        }),
    ))
}

/// List all staged (pending) mutations awaiting confirmation.
pub fn execute_list_pending(
    session: &SharedSession,
    ctx: &ClientContext,
) -> Result<ToolResult, ToolError> {
    let s = session
        .lock()
        .map_err(|_| err("session lock poisoned"))?;
    let pending = s.list_pending();
    if pending.is_empty() {
        return Ok(ToolResult::with_data(
            "(no pending mutations)".to_string(),
            serde_json::json!({
                "pending": [],
                "client_id": ctx.id,
            }),
        ));
    }
    let mut lines = vec![format!("{} pending mutation(s) awaiting confirmation:", pending.len())];
    for op in &pending {
        lines.push(format!("  [{}] {}", op.id, op.preview));
    }
    let text = lines.join("\n");
    let json_items: Vec<_> = pending.iter().map(|p| serde_json::json!({
        "id": p.id,
        "address": p.address,
        "preview": p.preview,
        "cheat_id": p.cheat_id,
    })).collect();

    Ok(ToolResult::with_data(
        text,
        serde_json::json!({
            "pending": json_items,
            "client_id": ctx.id,
        }),
    ))
}

/// Discard a staged mutation by id without applying it.
pub fn execute_reject_op(
    session: &SharedSession,
    ctx: &ClientContext,
    args: OpConfirmArgs,
) -> Result<ToolResult, ToolError> {
    let op = {
        let mut s = session
            .lock()
            .map_err(|_| err("session lock poisoned"))?;
        s.take_pending(args.id)
    };
    match op {
        Some(op) => {
            if let Ok(mut s) = session.lock() {
                s.log_activity(&ctx.id, format!("rejected pending op {} ({})", op.id, op.preview));
            }
            Ok(ToolResult::with_data(
                format!("rejected pending op {} ({})", op.id, op.preview),
                serde_json::json!({
                    "id": op.id,
                    "preview": op.preview,
                    "client_id": ctx.id,
                }),
            ))
        }
        None => Err(err(format!(
            "no pending op {}. Stage one with 'write'/'install_cave'/'undo' first.",
            args.id
        ))),
    }
}

/// Stage a write to game memory for confirmation (D8 gate).
pub fn execute_stage_write(
    session: &SharedSession,
    ctx: &ClientContext,
    mem: Option<&dyn ProcessMemory>,
    args: StageWriteArgs,
) -> Result<ToolResult, ToolError> {
    use crate::session::PendingKind;
    let address = eval_addr_expr(session, &args.address, mem)?;
    let (data, desc) = match (args.data.as_deref(), args.value.as_deref()) {
        (Some(hex_str), None) => {
            let bytes = crate::expr::parse_hex_bytes(hex_str).map_err(err)?;
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
            let value_type = crate::expr::parse_value_type(vt_str).map_err(err)?;
            let bytes = crate::expr::parse_value_bytes(val_str, value_type).map_err(err)?;
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

    let mut s = session
        .lock()
        .map_err(|_| err("session lock poisoned"))?;
    let id = s.stage_op(
        address,
        PendingKind::Write { data: data.clone() },
        desc,
    );
    s.log_activity(&ctx.id, format!("staged write (pending id {id}): {} byte(s) at {:#x}", data.len(), address));
    drop(s);

    Ok(ToolResult::with_data(
        format!(
            "staged write (pending id {id}): {} byte(s) at {:#x}. Call 'confirm_op' to apply or 'reject_op' to discard.",
            data.len(),
            address
        ),
        serde_json::json!({
            "pending_id": id,
            "address": address,
            "bytes_count": data.len(),
            "client_id": ctx.id,
        }),
    ))
}

/// Stage a code-cave hook install for confirmation (D8 gate).
pub fn execute_stage_install_cave(
    session: &SharedSession,
    ctx: &ClientContext,
    mem: Option<&dyn ProcessMemory>,
    args: InstallCaveArgs,
) -> Result<ToolResult, ToolError> {
    use crate::cave_hook::{CaveHook, JumpStyle};
    use crate::session::PendingKind;
    let target = eval_addr_expr(session, &args.target, mem)?;

    if args.asm.is_some() && !args.payload.trim().is_empty() {
        return Err(err("cannot provide both 'asm' and 'payload' (mutually exclusive)"));
    }

    let (payload, label_offsets) = if let Some(asm_src) = &args.asm {
        let symbols: std::collections::HashMap<String, u64> = {
            let s = session.lock().map_err(|_| err("session lock poisoned"))?;
            s.list_markers().iter().map(|m| (m.label.clone(), m.address)).collect()
        };
        let block = crate::asm::assemble_text(asm_src, target, &symbols).map_err(err)?;
        (block.bytes, block.label_offsets)
    } else {
        (crate::expr::parse_hex_bytes(&args.payload).map_err(err)?, std::collections::HashMap::new())
    };

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

    let mut s = session
        .lock()
        .map_err(|_| err("session lock poisoned"))?;
    let id = s.stage_op(
        target,
        PendingKind::InstallCave { hook, marker: args.marker.clone(), label_offsets },
        format!(
            "install {kind_desc} cave at {:#x}, payload={} byte(s){}",
            target,
            payload.len(),
            if let Some(m) = &args.marker { format!(" (marker: '{m}')") } else { String::new() }
        ),
    );
    s.log_activity(&ctx.id, format!("staged {kind_desc} cave install (pending id {id}) at {:#x}", target));
    drop(s);

    Ok(ToolResult::with_data(
        format!(
            "staged {kind_desc} cave install (pending id {id}) at {:#x}. Call 'confirm_op' to apply or 'reject_op' to discard.",
            target
        ),
        serde_json::json!({
            "pending_id": id,
            "target": target,
            "kind": kind_desc,
            "payload_len": payload.len(),
            "marker": args.marker,
            "client_id": ctx.id,
        }),
    ))
}

/// Stage an undo mutation for confirmation (D8 gate).
pub fn execute_stage_undo(
    session: &SharedSession,
    ctx: &ClientContext,
    args: UndoArgs,
) -> Result<ToolResult, ToolError> {
    use crate::session::PendingKind;
    let entry = {
        let s = session
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

    let mut s = session
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
    s.log_activity(&ctx.id, format!("staged undo (pending id {id}) for undo #{}", e.id));
    drop(s);

    Ok(ToolResult::with_data(
        format!(
            "staged undo (pending id {id}) for undo #{}. Call 'confirm_op' to apply or 'reject_op' to discard.",
            e.id
        ),
        serde_json::json!({
            "pending_id": id,
            "undo_id": e.id,
            "address": e.address,
            "bytes_len": e.original_bytes.len(),
            "client_id": ctx.id,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{ClientKind, SessionState};
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_execute_emit_relative_jump_and_assemble_asm() {
        let session = Arc::new(Mutex::new(SessionState::new()));
        let binding = session.lock().unwrap();
        let bus = binding.event_bus();
        let ctx = ClientContext::new("test-asm-ctx", ClientKind::Internal, bus);
        drop(binding);

        // 1. Test relative jump calculation
        let jmp_res = execute_emit_relative_jump(&session, &ctx, None, EmitRelativeJumpArgs {
            from: "0x140000000".into(),
            to: "0x140001000".into(),
            pad_to_len: Some(7),
        }).unwrap();
        assert!(jmp_res.message.contains("relative jump from 0x140000000 to 0x140001000"));
        assert!(jmp_res.message.contains("padded to 7 bytes"));

        // 2. Test assemble asm with named marker and defined labels
        session.lock().unwrap().set_marker("cave_target", 0x140002000, None).unwrap();

        let asm_res = execute_assemble_asm(&session, &ctx, None, AssembleAsmArgs {
            code: "mov rax, 0x1234\nfire_flag:\ndb 01\ncmd_ptr:\ndq 0x12345678\njmp $cave_target".into(),
            origin: Some("0x140000000".into()),
        }).unwrap();
        assert!(asm_res.message.contains("assembled"));
        assert!(asm_res.message.contains("disassembled"));
        assert!(asm_res.message.contains("fire_flag"));

        // Check markers were automatically registered in session
        let s = session.lock().unwrap();
        let fire_flag = s.get_marker("fire_flag").expect("fire_flag marker");
        let cmd_ptr = s.get_marker("cmd_ptr").expect("cmd_ptr marker");
        assert!(fire_flag.address > 0x140000000);
        assert!(cmd_ptr.address > fire_flag.address);
        drop(s);
    }

    struct MockMem {
        data: Vec<u8>,
    }

    impl ProcessMemory for MockMem {
        fn read(&self, address: u64, len: usize) -> Result<Vec<u8>, crate::memory::MemoryError> {
            let start = address as usize;
            let end = (start + len).min(self.data.len());
            if start >= self.data.len() {
                return Err(crate::memory::MemoryError::OutOfRange { address });
            }
            Ok(self.data[start..end].to_vec())
        }
        fn write(&self, address: u64, data: &[u8]) -> Result<usize, crate::memory::MemoryError> {
            let start = address as usize;
            if start + data.len() > self.data.len() {
                return Err(crate::memory::MemoryError::OutOfRange { address });
            }
            Ok(data.len())
        }
        fn regions(&self) -> Result<Vec<crate::memory::Region>, crate::memory::MemoryError> {
            Ok(vec![])
        }
    }

    #[test]
    fn test_execute_read_and_dump_struct() {
        let mut data = vec![0u8; 128];
        data[0..4].copy_from_slice(&12345i32.to_le_bytes());
        data[4..8].copy_from_slice(&2.5f32.to_le_bytes());
        data[8..11].copy_from_slice(b"hi\0");

        let mem = MockMem { data };
        let session = Arc::new(Mutex::new(SessionState::new()));
        let mut s = session.lock().unwrap();
        let ctx = s.create_context("test-ctx", ClientKind::Internal);
        drop(s);

        // Test read i32
        let res_i32 = execute_read(&session, &ctx, &mem, ReadArgs {
            address: "0x00".into(),
            len: None,
            value_type: Some("i32".into()),
        }).unwrap();
        assert_eq!(res_i32.message, "12345");

        // Test dump struct
        let res_struct = execute_dump_struct(&session, &ctx, &mem, DumpStructArgs {
            address: "0x00".into(),
            fields: vec![
                StructFieldSpec { name: "health".into(), offset: 0, value_type: "i32".into(), len: None },
                StructFieldSpec { name: "speed".into(), offset: 4, value_type: "f32".into(), len: None },
                StructFieldSpec { name: "tag".into(), offset: 8, value_type: "cstr".into(), len: Some(16) },
            ],
        }).unwrap();
        assert!(res_struct.message.contains("health: 12345"));
        assert!(res_struct.message.contains("speed: 2.5"));
        assert!(res_struct.message.contains("tag: \"hi\""));
    }

    #[test]
    fn test_execute_scan_suite_and_scan_set() {
        let mut data = vec![0u8; 256];
        // Place 100i32 at 0x10 and 0x20, and 200i32 at 0x30
        data[0x10..0x14].copy_from_slice(&100i32.to_le_bytes());
        data[0x20..0x24].copy_from_slice(&100i32.to_le_bytes());
        data[0x30..0x34].copy_from_slice(&200i32.to_le_bytes());

        struct ScanMem {
            data: std::sync::Mutex<Vec<u8>>,
        }

        impl ProcessMemory for ScanMem {
            fn read(&self, address: u64, len: usize) -> Result<Vec<u8>, crate::memory::MemoryError> {
                let d = self.data.lock().unwrap();
                let start = address as usize;
                let end = (start + len).min(d.len());
                if start >= d.len() {
                    return Err(crate::memory::MemoryError::OutOfRange { address });
                }
                Ok(d[start..end].to_vec())
            }
            fn write(&self, address: u64, data: &[u8]) -> Result<usize, crate::memory::MemoryError> {
                let mut d = self.data.lock().unwrap();
                let start = address as usize;
                if start + data.len() > d.len() {
                    return Err(crate::memory::MemoryError::OutOfRange { address });
                }
                d[start..start + data.len()].copy_from_slice(data);
                Ok(data.len())
            }
            fn regions(&self) -> Result<Vec<crate::memory::Region>, crate::memory::MemoryError> {
                Ok(vec![crate::memory::Region {
                    start: 0,
                    end: 256,
                    readable: true,
                    writable: true,
                    executable: false,
                    name: None,
                }])
            }
        }

        let mem = ScanMem { data: std::sync::Mutex::new(data) };
        let session = Arc::new(Mutex::new(SessionState::new()));
        let mut s = session.lock().unwrap();
        let mut ctx = s.create_context("scan-test-client", ClientKind::Gui);
        drop(s);

        // 1. scan_start
        let res1 = execute_scan_start(&session, &mut ctx, &mem, ScanStartArgs {
            value_type: "i32".into(),
            value: 100.0,
            max: None,
            alignment: Some(4),
            region: None,
        }).unwrap();
        assert!(res1.message.contains("2 match(es)"));

        // 2. scan_status
        let res_status = execute_scan_status(&session, &ctx).unwrap();
        assert!(res_status.message.contains("2 match(es)"));

        // 3. scan_set (batch test-write 999 to both matches)
        let res_set = execute_scan_set(&session, &ctx, &mem, ScanSetArgs {
            value: "999".into(),
            value_type: Some("i32".into()),
        }).unwrap();
        assert!(res_set.message.contains("wrote '999' to 2 address(es)"));

        // Verify values written in memory
        let check_val = mem.read(0x10, 4).unwrap();
        assert_eq!(i32::from_le_bytes(check_val.try_into().unwrap()), 999);

        // 4. scan_next (refine exact 999)
        let res_next = execute_scan_next(&session, &mut ctx, &mem, ScanNextArgs {
            op: "exact".into(),
            value: Some(999.0),
            max: None,
        }).unwrap();
        assert!(res_next.message.contains("2 match(es)"));

        // 5. scan_clear
        let res_clear = execute_scan_clear(&session, &mut ctx).unwrap();
        assert!(res_clear.message.contains("cleared"));
        assert!(ctx.scan.is_none());
    }

    #[test]
    fn test_execute_markers_cheats_and_undo_revert() {
        let mut data = vec![0u8; 128];
        data[0x20..0x24].copy_from_slice(&500i32.to_le_bytes());

        struct MockMem2 {
            data: std::sync::Mutex<Vec<u8>>,
        }

        impl ProcessMemory for MockMem2 {
            fn read(&self, address: u64, len: usize) -> Result<Vec<u8>, crate::memory::MemoryError> {
                let d = self.data.lock().unwrap();
                let start = address as usize;
                let end = (start + len).min(d.len());
                if start >= d.len() {
                    return Err(crate::memory::MemoryError::OutOfRange { address });
                }
                Ok(d[start..end].to_vec())
            }
            fn write(&self, address: u64, data: &[u8]) -> Result<usize, crate::memory::MemoryError> {
                let mut d = self.data.lock().unwrap();
                let start = address as usize;
                if start + data.len() > d.len() {
                    return Err(crate::memory::MemoryError::OutOfRange { address });
                }
                d[start..start + data.len()].copy_from_slice(data);
                Ok(data.len())
            }
            fn regions(&self) -> Result<Vec<crate::memory::Region>, crate::memory::MemoryError> {
                Ok(vec![])
            }
        }

        let mem = MockMem2 { data: std::sync::Mutex::new(data) };
        let session = Arc::new(Mutex::new(SessionState::new()));
        let mut s = session.lock().unwrap();
        let ctx = s.create_context("mcp-client-1", ClientKind::Mcp { agent_name: None });
        drop(s);

        // 1. Marker operations
        let m_set = execute_set_marker(&session, &ctx, Some(&mem), SetMarkerArgs {
            label: "gold_addr".into(),
            address: "0x20".into(),
            size: None,
            kind: None,
            struct_type: None,
            note: Some("gold currency".into()),
        }).unwrap();
        assert!(m_set.message.contains("saved marker '$gold_addr' = 0x20"));

        let m_get = execute_get_marker(&session, &ctx, GetMarkerArgs {
            label: "gold_addr".into(),
        }).unwrap();
        assert!(m_get.message.contains("gold_addr = 0x0000000000000020"));

        let m_list = execute_list_markers(&session, &ctx).unwrap();
        assert!(m_list.message.contains("gold_addr"));

        // 2. Cheat operations
        let c_add = execute_add_cheat(&session, &ctx, Some(&mem), AddCheatArgs {
            label: "Gold Cheat".into(),
            kind: "value".into(),
            address: Some("gold_addr".into()),
            value_type: Some("i32".into()),
            group: None,
            hotkey: None,
            hidden: None,
            note: None,
        }).unwrap();
        assert!(c_add.message.contains("added cheat 'Gold Cheat' (id 0)"));

        let c_list = execute_list_cheats(&session, &ctx).unwrap();
        assert!(c_list.message.contains("Gold Cheat"));

        // 3. Set cheat value (mutates memory to 777 and creates undo)
        let c_set = execute_set_cheat_value(&session, &ctx, &mem, SetCheatValueArgs {
            id: 0,
            value: "777".into(),
        }).unwrap();
        assert!(c_set.message.contains("set cheat #0 value to '777'"));

        let cur_val = mem.read(0x20, 4).unwrap();
        assert_eq!(i32::from_le_bytes(cur_val.try_into().unwrap()), 777);

        // 4. Inspect undo info
        let u_info = execute_undo_info(&session, &ctx, UndoInfoArgs { id: None }).unwrap();
        assert!(u_info.message.contains("undo #0"));

        // 5. Revert undo #0 (restores memory back to 500)
        let u_rev = execute_undo_revert(&session, &ctx, &mem, UndoRevertArgs { id: 0 }).unwrap();
        assert!(u_rev.message.contains("successfully reverted undo #0"));

        let restored_val = mem.read(0x20, 4).unwrap();
        assert_eq!(i32::from_le_bytes(restored_val.try_into().unwrap()), 500);

        // 6. Remove cheat and marker
        let c_rem = execute_remove_cheat(&session, &ctx, RemoveCheatArgs { id: 0 }).unwrap();
        assert!(c_rem.message.contains("removed cheat 'Gold Cheat'"));

        let m_rem = execute_remove_marker(&session, &ctx, RemoveMarkerArgs { label: "gold_addr".into() }).unwrap();
        assert!(m_rem.message.contains("removed marker '$gold_addr'"));
    }

    #[test]
    fn test_execute_staging_and_pending_ops() {
        let session = Arc::new(Mutex::new(SessionState::new()));
        let binding = session.lock().unwrap();
        let bus = binding.event_bus();
        let ctx = ClientContext::new("test-stage-ctx", ClientKind::Internal, bus);
        drop(binding);

        // 1. Stage a write
        let s_w = execute_stage_write(&session, &ctx, None, StageWriteArgs {
            address: "0x140001000".into(),
            data: Some("90 90 90 90".into()),
            value: None,
            value_type: None,
        }).unwrap();
        assert!(s_w.message.contains("staged write (pending id 0)"));

        // 2. List pending
        let l_p = execute_list_pending(&session, &ctx).unwrap();
        assert!(l_p.message.contains("[0] write 4 byte(s) at 0x140001000"));

        // 3. Reject pending op 0
        let r_p = execute_reject_op(&session, &ctx, OpConfirmArgs { id: 0 }).unwrap();
        assert!(r_p.message.contains("rejected pending op 0"));

        // 4. Verify pending list is empty
        let l_p2 = execute_list_pending(&session, &ctx).unwrap();
        assert!(l_p2.message.contains("(no pending mutations)"));
    }

    #[test]
    fn test_save_profile_preserves_setup_and_symbols() {
        let session = Arc::new(Mutex::new(SessionState::new()));
        let mut s = session.lock().unwrap();
        let ctx = s.create_context("test-save-profile", ClientKind::Internal);

        s.set_game_name("sins2.exe");
        let setup_step = crate::profile::SetupStep::AobScan {
            name: "research_hook".into(),
            pattern: "0F 2F 76 ?? 0F 28 B4 24 ?? ?? ?? ?? 77".into(),
            offset: Some(0),
            region: Some("sins2.exe".into()),
            original_bytes: Some("0f 2f 76 30 0f 28 b4 24 40 02 00 00 77 1e".into()),
            context: Some("comiss xmm6,[rsi+0x30]; movaps xmm6,[rsp+0x240]; ja +0x1e — research progress compare".into()),
        };
        s.set_setup_steps(vec![setup_step]);
        s.set_marker("research_hook", 0x140b246b3, Some("research hook marker")).unwrap();

        // Add a toggle cheat referencing research_hook
        let _ = s.add_cheat_group(
            "Instant Research",
            CheatKind::Toggle {
                hook: crate::cave_hook::CaveHook::Override {
                    payload: vec![0x90, 0x90],
                    jump: crate::cave_hook::JumpStyle::Absolute,
                },
                target: 0x140b246b3,
                enabled: false,
                original_bytes: vec![0x0f, 0x2f, 0x76, 0x30],
                cave_addr: 0,
            },
            Some("Research"),
            Some("Num 1"),
            false,
            Some("Instant research note"),
        );
        drop(s);

        let res = execute_save_profile(&session, &ctx, ProfileSaveArgs {
            file: Some("test_sins2_saved.yaml".into()),
        }).unwrap();
        assert!(res.message.contains("saved profile to"));

        // Read and parse back the saved YAML
        let path = crate::profile::profiles_dir_path().join("test_sins2_saved.yaml");
        let yaml = std::fs::read_to_string(&path).expect("read saved profile yaml");
        let _ = std::fs::remove_file(&path); // Clean up

        let loaded = crate::profile::GameProfile::from_yaml(&yaml).expect("parse saved yaml");
        assert_eq!(loaded.game, "sins2.exe");
        assert_eq!(loaded.setup.len(), 1);
        match &loaded.setup[0] {
            crate::profile::SetupStep::AobScan { name, pattern, offset, region, original_bytes, context } => {
                assert_eq!(name, "research_hook");
                assert_eq!(pattern, "0F 2F 76 ?? 0F 28 B4 24 ?? ?? ?? ?? 77");
                assert_eq!(*offset, Some(0));
                assert_eq!(region.as_deref(), Some("sins2.exe"));
                assert_eq!(original_bytes.as_deref(), Some("0f 2f 76 30 0f 28 b4 24 40 02 00 00 77 1e"));
                assert!(context.as_deref().unwrap().contains("research progress compare"));
            }
            _ => panic!("wrong setup step kind"),
        }

        assert_eq!(loaded.cheats.len(), 1);
        let cheat = &loaded.cheats[0];
        assert_eq!(cheat.label, "Instant Research");
        assert_eq!(cheat.target_ref.as_deref(), Some("research_hook"));
        assert_eq!(cheat.original_bytes.as_deref(), Some("0f 2f 76 30"));
    }

    #[test]
    fn test_empty_toggle_override_fails_and_does_not_stage() {
        let session = Arc::new(Mutex::new(SessionState::new()));
        let mut s = session.lock().unwrap();
        let ctx = s.create_context("test-ctx", ClientKind::Internal);
        let cid = s.add_cheat(
            "Stub Override Toggle",
            CheatKind::Toggle {
                hook: crate::cave_hook::CaveHook::Override {
                    payload: Vec::new(), // Empty payload!
                    jump: crate::cave_hook::JumpStyle::Absolute,
                },
                target: 0x140d3db44,
                enabled: false,
                original_bytes: vec![0x4d, 0x8b, 0xb7, 0xc8, 0x00, 0x00, 0x00],
                cave_addr: 0,
            },
            None,
            Some("Stub test"),
        );
        drop(s);

        let res = execute_set_cheat_toggle(&session, &ctx, SetCheatToggleArgs {
            id: cid,
            enabled: true,
        });
        assert!(res.is_err(), "enabling empty override toggle must return an error");
        let err_msg = res.unwrap_err().message;
        assert!(err_msg.contains("empty override hook with no payload"), "err_msg: {err_msg}");

        // Verify session state: no pending ops were staged, undo log is empty, and cheat remains disabled
        let s = session.lock().unwrap();
        assert_eq!(s.list_pending().len(), 0);
        assert_eq!(s.undo_len(), 0);
        let c = s.get_cheat(cid).unwrap();
        match &c.kind {
            CheatKind::Toggle { enabled, .. } => assert!(!enabled),
            _ => panic!("wrong cheat kind"),
        }
    }

    #[test]
    fn test_execute_scan_rgrep() {
        let session = Arc::new(Mutex::new(SessionState::new()));
        let mut s = session.lock().unwrap();
        let ctx = s.create_context("test-rgrep", ClientKind::Internal);
        drop(s);

        // Buffer with ASCII strings and binary patterns
        let mut data = vec![0u8; 1024];
        data[0x100..0x10d].copy_from_slice(b"Player_Health");
        data[0x200..0x10d + 0x100].copy_from_slice(b"Player_Energy");
        data[0x300..0x303].copy_from_slice(&[0x48, 0x89, 0x5C]);

        struct RgrepMem {
            data: Vec<u8>,
        }
        impl ProcessMemory for RgrepMem {
            fn read(&self, address: u64, len: usize) -> Result<Vec<u8>, crate::memory::MemoryError> {
                let start = address as usize;
                let end = (start + len).min(self.data.len());
                if start >= self.data.len() {
                    return Err(crate::memory::MemoryError::OutOfRange { address });
                }
                Ok(self.data[start..end].to_vec())
            }
            fn write(&self, _address: u64, _data: &[u8]) -> Result<usize, crate::memory::MemoryError> {
                Ok(0)
            }
            fn regions(&self) -> Result<Vec<crate::memory::Region>, crate::memory::MemoryError> {
                Ok(vec![crate::memory::Region {
                    start: 0,
                    end: 1024,
                    readable: true,
                    writable: true,
                    executable: false,
                    name: None,
                }])
            }
        }

        let proc = RgrepMem { data };

        // Regex scan for "Player_.*"
        let res = execute_scan_rgrep(&session, &ctx, &proc, ScanRgrepArgs {
            pattern: "Player_[A-Za-z]+".into(),
            alignment: Some(4),
            region: None,
            marker: Some("player_str".into()),
            limit: Some(10),
        }).unwrap();

        assert!(res.message.contains("2 match(es)"));
        assert!(res.message.contains("0x0000000000000100"));
        assert!(res.message.contains("0x0000000000000200"));

        // Marker auto-set
        let s = session.lock().unwrap();
        let m = s.get_marker("player_str").unwrap();
        assert_eq!(m.address, 0x100);
    }
}
