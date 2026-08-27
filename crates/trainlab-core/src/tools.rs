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
    pub content: String,
    pub kind: String,
    pub marker: Option<String>,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanPointerArgs {
    pub address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetMarkerArgs {
    pub label: String,
    pub address: String,
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
    pub hotkey: Option<String>,
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
    let data = proc.read(addr, max_len).map_err(|e| e.to_string())?;
    let len = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8(data[..len].to_vec()).map_err(|e| format!("invalid utf-8: {e}"))
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
    let mut bytes = args.content.as_bytes().to_vec();

    let is_rust = kind == "rust";
    let is_c_like = matches!(kind.as_str(), "c" | "json" | "yaml" | "xml" | "js" | "config");

    if !is_rust && !is_c_like {
        return Err(err(format!("unknown string kind '{kind}' (expected 'c', 'rust', 'json', 'yaml', 'xml', 'js', or 'config')")));
    }

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
            if let Some(m) = &args.marker {
                let _ = s.set_marker(m, alloc_addr, Some(&format!("Allocated string ('{kind}', {len} bytes)")));
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

    let regions = mem.regions().map_err(|e| err(format!("regions failed: {e}")))?;
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

    let regions = mem.regions().map_err(|e| err(format!("regions failed: {e}")))?;
    let mut matches = Vec::new();

    for r in regions {
        if !r.readable {
            continue;
        }
        let len = (r.end - r.start) as usize;
        if len < parsed_pat.len() {
            continue;
        }
        if let Ok(buf) = mem.read(r.start, len) {
            for off in crate::aob::find_all(&buf, &parsed_pat) {
                let match_addr = (r.start + off as u64) as i64 + args.offset.unwrap_or(0);
                matches.push(match_addr as u64);
            }
        }
    }

    let count = matches.len();

    if let Some(m) = &args.marker {
        if let Some(&first) = matches.first() {
            if let Ok(mut s) = session.lock() {
                let _ = s.set_marker(m, first, Some(&format!("AOB match for '{}'", args.pattern)));
            }
        }
    }

    if let Ok(mut s) = session.lock() {
        s.log_activity(&ctx.id, format!("AOB scan '{}': {count} match(es)", args.pattern));
    }

    let lines: Vec<String> = matches.iter().take(20).map(|m| format!("{m:#018x}")).collect();
    let mut text = format!("{count} match(es)\n");
    text.push_str(&lines.join("\n"));
    if count > 20 {
        text.push_str(&format!("\n... and {} more", count - 20));
    }

    Ok(ToolResult::with_data(
        text,
        serde_json::json!({
            "count": count,
            "matches": matches,
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
    let lines: Vec<String> = matches.iter().take(50).map(|(a, p)| format!("{a:#018x} -> {p:#018x}")).collect();
    let mut text = format!("{count} referrer(s)\n");
    text.push_str(&lines.join("\n"));
    if count > 50 {
        text.push_str(&format!("\n... and {} more", count - 50));
    }

    if let Ok(mut s) = session.lock() {
        s.log_activity(&ctx.id, format!("pointer scan for {address:#x}: {count} referrer(s)"));
    }

    Ok(ToolResult::with_data(
        text,
        serde_json::json!({
            "count": count,
            "target": address,
            "referrers": matches.iter().map(|(a, p)| serde_json::json!({ "address": a, "points_to": p })).collect::<Vec<_>>(),
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
    let mut offsets = Vec::new();
    for o in &args.offsets {
        offsets.push(eval_addr_expr(session, o, Some(mem))?);
    }

    let hops = crate::pointer::chase(mem, base, &offsets).map_err(|e| err(e.to_string()))?;
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

    Ok(ToolResult::with_data(
        lines.join("\n"),
        serde_json::json!({
            "base": base,
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
    let mut s = session.lock().map_err(|_| err("session lock poisoned"))?;
    s.set_marker(&args.label, target_addr, args.note.as_deref()).map_err(err)?;
    s.log_activity(&ctx.id, format!("saved marker '${}' = {target_addr:#x}", args.label));

    Ok(ToolResult::with_data(
        format!("saved marker '${}' = {target_addr:#x}", args.label),
        serde_json::json!({
            "label": args.label,
            "address": target_addr,
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
        other => return Err(err(format!("unsupported cheat kind: '{other}'"))),
    };

    let mut s = session.lock().map_err(|_| err("session lock poisoned"))?;
    let id = s.add_cheat(&args.label, cheat_kind, args.hotkey.as_deref(), args.note.as_deref());
    s.log_activity(&ctx.id, format!("added cheat '{}' (id {id})", args.label));

    Ok(ToolResult::with_data(
        format!("added cheat '{}' (id {id})", args.label),
        serde_json::json!({
            "id": id,
            "label": args.label,
            "client_id": ctx.id,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{ClientKind, SessionState};
    use std::sync::{Arc, Mutex};

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
        data[4..8].copy_from_slice(&3.14f32.to_le_bytes());
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
        assert!(res_struct.message.contains("speed: 3.14"));
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
}
