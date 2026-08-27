//! Universal, presentation-agnostic tool definitions and execution handlers.
//!
//! Every client (MCP server, REST API, Web dashboard, egui GUI, CLI) invokes these
//! exact same tools with typed arguments and receives structured results.

use serde::{Deserialize, Serialize};
use crate::expr::{format_value, parse_addr_expr_custom, parse_hex_bytes, parse_value_bytes, parse_value_type};
use crate::memory::ProcessMemory;
use crate::session::{CheatKind, SharedSession};

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
// Tool Arguments
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
    mem: &dyn ProcessMemory,
    args: ReadArgs,
) -> Result<ToolResult, ToolError> {
    let target_addr = eval_addr_expr(session, &args.address, Some(mem))?;

    if let Some(vt_str) = &args.value_type {
        let vt = parse_value_type(vt_str).map_err(err)?;
        let read_len = vt.size();
        let bytes = mem.read(target_addr, read_len).map_err(|e| err(e.to_string()))?;
        let formatted = format_value(&bytes, vt);
        Ok(ToolResult::with_data(
            format!("{formatted} ({vt_str} @ {target_addr:#x})"),
            serde_json::json!({
                "address": target_addr,
                "value": formatted,
                "value_type": vt_str,
                "bytes_read": read_len,
            }),
        ))
    } else {
        let len = args.len.unwrap_or(4).min(4096);
        let bytes = mem.read(target_addr, len).map_err(|e| err(e.to_string()))?;
        let hex = bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
        Ok(ToolResult::with_data(
            hex.clone(),
            serde_json::json!({
                "address": target_addr,
                "hex": hex,
                "bytes_read": bytes.len(),
            }),
        ))
    }
}

/// Execute a memory write operation (stages through D8 gate).
pub fn execute_write(
    session: &SharedSession,
    mem: Option<&dyn ProcessMemory>,
    args: WriteArgs,
) -> Result<ToolResult, ToolError> {
    let target_addr = eval_addr_expr(session, &args.address, mem)?;

    let (bytes, desc) = if let Some(val_str) = &args.value {
        let vt_str = args.value_type.as_deref().unwrap_or("i32");
        let vt = parse_value_type(vt_str).map_err(err)?;
        let data = parse_value_bytes(val_str, vt).map_err(err)?;
        (data, format!("write {val_str} ({vt_str}) @ {target_addr:#x}"))
    } else if let Some(hex_data) = &args.data {
        let data = parse_hex_bytes(hex_data).map_err(err)?;
        (data, format!("write {} byte(s) @ {target_addr:#x}", hex_data.len()))
    } else {
        return Err(err("either 'value' (with value_type) or 'data' (hex) must be provided"));
    };

    let mut s = session.lock().map_err(|_| err("session lock poisoned"))?;
    let op_id = s.stage_op(
        target_addr,
        crate::session::PendingKind::Write { data: bytes.clone() },
        desc.clone(),
    );
    s.log_activity("CORE", format!("staged write op #{op_id} @ {target_addr:#x}"));

    Ok(ToolResult::with_data(
        format!("staged write op #{op_id}: {desc}. Apply with 'confirm_op' (id {op_id}) or discard with 'reject_op'."),
        serde_json::json!({
            "op_id": op_id,
            "address": target_addr,
            "bytes_len": bytes.len(),
        }),
    ))
}

/// Execute a pointer chase operation.
pub fn execute_pointer_chase(
    session: &SharedSession,
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
        }),
    ))
}

/// Set a labeled marker in the session.
pub fn execute_set_marker(
    session: &SharedSession,
    mem: Option<&dyn ProcessMemory>,
    args: SetMarkerArgs,
) -> Result<ToolResult, ToolError> {
    let target_addr = eval_addr_expr(session, &args.address, mem)?;
    let mut s = session.lock().map_err(|_| err("session lock poisoned"))?;
    s.set_marker(&args.label, target_addr, args.note.as_deref()).map_err(err)?;
    s.log_activity("CORE", format!("saved marker '${}' = {target_addr:#x}", args.label));

    Ok(ToolResult::with_data(
        format!("saved marker '${}' = {target_addr:#x}", args.label),
        serde_json::json!({
            "label": args.label,
            "address": target_addr,
        }),
    ))
}

/// Add a cheat to the session.
pub fn execute_add_cheat(
    session: &SharedSession,
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
    s.log_activity("CORE", format!("added cheat '{}' (id {id})", args.label));

    Ok(ToolResult::with_data(
        format!("added cheat '{}' (id {id})", args.label),
        serde_json::json!({
            "id": id,
            "label": args.label,
        }),
    ))
}
