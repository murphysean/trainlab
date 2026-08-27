//! Unified expression parsing, value formatting, and byte conversions.
//!
//! Provides the single source of truth for:
//! - Recursive nested bracket pointer dereferencing: `[[[$player_base+0x8]+0x10]+0x14]`
//! - Marker resolution (`$wood_ptr`) and offset arithmetic (`base + 0x48`, `base - 0x10`)
//! - Loaded module base resolution (`GameAssembly.dll`, `game.exe`)
//! - Typed value encoding/decoding (`i32`, `u32`, `f32`, `i64`, `u64`, `f64`, `ptr`)
//! - Hex string decoding and formatting

use crate::memory::ProcessMemory;
use crate::scan::ValueType;

/// Format a little-endian byte slice as a human-readable string based on the given `ValueType`.
pub fn format_value(data: &[u8], vt: ValueType) -> String {
    let need = vt.size();
    if data.len() < need {
        return "?".to_string();
    }
    match vt {
        ValueType::I32 => i32::from_le_bytes([data[0], data[1], data[2], data[3]]).to_string(),
        ValueType::U32 => u32::from_le_bytes([data[0], data[1], data[2], data[3]]).to_string(),
        ValueType::F32 => f32::from_le_bytes([data[0], data[1], data[2], data[3]]).to_string(),
        ValueType::I64 => i64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ])
        .to_string(),
        ValueType::U64 => u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ])
        .to_string(),
        ValueType::F64 => f64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ])
        .to_string(),
        ValueType::Ptr => u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ])
        .to_string(),
    }
}

/// Parse a decimal, hex, or float string into little-endian bytes for a given `ValueType`.
pub fn parse_value_bytes(s: &str, vt: ValueType) -> Result<Vec<u8>, String> {
    let s = s.trim();
    match vt {
        ValueType::I32 => {
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                let v = i32::from_str_radix(hex, 16).map_err(|e| e.to_string())?;
                Ok(v.to_le_bytes().to_vec())
            } else {
                Ok(s.parse::<i32>().map_err(|e| e.to_string())?.to_le_bytes().to_vec())
            }
        }
        ValueType::U32 => {
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                let v = u32::from_str_radix(hex, 16).map_err(|e| e.to_string())?;
                Ok(v.to_le_bytes().to_vec())
            } else {
                Ok(s.parse::<u32>().map_err(|e| e.to_string())?.to_le_bytes().to_vec())
            }
        }
        ValueType::F32 => Ok(s.parse::<f32>().map_err(|e| e.to_string())?.to_le_bytes().to_vec()),
        ValueType::I64 => {
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                let v = i64::from_str_radix(hex, 16).map_err(|e| e.to_string())?;
                Ok(v.to_le_bytes().to_vec())
            } else {
                Ok(s.parse::<i64>().map_err(|e| e.to_string())?.to_le_bytes().to_vec())
            }
        }
        ValueType::U64 => {
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                let v = u64::from_str_radix(hex, 16).map_err(|e| e.to_string())?;
                Ok(v.to_le_bytes().to_vec())
            } else {
                Ok(s.parse::<u64>().map_err(|e| e.to_string())?.to_le_bytes().to_vec())
            }
        }
        ValueType::F64 => Ok(s.parse::<f64>().map_err(|e| e.to_string())?.to_le_bytes().to_vec()),
        ValueType::Ptr => {
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                let v = u64::from_str_radix(hex, 16).map_err(|e| e.to_string())?;
                Ok(v.to_le_bytes().to_vec())
            } else {
                Ok(s.parse::<u64>().map_err(|e| e.to_string())?.to_le_bytes().to_vec())
            }
        }
    }
}

/// Parse a whitespace-tolerant or continuous hex string into raw bytes.
pub fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.is_empty() {
        return Ok(Vec::new());
    }
    if !clean.len().is_multiple_of(2) {
        return Err(format!("odd hex string length: {}", clean.len()));
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).map_err(|e| format!("invalid hex byte: {e}")))
        .collect()
}

/// Parse a ValueType from a case-insensitive string identifier.
pub fn parse_value_type(s: &str) -> Result<ValueType, String> {
    match s.trim().to_lowercase().as_str() {
        "i32" | "int" | "int32" => Ok(ValueType::I32),
        "u32" | "uint" | "uint32" => Ok(ValueType::U32),
        "f32" | "float" => Ok(ValueType::F32),
        "i64" | "int64" => Ok(ValueType::I64),
        "u64" | "uint64" => Ok(ValueType::U64),
        "f64" | "double" => Ok(ValueType::F64),
        "ptr" | "pointer" | "usize" => Ok(ValueType::Ptr),
        other => Err(format!("unsupported value type: '{other}'")),
    }
}

/// Parse an address string (hex or dec) into a u64 address.
pub fn parse_addr_str(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|e| format!("invalid hex address '{s}': {e}"))
    } else if let Ok(a) = s.parse::<u64>() {
        Ok(a)
    } else if let Ok(a) = u64::from_str_radix(s, 16) {
        Ok(a)
    } else {
        Err(format!("invalid address string '{s}'"))
    }
}

/// Parse and evaluate an address expression with nested brackets, offsets, module names, and markers.
///
/// Supports:
/// - Nested bracket dereferencing: `[[[$player_base + 0x08] + 0x10] + 0x14]`
/// - Offset arithmetic: `marker + 0x48`, `module.dll + 0x100 - 0x10`
/// - Raw hex / decimal: `0x14001000`, `4096`
/// - Marker resolution via closure `resolve_marker`
/// - Module base resolution via closure `resolve_module`
pub fn parse_addr_expr_custom<FMarker, FModule>(
    input: &str,
    mem: Option<&dyn ProcessMemory>,
    resolve_marker: &FMarker,
    resolve_module: &FModule,
) -> Result<u64, String>
where
    FMarker: Fn(&str) -> Option<u64>,
    FModule: Fn(&str) -> Option<u64>,
{
    let input = input.trim();

    // 0. Handle top-level addition/subtraction outside of brackets, e.g. `[base + 0x10] + 0x20`
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
                split_idx = Some(i);
                is_add = false;
                break;
            }
            _ => {}
        }
    }

    if let Some(idx) = split_idx {
        let (base_part, off_part) = (&input[..idx], &input[idx + 1..]);
        let base = parse_addr_expr_custom(base_part, mem, resolve_marker, resolve_module)?;
        let off = parse_addr_str(off_part.trim())?;
        return Ok(if is_add {
            base.wrapping_add(off)
        } else {
            base.wrapping_sub(off)
        });
    }

    // 1. Check for nested bracket dereference: `[ <inner_expr> ]`
    if input.starts_with('[') && input.ends_with(']') {
        let inner = &input[1..input.len() - 1].trim();
        let ptr_addr = parse_addr_expr_custom(inner, mem, resolve_marker, resolve_module)?;

        let proc = mem.ok_or_else(|| {
            format!("cannot dereference pointer '{input}': no process memory provider attached")
        })?;

        let data = proc.read(ptr_addr, 8).map_err(|e| {
            format!("failed to dereference pointer at {ptr_addr:#x} (from '{input}'): {e}")
        })?;

        if data.len() < 8 {
            return Err(format!("short read dereferencing pointer at {ptr_addr:#x} (from '{input}')"));
        }
        let target_ptr = u64::from_le_bytes(data[..8].try_into().unwrap());
        return Ok(target_ptr);
    }

    // 2. Try raw hex or decimal
    if let Some(hex) = input.strip_prefix("0x").or_else(|| input.strip_prefix("0X")) {
        if let Ok(a) = u64::from_str_radix(hex, 16) {
            return Ok(a);
        }
    } else if let Ok(a) = input.parse::<u64>() {
        return Ok(a);
    }

    // 3. Try looking up marker
    let marker_name = input.strip_prefix('$').unwrap_or(input);
    if let Some(addr) = resolve_marker(marker_name).or_else(|| resolve_marker(input)) {
        return Ok(addr);
    }

    // 4. Try looking up loaded module base
    if let Some(addr) = resolve_module(input) {
        return Ok(addr);
    }

    // Fallback try raw hex without 0x if all characters are hex
    if !input.is_empty() && input.chars().all(|c| c.is_ascii_hexdigit())
        && let Ok(a) = u64::from_str_radix(input, 16) {
            return Ok(a);
        }

    Err(format!(
        "could not resolve address expression '{input}' (not a raw hex/dec address, marker, or loaded module)"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

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
        fn write(&self, _address: u64, _data: &[u8]) -> Result<usize, crate::memory::MemoryError> {
            Ok(0)
        }
        fn regions(&self) -> Result<Vec<crate::memory::Region>, crate::memory::MemoryError> {
            Ok(vec![])
        }
    }

    #[test]
    fn test_format_and_parse_values() {
        assert_eq!(format_value(&12345i32.to_le_bytes(), ValueType::I32), "12345");
        assert_eq!(format_value(&3.25f32.to_le_bytes(), ValueType::F32), "3.25");
        assert_eq!(
            parse_value_bytes("999", ValueType::I32).unwrap(),
            999i32.to_le_bytes().to_vec()
        );
        assert_eq!(
            parse_value_bytes("0x100", ValueType::U32).unwrap(),
            256u32.to_le_bytes().to_vec()
        );
    }

    #[test]
    fn test_parse_hex_bytes() {
        assert_eq!(parse_hex_bytes("48 8B 05").unwrap(), vec![0x48, 0x8b, 0x05]);
        assert_eq!(parse_hex_bytes("488b05").unwrap(), vec![0x48, 0x8b, 0x05]);
    }

    #[test]
    fn test_parse_addr_expr_multi_hop_chain() {
        let mut data = vec![0u8; 0x4000];
        let ptr1: u64 = 0x2000;
        let ptr2: u64 = 0x3000;
        data[0x1008..0x1010].copy_from_slice(&ptr1.to_le_bytes());
        data[0x2010..0x2018].copy_from_slice(&ptr2.to_le_bytes());
        data[0x3014..0x3018].copy_from_slice(&42.5f32.to_le_bytes());

        let mem = MockMem { data };

        let markers = std::collections::HashMap::from([("player_base".to_string(), 0x1000u64)]);
        let resolve_marker = |name: &str| markers.get(name).copied();
        let resolve_module = |_name: &str| None;

        // Test 1 hop: [$player_base + 0x08] -> 0x2000
        let res1 = parse_addr_expr_custom("[$player_base + 0x08]", Some(&mem), &resolve_marker, &resolve_module).unwrap();
        assert_eq!(res1, 0x2000);

        // Test 2 hops: [[$player_base + 0x08] + 0x10] -> 0x3000
        let res2 = parse_addr_expr_custom("[[$player_base + 0x08] + 0x10]", Some(&mem), &resolve_marker, &resolve_module).unwrap();
        assert_eq!(res2, 0x3000);

        // Test 3 hops + final offset: [[[$player_base + 0x08] + 0x10] + 0x14] -> 0x3014
        let res3 = parse_addr_expr_custom("[[$player_base + 0x08] + 0x10] + 0x14", Some(&mem), &resolve_marker, &resolve_module).unwrap();
        assert_eq!(res3, 0x3014);

        let final_val = mem.read(res3, 4).unwrap();
        assert_eq!(f32::from_le_bytes(final_val.try_into().unwrap()), 42.5);
    }
}
