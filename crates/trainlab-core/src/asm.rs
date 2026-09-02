//! x86-64 Assembly parser and compiler built on `iced-x86::code_asm`.
//!
//! Supports Cheat Engine style assembly scripts:
//! - Directives: `dd (float)4.0`, `dd 100`, `dq 0x1234`, `db 0x90 0x90`
//! - Instruction mnemonics: `mov`, `movss`, `movsd`, `mulss`, `divss`, `addss`, `subss`,
//!   `add`, `sub`, `inc`, `dec`, `xor`, `cmp`, `test`, `jmp`, `push`, `pop`, `ret`, `nop`
//! - Operands: registers (`rax`, `xmm0`, etc.), immediates, memory dereferences (`[rax+0x10]`, `dword ptr [rbx]`),
//!   and named markers (`$cave_const`, `[rip + $mining_mult]`, `jmp $return_addr`).

use std::collections::HashMap;

/// Result of assembling an assembly text block.
#[derive(Debug, Clone)]
pub struct AssembledBlock {
    pub bytes: Vec<u8>,
    pub hex: String,
    pub instruction_count: usize,
    /// Offset of each defined label relative to the start of the assembled byte stream (0-indexed).
    pub label_offsets: HashMap<String, u64>,
}

/// Assemble an assembly text block at a given base address (origin RIP).
/// Symbol references like `$marker_name` or `label` are resolved via `symbols`.
pub fn assemble_text(
    asm_code: &str,
    origin_rip: u64,
    symbols: &HashMap<String, u64>,
) -> Result<AssembledBlock, String> {
    use iced_x86::code_asm::*;

    let mut a = CodeAssembler::new(64).map_err(|e| format!("assembler init: {e}"))?;
    let mut labels_map: HashMap<String, CodeLabel> = HashMap::new();
    let mut defined_labels: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut referenced_labels: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut total_instructions = 0usize;

    let lines: Vec<&str> = asm_code.lines().collect();

    // First pass: scan for all defined labels `label_name:`
    for raw_line in &lines {
        let line = strip_comments(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        if let Some(label_name) = line.strip_suffix(':') {
            let name = label_name.trim().to_lowercase();
            if !labels_map.contains_key(&name) {
                let lbl = a.create_label();
                labels_map.insert(name.clone(), lbl);
            }
            defined_labels.insert(name);
        }
    }

    let mut label_offsets = HashMap::new();
    let mut current_offset: u64 = 0;
    let mut pending_labels: Vec<String> = Vec::new();

    // Second pass: emit instructions and directives, tracking exact byte offsets
    for raw_line in &lines {
        let line = strip_comments(raw_line).trim();
        if line.is_empty() {
            continue;
        }

        // Check for label definition: `my_label:`
        if let Some(label_name) = line.strip_suffix(':') {
            let name = label_name.trim().to_lowercase();
            if let Some(lbl) = labels_map.get_mut(&name) {
                let _ = a.set_label(lbl);
            }
            label_offsets.insert(name.clone(), current_offset);
            pending_labels.push(name);
            continue;
        }

        // Data Directives: `dd (float)4.0`, `dd 100`, `dq 0x...`, `db 90 90`
        if let Some(rest) = line.strip_prefix("dd ").or_else(|| line.strip_prefix("DD ")) {
            let b = parse_dd(rest.trim(), symbols)?;
            current_offset += b.len() as u64;
            a.db(&b).map_err(|e| format!("db emit: {e}"))?;
            total_instructions += 1;
            pending_labels.clear();
            continue;
        }
        if let Some(rest) = line.strip_prefix("dq ").or_else(|| line.strip_prefix("DQ ")) {
            let b = parse_dq(rest.trim(), symbols)?;
            current_offset += b.len() as u64;
            a.db(&b).map_err(|e| format!("db emit: {e}"))?;
            total_instructions += 1;
            pending_labels.clear();
            continue;
        }
        if let Some(rest) = line.strip_prefix("db ").or_else(|| line.strip_prefix("DB ")) {
            let b = parse_db(rest.trim())?;
            current_offset += b.len() as u64;
            a.db(&b).map_err(|e| format!("db emit: {e}"))?;
            total_instructions += 1;
            pending_labels.clear();
            continue;
        }

        // Parse standard instruction: mnemonic op1, op2
        // Assemble single instruction in temporary CodeAssembler to determine encoded byte length
        let mut temp_asm = CodeAssembler::new(64).map_err(|e| format!("temp assembler init: {e}"))?;
        let mut temp_labels = labels_map.clone();
        let mut temp_ref = referenced_labels.clone();
        let instr_len = if parse_and_emit_instruction(&mut temp_asm, line, origin_rip + current_offset, symbols, &mut temp_labels, &mut temp_ref).is_ok()
            && let Ok(encoded) = temp_asm.assemble(origin_rip + current_offset) {
                encoded.len() as u64
            } else {
                // Fallback estimate if temp assemble had unresolved branches
                5
            };

        parse_and_emit_instruction(&mut a, line, origin_rip, symbols, &mut labels_map, &mut referenced_labels)?;
        current_offset += instr_len;
        total_instructions += 1;
        pending_labels.clear();
    }

    // Check for any referenced label that was not defined
    for ref_lbl in &referenced_labels {
        if !defined_labels.contains(ref_lbl) {
            return Err(format!("unresolved label or marker '{ref_lbl}'"));
        }
    }

    // In iced_x86 CodeAssembler, a label set at the very end of the code stream
    // without any trailing instruction or byte causes "Unused label".
    // If the last emitted element was a label, emit a 0-byte slice / nop or let it assemble.
    let options = iced_x86::BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS;
    let format_assemble_error = |e: iced_x86::IcedError| -> String {
        let err_str = e.to_string();
        if err_str.contains("Displacement must fit in an i32") || err_str.contains("displacement") {
            format!(
                "assemble error: {err_str} (rip-relative [rip + label] reference exceeds ±2GB limit from origin {origin_rip:#x}; use 64-bit load 'mov r64, $marker' followed by 'cmp/mov reg, [r64]')"
            )
        } else {
            format!("assemble error: {err_str}")
        }
    };

    let assembled = match a.assemble_options(origin_rip, options) {
        Ok(result) => {
            // Update labels with exact IPs from the block encoder when available
            for (name, lbl) in &labels_map {
                if let Ok(label_ip) = result.label_ip(lbl) {
                    let offset = label_ip.saturating_sub(origin_rip);
                    label_offsets.insert(name.clone(), offset);
                }
            }
            result.inner.code_buffer
        }
        Err(e) if e.to_string().contains("Unused label") => {
            let _ = a.nop();
            let result = a.assemble_options(origin_rip, options).map_err(format_assemble_error)?;
            for (name, lbl) in &labels_map {
                if let Ok(label_ip) = result.label_ip(lbl) {
                    let offset = label_ip.saturating_sub(origin_rip);
                    label_offsets.insert(name.clone(), offset);
                }
            }
            result.inner.code_buffer
        }
        Err(e) => return Err(format_assemble_error(e)),
    };

    let hex = assembled.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");

    Ok(AssembledBlock {
        bytes: assembled,
        hex,
        instruction_count: total_instructions,
        label_offsets,
    })
}

/// Checks assembly code for trampoline code cave hazards where execution falls through
/// into data directive slots (`db`, `dd`, `dq`).
///
/// In a trampoline cave, the stolen-instruction replay is appended directly at the end
/// of the assembled payload. If the payload contains trailing data slots (or intermediate
/// data slots) that are not bypassed by an unconditional branch (`jmp`, `ret`), execution
/// will fall through and execute data bytes as x86-64 code.
pub fn check_trampoline_data_fallthrough(asm_code: &str) -> Result<(), String> {
    #[derive(Debug, PartialEq, Eq)]
    enum ItemKind {
        TerminatingInstr,   // jmp, ret
        NonTerminatingInstr,// push, pop, mov, add, cmp, etc.
        DataDirective,      // db, dd, dq
    }

    let lines: Vec<&str> = asm_code.lines().collect();
    let mut items: Vec<ItemKind> = Vec::new();

    for raw_line in lines {
        let line = strip_comments(raw_line).trim();
        if line.is_empty() || line.ends_with(':') {
            continue;
        }
        let lower = line.to_lowercase();
        if lower.starts_with("db ") || lower.starts_with("dd ") || lower.starts_with("dq ")
            || lower == "db" || lower == "dd" || lower == "dq" {
            items.push(ItemKind::DataDirective);
        } else {
            let mnemonic = lower.split_whitespace().next().unwrap_or("");
            if matches!(mnemonic, "jmp" | "ret") {
                items.push(ItemKind::TerminatingInstr);
            } else {
                items.push(ItemKind::NonTerminatingInstr);
            }
        }
    }

    // If there are no data directives, nothing can be executed as code accidentally
    if !items.contains(&ItemKind::DataDirective) {
        return Ok(());
    }

    // In a trampoline cave, control must never fall through from a non-terminating instruction
    // into a data directive.
    let mut last_instr_was_terminating = true;
    for item in &items {
        match item {
            ItemKind::NonTerminatingInstr => {
                last_instr_was_terminating = false;
            }
            ItemKind::TerminatingInstr => {
                last_instr_was_terminating = true;
            }
            ItemKind::DataDirective => {
                if !last_instr_was_terminating {
                    return Err(
                        "trampoline cave payload has instructions falling through directly into data directives (db/dd/dq). \
Execution will decode data bytes as code and crash once slots hold non-zero values.\n\
Fix by jumping over data slots to a tail label, e.g.:\n  jmp code\n  my_slot:\n  dq 0\n  code:\n\
Or pass 'force: true' to bypass this safety check.".into()
                    );
                }
            }
        }
    }

    Ok(())
}

fn strip_comments(s: &str) -> &str {
    if let Some(idx) = s.find(';') {
        &s[..idx]
    } else if let Some(idx) = s.find("//") {
        &s[..idx]
    } else {
        s
    }
}

fn parse_dd(s: &str, symbols: &HashMap<String, u64>) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if let Some(f_str) = s.strip_prefix("(float)").or_else(|| s.strip_prefix("(FLOAT)")) {
        let f: f32 = f_str.trim().parse().map_err(|e| format!("invalid float '{f_str}': {e}"))?;
        return Ok(f.to_le_bytes().to_vec());
    }
    if s.contains('.')
        && let Ok(f) = s.parse::<f32>() {
            return Ok(f.to_le_bytes().to_vec());
        }
    let val = parse_u64_expr(s, symbols)?;
    Ok((val as u32).to_le_bytes().to_vec())
}

fn parse_dq(s: &str, symbols: &HashMap<String, u64>) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if let Some(f_str) = s.strip_prefix("(double)").or_else(|| s.strip_prefix("(DOUBLE)")) {
        let f: f64 = f_str.trim().parse().map_err(|e| format!("invalid double '{f_str}': {e}"))?;
        return Ok(f.to_le_bytes().to_vec());
    }
    let val = parse_u64_expr(s, symbols)?;
    Ok(val.to_le_bytes().to_vec())
}

fn parse_db(s: &str) -> Result<Vec<u8>, String> {
    let parts = s.split_whitespace();
    let mut out = Vec::new();
    for p in parts {
        let p_clean = p.trim().trim_start_matches("0x").trim_start_matches("0X");
        let b = u8::from_str_radix(p_clean, 16).map_err(|e| format!("invalid byte '{p}': {e}"))?;
        out.push(b);
    }
    Ok(out)
}

fn parse_u64_expr(s: &str, symbols: &HashMap<String, u64>) -> Result<u64, String> {
    let s = s.trim();
    if let Some(sym_name) = s.strip_prefix('$') {
        if let Some(addr) = symbols.get(sym_name) {
            return Ok(*addr);
        }
        return Err(format!("unknown symbol '${sym_name}'"));
    }
    if let Some(addr) = symbols.get(s) {
        return Ok(*addr);
    }
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16).map_err(|e| format!("invalid hex '{s}': {e}"))
    } else if let Ok(n) = s.parse::<i64>() {
        Ok(n as u64)
    } else {
        s.parse::<u64>().map_err(|e| format!("invalid int '{s}': {e}"))
    }
}

fn parse_and_emit_instruction(
    a: &mut iced_x86::code_asm::CodeAssembler,
    line: &str,
    origin_rip: u64,
    symbols: &HashMap<String, u64>,
    labels: &mut HashMap<String, iced_x86::code_asm::CodeLabel>,
    referenced_labels: &mut std::collections::HashSet<String>,
) -> Result<(), String> {
    

    let line = line.trim();
    let (mnemonic, args_str) = match line.find(|c: char| c.is_whitespace()) {
        Some(idx) => (line[..idx].trim().to_lowercase(), line[idx..].trim()),
        None => (line.to_lowercase(), ""),
    };

    let args: Vec<&str> = if args_str.is_empty() {
        Vec::new()
    } else {
        args_str.split(',').map(|s| s.trim()).collect()
    };

    match mnemonic.as_str() {
        "nop" => { a.nop().map_err(|e| e.to_string())?; }
        "ret" => { a.ret().map_err(|e| e.to_string())?; }
        "push" => {
            if args.len() != 1 { return Err("push requires 1 operand".into()); }
            let reg = parse_gpr64(args[0])?;
            a.push(reg).map_err(|e| e.to_string())?;
        }
        "pop" => {
            if args.len() != 1 { return Err("pop requires 1 operand".into()); }
            let reg = parse_gpr64(args[0])?;
            a.pop(reg).map_err(|e| e.to_string())?;
        }
        "jmp" => {
            if args.len() != 1 { return Err("jmp requires 1 operand".into()); }
            let target = args[0].trim();
            if let Some(sym) = target.strip_prefix('$')
                && let Some(target_addr) = symbols.get(sym) {
                    a.jmp(*target_addr).map_err(|e| e.to_string())?;
                    return Ok(());
                }
            if let Ok(reg) = parse_gpr64(target) {
                a.jmp(reg).map_err(|e| e.to_string())?;
                return Ok(());
            }
            let name = target.trim_start_matches('$').to_lowercase();
            if labels.contains_key(&name) {
                referenced_labels.insert(name.clone());
                let lbl = *labels.get(&name).unwrap();
                a.jmp(lbl).map_err(|e| e.to_string())?;
                return Ok(());
            }
            if let Ok(imm) = parse_u64_expr(target, symbols) {
                a.jmp(imm).map_err(|e| e.to_string())?;
                return Ok(());
            }
            // Local label
            referenced_labels.insert(name.clone());
            let lbl = *labels.entry(name.clone()).or_insert_with(|| a.create_label());
            a.jmp(lbl).map_err(|e| e.to_string())?;
        }
        "mulss" => {
            if args.len() != 2 { return Err("mulss requires 2 operands (e.g. mulss xmm1, [rax+0x10])".into()); }
            let dst = parse_xmm(args[0])?;
            if let Ok(src) = parse_xmm(args[1]) {
                a.mulss(dst, src).map_err(|e| e.to_string())?;
            } else {
                let mem = parse_mem(args[1], symbols, origin_rip, labels, a, referenced_labels)?;
                a.mulss(dst, mem).map_err(|e| e.to_string())?;
            }
        }
        "divss" => {
            if args.len() != 2 { return Err("divss requires 2 operands (e.g. divss xmm2, [rax+0x10])".into()); }
            let dst = parse_xmm(args[0])?;
            if let Ok(src) = parse_xmm(args[1]) {
                a.divss(dst, src).map_err(|e| e.to_string())?;
            } else {
                let mem = parse_mem(args[1], symbols, origin_rip, labels, a, referenced_labels)?;
                a.divss(dst, mem).map_err(|e| e.to_string())?;
            }
        }
        "addss" => {
            if args.len() != 2 { return Err("addss requires 2 operands".into()); }
            let dst = parse_xmm(args[0])?;
            if let Ok(src) = parse_xmm(args[1]) {
                a.addss(dst, src).map_err(|e| e.to_string())?;
            } else {
                let mem = parse_mem(args[1], symbols, origin_rip, labels, a, referenced_labels)?;
                a.addss(dst, mem).map_err(|e| e.to_string())?;
            }
        }
        "subss" => {
            if args.len() != 2 { return Err("subss requires 2 operands".into()); }
            let dst = parse_xmm(args[0])?;
            if let Ok(src) = parse_xmm(args[1]) {
                a.subss(dst, src).map_err(|e| e.to_string())?;
            } else {
                let mem = parse_mem(args[1], symbols, origin_rip, labels, a, referenced_labels)?;
                a.subss(dst, mem).map_err(|e| e.to_string())?;
            }
        }
        "movss" => {
            if args.len() != 2 { return Err("movss requires 2 operands".into()); }
            if let Ok(dst) = parse_xmm(args[0]) {
                if let Ok(src) = parse_xmm(args[1]) {
                    a.movss(dst, src).map_err(|e| e.to_string())?;
                } else {
                    let mem = parse_mem(args[1], symbols, origin_rip, labels, a, referenced_labels)?;
                    a.movss(dst, mem).map_err(|e| e.to_string())?;
                }
            } else {
                let dst_mem = parse_mem(args[0], symbols, origin_rip, labels, a, referenced_labels)?;
                let src = parse_xmm(args[1])?;
                a.movss(dst_mem, src).map_err(|e| e.to_string())?;
            }
        }
        "mov" | "movabs" => {
            if args.len() != 2 { return Err(format!("{mnemonic} requires 2 operands")); }
            if let Ok(dst) = parse_gpr64(args[0]) {
                if let Ok(src) = parse_gpr64(args[1]) {
                    a.mov(dst, src).map_err(|e| e.to_string())?;
                } else if let Ok(mem) = parse_mem(args[1], symbols, origin_rip, labels, a, referenced_labels) {
                    a.mov(dst, mem).map_err(|e| e.to_string())?;
                } else if let Ok(imm) = parse_u64_expr(args[1], symbols) {
                    a.mov(dst, imm).map_err(|e| e.to_string())?;
                } else {
                    return Err(format!("unknown source operand for {mnemonic}: {}", args[1]));
                }
            } else if let Ok(dst) = parse_gpr32(args[0]) {
                if let Ok(src) = parse_gpr32(args[1]) {
                    a.mov(dst, src).map_err(|e| e.to_string())?;
                } else if let Ok(mem) = parse_mem(args[1], symbols, origin_rip, labels, a, referenced_labels) {
                    a.mov(dst, mem).map_err(|e| e.to_string())?;
                } else if let Ok(imm) = parse_u64_expr(args[1], symbols) {
                    a.mov(dst, imm as u32).map_err(|e| e.to_string())?;
                } else {
                    return Err(format!("unknown source operand for mov: {}", args[1]));
                }
            } else if let Ok(dst) = parse_gpr8(args[0]) {
                if let Ok(src) = parse_gpr8(args[1]) {
                    a.mov(dst, src).map_err(|e| e.to_string())?;
                } else if let Ok(mem) = parse_mem(args[1], symbols, origin_rip, labels, a, referenced_labels) {
                    a.mov(dst, mem).map_err(|e| e.to_string())?;
                } else if let Ok(imm) = parse_u64_expr(args[1], symbols) {
                    a.mov(dst, imm as u32).map_err(|e| e.to_string())?;
                } else {
                    return Err(format!("unknown source operand for mov: {}", args[1]));
                }
            } else if let Ok(dst_mem) = parse_mem(args[0], symbols, origin_rip, labels, a, referenced_labels) {
                if let Ok(src) = parse_gpr64(args[1]) {
                    a.mov(dst_mem, src).map_err(|e| e.to_string())?;
                } else if let Ok(src) = parse_gpr32(args[1]) {
                    a.mov(dst_mem, src).map_err(|e| e.to_string())?;
                } else if let Ok(src) = parse_gpr8(args[1]) {
                    a.mov(dst_mem, src).map_err(|e| e.to_string())?;
                } else if let Ok(imm) = parse_u64_expr(args[1], symbols) {
                    let mem_lower = args[0].to_lowercase();
                    if mem_lower.contains("byte") {
                        a.mov(dst_mem, imm as u32).map_err(|e| e.to_string())?;
                    } else if mem_lower.contains("qword") {
                        a.mov(dst_mem, imm as i32).map_err(|e| e.to_string())?;
                    } else {
                        a.mov(dst_mem, imm as u32).map_err(|e| e.to_string())?;
                    }
                } else {
                    return Err(format!("unknown source operand for mov to mem: {}", args[1]));
                }
            } else {
                return Err(format!("unsupported mov operands: {}, {}", args[0], args[1]));
            }
        }
        "cmp" => {
            if args.len() != 2 { return Err("cmp requires 2 operands".into()); }
            if let Ok(dst) = parse_gpr64(args[0]) {
                if let Ok(src) = parse_gpr64(args[1]) {
                    a.cmp(dst, src).map_err(|e| e.to_string())?;
                } else if let Ok(mem) = parse_mem(args[1], symbols, origin_rip, labels, a, referenced_labels) {
                    a.cmp(dst, mem).map_err(|e| e.to_string())?;
                } else if let Ok(imm) = parse_u64_expr(args[1], symbols) {
                    a.cmp(dst, imm as i32).map_err(|e| e.to_string())?;
                } else {
                    return Err(format!("unknown source operand for cmp {}: {}", args[0], args[1]));
                }
            } else if let Ok(dst) = parse_gpr32(args[0]) {
                if let Ok(src) = parse_gpr32(args[1]) {
                    a.cmp(dst, src).map_err(|e| e.to_string())?;
                } else if let Ok(mem) = parse_mem(args[1], symbols, origin_rip, labels, a, referenced_labels) {
                    a.cmp(dst, mem).map_err(|e| e.to_string())?;
                } else if let Ok(imm) = parse_u64_expr(args[1], symbols) {
                    a.cmp(dst, imm as i32).map_err(|e| e.to_string())?;
                } else {
                    return Err(format!("unknown source operand for cmp {}: {}", args[0], args[1]));
                }
            } else if let Ok(dst) = parse_gpr8(args[0]) {
                if let Ok(src) = parse_gpr8(args[1]) {
                    a.cmp(dst, src).map_err(|e| e.to_string())?;
                } else if let Ok(mem) = parse_mem(args[1], symbols, origin_rip, labels, a, referenced_labels) {
                    a.cmp(dst, mem).map_err(|e| e.to_string())?;
                } else if let Ok(imm) = parse_u64_expr(args[1], symbols) {
                    a.cmp(dst, imm as u32).map_err(|e| e.to_string())?;
                } else {
                    return Err(format!("unknown source operand for cmp {}: {}", args[0], args[1]));
                }
            } else if let Ok(dst_mem) = parse_mem(args[0], symbols, origin_rip, labels, a, referenced_labels) {
                if let Ok(src) = parse_gpr64(args[1]) {
                    a.cmp(dst_mem, src).map_err(|e| e.to_string())?;
                } else if let Ok(src) = parse_gpr32(args[1]) {
                    a.cmp(dst_mem, src).map_err(|e| e.to_string())?;
                } else if let Ok(src) = parse_gpr8(args[1]) {
                    a.cmp(dst_mem, src).map_err(|e| e.to_string())?;
                } else if let Ok(imm) = parse_u64_expr(args[1], symbols) {
                    let mem_lower = args[0].to_lowercase();
                    if mem_lower.contains("byte") {
                        a.cmp(dst_mem, imm as u32).map_err(|e| e.to_string())?;
                    } else if mem_lower.contains("qword") {
                        a.cmp(dst_mem, imm as i32).map_err(|e| e.to_string())?;
                    } else {
                        a.cmp(dst_mem, imm as i32).map_err(|e| e.to_string())?;
                    }
                } else {
                    return Err(format!("unknown source operand for cmp {}: {}", args[0], args[1]));
                }
            } else {
                return Err(format!("unsupported cmp operands: {}, {}", args[0], args[1]));
            }
        }
        "je" | "jz" | "jne" | "jnz" | "jg" | "jge" | "jl" | "jle" | "ja" | "jae" | "jb" | "jbe" | "js" | "jns" => {
            if args.len() != 1 { return Err(format!("{mnemonic} requires 1 operand")); }
            let target = args[0];
            let name = target.trim().trim_start_matches('$').to_lowercase();
            referenced_labels.insert(name.clone());
            let lbl = *labels.entry(name).or_insert_with(|| a.create_label());
            match mnemonic.as_str() {
                "je" | "jz" => { a.je(lbl).map_err(|e| e.to_string())?; }
                "jne" | "jnz" => { a.jne(lbl).map_err(|e| e.to_string())?; }
                "jg" => { a.jg(lbl).map_err(|e| e.to_string())?; }
                "jge" => { a.jge(lbl).map_err(|e| e.to_string())?; }
                "jl" => { a.jl(lbl).map_err(|e| e.to_string())?; }
                "jle" => { a.jle(lbl).map_err(|e| e.to_string())?; }
                "ja" => { a.ja(lbl).map_err(|e| e.to_string())?; }
                "jae" => { a.jae(lbl).map_err(|e| e.to_string())?; }
                "jb" => { a.jb(lbl).map_err(|e| e.to_string())?; }
                "jbe" => { a.jbe(lbl).map_err(|e| e.to_string())?; }
                "js" => { a.js(lbl).map_err(|e| e.to_string())?; }
                "jns" => { a.jns(lbl).map_err(|e| e.to_string())?; }
                _ => {}
            }
        }
        "test" => {
            if args.len() != 2 { return Err("test requires 2 operands".into()); }
            if let Ok(dst) = parse_gpr64(args[0]) {
                if let Ok(src) = parse_gpr64(args[1]) {
                    a.test(dst, src).map_err(|e| e.to_string())?;
                } else if let Ok(imm) = parse_u64_expr(args[1], symbols) {
                    a.test(dst, imm as i32).map_err(|e| e.to_string())?;
                } else {
                    return Err(format!("unknown source operand for test {}: {}", args[0], args[1]));
                }
            } else if let Ok(dst) = parse_gpr32(args[0]) {
                if let Ok(src) = parse_gpr32(args[1]) {
                    a.test(dst, src).map_err(|e| e.to_string())?;
                } else if let Ok(imm) = parse_u64_expr(args[1], symbols) {
                    a.test(dst, imm as i32).map_err(|e| e.to_string())?;
                } else {
                    return Err(format!("unknown source operand for test {}: {}", args[0], args[1]));
                }
            } else if let Ok(dst) = parse_gpr8(args[0]) {
                if let Ok(src) = parse_gpr8(args[1]) {
                    a.test(dst, src).map_err(|e| e.to_string())?;
                } else if let Ok(imm) = parse_u64_expr(args[1], symbols) {
                    a.test(dst, imm as u32).map_err(|e| e.to_string())?;
                } else {
                    return Err(format!("unknown source operand for test {}: {}", args[0], args[1]));
                }
            } else {
                return Err(format!("unsupported test operands: {}, {}", args[0], args[1]));
            }
        }
        "xor" | "xorps" => {
            if args.len() != 2 { return Err("xor/xorps requires 2 operands".into()); }
            if let Ok(dst) = parse_xmm(args[0]) {
                let src = parse_xmm(args[1])?;
                a.xorps(dst, src).map_err(|e| e.to_string())?;
            } else if let Ok(dst) = parse_gpr64(args[0]) {
                let src = parse_gpr64(args[1])?;
                a.xor(dst, src).map_err(|e| e.to_string())?;
            } else if let Ok(dst) = parse_gpr32(args[0]) {
                let src = parse_gpr32(args[1])?;
                a.xor(dst, src).map_err(|e| e.to_string())?;
            } else if let Ok(dst) = parse_gpr8(args[0]) {
                let src = parse_gpr8(args[1])?;
                a.xor(dst, src).map_err(|e| e.to_string())?;
            } else {
                return Err(format!("unsupported xor operands: {}, {}", args[0], args[1]));
            }
        }
        "add" => {
            if args.len() != 2 { return Err("add requires 2 operands".into()); }
            if let Ok(dst) = parse_gpr64(args[0]) {
                if let Ok(src) = parse_gpr64(args[1]) {
                    a.add(dst, src).map_err(|e| e.to_string())?;
                } else if let Ok(mem) = parse_mem(args[1], symbols, origin_rip, labels, a, referenced_labels) {
                    a.add(dst, mem).map_err(|e| e.to_string())?;
                } else if let Ok(imm) = parse_u64_expr(args[1], symbols) {
                    a.add(dst, imm as i32).map_err(|e| e.to_string())?;
                } else {
                    return Err(format!("unknown source operand for add {}: {}", args[0], args[1]));
                }
            } else if let Ok(dst) = parse_gpr32(args[0]) {
                if let Ok(src) = parse_gpr32(args[1]) {
                    a.add(dst, src).map_err(|e| e.to_string())?;
                } else if let Ok(mem) = parse_mem(args[1], symbols, origin_rip, labels, a, referenced_labels) {
                    a.add(dst, mem).map_err(|e| e.to_string())?;
                } else if let Ok(imm) = parse_u64_expr(args[1], symbols) {
                    a.add(dst, imm as i32).map_err(|e| e.to_string())?;
                } else {
                    return Err(format!("unknown source operand for add {}: {}", args[0], args[1]));
                }
            } else if let Ok(dst_mem) = parse_mem(args[0], symbols, origin_rip, labels, a, referenced_labels) {
                if let Ok(src) = parse_gpr64(args[1]) {
                    a.add(dst_mem, src).map_err(|e| e.to_string())?;
                } else if let Ok(src) = parse_gpr32(args[1]) {
                    a.add(dst_mem, src).map_err(|e| e.to_string())?;
                } else if let Ok(imm) = parse_u64_expr(args[1], symbols) {
                    a.add(dst_mem, imm as i32).map_err(|e| e.to_string())?;
                } else {
                    return Err(format!("unknown source operand for add {}: {}", args[0], args[1]));
                }
            } else {
                return Err(format!("unsupported add operands: {}, {}", args[0], args[1]));
            }
        }
        "sub" => {
            if args.len() != 2 { return Err("sub requires 2 operands".into()); }
            if let Ok(dst) = parse_gpr64(args[0]) {
                if let Ok(src) = parse_gpr64(args[1]) {
                    a.sub(dst, src).map_err(|e| e.to_string())?;
                } else if let Ok(mem) = parse_mem(args[1], symbols, origin_rip, labels, a, referenced_labels) {
                    a.sub(dst, mem).map_err(|e| e.to_string())?;
                } else if let Ok(imm) = parse_u64_expr(args[1], symbols) {
                    a.sub(dst, imm as i32).map_err(|e| e.to_string())?;
                } else {
                    return Err(format!("unknown source operand for sub {}: {}", args[0], args[1]));
                }
            } else if let Ok(dst) = parse_gpr32(args[0]) {
                if let Ok(src) = parse_gpr32(args[1]) {
                    a.sub(dst, src).map_err(|e| e.to_string())?;
                } else if let Ok(mem) = parse_mem(args[1], symbols, origin_rip, labels, a, referenced_labels) {
                    a.sub(dst, mem).map_err(|e| e.to_string())?;
                } else if let Ok(imm) = parse_u64_expr(args[1], symbols) {
                    a.sub(dst, imm as i32).map_err(|e| e.to_string())?;
                } else {
                    return Err(format!("unknown source operand for sub {}: {}", args[0], args[1]));
                }
            } else if let Ok(dst_mem) = parse_mem(args[0], symbols, origin_rip, labels, a, referenced_labels) {
                if let Ok(src) = parse_gpr64(args[1]) {
                    a.sub(dst_mem, src).map_err(|e| e.to_string())?;
                } else if let Ok(src) = parse_gpr32(args[1]) {
                    a.sub(dst_mem, src).map_err(|e| e.to_string())?;
                } else if let Ok(imm) = parse_u64_expr(args[1], symbols) {
                    a.sub(dst_mem, imm as i32).map_err(|e| e.to_string())?;
                } else {
                    return Err(format!("unknown source operand for sub {}: {}", args[0], args[1]));
                }
            } else {
                return Err(format!("unsupported sub operands: {}, {}", args[0], args[1]));
            }
        }
        "sar" | "shl" | "sal" | "shr" | "rol" | "ror" => {
            use iced_x86::code_asm::*;
            if args.len() != 2 { return Err(format!("{mnemonic} requires 2 operands (e.g. sar rax, 3)")); }
            let is_cl = args[1].trim().eq_ignore_ascii_case("cl");
            let imm = if is_cl { 0u32 } else { parse_u64_expr(args[1], symbols)? as u32 };

            if let Ok(dst) = parse_gpr64(args[0]) {
                match mnemonic.as_str() {
                    "sar" => { if is_cl { a.sar(dst, cl).map_err(|e| e.to_string())?; } else { a.sar(dst, imm).map_err(|e| e.to_string())?; } }
                    "shl" | "sal" => { if is_cl { a.shl(dst, cl).map_err(|e| e.to_string())?; } else { a.shl(dst, imm).map_err(|e| e.to_string())?; } }
                    "shr" => { if is_cl { a.shr(dst, cl).map_err(|e| e.to_string())?; } else { a.shr(dst, imm).map_err(|e| e.to_string())?; } }
                    "rol" => { if is_cl { a.rol(dst, cl).map_err(|e| e.to_string())?; } else { a.rol(dst, imm).map_err(|e| e.to_string())?; } }
                    "ror" => { if is_cl { a.ror(dst, cl).map_err(|e| e.to_string())?; } else { a.ror(dst, imm).map_err(|e| e.to_string())?; } }
                    _ => {}
                }
            } else if let Ok(dst) = parse_gpr32(args[0]) {
                match mnemonic.as_str() {
                    "sar" => { if is_cl { a.sar(dst, cl).map_err(|e| e.to_string())?; } else { a.sar(dst, imm).map_err(|e| e.to_string())?; } }
                    "shl" | "sal" => { if is_cl { a.shl(dst, cl).map_err(|e| e.to_string())?; } else { a.shl(dst, imm).map_err(|e| e.to_string())?; } }
                    "shr" => { if is_cl { a.shr(dst, cl).map_err(|e| e.to_string())?; } else { a.shr(dst, imm).map_err(|e| e.to_string())?; } }
                    "rol" => { if is_cl { a.rol(dst, cl).map_err(|e| e.to_string())?; } else { a.rol(dst, imm).map_err(|e| e.to_string())?; } }
                    "ror" => { if is_cl { a.ror(dst, cl).map_err(|e| e.to_string())?; } else { a.ror(dst, imm).map_err(|e| e.to_string())?; } }
                    _ => {}
                }
            } else {
                return Err(format!("unsupported destination register for {mnemonic}: '{}'", args[0]));
            }
        }
        "cld" => {
            a.cld().map_err(|e| e.to_string())?;
        }
        "rep" => {
            if args_str.eq_ignore_ascii_case("movsb") {
                a.rep().movsb().map_err(|e| e.to_string())?;
            } else {
                return Err(format!("unsupported rep suffix '{args_str}' in assemble_asm (expected 'rep movsb')"));
            }
        }
        "call" => {
            if args.len() != 1 { return Err("call requires 1 operand".into()); }
            let target = args[0];
            if let Some(sym) = target.strip_prefix('$')
                && let Some(target_addr) = symbols.get(sym) {
                    a.call(*target_addr).map_err(|e| e.to_string())?;
                    return Ok(());
                }
            if let Ok(reg) = parse_gpr64(target) {
                a.call(reg).map_err(|e| e.to_string())?;
                return Ok(());
            }
            if let Ok(imm) = parse_u64_expr(target, symbols) {
                a.call(imm).map_err(|e| e.to_string())?;
                return Ok(());
            }
            // Local label
            let name = target.trim().trim_start_matches('$').to_lowercase();
            referenced_labels.insert(name.clone());
            let lbl = *labels.entry(name.clone()).or_insert_with(|| a.create_label());
            a.call(lbl).map_err(|e| e.to_string())?;
        }
        "lea" => {
            if args.len() != 2 { return Err("lea requires 2 operands (e.g. lea r8, [rip + result_len])".into()); }
            if let Ok(dst) = parse_gpr64(args[0]) {
                let mem = parse_mem(args[1], symbols, origin_rip, labels, a, referenced_labels)?;
                a.lea(dst, mem).map_err(|e| e.to_string())?;
            } else if let Ok(dst) = parse_gpr32(args[0]) {
                let mem = parse_mem(args[1], symbols, origin_rip, labels, a, referenced_labels)?;
                a.lea(dst, mem).map_err(|e| e.to_string())?;
            } else {
                return Err(format!("unsupported destination register for lea: '{}'", args[0]));
            }
        }
        "movd" => {
            if args.len() != 2 { return Err("movd requires 2 operands (e.g. movd xmm0, eax)".into()); }
            if let Ok(dst) = parse_xmm(args[0]) {
                if let Ok(src) = parse_gpr32(args[1]) {
                    a.movd(dst, src).map_err(|e| e.to_string())?;
                } else if let Ok(src) = parse_gpr64(args[1]) {
                    a.movq(dst, src).map_err(|e| e.to_string())?;
                } else {
                    let mem = parse_mem(args[1], symbols, origin_rip, labels, a, referenced_labels)?;
                    a.movd(dst, mem).map_err(|e| e.to_string())?;
                }
            } else if let Ok(dst) = parse_gpr32(args[0]) {
                if let Ok(src) = parse_xmm(args[1]) {
                    a.movd(dst, src).map_err(|e| e.to_string())?;
                } else {
                    return Err(format!("unsupported movd operands: {}, {}", args[0], args[1]));
                }
            } else if let Ok(dst) = parse_gpr64(args[0]) {
                if let Ok(src) = parse_xmm(args[1]) {
                    a.movq(dst, src).map_err(|e| e.to_string())?;
                } else {
                    return Err(format!("unsupported movd/movq operands: {}, {}", args[0], args[1]));
                }
            } else if let Ok(dst_mem) = parse_mem(args[0], symbols, origin_rip, labels, a, referenced_labels) {
                let src = parse_xmm(args[1])?;
                a.movd(dst_mem, src).map_err(|e| e.to_string())?;
            } else {
                return Err(format!("unsupported movd operands: {}, {}", args[0], args[1]));
            }
        }
        "movq" => {
            if args.len() != 2 { return Err("movq requires 2 operands (e.g. movq xmm0, rax)".into()); }
            if let Ok(dst) = parse_xmm(args[0]) {
                if let Ok(src) = parse_xmm(args[1]) {
                    a.movq(dst, src).map_err(|e| e.to_string())?;
                } else if let Ok(src) = parse_gpr64(args[1]) {
                    a.movq(dst, src).map_err(|e| e.to_string())?;
                } else {
                    let mem = parse_mem(args[1], symbols, origin_rip, labels, a, referenced_labels)?;
                    a.movq(dst, mem).map_err(|e| e.to_string())?;
                }
            } else if let Ok(dst) = parse_gpr64(args[0]) {
                let src = parse_xmm(args[1])?;
                a.movq(dst, src).map_err(|e| e.to_string())?;
            } else if let Ok(dst_mem) = parse_mem(args[0], symbols, origin_rip, labels, a, referenced_labels) {
                let src = parse_xmm(args[1])?;
                a.movq(dst_mem, src).map_err(|e| e.to_string())?;
            } else {
                return Err(format!("unsupported movq operands: {}, {}", args[0], args[1]));
            }
        }
        "cvtsi2ss" => {
            if args.len() != 2 { return Err("cvtsi2ss requires 2 operands (e.g. cvtsi2ss xmm0, eax)".into()); }
            let dst = parse_xmm(args[0])?;
            if let Ok(src) = parse_gpr32(args[1]) {
                a.cvtsi2ss(dst, src).map_err(|e| e.to_string())?;
            } else if let Ok(src) = parse_gpr64(args[1]) {
                a.cvtsi2ss(dst, src).map_err(|e| e.to_string())?;
            } else {
                let mem = parse_mem(args[1], symbols, origin_rip, labels, a, referenced_labels)?;
                a.cvtsi2ss(dst, mem).map_err(|e| e.to_string())?;
            }
        }
        "cvtsi2sd" => {
            if args.len() != 2 { return Err("cvtsi2sd requires 2 operands (e.g. cvtsi2sd xmm0, rax)".into()); }
            let dst = parse_xmm(args[0])?;
            if let Ok(src) = parse_gpr32(args[1]) {
                a.cvtsi2sd(dst, src).map_err(|e| e.to_string())?;
            } else if let Ok(src) = parse_gpr64(args[1]) {
                a.cvtsi2sd(dst, src).map_err(|e| e.to_string())?;
            } else {
                let mem = parse_mem(args[1], symbols, origin_rip, labels, a, referenced_labels)?;
                a.cvtsi2sd(dst, mem).map_err(|e| e.to_string())?;
            }
        }
        "cvttss2si" | "cvtss2si" => {
            if args.len() != 2 { return Err(format!("{mnemonic} requires 2 operands (e.g. {mnemonic} eax, xmm0)")); }
            if let Ok(dst) = parse_gpr32(args[0]) {
                if let Ok(src) = parse_xmm(args[1]) {
                    if mnemonic == "cvttss2si" {
                        a.cvttss2si(dst, src).map_err(|e| e.to_string())?;
                    } else {
                        a.cvtss2si(dst, src).map_err(|e| e.to_string())?;
                    }
                } else {
                    let mem = parse_mem(args[1], symbols, origin_rip, labels, a, referenced_labels)?;
                    if mnemonic == "cvttss2si" {
                        a.cvttss2si(dst, mem).map_err(|e| e.to_string())?;
                    } else {
                        a.cvtss2si(dst, mem).map_err(|e| e.to_string())?;
                    }
                }
            } else if let Ok(dst) = parse_gpr64(args[0]) {
                if let Ok(src) = parse_xmm(args[1]) {
                    if mnemonic == "cvttss2si" {
                        a.cvttss2si(dst, src).map_err(|e| e.to_string())?;
                    } else {
                        a.cvtss2si(dst, src).map_err(|e| e.to_string())?;
                    }
                } else {
                    let mem = parse_mem(args[1], symbols, origin_rip, labels, a, referenced_labels)?;
                    if mnemonic == "cvttss2si" {
                        a.cvttss2si(dst, mem).map_err(|e| e.to_string())?;
                    } else {
                        a.cvtss2si(dst, mem).map_err(|e| e.to_string())?;
                    }
                }
            } else {
                return Err(format!("unsupported destination for {mnemonic}: {}", args[0]));
            }
        }
        "comiss" | "ucomiss" => {
            if args.len() != 2 { return Err(format!("{mnemonic} requires 2 operands (e.g. {mnemonic} xmm0, xmm1)")); }
            let dst = parse_xmm(args[0])?;
            if let Ok(src) = parse_xmm(args[1]) {
                if mnemonic == "comiss" {
                    a.comiss(dst, src).map_err(|e| e.to_string())?;
                } else {
                    a.ucomiss(dst, src).map_err(|e| e.to_string())?;
                }
            } else {
                let mem = parse_mem(args[1], symbols, origin_rip, labels, a, referenced_labels)?;
                if mnemonic == "comiss" {
                    a.comiss(dst, mem).map_err(|e| e.to_string())?;
                } else {
                    a.ucomiss(dst, mem).map_err(|e| e.to_string())?;
                }
            }
        }
        "maxss" | "minss" => {
            if args.len() != 2 { return Err(format!("{mnemonic} requires 2 operands (e.g. {mnemonic} xmm0, xmm1)")); }
            let dst = parse_xmm(args[0])?;
            if let Ok(src) = parse_xmm(args[1]) {
                if mnemonic == "maxss" {
                    a.maxss(dst, src).map_err(|e| e.to_string())?;
                } else {
                    a.minss(dst, src).map_err(|e| e.to_string())?;
                }
            } else {
                let mem = parse_mem(args[1], symbols, origin_rip, labels, a, referenced_labels)?;
                if mnemonic == "maxss" {
                    a.maxss(dst, mem).map_err(|e| e.to_string())?;
                } else {
                    a.minss(dst, mem).map_err(|e| e.to_string())?;
                }
            }
        }
        "pxor" => {
            if args.len() != 2 { return Err("pxor requires 2 operands (e.g. pxor xmm0, xmm0)".into()); }
            let dst = parse_xmm(args[0])?;
            if let Ok(src) = parse_xmm(args[1]) {
                a.pxor(dst, src).map_err(|e| e.to_string())?;
            } else {
                let mem = parse_mem(args[1], symbols, origin_rip, labels, a, referenced_labels)?;
                a.pxor(dst, mem).map_err(|e| e.to_string())?;
            }
        }
        "por" | "pand" | "pandn" => {
            if args.len() != 2 { return Err(format!("{mnemonic} requires 2 operands")); }
            let dst = parse_xmm(args[0])?;
            if let Ok(src) = parse_xmm(args[1]) {
                match mnemonic.as_str() {
                    "por" => a.por(dst, src).map_err(|e| e.to_string())?,
                    "pand" => a.pand(dst, src).map_err(|e| e.to_string())?,
                    "pandn" => a.pandn(dst, src).map_err(|e| e.to_string())?,
                    _ => {}
                }
            } else {
                let mem = parse_mem(args[1], symbols, origin_rip, labels, a, referenced_labels)?;
                match mnemonic.as_str() {
                    "por" => a.por(dst, mem).map_err(|e| e.to_string())?,
                    "pand" => a.pand(dst, mem).map_err(|e| e.to_string())?,
                    "pandn" => a.pandn(dst, mem).map_err(|e| e.to_string())?,
                    _ => {}
                }
            }
        }
        "inc" => {
            if args.len() != 1 { return Err("inc requires 1 operand".into()); }
            if let Ok(reg) = parse_gpr64(args[0]) {
                a.inc(reg).map_err(|e| e.to_string())?;
            } else if let Ok(reg) = parse_gpr32(args[0]) {
                a.inc(reg).map_err(|e| e.to_string())?;
            }
        }
        "dec" => {
            if args.len() != 1 { return Err("dec requires 1 operand".into()); }
            if let Ok(reg) = parse_gpr64(args[0]) {
                a.dec(reg).map_err(|e| e.to_string())?;
            } else if let Ok(reg) = parse_gpr32(args[0]) {
                a.dec(reg).map_err(|e| e.to_string())?;
            }
        }
        other => return Err(format!("unsupported mnemonic '{other}' in assemble_asm")),
    }

    Ok(())
}

fn parse_xmm(s: &str) -> Result<iced_x86::code_asm::AsmRegisterXmm, String> {
    use iced_x86::code_asm::*;
    match s.trim().to_lowercase().as_str() {
        "xmm0" => Ok(xmm0), "xmm1" => Ok(xmm1), "xmm2" => Ok(xmm2), "xmm3" => Ok(xmm3),
        "xmm4" => Ok(xmm4), "xmm5" => Ok(xmm5), "xmm6" => Ok(xmm6), "xmm7" => Ok(xmm7),
        "xmm8" => Ok(xmm8), "xmm9" => Ok(xmm9), "xmm10" => Ok(xmm10), "xmm11" => Ok(xmm11),
        "xmm12" => Ok(xmm12), "xmm13" => Ok(xmm13), "xmm14" => Ok(xmm14), "xmm15" => Ok(xmm15),
        other => Err(format!("not an xmm register: '{other}'")),
    }
}

fn parse_gpr64(s: &str) -> Result<iced_x86::code_asm::AsmRegister64, String> {
    use iced_x86::code_asm::*;
    match s.trim().to_lowercase().as_str() {
        "rax" => Ok(rax), "rcx" => Ok(rcx), "rdx" => Ok(rdx), "rbx" => Ok(rbx),
        "rsp" => Ok(rsp), "rbp" => Ok(rbp), "rsi" => Ok(rsi), "rdi" => Ok(rdi),
        "r8" => Ok(r8), "r9" => Ok(r9), "r10" => Ok(r10), "r11" => Ok(r11),
        "r12" => Ok(r12), "r13" => Ok(r13), "r14" => Ok(r14), "r15" => Ok(r15),
        other => Err(format!("not a 64-bit register: '{other}'")),
    }
}

fn parse_gpr32(s: &str) -> Result<iced_x86::code_asm::AsmRegister32, String> {
    use iced_x86::code_asm::*;
    match s.trim().to_lowercase().as_str() {
        "eax" => Ok(eax), "ecx" => Ok(ecx), "edx" => Ok(edx), "ebx" => Ok(ebx),
        "esp" => Ok(esp), "ebp" => Ok(ebp), "esi" => Ok(esi), "edi" => Ok(edi),
        "r8d" => Ok(r8d), "r9d" => Ok(r9d), "r10d" => Ok(r10d), "r11d" => Ok(r11d),
        "r12d" => Ok(r12d), "r13d" => Ok(r13d), "r14d" => Ok(r14d), "r15d" => Ok(r15d),
        other => Err(format!("not a 32-bit register: '{other}'")),
    }
}

fn parse_gpr8(s: &str) -> Result<iced_x86::code_asm::AsmRegister8, String> {
    use iced_x86::code_asm::*;
    match s.trim().to_lowercase().as_str() {
        "al" => Ok(al), "cl" => Ok(cl), "dl" => Ok(dl), "bl" => Ok(bl),
        "ah" => Ok(ah), "ch" => Ok(ch), "dh" => Ok(dh), "bh" => Ok(bh),
        "spl" => Ok(spl), "bpl" => Ok(bpl), "sil" => Ok(sil), "dil" => Ok(dil),
        "r8b" => Ok(r8b), "r9b" => Ok(r9b), "r10b" => Ok(r10b), "r11b" => Ok(r11b),
        "r12b" => Ok(r12b), "r13b" => Ok(r13b), "r14b" => Ok(r14b), "r15b" => Ok(r15b),
        other => Err(format!("not an 8-bit register: '{other}'")),
    }
}

fn parse_mem(
    s: &str,
    symbols: &HashMap<String, u64>,
    origin_rip: u64,
    labels: &mut HashMap<String, iced_x86::code_asm::CodeLabel>,
    a: &mut iced_x86::code_asm::CodeAssembler,
    referenced_labels: &mut std::collections::HashSet<String>,
) -> Result<iced_x86::code_asm::AsmMemoryOperand, String> {
    use iced_x86::code_asm::*;

    let s = s.trim();
    let s_lower = s.to_lowercase();
    let is_byte = s_lower.starts_with("byte ptr [") || s_lower.starts_with("byte [");
    let is_word = s_lower.starts_with("word ptr [") || s_lower.starts_with("word [");
    let is_qword = s_lower.starts_with("qword ptr [") || s_lower.starts_with("qword [");

    let inner = if let Some(stripped) = s.strip_prefix("dword ptr [").or_else(|| s.strip_prefix("DWORD PTR [")).or_else(|| s.strip_prefix("dword [")).or_else(|| s.strip_prefix("DWORD [")).or_else(|| s.strip_prefix("qword ptr [")).or_else(|| s.strip_prefix("QWORD PTR [")).or_else(|| s.strip_prefix("qword [")).or_else(|| s.strip_prefix("QWORD [")).or_else(|| s.strip_prefix("word ptr [")).or_else(|| s.strip_prefix("WORD PTR [")).or_else(|| s.strip_prefix("word [")).or_else(|| s.strip_prefix("WORD [")).or_else(|| s.strip_prefix("byte ptr [")).or_else(|| s.strip_prefix("BYTE PTR [")).or_else(|| s.strip_prefix("byte [")).or_else(|| s.strip_prefix("BYTE [")).or_else(|| s.strip_prefix('[')) {
        stripped.strip_suffix(']').ok_or_else(|| format!("unclosed bracket in '{s}'"))?
    } else {
        return Err(format!("expected memory operand with brackets '[...]', got '{s}'"));
    };

    let inner = inner.trim();

    let wrap_mem = |mem: iced_x86::code_asm::AsmMemoryOperand| -> iced_x86::code_asm::AsmMemoryOperand {
        if is_byte {
            byte_ptr(mem)
        } else if is_word {
            word_ptr(mem)
        } else if is_qword {
            qword_ptr(mem)
        } else {
            dword_ptr(mem)
        }
    };

    // Check for RIP-relative addressing: `[rip + ...]` or `[rip - ...]`
    if let Some(stripped) = inner.strip_prefix("rip +").or_else(|| inner.strip_prefix("RIP +")).or_else(|| inner.strip_prefix("rip+")).or_else(|| inner.strip_prefix("RIP+")) {
        let trimmed = stripped.trim();
        if let Ok(disp) = parse_u64_expr(trimmed, symbols) {
            let target_addr = origin_rip.wrapping_add(disp);
            return Ok(wrap_mem(dword_ptr(target_addr)));
        }
        let sym_name = trimmed.trim_start_matches('$').to_lowercase();
        referenced_labels.insert(sym_name.clone());
        let lbl = *labels.entry(sym_name).or_insert_with(|| a.create_label());
        return Ok(wrap_mem(dword_ptr(lbl)));
    }
    if let Some(stripped) = inner.strip_prefix("rip -").or_else(|| inner.strip_prefix("RIP -")).or_else(|| inner.strip_prefix("rip-")).or_else(|| inner.strip_prefix("RIP-")) {
        let trimmed = stripped.trim();
        if let Ok(disp) = parse_u64_expr(trimmed, symbols) {
            let target_addr = origin_rip.wrapping_sub(disp);
            return Ok(wrap_mem(dword_ptr(target_addr)));
        }
        let sym_name = trimmed.trim_start_matches('$').to_lowercase();
        referenced_labels.insert(sym_name.clone());
        let lbl = *labels.entry(sym_name).or_insert_with(|| a.create_label());
        return Ok(wrap_mem(dword_ptr(lbl)));
    }

    // Full SIB parser: tokenize by '+' and '-' while preserving signs
    // e.g. `rsi + rdx*4 + 0x8`, `rdx + rdx*4`, `rbx + rcx*8 - 0x10`, `rax + 0x10`, `[rax]`
    if let Ok(mem_op) = parse_sib_expression(inner, symbols) {
        return Ok(wrap_mem(mem_op));
    }

    // Check for symbol / marker expression e.g. `$cave_val` or `0x1400100`
    if let Ok(addr) = parse_u64_expr(inner, symbols) {
        return Ok(wrap_mem(dword_ptr(addr)));
    }

    Err(format!("unsupported memory operand syntax: '{s}'"))
}

/// Helper to parse complex SIB and displacement expressions within brackets:
/// `base + index*scale + disp` or variants
fn parse_sib_expression(inner: &str, symbols: &HashMap<String, u64>) -> Result<iced_x86::code_asm::AsmMemoryOperand, String> {
    use iced_x86::code_asm::*;

    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut sign = 1i32;

    for c in inner.chars() {
        if c == '+' || c == '-' {
            let trimmed = current.trim();
            if !trimmed.is_empty() {
                tokens.push((sign, trimmed.to_string()));
                current.clear();
            }
            sign = if c == '+' { 1 } else { -1 };
        } else {
            current.push(c);
        }
    }
    let trimmed = current.trim();
    if !trimmed.is_empty() {
        tokens.push((sign, trimmed.to_string()));
    }

    let mut base_reg: Option<AsmRegister64> = None;
    let mut index_scale: Option<(AsmRegister64, u32)> = None;
    let mut disp: i32 = 0;

    for (s_sign, tok) in tokens {
        if let Some((idx_str, scale_str)) = tok.split_once('*') {
            // Index * Scale, e.g. `rdx*4`
            let idx_reg = parse_gpr64(idx_str.trim())?;
            let scale: u32 = scale_str.trim().parse().map_err(|_| format!("invalid SIB scale '{scale_str}'"))?;
            if !matches!(scale, 1 | 2 | 4 | 8) {
                return Err(format!("SIB scale must be 1, 2, 4, or 8, got {scale}"));
            }
            if s_sign < 0 {
                return Err("negative SIB index register not supported in x86-64".into());
            }
            index_scale = Some((idx_reg, scale));
        } else if let Ok(reg) = parse_gpr64(&tok) {
            // Register without scale: if base already set, treat as index with scale 1
            if s_sign < 0 {
                return Err("negative base/index register not supported in x86-64".into());
            }
            if base_reg.is_none() {
                base_reg = Some(reg);
            } else if index_scale.is_none() {
                index_scale = Some((reg, 1));
            } else {
                return Err(format!("too many registers in memory expression '{inner}'"));
            }
        } else if let Ok(val) = parse_u64_expr(&tok, symbols) {
            let d = (val as i32) * s_sign;
            disp = disp.wrapping_add(d);
        } else {
            return Err(format!("unrecognized token '{tok}' in memory expression '{inner}'"));
        }
    }

    match (base_reg, index_scale) {
        (Some(b), Some((idx, scale))) => {
            let mem = match scale {
                1 => if disp == 0 { dword_ptr(b + idx * 1) } else { dword_ptr(b + idx * 1 + disp) },
                2 => if disp == 0 { dword_ptr(b + idx * 2) } else { dword_ptr(b + idx * 2 + disp) },
                4 => if disp == 0 { dword_ptr(b + idx * 4) } else { dword_ptr(b + idx * 4 + disp) },
                8 => if disp == 0 { dword_ptr(b + idx * 8) } else { dword_ptr(b + idx * 8 + disp) },
                _ => unreachable!(),
            };
            Ok(mem)
        }
        (None, Some((idx, scale))) => {
            let mem = match scale {
                1 => if disp == 0 { dword_ptr(idx * 1) } else { dword_ptr(idx * 1 + disp) },
                2 => if disp == 0 { dword_ptr(idx * 2) } else { dword_ptr(idx * 2 + disp) },
                4 => if disp == 0 { dword_ptr(idx * 4) } else { dword_ptr(idx * 4 + disp) },
                8 => if disp == 0 { dword_ptr(idx * 8) } else { dword_ptr(idx * 8 + disp) },
                _ => unreachable!(),
            };
            Ok(mem)
        }
        (Some(b), None) => {
            if disp == 0 {
                Ok(dword_ptr(b))
            } else {
                Ok(dword_ptr(b + disp))
            }
        }
        (None, None) => {
            Ok(dword_ptr(disp as u64))
        }
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assemble_basic_instructions_and_directives() {
        let mut symbols = HashMap::new();
        symbols.insert("mining_mult".to_string(), 0x140001000);
        symbols.insert("return_addr".to_string(), 0x140002000);

        let code = r#"
            dd (float)4.0
            mulss xmm1, [rax+0x10]
            divss xmm2, [rax+0x10]
            mov rax, 0x1234
            xorps xmm0, xmm0
            nop
            jmp $return_addr
        "#;

        let res = assemble_text(code, 0x140001000, &symbols);
        assert!(res.is_ok(), "assemble error: {:?}", res.err());
        let block = res.unwrap();
        assert!(!block.bytes.is_empty());
        // Verify float 4.0 bytes at the beginning: 00 00 80 40
        assert_eq!(&block.bytes[0..4], &[0x00, 0x00, 0x80, 0x40]);
    }

    #[test]
    fn test_assemble_rip_relative_memory_operand() {
        let mut symbols = HashMap::new();
        symbols.insert("return_addr".to_string(), 0x140001020);

        let code = r#"
            mining_speed_const:
            dd (float)4.0

            mulss xmm1, [rip + mining_speed_const]
            jmp $return_addr
        "#;

        let res = assemble_text(code, 0x140001000, &symbols);
        assert!(res.is_ok(), "assemble error: {:?}", res.err());
        let block = res.unwrap();
        assert!(!block.bytes.is_empty());
        // Verify decoded instructions contains RIP-relative memory references
        // The first 4 bytes are the float constant `dd (float)4.0` (00 00 80 40).
        // Disassemble the instructions starting after the constant at 0x140001004:
        let disasm = crate::disasm::disassemble(0x140001004, &block.bytes[4..], None);
        println!("Disasm lines:\n{}", disasm.join("\n"));
        assert!(disasm.iter().any(|line| line.contains("mulss") && (line.contains("[rel") || line.contains("[rip") || line.contains("[140001000"))));
    }
}


/// Porting Cheat Engine auto-assembler scripts VERBATIM.
///
/// CE constant-hook scripts reference a constant slot via `[label]` where the `label:` may be
/// defined BEFORE or AFTER the instruction that uses it. Our assembler must accept BOTH:
///   - const-first  ("BWD"):  label: dd X   then   instr [rip + label]
///   - instruction-first ("FWD"/CE-verbatim):  instr [rip + label]  then  label: dd X
///
/// The constant lands at a different offset in each layout (bytes differ), but EACH must
/// resolve `[rip + label]` to its constant slot with a correct relative displacement and must
/// NOT emit an address-size (0x67) prefix (which indicates an unresolved label in iced-x86).
#[cfg(test)]
mod ce_verbatim_porting {
    use super::*;

    /// Byte-level checks that hold regardless of data/instruction order:
    ///  - the constant bytes are present,
    ///  - there is no 0x67 address-size prefix (unresolved label),
    ///  - and, for the instruction-first case only, the disassembly shows a clean [rel] operand
    ///    (when the instruction leads, disassembly is aligned so this is meaningful).
    fn check(label: &str, hex: &str, const_bytes: &str, expect_clean_disasm: bool) {
        assert!(hex.contains(const_bytes), "[{label}] missing constant {const_bytes}: {hex}");
        assert!(!hex.starts_with("67"), "[{label}] 0x67 address-size prefix (label not resolved): {hex}");
        if expect_clean_disasm {
            let bytes: Vec<u8> = hex.split_whitespace().map(|b| u8::from_str_radix(b, 16).unwrap()).collect();
            let dis = crate::disasm::disassemble(0x140000000, &bytes, None);
            assert!(dis.iter().any(|l| l.contains("[rel")), "[{label}] no [rel] operand:\n{}", dis.join("\n"));
        }
    }

    fn both_orders(name: &str, label: &str, instr: &str, dd_line: &str, const_bytes: &str) {
        // CE-verbatim: instruction references the constant label BEFORE its `dd` definition.
        let fwd = assemble_text(
            &format!("{instr}\n{label}:\n  {dd_line}"),
            0x140000000, &HashMap::new(),
        ).unwrap_or_else(|e| panic!("[{name}_fwd] failed: {e}"));
        // const-first (our recommended layout).
        let bwd = assemble_text(
            &format!("{label}:\n  {dd_line}\n{instr}"),
            0x140000000, &HashMap::new(),
        ).unwrap_or_else(|e| panic!("[{name}_bwd] failed: {e}"));
        check(&format!("{name}_fwd"), &fwd.hex, const_bytes, true);   // instruction first -> clean disasm
        check(&format!("{name}_bwd"), &bwd.hex, const_bytes, false);  // data first -> skip disasm align check
    }

    #[test]
    fn mining_speed_ce_verbatim() {
        both_orders("mining_speed", "miningSpeedValue",
            "divss xmm2, [rip + miningSpeedValue]\naddss xmm2, xmm0",
            "dd (float)4.0", "00 00 80 40");
    }
    #[test]
    fn xp_mult_ce_verbatim() {
        both_orders("xp_mult", "xpMultValue",
            "mulss xmm1, [rip + xpMultValue]", "dd (float)3.0", "00 00 40 40");
    }
    #[test]
    fn one_hit_ce_verbatim() {
        both_orders("one_hit", "oneHitValue",
            "mov edx, [rip + oneHitValue]", "dd 99999", "9f 86 01 00");
    }
    #[test]
    fn attack_speed_ce_verbatim() {
        both_orders("attack_speed", "attackSpeedValue",
            "mulss xmm1, [rip + attackSpeedValue]", "dd (float)20.0", "00 00 a0 41");
    }
    #[test]
    fn instant_reload_ce_verbatim() {
        both_orders("instant_reload", "reloadTimeValue",
            "mov eax, [rip + reloadTimeValue]", "dd (float)0.1", "cd cc cc 3d");
    }
    #[test]
    fn no_spread_ce_verbatim() {
        both_orders("no_spread", "spreadValue",
            "movss xmm0, [rip + spreadValue]\nmovss xmm1, [rip + spreadValue]",
            "dd (float)1.0", "00 00 80 3f");
    }
    #[test]
    fn freeze_droppod_single_instruction() {
        let r = assemble_text("inc eax", 0x140000000, &HashMap::new()).unwrap();
        assert_eq!(r.hex, "ff c0", "inc eax must be FF C0, got {}", r.hex);
    }

    #[test]
    fn unresolved_label_fails_with_hard_error() {
        // [rip + typoLabel] where typoLabel is never defined anywhere
        let code = r#"
            miningSpeedValue:
            dd (float)4.0
            divss xmm2, [rip + miningSpeedValTypo]
        "#;
        let r = assemble_text(code, 0x140000000, &HashMap::new());
        assert!(r.is_err(), "expected unresolved label error, but succeeded with hex: {:?}", r.unwrap().hex);
        let err_msg = r.unwrap_err();
        assert!(err_msg.contains("unresolved label or marker 'miningspeedvaltypo'"), "unexpected error msg: {err_msg}");
    }

    #[test]
    fn test_cmp_je_and_memory_immediates() {
        let code = r#"
            cmp byte ptr [rip + flag], 0
            je skip
            push rax
            mov rax, [rdi+0x280]
            mov dword ptr [rax+0x14], 0x40800000
            mov byte ptr [rip + flag], 0
            pop rax
            skip:
            jmp replay
            flag:
              db 0
            replay:
        "#;
        let r = assemble_text(code, 0x140000000, &HashMap::new());
        assert!(r.is_ok(), "failed to assemble cmp/je payload: {:?}", r.err());
        let block = r.unwrap();
        assert!(!block.bytes.is_empty());
    }

    #[test]
    fn test_mov_dword_immediate_mem() {
        let code = r#"
            push rax
            mov rax, [rdi+0x280]
            mov dword [rax+0x14], 0x40800000
            pop rax
        "#;
        let r = assemble_text(code, 0x140000000, &HashMap::new());
        assert!(r.is_ok(), "failed to assemble mov dword payload: {:?}", r.err());
        let block = r.unwrap();
        assert!(!block.bytes.is_empty());
    }

    #[test]
    fn test_eval_cave_asm_with_call_lea_cld_rep_movsb() {
        let code = r#"
            mov rcx, [rip + saved_state]
            mov rdx, [rip + cmd_ptr]
            mov r10, 0x1401ae260
            call r10
            mov [rip + result_slot], eax
            test eax, eax
            jnz balance
            mov rcx, [rip + saved_state]
            xor r9d, r9d
            mov r8d, -1
            xor edx, edx
            mov r10, 0x1401a7ec0
            call r10
            mov [rip + result_slot], eax
            test eax, eax
            jnz balance
            mov rcx, [rip + saved_state]
            mov edx, -1
            lea r8, [rip + result_len]
            mov r10, [rip + tolstring_addr]
            test r10, r10
            jz balance
            call r10
            test rax, rax
            jz balance
            cld
            mov rsi, rax
            lea rdi, [rip + result_buf]
            mov rcx, [rip + result_len]
            cmp rcx, 4095
            jbe copy_ok
            mov rcx, 4095
            copy_ok:
            rep movsb
            mov byte ptr [rdi], 0
            balance:
            mov rdx, [rip + saved_top]
            mov rcx, [rip + saved_state]
            mov r10, 0x1401a6260
            call r10
            ret

            saved_state:
            dq 0
            cmd_ptr:
            dq 0
            result_slot:
            dd 0
            result_len:
            dq 0
            tolstring_addr:
            dq 0
            result_buf:
            dq 0
            saved_top:
            dq 0
        "#;
        let r = assemble_text(code, 0x140000000, &HashMap::new());
        assert!(r.is_ok(), "failed to assemble eval cave: {:?}", r.err());
        let block = r.unwrap();
        assert!(!block.bytes.is_empty());
        assert_eq!(block.instruction_count, 46);

        // Verify exact data slot offsets
        let off_saved_state = *block.label_offsets.get("saved_state").expect("saved_state");
        let off_cmd_ptr = *block.label_offsets.get("cmd_ptr").expect("cmd_ptr");
        let off_result_slot = *block.label_offsets.get("result_slot").expect("result_slot");
        let off_result_len = *block.label_offsets.get("result_len").expect("result_len");
        let off_tolstring_addr = *block.label_offsets.get("tolstring_addr").expect("tolstring_addr");

        assert_eq!(off_cmd_ptr - off_saved_state, 8, "dq saved_state must be 8 bytes");
        assert_eq!(off_result_slot - off_cmd_ptr, 8, "dq cmd_ptr must be 8 bytes");
        assert_eq!(off_result_len - off_result_slot, 4, "dd result_slot must be 4 bytes");
        assert_eq!(off_tolstring_addr - off_result_len, 8, "dq result_len must be 8 bytes");
    }

    #[test]
    fn test_label_ip_with_db() {
        use iced_x86::code_asm::*;
        let mut a = CodeAssembler::new(64).unwrap();
        let mut lbl_data = a.create_label();
        a.nop().unwrap(); // 1 byte (0x0)
        a.set_label(&mut lbl_data).unwrap();
        a.db(&[0xaa, 0xbb, 0xcc, 0xdd]).unwrap(); // 4 bytes (0x1..0x5)
        let mut lbl_after = a.create_label();
        a.set_label(&mut lbl_after).unwrap();
        a.nop().unwrap(); // 1 byte (0x5)
        let res = a.assemble_options(0x1000, iced_x86::BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS).unwrap();
        assert_eq!(res.label_ip(&lbl_data).unwrap(), 0x1001);
        assert_eq!(res.label_ip(&lbl_after).unwrap(), 0x1005);
        assert_eq!(res.inner.code_buffer.len(), 6);
    }

    #[test]
    fn test_helldivers_exact_offsets() {
        let code = r#"
      ; ---- stolen body (zlua_gettop) ----
      sub rax, [rcx + 0x10]
      sar rax, 3

      ; ---- fire-once flag gate ----
      cmp byte ptr [rip + fire_flag], 1
      jne done
      mov byte ptr [rip + fire_flag], 0
      mov [rip + saved_state], rcx
      mov [rip + saved_top], rax

      ; ---- self-clear anti-cheat gate ----
      mov r11, [rcx + 0x8]          ; l_G = [L+8]
      mov byte ptr [r11 + 0x198], 0 ; gate flag A
      mov byte ptr [r11 + 0x199], 0 ; gate flag B

      ; ---- execute program at cmd_ptr ----
      push rbx
      push rdx
      push r9
      push r8
      push rsi
      push rdi
      sub rsp, 0x28

      mov rcx, [rip + saved_state]
      mov rdx, [rip + cmd_ptr]
      mov r10, 0x1401ae260          ; zluaL_loadstring
      call r10
      mov [rip + result_slot], eax
      test eax, eax
      jnz balance

      mov rcx, [rip + saved_state]
      xor r9d, r9d
      mov r8d, -1                   ; nresults = -1 (all results)
      xor edx, edx
      mov r10, 0x1401a7ec0          ; zlua_pcall
      call r10
      mov [rip + result_slot], eax
      test eax, eax
      jnz balance

      ; ---- capture return value (top of stack) ----
      mov rcx, [rip + saved_state]
      mov edx, -1                   ; index -1 = stack top
      lea r8, [rip + result_len]    ; &len
      mov r10, [rip + tolstring_addr]
      test r10, r10
      jz balance                    ; tolstring not configured -> skip
      call r10                      ; lua_tolstring(L, -1, &len)
      test rax, rax
      jz balance                    ; NULL -> not a string, skip

      ; copy up to 16383 bytes from rax into [result_buf]
      cld
      mov rsi, rax
      mov rdi, [rip + result_buf]   ; result_buf is a POINTER to the buffer
      mov rcx, [rip + result_len]
      cmp rcx, 16383
      jbe copy_ok
      mov rcx, 16383
      copy_ok:
      rep movsb
      mov byte ptr [rdi], 0         ; null-terminate

      balance:
      mov rdx, [rip + saved_top]
      mov rcx, [rip + saved_state]
      mov r10, 0x1401a6260          ; zlua_settop
      call r10
      mov rax, [rip + saved_top]

      add rsp, 0x28
      pop rdi
      pop rsi
      pop r8
      pop r9
      pop rdx
      pop rbx

      done:
      ret

      ; ---- data slots ----
      fire_flag:
      db 00
      saved_state:
      dq 0
      saved_top:
      dq 0
      result_slot:
      dq 0
      cmd_ptr:
      dq 0
      tolstring_addr:
      dq 0
      result_len:
      dq 0
      result_buf:
      dq 0
        "#;
        let r = assemble_text(code, 0x1401a6254, &HashMap::new()).unwrap();
        println!("test_helldivers_exact_offsets byte len: {}", r.bytes.len());
        for (k, v) in &r.label_offsets {
            println!("  label {k} -> +{v:#x} ({v})");
        }
        use iced_x86::{Decoder, DecoderOptions, Formatter, NasmFormatter};
        let mut decoder = Decoder::with_ip(64, &r.bytes, 0x13fff0000, DecoderOptions::NONE);
        let mut formatter = NasmFormatter::new();
        let mut output = String::new();
        let mut instr = iced_x86::Instruction::default();
        while decoder.can_decode() {
            decoder.decode_out(&mut instr);
            output.clear();
            formatter.format(&instr, &mut output);
            println!("{:#x}: {}", instr.ip(), output);
        }
    }

    #[test]
    fn test_asm_data_directive_offsets_repro() {
        let code = r#"
            fire_flag:
            db 00
            saved_state:
            dq 0
            saved_top:
            dq 0
            result_slot:
            dq 0
            cmd_ptr:
            dq 0
            tolstring_addr:
            dq 0
            result_len:
            dq 0
            result_buf:
            db 00
        "#;
        let r = assemble_text(code, 0x140000000, &HashMap::new());
        assert!(r.is_ok());
        let block = r.unwrap();
        let off_fire_flag = *block.label_offsets.get("fire_flag").unwrap();
        let off_saved_state = *block.label_offsets.get("saved_state").unwrap();
        let off_saved_top = *block.label_offsets.get("saved_top").unwrap();
        let off_result_slot = *block.label_offsets.get("result_slot").unwrap();
        let off_cmd_ptr = *block.label_offsets.get("cmd_ptr").unwrap();
        let off_tolstring_addr = *block.label_offsets.get("tolstring_addr").unwrap();
        let off_result_len = *block.label_offsets.get("result_len").unwrap();
        let off_result_buf = *block.label_offsets.get("result_buf").unwrap();

        assert_eq!(off_fire_flag, 0);
        assert_eq!(off_saved_state, 1);
        assert_eq!(off_saved_top, 1 + 8);
        assert_eq!(off_result_slot, 1 + 8 + 8);
        assert_eq!(off_cmd_ptr, 1 + 8 + 8 + 8);
        assert_eq!(off_tolstring_addr, 1 + 8 + 8 + 8 + 8);
        assert_eq!(off_result_len, 1 + 8 + 8 + 8 + 8 + 8);
        assert_eq!(off_result_buf, 1 + 8 + 8 + 8 + 8 + 8 + 8);
    }

    #[test]
    fn test_sub_mem_and_shifts() {
        let code = r#"
            sub rax, [rcx + 0x10]
            sar rax, 3
            shl rdx, 2
            shr r8, 4
            add rax, [rbx + 0x8]
            sar eax, cl
        "#;
        let r = assemble_text(code, 0x140000000, &HashMap::new());
        assert!(r.is_ok(), "failed to assemble sub mem & shifts: {:?}", r.err());
        let block = r.unwrap();
        assert_eq!(block.instruction_count, 6);
        // Verify `sub rax, [rcx+0x10]` produces 48 2b 41 10
        assert_eq!(&block.bytes[0..4], &[0x48, 0x2b, 0x41, 0x10]);
        // Verify `sar rax, 3` produces 48 c1 f8 03
        assert_eq!(&block.bytes[4..8], &[0x48, 0xc1, 0xf8, 0x03]);
    }

    #[test]
    fn test_sib_addressing_and_sse_forms() {
        // Reproduce Sins of a Solar Empire II request exactly:
        let code = r#"
            cmp edx, 2
            ja back
            cmp edx, 0
            jne not_credit
            mov eax, 20000
            jmp store
            not_credit:
            mov eax, 10000
            store:
            movd xmm0, eax
            cvtsi2ss xmm1, eax
            pxor xmm2, xmm2
            comiss xmm0, xmm1
            maxss xmm0, xmm1
            mov dword [rsi + rdx*4 + 0x8], eax
            mov dword [rsi + rdx*4], 200000
            lea rax, [rdx + rdx*4]
            back:
        "#;
        let r = assemble_text(code, 0x140abec51, &HashMap::new());
        assert!(r.is_ok(), "failed to assemble sins2 cave: {:?}", r.err());
        let block = r.unwrap();
        assert!(!block.bytes.is_empty());
        // 13 parsed lines + 1 fallback NOP for trailing label `back:` = 14 or 15 instructions
        assert_eq!(block.instruction_count, 15);
    }

    #[test]
    fn test_check_trampoline_data_fallthrough_hazard_and_bypass() {
        // 1. Sins2 Live Repro: instructions falling through into trailing data slot (CRASH HAZARD)
        let hazard_code = r#"
            push rdi
            mov [rip + player_base_slot], rdi
            pop rdi
            player_base_slot:
            dq 0
        "#;
        let err = check_trampoline_data_fallthrough(hazard_code);
        assert!(err.is_err(), "Must reject unjumped data slots in trampoline caves");
        assert!(err.unwrap_err().contains("trampoline cave payload"));

        // 2. Correct Pattern: Unconditional JMP over data slots to tail label
        let safe_code = r#"
            push rdi
            mov [rip + player_base_slot], rdi
            pop rdi
            jmp code
            player_base_slot:
            dq 0
            code:
        "#;
        assert!(check_trampoline_data_fallthrough(safe_code).is_ok(), "Jumping over data slots must pass");

        // Assemble safe_code and verify label offset for `code` lands after `player_base_slot`
        let block = assemble_text(safe_code, 0x140000000, &HashMap::new()).unwrap();
        let slot_off = *block.label_offsets.get("player_base_slot").unwrap();
        let code_off = *block.label_offsets.get("code").unwrap();
        assert_eq!(code_off, slot_off + 8, "Tail label 'code' must land 8 bytes after player_base_slot");

        // 3. Eval cave with RET (leaf override) past data slots
        let leaf_code = r#"
            mov eax, 1
            ret
            my_data:
            dd 100
        "#;
        assert!(check_trampoline_data_fallthrough(leaf_code).is_ok(), "Leaf cave ending with ret before data must pass");
    }

    #[test]
    fn test_unresolved_marker_fails_assembly() {
        let code = r#"
            push rax
            cmp rax, $player_base
            jne exit
            mov [rax+0x10], 100
            exit:
            pop rax
        "#;
        let empty_symbols = HashMap::new();
        let res = assemble_text(code, 0x140000000, &empty_symbols);
        assert!(res.is_err(), "Assembly must fail if a marker ($player_base) cannot be resolved");
        let err_msg = res.unwrap_err();
        assert!(err_msg.contains("unknown symbol '$player_base'") || err_msg.contains("player_base"), "Error message should mention the unresolved marker, got: {err_msg}");

        // Now with resolved symbol, assembly must succeed
        let mut symbols = HashMap::new();
        symbols.insert("player_base".to_string(), 0x140123456);
        let ok_res = assemble_text(code, 0x140000000, &symbols);
        assert!(ok_res.is_ok(), "Assembly must succeed when marker is provided in symbols: {:?}", ok_res.err());
    }

    #[test]
    fn test_movabs_and_rip_displacement_diagnostics() {
        let mut symbols = HashMap::new();
        symbols.insert("player_base_slot".to_string(), 0x13fff0000);

        // 1. movabs mnemonic support
        let movabs_code = r#"
            movabs rax, 0x141380000
            movabs rdx, $player_base_slot
        "#;
        let res = assemble_text(movabs_code, 0x140000000, &symbols);
        assert!(res.is_ok(), "movabs mnemonic must assemble cleanly: {:?}", res.err());

        // 2. Clear error on rip-relative displacement overflow (> 2GB apart)
        let overflow_code = r#"
            cmp rax, [rip + 0x90000000]
        "#;
        let err_res = assemble_text(overflow_code, 0x140000000, &symbols);
        assert!(err_res.is_err());
        let err = err_res.unwrap_err();
        assert!(err.contains("exceeds ±2GB limit"), "Expected diagnostic displacement overflow message, got: {err}");
    }
}


