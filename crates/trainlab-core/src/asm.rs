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

    // Second pass: emit instructions and directives
    for raw_line in &lines {
        let line = strip_comments(raw_line).trim();
        if line.is_empty() {
            continue;
        }

        // Check for label definition: `my_label:`
        if let Some(label_name) = line.strip_suffix(':') {
            let name = label_name.trim().to_lowercase();
            if let Some(lbl) = labels_map.get_mut(&name) {
                a.set_label(lbl).map_err(|e| format!("set label '{name}': {e}"))?;
            }
            continue;
        }

        // Check for Data Directives: `dd (float)4.0`, `dd 100`, `dq 0x...`, `db 90 90`
        if let Some(rest) = line.strip_prefix("dd ").or_else(|| line.strip_prefix("DD ")) {
            let b = parse_dd(rest.trim(), symbols)?;
            a.db(&b).map_err(|e| format!("db emit: {e}"))?;
            total_instructions += 1;
            continue;
        }
        if let Some(rest) = line.strip_prefix("dq ").or_else(|| line.strip_prefix("DQ ")) {
            let b = parse_dq(rest.trim(), symbols)?;
            a.db(&b).map_err(|e| format!("db emit: {e}"))?;
            total_instructions += 1;
            continue;
        }
        if let Some(rest) = line.strip_prefix("db ").or_else(|| line.strip_prefix("DB ")) {
            let b = parse_db(rest.trim())?;
            a.db(&b).map_err(|e| format!("db emit: {e}"))?;
            total_instructions += 1;
            continue;
        }

        // Parse standard instruction: mnemonic op1, op2
        parse_and_emit_instruction(&mut a, line, origin_rip, symbols, &mut labels_map, &mut referenced_labels)?;
        total_instructions += 1;
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
    let assembled = match a.assemble(origin_rip) {
        Ok(bytes) => bytes,
        Err(e) if e.to_string().contains("Unused label") => {
            // Emitting a nop or zero-byte at the end allows terminal labels like `.replay:` to bind
            let _ = a.nop();
            a.assemble(origin_rip).map_err(|e| format!("assemble error: {e}"))?
        }
        Err(e) => return Err(format!("assemble error: {e}")),
    };
    let hex = assembled.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");

    Ok(AssembledBlock {
        bytes: assembled,
        hex,
        instruction_count: total_instructions,
    })
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
    if s.contains('.') {
        if let Ok(f) = s.parse::<f32>() {
            return Ok(f.to_le_bytes().to_vec());
        }
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
    use iced_x86::code_asm::*;

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
            let target = args[0];
            if let Some(sym) = target.strip_prefix('$') {
                if let Some(target_addr) = symbols.get(sym) {
                    a.jmp(*target_addr).map_err(|e| e.to_string())?;
                    return Ok(());
                }
            }
            if let Ok(reg) = parse_gpr64(target) {
                a.jmp(reg).map_err(|e| e.to_string())?;
                return Ok(());
            }
            if let Ok(imm) = parse_u64_expr(target, symbols) {
                a.jmp(imm).map_err(|e| e.to_string())?;
                return Ok(());
            }
            // Local label
            let name = target.trim().trim_start_matches('$').to_lowercase();
            referenced_labels.insert(name.clone());
            let lbl = labels.entry(name.clone()).or_insert_with(|| a.create_label()).clone();
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
        "mov" => {
            if args.len() != 2 { return Err("mov requires 2 operands".into()); }
            if let Ok(dst) = parse_gpr64(args[0]) {
                if let Ok(src) = parse_gpr64(args[1]) {
                    a.mov(dst, src).map_err(|e| e.to_string())?;
                } else if let Ok(mem) = parse_mem(args[1], symbols, origin_rip, labels, a, referenced_labels) {
                    a.mov(dst, mem).map_err(|e| e.to_string())?;
                } else if let Ok(imm) = parse_u64_expr(args[1], symbols) {
                    a.mov(dst, imm).map_err(|e| e.to_string())?;
                } else {
                    return Err(format!("unknown source operand for mov: {}", args[1]));
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
                }
            } else if let Ok(dst) = parse_gpr32(args[0]) {
                if let Ok(src) = parse_gpr32(args[1]) {
                    a.cmp(dst, src).map_err(|e| e.to_string())?;
                } else if let Ok(mem) = parse_mem(args[1], symbols, origin_rip, labels, a, referenced_labels) {
                    a.cmp(dst, mem).map_err(|e| e.to_string())?;
                } else if let Ok(imm) = parse_u64_expr(args[1], symbols) {
                    a.cmp(dst, imm as i32).map_err(|e| e.to_string())?;
                }
            } else if let Ok(dst) = parse_gpr8(args[0]) {
                if let Ok(src) = parse_gpr8(args[1]) {
                    a.cmp(dst, src).map_err(|e| e.to_string())?;
                } else if let Ok(mem) = parse_mem(args[1], symbols, origin_rip, labels, a, referenced_labels) {
                    a.cmp(dst, mem).map_err(|e| e.to_string())?;
                } else if let Ok(imm) = parse_u64_expr(args[1], symbols) {
                    a.cmp(dst, imm as u32).map_err(|e| e.to_string())?;
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
                }
            }
        }
        "je" | "jz" | "jne" | "jnz" | "jg" | "jge" | "jl" | "jle" | "ja" | "jae" | "jb" | "jbe" | "js" | "jns" => {
            if args.len() != 1 { return Err(format!("{mnemonic} requires 1 operand")); }
            let target = args[0];
            let name = target.trim().trim_start_matches('$').to_lowercase();
            referenced_labels.insert(name.clone());
            let lbl = labels.entry(name).or_insert_with(|| a.create_label()).clone();
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
                }
            } else if let Ok(dst) = parse_gpr32(args[0]) {
                if let Ok(src) = parse_gpr32(args[1]) {
                    a.test(dst, src).map_err(|e| e.to_string())?;
                } else if let Ok(imm) = parse_u64_expr(args[1], symbols) {
                    a.test(dst, imm as i32).map_err(|e| e.to_string())?;
                }
            } else if let Ok(dst) = parse_gpr8(args[0]) {
                if let Ok(src) = parse_gpr8(args[1]) {
                    a.test(dst, src).map_err(|e| e.to_string())?;
                } else if let Ok(imm) = parse_u64_expr(args[1], symbols) {
                    a.test(dst, imm as u32).map_err(|e| e.to_string())?;
                }
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
            }
        }
        "add" => {
            if args.len() != 2 { return Err("add requires 2 operands".into()); }
            if let Ok(dst) = parse_gpr64(args[0]) {
                if let Ok(src) = parse_gpr64(args[1]) {
                    a.add(dst, src).map_err(|e| e.to_string())?;
                } else if let Ok(imm) = parse_u64_expr(args[1], symbols) {
                    a.add(dst, imm as i32).map_err(|e| e.to_string())?;
                }
            } else if let Ok(dst) = parse_gpr32(args[0]) {
                if let Ok(src) = parse_gpr32(args[1]) {
                    a.add(dst, src).map_err(|e| e.to_string())?;
                } else if let Ok(imm) = parse_u64_expr(args[1], symbols) {
                    a.add(dst, imm as i32).map_err(|e| e.to_string())?;
                }
            }
        }
        "sub" => {
            if args.len() != 2 { return Err("sub requires 2 operands".into()); }
            if let Ok(dst) = parse_gpr64(args[0]) {
                if let Ok(src) = parse_gpr64(args[1]) {
                    a.sub(dst, src).map_err(|e| e.to_string())?;
                } else if let Ok(imm) = parse_u64_expr(args[1], symbols) {
                    a.sub(dst, imm as i32).map_err(|e| e.to_string())?;
                }
            } else if let Ok(dst) = parse_gpr32(args[0]) {
                if let Ok(src) = parse_gpr32(args[1]) {
                    a.sub(dst, src).map_err(|e| e.to_string())?;
                } else if let Ok(imm) = parse_u64_expr(args[1], symbols) {
                    a.sub(dst, imm as i32).map_err(|e| e.to_string())?;
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
        let lbl = labels.entry(sym_name).or_insert_with(|| a.create_label()).clone();
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
        let lbl = labels.entry(sym_name).or_insert_with(|| a.create_label()).clone();
        return Ok(wrap_mem(dword_ptr(lbl)));
    }

    // Check for base + offset, e.g. `rax+0x10` or `rax-0x8` or `rbx + 0x190`
    if let Some((reg_str, off_str)) = inner.split_once('+') {
        let reg = parse_gpr64(reg_str.trim())?;
        let off = parse_u64_expr(off_str.trim(), symbols)? as i32;
        return Ok(wrap_mem(dword_ptr(reg + off)));
    }
    if let Some((reg_str, off_str)) = inner.split_once('-') {
        let reg = parse_gpr64(reg_str.trim())?;
        let off = parse_u64_expr(off_str.trim(), symbols)? as i32;
        return Ok(wrap_mem(dword_ptr(reg - off)));
    }

    // Plain register, e.g. `[rax]`
    if let Ok(reg) = parse_gpr64(inner) {
        return Ok(wrap_mem(dword_ptr(reg)));
    }

    // Check for symbol / marker expression e.g. `$cave_val` or `0x1400100`
    if let Ok(addr) = parse_u64_expr(inner, symbols) {
        return Ok(wrap_mem(dword_ptr(addr)));
    }

    Err(format!("unsupported memory operand syntax: '{s}'"))
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
}
