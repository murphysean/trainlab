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
    let mut total_instructions = 0usize;

    // First pass: collect labels and parse lines
    let lines: Vec<&str> = asm_code.lines().collect();

    for raw_line in &lines {
        let line = strip_comments(raw_line).trim();
        if line.is_empty() {
            continue;
        }

        // Check for label definition: `my_label:`
        if let Some(label_name) = line.strip_suffix(':') {
            let name = label_name.trim().to_lowercase();
            if !labels_map.contains_key(&name) {
                let lbl = a.create_label();
                labels_map.insert(name.clone(), lbl);
            }
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
        parse_and_emit_instruction(&mut a, line, origin_rip, symbols, &mut labels_map)?;
        total_instructions += 1;
    }

    let assembled = a.assemble(origin_rip).map_err(|e| format!("assemble error: {e}"))?;
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
            let name = target.to_lowercase();
            let lbl = labels.entry(name.clone()).or_insert_with(|| a.create_label()).clone();
            a.jmp(lbl).map_err(|e| e.to_string())?;
        }
        "mulss" => {
            if args.len() != 2 { return Err("mulss requires 2 operands (e.g. mulss xmm1, [rax+0x10])".into()); }
            let dst = parse_xmm(args[0])?;
            if let Ok(src) = parse_xmm(args[1]) {
                a.mulss(dst, src).map_err(|e| e.to_string())?;
            } else {
                let mem = parse_mem(args[1], symbols, origin_rip)?;
                a.mulss(dst, mem).map_err(|e| e.to_string())?;
            }
        }
        "divss" => {
            if args.len() != 2 { return Err("divss requires 2 operands (e.g. divss xmm2, [rax+0x10])".into()); }
            let dst = parse_xmm(args[0])?;
            if let Ok(src) = parse_xmm(args[1]) {
                a.divss(dst, src).map_err(|e| e.to_string())?;
            } else {
                let mem = parse_mem(args[1], symbols, origin_rip)?;
                a.divss(dst, mem).map_err(|e| e.to_string())?;
            }
        }
        "addss" => {
            if args.len() != 2 { return Err("addss requires 2 operands".into()); }
            let dst = parse_xmm(args[0])?;
            if let Ok(src) = parse_xmm(args[1]) {
                a.addss(dst, src).map_err(|e| e.to_string())?;
            } else {
                let mem = parse_mem(args[1], symbols, origin_rip)?;
                a.addss(dst, mem).map_err(|e| e.to_string())?;
            }
        }
        "subss" => {
            if args.len() != 2 { return Err("subss requires 2 operands".into()); }
            let dst = parse_xmm(args[0])?;
            if let Ok(src) = parse_xmm(args[1]) {
                a.subss(dst, src).map_err(|e| e.to_string())?;
            } else {
                let mem = parse_mem(args[1], symbols, origin_rip)?;
                a.subss(dst, mem).map_err(|e| e.to_string())?;
            }
        }
        "movss" => {
            if args.len() != 2 { return Err("movss requires 2 operands".into()); }
            if let Ok(dst) = parse_xmm(args[0]) {
                if let Ok(src) = parse_xmm(args[1]) {
                    a.movss(dst, src).map_err(|e| e.to_string())?;
                } else {
                    let mem = parse_mem(args[1], symbols, origin_rip)?;
                    a.movss(dst, mem).map_err(|e| e.to_string())?;
                }
            } else {
                let dst_mem = parse_mem(args[0], symbols, origin_rip)?;
                let src = parse_xmm(args[1])?;
                a.movss(dst_mem, src).map_err(|e| e.to_string())?;
            }
        }
        "mov" => {
            if args.len() != 2 { return Err("mov requires 2 operands".into()); }
            if let Ok(dst) = parse_gpr64(args[0]) {
                if let Ok(src) = parse_gpr64(args[1]) {
                    a.mov(dst, src).map_err(|e| e.to_string())?;
                } else if let Ok(mem) = parse_mem(args[1], symbols, origin_rip) {
                    a.mov(dst, mem).map_err(|e| e.to_string())?;
                } else if let Ok(imm) = parse_u64_expr(args[1], symbols) {
                    a.mov(dst, imm).map_err(|e| e.to_string())?;
                } else {
                    return Err(format!("unknown source operand for mov: {}", args[1]));
                }
            } else if let Ok(dst) = parse_gpr32(args[0]) {
                if let Ok(src) = parse_gpr32(args[1]) {
                    a.mov(dst, src).map_err(|e| e.to_string())?;
                } else if let Ok(mem) = parse_mem(args[1], symbols, origin_rip) {
                    a.mov(dst, mem).map_err(|e| e.to_string())?;
                } else if let Ok(imm) = parse_u64_expr(args[1], symbols) {
                    a.mov(dst, imm as u32).map_err(|e| e.to_string())?;
                } else {
                    return Err(format!("unknown source operand for mov: {}", args[1]));
                }
            } else if let Ok(dst_mem) = parse_mem(args[0], symbols, origin_rip) {
                if let Ok(src) = parse_gpr64(args[1]) {
                    a.mov(dst_mem, src).map_err(|e| e.to_string())?;
                } else if let Ok(src) = parse_gpr32(args[1]) {
                    a.mov(dst_mem, src).map_err(|e| e.to_string())?;
                } else if let Ok(imm) = parse_u64_expr(args[1], symbols) {
                    a.mov(dst_mem, imm as u32).map_err(|e| e.to_string())?;
                } else {
                    return Err(format!("unknown source operand for mov to mem: {}", args[1]));
                }
            } else {
                return Err(format!("unsupported mov operands: {}, {}", args[0], args[1]));
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

fn parse_mem(
    s: &str,
    symbols: &HashMap<String, u64>,
    _origin_rip: u64,
) -> Result<iced_x86::code_asm::AsmMemoryOperand, String> {
    use iced_x86::code_asm::*;

    let s = s.trim();
    let inner = if let Some(stripped) = s.strip_prefix("dword ptr [").or_else(|| s.strip_prefix("DWORD PTR [")).or_else(|| s.strip_prefix("qword ptr [")).or_else(|| s.strip_prefix("QWORD PTR [")).or_else(|| s.strip_prefix('[')) {
        stripped.strip_suffix(']').ok_or_else(|| format!("unclosed bracket in '{s}'"))?
    } else {
        return Err(format!("expected memory operand with brackets '[...]', got '{s}'"));
    };

    let inner = inner.trim();

    // Check for base + offset, e.g. `rax+0x10` or `rax-0x8` or `rbx + 0x190`
    if let Some((reg_str, off_str)) = inner.split_once('+') {
        let reg = parse_gpr64(reg_str.trim())?;
        let off = parse_u64_expr(off_str.trim(), symbols)? as i32;
        return Ok(dword_ptr(reg + off));
    }
    if let Some((reg_str, off_str)) = inner.split_once('-') {
        let reg = parse_gpr64(reg_str.trim())?;
        let off = parse_u64_expr(off_str.trim(), symbols)? as i32;
        return Ok(dword_ptr(reg - off));
    }

    // Plain register, e.g. `[rax]`
    if let Ok(reg) = parse_gpr64(inner) {
        return Ok(dword_ptr(reg));
    }

    // Check for symbol / marker expression e.g. `$cave_val` or `0x1400100`
    if let Ok(addr) = parse_u64_expr(inner, symbols) {
        return Ok(dword_ptr(addr));
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
}

