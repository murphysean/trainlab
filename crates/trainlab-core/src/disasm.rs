//! Disassembly of raw bytes via `iced-x86`.
//!
//! This is the "pull the bytes out of the game and turn them into readable
//! instructions" capability. It is pure (no process access) — the caller
//! supplies the raw bytes (e.g. from [`crate::memory::ProcessMemory::read`])
//! and we decode them.

use iced_x86::{BlockEncoder, Decoder, DecoderOptions, FlowControl, Formatter, Instruction, NasmFormatter};

/// The relocated output of a stolen-instruction block: the position-correct
/// bytes that can run at a new address, plus whether the block terminates flow
/// (ends in a branch/call/ret) so the caller knows whether a separate jump-back
/// is still needed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelocatedBlock {
    /// The re-encoded bytes, fixed up for their new location.
    pub bytes: Vec<u8>,
    /// True if the last instruction transfers control (branch/call/ret) — in
    /// which case control does not fall through and no jump-back is required.
    pub ends_in_branch: bool,
}

/// Disassemble `bytes` starting at virtual address `base`.
///
/// Returns one string per decoded instruction. If `count` is `Some(n)`, stop
/// after `n` instructions; otherwise decode the whole buffer.
pub fn disassemble(base: u64, bytes: &[u8], count: Option<usize>) -> Vec<String> {
    let mut decoder = Decoder::with_ip(64, bytes, base, DecoderOptions::NONE);
    decoder.set_ip(base);
    let mut formatter = NasmFormatter::new();
    formatter.options_mut().set_uppercase_hex(false);
    formatter.options_mut().set_hex_prefix("0x");

    let mut out = Vec::new();
    let limit = count.unwrap_or(usize::MAX);
    for _ in 0..limit {
        let start = decoder.position();
        let insn = decoder.decode();
        if insn.is_invalid() {
            break;
        }
        let len = decoder.position() - start;
        let ip = base + start as u64;
        // SAFETY: `start`..`start+len` is within `bytes` (the decoder read it).
        let instr_bytes = &bytes[start..start + len];
        let hex: Vec<String> = instr_bytes.iter().map(|b| format!("{b:02x}")).collect();
        let mut text = String::new();
        text.push_str(&format!("{ip:#018x}  {}  ", hex.join(" ")));
        formatter.format(&insn, &mut text);
        out.push(text);
    }
    out
}

/// Decode just the first instruction at `bytes` and return its length in bytes.
///
/// This is important for safely patching: you must not overwrite the middle of
/// an instruction, so we need the exact length of the instruction we're about
/// to redirect.
pub fn first_instruction_len(bytes: &[u8]) -> Option<usize> {
    let mut decoder = Decoder::with_ip(64, bytes, 0, DecoderOptions::NONE);
    let start = decoder.position();
    let insn = decoder.decode();
    if insn.is_invalid() {
        None
    } else {
        Some(decoder.position() - start)
    }
}

/// Walk instructions from the start of `bytes`, summing their lengths, and
/// return the smallest total that is `>= min_len` and lands on an instruction
/// boundary. This is the number of bytes a code-cave patch must overwrite so
/// that a `jmp` of `min_len` bytes fits without splitting an instruction, and
/// the jump-back lands on a real instruction boundary.
pub fn instruction_aligned_len(bytes: &[u8], min_len: usize) -> Option<usize> {
    let mut decoder = Decoder::with_ip(64, bytes, 0, DecoderOptions::NONE);
    let mut total = 0usize;
    loop {
        let start = decoder.position();
        let insn = decoder.decode();
        if insn.is_invalid() {
            return None;
        }
        total += decoder.position() - start;
        if total >= min_len {
            return Some(total);
        }
        if total >= bytes.len() {
            return None;
        }
    }
}

/// Relocate a block of stolen instructions to a new address.
///
/// This is the heart of a *transparent* code-cave hook: when we overwrite the
/// first `patch_len` bytes of `target` with a `jmp`, those original instructions
/// are lost unless we re-emit them in the cave. This decodes them at their
/// original address, then re-encodes them to run at `new_ip`:
///
/// - relative branch targets are recomputed for the new location,
/// - RIP-relative memory operands are fixed up for the new location,
/// - branches whose target is outside the block (e.g. a `jmp` onward in the
///   original function) are preserved as an absolute target re-encoded to the
///   correct relative offset from the cave.
///
/// Returns the re-encoded bytes plus whether the last instruction transfers
/// control (`ends_in_branch`). If `ends_in_branch`, the caller should NOT append
/// a jump-back — control already leaves via the relocated branch.
///
/// # Errors
///
/// Returns `None` if any instruction in `bytes` fails to decode or re-encode.
pub fn relocate(bytes: &[u8], orig_ip: u64, new_ip: u64) -> Option<RelocatedBlock> {
    // Decode every whole instruction from `bytes`.
    let mut decoder = Decoder::with_ip(64, bytes, orig_ip, DecoderOptions::NONE);
    let mut instrs: Vec<Instruction> = Vec::new();
    let mut consumed = 0usize;
    loop {
        if consumed >= bytes.len() {
            break;
        }
        let start = decoder.position();
        let insn = decoder.decode();
        if insn.is_invalid() {
            return None;
        }
        let len = decoder.position() - start;
        if len == 0 {
            return None; // safety: avoid an infinite loop
        }
        consumed += len;
        instrs.push(insn);
    }
    if instrs.is_empty() {
        return None;
    }

    // Re-encode the decoded instructions to run at `new_ip`.
    let block = iced_x86::InstructionBlock::new(&instrs, new_ip);
    let result = BlockEncoder::encode(64, block, 0).ok()?;
    let ends_in_branch = instrs
        .last()
        .map(|i| matches!(
            i.flow_control(),
            FlowControl::UnconditionalBranch
                | FlowControl::ConditionalBranch
                | FlowControl::IndirectBranch
                | FlowControl::Return
                | FlowControl::Call
                | FlowControl::IndirectCall
        ))
        .unwrap_or(false);

    Some(RelocatedBlock {
        bytes: result.code_buffer,
        ends_in_branch,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disassembles_mov() {
        // mov eax, 0x2a  =>  B8 2A 00 00 00
        let bytes = [0xB8, 0x2A, 0x00, 0x00, 0x00];
        let text = disassemble(0x1000, &bytes, None);
        assert_eq!(text.len(), 1);
        assert!(text[0].contains("mov"), "got: {text:?}");
    }

    #[test]
    fn disassembles_multi() {
        // mov eax, 0x2a ; nop ; ret
        let bytes = [0xB8, 0x2A, 0x00, 0x00, 0x00, 0x90, 0xC3];
        let text = disassemble(0x1000, &bytes, None);
        assert_eq!(text.len(), 3, "got: {text:?}");
    }

    #[test]
    fn first_len_counts_bytes() {
        // mov eax, imm32 = 5 bytes
        let bytes = [0xB8, 0x2A, 0x00, 0x00, 0x00];
        assert_eq!(first_instruction_len(&bytes), Some(5));
    }

    #[test]
    fn invalid_bytes_give_none() {
        assert_eq!(first_instruction_len(&[0xFF, 0xFF, 0xFF]), None);
    }

    #[test]
    fn aligned_len_walks_instructions() {
        // movss [rax+0x10], xmm5 (5 bytes) then mov eax,1 (5 bytes) then jmp (5 bytes)
        let bytes = [
            0xf3, 0x0f, 0x11, 0x68, 0x10, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xe9, 0xcd, 0x02, 0x00,
            0x00,
        ];
        // min 12: 5+5+5 = 15 (>=12, instruction-aligned)
        assert_eq!(instruction_aligned_len(&bytes, 12), Some(15));
        // min 5: first instruction is 5 bytes
        assert_eq!(instruction_aligned_len(&bytes, 5), Some(5));
        // min 6: 5+5 = 10
        assert_eq!(instruction_aligned_len(&bytes, 6), Some(10));
    }

    #[test]
    fn relocate_keeps_bytes_and_marks_branch() {
        // movss [rax+0x10], xmm5 ; mov eax,1 ; jmp 0x1000 (relative onward)
        // The block ends in a branch, so ends_in_branch = true.
        let bytes = [
            0xf3, 0x0f, 0x11, 0x68, 0x10, // movss [rax+0x10], xmm5
            0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax,1
            0xe9, 0x00, 0x00, 0x00, 0x00, // jmp (rel32, patched by encoder to target)
        ];
        let r = relocate(&bytes, 0x4000, 0x76570000).expect("relocate");
        assert!(r.ends_in_branch, "block ends in jmp");
        // The re-encoded block should contain a movss and a mov eax,1 and a
        // branch. Just check it's non-empty and starts with the movss prefix.
        assert_eq!(r.bytes.len(), 15, "three 5-byte instrs re-encoded");
        assert_eq!(&r.bytes[0..3], &[0xf3, 0x0f, 0x11]);
    }

    #[test]
    fn relocate_marks_fallthrough_block() {
        // mov eax,1 ; mov edx,2 — no branch, ends_in_branch = false.
        let bytes = [0xb8, 0x01, 0x00, 0x00, 0x00, 0xba, 0x02, 0x00, 0x00, 0x00];
        let r = relocate(&bytes, 0x5000, 0x6000).expect("relocate");
        assert!(!r.ends_in_branch, "fallthrough block should not end in branch");
        assert_eq!(r.bytes.len(), 10);
    }

    #[test]
    fn relocate_preserves_relative_branch_target() {
        // A short jmp forward (E9 rel32 to +0x1000 from orig). The re-encoded
        // block at new_ip must retarget the same absolute destination, so the
        // rel32 differs.
        let bytes = [0x90, 0xe9, 0x00, 0x10, 0x00, 0x00]; // nop ; jmp +0x1000
        let orig = 0x4000u64;
        let r = relocate(&bytes, orig, 0x7000).expect("relocate");
        // nop (1) + jmp rel32 (5) = 6 bytes.
        assert_eq!(r.bytes.len(), 6);
        // Destination of the original jmp: 0x4000 + 1(nop) + 5(jmp) + 0x1000 = 0x5005.
        let orig_dst = orig + 1 + 5 + 0x1000;
        // The new rel32 = orig_dst - (new_ip + 1 + 5)  [relative to after the jmp].
        let after_new = 0x7000 + 1 + 5;
        let expect_rel = orig_dst as i64 - after_new as i64;
        let rel32 = i32::from_le_bytes(r.bytes[2..6].try_into().unwrap()) as i64;
        assert_eq!(rel32, expect_rel, "jmp retargeted to same absolute destination");
    }
}
