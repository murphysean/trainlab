//! Emit minimal x86-64 shellcode for common hook patterns.
//!
//! A code cave hook works like this:
//!
//! 1. We patch the first N bytes of a target instruction with an absolute
//!    `jmp cave` (RIP-relative, using `mov rax, imm64; jmp rax` for
//!    address-space independence — see [`patch_jump`]).
//! 2. Execution reaches the cave, runs our payload, then must **return** to
//!    the original flow — the instruction right after the patched region —
//!    via a jump-back.
//!
//! This module emits the *bytes* for the payload and the jump/return
//! trampolines. It is pure (no process access); installation is elsewhere.

/// Emit an absolute `jmp` to `target` that preserves all registers.
///
/// ```text
/// FF 25 <rel32>      jmp qword ptr [rip + rel32]
/// <8-byte target>    (in the slot right after the jmp)
/// ```
///
/// This is 14 bytes and reads the absolute 64-bit destination from the memory
/// slot immediately after the instruction. Crucially, it **clobbers no
/// registers** — unlike the `mov rax,imm64; jmp rax` form — which is essential
/// for transparent trampolines where the relocated stolen instructions depend
/// on register state (e.g. `movss [rax+0x10], xmm5` needs RAX intact). A plain
/// RIP-relative `E9 rel32` would be more compact (5 bytes) but has a ±2GB limit
/// that is fragile for caves allocated far from the target code, so we use the
/// memory-indirect absolute form instead.
///
/// Returns all 14 bytes (the `jmp` plus its embedded target slot), so the
/// caller writes them contiguously.
pub fn jmp_abs(target: u64) -> Vec<u8> {
    // FF 25 <rel32>: jmp qword ptr [rip+rel32]. rip at the end of this
    // instruction points to the slot, so rel32 = 0 reads the slot.
    let mut out = Vec::with_capacity(14);
    out.extend_from_slice(&[0xFF, 0x25]); // jmp qword ptr [rip+disp32]
    out.extend_from_slice(&0i32.to_le_bytes()); // disp32 = 0 (the slot below)
    out.extend_from_slice(&target.to_le_bytes()); // 8-byte absolute target slot
    out
}

/// Emit a short relative `jmp rel8` to reach an address within ±127 bytes.
/// Used for the jump-back from a small cave to the instruction after the patch.
pub fn jmp_rel8(offset: i8) -> Vec<u8> {
    vec![0xEB, offset as u8]
}

/// Emit a relative `jmp rel32` (5 bytes, `E9 <rel32>`).
pub fn jmp_rel32(rel: i32) -> Vec<u8> {
    let mut out = Vec::with_capacity(5);
    out.push(0xE9);
    out.extend_from_slice(&rel.to_le_bytes());
    out
}

/// Emit `mov rax, imm64` (10 bytes).
pub fn mov_rax_imm64(value: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(10);
    out.extend_from_slice(&[0x48, 0xB8]); // mov rax, imm64
    out.extend_from_slice(&value.to_le_bytes());
    out
}

/// Emit `mov dword [rax+disp], imm32` — store an immediate 32-bit value into
/// memory at `[rax + disp]`. Handy for overriding a resource/stat field.
///
/// ```text
/// C7 80 <disp32> <imm32>     mov dword ptr [rax+disp], imm32
/// ```
pub fn mov_dword_ptr_rax_disp_imm32(disp: i32, value: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(10);
    out.extend_from_slice(&[0xC7, 0x80]); // mov dword [rax+disp32]
    out.extend_from_slice(&disp.to_le_bytes());
    out.extend_from_slice(&value.to_le_bytes());
    out
}

/// Emit `mov dword [rax+disp], ecx` — copy a 32-bit register into memory.
///
/// ```text
/// 89 88 <disp32>              mov dword ptr [rax+disp], ecx
/// ```
pub fn mov_dword_ptr_rax_disp_ecx(disp: i32) -> Vec<u8> {
    let mut out = Vec::with_capacity(6);
    out.extend_from_slice(&[0x89, 0x88]);
    out.extend_from_slice(&disp.to_le_bytes());
    out
}

/// The length of a full `jmp_abs` trampoline (14 bytes): the `FF 25 rel32`
/// instruction plus its embedded 8-byte absolute target slot. Exposed so
/// callers can size the patched region / require a cave large enough.
pub const JMP_ABS_LEN: usize = 14;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jmp_abs_len_and_prefix() {
        let b = jmp_abs(0x12345678);
        // 14 bytes: FF 25 disp32 + 8-byte target slot.
        assert_eq!(b.len(), 14);
        assert_eq!(&b[0..2], &[0xFF, 0x25]);
        assert_eq!(i32::from_le_bytes(b[2..6].try_into().unwrap()), 0);
        assert_eq!(u64::from_le_bytes(b[6..14].try_into().unwrap()), 0x12345678);
    }

    #[test]
    fn mov_rax_imm() {
        let b = mov_rax_imm64(0xDEADBEEF);
        assert_eq!(b.len(), 10);
        assert_eq!(u64::from_le_bytes(b[2..10].try_into().unwrap()), 0xDEADBEEF);
    }

    #[test]
    fn mov_dword_ptr_rax_disp_imm() {
        let b = mov_dword_ptr_rax_disp_imm32(0x10, 500);
        assert_eq!(b.len(), 10);
        assert_eq!(&b[0..2], &[0xC7, 0x80]);
        assert_eq!(i32::from_le_bytes(b[2..6].try_into().unwrap()), 0x10);
        assert_eq!(u32::from_le_bytes(b[6..10].try_into().unwrap()), 500);
    }

    #[test]
    fn test_mov_dword_ptr_rax_disp_ecx() {
        let b = super::mov_dword_ptr_rax_disp_ecx(0x18);
        assert_eq!(b.len(), 6);
        assert_eq!(&b[0..2], &[0x89, 0x88]);
        assert_eq!(i32::from_le_bytes(b[2..6].try_into().unwrap()), 0x18);
    }
}
