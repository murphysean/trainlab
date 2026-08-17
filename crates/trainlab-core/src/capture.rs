//! Passive, non-stalling register capture at a code address.
//!
//! This is the "register-anchor" primitive: arm a transparent trampoline at a
//! stable code site that records the value of a chosen register each time the
//! site executes, replays the stolen instructions, and jumps back — the game
//! never stops. Read the recorded values back to reproduce a resource address
//! across sessions without re-scanning.
//!
//! The heavy lifting (allocate scratch, install trampoline, track for
//! uninstall) lives in `trainlab-inject`; this module defines the *wire
//! spec* (which register, how to decode it) and emits the non-stalling
//! capture payload that runs in the cave.

use serde::{Deserialize, Serialize};

/// Which register to record when the capture site executes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Register {
    /// General-purpose registers (64-bit).
    Rax,
    Rcx,
    Rdx,
    Rbx,
    Rsp,
    Rbp,
    Rsi,
    Rdi,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    /// SIMD registers (recorded as raw bits via `movq`; decode per value_type).
    Xmm0,
    Xmm1,
    Xmm2,
    Xmm3,
    Xmm4,
    Xmm5,
    Xmm6,
    Xmm7,
}

impl Register {
    fn xmm_index(self) -> Option<u8> {
        match self {
            Register::Xmm0 => Some(0),
            Register::Xmm1 => Some(1),
            Register::Xmm2 => Some(2),
            Register::Xmm3 => Some(3),
            Register::Xmm4 => Some(4),
            Register::Xmm5 => Some(5),
            Register::Xmm6 => Some(6),
            Register::Xmm7 => Some(7),
            _ => None,
        }
    }

    /// Whether this is an XMM (SIMD) register.
    pub fn is_xmm(self) -> bool {
        self.xmm_index().is_some()
    }

    pub fn name(self) -> &'static str {
        match self {
            Register::Rax => "rax",
            Register::Rcx => "rcx",
            Register::Rdx => "rdx",
            Register::Rbx => "rbx",
            Register::Rsp => "rsp",
            Register::Rbp => "rbp",
            Register::Rsi => "rsi",
            Register::Rdi => "rdi",
            Register::R8 => "r8",
            Register::R9 => "r9",
            Register::R10 => "r10",
            Register::R11 => "r11",
            Register::R12 => "r12",
            Register::R13 => "r13",
            Register::R14 => "r14",
            Register::R15 => "r15",
            Register::Xmm0 => "xmm0",
            Register::Xmm1 => "xmm1",
            Register::Xmm2 => "xmm2",
            Register::Xmm3 => "xmm3",
            Register::Xmm4 => "xmm4",
            Register::Xmm5 => "xmm5",
            Register::Xmm6 => "xmm6",
            Register::Xmm7 => "xmm7",
        }
    }

    /// Parse a register name (case-insensitive).
    pub fn parse(s: &str) -> Option<Register> {
        let l = s.trim().to_ascii_lowercase();
        Some(match l.as_str() {
            "rax" => Register::Rax,
            "rcx" => Register::Rcx,
            "rdx" => Register::Rdx,
            "rbx" => Register::Rbx,
            "rsp" => Register::Rsp,
            "rbp" => Register::Rbp,
            "rsi" => Register::Rsi,
            "rdi" => Register::Rdi,
            "r8" => Register::R8,
            "r9" => Register::R9,
            "r10" => Register::R10,
            "r11" => Register::R11,
            "r12" => Register::R12,
            "r13" => Register::R13,
            "r14" => Register::R14,
            "r15" => Register::R15,
            "xmm0" => Register::Xmm0,
            "xmm1" => Register::Xmm1,
            "xmm2" => Register::Xmm2,
            "xmm3" => Register::Xmm3,
            "xmm4" => Register::Xmm4,
            "xmm5" => Register::Xmm5,
            "xmm6" => Register::Xmm6,
            "xmm7" => Register::Xmm7,
            _ => return None,
        })
    }
}

/// How to interpret the captured raw 64-bit register value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValueType {
    /// Raw 64-bit address / integer (the default).
    Ptr,
    /// Signed 64-bit integer.
    I64,
    /// Unsigned 64-bit integer.
    U64,
    /// Interpret as an IEEE-754 double (from GPR bits or XMM).
    F64,
    /// Interpret as a 32-bit float (low 32 bits; upper ignored).
    F32,
}

impl ValueType {
    pub fn parse(s: &str) -> Option<ValueType> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "ptr" | "pointer" | "address" => ValueType::Ptr,
            "i64" | "i" | "s64" => ValueType::I64,
            "u64" | "u" => ValueType::U64,
            "f64" | "f" | "double" => ValueType::F64,
            "f32" | "float" => ValueType::F32,
            _ => return None,
        })
    }
    pub fn name(self) -> &'static str {
        match self {
            ValueType::Ptr => "ptr",
            ValueType::I64 => "i64",
            ValueType::U64 => "u64",
            ValueType::F64 => "f64",
            ValueType::F32 => "f32",
        }
    }
}

/// The full spec for a `CaptureReg` capture: which register + how to decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureRegSpec {
    pub reg: Register,
    pub value_type: ValueType,
}

impl CaptureRegSpec {
    pub fn new(reg: Register, value_type: ValueType) -> Self {
        Self { reg, value_type }
    }
}

// ---------------------------------------------------------------------------
// Ring buffer layout
// ---------------------------------------------------------------------------
//
// The capture payload writes into a DLL-owned ring. Layout (all little-endian):
//
//   +0   write_byte_offset u32   offset into the entries region to write next
//   +4   (pad)
//   +8   total_bytes     u32     capacity * ENTRY_STRIDE
//   +12  (pad)
//   +16  seq             u64     monotonically increasing capture counter
//   +24  entries[total_bytes]
//
// Each entry (ENTRY_STRIDE = 24 bytes):
//   +0  seq   u64
//   +8  raw   u64   (the captured register bits)
//   +16 rip   u64   (the site address that was executing)
// ---------------------------------------------------------------------------

/// Byte stride of one ring entry.
pub const ENTRY_STRIDE: usize = 24;
/// Offset of the `seq` field within an entry.
pub const ENTRY_SEQ_OFF: usize = 0;
/// Offset of the `raw` (register value) field within an entry.
pub const ENTRY_RAW_OFF: usize = 8;
/// Offset of the `rip` field within an entry.
pub const ENTRY_RIP_OFF: usize = 16;
/// Offset of the ring header in the allocated block.
pub const RING_HEADER: usize = 24;

/// Total ring allocation size for a given capacity.
pub fn ring_size(capacity: usize) -> usize {
    RING_HEADER + capacity * ENTRY_STRIDE
}

// ---------------------------------------------------------------------------
// Non-stalling capture payload
// ---------------------------------------------------------------------------

/// Push every register the payload clobbers (RAX, RCX, RDX, R8, R9, R10, R11),
/// so the relocated stolen instructions and the surrounding game code see an
/// intact register state. The captured value is parked in R11 (a saved
/// register) before anything is clobbered. Returns the pushes in order; the
/// caller must emit the matching pops in reverse.
fn push_clobbered() -> Vec<u8> {
    let mut out = Vec::new();
    // push r11, r10, r9, r8, rdx, rcx, rax
    for b in [
        0x41, 0x53, // push r11
        0x41, 0x52, // push r10
        0x41, 0x51, // push r9
        0x41, 0x50, // push r8
        0x52, // push rdx
        0x51, // push rcx
        0x50, // push rax
    ] {
        out.push(b);
    }
    out
}

/// Pop the registers saved by [`push_clobbered`], in reverse order.
fn pop_clobbered() -> Vec<u8> {
    let mut out = Vec::new();
    // pop rax, rcx, rdx, r8, r9, r10, r11
    for b in [
        0x58, // pop rax
        0x59, // pop rcx
        0x5A, // pop rdx
        0x41, 0x58, // pop r8
        0x41, 0x59, // pop r9
        0x41, 0x5A, // pop r10
        0x41, 0x5B, // pop r11
    ] {
        out.push(b);
    }
    out
}

/// Emit `mov r11, rN` (REX.W/B 89 /r): park the target register value in the
/// saved register r11 before the payload clobbers any scratch.
fn mov_r11_from_gpr(reg: Register) -> Vec<u8> {
    let idx = match reg {
        Register::Rax => 0,
        Register::Rcx => 1,
        Register::Rdx => 2,
        Register::Rbx => 3,
        Register::Rsp => 4,
        Register::Rbp => 5,
        Register::Rsi => 6,
        Register::Rdi => 7,
        Register::R8 => 0,
        Register::R9 => 1,
        Register::R10 => 2,
        Register::R11 => 3,
        Register::R12 => 4,
        Register::R13 => 5,
        Register::R14 => 6,
        Register::R15 => 7,
        _ => unreachable!(),
    };
    let extended = matches!(
        reg,
        Register::R8
            | Register::R9
            | Register::R10
            | Register::R11
            | Register::R12
            | Register::R13
            | Register::R14
            | Register::R15
    );
    // REX.W|B for r11 as rm; add REX.R if the source is r8-r15.
    let mut rex = 0x48 | 0x01; // W + B (rm=r11)
    if extended {
        rex |= 0x04; // R
    }
    // modrm = 11_<reg>_011 (rm = r11)
    let modrm = 0xC0 | (idx << 3) | 0x03;
    vec![rex, 0x89, modrm]
}

/// Emit `movq r11, xmmN` (66 REX.W/B 0F 7E /r): park an XMM register's low 64
/// bits into r11 before the payload clobbers any scratch.
fn mov_r11_from_xmm(reg: Register) -> Vec<u8> {
    let xmm = reg.xmm_index().unwrap();
    // 66 REX.W|B 0F 7E /r; reg = xmm index, rm = r11 (needs REX.B).
    let rex = 0x48 | 0x01;
    let modrm = 0xC0 | (xmm << 3) | 0x03;
    vec![0x66, rex, 0x0F, 0x7E, modrm]
}

/// Emit `mov rax, imm64` (10 bytes).
fn mov_rax_imm64(value: u64) -> Vec<u8> {
    let mut out = vec![0x48, 0xB8];
    out.extend_from_slice(&value.to_le_bytes());
    out
}

/// Emit the non-stalling capture payload body (excluding the volatile save /
/// restore prologue/epilogue, which the caller wraps). Assumes all volatile
/// regs are already saved on the stack and free to clobber.
///
/// `ring_base` is the DLL-allocated ring address. `site` is the code address
/// being patched (recorded into each entry's `rip` field). `reg` is the
/// register to record.
fn capture_body(ring_base: u64, site: u64, reg: Register) -> Vec<u8> {
    let mut b = Vec::new();

    // 1. Park the captured register value in r11 (a pushed, un-clobbered reg)
    //    *before* any scratch clobbering, so capturing rax/rcx/rdx/r8..r11 is
    //    correct.
    match reg {
        Register::Xmm0
        | Register::Xmm1
        | Register::Xmm2
        | Register::Xmm3
        | Register::Xmm4
        | Register::Xmm5
        | Register::Xmm6
        | Register::Xmm7 => b.extend(mov_r11_from_xmm(reg)),
        _ => b.extend(mov_r11_from_gpr(reg)),
    }

    // 2. r10 = ring_base (r10 is clobbered anyway, so we can use it to hold the
    //    header base across the site-immediate write without losing it).
    b.extend_from_slice(&[0x49, 0xBA]); // mov r10, imm64
    b.extend_from_slice(&ring_base.to_le_bytes());

    // 3. ecx = write_byte_offset, edx = total_bytes
    b.extend_from_slice(&[0x41, 0x8B, 0x0A]); // mov ecx, [r10]
    b.extend_from_slice(&[0x41, 0x8B, 0x52, 0x08]); // mov edx, [r10+8]

    // 4. single-wrap: if offset >= total, offset -= total
    b.extend_from_slice(&[0x39, 0xD1]); // cmp ecx, edx
    b.extend_from_slice(&[0x7C, 0x02]); // jl +2 (skip)
    b.extend_from_slice(&[0x29, 0xD1]); // sub ecx, edx

    // 5. r8 = entries_base = r10 + 24 ; r8 += ecx (current entry)
    b.extend_from_slice(&[0x4D, 0x8D, 0x42, 0x18]); // lea r8, [r10+24]
    b.extend_from_slice(&[0x49, 0x01, 0xC8]); // add r8, rcx

    // 6. bump seq, then store it at entry+0 (so the first entry has seq=1, not
    //    the "unwritten" sentinel 0 that the reader skips).
    b.extend_from_slice(&[0x49, 0xFF, 0x42, 0x10]); // inc qword [r10+16]
    b.extend_from_slice(&[0x4D, 0x8B, 0x4A, 0x10]); // mov r9, [r10+16]
    b.extend_from_slice(&[0x4D, 0x89, 0x08]); // mov [r8], r9

    // 7. store the parked captured value (r11) at entry+8
    b.extend_from_slice(&[0x4D, 0x89, 0x58, 0x08]); // mov [r8+8], r11

    // 8. store site (rip) at entry+16
    b.extend(mov_rax_imm64(site));
    b.extend_from_slice(&[0x49, 0x89, 0x40, 0x10]); // mov [r8+16], rax

    // 10. advance write offset by ENTRY_STRIDE, wrap into u32
    b.extend_from_slice(&[0x81, 0xC1, 0x18, 0x00, 0x00, 0x00]); // add ecx, 24
    b.extend_from_slice(&[0x41, 0x89, 0x0A]); // mov [r10], ecx

    b
}

/// Emit the full non-stalling capture payload: save the clobbered regs, record
/// the chosen register, restore the clobbered regs. This runs at the top of the
/// cave, *before* the relocated stolen instructions, so the game behavior is
/// fully preserved (the capture is read-only) and every register the game
/// depends on (including the captured one) is intact afterward.
pub fn emit_capture_payload(ring_base: u64, site: u64, reg: Register) -> Vec<u8> {
    let mut out = push_clobbered();
    out.extend(capture_body(ring_base, site, reg));
    out.extend(pop_clobbered());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_parse_roundtrip() {
        assert_eq!(Register::parse("rcx"), Some(Register::Rcx));
        assert_eq!(Register::parse("RBP"), Some(Register::Rbp));
        assert_eq!(Register::parse("xmm3"), Some(Register::Xmm3));
        assert_eq!(Register::parse("nope"), None);
        assert_eq!(ValueType::parse("f64"), Some(ValueType::F64));
        assert_eq!(ValueType::parse("ptr"), Some(ValueType::Ptr));
    }

    #[test]
    fn payload_starts_and_ends_with_balanced_save_restore() {
        let p = emit_capture_payload(0x5000, 0x1401b42e9, Register::Rcx);
        // Must begin with push r11 (41 53) and end with pop r11 (41 5B).
        assert_eq!(&p[0..2], &[0x41, 0x53], "starts by pushing volatile regs");
        assert_eq!(&p[p.len() - 2..], &[0x41, 0x5B], "ends by popping volatile regs");
        // Contains the ring base immediate.
        assert!(
            p.windows(8).any(|w| w == 0x5000u64.to_le_bytes()),
            "payload embeds ring base"
        );
    }

    #[test]
    fn xmm_payload_uses_movq() {
        let p = emit_capture_payload(0x9000, 0x1234, Register::Xmm2);
        // movq r11, xmm2 = 66 49 0F 7E D3 (REX.W|B for r11)
        assert!(
            p.windows(5).any(|w| w == [0x66, 0x49, 0x0F, 0x7E, 0xD3]),
            "xmm payload records via movq into r11"
        );
    }

    #[test]
    fn ring_size_matches_layout() {
        // capacity 32 => header(24) + 32*24
        assert_eq!(ring_size(32), 24 + 32 * ENTRY_STRIDE);
        assert_eq!(ring_size(1), 24 + ENTRY_STRIDE);
    }
}
