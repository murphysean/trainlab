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

/// How the gate compares the gate register's value. The comparison is always
/// against constants supplied by the trainer and pre-stored in the ring header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateCmp {
    /// gate == value
    Eq,
    /// gate != value
    Ne,
    /// gate > value
    Gt,
    /// gate < value
    Lt,
    /// gate >= value
    Ge,
    /// gate <= value
    Le,
    /// min <= gate <= max
    Range,
    /// gate is a clean whole number (no fractional part); for i64/u64/ptr this
    /// is always true.
    Whole,
}

impl GateCmp {
    pub fn parse(s: &str) -> Option<GateCmp> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "eq" | "==" => GateCmp::Eq,
            "ne" | "!=" => GateCmp::Ne,
            "gt" | ">" => GateCmp::Gt,
            "lt" | "<" => GateCmp::Lt,
            "ge" | ">=" => GateCmp::Ge,
            "le" | "<=" => GateCmp::Le,
            "range" | "in" => GateCmp::Range,
            "whole" => GateCmp::Whole,
            _ => return None,
        })
    }
    pub fn name(self) -> &'static str {
        match self {
            GateCmp::Eq => "eq",
            GateCmp::Ne => "ne",
            GateCmp::Gt => "gt",
            GateCmp::Lt => "lt",
            GateCmp::Ge => "ge",
            GateCmp::Le => "le",
            GateCmp::Range => "range",
            GateCmp::Whole => "whole",
        }
    }
}

/// A gate on the capture: only record the capture register when the *gate*
/// register satisfies a comparison. This is the decoupled "capture X if Y
/// compares Z" primitive — the value and the pointer are both live at the same
/// instant, so we gate on the value register (`rbp`) and capture the pointer
/// register (`rcx`) without dereferencing anything.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Gate {
    pub reg: Register,
    pub cmp: GateCmp,
    /// How to interpret the gate register's value (and the compare constants)
    /// for the comparison and for decoding `gate_value` on read-back.
    ///
    /// This is INDEPENDENT of the capture's `value_type`. The common case is a
    /// Lua/script double value register gated by its own f64 type while the
    /// capture records a pointer — without a separate gate type, the gate
    /// register would be mis-decoded (a double `3.0` has raw bits
    /// `0x4008000000000000`, which as an integer/ptr is ~4.6e18 and makes the
    /// range compare meaningless).
    pub value_type: ValueType,
    /// Compare constant for eq/ne/gt/lt/ge/le (interpreted per `value_type`).
    pub value: f64,
    /// Lower bound for `Range`.
    pub min: f64,
    /// Upper bound for `Range`.
    pub max: f64,
}

impl Gate {
    /// A single-constant comparison (eq/ne/gt/lt/ge/le).
    pub fn compare(reg: Register, cmp: GateCmp, value: f64) -> Self {
        Self { reg, cmp, value_type: ValueType::U64, value, min: 0.0, max: 0.0 }
    }
    /// A range comparison.
    pub fn range(reg: Register, min: f64, max: f64) -> Self {
        Self { reg, cmp: GateCmp::Range, value_type: ValueType::U64, value: 0.0, min, max }
    }
    /// A whole-number (no fractional part) gate.
    pub fn whole(reg: Register) -> Self {
        Self { reg, cmp: GateCmp::Whole, value_type: ValueType::F64, value: 0.0, min: 0.0, max: 0.0 }
    }
    /// Override the gate register's value type (defaults to U64 for compare/range
    /// gates, F64 for whole). Use this when the gate register holds a Lua/script
    /// double (e.g. `with_value_type(ValueType::F64)`).
    pub fn with_value_type(mut self, value_type: ValueType) -> Self {
        self.value_type = value_type;
        self
    }
}

/// The full spec for a `CaptureReg` capture: which register + how to decode,
/// plus an optional gate that decides *when* to record.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CaptureRegSpec {
    pub reg: Register,
    pub value_type: ValueType,
    /// Optional gate. If present, the capture register is only recorded when
    /// the gate register passes; if absent, the capture records unconditionally.
    pub gate: Option<Gate>,
    /// Patch jump style: Absolute (default, 14-byte) or Relative (5-byte short jump).
    #[serde(default)]
    pub jump: crate::cave_hook::JumpStyle,
}

impl CaptureRegSpec {
    pub fn new(reg: Register, value_type: ValueType) -> Self {
        Self { reg, value_type, gate: None, jump: crate::cave_hook::JumpStyle::Absolute }
    }
    pub fn with_gate(mut self, gate: Gate) -> Self {
        self.gate = Some(gate);
        self
    }
    pub fn with_jump(mut self, jump: crate::cave_hook::JumpStyle) -> Self {
        self.jump = jump;
        self
    }
    pub fn with_optional_gate(mut self, gate: Option<Gate>) -> Self {
        self.gate = gate;
        self
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
//   +12  disarmed        u32     1 = capture stopped (one_shot / stop_on_match)
//   +16  seq             u64     monotonically increasing capture counter
//   +24  const_a         u64     gate constant (eq/ne/gt/lt/ge/le) or range min
//   +32  const_b         u64     range max (unused otherwise)
//   +40  gate_scratch    u64     payload stores the gate register raw bits here
//   +48  entries[total_bytes]
//
// Each entry (ENTRY_STRIDE = 32 bytes):
//   +0  seq   u64
//   +8  raw   u64   (the captured register bits)
//   +16 rip   u64   (the site address that was executing)
//   +24 gate  u64   (the gate register raw bits at capture time)
// ---------------------------------------------------------------------------

/// Byte stride of one ring entry.
pub const ENTRY_STRIDE: usize = 32;
/// Offset of the `seq` field within an entry.
pub const ENTRY_SEQ_OFF: usize = 0;
/// Offset of the `raw` (register value) field within an entry.
pub const ENTRY_RAW_OFF: usize = 8;
/// Offset of the `rip` field within an entry.
pub const ENTRY_RIP_OFF: usize = 16;
/// Offset of the gate raw value within an entry.
pub const ENTRY_GATE_OFF: usize = 24;
/// Offset of the ring header in the allocated block.
pub const RING_HEADER: usize = 48;
/// Offset of the `disarmed` flag within the ring header.
pub const RING_DISARMED_OFF: usize = 12;
/// Offset of the gate `const_a` / range-min slot in the header.
pub const RING_CONST_A_OFF: usize = 24;
/// Offset of the range-max slot in the header.
pub const RING_CONST_B_OFF: usize = 32;
/// Offset of the gate-scratch slot in the header.
pub const RING_GATE_SCRATCH_OFF: usize = 40;

/// Total ring allocation size for a given capacity.
pub fn ring_size(capacity: usize) -> usize {
    RING_HEADER + capacity * ENTRY_STRIDE
}

// ---------------------------------------------------------------------------
// Non-stalling capture payload
// ---------------------------------------------------------------------------

/// The capture park register (a callee-saved GPR we push/pop) that holds the
/// captured register's value across the payload body.
const PARK_CAPTURE: u8 = 3; // r11
/// The gate park register that holds the gate register's value across the
/// payload body.
const PARK_GATE: u8 = 5; // r13

/// Push every register the payload clobbers (R13 + RAX, RCX, RDX, R8, R9, R10,
/// R11), so the relocated stolen instructions and the surrounding game code see
/// an intact register state. The captured value is parked in R11 and the gate
/// value in R13 (both saved) before anything is clobbered. Returns the pushes
/// in order; the caller must emit the matching pops in reverse.
fn push_clobbered() -> Vec<u8> {
    let mut out = Vec::new();
    for b in [
        0x41, 0x55, // push r13
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
    for b in [
        0x58, // pop rax
        0x59, // pop rcx
        0x5A, // pop rdx
        0x41, 0x58, // pop r8
        0x41, 0x59, // pop r9
        0x41, 0x5A, // pop r10
        0x41, 0x5B, // pop r11
        0x41, 0x5D, // pop r13
    ] {
        out.push(b);
    }
    out
}

fn gpr_index(reg: Register) -> u8 {
    match reg {
        Register::Rax | Register::R8 => 0,
        Register::Rcx | Register::R9 => 1,
        Register::Rdx | Register::R10 => 2,
        Register::Rbx | Register::R11 => 3,
        Register::Rsp | Register::R12 => 4,
        Register::Rbp | Register::R13 => 5,
        Register::Rsi | Register::R14 => 6,
        Register::Rdi | Register::R15 => 7,
        _ => unreachable!("not a GPR"),
    }
}

fn is_extended(reg: Register) -> bool {
    matches!(
        reg,
        Register::R8
            | Register::R9
            | Register::R10
            | Register::R11
            | Register::R12
            | Register::R13
            | Register::R14
            | Register::R15
    )
}

/// Emit `mov park, src` (REX.W 89 /r) where `park` is the GPR index of r11 or
/// r13. Preserves the source register value by copying it into the park
/// register before any clobbering. `src` may be any GPR.
fn park_from_gpr(src: Register, park: u8) -> Vec<u8> {
    let idx = gpr_index(src);
    // REX.W | B(rm=park in r8-r15) | R(src in r8-r15).
    let mut rex = 0x48 | 0x01;
    if is_extended(src) {
        rex |= 0x04;
    }
    let modrm = 0xC0 | (idx << 3) | park;
    vec![rex, 0x89, modrm]
}

/// Emit `movq park, xmmN` (66 REX.W/B 0F 7E /r): park an XMM register's low 64
/// bits into `park` (r11 or r13).
fn park_from_xmm(src: Register, park: u8) -> Vec<u8> {
    let xmm = src.xmm_index().unwrap();
    let rex = 0x48 | 0x01; // W + B (park in r8-r15)
    let modrm = 0xC0 | (xmm << 3) | park;
    vec![0x66, rex, 0x0F, 0x7E, modrm]
}

/// Emit `mov park, src` for a GPR or XMM source register.
fn park(src: Register, park: u8) -> Vec<u8> {
    if src.xmm_index().is_some() {
        park_from_xmm(src, park)
    } else {
        park_from_gpr(src, park)
    }
}

/// Emit `mov rax, imm64` (10 bytes).
fn mov_rax_imm64(value: u64) -> Vec<u8> {
    let mut out = vec![0x48, 0xB8];
    out.extend_from_slice(&value.to_le_bytes());
    out
}

/// Emit `mov r10, imm64` (10 bytes).
fn mov_r10_imm64(value: u64) -> Vec<u8> {
    let mut out = vec![0x49, 0xBA];
    out.extend_from_slice(&value.to_le_bytes());
    out
}

/// Park both the capture (into r11) and the gate (into r13) registers from
/// their original source registers before any scratch register is clobbered.
/// Handles the pathological case where the capture source is r13 and the gate
/// source is r11 (they would overwrite each other) by routing through r9.
fn park_capture_and_gate(capture: Register, gate: Option<Register>) -> Vec<u8> {
    let mut b = Vec::new();
    match gate {
        None => b.extend(park(capture, PARK_CAPTURE)),
        Some(g) => {
            if capture == Register::R13 && g == Register::R11 {
                // True swap conflict: stage capture in r9, then gate, then capture.
                b.extend(park(Register::R13, 1)); // mov r9, r13 (capture source)
                b.extend(park(Register::R11, PARK_GATE)); // mov r13, r11 (gate)
                b.extend(park(Register::R9, PARK_CAPTURE)); // mov r11, r9 (capture)
            } else if g == Register::R11 {
                // Gate source is the capture park register; fill gate park first.
                b.extend(park(Register::R11, PARK_GATE)); // mov r13, r11
                b.extend(park(capture, PARK_CAPTURE)); // mov r11, capture
            } else if capture == Register::R13 {
                // Capture source is the gate park register; fill capture park first.
                b.extend(park(Register::R13, PARK_CAPTURE)); // mov r11, r13
                b.extend(park(g, PARK_GATE)); // mov r13, gate
            } else {
                b.extend(park(capture, PARK_CAPTURE));
                b.extend(park(g, PARK_GATE));
            }
        }
    }
    b
}

/// Emit `cmp r13, [r10+24]` (integer compare of the gate register against the
/// stored const_a constant). For signed (I64) the flags are signed; for
/// unsigned (Ptr/U64) they are unsigned.
fn cmp_gate_const_a() -> Vec<u8> {
    // 4D 3B 6A 18 : REX.W|R|B, cmp r13, [r10+24]
    vec![0x4D, 0x3B, 0x6A, 0x18]
}

/// Emit `cmp r13, [r10+32]` (range max constant).
fn cmp_gate_const_b() -> Vec<u8> {
    vec![0x4D, 0x3B, 0x6A, 0x20]
}

/// Emit `mov [r10+40], r13` — store the gate register raw bits into the
/// header's gate-scratch slot so the float gate checks can read them as memory.
fn store_gate_scratch() -> Vec<u8> {
    vec![0x4D, 0x89, 0x6A, 0x28]
}

/// Emit `cmp dword [r10+12], 1` — test the ring's disarmed flag.
fn cmp_disarmed() -> Vec<u8> {
    vec![0x41, 0x83, 0x7A, 0x0C, 0x01]
}

/// Emit `mov dword [r10+12], 1` — set the disarmed flag after a one_shot /
/// stop_on_match capture.
fn set_disarmed() -> Vec<u8> {
    vec![0x41, 0xC7, 0x42, 0x0C, 0x01, 0x00, 0x00, 0x00]
}

/// A gate check: the bytes that set condition flags (prefix), plus the single
/// byte opcode of the conditional jump to take on FAILURE (which the caller
/// emits immediately after the prefix, followed by a rel8 placeholder).
struct GateCheck {
    prefix: Vec<u8>,
    fail_jcc: u8,
}

/// Emit the x87 float comparison that sets flags for `gate (st0) vs a memory
/// f64/f32 at `src_disp` and pops the compare operands. Load width depends on
/// `value_type` (f64 qword vs f32 dword).
fn float_cmp_prefix(src_disp: u32, value_type: ValueType) -> Vec<u8> {
    let mut b = Vec::new();
    let is_f32 = value_type == ValueType::F32;
    // fld const/mem, then fld gate_scratch, fucomip, fstp.
    if is_f32 {
        b.extend_from_slice(&[0x41, 0xD9, 0x42, src_disp as u8]); // fld dword [r10+disp]
    } else {
        b.extend_from_slice(&[0x41, 0xDD, 0x42, src_disp as u8]); // fld qword [r10+disp]
    }
    if is_f32 {
        b.extend_from_slice(&[0x41, 0xD9, 0x42, RING_GATE_SCRATCH_OFF as u8]); // fld dword [r10+40]
    } else {
        b.extend_from_slice(&[0x41, 0xDD, 0x42, RING_GATE_SCRATCH_OFF as u8]); // fld qword [r10+40]
    }
    b.extend_from_slice(&[0xDF, 0xE9]); // fucomip st, st(1)
    b.extend_from_slice(&[0xDD, 0xD8]); // fstp st(0)
    b
}

/// The integer value types that compare using raw 64-bit GPR semantics.
fn is_int_value_type(vt: ValueType) -> bool {
    matches!(vt, ValueType::Ptr | ValueType::I64 | ValueType::U64)
}

/// Emit the gate check(s) for a single-constant relational comparison, decoding
/// the gate register per `value_type` (float via x87, integer via GPR).
fn emit_gate_check(gate: &Gate, value_type: ValueType) -> Vec<GateCheck> {
    let float = !is_int_value_type(value_type);
    let unsigned = matches!(value_type, ValueType::Ptr | ValueType::U64);
    // The unsigned jump opcodes used on FAILURE for a given comparison.
    let fail_op = |cmp: GateCmp, signed: bool| -> u8 {
        use GateCmp::*;
        match cmp {
            Eq => 0x75,             // jne (ZF=0)
            Ne => 0x74,             // je (ZF=1)
            Gt => {
                if signed { 0x7E } else { 0x76 } // jle / jbe
            }
            Lt => {
                if signed { 0x7D } else { 0x73 } // jge / jae
            }
            Ge => {
                if signed { 0x7C } else { 0x72 } // jl / jb
            }
            Le => {
                if signed { 0x7F } else { 0x77 } // jg / ja
            }
            Range | Whole => 0x75,
        }
    };
    let mut checks = Vec::new();
    match gate.cmp {
        GateCmp::Whole => {
            // Whole only has meaning for floats. For integers it is always true
            // (emit no check -> unconditional capture).
            if float {
                // fld gate; frndint; fld gate; fucomip; fstp; fail if !=.
                let mut prefix = Vec::new();
                if value_type == ValueType::F32 {
                    prefix.extend_from_slice(&[0x41, 0xD9, 0x42, RING_GATE_SCRATCH_OFF as u8]);
                } else {
                    prefix.extend_from_slice(&[0x41, 0xDD, 0x42, RING_GATE_SCRATCH_OFF as u8]);
                }
                prefix.extend_from_slice(&[0xD9, 0xFC]); // frndint
                if value_type == ValueType::F32 {
                    prefix.extend_from_slice(&[0x41, 0xD9, 0x42, RING_GATE_SCRATCH_OFF as u8]);
                } else {
                    prefix.extend_from_slice(&[0x41, 0xDD, 0x42, RING_GATE_SCRATCH_OFF as u8]);
                }
                prefix.extend_from_slice(&[0xDF, 0xE9]); // fucomip
                prefix.extend_from_slice(&[0xDD, 0xD8]); // fstp st0
                checks.push(GateCheck { prefix, fail_jcc: 0x75 }); // jne on not-whole
            }
        }
        GateCmp::Range => {
            // Two bounds: [min, max].
            if float {
                // min <= gate (fail if gate < min -> jc after comparing gate,min)
                checks.push(GateCheck {
                    prefix: float_cmp_prefix(RING_CONST_A_OFF as u32, value_type),
                    fail_jcc: 0x72, // jc (gate < min or unordered)
                });
                // gate <= max (fail if gate > max -> ja after comparing gate,max)
                checks.push(GateCheck {
                    prefix: float_cmp_prefix(RING_CONST_B_OFF as u32, value_type),
                    fail_jcc: 0x77, // ja (gate > max)
                });
            } else {
                checks.push(GateCheck {
                    prefix: cmp_gate_const_a(),
                    fail_jcc: if unsigned { 0x72 } else { 0x7C }, // jb / jl
                });
                checks.push(GateCheck {
                    prefix: cmp_gate_const_b(),
                    fail_jcc: if unsigned { 0x77 } else { 0x7F }, // ja / jg
                });
            }
        }
        cmp => {
            if float {
                // For `eq`, `fucomip` sets ZF=1 for *unordered* operands (NaN),
                // so a plain `jne` would treat NaN as "equal" and pass — the
                // "gate records everything / gate_value=NaN" bug (Lua empty
                // slots are NaN). We must also reject unordered via `jp`
                // (parity=1) so NaN never passes an equality gate.
                if cmp == GateCmp::Eq {
                    checks.push(GateCheck {
                        prefix: float_cmp_prefix(RING_CONST_A_OFF as u32, value_type),
                        fail_jcc: 0x7A, // jp: fail if unordered (NaN)
                    });
                }
                checks.push(GateCheck {
                    prefix: float_cmp_prefix(RING_CONST_A_OFF as u32, value_type),
                    fail_jcc: fail_op(cmp, false),
                });
            } else {
                checks.push(GateCheck {
                    prefix: cmp_gate_const_a(),
                    fail_jcc: fail_op(cmp, !unsigned),
                });
            }
        }
    }
    checks
}

/// Emit the non-stalling capture payload body (excluding the volatile save /
/// restore prologue/epilogue, which the caller wraps). Assumes all volatile
/// regs are already saved on the stack and free to clobber.
///
/// `ring_base` is the DLL-allocated ring address. `site` is the code address
/// being patched (recorded into each entry's `rip` field). `reg` is the
/// register to record. `gate` optionally gates when the capture fires.
/// `disarm` makes the payload record once and set the disarmed flag (one_shot
/// or stop_on_match).
fn capture_body(
    ring_base: u64,
    site: u64,
    reg: Register,
    gate: Option<&Gate>,
    value_type: ValueType,
    disarm: bool,
) -> Vec<u8> {
    // The gate compares its own register using its OWN value type (defaulting
    // to the capture type for backward compatibility when a gate type wasn't
    // explicitly provided).
    let gate_type = gate.map(|g| g.value_type).unwrap_or(value_type);
    let mut b = Vec::new();
    let mut jump_positions: Vec<usize> = Vec::new();

    // 1. r10 = ring_base (a clobbered reg we use as the header base).
    b.extend(mov_r10_imm64(ring_base));

    // 2. If disarming, a top-of-body check: if the flag is already set (we
    //    already captured the one entry we wanted), skip straight to restore.
    if disarm {
        b.extend(cmp_disarmed()); // cmp dword [r10+12], 1
        jump_positions.push(b.len());
        b.extend_from_slice(&[0x74, 0x00]); // je SKIP_RECORD (placeholder)
    }

    // 3. Park the gate register into r13 and the capture register into r11 from
    //    their original source registers before anything else is clobbered.
    b.extend(park_capture_and_gate(reg, gate.map(|g| g.reg)));

    // 4. If gated, store the gate value and emit the checks; a failed check
    //    jumps past the record block (SKIP_RECORD). The gate compares its
    //    register using the gate's own value_type.
    if let Some(g) = gate {
        b.extend(store_gate_scratch()); // mov [r10+40], r13
        for check in emit_gate_check(g, gate_type) {
            b.extend(check.prefix);
            jump_positions.push(b.len());
            b.extend_from_slice(&[check.fail_jcc, 0x00]); // jcc SKIP_RECORD
        }
    }

    // 5. RECORD block: append an entry to the ring.
    let rec_start = b.len();
    // ecx = write_byte_offset, edx = total_bytes
    b.extend_from_slice(&[0x41, 0x8B, 0x0A]); // mov ecx, [r10]
    b.extend_from_slice(&[0x41, 0x8B, 0x52, 0x08]); // mov edx, [r10+8]
    // single-wrap: if offset >= total, offset -= total
    b.extend_from_slice(&[0x39, 0xD1]); // cmp ecx, edx
    b.extend_from_slice(&[0x7C, 0x02]); // jl +2 (skip)
    b.extend_from_slice(&[0x29, 0xD1]); // sub ecx, edx
    // r8 = entries_base = r10 + RING_HEADER ; r8 += ecx
    b.extend_from_slice(&[0x4D, 0x8D, 0x42, RING_HEADER as u8]); // lea r8, [r10+RING_HEADER]
    b.extend_from_slice(&[0x49, 0x01, 0xC8]); // add r8, rcx
    // bump seq and store it at entry+0
    b.extend_from_slice(&[0x49, 0xFF, 0x42, 0x10]); // inc qword [r10+16]
    b.extend_from_slice(&[0x4D, 0x8B, 0x4A, 0x10]); // mov r9, [r10+16]
    b.extend_from_slice(&[0x4D, 0x89, 0x08]); // mov [r8], r9
    // store the parked capture value (r11) at entry+ENTRY_RAW_OFF
    b.extend_from_slice(&[0x4D, 0x89, 0x58, ENTRY_RAW_OFF as u8]); // mov [r8+8], r11
    // store site (rip) at entry+ENTRY_RIP_OFF
    b.extend(mov_rax_imm64(site));
    b.extend_from_slice(&[0x49, 0x89, 0x40, ENTRY_RIP_OFF as u8]); // mov [r8+16], rax
    // store the gate value (r13) at entry+ENTRY_GATE_OFF
    b.extend_from_slice(&[0x4D, 0x89, 0x68, ENTRY_GATE_OFF as u8]); // mov [r8+24], r13
    // advance write offset by ENTRY_STRIDE
    b.extend_from_slice(&[0x81, 0xC1, ENTRY_STRIDE as u8, 0x00, 0x00, 0x00]); // add ecx, 32
    b.extend_from_slice(&[0x41, 0x89, 0x0A]); // mov [r10], ecx
    // if disarming, set the disarmed flag now that we recorded our one entry.
    if disarm {
        b.extend(set_disarmed()); // mov dword [r10+12], 1
    }
    let rec_end = b.len();
    let _ = rec_start;

    // 6. Patch every conditional jump that targets SKIP_RECORD (right after the
    //    record block) with its rel8 offset.
    for pos in jump_positions {
        let rel = rec_end as i64 - (pos as i64 + 2);
        let rel = rel.clamp(-128, 127) as u8;
        b[pos + 1] = rel;
    }

    b
}

/// Emit the full non-stalling capture payload: save the clobbered regs, run the
/// gate (if any) and record the chosen register when it passes, restore the
/// clobbered regs. This runs at the top of the cave, *before* the relocated
/// stolen instructions, so the game behavior is fully preserved (the capture is
/// read-only) and every register the game depends on (including the captured
/// one) is intact afterward.
///
/// `disarm` makes the payload capture at most once and then set the ring's
/// disarmed flag (used for `one_shot` and `stop_on_match`).
pub fn emit_capture_payload(
    ring_base: u64,
    site: u64,
    reg: Register,
    gate: Option<&Gate>,
    value_type: ValueType,
    disarm: bool,
) -> Vec<u8> {
    let mut out = push_clobbered();
    out.extend(capture_body(ring_base, site, reg, gate, value_type, disarm));
    out.extend(pop_clobbered());
    out
}

/// Compute the raw 64-bit header constant for a numeric gate value per the
/// value type (for storing into the ring header's const_a/const_b slots).
pub fn encode_gate_const(value: f64, value_type: ValueType) -> u64 {
    match value_type {
        ValueType::F64 => value.to_bits(),
        ValueType::F32 => (value as f32).to_bits() as u64,
        ValueType::Ptr | ValueType::U64 => value as u64,
        ValueType::I64 => value as i64 as u64,
    }
}

/// Decode a raw 64-bit register value (from an entry's raw or gate field) per a
/// value type, returning it as an f64 for the wire protocol.
pub fn decode_raw(raw: u64, value_type: ValueType) -> f64 {
    match value_type {
        ValueType::Ptr => raw as f64,
        ValueType::I64 => raw as i64 as f64,
        ValueType::U64 => raw as f64,
        ValueType::F64 => f64::from_bits(raw),
        ValueType::F32 => f32::from_bits((raw & 0xFFFF_FFFF) as u32) as f64,
    }
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
        let p = emit_capture_payload(0x5000, 0x1401b42e9, Register::Rcx, None, ValueType::U64, true);
        // Must begin with push r13 (41 55) and end with pop r13 (41 5D).
        assert_eq!(&p[0..2], &[0x41, 0x55], "starts by pushing volatile regs");
        assert_eq!(&p[p.len() - 2..], &[0x41, 0x5D], "ends by popping volatile regs");
        // Contains the ring base immediate.
        assert!(
            p.windows(8).any(|w| w == 0x5000u64.to_le_bytes()),
            "payload embeds ring base"
        );
    }

    #[test]
    fn xmm_payload_uses_movq() {
        let p = emit_capture_payload(0x9000, 0x1234, Register::Xmm2, None, ValueType::F64, false);
        // movq r11, xmm2 = 66 49 0F 7E D3 (REX.W|B for r11)
        assert!(
            p.windows(5).any(|w| w == [0x66, 0x49, 0x0F, 0x7E, 0xD3]),
            "xmm payload records via movq into r11"
        );
    }

    #[test]
    fn ring_size_matches_layout() {
        // capacity 32 => header(RING_HEADER) + 32*ENTRY_STRIDE
        assert_eq!(ring_size(32), RING_HEADER + 32 * ENTRY_STRIDE);
        assert_eq!(ring_size(1), RING_HEADER + ENTRY_STRIDE);
    }

    #[test]
    fn gate_cmp_parse_roundtrip() {
        assert_eq!(GateCmp::parse("eq"), Some(GateCmp::Eq));
        assert_eq!(GateCmp::parse("range"), Some(GateCmp::Range));
        assert_eq!(GateCmp::parse("whole"), Some(GateCmp::Whole));
        assert_eq!(GateCmp::parse(">="), Some(GateCmp::Ge));
        assert_eq!(GateCmp::parse("bogus"), None);
        assert_eq!(GateCmp::Range.name(), "range");
    }

    #[test]
    fn encode_gate_const_roundtrips() {
        assert_eq!(encode_gate_const(3.5, ValueType::F64), 3.5f64.to_bits());
        assert_eq!(encode_gate_const(3.5, ValueType::F32), (3.5f32).to_bits() as u64);
        assert_eq!(encode_gate_const(42.0, ValueType::U64), 42);
        assert_eq!(encode_gate_const(-5.0, ValueType::I64), (-5i64) as u64);
        assert_eq!(encode_gate_const(0x7777u64 as f64, ValueType::Ptr), 0x7777);
    }
}
