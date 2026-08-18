//! Non-stalling register capture installation.
//!
//! Builds on [`crate::cave::install`] to place a *passive* capture trampoline
//! at a code site: it allocates a DLL-owned ring buffer, emits the capture
//! payload (which records the chosen register each time the site executes),
//! installs a transparent trampoline so the game keeps working, and returns a
//! handle carrying the original bytes + ring address for read-back and
//! uninstall.

use trainlab_core::capture::{
    self, encode_gate_const, CaptureRegSpec, GateCmp, Register, ValueType, ENTRY_STRIDE,
    RING_CONST_A_OFF, RING_CONST_B_OFF,
};
use trainlab_core::protocol::{CaptureEntry, Response};

use crate::cave::{self, HookKind};

/// A live register capture installed into the target process.
pub struct InstalledCapture {
    /// Identifies this capture for read-back / uninstall.
    pub id: u64,
    /// Address of the DLL-allocated ring buffer (readable via `read`).
    pub scratch: u64,
    /// The patched call site (first overwritten byte).
    pub target: u64,
    /// Original bytes overwritten at `target` (for restore).
    pub original: Vec<u8>,
    /// The number of entries the ring can hold.
    pub capacity: usize,
    /// The register being captured.
    pub reg: Register,
    /// The value type used to decode captured entries.
    pub value_type: ValueType,
    /// Whether the payload is gated.
    pub has_gate: bool,
    /// The gate's own value type (defaults to `value_type` when ungated);
    /// used to decode the per-entry `gate_value` on read-back.
    pub gate_value_type: ValueType,
}

/// Install a passive register capture at `target`.
///
/// `read`/`write`/`allocate` are the injected DLL's in-process closures.
/// Allocates a scratch ring (size [`capture::ring_size`]) for the recorded
/// values and an executable cave for the trampoline. Returns the installed
/// capture handle.
///
/// `disarm` makes the payload capture at most once and then set the ring's
/// disarmed flag (used for `one_shot` and `stop_on_match`).
pub fn install_capture<R, W, A>(
    target: u64,
    spec: CaptureRegSpec,
    capacity: usize,
    disarm: bool,
    read: R,
    write: W,
    allocate: A,
) -> Result<InstalledCapture, String>
where
    R: Fn(u64, usize) -> Result<Vec<u8>, String>,
    W: Fn(u64, &[u8]) -> Result<usize, String>,
    A: Fn(usize, bool) -> Result<u64, String>,
{
    // Allocate the data ring first (non-executable), then emit the capture
    // payload referencing it. The ring must exist before the payload runs.
    let ring_base = allocate(capture::ring_size(capacity), false)
        .map_err(|e| format!("allocate ring: {e}"))?;

    // Initialize the ring header (offset 0, total, seq 0, disarmed 0) and the
    // gate constants, before any capture can fire. The entries region stays
    // zeroed (seq 0 = empty sentinel).
    let total = (capacity * ENTRY_STRIDE) as u32;
    let mut header = vec![0u8; 48];
    header[0..4].copy_from_slice(&0u32.to_le_bytes()); // write offset = 0
    header[8..12].copy_from_slice(&total.to_le_bytes()); // total bytes
    // const_a / const_b from the gate (if any), so the payload compares against
    // them as memory without needing more immediates.
    //
    // IMPORTANT: (1) for a Range gate the lower bound lives in `g.min`, NOT
    // `g.value` (which defaults to 0 for Range) — using `g.value` would silently
    // hardcode the lower bound to 0, so `min=1` would still accept 0. (2) The
    // constants are encoded per the GATE's own value_type, not the capture's,
    // so a Lua double gate compares its raw double bits correctly.
    if let Some(g) = spec.gate {
        let gt = g.value_type;
        let (a, b) = match g.cmp {
            GateCmp::Range => (encode_gate_const(g.min, gt), encode_gate_const(g.max, gt)),
            _ => (encode_gate_const(g.value, gt), 0),
        };
        header[RING_CONST_A_OFF..RING_CONST_A_OFF + 8].copy_from_slice(&a.to_le_bytes());
        header[RING_CONST_B_OFF..RING_CONST_B_OFF + 8].copy_from_slice(&b.to_le_bytes());
    }
    write(ring_base, &header).map_err(|e| format!("init ring header: {e}"))?;

    // Emit the passive capture payload: save volatile regs, run the gate (if
    // any) and record the chosen register when it passes, restore volatile
    // regs. Runs before the relocated stolen instructions, so the game never
    // stalls and behavior is preserved.
    let payload = capture::emit_capture_payload(
        ring_base,
        target,
        spec.reg,
        spec.gate.as_ref(),
        spec.value_type,
        disarm,
    );

    // Install a transparent trampoline with this payload in an executable cave.
    let kind = HookKind::Trampoline { payload };
    let hook = cave::install(target, kind, read, write, allocate)?;

    Ok(InstalledCapture {
        id: 0,
        scratch: ring_base,
        target: hook.target,
        original: hook.original,
        capacity,
        reg: spec.reg,
        value_type: spec.value_type,
        has_gate: spec.gate.is_some(),
        gate_value_type: spec.gate.map(|g| g.value_type).unwrap_or(spec.value_type),
    })
}

/// Read back the entries currently in the capture ring, oldest first.
///
/// The ring is single-wrapped: a running write offset and total byte count
/// live in the header, and entries are `ENTRY_STRIDE` bytes each. We read the
/// whole ring (header + entries region) once and decode the entries that have
/// been written (those with a non-zero `seq`).
pub fn read_captures<R>(
    scratch: u64,
    capacity: usize,
    value_type: ValueType,
    gate_value_type: ValueType,
    read: R,
) -> Result<Vec<CaptureEntry>, String>
where
    R: Fn(u64, usize) -> Result<Vec<u8>, String>,
{
    let total_bytes = capture::ring_size(capacity);
    let buf = read(scratch, total_bytes).map_err(|e| format!("read ring: {e}"))?;
    if buf.len() < capture::RING_HEADER {
        return Err("ring too small".into());
    }

    let offset = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
    let ring_total = capacity * ENTRY_STRIDE;
    // Clamp offset into the entries region in case of a torn write.
    let offset = offset.min(ring_total);

    let mut entries = Vec::new();
    let entries_base = capture::RING_HEADER;
    // Walk from the oldest entry (just after the write offset) to the newest,
    // i.e. we read them in ring order starting at `offset` (oldest) wrapping to
    // offset (newest). But since offset is where the NEXT write goes, the
    // oldest is at `offset`, and the newest is just before `offset`. We want
    // oldest-first output, so iterate ring order starting at `offset`.
    for k in 0..capacity {
        let slot = (offset + k * ENTRY_STRIDE) % ring_total;
        let e = entries_base + slot;
        if e + ENTRY_STRIDE > buf.len() {
            break;
        }
        let seq = u64::from_le_bytes(buf[e..e + 8].try_into().unwrap());
        let raw = u64::from_le_bytes(buf[e + 8..e + 16].try_into().unwrap());
        let rip = u64::from_le_bytes(buf[e + 16..e + 24].try_into().unwrap());
        let gate = u64::from_le_bytes(buf[e + 24..e + 32].try_into().unwrap());
        // Skip unwritten slots (seq 0).
        if seq == 0 {
            continue;
        }
        let reg_value = decode(raw, value_type);
        let gate_value = decode(gate, gate_value_type);
        entries.push(CaptureEntry {
            seq,
            reg_value,
            raw,
            rip,
            gate_value,
            captured_at: rip, // rip doubles as the captured site address
        });
    }
    // Sort by seq ascending so the caller sees oldest-first regardless of ring
    // wrap position.
    entries.sort_by_key(|e| e.seq);
    Ok(entries)
}

/// Decode a raw 64-bit register value per a value type.
pub fn decode(raw: u64, value_type: ValueType) -> f64 {
    match value_type {
        ValueType::Ptr => raw as f64,
        ValueType::I64 => raw as i64 as f64,
        ValueType::U64 => raw as f64,
        ValueType::F64 => f64::from_bits(raw),
        ValueType::F32 => f32::from_bits((raw & 0xFFFF_FFFF) as u32) as f64,
    }
}

/// Read the ring's `disarmed` flag (1 = one_shot / stop_on_match fired).
pub fn read_disarmed<R>(scratch: u64, read: R) -> Result<bool, String>
where
    R: Fn(u64, usize) -> Result<Vec<u8>, String>,
{
    let buf = read(scratch + trainlab_core::capture::RING_DISARMED_OFF as u64, 4)
        .map_err(|e| format!("read disarm flag: {e}"))?;
    let v = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    Ok(v != 0)
}

/// A convenience to convert a decoded capture to a protocol `Response`,
/// including the ring's disarmed flag.
pub fn read_captures_response<R>(
    scratch: u64,
    capacity: usize,
    value_type: ValueType,
    gate_value_type: ValueType,
    read: R,
) -> Result<Response, String>
where
    R: Fn(u64, usize) -> Result<Vec<u8>, String>,
{
    let disarmed = read_disarmed(scratch, &read)?;
    let entries = read_captures(scratch, capacity, value_type, gate_value_type, read)?;
    Ok(Response::ReadCaptures { entries, disarmed })
}

/// Restore the original bytes at a capture's patched site.
pub fn restore_capture<W>(target: u64, original: &[u8], write: W) -> Result<(), String>
where
    W: Fn(u64, &[u8]) -> Result<usize, String>,
{
    cave::restore(target, original, write)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    #[test]
    fn decode_all_value_types() {
        // ptr / u64
        assert_eq!(decode(0x12345678, ValueType::Ptr), 0x12345678u64 as f64);
        // i64 negative
        assert_eq!(decode((-5i64) as u64, ValueType::I64), -5.0);
        // f64
        assert_eq!(decode(1.5f64.to_bits(), ValueType::F64), 1.5);
        // f32 (low 32 bits)
        assert_eq!(decode(3.25f32.to_bits() as u64, ValueType::F32), 3.25);
    }

    #[test]
    fn read_captures_roundtrip_via_fake_ring() {
        // Build a fake ring in a byte arena and check read_captures decodes it.
        // ring layout: header(24) + capacity*24 entries.
        let capacity = 2usize;
        let ring_total = capture::ring_size(capacity);
        let arena: RefCell<Vec<u8>> = RefCell::new(vec![0u8; ring_total + 16]);
        {
            let mut m = arena.borrow_mut();
            // write offset = 0 (we'll write two entries then leave offset at 2*24)
            m[8..12].copy_from_slice(&((capacity * ENTRY_STRIDE) as u32).to_le_bytes());
            // entry 0: seq=1, raw=0x111, rip=0x4000, gate=0x999
            let e0 = capture::RING_HEADER;
            m[e0..e0 + 8].copy_from_slice(&1u64.to_le_bytes());
            m[e0 + 8..e0 + 16].copy_from_slice(&0x111u64.to_le_bytes());
            m[e0 + 16..e0 + 24].copy_from_slice(&0x4000u64.to_le_bytes());
            m[e0 + 24..e0 + 32].copy_from_slice(&0x999u64.to_le_bytes());
            // entry 1: seq=2, raw=0x222, rip=0x4000, gate=0x998
            let e1 = e0 + ENTRY_STRIDE;
            m[e1..e1 + 8].copy_from_slice(&2u64.to_le_bytes());
            m[e1 + 8..e1 + 16].copy_from_slice(&0x222u64.to_le_bytes());
            m[e1 + 16..e1 + 24].copy_from_slice(&0x4000u64.to_le_bytes());
            m[e1 + 24..e1 + 32].copy_from_slice(&0x998u64.to_le_bytes());
            // advance write offset to after 2 entries
            m[0..4].copy_from_slice(&((2 * ENTRY_STRIDE) as u32).to_le_bytes());
        }
        let read = |addr: u64, len: usize| -> Result<Vec<u8>, String> {
            let m = arena.borrow();
            let s = addr as usize;
            let e = s + len;
            if e > m.len() {
                return Err("OOB".into());
            }
            Ok(m[s..e].to_vec())
        };
        let entries = read_captures(0, capacity, ValueType::U64, ValueType::U64, read).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].seq, 1);
        assert_eq!(entries[0].raw, 0x111);
        assert_eq!(entries[0].rip, 0x4000);
        assert_eq!(entries[0].gate_value, 0x999u64 as f64);
        assert_eq!(entries[1].seq, 2);
        assert_eq!(entries[1].raw, 0x222);
        assert_eq!(entries[1].gate_value, 0x998u64 as f64);
    }

    #[test]
    fn read_captures_skips_unwritten_slots() {
        let capacity = 4usize;
        let ring_total = capture::ring_size(capacity);
        let arena: RefCell<Vec<u8>> = RefCell::new(vec![0u8; ring_total]);
        {
            let mut m = arena.borrow_mut();
            m[8..12].copy_from_slice(&((capacity * ENTRY_STRIDE) as u32).to_le_bytes());
            // Only entry 1 written.
            let e = capture::RING_HEADER + ENTRY_STRIDE;
            m[e..e + 8].copy_from_slice(&1u64.to_le_bytes());
            m[e + 8..e + 16].copy_from_slice(&0xABCDu64.to_le_bytes());
            m[0..4].copy_from_slice(&(ENTRY_STRIDE as u32).to_le_bytes());
        }
        let read = |addr: u64, len: usize| -> Result<Vec<u8>, String> {
            let m = arena.borrow();
            let s = addr as usize;
            let e = s + len;
            if e > m.len() {
                return Err("OOB".into());
            }
            Ok(m[s..e].to_vec())
        };
        let entries = read_captures(0, capacity, ValueType::U64, ValueType::U64, read).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].raw, 0xABCD);
    }

    #[test]
    fn install_capture_places_payload_and_ring() {
        // A fake arena + allocator that hands out two distinct addresses.
        let arena: RefCell<Vec<u8>> = RefCell::new(vec![0u8; 0x100000]);
        let allocs: RefCell<Vec<u64>> = RefCell::new(vec![0x8000, 0x9000]); // ring, then cave
        let alloc_i: RefCell<usize> = RefCell::new(0);
        let read = |addr: u64, len: usize| -> Result<Vec<u8>, String> {
            let m = arena.borrow();
            let s = addr as usize;
            let e = s + len;
            if e > m.len() {
                return Err("OOB".into());
            }
            Ok(m[s..e].to_vec())
        };
        let write = |addr: u64, data: &[u8]| -> Result<usize, String> {
            let mut m = arena.borrow_mut();
            let s = addr as usize;
            let e = s + data.len();
            if e > m.len() {
                return Err("OOB".into());
            }
            m[s..e].copy_from_slice(data);
            Ok(data.len())
        };
        let allocate = |_size: usize, _exec: bool| -> Result<u64, String> {
            let i = *alloc_i.borrow();
            *alloc_i.borrow_mut() += 1;
            allocs.borrow().get(i).copied().ok_or("no more allocs".into())
        };
        // Seed the target site with instructions: mov eax,1 (5) ; nop (1) ; ret (1)
        let target = 0x4000u64;
        write(target, &[0xB8, 0x01, 0x00, 0x00, 0x00, 0x90, 0xC3]).unwrap();
        let spec = CaptureRegSpec::new(Register::Rcx, ValueType::U64);
        let cap = install_capture(target, spec, 2, true, read, write, allocate).unwrap();
        assert_eq!(cap.scratch, 0x8000);
        assert_eq!(cap.target, 0x4000);
        assert!(!cap.original.is_empty());
        // Ring header initialized: total = 2*ENTRY_STRIDE.
        let hdr = read(0x8000, 16).unwrap();
        assert_eq!(
            u32::from_le_bytes(hdr[8..12].try_into().unwrap()),
            (2 * ENTRY_STRIDE) as u32
        );
        // Cave (0x9000) begins with the payload: push r13 (41 55).
        let cave_start = read(0x9000, 8).unwrap();
        assert_eq!(&cave_start[0..2], &[0x41, 0x55]);
    }

    // Keep the import used (decode/value-type helpers referenced above).
    #[allow(dead_code)]
    fn _touch(_: HashMap<u64, u64>) {}

    /// Execute the actual emitted payload against a real mmap'd ring to prove
    /// the hand-assembled x86-64 is correct (it must capture the register and
    /// leave the game state intact). This is the "driver test" that validates
    /// the non-stalling capture end-to-end.
    #[test]
    fn payload_executes_and_captures_rcx() {
        use std::arch::asm;
        use trainlab_core::capture::Register;

        let ring_size = capture::ring_size(4);
        let ring = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                ring_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert!(ring != libc::MAP_FAILED, "mmap ring");
        // Init ring header.
        unsafe {
            std::ptr::write_bytes(ring as *mut u8, 0, ring_size);
            let total = (4 * ENTRY_STRIDE) as u32;
            std::ptr::write_unaligned((ring as *mut u8).add(8) as *mut u32, total);
        }

        let payload = capture::emit_capture_payload(
            ring as u64,
            0x1401b42e9,
            Register::Rcx,
            None,
            ValueType::U64,
            true,
        );
        let cave_size = payload.len() + 64;
        let cave = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                cave_size,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert!(cave != libc::MAP_FAILED, "mmap cave");
        unsafe {
            std::ptr::copy_nonoverlapping(payload.as_ptr(), cave as *mut u8, payload.len());
            // A `ret` after the payload so a stray fallthrough doesn't run off.
            std::ptr::write((cave as *mut u8).add(payload.len()), 0xC3);
        }

        // Execute the payload with a distinctive RCX; verify the ring captured it.
        let f: extern "C" fn() = unsafe { std::mem::transmute(cave) };
        unsafe {
            asm!(
                "mov rcx, {val}",
                "mov rax, 0x111",
                "mov rdx, 0x222",
                "mov r13, {f}",
                "call r13",
                val = in(reg) 0x7777_7777_7777u64,
                f = in(reg) f as usize,
                out("rax") _, out("rcx") _, out("rdx") _, out("r8") _, out("r9") _,
                out("r10") _, out("r11") _, out("r13") _,
            );
        }

        // Read the ring back.
        let read = |addr: u64, len: usize| -> Result<Vec<u8>, String> {
            let mut out = vec![0u8; len];
            unsafe {
                std::ptr::copy_nonoverlapping(addr as *const u8, out.as_mut_ptr(), len);
            }
            Ok(out)
        };
        let entries = read_captures(ring as u64, 4, ValueType::U64, ValueType::U64, read).unwrap();
        assert_eq!(entries.len(), 1, "expected exactly 1 captured entry");
        assert_eq!(
            entries[0].raw, 0x7777_7777_7777u64,
            "RCX captured wrong: 0x{:x}",
            entries[0].raw
        );
        assert_eq!(entries[0].rip, 0x1401b42e9, "rip mismatch");
        unsafe {
            libc::munmap(ring, ring_size);
            libc::munmap(cave, cave_size);
        }
    }

    /// Execute the payload capturing an XMM register to verify movq encoding.
    #[test]
    fn payload_executes_and_captures_xmm() {
        use std::arch::asm;
        use trainlab_core::capture::Register;

        let ring_size = capture::ring_size(4);
        let ring = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                ring_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert!(ring != libc::MAP_FAILED, "mmap ring");
        unsafe {
            std::ptr::write_bytes(ring as *mut u8, 0, ring_size);
            let total = (4 * ENTRY_STRIDE) as u32;
            std::ptr::write_unaligned((ring as *mut u8).add(8) as *mut u32, total);
        }

        let payload = capture::emit_capture_payload(
            ring as u64,
            0x1401b42e9,
            Register::Xmm3,
            None,
            ValueType::F64,
            true,
        );
        let cave_size = payload.len() + 64;
        let cave = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                cave_size,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert!(cave != libc::MAP_FAILED, "mmap cave");
        unsafe {
            std::ptr::copy_nonoverlapping(payload.as_ptr(), cave as *mut u8, payload.len());
            std::ptr::write((cave as *mut u8).add(payload.len()), 0xC3);
        }

        // Load xmm3 = double 3.25, execute, expect raw = 3.25f64.to_bits().
        let val: u64 = 3.25f64.to_bits();
        let f: extern "C" fn() = unsafe { std::mem::transmute(cave) };
        unsafe {
            asm!(
                "mov rax, {val}",
                "movq xmm3, rax",
                "mov r12, {f}",
                "call r12",
                val = in(reg) val,
                f = in(reg) f as usize,
                out("rax") _, out("rcx") _, out("rdx") _, out("r8") _, out("r9") _,
                out("r10") _, out("r11") _, out("r12") _,
            );
        }

        let read = |addr: u64, len: usize| -> Result<Vec<u8>, String> {
            let mut out = vec![0u8; len];
            unsafe {
                std::ptr::copy_nonoverlapping(addr as *const u8, out.as_mut_ptr(), len);
            }
            Ok(out)
        };
        let entries = read_captures(ring as u64, 4, ValueType::F64, ValueType::F64, read).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].reg_value, 3.25, "xmm capture decoded wrong");
        unsafe {
            libc::munmap(ring, ring_size);
            libc::munmap(cave, cave_size);
        }
    }

    /// Execute a gated payload: gate on RBP being a whole number in [0,100000].
    /// First run with RBP = 3.0 (whole, in range) must capture RCX and disarm;
    /// a second run with RBP = 3.5 must NOT capture (already disarmed).
    #[test]
    fn gated_payload_captures_on_match_and_disarms() {
        use std::arch::asm;
        use trainlab_core::capture::{Gate, Register};

        let ring_size = capture::ring_size(4);
        let ring = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                ring_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert!(ring != libc::MAP_FAILED, "mmap ring");
        unsafe {
            std::ptr::write_bytes(ring as *mut u8, 0, ring_size);
            let total = (4 * ENTRY_STRIDE) as u32;
            std::ptr::write_unaligned((ring as *mut u8).add(8) as *mut u32, total);
            // const_a = 0.0 (min), const_b = 100000.0 (max).
            std::ptr::write_unaligned((ring as *mut u8).add(24) as *mut f64, 0.0f64);
            std::ptr::write_unaligned((ring as *mut u8).add(32) as *mut f64, 100000.0f64);
        }

        // Capture rcx, gate on rsi being in [0, 100000] as f64, disarm on match.
        let gate = Gate::range(Register::Rsi, 0.0, 100000.0).with_value_type(ValueType::F64);
        let payload = capture::emit_capture_payload(
            ring as u64,
            0x1401b42e9,
            Register::Rcx,
            Some(&gate),
            ValueType::F64,
            true,
        );
        let cave_size = payload.len() + 64;
        let cave = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                cave_size,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert!(cave != libc::MAP_FAILED, "mmap cave");
        unsafe {
            std::ptr::copy_nonoverlapping(payload.as_ptr(), cave as *mut u8, payload.len());
            std::ptr::write((cave as *mut u8).add(payload.len()), 0xC3);
        }
        let f: extern "C" fn() = unsafe { std::mem::transmute(cave) };

        // Run 1: RBP = 3.0 (whole, in range) => should capture RCX = 0xABCD.
        let v3 = 3.0f64.to_bits();
        unsafe {
            asm!(
                "mov rcx, 0xabcd",
                "mov rsi, {val}",
                "mov r12, {f}",
                "call r12",
                val = in(reg) v3,
                f = in(reg) f as usize,
                out("rax") _, out("rcx") _, out("rdx") _, out("r8") _, out("r9") _,
                out("r10") _, out("r11") _, out("r12") _, out("r13") _, out("rsi") _,
            );
        }
        let read = |addr: u64, len: usize| -> Result<Vec<u8>, String> {
            let mut out = vec![0u8; len];
            unsafe {
                std::ptr::copy_nonoverlapping(addr as *const u8, out.as_mut_ptr(), len);
            }
            Ok(out)
        };
        let (entries, disarmed) = read_with_flag(ring as u64, 4, ValueType::F64, read);
        assert_eq!(entries.len(), 1, "expected 1 capture on matching gate");
        assert_eq!(entries[0].raw, 0xABCD, "captured rcx wrong");
        assert_eq!(entries[0].gate_value, 3.0, "gate value wrong");
        assert!(disarmed, "should disarm after first match");

        // Run 2: RBP = 3.5 (out of range would fail anyway; the point is the
        // disarmed flag now short-circuits before the record block).
        let v35 = 3.5f64.to_bits();
        unsafe {
            asm!(
                "mov rcx, 0x2222",
                "mov rsi, {val}",
                "mov r12, {f}",
                "call r12",
                val = in(reg) v35,
                f = in(reg) f as usize,
                out("rax") _, out("rcx") _, out("rdx") _, out("r8") _, out("r9") _,
                out("r10") _, out("r11") _, out("r12") _, out("r13") _, out("rsi") _,
            );
        }
        let (entries2, _) = read_with_flag(ring as u64, 4, ValueType::F64, read);
        assert_eq!(entries2.len(), 1, "disarmed capture must not record again");

        unsafe {
            libc::munmap(ring, ring_size);
            libc::munmap(cave, cave_size);
        }
    }

    /// Execute a gated payload where the gate FAILS: RBP out of range. Must
    /// record nothing and NOT disarm.
    #[test]
    fn gated_payload_skips_when_gate_fails() {
        use std::arch::asm;
        use trainlab_core::capture::{Gate, Register};

        let ring_size = capture::ring_size(4);
        let ring = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                ring_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert!(ring != libc::MAP_FAILED, "mmap ring");
        unsafe {
            std::ptr::write_bytes(ring as *mut u8, 0, ring_size);
            let total = (4 * ENTRY_STRIDE) as u32;
            std::ptr::write_unaligned((ring as *mut u8).add(8) as *mut u32, total);
            std::ptr::write_unaligned((ring as *mut u8).add(24) as *mut f64, 0.0f64);
            std::ptr::write_unaligned((ring as *mut u8).add(32) as *mut f64, 100000.0f64);
        }

        let gate = Gate::range(Register::Rsi, 0.0, 100000.0).with_value_type(ValueType::F64);
        let payload = capture::emit_capture_payload(
            ring as u64,
            0x1401b42e9,
            Register::Rcx,
            Some(&gate),
            ValueType::F64,
            true,
        );
        let cave_size = payload.len() + 64;
        let cave = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                cave_size,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert!(cave != libc::MAP_FAILED, "mmap cave");
        unsafe {
            std::ptr::copy_nonoverlapping(payload.as_ptr(), cave as *mut u8, payload.len());
            std::ptr::write((cave as *mut u8).add(payload.len()), 0xC3);
        }
        let f: extern "C" fn() = unsafe { std::mem::transmute(cave) };

        // RBP = 999999 (out of range) => no capture, not disarmed.
        let vbig = 999999.0f64.to_bits();
        unsafe {
            asm!(
                "mov rcx, 0x7777",
                "mov rsi, {val}",
                "mov r12, {f}",
                "call r12",
                val = in(reg) vbig,
                f = in(reg) f as usize,
                out("rax") _, out("rcx") _, out("rdx") _, out("r8") _, out("r9") _,
                out("r10") _, out("r11") _, out("r12") _, out("r13") _, out("rsi") _,
            );
        }
        let read = |addr: u64, len: usize| -> Result<Vec<u8>, String> {
            let mut out = vec![0u8; len];
            unsafe {
                std::ptr::copy_nonoverlapping(addr as *const u8, out.as_mut_ptr(), len);
            }
            Ok(out)
        };
        let (entries, disarmed) = read_with_flag(ring as u64, 4, ValueType::F64, read);
        assert_eq!(entries.len(), 0, "gate fail must not capture");
        assert!(!disarmed, "gate fail must not disarm");

        // RBP = 7.0 (in range) => now captures.
        let v7 = 7.0f64.to_bits();
        unsafe {
            asm!(
                "mov rcx, 0x1234",
                "mov rsi, {val}",
                "mov r12, {f}",
                "call r12",
                val = in(reg) v7,
                f = in(reg) f as usize,
                out("rax") _, out("rcx") _, out("rdx") _, out("r8") _, out("r9") _,
                out("r10") _, out("r11") _, out("r12") _, out("r13") _, out("rsi") _,
            );
        }
        let (entries2, disarmed2) = read_with_flag(ring as u64, 4, ValueType::F64, read);
        assert_eq!(entries2.len(), 1, "later in-range store must capture");
        assert_eq!(entries2[0].raw, 0x1234);
        assert!(disarmed2, "should disarm after the match");

        unsafe {
            libc::munmap(ring, ring_size);
            libc::munmap(cave, cave_size);
        }
    }

    /// Execute the `whole` gate (clean whole number, no fractional part):
    /// RSI = 4.0 captures, RSI = 4.5 (fractional) does not.
    #[test]
    fn gated_payload_whole_gate() {
        use std::arch::asm;
        use trainlab_core::capture::{Gate, Register};

        let ring_size = capture::ring_size(4);
        let ring = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                ring_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert!(ring != libc::MAP_FAILED, "mmap ring");
        unsafe {
            std::ptr::write_bytes(ring as *mut u8, 0, ring_size);
            let total = (4 * ENTRY_STRIDE) as u32;
            std::ptr::write_unaligned((ring as *mut u8).add(8) as *mut u32, total);
        }

        let gate = Gate::whole(Register::Rsi);
        let payload = capture::emit_capture_payload(
            ring as u64,
            0x1401b42e9,
            Register::Rcx,
            Some(&gate),
            ValueType::F64,
            true,
        );
        let cave_size = payload.len() + 64;
        let cave = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                cave_size,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert!(cave != libc::MAP_FAILED, "mmap cave");
        unsafe {
            std::ptr::copy_nonoverlapping(payload.as_ptr(), cave as *mut u8, payload.len());
            std::ptr::write((cave as *mut u8).add(payload.len()), 0xC3);
        }
        let f: extern "C" fn() = unsafe { std::mem::transmute(cave) };
        let read = |addr: u64, len: usize| -> Result<Vec<u8>, String> {
            let mut out = vec![0u8; len];
            unsafe {
                std::ptr::copy_nonoverlapping(addr as *const u8, out.as_mut_ptr(), len);
            }
            Ok(out)
        };

        // RSI = 4.5 (fractional) => no capture, not disarmed.
        let v45 = 4.5f64.to_bits();
        unsafe {
            asm!(
                "mov rcx, 0x1111",
                "mov rsi, {val}",
                "mov r12, {f}",
                "call r12",
                val = in(reg) v45,
                f = in(reg) f as usize,
                out("rax") _, out("rcx") _, out("rdx") _, out("r8") _, out("r9") _,
                out("r10") _, out("r11") _, out("r12") _, out("r13") _, out("rsi") _,
            );
        }
        let (entries, disarmed) = read_with_flag(ring as u64, 4, ValueType::F64, read);
        assert_eq!(entries.len(), 0, "fractional gate must not capture");
        assert!(!disarmed, "fractional gate must not disarm");

        // RSI = 4.0 (whole) => captures.
        let v4 = 4.0f64.to_bits();
        unsafe {
            asm!(
                "mov rcx, 0x2222",
                "mov rsi, {val}",
                "mov r12, {f}",
                "call r12",
                val = in(reg) v4,
                f = in(reg) f as usize,
                out("rax") _, out("rcx") _, out("rdx") _, out("r8") _, out("r9") _,
                out("r10") _, out("r11") _, out("r12") _, out("r13") _, out("rsi") _,
            );
        }
        let (entries2, disarmed2) = read_with_flag(ring as u64, 4, ValueType::F64, read);
        assert_eq!(entries2.len(), 1, "whole gate must capture");
        assert_eq!(entries2[0].raw, 0x2222);
        assert!(disarmed2, "should disarm after whole match");

        unsafe {
            libc::munmap(ring, ring_size);
            libc::munmap(cave, cave_size);
        }
    }

    /// Regression test for the "gate does not filter" bug: a range gate with a
    /// non-zero lower bound (min=1) must reject a gate value of 0. Before the
    /// fix, the Range lower bound was written from `g.value` (default 0) instead
    /// of `g.min`, so `[1,100000]` silently became `[0,100000]` and accepted 0.
    #[test]
    fn gated_payload_range_min_rejects_zero() {
        use std::arch::asm;
        use trainlab_core::capture::{Gate, Register};

        let ring_size = capture::ring_size(4);
        let ring = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                ring_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert!(ring != libc::MAP_FAILED, "mmap ring");
        unsafe {
            std::ptr::write_bytes(ring as *mut u8, 0, ring_size);
            let total = (4 * ENTRY_STRIDE) as u32;
            std::ptr::write_unaligned((ring as *mut u8).add(8) as *mut u32, total);
            // min = 1.0, max = 100000.0 (the bug wrote 0.0 here for the lower
            // bound via g.value; the fix writes g.min = 1.0).
            std::ptr::write_unaligned((ring as *mut u8).add(24) as *mut f64, 1.0f64);
            std::ptr::write_unaligned((ring as *mut u8).add(32) as *mut f64, 100000.0f64);
        }

        let gate = Gate::range(Register::Rsi, 1.0, 100000.0).with_value_type(ValueType::F64);
        let payload = capture::emit_capture_payload(
            ring as u64,
            0x1401b42e9,
            Register::Rcx,
            Some(&gate),
            ValueType::F64,
            false, // keep capturing so we can observe both a reject and a pass
        );
        let cave_size = payload.len() + 64;
        let cave = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                cave_size,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert!(cave != libc::MAP_FAILED, "mmap cave");
        unsafe {
            std::ptr::copy_nonoverlapping(payload.as_ptr(), cave as *mut u8, payload.len());
            std::ptr::write((cave as *mut u8).add(payload.len()), 0xC3);
        }
        let f: extern "C" fn() = unsafe { std::mem::transmute(cave) };
        let read = |addr: u64, len: usize| -> Result<Vec<u8>, String> {
            let mut out = vec![0u8; len];
            unsafe {
                std::ptr::copy_nonoverlapping(addr as *const u8, out.as_mut_ptr(), len);
            }
            Ok(out)
        };

        // RSI = 0.0 (below min=1) must NOT capture.
        let v0 = 0.0f64.to_bits();
        unsafe {
            asm!(
                "mov rcx, 0x1111",
                "mov rsi, {val}",
                "mov r12, {f}",
                "call r12",
                val = in(reg) v0,
                f = in(reg) f as usize,
                out("rax") _, out("rcx") _, out("rdx") _, out("r8") _, out("r9") _,
                out("r10") _, out("r11") _, out("r12") _, out("r13") _, out("rsi") _,
            );
        }
        let (entries, _) = read_with_flag(ring as u64, 4, ValueType::F64, read);
        assert_eq!(entries.len(), 0, "gate value 0.0 (below min=1) must be rejected");

        // RSI = 50.0 (in [1,100000]) must capture.
        let v50 = 50.0f64.to_bits();
        unsafe {
            asm!(
                "mov rcx, 0x2222",
                "mov rsi, {val}",
                "mov r12, {f}",
                "call r12",
                val = in(reg) v50,
                f = in(reg) f as usize,
                out("rax") _, out("rcx") _, out("rdx") _, out("r8") _, out("r9") _,
                out("r10") _, out("r11") _, out("r12") _, out("r13") _, out("rsi") _,
            );
        }
        let (entries2, _) = read_with_flag(ring as u64, 4, ValueType::F64, read);
        assert_eq!(entries2.len(), 1, "gate value 50.0 (in range) must be captured");
        assert_eq!(entries2[0].raw, 0x2222);
        assert_eq!(entries2[0].gate_value, 50.0, "gate_value must decode as f64");

        unsafe {
            libc::munmap(ring, ring_size);
            libc::munmap(cave, cave_size);
        }
    }

    /// Regression test for the range-gate constant mapping: `install_capture`
    /// must write the gate's `min` into the ring header's const_a slot (not the
    /// default `g.value`, which is 0 for a Range gate). Before the fix, a
    /// `[1,100000]` gate became `[0,100000]` and accepted 0.
    #[test]
    fn install_capture_writes_range_min_to_header() {
        let arena: RefCell<Vec<u8>> = RefCell::new(vec![0u8; 0x100000]);
        let allocs: RefCell<Vec<u64>> = RefCell::new(vec![0x8000, 0x9000]);
        let alloc_i: RefCell<usize> = RefCell::new(0);
        let read = |addr: u64, len: usize| -> Result<Vec<u8>, String> {
            let m = arena.borrow();
            let s = addr as usize;
            let e = s + len;
            if e > m.len() { return Err("OOB".into()); }
            Ok(m[s..e].to_vec())
        };
        let write = |addr: u64, data: &[u8]| -> Result<usize, String> {
            let mut m = arena.borrow_mut();
            let s = addr as usize;
            let e = s + data.len();
            if e > m.len() { return Err("OOB".into()); }
            m[s..e].copy_from_slice(data);
            Ok(data.len())
        };
        let allocate = |_size: usize, _exec: bool| -> Result<u64, String> {
            let i = *alloc_i.borrow();
            *alloc_i.borrow_mut() += 1;
            allocs.borrow().get(i).copied().ok_or("no more allocs".into())
        };
        let target = 0x4000u64;
        write(target, &[0xB8, 0x01, 0x00, 0x00, 0x00, 0x90, 0xC3]).unwrap();
        // Range gate [1.0, 100000.0] on rsi, gated as f64.
        let gate = trainlab_core::capture::Gate::range(Register::Rsi, 1.0, 100000.0)
            .with_value_type(ValueType::F64);
        let spec = CaptureRegSpec::new(Register::Rcx, ValueType::U64).with_gate(gate);
        let cap = install_capture(target, spec, 2, false, read, write, allocate).unwrap();
        // Read const_a (offset 24) and const_b (offset 32) from the ring header.
        let hdr = read(cap.scratch, 48).unwrap();
        let a_bits = u64::from_le_bytes(hdr[RING_CONST_A_OFF..RING_CONST_A_OFF + 8].try_into().unwrap());
        let b_bits = u64::from_le_bytes(hdr[RING_CONST_B_OFF..RING_CONST_B_OFF + 8].try_into().unwrap());
        assert_eq!(f64::from_bits(a_bits), 1.0, "const_a must be the gate min (1.0), not 0.0");
        assert_eq!(f64::from_bits(b_bits), 100000.0, "const_b must be the gate max");
    }

    /// Repro for the "exact-value gate does not filter" bug: an `eq` gate with
    /// `value=1.0, value_type=f64` must record ONLY when the gate register holds
    /// exactly 1.0, and the recorded `gate_value` must decode to 1.0 (not NaN).
    #[test]
    fn gated_payload_eq_f64_filters_and_decodes() {
        use std::arch::asm;
        use trainlab_core::capture::{Gate, Register};

        let ring_size = capture::ring_size(4);
        let ring = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                ring_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert!(ring != libc::MAP_FAILED, "mmap ring");
        unsafe {
            std::ptr::write_bytes(ring as *mut u8, 0, ring_size);
            let total = (4 * ENTRY_STRIDE) as u32;
            std::ptr::write_unaligned((ring as *mut u8).add(8) as *mut u32, total);
            // const_a = 1.0 (the eq target), as f64 bits.
            std::ptr::write_unaligned((ring as *mut u8).add(24) as *mut f64, 1.0f64);
        }

        // Capture rcx, gate on rsi == 1.0 as f64.
        let gate = Gate::compare(Register::Rsi, GateCmp::Eq, 1.0).with_value_type(ValueType::F64);
        let payload = capture::emit_capture_payload(
            ring as u64,
            0x1401b42e9,
            Register::Rcx,
            Some(&gate),
            ValueType::F64,
            false, // keep capturing so we can observe both a reject and a pass
        );
        let cave_size = payload.len() + 64;
        let cave = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                cave_size,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert!(cave != libc::MAP_FAILED, "mmap cave");
        unsafe {
            std::ptr::copy_nonoverlapping(payload.as_ptr(), cave as *mut u8, payload.len());
            std::ptr::write((cave as *mut u8).add(payload.len()), 0xC3);
        }
        let f: extern "C" fn() = unsafe { std::mem::transmute(cave) };
        let read = |addr: u64, len: usize| -> Result<Vec<u8>, String> {
            let mut out = vec![0u8; len];
            unsafe {
                std::ptr::copy_nonoverlapping(addr as *const u8, out.as_mut_ptr(), len);
            }
            Ok(out)
        };

        // rsi = 2.0 (not equal to 1.0) must NOT capture.
        let v2 = 2.0f64.to_bits();
        unsafe {
            asm!(
                "mov rcx, 0x1111",
                "mov rsi, {val}",
                "mov r12, {f}",
                "call r12",
                val = in(reg) v2,
                f = in(reg) f as usize,
                out("rax") _, out("rcx") _, out("rdx") _, out("r8") _, out("r9") _,
                out("r10") _, out("r11") _, out("r12") _, out("r13") _, out("rsi") _,
            );
        }
        let (entries, _) = read_with_flag(ring as u64, 4, ValueType::F64, read);
        assert_eq!(entries.len(), 0, "gate value 2.0 (not equal to 1.0) must be rejected");

        // rsi = 1.0 (equal) must capture, and gate_value must decode to 1.0.
        let v1 = 1.0f64.to_bits();
        unsafe {
            asm!(
                "mov rcx, 0x2222",
                "mov rsi, {val}",
                "mov r12, {f}",
                "call r12",
                val = in(reg) v1,
                f = in(reg) f as usize,
                out("rax") _, out("rcx") _, out("rdx") _, out("r8") _, out("r9") _,
                out("r10") _, out("r11") _, out("r12") _, out("r13") _, out("rsi") _,
            );
        }
        let (entries2, _) = read_with_flag(ring as u64, 4, ValueType::F64, read);
        assert_eq!(entries2.len(), 1, "gate value 1.0 (equal) must be captured");
        assert_eq!(entries2[0].raw, 0x2222);
        assert_eq!(entries2[0].gate_value, 1.0, "gate_value must decode to 1.0, not NaN");

        unsafe {
            libc::munmap(ring, ring_size);
            libc::munmap(cave, cave_size);
        }
    }

    /// Exact repro of the report: capture `rcx` as **ptr**, gate `rsi` as **f64**
    /// with `eq value=1.0`. This is the precise combination the Helldivers agent
    /// used (capture a pointer, gate on a Lua double). Verifies the gate filters
    /// and `gate_value` decodes to 1.0 (not NaN) even when the capture type is ptr.
    #[test]
    fn gated_payload_eq_f64_capture_ptr() {
        use std::arch::asm;
        use trainlab_core::capture::{Gate, Register};

        let ring_size = capture::ring_size(4);
        let ring = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                ring_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert!(ring != libc::MAP_FAILED, "mmap ring");
        unsafe {
            std::ptr::write_bytes(ring as *mut u8, 0, ring_size);
            let total = (4 * ENTRY_STRIDE) as u32;
            std::ptr::write_unaligned((ring as *mut u8).add(8) as *mut u32, total);
            std::ptr::write_unaligned((ring as *mut u8).add(24) as *mut f64, 1.0f64);
        }

        // Capture rcx as ptr, gate on rsi == 1.0 as f64.
        let gate = Gate::compare(Register::Rsi, GateCmp::Eq, 1.0).with_value_type(ValueType::F64);
        let payload = capture::emit_capture_payload(
            ring as u64,
            0x1401b42e9,
            Register::Rcx,
            Some(&gate),
            ValueType::Ptr, // capture type is ptr, gate type is f64
            false,
        );
        let cave_size = payload.len() + 64;
        let cave = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                cave_size,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert!(cave != libc::MAP_FAILED, "mmap cave");
        unsafe {
            std::ptr::copy_nonoverlapping(payload.as_ptr(), cave as *mut u8, payload.len());
            std::ptr::write((cave as *mut u8).add(payload.len()), 0xC3);
        }
        let f: extern "C" fn() = unsafe { std::mem::transmute(cave) };
        let read = |addr: u64, len: usize| -> Result<Vec<u8>, String> {
            let mut out = vec![0u8; len];
            unsafe {
                std::ptr::copy_nonoverlapping(addr as *const u8, out.as_mut_ptr(), len);
            }
            Ok(out)
        };

        // rsi = 2.0 (not equal) must NOT capture.
        let v2 = 2.0f64.to_bits();
        unsafe {
            asm!(
                "mov rcx, 0x1111",
                "mov rsi, {val}",
                "mov r12, {f}",
                "call r12",
                val = in(reg) v2,
                f = in(reg) f as usize,
                out("rax") _, out("rcx") _, out("rdx") _, out("r8") _, out("r9") _,
                out("r10") _, out("r11") _, out("r12") _, out("r13") _, out("rsi") _,
            );
        }
        let (entries, _) = read_with_flag_gate(ring as u64, 4, ValueType::Ptr, ValueType::F64, read);
        assert_eq!(entries.len(), 0, "gate value 2.0 must be rejected");

        // rsi = 1.0 (equal) must capture; gate_value decodes as f64 = 1.0.
        let v1 = 1.0f64.to_bits();
        unsafe {
            asm!(
                "mov rcx, 0x2222",
                "mov rsi, {val}",
                "mov r12, {f}",
                "call r12",
                val = in(reg) v1,
                f = in(reg) f as usize,
                out("rax") _, out("rcx") _, out("rdx") _, out("r8") _, out("r9") _,
                out("r10") _, out("r11") _, out("r12") _, out("r13") _, out("rsi") _,
            );
        }
        let (entries2, _) = read_with_flag_gate(ring as u64, 4, ValueType::Ptr, ValueType::F64, read);
        assert_eq!(entries2.len(), 1, "gate value 1.0 must be captured");
        assert_eq!(entries2[0].raw, 0x2222);
        assert_eq!(entries2[0].gate_value, 1.0, "gate_value must decode to 1.0, not NaN");

        unsafe {
            libc::munmap(ring, ring_size);
            libc::munmap(cave, cave_size);
        }
    }

    /// Regression test for the "eq gate records everything / gate_value=NaN"
    /// bug: `fucomip` sets ZF=1 for unordered (NaN) operands, so a plain `jne`
    /// would treat NaN as "equal" and pass. The fix adds a `jp` (parity) check
    /// so NaN never passes an equality gate. Here the gate register holds NaN
    /// and must be rejected.
    #[test]
    fn gated_payload_eq_f64_rejects_nan() {
        use std::arch::asm;
        use trainlab_core::capture::{Gate, Register};

        let ring_size = capture::ring_size(4);
        let ring = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                ring_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert!(ring != libc::MAP_FAILED, "mmap ring");
        unsafe {
            std::ptr::write_bytes(ring as *mut u8, 0, ring_size);
            let total = (4 * ENTRY_STRIDE) as u32;
            std::ptr::write_unaligned((ring as *mut u8).add(8) as *mut u32, total);
            std::ptr::write_unaligned((ring as *mut u8).add(24) as *mut f64, 1.0f64);
        }

        let gate = Gate::compare(Register::Rsi, GateCmp::Eq, 1.0).with_value_type(ValueType::F64);
        let payload = capture::emit_capture_payload(
            ring as u64,
            0x1401b42e9,
            Register::Rcx,
            Some(&gate),
            ValueType::F64,
            false,
        );
        let cave_size = payload.len() + 64;
        let cave = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                cave_size,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert!(cave != libc::MAP_FAILED, "mmap cave");
        unsafe {
            std::ptr::copy_nonoverlapping(payload.as_ptr(), cave as *mut u8, payload.len());
            std::ptr::write((cave as *mut u8).add(payload.len()), 0xC3);
        }
        let f: extern "C" fn() = unsafe { std::mem::transmute(cave) };
        let read = |addr: u64, len: usize| -> Result<Vec<u8>, String> {
            let mut out = vec![0u8; len];
            unsafe {
                std::ptr::copy_nonoverlapping(addr as *const u8, out.as_mut_ptr(), len);
            }
            Ok(out)
        };

        // rsi = NaN must NOT capture (the bug: it would pass an eq gate).
        let nan = f64::NAN.to_bits();
        unsafe {
            asm!(
                "mov rcx, 0x3333",
                "mov rsi, {val}",
                "mov r12, {f}",
                "call r12",
                val = in(reg) nan,
                f = in(reg) f as usize,
                out("rax") _, out("rcx") _, out("rdx") _, out("r8") _, out("r9") _,
                out("r10") _, out("r11") _, out("r12") _, out("r13") _, out("rsi") _,
            );
        }
        let (entries, _) = read_with_flag(ring as u64, 4, ValueType::F64, read);
        assert_eq!(entries.len(), 0, "NaN gate value must be rejected by an eq gate");

        // rsi = 1.0 must still capture.
        let v1 = 1.0f64.to_bits();
        unsafe {
            asm!(
                "mov rcx, 0x2222",
                "mov rsi, {val}",
                "mov r12, {f}",
                "call r12",
                val = in(reg) v1,
                f = in(reg) f as usize,
                out("rax") _, out("rcx") _, out("rdx") _, out("r8") _, out("r9") _,
                out("r10") _, out("r11") _, out("r12") _, out("r13") _, out("rsi") _,
            );
        }
        let (entries2, _) = read_with_flag(ring as u64, 4, ValueType::F64, read);
        assert_eq!(entries2.len(), 1, "gate value 1.0 must still be captured");
        assert_eq!(entries2[0].gate_value, 1.0);

        unsafe {
            libc::munmap(ring, ring_size);
            libc::munmap(cave, cave_size);
        }
    }

    /// Read the ring and the disarmed flag together. `value_type` is the
    /// capture type; `gate_value_type` is the gate's own type (defaults to the
    /// capture type when not given).
    fn read_with_flag<R>(
        scratch: u64,
        capacity: usize,
        value_type: ValueType,
        read: R,
    ) -> (Vec<CaptureEntry>, bool)
    where
        R: Fn(u64, usize) -> Result<Vec<u8>, String>,
    {
        read_with_flag_gate(scratch, capacity, value_type, value_type, read)
    }

    fn read_with_flag_gate<R>(
        scratch: u64,
        capacity: usize,
        value_type: ValueType,
        gate_value_type: ValueType,
        read: R,
    ) -> (Vec<CaptureEntry>, bool)
    where
        R: Fn(u64, usize) -> Result<Vec<u8>, String>,
    {
        let disarmed = read_disarmed(scratch, &read).unwrap();
        let entries = read_captures(scratch, capacity, value_type, gate_value_type, read).unwrap();
        (entries, disarmed)
    }
}
