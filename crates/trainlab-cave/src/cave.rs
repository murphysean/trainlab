//! Code cave installation: allocate executable memory, emit shellcode, patch
//! a call site with a jump, and track the original bytes for undo.
//!
//! The injected DLL runs in-process, so installation uses its `allocate`
//! (VirtualAlloc on Windows / mmap on Unix) plus plain writes.
//!
//! ## Hook kinds
//!
//! A hook is a `jmp` placed over the first whole instructions of a target. When
//! we overwrite those instructions we lose them — unless we re-emit them. The
//! [`HookKind`] picks what the cave does:
//!
//! - [`HookKind::Trampoline`] — **transparent**: relays the stolen instructions
//!   (relocated to the cave) and optionally runs a `payload` first, then jumps
//!   back. The game's original behavior is preserved, so a no-op hook (empty
//!   payload) is fully transparent and wood keeps ticking. This is the "work
//!   with the loop" model (override a value, then let the loop continue).
//! - [`HookKind::Override`] — **replace**: runs only `payload` then jumps back,
//!   skipping the stolen instruction(s) entirely. Use to short-circuit /
//!   redirect the target. Caller must supply behavior in `payload`.

use crate::emitter;
use trainlab_core::disasm;

pub use trainlab_core::cave_hook::JumpStyle;

/// How a code-cave hook redirects the target instruction(s).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookKind {
    /// Transparent hook: run `payload` (default empty), then **replay** the
    /// stolen instructions (relocated to the cave) before jumping back. The
    /// target's original behavior is preserved. Empty payload = pure no-op.
    Trampoline {
        payload: Vec<u8>,
        jump: JumpStyle,
    },
    /// Replace hook: run `payload` then jump straight back, **skipping** the
    /// stolen instruction(s). The original behavior is replaced.
    Override {
        payload: Vec<u8>,
        jump: JumpStyle,
    },
}

/// A live code cave hook installed into the target process.
///
/// Holding this handle lets the caller:
/// - know where the shellcode lives (`cave_addr`),
/// - know what original bytes were overwritten at the call site (`original`),
/// - restore the original bytes via [`restore`].
pub struct InstalledCave {
    /// Address of the allocated shellcode block (the "cave").
    pub cave_addr: u64,
    /// Address of the patched call site (first overwritten byte).
    pub target: u64,
    /// The original bytes that were overwritten at `target`.
    pub original: Vec<u8>,
    /// The jump-back target: the instruction right after the patched region.
    pub return_to: u64,
    /// How the hook was installed (for reporting / undo semantics).
    pub kind: HookKind,
}

/// Install a code cave hook at `target` per `kind`.
///
/// The common work, independent of kind:
/// 1. Determine the instruction-aligned patch length — overwrite a whole number
///    of instructions whose total length is >= the absolute-jmp size, so the
///    `jmp` fits without splitting an instruction and the jump-back lands on a
///    real boundary.
/// 2. Save the original bytes for undo.
/// 3. Allocate an executable cave.
/// 4. Build the cave body per `kind`:
///    - `Trampoline`: `[payload][relocated stolen]` then a jump-back if the
///      stolen block does not itself end in a branch.
///    - `Override`: `[payload][jump-back]`.
/// 5. Patch `target` with `jmp cave`.
///
/// `read`/`write` read/write bytes in the target process (the injected DLL's
/// in-process access). `allocate` allocates executable memory in the target.
///
/// Returns a handle carrying the original bytes for [`restore`].
pub fn install<R, W, A>(
    target: u64,
    kind: HookKind,
    read: R,
    write: W,
    allocate: A,
) -> Result<InstalledCave, String>
where
    R: Fn(u64, usize) -> Result<Vec<u8>, String>,
    W: Fn(u64, &[u8]) -> Result<usize, String>,
    A: Fn(usize, bool) -> Result<u64, String>,
{
    let jump_style = match &kind {
        HookKind::Override { jump, .. } | HookKind::Trampoline { jump, .. } => *jump,
    };
    let min_patch_len = match jump_style {
        JumpStyle::Absolute => emitter::JMP_ABS_LEN,
        JumpStyle::Relative => 5,
    };

    // 1. Instruction-aligned patch length (>= min_patch_len), so the jmp fits and
    //    the jump-back lands on a real instruction boundary.
    let window = min_patch_len + 32;
    let buf = read(target, window).map_err(|e| format!("read window: {e}"))?;
    let patch_len = disasm::instruction_aligned_len(&buf, min_patch_len)
        .ok_or_else(|| "could not find an instruction-aligned patch length".to_string())?;

    // 2. Original bytes for undo.
    let original = read(target, patch_len).map_err(|e| format!("read originals: {e}"))?;
    let return_to = target + patch_len as u64;

    // 3. Allocate a cave big enough for payload + worst-case relocated block +
    //    jump-back slack. (Relocation length can grow if the encoder rewrites a
    //    short branch into a longer one, so we pad generously.)
    let payload_len = match &kind {
        HookKind::Override { payload, .. } | HookKind::Trampoline { payload, .. } => payload.len(),
    };
    let slack = patch_len + 48;
    let cave = allocate(payload_len + slack, true)?;

    // 5. Build the cave body.
    match &kind {
        HookKind::Override { payload, .. } => {
            write(cave, payload).map_err(|e| format!("write payload: {e}"))?;
            // Only append jump-back if the payload doesn't terminate with a ret (0xC3)
            let ends_in_ret = payload.last() == Some(&0xC3);
            if !ends_in_ret {
                let jmp_back = emitter::jmp_abs(return_to);
                write(cave + payload.len() as u64, &jmp_back)
                    .map_err(|e| format!("write jump-back: {e}"))?;
            }
        }
        HookKind::Trampoline { payload, .. } => {
            // Relocate stolen instructions to run right after the payload.
            let reloc_ip = cave + payload.len() as u64;
            let relocated = disasm::relocate(&original, target, reloc_ip).ok_or_else(|| {
                "could not relocate stolen instructions for the trampoline".to_string()
            })?;
            // Payload first.
            write(cave, payload).map_err(|e| format!("write payload: {e}"))?;
            // Relocated stolen.
            write(reloc_ip, &relocated.bytes).map_err(|e| format!("write relocated: {e}"))?;
            // Jump-back only if the relocated block does not end in a branch.
            if !relocated.ends_in_branch {
                let jmp_back = emitter::jmp_abs(return_to);
                write(
                    reloc_ip + relocated.bytes.len() as u64,
                    &jmp_back,
                )
                .map_err(|e| format!("write jump-back: {e}"))?;
            }
        }
    }

    // 6. Patch the call site with `jmp cave`.
    let jmp_in = match jump_style {
        JumpStyle::Absolute => emitter::jmp_abs(cave),
        JumpStyle::Relative => {
            let rel = (cave as i128) - ((target + 5) as i128);
            if rel < i32::MIN as i128 || rel > i32::MAX as i128 {
                return Err(format!("cave target {cave:#x} out of ±2GB range for relative jump from {target:#x}"));
            }
            let mut bytes = vec![0xE9];
            bytes.extend_from_slice(&(rel as i32).to_le_bytes());
            // NOP-pad remaining stolen bytes in the patch window if patch_len > 5
            if patch_len > 5 {
                bytes.resize(patch_len, 0x90);
            }
            bytes
        }
    };
    write(target, &jmp_in).map_err(|e| format!("patch target: {e}"))?;

    Ok(InstalledCave {
        cave_addr: cave,
        target,
        original,
        return_to,
        kind,
    })
}

/// Restore the original bytes at a patched call site.
///
/// `original` is the byte-for-byte original saved when the hook was installed.
/// `write` writes into the target process.
pub fn restore<W>(target: u64, original: &[u8], write: W) -> Result<(), String>
where
    W: Fn(u64, &[u8]) -> Result<usize, String>,
{
    write(target, original).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    // A tiny fake "process" for tests: a byte arena.
    #[derive(Clone)]
    struct FakeMem(Rc<RefCell<Vec<u8>>>);

    impl FakeMem {
        fn new(size: usize) -> Self {
            FakeMem(Rc::new(RefCell::new(vec![0u8; size])))
        }
        fn write(&self, addr: u64, data: &[u8]) -> Result<usize, String> {
            let mut m = self.0.borrow_mut();
            let start = addr as usize;
            let end = start + data.len();
            if end > m.len() {
                return Err("OOB".into());
            }
            m[start..end].copy_from_slice(data);
            Ok(data.len())
        }
        fn read(&self, addr: u64, len: usize) -> Result<Vec<u8>, String> {
            let m = self.0.borrow();
            let start = addr as usize;
            let end = start + len;
            if end > m.len() {
                return Err("OOB".into());
            }
            Ok(m[start..end].to_vec())
        }
        fn alloc(&self, _size: usize, _exec: bool) -> Result<u64, String> {
            Ok(0x100000)
        }
        fn bytes_at(&self, addr: u64, len: usize) -> Vec<u8> {
            let m = self.0.borrow();
            m[addr as usize..addr as usize + len].to_vec()
        }
    }

    thread_local! {
        static FAKE: FakeMem = FakeMem::new(0x200000);
    }

    fn fake_read(addr: u64, len: usize) -> Result<Vec<u8>, String> {
        FAKE.with(|m| m.read(addr, len))
    }
    fn fake_write(addr: u64, data: &[u8]) -> Result<usize, String> {
        FAKE.with(|m| m.write(addr, data))
    }
    fn fake_alloc(size: usize, exec: bool) -> Result<u64, String> {
        FAKE.with(|m| m.alloc(size, exec))
    }

    #[test]
    fn install_override_writes_payload_and_jumpback() {
        let payload = [0x90, 0x90, 0x90]; // nop nop nop
        let target = 0x4000u64;
        let kind = HookKind::Override {
            payload: payload.to_vec(),
            jump: JumpStyle::Absolute,
        };
        let hook = install(target, kind, fake_read, fake_write, fake_alloc).unwrap();
        assert_eq!(hook.target, 0x4000);
        // Original bytes captured at the target (>= 12, instruction-aligned).
        assert!(hook.original.len() >= 12, "orig len = {}", hook.original.len());
        // Payload written at the cave start (0x100000).
        FAKE.with(|m| assert_eq!(m.bytes_at(0x100000, 3), payload));
        // Jump-back written after the payload.
        FAKE.with(|m| {
            let jb = m.bytes_at(0x100000 + 3, 12);
            assert_eq!(&jb[0..2], &[0xFF, 0x25]);
        });
        // Target patched with a jmp into the cave.
        FAKE.with(|m| {
            let patched = m.bytes_at(0x4000, 14);
            assert_eq!(&patched[0..2], &[0xFF, 0x25]); // jmp qword ptr [rip+disp32]
            assert_eq!(u64::from_le_bytes(patched[6..14].try_into().unwrap()), 0x100000);
        });
    }

    #[test]
    fn install_trampoline_relocates_stolen_and_jumps_back() {
        // Target bytes: mov eax,1 (5) ; nop (1) ... The trampoline replays the
        // stolen instruction so the original behavior is preserved.
        let target = 0x5000u64;
        // Pre-seed the fake memory at target with a real instruction sequence
        // (mov eax,1 ; nop ; ret). The fake memory is zero-initialized, so seed
        // it first via the write closure.
        let seed = [0xB8, 0x01, 0x00, 0x00, 0x00, 0x90, 0xC3]; // mov eax,1 ; nop ; ret
        fake_write(target, &seed).unwrap();
        let kind = HookKind::Trampoline {
            payload: Vec::new(),
            jump: JumpStyle::Absolute,
        };
        let hook = install(target, kind, fake_read, fake_write, fake_alloc).unwrap();
        // Original captured == the seed.
        assert!(hook.original.len() >= 7);
        // The cave (0x100000) must contain the relocated stolen bytes (mov eax,1...).
        // The trampoline relays the stolen instructions, so bytes at cave start
        // should begin with the relocated mov eax,1 prefix.
        FAKE.with(|m| {
            let first = m.bytes_at(0x100000, 5);
            assert_eq!(&first[0..2], &[0xB8, 0x01], "stolen mov eax,1 relocated");
        });
    }

    #[test]
    fn install_relative_jump_5byte_patch() {
        let target = 0x100005u64; // Close to fake_alloc 0x100000
        let seed = [0x48, 0x2B, 0x41, 0x10, 0x48, 0xC1, 0xF8, 0x03, 0xC3]; // 9 bytes (sub; sar; ret)
        fake_write(target, &seed).unwrap();
        let kind = HookKind::Trampoline {
            payload: Vec::new(),
            jump: JumpStyle::Relative,
        };
        let hook = install(target, kind, fake_read, fake_write, fake_alloc).unwrap();
        // Patch window for relative jump on this 4-byte sub + 4-byte sar + 1-byte ret should be 8 bytes
        assert_eq!(hook.original.len(), 8);
        FAKE.with(|m| {
            let patched = m.bytes_at(target, 8);
            assert_eq!(patched[0], 0xE9); // relative jump opcode
            // Remaining 3 bytes in the 8-byte patch window must be NOP padded (0x90)
            assert_eq!(&patched[5..8], &[0x90, 0x90, 0x90]);
        });
    }

    #[test]
    fn restore_puts_back_bytes() {
        let original = vec![0x8B, 0x45, 0x08, 0x00, 0x00]; // original 5 bytes
        restore(0x4000, &original, fake_write).unwrap();
        FAKE.with(|m| assert_eq!(m.bytes_at(0x4000, 5), original));
    }
}
