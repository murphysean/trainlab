//! Registry + handlers for non-stalling register captures inside the game.
//!
//! Keeps the installed captures (id, ring address, original bytes, capacity,
//! value type) in a static map so the DLL can:
//! - install a passive capture trampoline at a code site,
//! - read back the recorded ring entries,
//! - uninstall (restore original bytes, free the ring) cleanly.
//!
//! All state is guarded by a mutex; the capture payload itself (which runs on
//! a game thread) only touches the ring memory directly and never locks.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use trainlab_core::capture::{CaptureRegSpec, ValueType};
use trainlab_core::memory::{ProcessMemory, SelfProcess};

/// A live capture's bookkeeping.
struct LiveCapture {
    target: u64,
    original: Vec<u8>,
    scratch: u64,
    capacity: usize,
    value_type: ValueType,
    gate_value_type: ValueType,
}

struct Registry {
    next_id: u64,
    captures: HashMap<u64, LiveCapture>,
}

static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();

fn registry() -> &'static Mutex<Registry> {
    REGISTRY.get_or_init(|| Mutex::new(Registry {
        next_id: 1,
        captures: HashMap::new(),
    }))
}

/// Install a passive register capture at `target`. Returns the capture id and
/// the original bytes overwritten at the site (for undo).
pub fn install(
    target: u64,
    spec: CaptureRegSpec,
    capacity: usize,
    disarm: bool,
) -> Result<(u64, Vec<u8>), String> {
    let mem = SelfProcess;
    let read = |addr: u64, len: usize| mem.read(addr, len).map_err(|e| e.to_string());
    let write = |addr: u64, data: &[u8]| mem.write(addr, data).map_err(|e| e.to_string());
    let alloc = |size: usize, exec: bool| crate::allocate(size, exec);

    let cap = trainlab_cave::capture::install_capture(
        target,
        spec,
        capacity,
        disarm,
        read,
        write,
        alloc,
    )?;
    let original = cap.original.clone();

    let mut reg = registry().lock().map_err(|_| "capture registry poisoned".to_string())?;
    let id = reg.next_id;
    reg.next_id += 1;
    reg.captures.insert(
        id,
        LiveCapture {
            target: cap.target,
            original: cap.original,
            scratch: cap.scratch,
            capacity: cap.capacity,
            value_type: cap.value_type,
            gate_value_type: cap.gate_value_type,
        },
    );
    Ok((id, original))
}

/// Read back the recorded entries + the ring's disarmed flag for a capture.
pub fn read(
    id: u64,
) -> Result<(Vec<trainlab_core::protocol::CaptureEntry>, bool), String> {
    let reg = registry().lock().map_err(|_| "capture registry poisoned".to_string())?;
    let c = reg
        .captures
        .get(&id)
        .ok_or_else(|| format!("no capture with id {id}"))?;
    let mem = SelfProcess;
    let read = |addr: u64, len: usize| mem.read(addr, len).map_err(|e| e.to_string());
    let entries = trainlab_cave::capture::read_captures(
        c.scratch,
        c.capacity,
        c.value_type,
        c.gate_value_type,
        read,
    )?;
    let disarmed = trainlab_cave::capture::read_disarmed(c.scratch, &read)?;
    Ok((entries, disarmed))
}

/// Uninstall a capture: restore original bytes at its target and free the ring.
pub fn uninstall(id: u64) -> Result<(), String> {
    let mut reg = registry().lock().map_err(|_| "capture registry poisoned".to_string())?;
    let c = reg
        .captures
        .remove(&id)
        .ok_or_else(|| format!("no capture with id {id}"))?;
    let mem = SelfProcess;
    let write = |addr: u64, data: &[u8]| mem.write(addr, data).map_err(|e| e.to_string());
    trainlab_cave::capture::restore_capture(c.target, &c.original, write)?;
    crate::free(c.scratch);
    Ok(())
}

/// Look up the ring address of a capture (used by the GUI to expose scratch).
pub fn scratch(id: u64) -> Option<u64> {
    registry()
        .lock()
        .ok()
        .and_then(|r| r.captures.get(&id).map(|c| c.scratch))
}
