//! Pointer chasing — resolving a known pointer chain to a live address.
//!
//! Games reallocate objects between launches, so a fixed address for a value
//! (e.g. player health) is useless. But the *pointer chain* — "the object is
//! at `base`, then follow offset `0x10`, then offset `0x20`" — stays stable
//! across runs. [`pointer_chase`] resolves that chain against a live process
//! and reports every hop, so a trainer can reproduce the current address of
//! the value every session.
//!
//! This is a *resolution* tool, not a *discovery* tool: you supply the chain
//! (usually found once by hand or by scanning). See the module docs on
//! [`chase`] for the two ways to express a chain.
//!
//! Note this is distinct from a **reverse-reference / pointer-scan**, which
//! finds *what points to* a given address (useful for finding the owning
//! object). That is a scan operation, not this.

use crate::memory::{MemoryError, ProcessMemory};

/// Chase a pointer chain in one step, resolving each offset.
///
/// `base` is the starting address. `offsets` is the sequence of field offsets
/// applied after each dereference, ending with the offset of the final value.
///
/// The chain is resolved as:
/// ```text
/// hop 0: ptr = read(base)                          // first deref
/// hop 1: ptr = read(ptr + offsets[0])              // apply offset, deref
/// hop 2: ptr = read(ptr + offsets[1])
/// ...
/// final: address = ptr + offsets[last]             // value address (no deref)
/// ```
///
/// Returns a vector of the intermediate pointer values *plus* the final
/// resolved value address. The last element is the value's address; the
/// preceding elements are each hop's pointer. If `offsets` is empty, the
/// result is `[base]`.
pub fn chase<P: ProcessMemory + ?Sized>(
    proc: &P,
    base: u64,
    offsets: &[u64],
) -> Result<Vec<u64>, MemoryError> {
    chase_with(proc, base, offsets, |hop| hop)
}

/// Chase a pointer chain, but let the caller transform each intermediate hop
/// (e.g. to apply an added module base offset between dereferences).
///
/// `transform` receives each pointer value after reading it (and before the
/// next offset is applied) and returns the value to continue from. This is
/// useful when a chain is expressed relative to a module base that isn't
/// known until runtime.
pub fn chase_with<P: ProcessMemory + ?Sized>(
    proc: &P,
    base: u64,
    offsets: &[u64],
    mut transform: impl FnMut(u64) -> u64,
) -> Result<Vec<u64>, MemoryError> {
    let mut hops = Vec::with_capacity(offsets.len() + 1);
    let mut ptr = base;

    // Offsets[0] is applied on the *second* deref (the first deref is at
    // `base` with no offset). So deref `k` reads at `ptr + offsets[k-1]`.
    for i in 0..offsets.len() {
        if i == 0 {
            // First deref reads the pointer at `base`.
            ptr = read_ptr(proc, ptr)?;
        } else {
            // Subsequent derefs read at the previous pointer + the offset
            // that precedes this hop.
            ptr = read_ptr(proc, ptr + offsets[i - 1])?;
        }
        ptr = transform(ptr);
        hops.push(ptr);
    }

    // The final value address is the last pointer plus the last offset.
    let final_addr = match offsets.last() {
        Some(off) => ptr + *off,
        None => base,
    };
    hops.push(final_addr);

    Ok(hops)
}

/// Read a single native-width pointer (usize) from a process.
fn read_ptr<P: ProcessMemory + ?Sized>(proc: &P, address: u64) -> Result<u64, MemoryError> {
    let size = std::mem::size_of::<usize>();
    let buf = proc.read(address, size)?;
    let mut arr = [0u8; 8];
    arr[..size].copy_from_slice(&buf);
    Ok(u64::from_le_bytes(arr))
}

/// A reverse-reference / pointer-scan: find addresses in writable memory whose
/// pointer value points to (or into) a target address range.
///
/// This is the "find *what points to* this address" tool. It walks readable
/// writable regions, reads every pointer-sized value, and reports each address
/// whose stored value falls within `[target_lo, target_hi]`. Useful for finding
/// the owning object(s) that reference a discovered value, then chasing a
/// stable chain (T-013).
///
/// Returns `(address, pointed_value)` pairs. `pointed_value` is the pointer
/// stored at `address` (which is within the target range).
pub fn reverse_scan<P: ProcessMemory + ?Sized>(
    proc: &P,
    regions: &[crate::memory::Region],
    target_lo: u64,
    target_hi: u64,
) -> Result<Vec<(u64, u64)>, MemoryError> {
    let size = std::mem::size_of::<usize>();
    let mut out = Vec::new();
    for r in regions {
        if !r.readable || !r.writable {
            continue;
        }
        let start = r.start;
        let end = r.end;
        let len = (end - start) as usize;
        if len < size {
            continue;
        }
        let buf = match proc.read(start, len) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let nvals = buf.len() / size;
        for i in 0..nvals {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&buf[i * size..(i + 1) * size]);
            let ptr = u64::from_le_bytes(arr);
            if ptr >= target_lo && ptr <= target_hi {
                out.push((start + (i * size) as u64, ptr));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{MemoryError, ProcessMemory, Region};
    use std::cell::RefCell;

    struct Mock {
        buf: RefCell<Vec<u8>>,
    }

    impl Mock {
        fn new(size: usize) -> Self {
            Self {
                buf: RefCell::new(vec![0u8; size]),
            }
        }
        fn put_ptr(&self, addr: u64, val: u64) {
            let mut b = self.buf.borrow_mut();
            let bytes = val.to_le_bytes();
            b[addr as usize..addr as usize + 8].copy_from_slice(&bytes);
        }
    }

    impl ProcessMemory for Mock {
        fn read(&self, address: u64, len: usize) -> Result<Vec<u8>, MemoryError> {
            let b = self.buf.borrow();
            let start = address as usize;
            if start + len > b.len() {
                return Err(MemoryError::OutOfRange { address });
            }
            Ok(b[start..start + len].to_vec())
        }
        fn write(&self, _address: u64, _data: &[u8]) -> Result<usize, MemoryError> {
            Ok(0)
        }
        fn regions(&self) -> Result<Vec<Region>, MemoryError> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn single_hop() {
        let m = Mock::new(256);
        // base at 0x10 holds pointer to 0x200.
        m.put_ptr(0x10, 0x200);
        // value at 0x200 + 0x20 = 0x220.
        let hops = chase(&m, 0x10, &[0x20]).unwrap();
        assert_eq!(hops, vec![0x200, 0x220]);
    }

    #[test]
    fn multi_hop_chain() {
        let m = Mock::new(1024);
        // base at 0x100 -> 0x300 (hop 0)
        m.put_ptr(0x100, 0x300);
        // offsets[0]=0x10: read at 0x300+0x10=0x310 -> 0x500 (hop 1)
        m.put_ptr(0x310, 0x500);
        // value at 0x500 + offsets[1]=0x40 = 0x540
        let hops = chase(&m, 0x100, &[0x10, 0x40]).unwrap();
        assert_eq!(hops, vec![0x300, 0x500, 0x540]);
    }

    #[test]
    fn empty_offsets_returns_base() {
        let m = Mock::new(64);
        let hops = chase(&m, 0x1000, &[]).unwrap();
        assert_eq!(hops, vec![0x1000]);
    }

    #[test]
    fn chase_with_transform() {
        let m = Mock::new(8192);
        // base holds a relative value we must add a module base to.
        m.put_ptr(0x20, 0x100);
        // hop 0: read(0x20)=0x100, +0x1000 -> 0x1100
        // offsets[0]=0x8: read at 0x1100+0x8=0x1108 -> 0x700, +0x1000 -> 0x1700
        m.put_ptr(0x1108, 0x700);
        // value at 0x1700 + offsets[1]=0x30 = 0x1730
        let hops = chase_with(&m, 0x20, &[0x8, 0x30], |v| v + 0x1000).unwrap();
        assert_eq!(hops, vec![0x1100, 0x1700, 0x1730]);
    }

    #[test]
    fn reverse_scan_finds_pointers() {
        let m = Mock::new(256);
        // Two addresses point into target range [0x1000, 0x2000].
        m.put_ptr(0x10, 0x1500);
        m.put_ptr(0x20, 0x1800);
        // One points outside.
        m.put_ptr(0x30, 0x5000);
        let region = Region {
            start: 0,
            end: 256,
            readable: true,
            writable: true,
            executable: false,
            name: None,
        };
        let found = reverse_scan(&m, &[region], 0x1000, 0x2000).unwrap();
        // 0x10 -> 0x1500, 0x20 -> 0x1800 (0x30 -> 0x5000 excluded).
        assert_eq!(found, vec![(0x10, 0x1500), (0x20, 0x1800)]);
    }
}
