//! Value scanning with narrowing — the scanmem / Cheat Engine workflow.
//!
//! A [`Scan`] holds a **persistent match set**: the addresses (and last
//! observed values) that currently match. You start with a first scan for an
//! exact/range value, then *narrow* as the game runs by re-reading each match
//! and filtering on `changed` / `unchanged` / `increased` / `decreased` or a
//! new exact/range value.
//!
//! The match set is what makes `trainlab-scanner next` (T-014) and the MCP
//! recon tools work — without it, "refine a previous scan" is meaningless.
//!
//! Supported value types: `i32`, `u32`, `f32`, `f64`. More can be added by
//! extending [`ValueType`].

use crate::memory::{MemoryError, ProcessMemory};
use serde::{Deserialize, Serialize};

/// The width/interpretation of a scanned value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueType {
    #[serde(alias = "I32", alias = "int", alias = "int32")]
    I32,
    #[serde(alias = "U32", alias = "uint", alias = "uint32")]
    U32,
    #[serde(alias = "F32", alias = "float")]
    F32,
    #[serde(alias = "I64", alias = "int64")]
    I64,
    #[serde(alias = "U64", alias = "uint64")]
    U64,
    #[serde(alias = "F64", alias = "double")]
    F64,
    /// A pointer-sized value (8 bytes on x86-64).
    #[serde(alias = "PTR", alias = "Ptr", alias = "pointer", alias = "usize")]
    Ptr,
}

impl ValueType {
    /// Number of bytes each value occupies in memory.
    pub fn size(&self) -> usize {
        match self {
            ValueType::I32 | ValueType::U32 | ValueType::F32 => 4,
            ValueType::I64 | ValueType::U64 | ValueType::F64 | ValueType::Ptr => 8,
        }
    }
}

/// A narrowing operation applied to a scan.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ScanOp {
    /// Keep addresses whose current value equals `value`.
    Exact { value: f64 },
    /// Keep addresses whose current value is in `[min, max]`.
    Range { min: f64, max: f64 },
    /// Keep addresses whose value changed since the last scan.
    Changed,
    /// Keep addresses whose value is unchanged since the last scan.
    Unchanged,
    /// Keep addresses whose value increased since the last scan.
    Increased,
    /// Keep addresses whose value decreased since the last scan.
    Decreased,
}

/// A persistent value scan over a process.
///
/// `matches` stores `(address, last_observed_value)` so that narrowing ops
/// (`Changed`/`Unchanged`/`Increased`/`Decreased`) can compare against the
/// previous read.
///
/// It is [`Serialize`]/[`Deserialize`] so the match set can be persisted to
/// disk between CLI invocations (that's what lets `trainlab-scanner next`
/// refine a previous `scan`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scan {
    value_type: ValueType,
    /// Byte alignment for candidate addresses (e.g. 4 or 8). 0/1 = any.
    alignment: usize,
    matches: Vec<(u64, f64)>,
}

impl Scan {
    /// Start a new scan of the given value type with an empty match set.
    pub fn new(value_type: ValueType) -> Self {
        Self {
            value_type,
            alignment: 0,
            matches: Vec::new(),
        }
    }

    /// Create a scan from a persisted value type and match set.
    pub fn from_parts(value_type: ValueType, matches: Vec<(u64, f64)>) -> Self {
        Self {
            value_type,
            alignment: 0,
            matches,
        }
    }

    /// Set the byte alignment for candidate addresses (0/1 = any).
    pub fn with_alignment(mut self, alignment: usize) -> Self {
        self.alignment = alignment;
        self
    }

    /// The byte alignment for candidate addresses (0/1 = any).
    pub fn alignment(&self) -> usize {
        self.alignment
    }

    /// The value type this scan operates on.
    pub fn value_type(&self) -> ValueType {
        self.value_type
    }

    /// The current match set as `(address, last_value)` pairs.
    pub fn matches(&self) -> &[(u64, f64)] {
        &self.matches
    }

    /// Number of addresses currently in the match set.
    pub fn len(&self) -> usize {
        self.matches.len()
    }

    /// Whether the match set is empty.
    pub fn is_empty(&self) -> bool {
        self.matches.is_empty()
    }

    /// Perform the first scan: walk `regions`, read every value of
    /// `self.value_type`, and keep those satisfying `op`.
    ///
    /// This replaces the match set (it's the initial population).
    ///
    /// Performance: each region is **bulk-read** into a buffer in one syscall
    /// and scanned in memory, rather than one syscall per value. This matters
    /// a lot on large heaps (a Unity game can have hundreds of MB of heap; a
    /// per-value read would be millions of syscalls).
    pub fn first_scan<P: ProcessMemory + ?Sized>(
        &mut self,
        proc: &P,
        regions: &[crate::memory::Region],
        op: ScanOp,
    ) -> Result<usize, MemoryError> {
        let size = self.value_type.size();
        let mut matches = Vec::new();
        for r in regions {
            if !r.readable {
                continue;
            }
            let start = r.start;
            let end = r.end;
            let len = (end - start) as usize;
            if len < size {
                continue;
            }
            // Ask the process to scan this region. `SelfProcess` overrides this
            // to scan in-place (no full-region copy); external processes use
            // the default bulk-read implementation.
            let m = proc.scan_region(r, size, self.alignment, self.value_type, op);
            matches.extend(m);
        }
        self.matches = matches;
        Ok(self.matches.len())
    }

    /// Narrow the existing match set by re-reading each address and keeping
    /// those that satisfy `op`.
    ///
    /// For `Changed`/`Unchanged`/`Increased`/`Decreased`, the comparison is
    /// against the value stored from the previous scan. For `Exact`/`Range`,
    /// the comparison is against the freshly-read value.
    pub fn refine<P: ProcessMemory + ?Sized>(
        &mut self,
        proc: &P,
        op: ScanOp,
    ) -> Result<usize, MemoryError> {
        let mut kept = Vec::with_capacity(self.matches.len());
        for (addr, prev) in &self.matches {
            if let Ok(cur) = read_value(proc, *addr, self.value_type)
                && op_matches(op, *prev, cur, self.value_type) {
                    kept.push((*addr, cur));
            }
        }
        self.matches = kept;
        Ok(self.matches.len())
    }
}

/// Read a single value of `value_type` at `address` as an `f64`.
fn read_value<P: ProcessMemory + ?Sized>(
    proc: &P,
    address: u64,
    value_type: ValueType,
) -> Result<f64, MemoryError> {
    let size = value_type.size();
    let buf = proc.read(address, size)?;
    Ok(buf_to_f64(&buf, value_type))
}

/// Interpret a little-endian byte slice as `value_type` and return it as `f64`.
///
/// `buf` must be at least `value_type.size()` bytes long.
fn buf_to_f64(buf: &[u8], value_type: ValueType) -> f64 {
    match value_type {
        ValueType::I32 => i32::from_le_bytes(buf[..4].try_into().unwrap()) as f64,
        ValueType::U32 => u32::from_le_bytes(buf[..4].try_into().unwrap()) as f64,
        ValueType::F32 => f32::from_le_bytes(buf[..4].try_into().unwrap()) as f64,
        ValueType::I64 => i64::from_le_bytes(buf[..8].try_into().unwrap()) as f64,
        ValueType::U64 => u64::from_le_bytes(buf[..8].try_into().unwrap()) as f64,
        ValueType::F64 => f64::from_le_bytes(buf[..8].try_into().unwrap()),
        ValueType::Ptr => u64::from_le_bytes(buf[..8].try_into().unwrap()) as f64,
    }
}

/// Decide whether a value satisfies `op`. `prev` is the last observed value
/// (used only by the change ops); `cur` is the freshly-read value.
fn op_matches(op: ScanOp, prev: f64, cur: f64, value_type: ValueType) -> bool {
    match op {
        ScanOp::Exact { value } => match value_type {
            ValueType::F32 => (cur as f32 - value as f32).abs() < 1e-4,
            ValueType::F64 => (cur - value).abs() < 1e-7,
            _ => cur == value,
        },
        ScanOp::Range { min, max } => match value_type {
            ValueType::F32 => (cur as f32) >= (min as f32) && (cur as f32) <= (max as f32),
            _ => cur >= min && cur <= max,
        },
        ScanOp::Changed => match value_type {
            ValueType::F32 => (cur as f32) != (prev as f32),
            _ => cur != prev,
        },
        ScanOp::Unchanged => match value_type {
            ValueType::F32 => (cur as f32 - prev as f32).abs() < 1e-4,
            ValueType::F64 => (cur - prev).abs() < 1e-7,
            _ => cur == prev,
        },
        ScanOp::Increased => match value_type {
            ValueType::F32 => (cur as f32) > (prev as f32),
            _ => cur > prev,
        },
        ScanOp::Decreased => match value_type {
            ValueType::F32 => (cur as f32) < (prev as f32),
            _ => cur < prev,
        },
    }
}

/// Default chunk size for streaming memory scans (2 MB).
pub const DEFAULT_CHUNK_SIZE: usize = 2 * 1024 * 1024;

/// Metrics returned after completing a scan over multiple memory regions.
#[derive(Debug, Clone, Default)]
pub struct ScanMetrics {
    pub regions_scanned: usize,
    pub bytes_scanned: u64,
    pub unreadable_chunks: usize,
}

/// Stream across memory `region` in bounded chunks of size `chunk_size`, maintaining an
/// `overlap` of bytes between adjacent chunks so multi-byte values / patterns straddling
/// a chunk boundary are not missed.
///
/// If a large chunk read fails (e.g. hitting a guard page or uncommitted tail page), it falls
/// back to reading in 4 KB pages so readable pages are not abandoned.
pub fn scan_region_chunks<P: ProcessMemory + ?Sized, F>(
    proc: &P,
    region: &crate::memory::Region,
    chunk_size: usize,
    overlap: usize,
    mut on_chunk: F,
) -> (u64, usize)
where
    F: FnMut(u64, &[u8]),
{
    let mut total_bytes = 0u64;
    let mut skipped_chunks = 0usize;
    let chunk_size = chunk_size.max(4096);
    let mut cur = region.start;
    let end = region.end;

    while cur < end {
        let max_to_read = (end - cur) as usize;
        let read_len = max_to_read.min(chunk_size + overlap);

        match proc.read(cur, read_len) {
            Ok(buf) if !buf.is_empty() => {
                let actual_len = buf.len();
                total_bytes += actual_len as u64;
                on_chunk(cur, &buf);

                // Advance by (actual_len - overlap) to maintain boundary overlap on the next chunk
                let advance = if actual_len > overlap {
                    actual_len - overlap
                } else {
                    actual_len
                };
                cur += advance as u64;
            }
            _ => {
                // If a large chunk read failed, try walking page-by-page (4KB) through this chunk
                let page_size = 4096;
                let page_limit = cur.saturating_add(chunk_size as u64).min(end);
                let mut page_addr = cur;
                while page_addr < page_limit {
                    let page_to_read = (page_limit - page_addr) as usize;
                    let page_len = page_to_read.min(page_size + overlap);
                    match proc.read(page_addr, page_len) {
                        Ok(pbuf) if !pbuf.is_empty() => {
                            let pactual = pbuf.len();
                            total_bytes += pactual as u64;
                            on_chunk(page_addr, &pbuf);
                            let padvance = if pactual > overlap {
                                pactual - overlap
                            } else {
                                pactual
                            };
                            page_addr += padvance as u64;
                        }
                        _ => {
                            skipped_chunks += 1;
                            page_addr += page_size as u64;
                        }
                    }
                }
                cur = page_limit;
            }
        }
    }
    (total_bytes, skipped_chunks)
}

/// Scan a byte buffer for values of `value_type` satisfying `op`, starting at
/// `base` address, respecting `alignment`. Returns `(address, value)` pairs.
///
/// This is the shared scanning core used by both the default bulk-read
/// [`ProcessMemory::scan_region`] and `SelfProcess`'s in-place override.
pub(crate) fn scan_buffer(
    buf: &[u8],
    base: u64,
    size: usize,
    alignment: usize,
    value_type: ValueType,
    op: ScanOp,
) -> Vec<(u64, f64)> {
    let mut out = Vec::new();
    if buf.len() < size {
        return out;
    }
    let step = if alignment > 0 { alignment } else { 1 };
    let end_offset = buf.len() - size;

    let mut offset = 0;
    while offset <= end_offset {
        let addr = base + offset as u64;
        if alignment > 1 && !addr.is_multiple_of(alignment as u64) {
            let rem = (addr % (alignment as u64)) as usize;
            offset += alignment - rem;
            continue;
        }
        let v = buf_to_f64(&buf[offset..offset + size], value_type);
        if op_matches(op, v, v, value_type) {
            out.push((addr, v));
        }
        offset += step;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{MemoryError, ProcessMemory, Region};
    use std::cell::RefCell;

    /// A mock process backed by a byte buffer, so we can test scan logic
    /// without a real OS process.
    struct MockProcess {
        buf: RefCell<Vec<u8>>,
    }

    impl MockProcess {
        fn new(buf: Vec<u8>) -> Self {
            Self {
                buf: RefCell::new(buf),
            }
        }
    }

    impl ProcessMemory for MockProcess {
        fn read(&self, address: u64, len: usize) -> Result<Vec<u8>, MemoryError> {
            let b = self.buf.borrow();
            let start = address as usize;
            if start + len > b.len() {
                return Err(MemoryError::OutOfRange { address });
            }
            Ok(b[start..start + len].to_vec())
        }
        fn write(&self, address: u64, data: &[u8]) -> Result<usize, MemoryError> {
            let mut b = self.buf.borrow_mut();
            let start = address as usize;
            if start + data.len() > b.len() {
                return Err(MemoryError::OutOfRange { address });
            }
            b[start..start + data.len()].copy_from_slice(data);
            Ok(data.len())
        }
        fn regions(&self) -> Result<Vec<Region>, MemoryError> {
            Ok(vec![Region {
                start: 0,
                end: self.buf.borrow().len() as u64,
                readable: true,
                writable: true,
                executable: false,
                name: None,
            }])
        }
    }

    fn region() -> Region {
        Region {
            start: 0,
            end: 64,
            readable: true,
            writable: true,
            executable: false,
            name: None,
        }
    }

    fn region_to(len: u64) -> Region {
        Region {
            start: 0,
            end: len,
            readable: true,
            writable: true,
            executable: false,
            name: None,
        }
    }

    #[test]
    fn first_scan_exact_i32() {
        // 16 i32 values: 0..15
        let mut buf = Vec::new();
        for i in 0..16i32 {
            buf.extend_from_slice(&i.to_le_bytes());
        }
        let proc = MockProcess::new(buf);
        let mut scan = Scan::new(ValueType::I32);
        let n = scan
            .first_scan(&proc, &[region()], ScanOp::Exact { value: 7.0 })
            .unwrap();
        assert_eq!(n, 1);
        assert_eq!(scan.matches()[0].0, 7 * 4);
    }

    #[test]
    fn first_scan_range_u32() {
        let mut buf = Vec::new();
        for i in 0..16u32 {
            buf.extend_from_slice(&i.to_le_bytes());
        }
        let proc = MockProcess::new(buf);
        let mut scan = Scan::new(ValueType::U32);
        let n = scan
            .first_scan(&proc, &[region()], ScanOp::Range { min: 5.0, max: 9.0 })
            .unwrap();
        assert_eq!(n, 5); // 5,6,7,8,9
    }

    #[test]
    fn first_scan_range_f32_fractional() {
        // Simulate a game resource stored as f32 with a fractional part that
        // the UI rounds to a whole number: 14790.3, 14790.0, 14791.7, 14792.5.
        let vals = [14790.3f32, 14790.0, 14791.7, 14792.5];
        let mut buf = Vec::new();
        for v in vals {
            buf.extend_from_slice(&v.to_le_bytes());
        }
        let proc = MockProcess::new(buf);
        let mut scan = Scan::new(ValueType::F32);
        // Range 14760..14820 should catch all four (they're all in [14760,14820]).
        let n = scan
            .first_scan(&proc, &[region_to(16)], ScanOp::Range { min: 14760.0, max: 14820.0 })
            .unwrap();
        assert_eq!(n, 4);
        // A tighter range 14790.0..14790.5 should catch only 14790.0 and 14790.3.
        let mut scan = Scan::new(ValueType::F32);
        let n = scan
            .first_scan(&proc, &[region_to(16)], ScanOp::Range { min: 14790.0, max: 14790.5 })
            .unwrap();
        assert_eq!(n, 2);
    }

    #[test]
    fn refine_unchanged_and_changed() {
        // 8 i32 values, all 100.
        let mut buf = Vec::new();
        for _ in 0..8i32 {
            buf.extend_from_slice(&100i32.to_le_bytes());
        }
        let proc = MockProcess::new(buf);
        let mut scan = Scan::new(ValueType::I32);
        scan.first_scan(&proc, &[region_to(32)], ScanOp::Exact { value: 100.0 })
            .unwrap();
        let mut scan2 = Scan::new(ValueType::I32);
        scan2
            .first_scan(&proc, &[region_to(32)], ScanOp::Exact { value: 100.0 })
            .unwrap();
        assert_eq!(scan.len(), 8);
        assert_eq!(scan2.len(), 8);

        // Change the value at index 3 (address 12) to 200.
        proc.write(12, &200i32.to_le_bytes()).unwrap();

        // Unchanged keeps 7 (all but index 3).
        let n = scan.refine(&proc, ScanOp::Unchanged).unwrap();
        assert_eq!(n, 7);
        assert!(!scan.matches().iter().any(|(a, _)| *a == 12));

        // Changed keeps exactly the one that moved.
        let n = scan2.refine(&proc, ScanOp::Changed).unwrap();
        assert_eq!(n, 1);
        assert_eq!(scan2.matches()[0].0, 12);
    }

    #[test]
    fn refine_increased_decreased() {
        let mut buf = Vec::new();
        for _ in 0..4i32 {
            buf.extend_from_slice(&50i32.to_le_bytes());
        }
        let proc = MockProcess::new(buf);

        // Two scans, both baselined while all four addresses hold 50.
        let mut scan_inc = Scan::new(ValueType::I32);
        scan_inc
            .first_scan(&proc, &[region_to(16)], ScanOp::Exact { value: 50.0 })
            .unwrap();
        let mut scan_dec = Scan::new(ValueType::I32);
        scan_dec
            .first_scan(&proc, &[region_to(16)], ScanOp::Exact { value: 50.0 })
            .unwrap();
        assert_eq!(scan_inc.len(), 4);
        assert_eq!(scan_dec.len(), 4);

        // addr 0 -> 60 (increased), addr 4 -> 40 (decreased), addr 8 -> 50 (same)
        proc.write(0, &60i32.to_le_bytes()).unwrap();
        proc.write(4, &40i32.to_le_bytes()).unwrap();

        let n = scan_inc.refine(&proc, ScanOp::Increased).unwrap();
        assert_eq!(n, 1);
        assert_eq!(scan_inc.matches()[0].0, 0);

        let n = scan_dec.refine(&proc, ScanOp::Decreased).unwrap();
        assert_eq!(n, 1);
        assert_eq!(scan_dec.matches()[0].0, 4);
    }

    #[test]
    fn f64_scan() {
        let mut buf = Vec::new();
        for i in 0..8u64 {
            buf.extend_from_slice(&(i as f64).to_le_bytes());
        }
        let proc = MockProcess::new(buf);
        let mut scan = Scan::new(ValueType::F64);
        let n = scan
            .first_scan(&proc, &[region()], ScanOp::Exact { value: 3.0 })
            .unwrap();
        assert_eq!(n, 1);
        assert_eq!(scan.matches()[0].0, 3 * 8);
    }

    #[test]
    fn ptr_scan() {
        // 4 pointer values: 0x1000, 0x2000, 0x3000, 0x4000
        let mut buf = Vec::new();
        for v in [0x1000u64, 0x2000, 0x3000, 0x4000] {
            buf.extend_from_slice(&v.to_le_bytes());
        }
        let proc = MockProcess::new(buf);
        let mut scan = Scan::new(ValueType::Ptr);
        let n = scan
            .first_scan(&proc, &[region_to(32)], ScanOp::Exact { value: 0x3000 as f64 })
            .unwrap();
        assert_eq!(n, 1);
        assert_eq!(scan.matches()[0].0, 2 * 8);
    }

    #[test]
    fn i64_scan() {
        let mut buf = Vec::new();
        for v in [0i64, 1, -1, 2] {
            buf.extend_from_slice(&v.to_le_bytes());
        }
        let proc = MockProcess::new(buf);
        let mut scan = Scan::new(ValueType::I64);
        let n = scan
            .first_scan(&proc, &[region_to(32)], ScanOp::Exact { value: -1.0 })
            .unwrap();
        assert_eq!(n, 1);
        assert_eq!(scan.matches()[0].0, 2 * 8);
    }

    #[test]
    fn alignment_filters_addresses() {        // 8 i32 values: 0..7
        let mut buf = Vec::new();
        for i in 0..8i32 {
            buf.extend_from_slice(&i.to_le_bytes());
        }
        let proc = MockProcess::new(buf);
        // Scan for value 3 with 8-byte alignment: addr 12 (index 3) is
        // 4-aligned but not 8-aligned, so it's filtered out.
        let mut scan = Scan::new(ValueType::I32).with_alignment(8);
        let n = scan
            .first_scan(&proc, &[region_to(32)], ScanOp::Exact { value: 3.0 })
            .unwrap();
        assert_eq!(n, 0); // addr 12 is not 8-aligned

        // With 4-byte alignment (default), addr 12 matches.
        let mut scan4 = Scan::new(ValueType::I32);
        let n4 = scan4
            .first_scan(&proc, &[region_to(32)], ScanOp::Exact { value: 3.0 })
            .unwrap();
        assert_eq!(n4, 1);
        assert_eq!(scan4.matches()[0].0, 12);
    }

    #[test]
    fn scan_buffer_shared_core() {
        // 8 i32 values: 0..7
        let mut buf = Vec::new();
        for i in 0..8i32 {
            buf.extend_from_slice(&i.to_le_bytes());
        }
        let found = scan_buffer(&buf, 0x1000, 4, 0, ValueType::I32, ScanOp::Exact { value: 5.0 });
        assert_eq!(found, vec![(0x1000 + 5 * 4, 5.0)]);
        // range
        let found = scan_buffer(&buf, 0, 4, 0, ValueType::I32, ScanOp::Range { min: 2.0, max: 4.0 });
        assert_eq!(found.len(), 3);
    }

    #[test]
    fn scan_region_chunks_overlap_and_boundary_crossing() {
        // Create 10000 bytes with a target value 0xDEADBEEF placed exactly at offset 4094
        // (straddling a 4096-byte boundary).
        let mut buf = vec![0u8; 10000];
        let target_val = 0xDEADBEEFu32;
        buf[4094..4098].copy_from_slice(&target_val.to_le_bytes());

        let proc = MockProcess::new(buf);
        let region = Region {
            start: 0,
            end: 10000,
            readable: true,
            writable: true,
            executable: false,
            name: None,
        };

        // Scan in 4096-byte chunks with 3 bytes of overlap
        let mut hits = Vec::new();
        let (scanned, skipped) = scan_region_chunks(&proc, &region, 4096, 3, |chunk_base, chunk_buf| {
            let m = scan_buffer(chunk_buf, chunk_base, 4, 0, ValueType::U32, ScanOp::Exact { value: target_val as f64 });
            hits.extend(m);
        });

        assert_eq!(skipped, 0);
        assert!(scanned >= 10000);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, 4094);
    }
}
