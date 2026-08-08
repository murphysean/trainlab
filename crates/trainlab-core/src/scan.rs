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

/// The width/interpretation of a scanned value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueType {
    I32,
    U32,
    F32,
    F64,
}

impl ValueType {
    /// Number of bytes each value occupies in memory.
    pub fn size(&self) -> usize {
        match self {
            ValueType::I32 | ValueType::U32 | ValueType::F32 => 4,
            ValueType::F64 => 8,
        }
    }
}

/// A narrowing operation applied to a scan.
#[derive(Debug, Clone, Copy, PartialEq)]
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
pub struct Scan {
    value_type: ValueType,
    matches: Vec<(u64, f64)>,
}

impl Scan {
    /// Start a new scan of the given value type with an empty match set.
    pub fn new(value_type: ValueType) -> Self {
        Self {
            value_type,
            matches: Vec::new(),
        }
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
    pub fn first_scan<P: ProcessMemory>(
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
            // Align the start of the region up to the value size so we don't
            // read misaligned values at the very edge.
            let start = r.start;
            let end = r.end;
            let mut addr = start;
            while addr + size as u64 <= end {
                match read_value(proc, addr, self.value_type) {
                    Ok(v) => {
                        if op_matches(op, v, v) {
                            matches.push((addr, v));
                        }
                    }
                    // A region may have changed or become unreadable mid-scan;
                    // skip the offending address and continue.
                    Err(_) => {}
                }
                addr += size as u64;
            }
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
    pub fn refine<P: ProcessMemory>(
        &mut self,
        proc: &P,
        op: ScanOp,
    ) -> Result<usize, MemoryError> {
        let mut kept = Vec::with_capacity(self.matches.len());
        for (addr, prev) in &self.matches {
            match read_value(proc, *addr, self.value_type) {
                Ok(cur) => {
                    if op_matches(op, *prev, cur) {
                        kept.push((*addr, cur));
                    }
                }
                // Address no longer readable (freed / unmapped): drop it.
                Err(_) => {}
            }
        }
        self.matches = kept;
        Ok(self.matches.len())
    }
}

/// Read a single value of `value_type` at `address` as an `f64`.
fn read_value<P: ProcessMemory>(
    proc: &P,
    address: u64,
    value_type: ValueType,
) -> Result<f64, MemoryError> {
    let size = value_type.size();
    let buf = proc.read(address, size)?;
    Ok(match value_type {
        ValueType::I32 => i32::from_le_bytes(buf.try_into().unwrap()) as f64,
        ValueType::U32 => u32::from_le_bytes(buf.try_into().unwrap()) as f64,
        ValueType::F32 => f32::from_le_bytes(buf.try_into().unwrap()) as f64,
        ValueType::F64 => f64::from_le_bytes(buf.try_into().unwrap()),
    })
}

/// Decide whether a value satisfies `op`. `prev` is the last observed value
/// (used only by the change ops); `cur` is the freshly-read value.
fn op_matches(op: ScanOp, prev: f64, cur: f64) -> bool {
    match op {
        ScanOp::Exact { value } => cur == value,
        ScanOp::Range { min, max } => cur >= min && cur <= max,
        ScanOp::Changed => cur != prev,
        ScanOp::Unchanged => cur == prev,
        ScanOp::Increased => cur > prev,
        ScanOp::Decreased => cur < prev,
    }
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
    fn refine_unchanged_and_changed() {
        // 8 i32 values, all 100.
        let mut buf = Vec::new();
        for _ in 0..8i32 {
            buf.extend_from_slice(&100i32.to_le_bytes());
        }
        let proc = MockProcess::new(buf);
        let mut scan = Scan::new(ValueType::I32);
        scan.first_scan(&proc, &[region()], ScanOp::Exact { value: 100.0 })
            .unwrap();
        let mut scan2 = Scan::new(ValueType::I32);
        scan2
            .first_scan(&proc, &[region()], ScanOp::Exact { value: 100.0 })
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
            .first_scan(&proc, &[region()], ScanOp::Exact { value: 50.0 })
            .unwrap();
        let mut scan_dec = Scan::new(ValueType::I32);
        scan_dec
            .first_scan(&proc, &[region()], ScanOp::Exact { value: 50.0 })
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
}
