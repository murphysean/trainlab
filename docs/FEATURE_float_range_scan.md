# Feature Request: Initial float scan within a range

**Status:** ✅ implemented (2026-08-17)
**Priority:** [P1]
**crate:** `trainlab-core` (scan), `trainlab-gui` (MCP `scan` tool)
**Requested by:** sins2 training session (2026-08-17)

## Problem

The MCP `scan` tool only supports an **exact** first scan:

```rust
// crates/trainlab-gui/src/mcp.rs, fn scan
let op = trainlab_core::scan::ScanOp::Exact { value: args.value };
```

For **float** values this is often useless in practice. Game resources are
frequently stored as `f32` with a **fractional part** that the UI rounds to a
whole number. Example from Sins of a Solar Empire II:

- UI shows **14790 credits**, income **+21.6/s**.
- The real stored value is something like `14790.3` (or `14790.0 + delta`),
  **not** exactly `14790.0`.
- `scan` for `f32 = 14790` → **0 matches**, even though the value is right
  there in memory.

The user has to guess the exact fractional value, which is impractical. The
classic Cheat Engine / scanmem workflow is to do an **initial range scan**
(e.g. `14760..14820`, i.e. `14790 ± 30`) to catch the float, then narrow.

## What already exists

The core scan engine **already supports range** — it's just not exposed on the
initial `scan` tool:

```rust
// crates/trainlab-core/src/scan.rs
pub enum ScanOp {
    Exact { value: f64 },
    Range { min: f64, max: f64 },   // <-- already here
    Changed,
    Unchanged,
    Increased,
    Decreased,
}
```

And `first_scan` already takes a `ScanOp`:

```rust
pub fn first_scan<P: ProcessMemory + ?Sized>(
    &mut self,
    proc: &P,
    regions: &[crate::memory::Region],
    op: ScanOp,   // <-- already accepts Range
) -> Result<usize, MemoryError>
```

The `next` tool already supports `range` (min + max). Only the **initial**
`scan` tool is hardcoded to `Exact`.

## Requested change

Expose an optional `min`/`max` (or a `range` flag) on the MCP `scan` tool so
the **first** scan can be a range scan, matching what `next` already does.

### Proposed MCP `scan` args

```rust
pub struct ScanArgs {
    pub value_type: String,
    /// For exact: the value. For range: the min.
    pub value: f64,
    /// For range: the max (optional; if present, do a range scan).
    pub max: Option<f64>,
    pub alignment: Option<usize>,
}
```

Behavior:
- If `max` is `None` → `ScanOp::Exact { value }` (current behavior, backward
  compatible).
- If `max` is `Some` → `ScanOp::Range { min: value, max }`.

### Core change (if any)

`Scan::first_scan` already handles `Range`, so likely **no core change** — just
wire the MCP arg through. Verify `first_scan`'s `Range` path is correct for
floats (it should compare `min <= v <= max`).

## Acceptance criteria

1. `scan` with `value_type: "f32"`, `value: 14760`, `max: 14820` returns
   addresses whose f32 value is in `[14760, 14820]`.
2. `scan` with no `max` still does an exact scan (no regression).
3. The result set can be narrowed with `next` (changed/unchanged/exact/range)
   as usual.
4. Unit test in `trainlab-core/src/scan.rs` for a float range first-scan.

## Why this matters

Without it, float-based game values with fractional storage (very common:
resources, health, timers, rates) can't be found by an initial scan. This is
the single biggest blocker for the sins2 resource hunt and will recur in every
float-heavy game.

## Notes

- The user's workflow after this lands: `scan f32 14760..14820` → unpause →
  `next changed` → narrow to a handful → confirm the player struct.
- The `next` tool's `range` op already works; this just brings the initial
  scan up to parity.

## Implementation

- `ScanArgs` gained an optional `max: Option<f64>`. If present, the first
  scan uses `ScanOp::Range { min: value, max }`; if absent, it stays
  `ScanOp::Exact { value }` (backward compatible).
- No core change needed — `Scan::first_scan` already handled `Range`.
- Added `first_scan_range_f32_fractional` unit test in
  `trainlab-core/src/scan.rs` covering the sins2-style case (UI shows 14790,
  stored f32 is 14790.3).
