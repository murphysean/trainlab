# Feature Request: bound AOB scan setup step to a region/module to avoid heap false-matches

**Status:** ✅ RESOLVED (2026-09-01)
**Priority:** P2
**crate:** trainlab (profile setup step `aob_scan`)
**Requested by:** sins2 (Sins of a Solar Empire II), 2026-09-01
**Date:** 2026-09-01

## Problem

The profile `aob_scan` setup step scans **all** readable memory and takes the **first**
match. For patterns that are not unique to the game's executable, this frequently grabs a
false match in a heap/scratch region instead of the intended module site. The resolved
marker then points at garbage, and any toggle cheat referencing it targets dead memory.

Concrete case (sins2, 1.61.4): the influence hook AOB `8B B7 ?? ?? ?? ?? 39 B3` has **3
matches** in the live process:

```
0x000000003fe30074   <- heap/scratch (trainlab's own alloc region)
0x00000000f6a3b910   <- heap
0x00000001405ceda8   <- REAL module site (sins2.exe+0x5ceda8)
```

`load_profile` resolved `$influence_hook` to `0x3fe30074` (the first match), so the
"Minimum Influence" toggle pointed at a scratch buffer. This happened **twice** in one
session before I worked around it by switching the setup step to a fixed `Address`.

## Repro

```yaml
# sins2.yaml setup step (before workaround)
- type: aob_scan
  name: influence_hook
  pattern: "8B B7 ?? ?? ?? ?? 39 B3"
  offset: 0

# load_profile → resolves to 0x3fe30074 (heap), not 0x1405ceda8 (module)
```

## Expected vs Actual

- **Expected:** the AOB scan is bound to the game's executable image (or a named region),
  so it only matches `sins2.exe` code and returns `0x1405ceda8`.
- **Actual:** scans all memory, returns the first (heap) match `0x3fe30074`.

## Resolution & Fix Summary

1. **Schema Extended in `trainlab-core` (`profile.rs`)**:
   - Added optional `region: Option<String>` field to `SetupStep::AobScan` and `ProfileCommand::AobScan`.
   - Supported in YAML cheat tables via `region: "sins2.exe"` or region marker names.
2. **Setup Step & Command Execution in `trainlab-gui` (`mcp.rs`)**:
   - `resolve_setup_step` and `apply_profile` command sequence now filter memory regions against `region` (module name or marker) before executing the pattern scan.
   - When `region` is specified, memory regions outside the target module/region boundaries are ignored, eliminating false heap/scratch matches.
3. **Unit Tests Added**:
   - Added `test_aob_scan_with_region_roundtrips_yaml` in `crates/trainlab-core/src/profile.rs`.

Example profile setup step:
```yaml
setup:
  - type: aob_scan
    name: influence_hook
    pattern: "8B B7 ?? ?? ?? ?? 39 B3"
    offset: 0
    region: "sins2.exe"
```

