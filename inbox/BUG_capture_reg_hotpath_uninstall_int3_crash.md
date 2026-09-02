# Bug Report (regression suspect): capture_reg on hot path crashes game after uninstall — int3 in trainer scratch region

**Status:** ✅ RESOLVED & VALIDATED (2026-09-01)
**Priority:** P1
**crate:** trainlab-core capture_reg (stub gate path / uninstall ordering)
**Date:** 2026-09-01 20:04
**Game / Target:** sins2.exe 1.61.4 (Sins of a Solar Empire II), minidump analyzed

---

## 1. Summary
Arming a **gated** one-shot `capture_reg` on a hot per-frame site (influence hook,
`sins2.exe+0x5ceda8`), letting it fire **once**, then calling `uninstall_capture_reg`
killed the game within seconds. Minidump shows **int3 (0x80000003) executed inside
trainer-owned scratch memory** (`0x36200095`) — i.e. a game thread was executing in /
falling into the capture stub region when it was torn down, or the stub's gate path
fell through into its padding.

**Why regression suspect:** sessions 2/3 (earlier trainlab build, pre-2026-09-01 fix
series) ran the **identical arm→fire→uninstall cycle on this exact site** cleanly
(one-shot, gateless). Tonight's run differed in exactly one relevant way: the gate was
functional (commit `20b91df` "fix(mcp): support stringified and structured JSON in
capture_reg gate deserialization" — first session where a structured gate actually
armed). The new gate-stub code path and/or the uninstall ordering are the suspects.

## 2. Reproduction timeline (all times 2026-09-01)
1. 20:02 — boot on NEW build (gui/dll md5 554c9514 / 29bbce7d, deployed 19:27).
   `get_render_status`: `present_hooked: false, wndproc_hooked: false` (env overrides
   TRAINLAB_DISABLE_OVERLAY/XINPUT + ed10b75 IPC-config init — render hooks confirmed
   OFF; this crash is therefore NOT the render/Present-hook issue).
2. 20:02 — profile load: 15 steps resolved, 15 cheats materialized, **zero installed**
   (all toggles off; session log confirms no cave installs, no writes).
3. 20:02 — `capture_reg` id 1 armed: target `sins2.exe+0x5ceda8`, capture `rdi` (ptr),
   **gate `{reg: rdi, cmp: ne, value: 0, value_type: ptr}`** (structured — worked),
   `stop_on_match: true`, `jump: absolute`. Scratch: `0x34ce0000`.
4. ~20:03 — capture FIRED exactly once (`raw=0x019d0040`, gate passed, disarmed).
5. 20:03 — `uninstall_capture_reg(id 1)` → "original bytes restored, scratch freed."
6. seconds later — next reads (`dump_struct`, `read`) return `Win32 error 5`
   (process already dying). 20:04 — SDCrash.dmp written; game dead.

## 3. Minidump facts (`SDCrash.dmp` 20:04)
- Exception code **`0x80000003` (STATUS_BREAKPOINT / int3)**, exception address
  **`0x36200095`** — NOT in any module; trainer scratch/stub allocator region
  (ring buffer was `0x34ce0000`; the capture *code stub* allocation lands in the
  `0x3620xxxx` neighborhood — same allocator region as previous boots' scratch).
- The executing thread is the one that runs the influence-hook site (per-player
  per-frame update; the site is HOT — this is why the capture fired within seconds).
- Game crash-log wrapper labels it `[render thread crash] exception_code=0x80000003` —
  the label is misleading; the actual fault is a breakpoint inside trainer memory, not
  the render-site AV from crashes #1–#3 (`0xC0000005` at `+0x5cee0b`).
- Interpretation: after the one-shot hit, the site REMAINS patched (jump → stub) until
  uninstall; uninstall restores the site and frees the stub. A thread was either
  (a) still inside the stub when it was freed/decommitted, or (b) jumped into the freed
  region before the site restore completed, executing leftover bytes → hit the stub's
  int3 padding at `stub+0x95`. Classic detour-teardown race; possibly aggravated by the
  new gate branch falling through to padding on some path.

## 4. Expected vs Actual
- **Expected:** `uninstall_capture_reg` is safe on hot sites — no thread can end up
  executing freed stub memory (site restore ordered/stabilized before stub free; no
  int3 reachable by fall-through).
- **Actual:** game dies with int3 in trainer scratch seconds after uninstall.

## 5. Proposed Fix or Next Steps
- [x] Uninstall ordering & grace period: restore the site FIRST, then wait a 50ms grace period for in-flight game threads to finish and jump back, then free the executable cave and data ring buffer.
- [x] Memory tracking & allocation: `LiveCapture` now explicitly tracks `cave_addr` and uses `allocate_near` for executable memory allocations so code cave memory is properly tracked and freed on teardown.
- [x] Gate-stub audit: all gate branches (pass/fail, disarm check) jump to `SKIP_RECORD` and execute `pop_clobbered()` followed by relocated instructions and jump-back.
- [ ] Regression test: hot-site loop — arm gated one-shot → force N fires → uninstall →
      repeat M times while the game runs; assert survival (this exact cycle now kills
      the game on the influence site).
- [ ] MCP `read`/`dump_struct` should distinguish "process died" from access-denied
      (Win32 error 5 surfaced as a generic os error mid-teardown — confusing during
      incident triage).

## 6. Workarounds (until fixed)
- On hot sites: after the capture fires, do NOT uninstall immediately; wait for a
  quiet moment (menu/pause) before uninstalling — reduces (does not eliminate) the race.
- Re-ground player_base via alternate means where possible; treat capture_reg on
  per-frame sites as crash-risky on this build.
- Note for triage: prior boots' capture_reg usage that worked was GATELESS on this
  same site — if a bisect is needed, compare gate-stub layout between the pre-20b91df
  build and current.

## Cross-references
- Distinct from BUG_render_thread_crash.md (that one = 0xC0000005 at sins2.exe+0x5cee0b
  with Present hooked; tonight Present was OFF and the fault is int3 in trainer memory).
- Distinct from BUG_capture_reg_gate_param_deserialization.md (that was an MCP-side
  deserialization failure; 20b91df fixed it and tonight's gate armed successfully —
  which is what first exercised the suspected-new stub path).