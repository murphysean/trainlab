# Bug Report: enabling a toggle with NO payload/asm installs a destructive empty override (game crash)

**Status:** ✅ RESOLVED & VALIDATED (2026-09-01)
**Priority:** P1
**Area:** trainlab-core cheats (materialize + set_cheat_toggle) / MCP
**Date:** 2026-09-01
**Game / Target:** sins2.exe 1.61.4 — crash reproduced, minidump analyzed

---

## 1. Summary & Context
A profile toggle cheat that has **neither `payload:` nor `asm:`** (a stub, e.g. awaiting
payload port) is *still enabled successfully* by `set_cheat_toggle`. The installed hook
is an **empty override cave**: the target's stolen instructions are skipped entirely and
nothing replays them. Any site whose stolen bytes carry required state (a register load,
a store) is then corrupted on the next execution → hard crash.

This converts any innocent enable of a stub/TODO toggle into a game crash. Expected
behavior: **refuse** (error) or install nothing (inert toggle + warning), never a
destructive skip.

## 2. Reproduction Steps
1. Profile toggle with no payload/asm, e.g.:
   ```yaml
   - id: fast_build_orbital
     label: "Fast Build Orbital Structures"
     kind: toggle
     target_ref: fast_build_orbital
     hook: override
     jump: relative
     note: "TODO: port payload"
   ```
2. `set_cheat_toggle(id, enabled=true)` → stages; `confirm_op` → **"confirmed cave ...
   (enable toggle cheat N) original saved (7 byte(s))"** — installs happily.
3. Game executes the site → crash.

## 3. Crash evidence (sins2, 2026-09-01 19:14)
- Target `fast_build_orbital` = `sins2.exe+0xd3db44`, 7 stolen bytes:
  `4d 8b b7 c8 00 00 00  mov r14,[r15+0xc8]` — the **only** load of `r14` before
  `+0xd3db4b: 41 0f 2f 76 18  comiss xmm6,[r14+0x18]`.
- Empty override cave → `r14` never loaded → `comiss` reads `[garbage+0x18]`.
- Minidump (`SDCrash.dmp`, wine-11.0): exception `0xC0000005 READ` at target `0x1a`
  (= garbage r14 ≈ 0x2 + 0x18), **exception address `0x140d3db4b`** = exactly the
  override return point (stolen-7 end).
- Session log shows the toggles staged (`pending id 2` for cheat 10) and the profile
  materialized with only `min_resources` carrying asm — i.e. the loaded profile had
  stub toggles.
- Note: dump thread context itself is garbled (RIP `0x9000000000000` — wine dump
  capture imperfection), but the exception address is authoritative and lands precisely
  on the hook return point.

Also confirmed with the sibling site: `fast_build_ships` (+0xdf0b7a, 5 stolen bytes
`mov eax,[rdx+0x38]; mov [rbx],eax`) ran ~6 s under the same empty override without
crashing (skipped write, state silently wrong) — i.e. the same bug corrupts game state
even when it doesn't crash.

## 4. Expected vs Actual Behavior
- **Expected:** toggling a cheat that has no executable behavior (no payload, no asm,
  no patch_bytes) either errors ("cheat has no payload — not enabled") or installs
  nothing. The cheat stays visible but inert.
- **Actual:** installs an empty override cave that swallows the stolen instructions.

## 5. Proposed Fix or Next Steps
- [x] In materialize/enable path: if `kind=toggle` and payload/asm are absent/empty →
      refuse with a clear error; do NOT patch memory.
- [x] Belt-and-braces: if a toggle's payload/asm is empty at *runtime* enable, log
      loudly + skip install (GUI toast + MCP error), leave site untouched.
- [x] GUI safeguards: stub toggles and empty patches are grayed out with a visible `(stub — no payload)` label.
- [x] Regression tests: `install_empty_override_fails_with_error` in `trainlab-cave` and `test_empty_toggle_override_fails_and_does_not_stage` in `trainlab-core` assert rejection with 0 writes and 0 undo log pollution.

## Notes for the agent
- Operator error was involved (enabling stubs intentionally as a smoke test — but under
  the assumption the loaded profile carried payloads; a stale deployed copy was actually
  loaded). The tool's job is to make that mistake harmless; today it made it fatal.
- Related docs: FEATURE_save_profile_preserve_setup_and_original_bytes.md (same
  materialization area), BUG_render_block_not_enforced_at_injection.md.
- Post-incident: local sins2.yaml (md5 2422df83) has real payloads for all 7 Phase A
  cheats; crash prevented none of that work. Deploy before load next time.