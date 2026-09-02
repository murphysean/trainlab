# Feature/Bug: save_profile drops setup steps (AOB patterns, original_bytes, context) — round-trip loses migration metadata

**Status:** ✅ RESOLVED (2026-09-01)
**Priority:** P2
**Area:** Profile Parser / save_profile (MCP + GUI + web)
**Date:** 2026-09-01
**Game / Target:** sins2.exe (Sins of a Solar Empire II v1.61.4)

---

## 1. Summary & Context
`save_profile` previously wrote a session back to YAML without active setup steps (writing `setup: []`) and lost symbolic marker names.

---

## 2. Solution Implemented
1. **Session-Level Setup & Profile Metadata Tracking**:
   - `SessionState` in `trainlab-core` now stores active `SetupStep` definitions, profile metadata (name, version, game_version, author, date, init_commands, render config).
   - `load_profile` in `trainlab-gui` populates this state via `s.set_active_profile(&profile)`.
2. **Symbolic Marker Resolution on Save**:
   - `execute_save_profile` builds an address-to-marker mapping and automatically maps cheat targets and base addresses back to their symbolic setup step names (e.g. `target_ref: research_hook`).
3. **Preservation of Original Bytes & Context**:
   - Retains `original_bytes` and `context` across setup steps and toggle/patch cheats.
4. **Regression Unit Test**:
   - Added `test_save_profile_preserves_setup_and_symbols` in `trainlab-core::tools::tests` verifying full preservation and roundtrip parsing.

---

## 5. Completed Items
- [x] `save_profile` serializes active setup steps (AOB patterns, offsets, regions, original_bytes, context).
- [x] Keep `target_ref` as the setup-step name when the target matches a named marker.
- [x] Retain `original_bytes` and metadata on cheats and setup steps.
- [x] Add round-trip regression test: `test_save_profile_preserves_setup_and_symbols`.

## Notes for the agent
The migration feature itself (original_bytes fallback on AOB mismatch) was verified
working live: a test profile with a deliberately broken `research_hook` pattern
(`DE AD BE EF...`) fell back to scanning original_bytes and resolved to the correct
`0x140b246b3`. Only the save side needs work.