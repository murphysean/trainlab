# TODO — Code-Review Fixes

Fixes arising from the 2026-08-23 code review (`docs/CODE_REVIEW.md`). These are
**correctness / consistency** work, not new capability. Grouped by theme; within
a group, work roughly top-down. Task IDs continue the build-playbook numbering
(after T-070) starting at T-100.

## Legend

- **[P0]** — correctness / safety bug: the code does the wrong thing or can
  lose/corrupt state. Fix first.
- **[P1]** — frontend-parity / consistency gap: behavior differs across
  egui / MCP / web for no good reason.
- **[P2]** — robustness / hygiene: silent failures, dead code, doc drift.
- **crate:** the crate(s) touched. Most fixes live in `trainlab-gui`.

## Reading guide

Each item lists: **symptom** (what's wrong), **where** (file:line), and
**fix** (the concrete change). Where a decision is needed, it's flagged
**"DECIDE."**

---

## A. The D8 mutation story (decide, then enforce everywhere)

**DECISION (2026-08-23): Profile commands (init_commands, button cheats) are
trusted code. D8 staging does NOT apply to them. The user/agent sending
connect/load_profile is OK with executing init everything. Undo snapshots
are still recorded for safety. D8 gate applies only to ad-hoc MCP tools
(write, install_cave, undo, set_cheat_value, set_cheat_toggle).**

- [x] **T-100 [P0] Decide the trust model for profile commands** (`crate: trainlab-gui`, docs)
  - **Decision:** profile commands are **trusted code** (option a).
  - Documented in `CHEAT_PROFILE.md` §9 and `DESIGN_DECISIONS.md` D11.

- [x] **T-101 [P0] Record undo snapshots for profile-command writes/caves** (`crate: trainlab-gui`)
  - `execute_profile_commands` Write arm now reads original bytes before writing
    and calls `record_undo`. InstallCave arm records undo from `CaveInstalled.original`.

- [x] **T-102 [P0] Don't lose a staged op when `confirm_op` fails** (`crate: trainlab-gui`)
  - `confirm_op` now peeks the op, applies it, and only removes from `pending_ops`
    on success. On failure, the op stays staged for retry or reject.

---

## B. Toggle cheats (cave on/off) actually work

- [x] **T-110 [P0] Implement toggle-off (cave restore)** (`crate: trainlab-gui`)
  - `CheatKind::Toggle` now has `original_bytes` + `cave_addr` fields.
  - On enable (confirm_op), `set_toggle_cave_info` stores the original bytes.
  - On disable, `set_cheat_toggle` stages an `Undo` with the real original bytes.
  - GUI toggle + hotkey both install/restore the real cave.

- [x] **T-111 [P0] Flip `enabled` in the MCP toggle path** (`crate: trainlab-gui`)
  - `confirm_op` now calls `set_cheat_toggle(id, true/false)` on success for
    toggle ops (tracked via `PendingOp.cheat_id`).

- [x] **T-112 [P1] Make GUI/hotkey toggle drive the real cave** (`crate: trainlab-gui`)
  - GUI checkbox + hotkey now install the cave on enable and restore original
    bytes on disable, via `Request::InstallCave` / `Request::Write`.

---

## C. Web/REST can confirm, and stops misreporting

- [x] **T-120 [P0] Add confirm/reject/pending endpoints** (`crate: trainlab-gui` `api.rs`)
  - Added `GET /api/pending`, `POST /api/confirm_op`, `POST /api/reject_op`.

- [x] **T-121 [P0] Stop claiming staged ops applied** (`crate: trainlab-gui` `api.rs` + `web/index.html`)
  - Staging routes now return `{"status":"staged","pending_id":N}`.
  - Web dashboard shows a Pending Operations panel with Confirm/Reject buttons.

- [x] **T-122 [P1] Lock handling consistent in `api.rs`** (`crate: trainlab-gui`)
  - All `.lock().unwrap()` replaced with `lock_session_or_500()` helper that
    returns a 500 `ApiError` on poison.

---

## D. YAML intake correctness (the semantic bugs)

- [x] **T-130 [P0] `Assert` actually compares concrete values** (`crate: trainlab-gui`)
  - Assert now parses `expected` per `value_type` and compares byte-for-byte.
  - Errors with got-vs-expected on mismatch.

- [x] **T-131 [P0] `PointerChase` command errors on bad offsets** (`crate: trainlab-gui`)
  - Offsets now parsed via `collect::<Result<Vec<_>, _>>()` — errors name the
    bad offset instead of silently dropping it.

- [x] **T-132 [P1] `resolve_cheat_address` tries all refs before failing** (`crate: trainlab-gui`)
  - Now tries every ref; only errors after all are exhausted, collecting which
    refs were tried into the error message.

- [x] **T-133 [P1] Consistent `hook` parsing (no silent trampoline)** (`crate: trainlab-gui`)
  - `execute_profile_commands` now accepts only `"trampoline"`/`"override"` and
    errors otherwise, matching `load_profile`.

- [x] **T-134 [P1] Untangle `setup` vs `init_commands`** (`crate: trainlab-gui`, docs)
  - GUI "Re-run Initialization" now runs setup (run_setup=true) and init_commands
    independently. Documented in `CHEAT_PROFILE.md`.

- [x] **T-135 [P1] Add `validate_profile` (dry-run) tool** (`crate: trainlab-gui`)
  - Added `validate_profile` MCP tool: read-only dry-run that parses the profile,
    resolves refs, validates hex/value types/hook kinds, reports errors.

---

## E. Initialization consistency across frontends

- [x] **T-140 [P1] Honor `auto_init`** (`crate: trainlab-gui`)
  - GUI attach now gates profile init on `self.auto_init`.

- [x] **T-141 [P1] One documented attach→init flow for all frontends** (`crate: trainlab-gui`, docs)
  - Documented in `CHEAT_PROFILE.md` §5 and `ARCHITECTURE.md`.
  - `attach_game` does NOT trigger profile init; `load_profile` does the full flow.

- [x] **T-142 [P1] Don't set `connected` when nothing attached** (`crate: trainlab-gui`)
  - `load_profile` no longer unconditionally calls `set_connected(true)`.

- [x] **T-143 [P1] Surface `load_profile` result detail** (`crate: trainlab-gui`)
  - `load_profile_by_name` now returns the detailed text (resolved addresses, counts).
  - GUI attach + re-run now log success and failure distinctly.

- [x] **T-144 [P1] Move attach/scan/button off the GUI render thread** (`crate: trainlab-gui`)
  - `find_inject_connect`, memory scanning (First Scan / Next Scan), and profile command buttons now execute on background worker threads with atomic in-flight guard flags (`is_attaching`, `is_scanning`) and UI spinner feedback, keeping the egui frame loop completely unblocked.

---

## F. Event-bus emission parity

- [x] **T-150 [P1] Emit events for all mutations** (`crate: trainlab-gui`)
  - `remove_cheat` now emits `CheatUpdated`. "Clear all" emits `ProfileLoaded`
    with 0 cheats. `confirm_op` requests repaint.

- [x] **T-151 [P1] `confirm_op` requests repaint; GUI Apply emits `CheatUpdated`** (`crate: trainlab-gui`)
  - `confirm_op` calls `request_repaint` on success.
  - GUI value-cheat Apply emits `CheatUpdated{value}` after writing.

---

## G. Protocol-layer hygiene + security

- [x] **T-160 [P1] `call_dll` honors session host/port + add timeouts** (`crate: trainlab-gui`)
  - `call_dll` now takes `&SharedSession` and reads `dll_host`/`dll_port` from it
    (falling back to `127.0.0.1:31337`). All call sites updated.

- [x] **T-161 [P1] Guard `format_value` against short reads** (`crate: trainlab-gui`)
  - `format_value` now length-checks before decoding; returns `"?"` on short read.

- [x] **T-162 [P2] Document LAN exposure + optional bind/token guard** (`crate: trainlab-gui`, docs)
  - Security note added to `LAUNCHING.md` and `ARCHITECTURE.md`.

- [x] **T-163 [P2] Fix window double-toggle + stale comment** (`crate: trainlab-gui`)
  - Removed focused `J` key handler (global hotkey ID 9999 already handles it).
  - Fixed stale comment (was `[`, now `J`).

- [x] **T-164 [P2] Clean up small wart list** (`crate: trainlab-gui`)
  - `MarkerDto`/`ScanMatchDto` `address_hex` now `#[serde(skip_serializing)]`.
  - `get_profiles` now `spawn_blocking` (FS I/O off executor).
  - `allocate_string_in_game` returns error on non-Windows instead of fake address.
  - `mcp_addr` display + marker edit alias: left as-is (cosmetic, low priority).

---

## Deferred

- **T-144** — Move attach/scan/button off the GUI render thread. Requires
  worker-thread infrastructure + event-bus progress reporting. Larger change.