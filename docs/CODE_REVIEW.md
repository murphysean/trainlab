# trainlab — Code Review

**Date:** 2026-08-23
**Scope:** architecture, purpose, the three frontends (egui GUI / MCP over HTTP / web REST), the event system, the YAML cheat-profile intake, and initialization consistency.
**Method:** full read of `trainlab-gui` (`main.rs`, `mcp.rs`, `api.rs`, `session.rs`, `profile.rs`, `controller.rs`, `event.rs`, `hotkeys.rs`, `inject.rs`, `web/index.html`), `trainlab-core::protocol`, and the design docs (`ARCHITECTURE.md`, `DESIGN_DECISIONS.md`, `CHEAT_PROFILE.md`, `CONCEPTS.md`).

---

## 1. Purpose — what trainlab is meant to do

trainlab is an **LLM-agent–driven trainer framework** for Windows games running
under **Wine/Proton** (Steam Deck / Linux target, developed on Linux). Its
distinguishing idea: instead of a human hand-driving Cheat Engine, an **agent
(via MCP)** does the reversing loop (value-scan → pointer-chase → find-writes →
code-cave), while a **human** confirms mutations and adjusts the discovered
cheats in a GUI.

Three architectural layers:

```
LLM / agent ──MCP over HTTP──▶ trainlab-gui  (hub: injector + MCP server + proxy + session state)
                                  │  fast channel (TCP, bincode, 4-byte LE length-prefixed)
                                  ▼
                           trainlab-inject.dll  (injected into the game)
                                  ▼
                           Game exe under Proton/Wine
```

### Core invariants (from `ARCHITECTURE.md` — must never be violated)

1. **The LLM never talks to the DLL directly** — it always goes through the GUI
   hub, which is the safety-enforcement point and session-state holder.
2. **Fast ops on the fast channel; reasoning on MCP.** High-frequency scans /
   patching can't afford the reasoning round-trip.
3. **Every mutation is undoable (D8).** Mutating MCP tools **stage** a change
   and a human **confirms** it; originals are snapshotted for undo.

### Capability surface

- **Memory:** read/write, region enumeration, value scan + narrowing
  (exact/range/changed/unchanged/increased/decreased), `dump`, `dump_struct`,
  memory `snapshot`.
- **Discovery:** `aob_scan`, `pointer_scan`, `pointer_chase`, `addr_to_module`,
  `disassemble`.
- **Reversing hooks:** `watch_writes` (hardware watchpoint, DR0/DR7),
  `break_on_code` (int3), `capture_reg` (passive register capture / trampoline
  ring buffer), `clear_breakpoints`.
- **Patching:** `install_cave` (trampoline / override, absolute / relative
  jumps), `undo`, `allocate`/`free`, `allocate_string`.
- **Higher level:** cheats (value / toggle / button), markers, **YAML cheat
  profiles** (portable cheat tables), app launching, activity log, and a web
  dashboard with SSE.

This is a genuinely novel, well-conceived architecture. The rest of this review
is the hard look at how the implementation measures up to it.

---

## 2. Verdict summary

**The architecture is sound and the layering is clean.** A single
`Arc<Mutex<SessionState>>` is correctly shared by all three frontends, the web
REST layer reuses the MCP internals rather than duplicating logic, and the wire
protocol lives in `trainlab-core` so the GUI and DLL cannot drift.

**The implementation is internally inconsistent.** The three headline
mechanisms — the D8 confirmation gate, the event bus, and profile
initialization — are each followed carefully in *some* code paths and bypassed
in others. The biggest problems concentrate in **YAML `init_commands` / button
command execution** (which bypass D8 entirely) and in **frontend parity**
(staged vs. direct writes, event emission, confirm availability).

---

## 3. Consistency across the three frontends (egui / MCP / web)

### 3a. The D8 confirmation gate is not actually a gate — it is bypassable from almost everywhere

D8 (`DESIGN_DECISIONS.md`) is the flagship safety invariant: *mutations stage, a
human confirms*. In practice the gate holds only on the "canonical" MCP tools:

| Path | Stages through D8? |
|---|---|
| MCP `write` / `install_cave` / `undo` | ✅ staged |
| MCP `set_cheat_value` / `set_cheat_toggle` | ✅ staged |
| Web `/api/write`, `/cheats/apply`, `/cheats/toggle` (delegate to MCP) | ✅ staged |
| **Web `/api/cheats/run`** (button cheat) | ❌ **writes directly** (`execute_profile_commands`) |
| **Profile `init_commands`** (MCP `load_profile`, GUI attach, web load) | ❌ **writes/cave-installs directly** |
| **GUI cheats panel "Apply"** | ❌ **writes directly** (`Request::Write`) |
| **GUI marker writes / scan-add-cheat** | ❌ direct |

`execute_profile_commands` (`mcp.rs:2855`) sends `Request::Write`
(`mcp.rs:2885`) / `Request::InstallCave` (`mcp.rs:2916`) straight to the DLL —
**no staging, no confirmation, no undo snapshot**. That is exactly how nearly
every *validated* cheat is delivered (Helldivers research/XP/cooldown buttons,
init hooks). The undo log is central to the safety story, yet profile writes
never record undo entries.

> The GUI value-cheat "Apply" bypass is *defensible* — the docs frame the human
> at the keyboard as the confirmation. But `init_commands` and button cheats are
> **agent-authored shellcode/write macros** that run unguarded. This is the single
> most important inconsistency: decide whether profile commands are trusted code
> (document it loudly, drop the "gate" language) or data (route them through D8).

### 3b. No HTTP endpoint exists to confirm web-staged ops

`/api/write`, `/cheats/apply`, `/cheats/toggle` stage ops into the pending list
but **`api.rs` exposes no `/confirm` or `/reject` route**, and the dashboard JS
never calls confirm. A web user clicks Apply, receives `{"status":"ok"}` (and an
`alert("Wrote …")`), believes it worked — and the op **silently sits in
`list_pending` forever**. The web UI *misrepresents staged ops as applied* and
cannot complete them. (`run_cheat`/`toggle_cheat`/`apply_cheat`/`write_memory`
in `api.rs`; `web/index.html:657–666`.)

### 3c. Event-bus (`SessionEvent`) emission is asymmetric

`event.rs` defines a clean typed broadcast bus (capacity 256) feeding the egui
repaint loop and the `/api/events` SSE stream. Emission, however, is scattered:

- **Exactly one `emit` exists in all of `mcp.rs`** — `ProfileLoaded`
  (`mcp.rs:1189`). Attach, `confirm_op`/`reject_op`, cheat add/remove, and
  `execute_profile_commands` emit **nothing** (only `log_activity`, which emits
  `ActivityLogged`).
- `session.rs` setters emit correctly: `CheatUpdated`, `MarkerSet`,
  `ConnectionChanged`, `ScanUpdated`, `WindowVisibility`, `AppLaunched`.
- **GUI value-cheat Apply and hotkey-apply write the DLL but emit no
  `CheatUpdated{value}`**; SSE subscribers never see them.
- `remove_cheat` and GUI "Clear all" emit nothing.
- **`confirm_op` doesn't even call `request_repaint`**, so a confirmed write
  won't refresh the egui cheats panel.

Net: the SSE dashboard and the egui UI have **inconsistent live-update
guarantees**; some mutations surface only via the web UI's 5-second
`refreshStatus` polling fallback.

### 3d. Toggle semantics differ and are misleading

- **GUI toggle checkbox / hotkey** (`main.rs:563–578`, `trigger_cheat`): flips
  only the session's `enabled` flag and emits `CheatUpdated{enabled}`. The
  comment says cave install/remove "is handled by the agent via MCP." Clicking a
  toggle in the GUI **changes nothing in game memory** while the dashboard
  happily reports it enabled.
- **MCP `set_cheat_toggle`** (`mcp.rs:938–997`): enable stages a cave install;
  **disable stages `PendingKind::Undo { original_bytes: Vec::new() }`, which on
  confirm issues a zero-byte write — a no-op** ("Full cave-restore wiring is a
  follow-up"). And the cheat's `enabled` flag is never flipped in the MCP path.

**Consequence: today no frontend can actually turn a cave hook off.** Given how
much real work is cave-based (zlua_gettop hooks), a non-functional "off" that
*looks* functional is dangerous.

---

## 4. YAML intake format — robustness

The schema (`profile.rs`) is well-designed and version-tagged
(`trainlab-profile/v1`); `SetupStep`/`ProfileCommand` use serde
internally-tagged enums. Parsing (`from_yaml`) is strict about *types*, but the
**semantic layer has several first-order bugs and silent-failure paths**:

1. **`Assert` with a concrete value never compares.** In
   `execute_profile_commands` (`mcp.rs:3074–3078`), any `expected` other than
   `!0`/`!0x0`/`!null` logs `"... passed"` unconditionally — it never compares
   the read bytes to `expected`. So `assert: <value>` **always passes**; only the
   non-null assert is enforced. This undermines the assert+wait hardening work.

2. **`PointerChase` command silently drops bad offsets.** Offsets are parsed via
   `filter_map(… .ok())` (`mcp.rs:3010–3013`) — a malformed offset is **dropped
   silently**, shortening the chain with no error. Contrast with the
   `SetupStep::PointerChain` path, which *does* error via `collect::<Result<_>>()`.

3. **`resolve_cheat_address` short-circuits.** The `return Err(...)` lives
   *inside* the ref loop (`mcp.rs:3245`), so if a cheat has both `address_ref`
   and `target_ref`, the first failing ref aborts before trying the second.

4. **`hook` falls through silently.** In `execute_profile_commands`, any
   non-`"override"` hook string becomes `Trampoline`; whereas `load_profile`
   correctly errors on unknown hook kinds. Two code paths, two behaviors.

5. **Value-as-address ambiguity.** In `Write` commands the value is first parsed
   as an address expression (`parse_addr_expr`), so a marker name used as a
   value resolves to the marker's **address** — intended — but the default
   value-type heuristic (`ptr` if `0x`/`$`-prefixed, else `i32`) is subtle and
   undocumented in `CHEAT_PROFILE.md`.

6. **`init_commands` vs `setup` coupling is inverted and load-bearing.** In the
   GUI "Re-run Initialization," `let run_setup = p.init_commands.is_none();` —
   setup steps run only when there are *no* `init_commands`. That coupling is
   non-obvious, undocumented in `CHEAT_PROFILE.md`, and likely wrong-headed:
   `setup` (AOB/pointer/address) and `init_commands` (macro) are independent
   concerns; a profile may legitimately need both.

7. **Silent failure on GUI attach.** `inject_and_connect` wraps
   `load_profile_by_name(&file, true)` in `if let Ok(_)` (`main.rs:236`),
   discarding the error. A failed init looks identical to success. Separately,
   `load_profile_by_name` (`mcp.rs:1028–1031`) **discards the rich result text**
   (resolved addresses, counts), returning the constant `"profile loaded"`.

**Is YAML intake robust?** Structurally yes (serde-validated); semantically no.
There are silent-failure, no-op, and inconsistent branches an LLM/hand author
will trip on, and no `--check`/`validate_profile` command to catch them before
running. Given an LLM is the primary author of these files, an upfront
dry-run validator would pay for itself.

---

## 5. Initialization consistency across frontends

Three different "init/attach" entry points behave differently:

| Trigger | Auto-attach? | Runs `setup`? | Runs `init_commands`? | Honors `auto_init`? |
|---|---|---|---|---|
| GUI "Find & Inject" (`inject_and_connect`) | n/a (already attaching) | **yes** | **yes** | ❌ **ignored** |
| GUI "Re-run Initialization" | no | only if no init_commands | yes | n/a |
| MCP `load_profile(run_setup)` | yes (if `inject_dll`) | if `run_setup` | yes | n/a |
| MCP `attach_game` | yes | no | **no** | n/a |
| Web `/api/profiles/load` | yes | yes (`true`) | yes | n/a |

Specific issues:

- **`auto_init` is dead.** The checkbox exists twice (`main.rs:455`, `1385`) but
  `inject_and_connect` never reads it — profile init **always auto-runs** on GUI
  attach regardless of the checkbox.
- **`attach_game` never runs profile init/setup**, even though it is the
  canonical "agent attaches remotely" tool. `CHEAT_PROFILE.md §5` says init
  auto-runs on attach; the code only does it via `load_profile`. Docs and code
  disagree across tools.
- **`load_profile` marks the session connected even when nothing attached.**
  `s.set_connected(true)` (`mcp.rs:1185`) runs unconditionally — for a profile
  with `inject_dll: false`, or `run_setup: false`, `connection_status` lies.
- **Attach/inject and button cheats block the GUI render thread.**
  `find_inject_connect` polls up to ~4.5 s synchronously inside `update()`
  (`main.rs`); `run_cheat_commands` runs `Wait`-containing sequences on the GUI
  thread too. The web path correctly uses `spawn_blocking`; the egui path does
  not, so the UI freezes on attach and on any delayed button cheat.
- `load_profile` / `inject_and_connect` re-enter the same code with slightly
  different rules, so "what ran init" depends on which button/tool was used.

---

## 6. Other correctness / robustness findings (verified)

**Concurrency / safety**

- One global `Mutex<SessionState>` — **no lock-ordering deadlock** (no nested
  locking). But MCP tool handlers can hold the lock across activity-log
  filesystem writes. GUI snapshots-and-drops correctly.
- **Inconsistent mutex-error policy:** `api.rs` uses `.lock().unwrap()`
  throughout (a poisoned mutex 500s the whole API), while `mcp.rs` /
  `controller.rs` handle poison with `map_err`.
- **Blocking TCP on the egui render thread with no timeouts** on
  `controller::request` (`controller.rs:44–58`) — a wedged DLL hangs the whole
  GUI. Contrast `mcp::call_dll`, which sets 5 s read/write timeouts.
- **`call_dll` hardcodes `127.0.0.1:31337`** and ignores the session's
  `dll_host`/`dll_port` — `confirm_op` can connect somewhere different than
  `connection_status` reports. `controller::request` and `call_dll` diverge.
- `format_value` indexes `data[0..7]` with no length check; the cheats panel
  feeds it arbitrary DLL `Read` results → **GUI panic** on a short/malformed read.

**Confirm-gate loss**

- `confirm_op` calls `take_pending` **before** applying (`mcp.rs:2522–2528`). If
  the DLL call fails, the staged op is **already consumed** — unrecoverable, no
  retry, no reject.

**Minor**

- Window toggle: global hotkey id 9999 *and* the focused-`J` egui handler both
  toggle (`main.rs:1195–1227`) → pressing `J` while focused toggles twice. Stale
  comment says 9999 is `[` (it is now `J`).
- Marker edit values alias the same `cheat_values` HashMap keyed by cheat id
  (collision risk).
- `mcp_addr` display hardcodes `127.0.0.1` while the server actually binds
  `TRAINLAB_MCP_HOST` (default `0.0.0.0`).
- Marker DTO / scan-match DTO set `address` and `address_hex` to the same value
  (`api.rs:370–371`, `498–499`) — redundant.
- `/profiles` does blocking FS I/O inline on the async executor while
  `load_profile` correctly uses `spawn_blocking`.
- Off-Windows `allocate_string_in_game` returns a **fake `0x10000`** address as
  success (`mcp.rs:3131+`).

**Security**

- The server binds `0.0.0.0` unauthenticated (for LAN use; `LAUNCHING.md`),
  exposing `/api/write`, `/api/cheats/*`, `/log`, and `/snapshots` to the LAN.
  The MCP host-allowlist is disabled for `0.0.0.0` — reasonable for SSE, but it
  means **anyone on the LAN can read/write game memory**. Worth a loud note in
  the docs and/or an optional bind/token guard.

---

## 7. Recommendations (ranked)

1. **Decide & enforce one mutation story for profile commands.** Either
   `execute_profile_commands` is trusted code (document it loudly, drop the
   "gate" language) or it must stage through D8 like `write`/`install_cave`.
2. **Implement toggle-off cave restore** (remove the `original_bytes: Vec::new()`
   no-op) and **flip `enabled` in the MCP path** — today "off" does nothing.
3. **Add HTTP `/api/confirm_op`, `/api/reject_op`, `/api/pending`** and wire the
   dashboard's staged ops to them; stop returning `{"status":"ok"}` before
   confirmation.
4. **Fix the YAML semantic bugs** (`Assert` no-op compare, PointerChase silent
   offset drop, `resolve_cheat_address` short-circuit, hook fall-through) and add
   a `validate_profile` / `--check` that resolves a profile without touching
   memory.
5. **Make init behavior uniform:** honor `auto_init`, drop the
   `run_setup = init_commands.is_none()` inversion, route all attach→load paths
   through one documented flow, and surface `load_profile`'s detailed result.
6. **Emit events consistently** (attach, confirm/reject, cheat add/remove,
   command results); make `confirm_op` repaint; have GUI value-apply emit
   `CheatUpdated{value}` so SSE matches the UI.
7. **Move attach/scan/button off the GUI render thread** (`spawn_blocking`) and
   add read/write timeouts to `controller::request`.
8. **Standardize mutex handling** (`map_err`, not `unwrap`) in `api.rs`; make
   `call_dll` honor session host/port.

See **`docs/CODE_REVIEW_FIXES.md`** for the task-tracked fix plan (T-100+).
