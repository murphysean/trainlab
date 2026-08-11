# TODO — Build Plan

The ordered work plan for `trainlab`. Work down the list; each item builds on
the last. Check off as completed. This is the "how do I start building" guide.

## Legend

- **[P0]** — must-have for the first usable milestone (LLM-driven recon on a real game)
- **[P1]** — important, builds toward the vision
- **[P2]** — nice-to-have / future
- **crate:** the crate(s) touched

## Architecture note (scan-family in GUI, poke-family in DLL)

Scans must be **external** (GUI → `WindowsProcess`/`ReadProcessMemory`, which
fails *gracefully* per-region). An **in-process** raw-pointer scan of a big heap
faults the whole game — that was the crash we hit scanning Urbek's 900MB Mono
heap from the injected DLL. So:

- **GUI (external):** `scan`, `next`, `aob_scan`, `pointer_scan`,
  `pointer_chase`, `read`, `write`, `dump`, `list_regions`.
- **DLL (in-process):** `watch_writes`, `break_on_code`, `clear_breakpoints`,
  `allocate`/`free` (code caves) — event-catching / poke-the-process ops must
  run where the exception fires.

The GUI and DLL still talk over the fast channel; the GUI just also opens the
game PID (`WindowsProcess::open`) for the scan-family.

---

## Phase 0 — Make the current workspace compile cleanly

- [x] **T-000 [P0] Fix `no_mangle` under edition 2024** (`crate: trainlab-inject`)
  - `crates/trainlab-inject/src/lib.rs:243`: change `#[no_mangle]` to
    `#[unsafe(no_mangle)]` (edition 2024 requires the `unsafe(...)` wrapper).
  - Verify with `cargo build` and `cargo test`.
- [x] **T-001 [P0] `git init` + commit the current scaffolding**
  - The workspace isn't a git repo yet (only referenced in `Cargo.toml`).
  - Add a `.gitignore` for `/target` and commit the working base so changes are
    tracked from here on.

## Phase 1 — Solidify the memory core (foundation)

- [x] **T-010 [P0] Implement the Windows memory backend** (`crate: trainlab-core`)
  - `trainlab-core::memory::windows`: implement `ReadProcessMemory`,
    `WriteProcessMemory`, and region enumeration via `VirtualQuery` (using
    `windows-sys`).
  - **Why first:** you'll do most real work against a Windows-under-Wine game;
    the Linux backend is done but the Windows one is a stub.
  - Implemented in `memory.rs` (`WindowsProcess` with `open(pid)`, read/write,
    and `VirtualQueryEx` region enumeration). Cross-compiles to
    `x86_64-pc-windows-gnu`; runtime validation still needs Wine/Windows.
- [x] **T-011 [P0] Real value-scan algorithm with narrowing** (`crate: trainlab-core`)
  - Add a `scan` module supporting first-scan + refine by
    `changed/unchanged/increased/decreased` and exact/range value.
  - Needs a **persistent match set** (the current `trainlab-scanner next` is a
    stub precisely because there's no persistent set).
  - Types: at minimum `i32/u32/f32/f64`; add more later.
  - Done: `trainlab_core::scan` with `Scan` (persistent `(addr, value)` match
    set), `ValueType` (i32/u32/f32/f64), `ScanOp` (Exact/Range/Changed/
    Unchanged/Increased/Decreased), `first_scan` + `refine`. Unit-tested with a
    mock process.
- [x] **T-012 [P0] Region scoping / classification** (`crate: trainlab-core`)
  - Add helpers to classify regions: private heap vs `MEM_IMAGE`/`MEM_MAPPED` vs
    code. Expose a "scan these regions" filter.
  - On Linux map to `/proc/pid/maps` heuristics now; on Windows use
    `VirtualQuery` (see D5).
  - Done: `trainlab_core::wine::ScanScope` (Heap/HeapAndStack/All) with a
    `regions(&tagged)` filter, plus `scan_regions(pid, scope)` convenience.
    `classify` tags heap/stack/image/mapped/other. Windows `VirtualQuery`
    regions already tag image/mapped/private (T-010); a Windows-side
    `ScanScope` can reuse the same kind logic later.
- [x] **T-013 [P1] Pointer-chase primitive** (`crate: trainlab-core`)
  - `pointer_chase(base, offsets: &[u64]) -> Vec<u64>` reporting each hop.
  - Done: `trainlab_core::pointer` with `chase` and `chase_with` (transform for
    module-base-relative chains). Resolves a chain against a live process and
    reports each hop + final value address. Unit-tested.
  - Note: this *resolves* a known chain; finding *what points to* an address is
    a separate reverse-reference/pointer-scan tool (deferred).
- [x] **T-016 [P0] Wine-aware region discovery + tagging (Linux side)** (`crate: trainlab-core`)
  - Detect whether a PID is part of a Wine/Proton tree (walk `/proc` ancestry
    for `wineserver`/`wine`).
  - Tag `/proc/pid/maps` regions as heap/stack/image/mapped/other so scans can
    be scoped to private heap (the Linux half of D5).
  - Expose via `trainlab-scanner wine list|check|regions`.
  - The Windows-API half of D5 (`GetProcessHeaps`/`HeapWalk`/`VirtualQuery`
    from the injected DLL) is a later phase.
- [x] **T-014 [P0] Wire `trainlab-scanner next` to the persistent match set**
  (`crate: trainlab-scanner`)
  - Make scan/next actually work end-to-end so you can do the scanmem workflow
    from the CLI.
  - Done: `scan --type <i32|u32|f32|f64> <pid> <value>` scopes to heap regions
    (via `wine::tag_regions`) and persists the match set to a per-PID state
    file; `next <pid> <changed|unchanged|increased|decreased|exact|range>`
    loads it, refines, and re-persists. Verified live against a test process
    (12345 → 99999 narrowed to a single match).
- [x] **T-015 [P0] Mark `trainlab-scanner` as Linux-only** (`crate: trainlab-scanner`)
  - The scanner imports `LinuxProcess` (a `#[cfg(unix)]` type) and reads
    `/proc/pid/mem`; it must not be built for the Windows target.
  - Add a `#[cfg(unix)]` guard on the binary or document that it's Linux-only
    (see `docs/BUILDING.md`). Prevents `cargo build --target
    x86_64-pc-windows-gnu` (whole workspace) from failing.
  - Done: `#[cfg(unix)]` guards on all Linux-only items; a `#[cfg(not(unix))]`
    stub `main` reports the tool is Linux-only. Whole-workspace Windows build
    is now green.

## Phase 2 — First usable milestone: LLM-driven recon

This is the "wow, it works" point: an agent connects and does live recon on a
game.

- [x] **T-020 [P0] MCP server in `trainlab-gui`** — MCP server skeleton
  - Use `rmcp`. The GUI hosts an MCP server over HTTP (streamable HTTP/SSE) on
    `127.0.0.1` with a configurable port. (Decision D10 — the GUI is the hub.)
  - Expose a "ping" / "hello" tool and verify an agent (e.g., goose) can connect
    and call it.
  - Done: `trainlab-gui::mcp` hosts a Streamable HTTP MCP server via `rmcp` +
    axum at `/mcp`, using `#[tool_router(server_handler)]`. Exposes a `ping`
    tool. Wired into the GUI `main` on a background tokio runtime (default port
    8123). Integration test spins up the server, connects an MCP client, and
    verifies `ping` returns "pong".
- [x] **T-021 [P0] Expose read-only recon tools over MCP, proxied to the DLL**
  - `list_regions`, `scan`, `aob_scan`, `read`, `pointer_chase`. These are
    read-only and safe for an agent to call freely.
  - The GUI **proxies** each MCP tool call to the game DLL over the fast channel
    (D10). The GUI is the translation layer between MCP tool calls and
    `trainlab-core::protocol::Request` messages.
  - IMPLEMENTED: `list_regions`, `read`, `aob_scan`, `ping` exposed; proxy to
    DLL over the fast channel (TCP 31337). Verified live against Urbek under
    Proton — `list_regions` returns the full game memory map (required
    implementing `SelfProcess::regions()`: VirtualQuery on Windows,
    /proc/self/maps on Linux). `scan`/`pointer_chase` deferred: `scan` is
    stateful (belongs in T-022 session state), `pointer_chase` needs a
    reverse-reference discovery tool first.
- [x] **T-022 [P0] Session state: markers + undo log** (`crate: trainlab-gui` + core)
  - `set_marker`/`get_markers` so the agent persists labeled addresses across
    turns (see D7).
  - Undo log structure (store original bytes for every mutation) — even if no
    mutating tools exist yet, build the structure now.
  - IMPLEMENTED: `session` module (markers + undo log, Arc<Mutex> shared across
    MCP sessions). MCP tools: set_marker, get_marker, list_markers,
    remove_marker, undo_info. Undo structure (record_undo/pop_undo) built for
    Phase 3 mutating tools.
- [x] **T-023 [P0] Verify against a real target game**
  - Get the DLL loaded into a game under Wine (T-040), run the MCP server in the
    GUI, and have an agent do the full recon loop: find a value, chase its
    pointer, dump a struct, propose a patch. (Urbek is a good first target —
    Mono.)
  - DONE (2026-08-09): Full loop proven live on Urbek under Proton — injected
    DLL, MCP server, scan/narrow to wood, hardware watchpoint to find the write
    instruction, disassemble, install a transparent trampoline cave, verify the
    game ticks through it, and undo/restore. See `.goose/memory/urbek-recon.txt`.

## Phase 2.5 — Discovery tooling (fleshed out)

The core of the trainer: everything an agent needs to *find* and *understand*
values in a live game. Ordered by dependency. Playbook loader is deferred
(see T-070); struct dumping is just `read` + LLM-side tooling (no dedicated
tool needed beyond a `dump` convenience).

- [x] **T-024 [P0] Stateful `scan`/`next` MCP tools + scan-core extensions**
  (`crate: trainlab-gui` + `trainlab-core`)
  - Wire the persistent `Scan` match set (T-011) into the MCP server, using the
    T-022 session state so the agent can run the full scanmem loop:
    `scan <type> <value>` → change game → `next <op>` → narrow to one address.
  - Extend `ValueType` with **pointer (u64/ptr)**, **I64/U64**, and add
    **alignment** to the scan (so values can be scanned at 4/8-byte-aligned
    addresses only). AOB already works via `aob_scan`.
  - This is the foundation for every other discovery tool.
  - IMPLEMENTED: ValueType +I64/U64/Ptr, Scan.with_alignment. Scan/Next protocol
    requests; DLL runs scan in-process, GUI stores match set in session (D7).
    MCP tools scan/next. Scanner CLI updated.
- [x] **T-025 [P0] Reverse-reference / pointer-scan** (`crate: trainlab-core` + `trainlab-gui`)
  - Find *what points to* an address: scan writable regions for a pointer value
    equal to a target address (or within a range). This is the missing half of
    T-013 (which only *resolves* a known chain).
  - Expose `pointer_scan` MCP tool. Enables the "chase pointers from CODE to
    values, restart-stable" workflow.
- [x] **T-026 [P0] `pointer_chase` MCP tool** (`crate: trainlab-gui`)
  - Expose the existing `chase`/`chase_with` (T-013) over MCP so an agent can
    resolve a discovered chain against the live game.
- [x] **T-027 [P0] `dump` MCP tool** (`crate: trainlab-gui`)
  - Read a chunk of memory around an address and format it (hex + ASCII, and
    optionally as a struct of typed fields) so the agent can reverse a struct
    layout / class. The LLM does the actual teasing-out; this just feeds it
    bytes in a useful shape.
- [x] **T-028 [P0] `find_writes` via hardware watchpoint** (`crate: trainlab-inject` + `trainlab-gui`)
  - **Moved up from T-034.** Set a hardware watchpoint (debug registers DR0-DR3
    via `SetThreadContext`) on an address; when the game writes it, capture the
    instruction pointer + register state and report which *code* wrote the value.
  - This is the "find where in CODE a value is read/written" capability.
- [x] **T-029 [P0] Lightweight breakpoint + register/stack capture**
  (`crate: trainlab-inject` + `trainlab-gui`)
  - **Moved up.** Break on a read/write or instruction (software int3 or
    hardware breakpoint), capture registers + a stack trace, and report them —
    without a full debugger stop. The "hey, when you hit that, here's the
    registers/stack" mechanism.

## Phase 3 — Code caves & hooks

- [x] **T-030 [P0] Shellcode emitter** (`crate: trainlab-cave` — new)
  - Emit minimal x86-64 shellcode for: override a register value, cmp a register
    against a data pointer + conditional branch (player check), jump-back.
  - Provide the "build_hook" equivalent of the Sins 2 `cooldown_hook_v3.py` in
    idiomatic Rust.
  - DONE: `trainlab-cave::emitter` — `jmp_abs` (register-preserving `FF 25`
    memory-indirect absolute jump), `jmp_rel8/rel32`, `mov_rax_imm64`,
    `mov_dword_ptr_rax_disp_imm32/ecx`. Unit-tested.
- [x] **T-031 [P0] Cave finder + installer** (`crate: trainlab-cave`)
  - Scan an executable region for a run of `0xCC`/`0x00` (cave).
  - Place shellcode in the cave, patch the call site with a `jmp`, save original
    bytes, return a handle.
  - DONE: `trainlab-cave::cave::install` — instruction-aligned patch length
    (via `disasm::instruction_aligned_len`), two hook kinds (`Trampoline`
    relocates stolen instructions via `disasm::relocate`; `Override` skips
    them), register-preserving `FF 25` jump. Validated live on Urbek.
- [x] **T-032 [P0] Undo/restore for caves** (`crate: trainlab-cave`)
  - Restore original bytes from the undo log on toggle-off.
  - Note: for Mono games this is re-JIT-based, not byte-restore (see D9).
  - DONE: `cave::restore` restores the saved original bytes; wired to the GUI
    undo log. Validated live (restored 15 bytes cleanly).
- [x] **T-033 [P1] `install_cave` / `restore` / `undo` MCP tools** (`crate: trainlab-mcp`)
  - With the confirmation gate (dry-run or human approve) per D8.
  - DONE: MCP `install_cave` (takes `hook` kind + `payload`), `undo` tools in
    `trainlab-gui::mcp`. Driven live via the `cave_validate` example.
- [x] **T-034 [P1] `find_writes` via hardware watchpoint** — **MOVED to T-028**
  (discovery phase). See T-028.

## Phase 4 — Windows injection / load

- [x] **T-040 [P0] `CreateRemoteThread` + `LoadLibrary` injection** (`crate: trainlab-gui`)
  - Implement the injection primitive in the GUI: `OpenProcess` →
    `VirtualAllocEx` → `WriteProcessMemory` → `CreateRemoteThread` →
    `WaitForSingleObject`. (Decision D6 — this is the chosen mechanism.)
  - The GUI injects the DLL, then pings it over the fast channel to confirm.
  - DONE: `trainlab-gui::inject` — full sequence implemented; validated live
    (DLL injected into Urbek under Proton, pinged over the fast channel).
- [x] **T-041 [P1] Windows allocate/free for caves** (`crate: trainlab-inject`)
  - Implement the Windows `allocate`/`free` stubs (`VirtualAlloc`/`VirtualFree`)
    so caves can be placed on the Windows path.
  - DONE: `trainlab-inject` `allocate`/`free` via `VirtualAlloc`/`VirtualFree`
    (PAGE_EXECUTE_READWRITE). Used by the live cave installs.
- [x] **T-042 [P2] Launch instructions (launcher-agnostic)** — DONE as
  `docs/LAUNCHING.md`, and deliberately **reframed away from STL-specific
  scripts**. trainlab is a trainer (Cheat Engine / Aurora / Fling style): you
  ship a binary and launch it alongside the game with whatever tools you want.
  Windows: run the exe. SteamOS/Linux: any launcher (STL is one option, not a
  requirement). We intentionally ship **no launcher scripts** — launch tooling
  on SteamOS evolves and is user/environment-specific. `docs/LAUNCHING.md`
  documents launching, env vars, MCP, and remote connectivity.
- [x] **T-044 [P1] `dump_struct` typed struct dump MCP tool** (`crate: trainlab-gui`)
  - `dump_struct` reads a struct at an address as a list of typed fields
    (name, type, offset, optional len). Field types: i8/u8/i16/u16/i32/u32/
    i64/u64/f32/f64/ptr/cstr (null-terminated ASCII)/bytes. Output is one line
    per field, `+off  type  name: value`, so the agent can reverse a
    struct/class layout without manually slicing raw bytes.
  - DONE: `dump_struct` tool + `StructField` args, LE value-read helpers
    (`read_i8..u64`, `read_f32_val`, `read_f64_val`, `read_cstr`), `dumpstruct`
    stage in the `cave_validate` driver. Unit-tested (LE decode + cstr). All
    tests pass, Windows cross-compile green.
- [x] **T-043 [P0] Enforce the D8 confirmation gate on mutating MCP tools**
  (`crate: trainlab-gui`)
  - `write`, `install_cave`, and `undo` no longer mutate memory directly; they
    **stage** a change into the session and return a pending op id + preview.
  - New `confirm_op` (apply a staged op, snapshotting originals for undo),
    `reject_op` (discard), and `list_pending` (enumerate staged ops) MCP tools.
  - No `confirm:true` bypass — a human must call `confirm_op`.
  - Done: session pending-op state, staged write/install_cave/undo, confirm/
    reject/list tools, `cave_validate` driver updated (write/writei/cave/restore
    now stage; new `pending`/`confirm`/`reject` stages). All tests pass, Windows
    cross-compile green.

## Phase 5 — Mono support (REMOVED — out of scope for the trainer)

**Decision (2026-08-10):** Mono/Unity games are **not** a trainer target. The
clean way to hack a Mono game is to **patch the IL in the assembly before it
loads** (a build/load-time patch via `ilspycmd`/`dnSpy`), not runtime memory
hacking. That's a different workflow and doesn't need runtime walking or IL
re-JIT hooks. The trainer targets **native** games (C/C++/Godot native, etc.)
where inline code caves and value pinning apply. See `docs/DESIGN_DECISIONS.md`
D9 for the reasoning.

## Phase 6 — Polish & distribution

- [x] **T-060 [P2] GUI: session panel** (`crate: trainlab-gui`)
  - Show markers, undo log, and pending (staged) mutations in the egui app,
    with Confirm/Reject buttons for pending ops. Surfaces the state the agent
    manipulates via MCP so the human can see and act on it.
  - DONE: `show_session_panel` (markers/undo/pending + confirm/reject),
    `apply_pending` (write/cave/undo). Tests all pass, Windows cross-compile
    green.
- [x] **T-061 [P2] Remote connectivity** (`crate: trainlab-gui`)
  - Configurable MCP bind address (`TRAINLAB_MCP_HOST`, default `0.0.0.0`) and
    port (`TRAINLAB_MCP_PORT`, default `8123`).
  - `docs/LAUNCHING.md` documents SSH tunnel / Tailscale / direct-LAN options
    for reaching the trainer from a Steam Deck or another machine, plus a
    security note about the unauthenticated mutating MCP surface.
- [x] **T-062 [P2] Disassembler integration** (`crate: trainlab-core` + `trainlab-gui`)
  - `iced-x86` for `disassemble` and safe instruction-length before patching.
  - `trainlab_core::disasm` (disassemble + first_instruction_len), `trainlab_core::modinfo`
    (addr→module resolution via toolhelp); MCP tools `disassemble` and `addr_to_module`.
- [x] **T-063 [P1] Remote attach/manage over MCP** (`crate: trainlab-gui`)
  - Make the whole setup loop driveable by an LLM remotely (Steam Deck / Steam
    machine use case). Extracted a shared `controller` module used by both the
    GUI and MCP so they stay in sync.
  - Session now holds DLL connection state (host/port, connected, game name,
    dll path, inject version) as a single source of truth.
  - New MCP tools: `find_games`, `attach_game` (find process + inject DLL +
    connect), `connection_status`, `set_connection`.
  - `cave_validate` gains `games`/`attach`/`status` stages.
  - DONE: controller.rs, session connection state, 4 new MCP tools, GUI routes
    through controller, `games`/`attach`/`status` stages. Tests all pass,
    Windows cross-compile green.
- [x] **T-064 [P1] Cheats: adjustable game options** (`crate: trainlab-gui`)
  - The agent discovers a location and adds a **cheat** (a user-facing
    adjustable game option) that shows up in the GUI's **Cheats panel** for the
    human to adjust — value cheats (type a number, hit Apply) or toggle cheats
    (god mode, on/off).
  - Session: `Cheat`/`CheatKind` (Value{address,value_type} | Toggle{hook,
    target, enabled}), add/get/list/remove/set_toggle methods.
  - MCP: `add_cheat`, `list_cheats`, `remove_cheat`, `set_cheat_value` (stages
    through D8), `set_cheat_toggle` (stages through D8).
  - GUI: Cheats panel with live value reads, editable fields + Apply (writes
    directly — the user is the human confirmation), and toggle checkboxes.
  - `cave_validate`: `addcheat`/`cheats`/`setcheat` stages.
  - DONE: Cheat model, 5 MCP tools, GUI Cheats panel, driver stages. Tests all
    pass, Windows cross-compile green.
- [x] **T-065 [P1] Cheat profile (portable YAML cheat table)** — design in
  `docs/CHEAT_PROFILE.md` (schema v1, setup/init steps, MCP tools, `mechanism`
  cave-vs-timer for pinning).
  - `profile.rs`: `GameProfile` (schema, game, inject_dll, version, setup,
    cheats), `SetupStep` (AobScan/PointerChain/Address), `ProfileCheat`,
    YAML round-trip, `discover_profiles` (scans `cheats/*.yaml` next to exe),
    `find_profile_for_game`.
  - MCP: `list_profiles`, `load_profile` (runs setup to resolve base addresses,
    materializes cheats, does NOT enable), `save_profile` (serializes session
    cheats to `cheats/<game>.yaml`).
  - `cave_validate`: `profiles`/`loadprofile`/`saveprofile` stages.
  - DONE: GameProfile + YAML, 3 MCP tools, driver stages. Tests all pass,
    Windows cross-compile green.
  - **Module-base resolution (done 2026-08-10):** `PointerChain` and `Address`
    setup steps now resolve the module base against the game's loaded modules
    (`enumerate_windows`) and add the module-relative offset, so chains are
    truly restart-stable (like CE). `resolve_module_base` helper.
- [ ] **T-070 [P2] Playbook / table loader** (`crate: trainlab-gui`)
  - **Deferred.** Load a session from a file (yaml/json, later a Cheat Engine
    table) to jump-start the trainer with findings/cheats. Depends on the
    session state (T-022) and the discovery tools being stable.

---

## Notes on dependencies

- Add `windows-sys` for the Windows memory backend + injection.
- Add `rmcp` for the MCP server.
- Add `iced-x86` for disassembly.
- Keep the protocol in `trainlab-core` so GUI/scanner/inject can't drift.
