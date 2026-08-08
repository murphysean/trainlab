# TODO — Build Plan

The ordered work plan for `trainlab`. Work down the list; each item builds on
the last. Check off as completed. This is the "how do I start building" guide.

## Legend

- **[P0]** — must-have for the first usable milestone (LLM-driven recon on a real game)
- **[P1]** — important, builds toward the vision
- **[P2]** — nice-to-have / future
- **crate:** the crate(s) touched

---

## Phase 0 — Make the current workspace compile cleanly

- [ ] **T-000 [P0] Fix `no_mangle` under edition 2024** (`crate: trainlab-inject`)
  - `crates/trainlab-inject/src/lib.rs:243`: change `#[no_mangle]` to
    `#[unsafe(no_mangle)]` (edition 2024 requires the `unsafe(...)` wrapper).
  - Verify with `cargo build` and `cargo test`.
- [ ] **T-001 [P0] `git init` + commit the current scaffolding**
  - The workspace isn't a git repo yet (only referenced in `Cargo.toml`).
  - Add a `.gitignore` for `/target` and commit the working base so changes are
    tracked from here on.

## Phase 1 — Solidify the memory core (foundation)

- [ ] **T-010 [P0] Implement the Windows memory backend** (`crate: trainlab-core`)
  - `trainlab-core::memory::windows`: implement `ReadProcessMemory`,
    `WriteProcessMemory`, and region enumeration via `VirtualQuery` (using
    `windows-sys`).
  - **Why first:** you'll do most real work against a Windows-under-Wine game;
    the Linux backend is done but the Windows one is a stub.
- [ ] **T-011 [P0] Real value-scan algorithm with narrowing** (`crate: trainlab-core`)
  - Add a `scan` module supporting first-scan + refine by
    `changed/unchanged/increased/decreased` and exact/range value.
  - Needs a **persistent match set** (the current `trainlab-scanner next` is a
    stub precisely because there's no persistent set).
  - Types: at minimum `i32/u32/f32/f64`; add more later.
- [ ] **T-012 [P0] Region scoping / classification** (`crate: trainlab-core`)
  - Add helpers to classify regions: private heap vs `MEM_IMAGE`/`MEM_MAPPED` vs
    code. Expose a "scan these regions" filter.
  - On Linux map to `/proc/pid/maps` heuristics now; on Windows use
    `VirtualQuery` (see D5).
- [ ] **T-013 [P1] Pointer-chase primitive** (`crate: trainlab-core`)
  - `pointer_chase(base, offsets: &[u64]) -> Vec<u64>` reporting each hop.
- [ ] **T-014 [P0] Wire `trainlab-scanner next` to the persistent match set**
  (`crate: trainlab-scanner`)
  - Make scan/next actually work end-to-end so you can do the scanmem workflow
    from the CLI.

## Phase 2 — First usable milestone: LLM-driven recon

This is the "wow, it works" point: an agent connects and does live recon on a
game.

- [ ] **T-020 [P0] New crate `trainlab-mcp`** — MCP server skeleton
  - Use `rmcp`. Host an MCP server over HTTP (streamable HTTP/SSE) on
    `127.0.0.1` with a configurable port.
  - Expose a "ping" / "hello" tool and verify an agent (e.g., goose) can connect
    and call it.
- [ ] **T-021 [P0] Expose read-only recon tools over MCP**
  - `list_regions`, `scan`, `aob_scan`, `read`, `pointer_chase`. These are
    read-only and safe for an agent to call freely.
- [ ] **T-022 [P0] Session state: markers + undo log** (`crate: trainlab-mcp` + core)
  - `set_marker`/`get_markers` so the agent persists labeled addresses across
    turns (see D7).
  - Undo log structure (store original bytes for every mutation) — even if no
    mutating tools exist yet, build the structure now.
- [ ] **T-023 [P0] Verify against a real target game**
  - Get the DLL loaded into a game under Wine, run the MCP server, and have an
    agent do the full recon loop: find a value, chase its pointer, dump a
    struct, propose a patch. (Urbek is a good first target — Mono.)

## Phase 3 — Code caves & hooks

- [ ] **T-030 [P0] Shellcode emitter** (`crate: trainlab-cave` — new)
  - Emit minimal x86-64 shellcode for: override a register value, cmp a register
    against a data pointer + conditional branch (player check), jump-back.
  - Provide the "build_hook" equivalent of the Sins 2 `cooldown_hook_v3.py` in
    idiomatic Rust.
- [ ] **T-031 [P0] Cave finder + installer** (`crate: trainlab-cave`)
  - Scan an executable region for a run of `0xCC`/`0x00` (cave).
  - Place shellcode in the cave, patch the call site with a `jmp`, save original
    bytes, return a handle.
- [ ] **T-032 [P0] Undo/restore for caves** (`crate: trainlab-cave`)
  - Restore original bytes from the undo log on toggle-off.
  - Note: for Mono games this is re-JIT-based, not byte-restore (see D9).
- [ ] **T-033 [P1] `install_cave` / `restore` / `undo` MCP tools** (`crate: trainlab-mcp`)
  - With the confirmation gate (dry-run or human approve) per D8.
- [ ] **T-034 [P1] `find_writes` via hardware watchpoint** (`crate: trainlab-core`/`trainlab-mcp`)
  - Find what instruction writes to an address; report IP + register state.

## Phase 4 — Windows injection / load

- [ ] **T-040 [P1] Load the DLL into a game under Wine**
  - Implement and evaluate proxy-DLL (`WINEDLLOVERRIDES`) vs `CreateRemoteThread`
    injection vs Linux `/proc/pid/mem` stub write (see D6 / OD3). Pick one to
    standardize on.
- [ ] **T-041 [P1] Windows allocate/free for caves** (`crate: trainlab-inject`)
  - Implement the Windows `allocate`/`free` stubs (`VirtualAlloc`/`VirtualFree`)
    so caves can be placed on the Windows path.
- [ ] **T-042 [P2] STL integration** — document/script the fork+inject flow so the
  trainer launches with the game on Steam machine / Steam Deck.

## Phase 5 — Mono support (Urbek-class games)

- [ ] **T-050 [P2] Mono runtime walking** (`crate: trainlab-mono` — new)
  - Locate Mono's method/class metadata in the game's memory.
- [ ] **T-051 [P2] IL-level hooking / re-JIT** (`crate: trainlab-mono`)
  - Patch in-memory IL or force re-JIT to change behavior (the "work with the
    loop" approach for Mono).

## Phase 6 — Polish & distribution

- [ ] **T-060 [P2] GUI: MCP + session panel** (`crate: trainlab-gui`)
  - Connect the egui app to the MCP server; show markers, undo log, active
    hooks.
- [ ] **T-061 [P2] Remote connectivity** (`crate: trainlab-mcp`)
  - Configurable bind address / SSH tunnel / Tailscale notes for Steam Deck
    (see OD4).
- [ ] **T-062 [P2] Disassembler integration** (`crate: trainlab-core`)
  - `iced-x86` for `disassemble` and safe instruction-length before patching.

---

## Notes on dependencies

- Add `windows-sys` for the Windows memory backend + injection.
- Add `rmcp` for the MCP server.
- Add `iced-x86` for disassembly.
- Keep the protocol in `trainlab-core` so GUI/scanner/inject can't drift.
