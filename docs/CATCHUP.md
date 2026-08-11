# Trainlab — Session Catchup Doc

> **Purpose:** This doc lets a fresh session pick up exactly where we left off.
> Read this first, then the recon notes in `.goose/memory/`, then `docs/TODO.md`.
> Last updated: 2026-08-10 00:51 (session end).

---

## 1. What this project is

`trainlab` is a Rust workspace that builds a **game trainer framework**:
- A **Windows DLL** (`trainlab-inject`) injected into a game that opens a TCP
  fast channel (port 31337) for in-process memory ops (watchpoints, breakpoints,
  code caves, allocate/free).
- A **Windows GUI** (`trainlab-gui`) that injects the DLL, hosts an **MCP server**
  (port 8123) for external recon (scan, narrow, read, disassemble, regions), and
  has a session/undo system.
- A **core crate** (`trainlab-core`) with the wire protocol, disassembler
  (iced-x86), scan engine, and cave-hook types.
- A **cave crate** (`trainlab-cave`) with the shellcode emitter + cave installer.

**Targets:** games under Steam/Proton/Wine. We've validated against **Urbek**
(Mono/Unity) and are now on **Unrailed 2** (Godot 4).

---

## 2. Current state (committed, clean tree)

Latest commits (newest first):
- `1d8597a` Remove 'unrailed' from game-candidate exclusion list
- `e9fc46b` Add process enumeration + smart game-candidate detection to the GUI
- `b06b260` Make injection game target configurable via `TRAINLAB_GAME` env var
- `c437065` Add write/seedr stages to cave_validate driver
- `1021f11` Mark Phase 3 (caves) + Phase 4 (injection) + T-023 validated
- `e17bbc8` Fix cave hook clobbering RAX (register-preserving `FF 25` jump)
- `f8d31b2` Add transparent trampoline cave hooks (relocate stolen instructions)

**All tests pass** (36 core + 7 cave + 4 gui + 1 inject). Both Windows crates
cross-compile cleanly to `x86_64-pc-windows-gnu`.

**Phases done:** 0 (workspace), 1 (memory core), 2/2.5 (MCP + discovery),
3 (code caves), 4 (injection). **Not started:** Phase 6 (polish). **Phase 5
(Mono) removed** — Mono games are out of scope for the trainer (see D9).

---

## 3. How to launch the trainer (Windows GUI under Proton)

The trainer is a Windows exe run under Proton, **in the same prefix as the game**
so it can see the game's processes.

```bash
# Build the Windows GUI + DLL
cargo build --target x86_64-pc-windows-gnu -p trainlab-gui
cargo build --target x86_64-pc-windows-gnu -p trainlab-inject

# Launch the GUI under Proton (same way the game runs)
# (the exact proton invocation used before — see shell history)
proton run .../target/x86_64-pc-windows-gnu/debug/trainlab-gui.exe
```

**In the GUI:**
1. Click **"Scan for games"** → a dropdown lists likely game processes
   (heuristic excludes system/steam/trainlab processes).
2. Pick the game (e.g. `Unrailed2.exe`), click **"Find & Inject"**.
3. The DLL injects and the GUI connects to the fast channel (port 31337).

**Explicit override:** `TRAINLAB_GAME="Unrailed2.exe"` env var still works.

---

## 4. The `cave_validate` driver (our live-testing tool)

`crates/trainlab-gui/examples/cave_validate.rs` is a CLI that drives the MCP
server + DLL. Stages (run via `cargo run -p trainlab-gui --example cave_validate -- <stage> [args]`):

| Stage | Args | Purpose |
|-------|------|---------|
| `ping` | — | Check MCP + DLL alive |
| `seed` | `<f32>` | First scan for an f32 value |
| `seedi` | `<i32>` | First scan for an i32 value (integer currency) |
| `seedr` | `<min> <max>` | First scan for f32 in a range |
| `narrow` | — | Narrow previous scan by `changed` |
| `read` | `<addr>` | Read f32 at address |
| `write` | `<addr> <f32>` | Write f32 (4 hex bytes) |
| `writei` | `<addr> <i32>` | Write i32 (4 hex bytes) |
| `watch` | `<addr>` | Arm a hardware data-write watchpoint |
| `poll` | — | Poll watchpoint/breakpoint for a hit (dumps RIP + regs) |
| `disasm` | `<addr>` | Disassemble at address |
| `cave` | `<target> <hook> <payloadhex>` | Install a code cave (trampoline/override) |
| `clear` | — | Clear all watchpoints/breakpoints |
| `restore` | `<undo_id>` | Restore a cave/undo |
| `pending` | — | List staged (unconfirmed) mutations |
| `confirm` | `<pending_id>` | Apply a staged mutation (human gate) |
| `reject` | `<pending_id>` | Discard a staged mutation |

**IMPORTANT:** `read`/`write` interpret values as **f32**. For integer fields
(like hexnuts), use `seedi`/`writei` for the scan/write, and remember `read`
will show the i32 bytes as a tiny f32 — that's expected, not a bug.

**D8 confirmation gate (since 2026-08-10, T-043):** the `write`, `writei`, and
`cave` stages **stage** a mutation and return a `pending id N` — they do **not**
modify memory. Append `confirm` to the stage to apply it in the same call, or
run `confirm <N>`. `restore` stages+applies an undo. This is deliberate: an
agent proposes, a human confirms (see DESIGN_DECISIONS D8).

---

## 5. Where we are with Unrailed 2 (the current target)

**Game:** Unrailed 2 "Back on Track" — **Godot 4** engine
(`Unrailed2.pck`, `UnrailedGodot.dll`). Installed at
`~/.local/share/Steam/steamapps/common/Unrailed! 2 Back on Track/`.

**Why it's a good target:** native C++ core (no Mono JIT), stored values
(unlike Urbek's computed rates). Much friendlier for the pin/add workflow.

**What we've confirmed live (2026-08-10):**
- ✅ **Injection works** — process-detection feature found `Unrailed2.exe`
  (the game is the process at high CPU; `Bootstrap.exe` is just a launcher).
- ✅ **Value discovery works** — scan/narrow isolated the hexnuts field.
- ✅ **Write path works** — writing 999 to `0x14aaa37f4` showed 999 in the UI.

**The finding (Godot mirrors values):**
- Hexnuts is mirrored across **three addresses**:
  `0x14aaa37f4`, `0x14aaae0bc`, `0x14b4367f4` (all i32).
- Writing to `0x14aaa37f4` changed the **UI display** to 999, but when the user
  bought something, the value dropped to **126 = 156 − cost** (not 999 − cost).
  This means the **buy logic read a different authoritative field** (still at
  156) and then synced the mirrors.
- So `0x14aaa37f4` is a **UI mirror**, not the authoritative field the game
  logic reads/writes.

**Next step (the goal):** find the **authoritative** hexnuts field, then either
pin it or hook its write instruction. To find it:
1. Arm watchpoints on the mirrors, trigger a value change (earn hexnuts by
   completing a task/level, or buy when affordable), and see which address the
   game *writes* to.
2. That address is authoritative → pin it (writei a large value) or find its
   write instruction (watchpoint → disasm) and install a cave hook.

**User's stated goal:** unlock all the options and buy them out. Wants to come
back to this later.

---

## 6. Key lessons from Urbek (the previous target)

Urbek (Mono/Unity) was **hostile to inline code-cave hooks**:
- Resource **rate** is a computed aggregate, rebuilt every tick — not pinnable
  by direct write.
- Hooking the **accumulation write** freezes the game clock (game sees the
  value never change → stops producing).
- **Storage capacity** (`misStorage[key]`) IS pinnable — writing 100000 to the
  iron capacity changed the UI cap 2000→100k. This is the one clean lever.
- **Conclusion:** Mono games are a hard target for byte-level inline hooks.
  A native game (like Unrailed 2) is the better validation target.

Full details in `.goose/memory/urbek-recon.txt`.

---

## 7. What's next (priorities)

> **Focus shift (2026-08-10):** the Unrailed-2 training/testing has been split
> off to a *separate* agent/client using the framework over MCP. This session's
> focus is **finishing out the framework and improving the API surface**, not
> driving a specific game.

1. **D8 confirmation gate (done 2026-08-10, T-043):** mutating MCP tools
   (`write`/`install_cave`/`undo`) now **stage** a change and return a pending
   op id; `confirm_op` applies it, `reject_op` discards it, `list_pending`
   enumerates. No `confirm:true` bypass. The `cave_validate` driver's
   write/writei/cave/restore stages now stage (pass `confirm` or use the
   `confirm <id>` stage to apply).
2. **Unrailed 2: find the authoritative hexnuts field** (see §5) — now handled
   by the separate training client.
3. **Validate the cave framework on a non-Mono game** — Unrailed is the chance
   to prove the transparent trampoline on a friendlier target; also on the
   training client.
4. **Framework/API improvements (this session's focus):**
   - `dump_struct` typed struct dump (**done 2026-08-10, T-044**) — read a
     struct as typed fields (i8..u64/f32/f64/ptr/cstr/bytes, per-field offset).
   - Remote connectivity (**done 2026-08-10, T-061**) — `TRAINLAB_MCP_HOST`
     (default `0.0.0.0`) + `TRAINLAB_MCP_PORT` (default `8123`), documented in
     `docs/LAUNCHING.md` (SSH tunnel / Tailscale / LAN).
   - Launch instructions (**done 2026-08-10, T-042, reframed**) — `README.md`
     rewritten to reflect Phases 0–4 done; `docs/LAUNCHING.md` covers launching
     (Windows: run exe; Linux/SteamOS: any launcher), env vars, MCP, remote.
     Reframed away from STL-specific scripts — trainlab is launcher-agnostic.
   - Remote attach/manage over MCP (**done 2026-08-10, T-063**) — new
     `find_games`/`attach_game`/`connection_status`/`set_connection` MCP tools
     let an LLM run the whole setup loop remotely (find game, inject DLL,
     connect, query state) without the GUI. Shared `controller` module + DLL
     connection state in the session.
   - Cheats: adjustable game options (**done 2026-08-10, T-064**) — the agent
     adds a **cheat** (value or toggle) that appears in the GUI **Cheats panel**
     for the human to adjust. Value cheats: type a number + Apply (writes
     directly). Toggle cheats (god mode): on/off. MCP `add_cheat`/`list_cheats`/
     `remove_cheat`/`set_cheat_value`/`set_cheat_toggle` (mutating stages through
     D8). This is the seed of the "portable game file / cheat table" idea.
   - Cheat profile / portable YAML cheat table (**done 2026-08-10, T-065**) —
     `GameProfile` + `SetupStep` (AOB/pointer-chain/address) + `ProfileCheat`,
     YAML round-trip, `discover_profiles` (scans `cheats/*.yaml` next to exe),
     MCP `list_profiles`/`load_profile`/`save_profile`. Loading runs setup to
     resolve base addresses and materializes cheats (populates known values,
     does NOT enable). Design in `docs/CHEAT_PROFILE.md`.
   - GUI session panel (**done 2026-08-10, T-060**) — markers, undo log, and
     pending (staged) mutations shown in the egui app with Confirm/Reject
     buttons, so the human can see and act on what the agent staged.
   - Module-base resolution (**done 2026-08-10**) — `PointerChain`/`Address`
     setup steps resolve module base against loaded modules, so cheat-profile
     chains are restart-stable. (Phase 5 Mono removed — out of scope.)

**goose config note:** `~/.config/goose/config.yaml` now has a `trainlab`
`streamable_http` extension (`http://127.0.0.1:8123/mcp`), **`enabled: false`**.
The training client enables it explicitly (e.g.
`goose session --with-streamable-http-extension "http://127.0.0.1:8123/mcp"`).

---

## 8. Useful commands / gotchas

- **Rebuild after code changes:** the running GUI/DLL are stale until rebuilt.
  The GUI exe and DLL are at `target/x86_64-pc-windows-gnu/debug/`.
- **Find which process has the DLL:** `grep trainlab_inject /proc/<pid>/maps`.
- **Game PID changes each launch** — always re-scan/re-inject.
- **Watchpoints can stall the game** (hardware debug registers) — clear them
  (`clear` stage) when done, and prefer restarting the game if the clock stalls.
- **Decompiling Mono games:** `DOTNET_ROOT=~/.dotnet DOTNET_ROLL_FORWARD=LatestMajor
  ~/.dotnet/tools/ilspycmd -p -o /tmp/urbek-decomp Assembly-CSharp.dll`.
- **Recon notes** live in `.goose/memory/` (gitignored, local-only).
