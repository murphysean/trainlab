# trainlab

A Rust workspace for building **game trainers and reverse-engineering tooling**,
with a focus on Windows games running under **Proton/Wine on Linux**, and a
first-class **LLM/agent interface** (MCP) so a coding agent can help hunt,
scan, chase pointers, and develop code caves *live* alongside a human.

## What it is

`trainlab` is a **game trainer framework**, in the spirit of Cheat Engine,
Aurora, or Fling — you ship a **binary** (plus an injected DLL) that you launch
alongside your game using whatever tools you prefer. It is **not** a game
launcher and does not replace tools like Steam Tinker Launch (STL). If you're
on Windows you just run the exe; on SteamOS/Linux you use whatever launcher
you like (STL is one option among many) to start it alongside the game.

It additionally exposes a **Model Context Protocol (MCP) server** so an LLM or
coding agent can drive memory recon, pointer chasing, scans, and code-cave
development live, next to a human.

## Status

**Working and validated (Phases 0–4).** The framework supports live recon and
mutating against a running game:

- **Memory recon** — value scans (i32/u32/f32/i64/u64/f64/ptr) with narrowing,
  AOB pattern scans, reverse-reference pointer scans, pointer-chain chasing,
  region listing.
- **Struct/class reversal** — raw hex+ASCII `dump` and typed `dump_struct`
  (read a struct as fields by name/type/offset).
- **Code analysis** — `disassemble` (iced-x86), `addr_to_module` (restart-stable
  module+offset resolution), hardware watchpoints and breakpoints to find what
  *writes* an address.
- **Code caves / hooks** — install transparent (trampoline) or override code
  caves with shellcode payloads.
- **Safety** — every mutation is **staged and human-confirmed** (a confirmation
  gate), and every applied mutation is **undoable**.
- **Windows injection** — `trainlab-gui` finds the game process, injects the
  DLL via `CreateRemoteThread`+`LoadLibrary`, and manages it over a fast
  channel.
- **MCP server** — the GUI hosts a Streamable-HTTP MCP server so an agent can
  drive the above tools.
- **Remote attach / full LLM control** — `find_games` / `attach_game` /
  `connection_status` / `set_connection` let an agent run the whole setup loop
  (find the game, inject the DLL, connect) remotely from a desktop against a
  Steam Deck / Steam machine, then do all the recon and training work.
- **Cheats panel** — the agent discovers a location and adds a **cheat** (a
  user-facing adjustable game option) that appears in the GUI's **Cheats panel**
  for the human to adjust: value cheats (type a number, hit Apply) or toggle
  cheats (god mode, on/off). MCP: `add_cheat` / `list_cheats` / `remove_cheat` /
  `set_cheat_value` / `set_cheat_toggle`.
- **Portable cheat profiles** — a YAML cheat table (`cheats/*.yaml`) describing
  a game's discovered layout: setup steps (AOB scans, pointer chains, addresses)
  that resolve base addresses on attach, plus the cheats that reference them.
  Pointer chains resolve module bases against the live process, so tables are
  restart-stable. MCP: `list_profiles` / `load_profile` / `save_profile`.
  LLM-friendly, versionable, shareable. See `docs/CHEAT_PROFILE.md`.
- **Session panel** — the GUI shows markers, the undo log, and pending (staged)
  mutations with Confirm/Reject buttons, so the human can see and act on what
  the agent staged via MCP.

See [`docs/TODO.md`](docs/TODO.md) for the build plan. Mono/Unity games are
**out of scope** — the clean way to hack those is a pre-load IL patch (a
build-time tool), not a runtime trainer.

## Why this exists

Urbek (a Unity **Mono** game) exposed a hard problem: pinning a resource *stock*
value fails because the game loop recomputes stock from a *rate* every tick. The
lesson generalizes — trainers fail when they fight the game's loop instead of
working with it. (Mono games themselves are out of scope — the clean hack is a
pre-load IL patch, not a runtime trainer.) This project is an attempt to build a
proper, reusable trainer framework that:

- works with the game loop, not against it (code caves / hooks over value-pinning),
- handles the **Proton/Wine** reality (Windows DLL inside a Wine prefix),
- scopes memory scans intelligently (heap/VM regions, not whole address space),
- exposes a clean **C ABI** for a **Rust** trainer DLL,
- and lets an **LLM/agent drive the reversing loop** over **MCP**,
- with `trainlab-gui` as the central hub that injects the DLL, manages it, and
  proxies MCP tool calls to it.

## The core architecture

```
┌──────────────────────────┐
│  Game (Windows .exe)     │
│   ┌────────────────────┐ │
│   │ Agent DLL (Rust)   │ │   in-process: scan, AOB, cave, hooks
│   │  cdylib, loaded    │ │
│   │  via CreateRemote  │ │
│   │  Thread+LoadLibrary│ │
│   └─────────┬──────────┘ │
└─────────────┼────────────┘
              │ fast channel: shared memory / TCP (low-level)
              ▼
┌──────────────────────────┐
│  trainlab-gui (Rust,    │   the central hub: injects the DLL,
│  Windows, under Wine)   │   manages it, hosts the MCP server,
│   ┌────────────────────┐ │   proxies MCP calls to the DLL
│   │ MCP server (HTTP) │ │   exposes scan/aob/read/cave tools
│   └─────────┬──────────┘ │
└─────────────┼────────────┘
              │ MCP over HTTP (slow, reasoning)
              ▼
┌──────────────────────────┐
│  LLM / coding agent      │   hunts, chases pointers, dialogs
└──────────────────────────┘
```

Two channels, two speeds, two purposes:
- **Fast** (shared memory / TCP): trainer ↔ DLL. High-frequency memory ops.
- **MCP (HTTP)**: trainer ↔ LLM. Reasoning/orchestration. Slow is fine; it's for thinking.

The **LLM never talks to the DLL directly** — it talks to the trainer, which
translates MCP tool calls into DLL commands. This keeps the low-level code lean
and lets the trainer enforce safety (undo, region validation, confirmation gates).

## Workspace layout

| Crate | Role |
|-------|------|
| `trainlab-core` | Shared protocol (bincode + TCP framing), memory primitives, AOB scanning, scan engine, pointer chasing, disassembly, process discovery |
| `trainlab-inject` | `cdylib` (`.dll`/`.so`) loaded into the game; serves memory requests over TCP |
| `trainlab-scanner` | CLI memory-hunting tool (`trainlab-scan`) |
| `trainlab-gui` | **The central hub**: injects the DLL (`CreateRemoteThread`+`LoadLibrary`), manages it over the fast channel, hosts the MCP HTTP server, and proxies MCP tool calls to the DLL |

## Quickstart

```bash
cargo build
cargo test
cargo run -p trainlab-scanner -- list              # find the game PID
cargo run -p trainlab-scanner -- regions <pid>     # list memory regions
cargo run -p trainlab-scanner -- aob <pid> "48 8B 05 ?? ?? ?? ??"   # AOB scan
```

## Launching the trainer

`trainlab-gui` is the trainer you run alongside your game. It is launcher-agnostic:

- **Windows** — just run `trainlab-gui.exe`.
- **Linux / SteamOS** — launch it however you like (a terminal, a custom script,
  STL, Heroic, etc.) so it starts alongside the game. It needs to be in the same
  Wine prefix / environment as the game to inject the DLL.

See [`docs/LAUNCHING.md`](docs/LAUNCHING.md) for environment variables
(`TRAINLAB_GAME`, `TRAINLAB_MCP_HOST`, `TRAINLAB_MCP_PORT`) and remote
connectivity.

## Connecting an agent (MCP)

The GUI hosts an MCP server on `http://127.0.0.1:8123/mcp` (bind address
configurable via `TRAINLAB_MCP_HOST`, default `0.0.0.0`). Point a goose
`streamable_http` extension at it:

```yaml
  trainlab:
    type: streamable_http
    uri: http://127.0.0.1:8123/mcp
    enabled: false   # enable per-session, e.g. with --with-streamable-http-extension
```

## Cross-compiling to Windows

The GUI and inject DLL cross-compile to Windows from Linux (no Docker needed):

```bash
rustup target add x86_64-pc-windows-gnu
sudo pacman -S mingw-w64-gcc
cargo build --target x86_64-pc-windows-gnu -p trainlab-gui
cargo build --target x86_64-pc-windows-gnu -p trainlab-inject
```

The scanner is **Linux-only** (it reads `/proc/pid/mem`). See
[`docs/BUILDING.md`](docs/BUILDING.md) for details.

## Docs

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — full architecture, data flow, decisions
- [`docs/CONCEPTS.md`](docs/CONCEPTS.md) — the game-hacking concepts you need (code caves, Proton/Wine, injection)
- [`docs/DESIGN_DECISIONS.md`](docs/DESIGN_DECISIONS.md) — why each decision was made
- [`docs/BUILDING.md`](docs/BUILDING.md) — how to build for Linux and Windows (cross-compile)
- [`docs/LAUNCHING.md`](docs/LAUNCHING.md) — how to launch the trainer alongside your game, and remote connectivity
- [`docs/CHEAT_PROFILE.md`](docs/CHEAT_PROFILE.md) — the portable YAML cheat-table format (schema, setup steps, pinning)
- [`docs/TODO.md`](docs/TODO.md) — the build plan, in order
- [`docs/AGENT_GUIDE.md`](docs/AGENT_GUIDE.md) — how an LLM/agent should work on this codebase
- [`docs/REVERSING_WORKFLOW.md`](docs/REVERSING_WORKFLOW.md) — the end-to-end reversing process this framework enables

## License

Dual-licensed under **MIT** ([LICENSE-MIT](LICENSE-MIT)) and **Apache-2.0**
([LICENSE-APACHE](LICENSE-APACHE)) — permissive and very open. See
[LICENSE](LICENSE) for the full terms.
