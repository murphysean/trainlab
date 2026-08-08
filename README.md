# trainlab

A Rust workspace for building **game trainers and reverse-engineering tooling**,
with a focus on Windows games running under **Proton/Wine on Linux**, and a
first-class **LLM/agent interface** (MCP) so a coding agent can help hunt,
scan, chase pointers, and develop code caves *live* alongside a human.

## Status

**Early scaffolding.** The core protocol, Linux memory primitives, AOB scanning,
a CLI scanner, an injectable DLL stub, and an egui GUI control panel exist and
compile. The exciting parts — real value scanning, pointer chasing, code-cave
emission, undo, Windows injection, Wine-aware region scoping, the MCP server,
and Mono support — are **not yet built**. See [`docs/TODO.md`](docs/TODO.md).

## Why this exists

Urbek (a Unity **Mono** game) exposed a hard problem: pinning a resource *stock*
value fails because the game loop recomputes stock from a *rate* every tick. The
lesson generalizes — trainers fail when they fight the game's loop instead of
working with it. This project is an attempt to build a proper, reusable trainer
framework that:

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
| `trainlab-core` | Shared protocol (bincode + TCP framing), memory primitives, AOB scanning, process discovery |
| `trainlab-inject` | `cdylib` (`.dll`/`.so`) loaded into the game; serves memory requests over TCP |
| `trainlab-scanner` | CLI memory-hunting tool (`trainlab-scan`) |
| `trainlab-gui` | **The central hub**: injects the DLL (`CreateRemoteThread`+`LoadLibrary`), manages it over the fast channel, hosts the MCP HTTP server, and proxies MCP tool calls to the DLL |

## Quickstart

```bash
cargo build
cargo run -p trainlab-scanner -- list              # find the game PID
cargo run -p trainlab-scanner -- regions <pid>     # list memory regions
cargo run -p trainlab-scanner -- aob <pid> "48 8B 05 ?? ?? ?? ??"   # AOB scan
```

> **Note:** The workspace currently only compiles on Linux for the Linux paths
> (the `windows` memory backend is a stub, and `trainlab-inject`'s `no_mangle`
> needs `unsafe(...)` under edition 2024 — see `docs/TODO.md`).

## Docs

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — full architecture, data flow, decisions
- [`docs/CONCEPTS.md`](docs/CONCEPTS.md) — the game-hacking concepts you need (code caves, Mono, Proton/Wine, injection)
- [`docs/DESIGN_DECISIONS.md`](docs/DESIGN_DECISIONS.md) — why each decision was made
- [`docs/TODO.md`](docs/TODO.md) — the build plan, in order
- [`docs/AGENT_GUIDE.md`](docs/AGENT_GUIDE.md) — how an LLM/agent should work on this codebase
- [`docs/REVERSING_WORKFLOW.md`](docs/REVERSING_WORKFLOW.md) — the end-to-end reversing process this framework enables

## License

MIT OR Apache-2.0 (per `Cargo.toml`).
