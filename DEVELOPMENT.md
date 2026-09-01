# Trainlab Developer Guide

This document covers repository structure, building, cross-compilation, running test suites, and developing internal subsystems within `trainlab`.

---

## 1. Workspace Architecture

`trainlab` is split into targeted crates:

| Crate | Purpose | Platform |
|-------|---------|----------|
| [`trainlab-core`](crates/trainlab-core) | Core data models, AOB engine, disassembly (`iced-x86`), CE-style asm assembly, pointer chase, session management, and cheat profile schema. | Cross-platform |
| [`trainlab-inject`](crates/trainlab-inject) | Dynamic library (`.dll`) injected into the target Windows game. Handles DirectX 11 in-game overlay rendering (`egui`), XInput interception, and in-process execution. | Windows (`x86_64-pc-windows-gnu`) |
| [`trainlab-gui`](crates/trainlab-gui) | Standalone trainer GUI application (`egui`/`eframe`), remote MCP server (Streamable-HTTP), Web UI backend, process management, and DLL injection manager. | Windows / Linux |
| [`trainlab-cave`](crates/trainlab-cave) | Shellcode assembly emission and trampoline/override cave patch generation. | Cross-platform |
| [`trainlab-scanner`](crates/trainlab-scanner) | Standalone CLI memory hunting tool. | Linux (`/proc/pid/mem`) |

---

## 2. Building & Cross-Compiling

### Prerequisites (Linux Host)
- Rust toolchain (`rustup`)
- MinGW GCC toolchain:
  - Arch / Manjaro: `sudo pacman -S mingw-w64-gcc`
  - Debian / Ubuntu: `sudo apt-get install gcc-mingw-w64-x86-64`
- Windows target:
  ```bash
  rustup target add x86_64-pc-windows-gnu
  ```

### Build Commands

#### Native Linux Build & Test Suite:
```bash
cargo check
cargo test --all
```

#### Windows Release Binaries (for Steam Deck / Wine / Windows):
```bash
cargo build --release --target x86_64-pc-windows-gnu --package trainlab-gui --package trainlab-inject
```

Artifacts are produced in:
- `target/x86_64-pc-windows-gnu/release/trainlab-gui.exe`
- `target/x86_64-pc-windows-gnu/release/trainlab_inject.dll`

---

## 3. Architecture & Internal Contracts

### Dual-Channel Communication
```
┌──────────────────────────────────────────────┐
│ Game Process (.exe)                          │
│   ┌────────────────────────────────────────┐ │
│   │ Injected DLL (trainlab_inject.dll)     │ │   DirectX 11 Overlay + Hooks
│   └───────────────────▲────────────────────┘ │
└───────────────────────┼──────────────────────┘
                        │ TCP Channel (Port 31337)
┌───────────────────────▼──────────────────────┐
│ Trainlab GUI (trainlab-gui.exe)              │   Session Manager + Profile Runner
│   ┌────────────────────────────────────────┐ │
│   │ MCP Server (Port 8123) / Web UI (8080) │ │
│   └───────────────────▲────────────────────┘ │
└───────────────────────┼──────────────────────┘
                        │ HTTP / JSON-RPC
┌───────────────────────▼──────────────────────┐
│ AI Coding Agent (MCP) / Browser User         │
└──────────────────────────────────────────────┘
```

1. **Fast In-Process Channel (TCP 31337)**: Handles high-speed memory read/write requests, code cave installation, and UI event synchronization between `trainlab-gui` and `trainlab_inject.dll`.
2. **MCP HTTP Server (`:8123/mcp`)**: Exposes structured reversing and memory tooling to external AI agents and automation.

---

## 4. Documentation & Specifications
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — Comprehensive technical design & IPC protocol.
- [`docs/CHEAT_PROFILE.md`](docs/CHEAT_PROFILE.md) — Specification for the YAML cheat profile format.
- [`docs/CONCEPTS.md`](docs/CONCEPTS.md) — Reverse engineering principles, code caves, and Wine memory layout.
- [`docs/DESIGN_DECISIONS.md`](docs/DESIGN_DECISIONS.md) — Architectural rationale and design trade-offs.
- [`docs/ISSUE_TEMPLATE.md`](docs/ISSUE_TEMPLATE.md) — Template for logging bugs and feature proposals in `inbox/`.
