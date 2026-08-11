# Building

How to build `trainlab` for both Linux and Windows targets.

## Prerequisites

- **Rust** (stable) + `rustup`
- **Linux target** — default, nothing extra.
- **Windows target** — two pieces:
  ```bash
  rustup target add x86_64-pc-windows-gnu
  sudo pacman -S mingw-w64-gcc     # Arch; provides the MinGW-w64 linker
  ```
  No Docker/podman needed — Rust cross-compiles to Windows directly from Linux.

## Which target for which crate

| Crate | Linux | Windows |
|-------|-------|---------|
| `trainlab-core` | ✅ | ✅ |
| `trainlab-inject` | ✅ (`.so`) | ✅ (`.dll`) |
| `trainlab-gui` | ✅ (dev only) | ✅ (`.exe`) — **the real target** |
| `trainlab-scanner` | ✅ | ❌ **Linux-only** (imports `LinuxProcess`, a `#[cfg(unix)]` type) |

The **scanner is Linux-only by design** — it's a CLI hunting tool that reads
`/proc/pid/mem`. It should never be built for the Windows target.

## Build commands

### Linux (default)
```bash
cargo build
cargo test
```

### Windows (cross-compile)
```bash
# The two crates that matter for Windows:
cargo build --target x86_64-pc-windows-gnu -p trainlab-gui
cargo build --target x86_64-pc-windows-gnu -p trainlab-inject
```

Artifacts land in `target/x86_64-pc-windows-gnu/debug/`:
- `trainlab-gui.exe` — PE32+ x86-64 Windows executable
- `trainlab_inject.dll` — PE32+ x86-64 Windows DLL

> **Do NOT** run `cargo build --target x86_64-pc-windows-gnu` (whole workspace) —
> it will try to build `trainlab-scanner` for Windows and fail, because the
> scanner is Linux-only. Build the GUI and inject crates explicitly.

## Running the Windows binaries

Cross-compiling produces Windows PE binaries. To *run* them you need **Wine**
(they're Windows binaries). Under STL, the GUI runs in the same Wine prefix as
the game so it can inject the DLL via `CreateRemoteThread`.

## Current status

- ✅ `trainlab-gui` and `trainlab-inject` cross-compile to Windows cleanly.
- ⚠️ The Windows **memory backend** in `trainlab-core` is still a stub (T-010).
  The GUI/inject compile, but real Windows memory work needs that implemented.
- ⚠️ The Windows `allocate`/`free` in `trainlab-inject` are stubs (T-041).
