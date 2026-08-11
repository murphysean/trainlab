# Agent Guide — How to work on `trainlab`

This guide tells a coding agent (or a human working with one) how to productively
operate on this codebase. It captures the context, the gotchas, and the workflow
so you don't have to re-derive them from scratch.

## 1. The big picture in one paragraph

`trainlab` is a Rust workspace for building game trainers for Windows games
running under **Proton/Wine on Linux**, with a first-class **MCP interface** so
an LLM can drive the reversing loop (scan, pointer-chase, code caves) live
alongside a human. The three layers: **game** ←fast→ **Agent DLL** ←fast→
**Trainer** ←MCP→ **LLM**. The LLM never talks to the DLL directly.

## 2. Read these first, in order

1. `README.md` — orientation, crate map, quickstart.
2. `docs/ARCHITECTURE.md` — the target design (much not built yet). Read the
   "code-cave mental model" section carefully — it's the conceptual core.
3. `docs/DESIGN_DECISIONS.md` — *why* things are the way they are. If you're
   about to "improve" something, check here first — it may be a deliberate
   decision, not an oversight.
4. `docs/TODO.md` — the ordered build plan. Work top-down; items build on each
   other.
5. `docs/CONCEPTS.md` — the game-hacking vocabulary (scanning, caves, Mono,
   Wine, injection).

## 3. Current state (important — set expectations)

This is **early scaffolding**, not a finished tool. Be aware:

- **It compiles on Linux** for the Linux paths. There is a **known build error**
  right now: `crates/trainlab-inject/src/lib.rs:243` uses `#[no_mangle]`, which
  edition 2024 rejects — must be `#[unsafe(no_mangle)]`. That's T-000.
- The **Windows memory backend is a stub** (`trainlab-core::memory::windows`).
  Real Windows work needs `windows-sys` and implementing `ReadProcessMemory`/
  `WriteProcessMemory`/`VirtualQuery`.
- `trainlab-scanner`'s `next` command is a **stub** (no persistent match set).
- There is **no MCP server yet**, **no code-cave emitter**, **no pointer
  chasing**, **no Mono support**. Those are the exciting parts, all TODO.
- It's **not a git repo yet** (T-001). Consider initializing it.

**So if the user asks you to "make the trainer find a value in Urbek," the honest
answer is: the pieces for that aren't built yet.** The right move is to work the
TODO list top-down, not to try to hack around missing foundations.

## 4. Workflow / how to help

When asked to do something on `trainlab`:

1. **Orient:** read the relevant doc (above). Check `docs/TODO.md` for whether
   the task is already planned and where it fits.
2. **Check the design decisions** before proposing a change — respect D1–D9.
3. **Build incrementally, bottom-up:** `trainlab-core` first (memory, scan,
   protocol), then consumers. Verify with `cargo build`/`cargo test` after each
   unit of work.
4. **When a change affects the protocol** (`trainlab-core::protocol`), update
   *all* consumers (inject, scanner, gui) — the whole point of keeping the
   protocol in core is that they can't drift.
5. **Prefer adding to TODO.md** (with a T-number) over silently expanding scope.
   Keep it a faithful, ordered plan.

## 5. Key gotchas

- **Edition 2024:** `#[no_mangle]` → `#[unsafe(no_mangle)]`.
- **`trainlab-core` is the shared protocol crate.** Changes ripple everywhere.
- **The fast channel uses TCP + bincode + 4-byte length framing** (see
  `protocol.rs`). If you change it, change `encode`/`decode` and all callers
  together.
- **The memory layer is a `ProcessMemory` trait** with `LinuxProcess`/
  `SelfProcess` impls. Windows impl is a stub. Keep the trait as the seam.
- **Don't try to run a real Windows game from this Linux workspace.** Building
  the `windows` backend and the inject crate for the Windows target requires
  cross-compilation (or building on Windows/Wine). For now, develop and test the
  Linux paths; the Windows paths are where the *real* game work happens later.

## 6. Safety principles (respect these in code)

- **Every mutation must be undoable.** Store original bytes. (D8)
- **Mutating MCP tools need a confirmation gate** or dry-run. (D8)
- **Never put complex logic in a code cave** — caves are minimal native
  shellcode. (D4 / ARCHITECTURE §4)
- **Scope scans to private heap** via region classification, don't scan the
  whole address space. (D5)

## 7. If the user is doing live reversing

If a session is in progress (game running, trainer attached), your role is to
drive the MCP recon tools and *dialogue* with the human about findings. Use the
markers (`set_marker`/`get_markers`) to persist your progress — your context is
ephemeral, the Trainer's state is not. Propose (don't silently execute) any
mutation, and always confirm.

## 8. Definition of done for a unit of work

- Compiles (`cargo build`) and tests pass (`cargo test`).
- Protocol changes ripple to all consumers.
- Design decisions respected (check DESIGN_DECISIONS).
- TODO.md updated (item checked off / new T-number).
- New behavior is documented (at least a code comment; a doc section if notable).
