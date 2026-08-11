# Design Decisions

A record of *why* `trainlab` is designed the way it is. Each entry: decision,
rationale, and alternatives considered. This is a living doc — add entries as
you make new decisions.

## D1: Two channels (fast + MCP) instead of one

**Decision:** The Trainer talks to the DLL over a fast channel (TCP/shared
memory), and to the LLM over MCP (HTTP). The LLM never talks to the DLL directly.

**Why:** High-frequency memory ops (scanning hot loops) can't afford the
reasoning channel's round-trip. And the LLM should never drive low-level code
directly — the Trainer enforces safety (undo, region validation, confirmation).
Separating concerns keeps the DLL lean and the reasoning safe.

**Alternatives:** LLM→DLL directly (rejected: unsafe, no enforcement point).

## D2: MCP over HTTP, not stdio

**Decision:** The Trainer hosts an MCP server over streamable HTTP/SSE.

**Why:** The Trainer is already running (spawned by STL). The LLM connects to
it; it doesn't spawn it. So HTTP server, not stdio child process.

**Why `rmcp`:** Mature Rust MCP SDK.

## D3: Rust for everything (no Lua/WASM in core, for now)

**Decision:** Core is Rust. No scripting layer yet. If one is added later, Lua
over WASM.

**Why defer:** The scripting layer's only job is to *describe* what to patch — a
small job. We don't yet know what the cheat logic looks like. Build primitives
first, reverse a real game, then decide.

**Why Lua over WASM if added:** WASM is sandboxed and can't emit/execute native
x86-64 or touch raw registers — it'd be a wrapper that calls back into Rust for
every interesting op. Lua is tiny, C-ABI friendly, proven (CE).

## D4: Code caves are outputs, not runtimes

**Decision:** Logic runs in the Trainer; caves contain minimal native shellcode
that does one register-level thing.

**Why:** A cave is an inline patch context holding live registers/stack. You
can't call Lua/WASM/Rust functions from it. Complex logic in a cave is where
crashes come from (register assumptions).

## D5: Scope scans via Windows heap/VM APIs under Wine

**Decision:** Use `GetProcessHeaps`/`HeapWalk`/`VirtualQuery` from the Windows
trainer DLL to enumerate heap blocks, then restrict scans to private heap. Skip
`MEM_IMAGE`/`MEM_MAPPED` and code regions.

**Why:** Solves "scanning gigs of GPU assets." `/proc/pid/maps` is coarse and
doesn't tag allocations; Wine emulates the Windows memory model so the Windows
APIs work.

**Caveat:** Wine's heap emulation isn't always 1:1; some allocations may be
merged/untagged. The high-level win (scan only private heap) still holds.

## D6: Load the DLL via `CreateRemoteThread` + `LoadLibrary`

**Decision:** The Windows `trainlab-gui` injects the Agent DLL into the game
process using **`CreateRemoteThread` + `LoadLibrary`** (the classic Windows
injection primitive), then manages it over the process-to-process channel.

**Why:** This is the most direct and standard mechanism. The GUI (a Windows
binary running under Wine via STL) can call `OpenProcess` +
`CreateRemoteThread` + `LoadLibrary` against the game as a normal Windows
process. It gives full control over when the DLL loads and lets the GUI manage
the DLL's lifecycle (inject, ping, unload) explicitly.

**Why not proxy DLL (`WINEDLLOVERRIDES`):** It loads the DLL automatically when
the game starts, which is less explicit and gives the GUI less control over
injection timing and lifecycle. It's a viable fallback but not the primary path.

**Why not Vulkan layer:** Runs on the Linux side of the Wine boundary; can't
natively touch the game's Windows memory without bridging. Rejected.

**Why not Linux `/proc/pid/mem` stub write:** Works but is more fragile and
doesn't give the clean Windows-native lifecycle that `CreateRemoteThread` does.

## D7: The Trainer holds session state, not the LLM

**Decision:** Markers, confirmed offsets, hypotheses, and undo log live in the
Trainer.

**Why:** The LLM's context is ephemeral and per-conversation. For a long
reversing session, findings must persist so the agent can reload them next turn.

## D8: Every mutation is undoable

**Decision:** Any write/cave operation snapshots original bytes and can be
reverted. Write/cave tools require a confirmation gate (or dry-run).

**Why:** An autonomous agent writing raw memory can crash the game or corrupt
state. Undo + confirmation is the safety contract that makes agent-driven
mutating safe enough to use.

**Implemented (2026-08-10):** the confirmation gate is enforced in the Trainer.
Mutating MCP tools (`write`, `install_cave`, `undo`) **stage** a change into the
session and return a pending op id + a human-readable preview; they never touch
memory. A separate `confirm_op` tool applies a staged op (snapshotting originals
for undo); `reject_op` discards it; `list_pending` enumerates everything awaiting
confirmation. There is no `confirm:true` shortcut an agent can pass to bypass
the gate — a human must call `confirm_op` (or a human-driven client must).

## D9: Mono games (Urbek) are NOT a trainer target

**Decision (revised 2026-08-10):** Mono/Unity games are **out of scope** for
the trainer. The clean way to hack a Mono game is to **patch the IL in the
assembly before it loads** (a build/load-time patch via `ilspycmd`/`dnSpy`),
not runtime memory hacking. That's a different workflow and doesn't need
runtime walking or IL re-JIT hooks.

**Why:** Mono games keep logic in a .NET assembly JIT'd at runtime. Inline
byte-level code caves are hostile to them (the JIT re-emits code), and the
lossless decompilation + pre-load IL patching is a far better fit than runtime
hooking. The trainer targets **native** games (C/C++, Godot native, etc.)
where inline caves and value pinning apply. Urbek was a useful *proof* of the
framework's limits, not a target to support.

## D10: `trainlab-gui` is the central hub (injector + MCP server + proxy)

**Decision:** The Windows `trainlab-gui` is the single control process. It:
1. **Injects** the Agent DLL into the game via `CreateRemoteThread`+`LoadLibrary`.
2. **Manages** the DLL over the process-to-process channel (the fast channel).
3. **Hosts a full HTTP server** offering an MCP (`rmcp`) connection with tools
   for all commands.
4. **Proxies** MCP tool calls to the game DLL over the fast channel.

**Why:** This makes the GUI the one place that owns both the low-level channel
(to the DLL) and the reasoning channel (to the LLM). It's the enforcement point
for safety (undo, region validation, confirmation) and the holder of session
state (markers, undo log). The LLM talks only to the GUI; the GUI talks to the
DLL.

## Open decisions (not yet made)

- **OD1:** Fast channel — keep TCP or move to shared memory for hot loops?
- **OD2:** Scripting layer — add Lua later if iteration speed demands it?
- **OD4:** Remote connectivity — how to expose MCP for Steam Deck (bind address,
  SSH tunnel, Tailscale)?
