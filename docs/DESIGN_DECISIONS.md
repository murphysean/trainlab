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

## D6: Windows DLL + STL, with proxy-DLL as the load mechanism to evaluate

**Decision:** Build a Windows trainer DLL that runs under Wine (via STL fork),
and evaluate **proxy DLL (`WINEDLLOVERRIDES`)** vs **injection
(`CreateRemoteThread`+`LoadLibrary`)** as the load mechanism.

**Why:** A Windows DLL running in the same Wine prefix can use native Windows
APIs against the game. Proxy DLL needs no injection tooling (game loads it
naturally) and is very portable.

**Why not Vulkan layer:** Runs on the Linux side of the Wine boundary; can't
natively touch the game's Windows memory without bridging. Proxy DLL is simpler
and more direct for hooking a Windows game's memory.

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

## D9: Mono games (Urbek) as a first-class target

**Decision:** Support Mono runtime walking and IL-level hooking in addition to
native x86 caves.

**Why:** Mono games decompile near-losslessly and hook cleanly at the runtime
level. Urbek is a great first target to prove the framework against a real,
tractable game.

## Open decisions (not yet made)

- **OD1:** Fast channel — keep TCP or move to shared memory for hot loops?
- **OD2:** Scripting layer — add Lua later if iteration speed demands it?
- **OD3:** Load mechanism — proxy DLL vs `CreateRemoteThread` injection vs Linux
  `/proc/pid/mem` stub write? (D6 lists these to evaluate.)
- **OD4:** Remote connectivity — how to expose MCP for Steam Deck (bind address,
  SSH tunnel, Tailscale)?
