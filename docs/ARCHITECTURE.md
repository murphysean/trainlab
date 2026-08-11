# Architecture

This document is the source of truth for how `trainlab` is meant to work. It
distills the design conversations into a concrete plan. It describes the
**target** architecture — much of it is not yet built.

## 1. High-level shape

`trainlab` has three layers, separated by clear boundaries:

```
  LLM / agent
     │   MCP (HTTP, 127.0.0.1:PORT) — reasoning, orchestration, dialog
     ▼
  trainlab-gui (Rust, Windows, runs under Wine via STL)  ← the central hub
     │   injects the DLL via CreateRemoteThread + LoadLibrary
     │   fast channel — shared memory / TCP — low-level memory ops
     ▼
  Agent DLL (Rust cdylib, injected into the game process)
     │
     ▼
  Game (Windows .exe under Proton/Wine)
```

`trainlab-gui` is the **single control process**. It injects the DLL, manages it
over the fast channel, hosts the MCP HTTP server, and proxies MCP tool calls to
the DLL. It is the enforcement point for safety and the holder of session state.

Rules that must never be violated:

1. **The LLM never talks to the DLL directly.** It always goes through the
   Trainer. This keeps the low-level code lean and lets the Trainer enforce
   safety.
2. **Fast ops (scanning hot loops, patching) happen on the fast channel.**
   Reasoning (deciding *what* to patch) happens on the MCP channel.
3. **Every mutation is undoable.** The Trainer keeps a snapshot of original
   bytes for everything it changes.

## 2. The two channels

### Fast channel (Trainer ↔ DLL)

- **Transport:** shared memory or local TCP. The current code uses TCP with a
  4-byte LE length prefix + bincode payload (see `trainlab-core::protocol`).
- **Purpose:** high-frequency, low-latency memory operations that can't afford
  the MCP round-trip — value scans that need to run over many regions, AOB
  scans, pointer-chase reads, cave placement.
- **Why TCP today:** simplest thing that works and the code already has it.
  **Future:** shared memory for the hot loops to avoid syscall overhead.

### MCP channel (Trainer ↔ LLM)

- **Transport:** MCP over **HTTP** (streamable HTTP/SSE), **not stdio.**
  Reason: the Trainer is already running (spawned by STL into the Wine prefix);
  the LLM connects to it, it doesn't spawn it. So the Trainer **hosts an MCP
  server** bound to `127.0.0.1`. For remote (Steam machine/Deck) make the bind
  address configurable or tunnel it (SSH/Tailscale).
- **SDK:** [`rmcp`](https://github.com/nononov/rmcp) (Rust MCP SDK).
- **Purpose:** expose the Trainer's capabilities as MCP *tools* the agent can
  call, plus the agent's persistent session state.

## 3. The tool surface (MCP tools)

Grouped by risk. This is the contract the Trainer exposes to the agent.

### Attach / manage (session setup — agent may call freely)

These let an agent run the whole setup loop remotely (Steam Deck / Steam
machine): find the game, inject the DLL, connect, and query state — without
touching the GUI.

| Tool | What it does |
|------|--------------|
| `find_games` | List likely game processes (name + pid) |
| `attach_game` | Find the game by name, inject the DLL, connect to its listener |
| `connection_status` | Report connected state, game pid, game name, DLL version |
| `set_connection` | Set the DLL fast-channel host/port |

### Cheats (adjustable game options — agent builds, user adjusts)

The agent discovers a location and adds a **cheat** (a user-facing adjustable
game option). It shows up in the GUI's **Cheats panel** for the human to
adjust — value cheats (type a number, hit Apply) or toggle cheats (god mode,
on/off). The GUI writes value cheats directly (the user is the human
confirmation); the MCP `set_cheat_value`/`set_cheat_toggle` stage through the
D8 gate.

| Tool | What it does |
|------|--------------|
| `add_cheat` | Add a value or toggle cheat to the session (appears in the GUI panel) |
| `list_cheats` | List all cheats with ids, kinds, addresses |
| `remove_cheat` | Remove a cheat by id |
| `set_cheat_value` | Stage a typed value write for a value cheat (D8 gate) |
| `set_cheat_toggle` | Stage enabling/disabling a toggle cheat (D8 gate) |

### Read-only recon (agent may call freely)

| Tool | What it does |
|------|--------------|
| `list_regions` | Enumerate memory regions, filtered to interesting ones (private heap, skip mapped/GPU) |
| `scan` | Value scan with narrowing (type, value, changed/unchanged/increased/decreased) |
| `aob_scan` | Byte-pattern scan (`??` wildcards) |
| `read` | Read N bytes at an address |
| `dump_struct` | Read + format a struct at an address given a field map |
| `pointer_chase` | Walk a pointer chain, report each hop |
| `find_writes` | Find what instruction writes to an address (HW breakpoint / code hook) |
| `disassemble` | Disassemble a region (via iced-x86) |

### Mutating (agent proposes, human confirms)

The confirmation gate (D8): mutating tools **stage** a change and return a
pending op id + preview — they never touch memory directly. A separate
`confirm_op` applies it (snapshotting originals for undo); `reject_op` discards
it. `list_pending` shows everything awaiting confirmation.

| Tool | What it does |
|------|--------------|
| `write` | Stage a byte write (with undo snapshot, validated to writable regions) |
| `install_cave` | Stage a shellcode cave install (emit, place, write the jmp, save originals) |
| `undo` | Stage a revert to saved original bytes |
| `confirm_op` | Apply a staged mutation (the human-confirmation step) |
| `reject_op` | Discard a staged mutation without applying |
| `list_pending` | List all staged mutations awaiting confirmation |

### Session state

| Tool | What it does |
|------|--------------|
| `set_marker` / `get_markers` | Persist labeled addresses so the agent remembers across turns |
| `run_script` | Invoke a script (Lua/DSL) the agent wrote |

## 4. The code-cave mental model (critical)

> **A code cave is the *output* of logic, not the *runtime* for logic.**

When execution jumps into a cave, you are mid-function holding the game's
registers and stack. The **only** thing that can run there is minimal native
machine code that operates on that exact register/stack state. You **cannot**
call Lua, WASM, or a normal Rust/C function from inside a cave — a cave is an
inline patch context, not a call context.

The correct division:

```
[Logic decides WHAT to patch]  ←  Trainer (Lua/WASM/Rust), outside the cave
        ↓
[native emitter produces shellcode]  ← pure bytes that do ONE tiny thing
        ↓
[cave executes those bytes inline, touches a register or two, jumps back]
```

Example — "pin player ship health to 100":
1. Trainer finds the player pointer (scanning/pointer-chasing).
2. Trainer writes that pointer into a data area the cave can reach.
3. Trainer emits shellcode that `cmp`s a register against the stored pointer,
   and if it matches, overrides the value register.
4. Cave runs, jumps back.

The cave does the *comparing* (one `cmp`+`jne`). The Trainer does the *thinking*
(finding the player). Never put complex logic in a cave.

### The one advanced cave technique (rarely needed)

If you genuinely need to call a function from a cave, the "hollow trampoline"
works but is fragile:
- allocate a full stack frame in the cave,
- save all volatile registers (this is where crashes come from — register
  assumptions),
- `call` into a position-independent function you placed in the cave region,
- restore everything, jump back.

This is the source of the "register assumptions" crashes in real trainer work.
Avoid it unless you truly need it.

## 5. Memory access strategy

### The problem

Raw-scanning the whole address space wastes huge time on GPU/shader regions.
`/proc/pid/maps` on Linux is coarse — it groups allocations into contiguous
regions but doesn't tell you what each is *for*.

### The insight (novel)

The game is a **Windows process under Wine**, so Wine emulates the **Windows
memory model**. Therefore you can use **Windows heap/VM APIs** from your Windows
trainer DLL to enumerate *actual* heap blocks and their tags, then restrict
scans to the interesting ones. This is what CE does on Windows, and you can
leverage Wine to do the same.

Key APIs (via `windows-sys`):
- `GetProcessHeaps()` / `HeapWalk()` — enumerate heap blocks, sizes, tags.
- `VirtualQuery` — per-region state, protection, type (`MEM_IMAGE`,
  `MEM_MAPPED`, `MEM_PRIVATE`).

Filtering rule: **scan private heap regions; skip `MEM_IMAGE`/`MEM_MAPPED` and
read-only/executable code.** This is the "don't scan gigs of GPU assets" fix.

> **Caveat:** Wine's heap emulation isn't always 1:1 with Windows; some
> allocations may be merged or untagged differently. But the high-level win —
> *scan only the private heap* — works.

### Platform backends

- **Linux (`trainlab-core::memory::unix`)** — `process_vm_readv`/`writev` (no
  ptrace needed for read), `/proc/pid/maps` for regions. **Implemented.**
- **Windows (`trainlab-core::memory::windows`)** — `ReadProcessMemory`/
  `WriteProcessMemory`, `VirtualQuery`. **Stub. This is a priority.**

## 6. Injection / loading the DLL

### The chosen mechanism: `CreateRemoteThread` + `LoadLibrary`

The Windows `trainlab-gui` injects the Agent DLL into the game process using the
classic Windows injection primitive:

1. `OpenProcess` the game (with `PROCESS_ALL_ACCESS`).
2. `VirtualAllocEx` a region in the game for the DLL path string.
3. `WriteProcessMemory` the DLL path into that region.
4. `CreateRemoteThread` a thread in the game that runs `LoadLibraryW(path)`.
5. `WaitForSingleObject` for the thread; the DLL's `DllMain` runs and starts its
   listener.

The GUI then manages the DLL over the fast channel (ping, inject, unload).

### Launching (launcher-agnostic)

The trainer is launcher-agnostic (Cheat Engine / Aurora / Fling style): you ship
a binary and launch it alongside the game however you like. On Windows you run
the exe; on SteamOS/Linux you use any launcher that starts it in the same Wine
prefix as the game. **STL (Steam Tinker Launch)** is one convenient option — it
can *fork* the GUI alongside the game in the same Wine prefix, or *inject* it
after the game loads — but it is **not a requirement** and trainlab ships no
STL-specific scripts. See [`LAUNCHING.md`](LAUNCHING.md).

### Rejected alternatives

- **Proxy DLL (`WINEDLLOVERRIDES`)** — loads the DLL automatically at game
  start; less explicit control over injection timing/lifecycle. Viable fallback,
  not primary.
- **Vulkan layer** — runs on the Linux side of the Wine boundary; can't natively
  touch the game's Windows memory without bridging.
- **Linux `/proc/pid/mem` stub write** — works but more fragile; no clean
  Windows-native lifecycle.

## 7. Mono games are out of scope (for games like Urbek)

Mono games (Unity managed builds) keep their logic in a .NET assembly
(`Assembly-CSharp.dll`) JIT-compiled at runtime. **The trainer does not target
them.** The clean way to hack a Mono game is to **patch the IL in the assembly
before it loads** (a build/load-time patch via `ilspycmd`/`dnSpy`), not runtime
memory hacking. That's a different workflow and doesn't need runtime walking or
IL re-JIT hooks.

For a Mono game, `dnSpy`/`ilspy` can attach and debug at the IL/source level,
which beats both GDB and x64dbg for understanding game logic — but that's a
separate toolchain from this trainer. The trainer targets **native** games
(C/C++, Godot native, etc.) where inline code caves and value pinning apply.

## 8. Debugging under Wine — the hard truth

**GDB/PINCE on the Linux side cannot walk the game's Windows call stack.** The
game is a Windows process *inside* Wine; its Windows stack/heap are emulated,
not native frames. GDB sees the Linux process (Wine host) and stops at the Wine
boundary. This is fundamental, not a tooling gap.

Correct approaches:
- **Native x86 game:** use a Windows debugger *under Wine* (x64dbg) so you're
  in the Windows world.
- **Mono game:** debug at the Mono runtime level (dnSpy/ilspy).
- **Our framework:** prefer the MCP-driven recon over interactive debuggers for
  the scan/pointer-chase/cave workflow.

## 9. Scripting layer — deferred decision

Currently **no Lua/WASM** in the core. Rationale: the scripting layer's only job
is to *describe* what patch to make (a small job), and we don't yet know what
the cheat logic looks like. Build the Rust primitives first, use them to reverse
a real game, *then* decide whether a scripting layer earns its complexity.

If/when added:
- **Lua** — tiny, C-ABI friendly, proven (CE). Good choice.
- **WASM** — **avoid for this use case.** WASM is sandboxed and cannot emit or
  execute native x86-64 or touch raw registers. It'd be a wrapper that calls
  back into Rust for every interesting op — added indirection, no benefit.

## 10. Session state / agent memory

The agent's context is ephemeral and per-conversation. For a long reversing
session the framework must **persist** findings (confirmed offsets, hypotheses,
marker addresses) so the agent can reload them next turn. Design the **Trainer**
to hold session state (markers, undo log), not the LLM.

## 11. Crates and current gaps

| Crate | Present | Gaps |
|-------|---------|------|
| `trainlab-core` | protocol, Linux mem, AOB, process | Windows mem backend; value-scan algorithm; region scoping; pointer chase |
| `trainlab-inject` | TCP server, in-process mem | Windows allocate/free; injection entrypoints |
| `trainlab-scanner` | list/regions/aob/read/write | `next` is a stub (no persistent match set); real value narrowing |
| `trainlab-gui` | read/write/aob/regions/log | connect to MCP; session panel |
| *(new)* `trainlab-mcp` | — | MCP server, tool surface, markers, undo log |
| *(new)* `trainlab-cave` | — | shellcode emitter, hook installer, undo |

See [`docs/TODO.md`](docs/TODO.md) for the ordered build plan.
