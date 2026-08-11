# Game-Hacking Concepts (for trainlab)

A distilled reference of the concepts needed to build and use `trainlab`. This
captures the working knowledge behind the design — the vocabulary and mental
models that make the code make sense.

## 1. External vs internal

- **External** — a separate process reads/writes the game's memory. On Linux via
  `/proc/pid/mem` or `process_vm_readv/writev`; on Windows via
  `ReadProcessMemory`/`WriteProcessMemory`. No code runs inside the game. Safe,
  easy to write. This is what the Sins 2 work did.
- **Internal** — code runs *inside* the game process (injected DLL, proxy DLL,
  or a code cave). More powerful, more fragile. Needed for code caves/hooks.

The moment you move from manipulating *data* to manipulating *code execution*,
you cross the internal boundary.

## 2. Value scanning (the data layer)

The scanmem/Cheat Engine workflow:

1. **First scan** — find all addresses holding a value.
2. **Narrow** — as the game runs, filter by `changed` / `unchanged` /
   `increased` / `decreased`, or rescan for a new exact/range value.
3. **Identify** — you end up with a handful of addresses; the real one usually
   sits in a struct with other related fields nearby (±0x200 bytes).

**Limitation (why pinning fails on rate-based economies):** some games (Urbek)
compute a *rate* each tick and apply it to a *stock*. Pinning the stock is
futile — the next tick recomputes it. You must either pin the **rate** or hook
the **code** that applies it. **Work with the loop, not against it.**

## 3. Pointer chasing

The value isn't at a fixed address — it's behind a pointer chain:
`manager → object → field → field`. You find the pointer chain so your trainer
survives the game reallocating memory between launches. This is the "why does my
address change every launch" problem.

`pointer_chase` is a core tool: read a pointer, follow it, report each hop.

## 4. Code caves & inline hooks (the code layer)

- **Code cave** — find a gap (run of `0xCC`/`0x00`) in an executable region,
  `jmp` into it, run your instructions, `jmp` back.
- **Inline hook / detour** — overwrite the first bytes of a target function
  with a `jmp` to your code. Same concept as an EDR/AV inline hook.

**The cardinal rule:** a cave is an **inline patch context**, not a call
context. It holds the game's live registers and stack. Only minimal native
shellcode can run there. All logic lives in the trainer; the cave does one tiny
register-level thing.

## 5. "Find what writes to this address"

Install a **hardware watchpoint** on an address. When the game writes to it,
the CPU traps; you capture the instruction pointer and register state. This
reveals the code that mutates your value — the anchor for a hook.

Tools: gdb watchpoints (Linux native), CE's "find what writes", or `find_writes`
in our framework.

## 6. AOB patterns

Array-of-bytes scanning: find a distinctive byte pattern (with `??` wildcards)
to locate a function/data structure, then use it as an anchor. This survives
ASLR because you're matching bytes, not absolute addresses. `trainlab-core::aob`
implements this.

## 7. The Mono special case (out of scope)

Mono games (Unity managed) keep logic in a .NET assembly, JIT'd at runtime.

- **Decompilation is near-lossless.** A .NET decompiler reconstructs
  near-original C# with real method/field/class names — far better than C/C++.
- **The clean hack is a pre-load IL patch** — patch the assembly before it
  loads (via `ilspycmd`/`dnSpy`), not runtime memory hacking. The JIT re-emits
  code, so byte-level inline caves are fragile.
- Debug with `dnSpy`/`ilspy` at the IL/source level.

This is why Mono games are **out of scope** for the trainer: the pre-load IL
patch is a build-time workflow, not a runtime trainer. The trainer targets
**native** games (C/C++, Godot native, etc.) where inline caves and value
pinning apply.

## 8. Proton / Wine reality

- The game is a **Windows PE inside a Wine process**.
- **GDB/PINCE on Linux cannot walk the game's Windows call stack** — the
  Windows stack/heap are emulated above Wine's native frames. This is
  fundamental. Use a Windows debugger under Wine (x64dbg) or a Mono-level
  debugger instead.
- Wine **does** emulate the Windows memory model, so **Windows heap/VM APIs work**
  against a Proton game. This lets you enumerate heap blocks (via
  `GetProcessHeaps`/`HeapWalk`/`VirtualQuery`) and scope scans to private heap —
  the fix for "scanning gigs of GPU assets."

## 9. Injection mechanisms

- **`LD_PRELOAD`** — Linux-native, **doesn't work** for Windows-under-Proton
  (the game is a PE, not an ELF).
- **Wine-side DLL injection** — Windows DLL + `CreateRemoteThread`+`LoadLibrary`,
  done from within Wine. Standard path. Requires a Windows trainer under Wine.
  **This is the chosen mechanism for `trainlab` (D6).**
- **Proxy DLL (`WINEDLLOVERRIDES`)** — replace a DLL the game loads with yours.
  No injection tooling; the game loads your DLL naturally. Very portable. Viable
  fallback, not primary.
- **Vulkan layer** — gets loaded into the process (Proton renders via Vulkan),
  but runs on the Linux side of the Wine boundary; can't natively touch the
  game's Windows memory without bridging. Rejected.
- **External `/proc/pid/mem`** — no injection at all; the Sins 2 approach. Fast
  on your own machine, but offsets are per-game-version and harder to distribute.

## 10. Trainers vs cracks

- **Crack** — defeats DRM/copy protection. Not what we do.
- **Trainer/cheat** — modifies gameplay (memory, logic). What we do.
- Urbek's `rockgame` city name or `recIniciales > 3` triggers a built-in
  `gratis` (free) mode: free building, free upkeep, everything unlocked —
  **without** disabling achievements. Good for sandbox testing.
- Many "embedded CE tables" trainers are hobbyist; professional trainers
  (Fling, etc.) write their own injection and patching. CE's injected DLL is
  its internal runtime (Lua-based), not a public third-party API, and its kernel
  driver doesn't work under Wine.

## 11. Rust libraries

- **`memflow`** — memory scanning/forensics framework in Rust (scanner module,
  AOB). Built around hypervisor/physical-memory backends (heavier setup).
- **`sherlock`** — game-cheat-oriented Rust crate: value scan, pointer chase,
  pattern scan.
- For a single Proton game, writing your own `/proc/pid/mem` scan loop and using
  the *algorithms* is often leaner than pulling in a hypervisor framework.
- **`rmcp`** — Rust MCP SDK (for the agent interface).
- **`iced-x86`** — x86 disassembler (for `disassemble` / instruction-length for
  safe patching).

## 12. STL (Steam Tinker Launch) integration

- **fork** — spawn the trainer alongside the game in the same Wine prefix
  (shared Wine env; separate processes).
- **inject** — launch the trainer after the game loads so it can attach.
- Both keep the trainer in the game's Wine prefix, so the trainer can be a
  Windows binary using Windows APIs against the game — the clean distribution
  path for Steam machine / Steam Deck.
