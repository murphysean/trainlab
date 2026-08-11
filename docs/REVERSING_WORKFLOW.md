# Reversing Workflow

The end-to-end process `trainlab` is built to enable. This is the "how we use it
to actually reverse a game" playbook — the workflow that a human and an LLM/agent
run together.

## The goal

Not just "find a value and pin it." The goal is: **understand a mechanic, then
make a surgical, reversible change that works *with* the game's loop.** And do
it fast, with an agent doing the mechanical hunting while the human guides and
judges.

## The loop (agent + human together)

```
1. Load in        — get the DLL into the game, start the MCP server.
2. Recon          — find a value you care about.
3. Anchor         — find the code that owns it (AOB / find-writes).
4. Understand     — disassemble / decompile the surrounding logic.
5. Design patch   — decide the smallest surgical change.
6. Emit + place   — emit shellcode, install cave / hook (with undo).
7. Verify         — does it do what you want? Does it crash?
8. Toggle/undo    — on/off, restore, iterate.
```

## Step-by-step

### 1. Load in

- STL forks the trainer alongside the game in the same Wine prefix.
- The Trainer injects the Agent DLL (`CreateRemoteThread`+`LoadLibrary`, proxy
  DLL, or `/proc/pid/mem` stub — whichever we standardized on).
- The Trainer starts the MCP server; the agent connects.

### 2. Recon (read-only, agent-driven)

- `list_regions` → find the private heap regions (skip GPU/mapped).
- `scan` → first scan for a known value (e.g., resources, health). Narrow with
  `changed`/`unchanged`/`increased`/`decreased` as the game runs.
- `read` / `dump_struct` → at the surviving candidate addresses, look for a
  struct with related fields nearby (±0x200 bytes).

### 3. Anchor (find the code, not just the data)

- `pointer_chase` → walk the pointer chain from the value up to its owner object.
- `find_writes` → hardware-watchpoint the address; capture the instruction that
  writes it and the register state. That instruction is your hook anchor.
- `aob_scan` → find a distinctive byte pattern near the anchor for a stable,
  ASLR-proof reference.

### 4. Understand

- `disassemble` the anchor region (or, for a Mono game, decompile the IL — much
  easier).
- Read the surrounding logic to learn: what value is loaded, what modifiers apply,
  what the loop does each tick.

> **Key decision point:** is the value a *stock* recomputed from a *rate* each
> tick (Urbek-style)? If so, **pinning the stock is futile.** You must hook the
> *rate* or the *code that applies it*. Work with the loop, not against it.

### 5. Design the patch

Choose the smallest surgical change. Prefer:
- Overriding a value **in a register** at the point it's used (a cave), over
  patching logic.
- A **conditional** cave (e.g., "only for the player") via a `cmp` against a
  stored pointer the Trainer wrote in.
- **Not** calling functions from inside a cave (that's where crashes come from).

### 6. Emit + place (mutating — confirm first)

- `install_cave` → Trainer emits the shellcode, finds a cave, writes the `jmp`,
  saves original bytes.
- The agent **proposes**; the human **confirms** (D8).
- The cave's data area (e.g., the player pointer) is written by the Trainer
  before placement.

### 7. Verify

- Watch the game: does the value behave? Any crash? If a cave crashes, it's
  almost always a **register assumption** — the cave clobbered a register the
  game still needed. Fix by preserving the register (push/pop) or narrowing the
  clobber set.

### 8. Toggle / undo

- `restore`/`undo` → revert to saved original bytes.
- For Mono games, "undo" is forcing a re-JIT, not byte-restore.
- Iterate: adjust, re-verify.

## The "dialogue" with the agent

The human and agent trade findings:

- **Agent:** "I found the value at 0x…; the pointer chain leads to a struct at
  +0x58; the write happens at `exe+0x9fdedd` with the owner in `r14+0x28`."
- **Human:** "That's the ability context; make it player-only." / "That's the
  wrong struct; try the other candidate."
- **Agent** saves markers (`set_marker`) so it remembers across turns, proposes
  a cave, waits for confirmation.

The markers/session state in the Trainer (not the LLM) are what make this a
real multi-session conversation rather than a fresh-start every turn.

## Anti-patterns to avoid

- **Pinning a stock value in a rate-based economy.** Work with the loop.
- **Complex logic in a cave.** Logic in the Trainer; caves do one tiny thing.
- **Scanning the whole address space.** Scope to private heap.
- **Silent mutations.** Always confirm + undoable.
- **Fighting GDB's Wine barrier.** For native games use a Windows debugger under
  Wine; for Mono games use a Mono-level debugger. For this framework, prefer
  MCP-driven recon over interactive debuggers.
