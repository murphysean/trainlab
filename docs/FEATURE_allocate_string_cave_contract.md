# Feature Request: `allocate_string` + generic cave contract (agentic program execution)

**Status:** proposal — not yet implemented.
**Priority:** [P1]
**crate:** `trainlab-core` (string allocator), `trainlab-inject` (in-process
  allocator exposed to harness), `trainlab-gui` (MCP `allocate_string` tool)
**Requested by:** Helldivers 1 Lua-injection session (2026-08-19) — reframed from
  `FEATURE_exec_lua_generic.md` (superseded).

---

## 1. The problem

We keep hitting the same wall: **getting a string across the process boundary into
the game, and having a code cave execute it as a program.** Every game we touch
has a scripting/config surface (Helldivers = Lua; others = JSON/YAML/XML config,
JS, etc.), and the cheat that matters is "run this program in the game's engine."

The naive approach — a hardcoded `exec_lua` tool — is wrong because:

1. It bakes in "Lua" and "Helldivers" (the `zlua_gettop` hook, the gate flags).
   The *transport* is generic; only the cave assembly is game-specific.
2. It hardcodes the command into the cave at a fixed offset, forcing a
   hex-encode → write → confirm dance per iteration.
3. It's a tool, not a recipe. The agent should be able to *compose* the steps
   (allocate → point → fire → read) for whatever program type the game accepts.

## 2. The two generic primitives

### 2a. `allocate_string` — the cross-boundary string transport

A single tool that allocates and lays out a string inside the game process and
returns the address(es) the consumer needs for that string type:

```
allocate_string(
    content: string,          # the raw bytes to place in the game (a program, config, etc.)
    kind: string,             # "c" | "rust" | "json" | "yaml" | "xml" | "js" | "config" | ...
) -> Layout                     # shape depends on kind (see below)
```

**`kind` is NOT an advisory label — it determines the returned layout.** The tool's
job is to allocate and lay out the string in the canonical in-memory form for that
type, and return whatever metadata that layout needs:

| kind | in-memory layout | returned shape |
|------|------------------|----------------|
| `"c"` | NUL-terminated byte buffer | single `ptr` |
| `"json"`/`"yaml"`/`"xml"`/`"js"`/`"config"` | same as `"c"` (parser takes a C string) | single `ptr` (labeled so the recipe routes it) |
| `"rust"` | Rust `String`/`&str` = **fat pointer** (`ptr` + `len`, no NUL required) | `{ ptr, len }` |

So for `"c"` and the config-ish kinds the return is a single pointer; for `"rust"`
it's a fat pointer `(ptr, len)`. The `kind` argument tells the tool *which layout
to build and which shape to return.*

> **Explicitly NOT supported: a Lua string type.** We deliberately do NOT offer a
> `"lua"` kind that builds a Lua `TString` object. Lua strings are GC-managed
> GCObjects; a hand-allocated TString outside Lua's allocation bookkeeping would
> conflict with the garbage collector (Lua could try to sweep/free memory it doesn't
> own, or miss it entirely and leak). When the cave hands a string to the game's Lua
> API, we always hand it a **plain C string** and let Lua's own `luaL_loadstring` /
> `lua_pushstring` / `luaL_loadbuffer` copy it into a proper GC-managed TString
> internally. We never manufacture TString objects ourselves.

**Future generalization:** a follow-on `allocate_struct` would lay out an arbitrary
struct in the game and return its base pointer (the cave/recipe indexes fields).
That is `allocate_string` generalized from "one string layout" to "any layout" —
out of scope for v1 but a natural next step.

All buffers live for the session (reused or freed on next call) — no per-call leak.

This is the **generic way to pass any string across the boundary**: a full Lua
program, a JSON blob, a YAML config, an XML document, a JS snippet — whatever the
game's engine can consume. The consumer (cave / recipe) never hand-encodes bytes;
it uploads text and gets the layout it needs.

### 2b. The cave contract — fire_flag + cmd_ptr + result_slot

The code cave is **our responsibility** (we author the assembly per game). But we
standardize its **interface** so the harness can drive any cave the same way:

```
+0x...  fire_flag     ; harness sets to 1 (one-shot). Cave auto-clears on fire.
+0x...  cmd_ptr       ; harness points at a string allocated via allocate_string.
+0x...  result_slot   ; int32 — the program's status (0 = OK, nonzero = error).
+0x...  saved_state   ; game-specific (e.g. L for Lua) captured on fire.
```

The cave's job, on fire:
1. Read the string at `cmd_ptr`.
2. Execute it as a program in the game's engine (Lua, JS, config loader, whatever
   the game exposes).
3. Write the result to `result_slot`.
4. Auto-clear `fire_flag` and return to the idle path.

**The cave assembly is game-specific and agent-authored.** For Helldivers that
means: hook `zlua_gettop`, compute `l_G = [L+8]`, self-clear the anti-cheat gate
flags, `luaL_loadstring(L, [cmd_ptr])`, `lua_pcall`, `lua_settop`. For another game
it's a different hook and a different engine call — but the *interface* (fire_flag,
cmd_ptr, result_slot) is the same, so the harness and recipe don't change.

## 3. The agentic recipe (not a hardcoded tool)

The agent drives execution by composing the primitives — this is what makes it
generic. For any program type the game accepts:

```
1. allocate_string("<program source>", kind="c"|"json"|...)  ->  ptr
2. write cmd_ptr = ptr
3. write fire_flag = 1
4. poll fire_flag until it auto-clears   (confirms the fire happened)
5. read result_slot                      (0 = OK, nonzero = error)
6. (optional) read the program's output area
```

This is a **recipe**, not a tool. The agent decides what program to run, what
`kind` it is, and how to interpret the result. The same recipe works for:

- **Lua** (Helldivers): `allocate_string("SaveManager...research_samples=99990;", "c")` — the cave feeds it to `luaL_loadstring` as a C string.
- **JSON config** (a game that loads JSON): `allocate_string('{"magazine_capacity":999999}', "json")`
- **YAML/XML/JS/config**: whatever the game's engine can be hooked to consume.

**One cave, many programs.** The cave is installed once; each execution just
allocates a new string, points `cmd_ptr` at it, and fires. No re-install, no
re-encoding.

### Preallocated "program library" pattern

Because `allocate_string` buffers live for the session, the trainer can
**preallocate every cheat program once at startup** and store its pointer, then
fire a cheat by just pointing `cmd_ptr` at the preloaded program. This turns each
cheat into *a pointer into a library*, not *a string upload per click*:

```
trainer init:
  ptr_research  = allocate_string("SaveManager...research_samples=99990;",  "c")
  ptr_xp        = allocate_string("SaveManager...player_xp=5000;",           "c")
  ptr_ammo      = allocate_string("<weapon_info walker...>",                 "c")
  ... (one allocate per cheat program)

on cheat click (e.g. "Give 9999 Research Points"):
  1. write cmd_ptr = ptr_research      # point the cave at the preloaded program
  2. write fire_flag = 1               # run-once
  3. wait for fire_flag to auto-clear  # confirms it fired
  4. read result_slot                  # errno / status (0 = OK)
  5. (optional) validate via scan      # read back game state
```

This is the generic shape the user described: preload all programs, and each cheat
click is just `set pointer → set flag → wait → check errno → validate`. The
`allocate_string` buffers live for the session, so preallocating a bunch of cheat
programs is cheap and expected — they persist until the trainer exits.

A `free_string(pointer)` tool is a **deferred follow-on** (nice for long sessions /
iterating many throwaway programs, but not required for v1). The session buffer
manager frees everything on trainer teardown, so leaked per-iteration buffers are
acceptable while iterating.

## 4. Why this is the right abstraction

| Concern | Hardcoded `exec_lua` | `allocate_string` + cave contract + recipe |
|---------|----------------------|---------------------------------------------|
| Transport | Lua-specific | Generic C-string transport |
| Cave | One hardcoded payload | Agent-authored per game, standard interface |
| Program type | Lua only | Lua, JSON, YAML, XML, JS, config — anything |
| Iteration | hex-encode per command | upload text, get pointer, fire |
| Who drives | a tool | the agent (recipe) |

## 5. MCP surface

- **`allocate_string(content, kind) -> Layout`** — the ONLY new low-level tool
  requested of trainlab. Everything else the recipe needs already exists:
  `install_cave` (create the code cave), `write` (flip `fire_flag`, write
  `cmd_ptr`/`result_slot` into the cave), `read` (read `result_slot` / outputs),
  `disassemble`/`dump` (iterate on the assembly). The cave assembly itself is
  authored by us per game; trainlab just provides the allocator.
- The cave install stays `install_cave` (agent supplies the game-specific payload).
- **`free_string(pointer)` is deferred follow-on** (v2): for freeing a specific
  preallocated buffer mid-session. v1 relies on the session buffer manager freeing
  everything on teardown.
- The recipe is documented (this file + a `REVERSING_WORKFLOW.md` section) so the
  agent knows the composition.

## 6. Gotchas to encode

- **Hot-path discipline:** the cave must be **fire-once gated** with a cheap idle
  path (replay stolen body + `ret`). Persistent capture/trampoline on a hot
  function (e.g. `zlua_gettop`) has crashed the game repeatedly.
- **State not restart-stable:** game-specific state (e.g. `L`/`l_G`) moves each
  launch. Always derive it live on fire from the hook's registers — never cache.
- **Buffer lifetime:** `allocate_string` buffers live for the session; reuse or
  free on next call. Don't leak per call.
- **`kind` determines the returned layout** (single ptr vs fat ptr), NOT just
  routing. The cave interprets the bytes per its own game-specific logic; `kind`
  tells the recipe which layout it got back. There is no `"lua"` kind (see §2a).
- **Result timing:** `result_slot` is valid after `fire_flag` auto-clears (the
  program has run). Poll the flag, then read the slot.

## 7. Files

- `docs/FEATURE_allocate_string_cave_contract.md` — this proposal (supersedes
  `FEATURE_exec_lua_generic.md`).
- Reference Helldivers cave: `lua_cave.payload.hex` + `lua_cave.asm` (game dir) —
  the basis for the agent-authored generic cave.
- `docs/FEATURE_lua_command_cheat.md` — the higher-level cheat-kind abstraction
  that can build on this recipe.
- Working profile stub: Helldivers `helldivers.yaml`.
