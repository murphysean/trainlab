# Feature proposal: `lua_command` cheat kind

Status: **proposal / design** — not yet implemented.
Filed from the Helldivers session (2026-08-19) where we validated a working Lua
injection transport end-to-end.

## 1. The problem

Some games are **Lua-driven** (Helldivers 1 is Bitsquid/Stingray with a Lua
gameplay layer; research points, XP, armor are all Lua-table fields). For these,
the cheat that matters is not "write a number to an address" — it's **"run a Lua
command"** (e.g. set a field on a SaveManager object). The current profile schema
only has `kind: value` (write a number to an address) and `kind: toggle`
(code-cave hook). Neither expresses a one-shot Lua script.

## 2. What the Helldivers transport proved (working recipe)

For Helldivers specifically, running a Lua command requires a **5-step sequence**
(there's no direct address to write; the value lives in a Lua object path):

1. **Install a fire-once hook** on `zlua_gettop` (helldivers.exe+0x1a6254),
   `hook="override"`, `jump="relative"`. The cave inlines the stolen gettop replay,
   checks a **fire flag byte** (cave-relative `+0xa8`), and if set:
   - clears the flag (auto-disarm),
   - calls `luaL_loadstring` (0x1401ae260) on a command string (cave-relative `+0xc0`),
   - calls `lua_pcall` (0x1401a7ec0) to execute it,
   - calls `lua_settop` to clean up.
   Idle otherwise (near-zero cost on the hot path).
2. **Clear the anti-cheat gate flags** in the Lua global state `l_G = [L+8]`:
   - Flag A at `l_G + 0x198`,
   - Flag B at `l_G + 0x199`.
   Both MUST be 0 or `luaL_loadstring` force-returns `LUA_ERRSYNTAX (3)` on ANY
   source (even a comment / empty string). This is a game-authored anti-modding
   gate, not VAC.
3. **Write the Lua command string** into the cave command buffer.
4. **Set the fire flag** byte.
5. The hook fires on the next `zlua_gettop`, executes the Lua, auto-clears.

**Validated result:** `SaveManager._primary_system._system._data.user[SaveManager._primary_system._latest_user].research_samples=99990;`
→ UI refreshed showing research points, user bought everything, left lobby,
reloaded → **all persisted**. (KNOWLEDGE.md §15/§16 in the Helldivers dir.)

## 3. Proposed schema (Option A: `lua_command` cheat kind)

```yaml
cheats:
  - id: research_points_9999
    label: "Give 9999 Research Points"
    kind: lua_command           # NEW kind
    # Which setup AOB is the hook site to install the fire-once cave on.
    hook_ref: zlua_gettop
    hook: override
    jump: relative
    # Cave-relative offsets (where in the payload the flag/cmd live).
    fire_flag: "+0xa8"
    command_buffer: "+0xc0"
    result_slot: "+0xb8"        # optional: where loadresult is recorded (int32)
    # Anti-cheat gate flags, resolved via l_G = [L+8] (captured from the hook).
    gate_flags:
      flag_a: +0x198            # l_G + 0x198
      flag_b: +0x199            # l_G + 0x199
      # how the trainer resolves L: from the gettop hook's rcx on first fire.
    command: "SaveManager._primary_system._system._data.user[SaveManager._primary_system._latest_user].research_samples=99990;"
    note: "One-shot Lua injection: gives 9999 research points, persists."
```

### Semantics

- The cheat appears in the Cheats panel as a **button** ("Give 9999 Research Points").
- Pressing it runs the full sequence: ensure hook installed → clear gate flags →
  write command → set fire flag → (auto-clear on fire).
- It's a **one-shot** action, not a continuous pin. Each press = one Lua command.
- For continuous cheats (e.g. god mode / armor) the profile would use a
  `kind: toggle` / `lua_toggle` that keeps the gate flags cleared and re-fires on
  a tick — future work.

## 4. Why `lua_command` is the right abstraction (vs Option B/C)

| Option | Approach | Verdict |
|--------|----------|---------|
| **A. `lua_command` kind** | Encapsulate the full hook+gate+fire sequence as one cheat kind. | ✅ **Best.** Reusable, one click, maps to a named primitive. |
| B. `script`/`sequence` mechanism | A generic ordered list of primitives (write X, fire Y). | More flexible but heavier; not needed for v1. |
| C. Document-only | Keep current schema, drive via MCP tools each session. | Works but no GUI button — agent-driven only. |

Recommend A for v1.

## 5. Mapping to trainlab primitives

The sequence composes existing primitives — no new low-level machinery needed:

| Sequence step | trainlab primitive(s) |
|---------------|----------------------|
| Install cave | `install_cave` (hook=override, jump=relative) + `confirm_op` |
| Clear gate flags | `write` + `confirm_op` (two 1-byte writes at l_G+off) |
| Write command buffer | `write` + `confirm_op` (hex-encoded Lua string) |
| Set fire flag | `write` + `confirm_op` (1 byte = 01 at cave+0xa8) |
| Verify | `read` `result_slot` (expect 0 = LUA_OK) |

The `lua_command` kind mainly needs a **driver orchestration** layer that turns the
profile's fields into this sequence — not new core primitives.

## 6. Details / gotchas to encode

- **State is not restart-stable.** The `lua_State` (`L`) address moves each launch.
  Capture `L` from the gettop hook's `rcx` on the first fire (that IS the state the
  command runs in). Derive `l_G = [L+8]` live.
- **State is not restart-stable.** The `lua_State` (`L`) address moves each launch.
  Capture `L` from the gettop hook's `rcx` on the first fire (that IS the state the
  command runs in). Derive `l_G = [L+8]` live.
- **Gate flags may need re-clearing** per session or if the global state is
  recreated. Observed: they **re-arm between fires** (reset to `01 01` on their
  own), so clear them as part of **each** fire, not once per session.
- **XP applies on main-menu reload**, not instantly (research points apply
  instantly). Both persist after reload. UI-refresh timing varies by field.
- **Payload is game/version-specific.** Keep `lua_cave.payload.hex` alongside the
  profile; the profile references hook offsets, not the whole payload.
- **`loadresult` check:** after fire, `result_slot` should read `0` (LUA_OK). Non-zero
  means the command failed to compile/run — surface it for diagnostics.

## 7. Files

- `docs/FEATURE_lua_command_cheat.md` — this proposal.
- **`docs/FEATURE_exec_lua_generic.md`** — the low-level `exec_lua` primitive this
  cheat kind builds on (pointer-based command buffer + self-clearing gate + real
  result slot). **Implement `exec_lua` first**; then layer `lua_command` on top.
- Working copy of a profile with the `lua_command` stub: see Helldivers
  `helldivers.yaml` (in the game dir).
- Reference payload: Helldivers `lua_cave.payload.hex` + `lua_cave.asm`.
