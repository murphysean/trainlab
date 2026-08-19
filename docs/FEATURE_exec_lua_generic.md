# Feature Request: generic `exec_lua` primitive (pointer-based command buffer)

**Status:** proposal — not yet implemented.
**Priority:** [P1]
**crate:** `trainlab-core` (lua transport), `trainlab-cave` (payload emitter),
  `trainlab-gui` (MCP `exec_lua` tool + `lua_command` cheat-kind driver)
**Requested by:** Helldivers 1 Lua-injection session (2026-08-19) — the follow-on
  to `FEATURE_lua_command_cheat.md`.

---

## 1. The problem

`FEATURE_lua_command_cheat.md` proposed a `lua_command` cheat kind that encodes the
Helldivers Lua-injection transport (fire-once `zlua_gettop` cave + gate-flag
clearing + fixed inline command buffer). Session experience exposed three
frictions that the proposed design didn't solve:

1. **The command string is baked into the cave at a fixed offset (`+0xc0`).**
   Every iteration is a hex-encode-the-Lua → `write` → `confirm` dance. There is
   no way to run an arbitrary/one-off Lua expression quickly.
2. **The anti-cheat gate flags must be cleared manually before EVERY fire**
   (they re-arm between fires, we observed `01 01` resetting on their own). This
   is a redundant per-call step that the cave itself is perfectly positioned to do.
3. **There is no trustworthy result channel.** This session we discovered that
   what we *thought* was the `result_slot` (`cave+0xb8`) is actually the payload's
   `saved_top` (a `lua_Integer`). Our "LUA_ERRRUN (2)" readings were garbage —
   we could not reliably tell success from failure.

## 2. Goal

A **generic, reusable "execute arbitrary Lua in the game's Lua VM" primitive** that
the harness drives with *one call*, not a 5-step manual sequence:

```
exec_lua("<any lua source>")  ->  (status, result)
```

The cave becomes a reusable execution engine; the command string is **uploaded to
a DLL-allocated buffer and referenced by pointer**, the cave **self-clears the
anti-cheat gate** (it can compute `l_G` from the `L` it already receives), and it
**writes the real pcall result** to a dedicated slot.

## 3. Cave design (generic, not Helldivers-specific)

Hook model: fire-once `override` on the game's `lua_gettop` (or a chosen
`zlua_gettop` AOB). Idle path = replay stolen body + `ret` (near-zero cost on the
hot path). On fire:

```
+0x000  [replay stolen gettop body]          ; rax = top (idle path returns here)
+0x008  cmp byte [fire_flag],1 ; jne done    ; idle unless fired
        ; fire sequence (L is in rcx):
        l_G = [L+8]
        clear byte [l_G+0x198]               ; anti-cheat gate flag A
        clear byte [l_G+0x199]               ; anti-cheat gate flag B
        rax = luaL_loadstring(L, [cmd_ptr])  ; <-- reads a POINTER, not inline bytes
        if rax==0: lua_pcall(L, 0, -1, 0)
        lua_settop(L, saved_top)
        store pcall_result -> [result_slot]  ; real return code
        restore rax = top
+0x...  fire_flag     ; harness sets to 1, cave auto-clears on fire
+0x...  cmd_ptr       ; harness points at uploaded command buffer (in game proc)
+0x...  saved_state   ; L captured from gettop's rcx
+0x...  saved_top
+0x...  result_slot   ; int32 — real loadresult/pcall status (0 = LUA_OK)
done:   ret
```

### Key properties

- **Pointer-based command buffer** (`cmd_ptr`): the harness `VirtualAlloc`s (or the
  DLL exposes an allocator) a writable region *inside the game process*, writes the
  raw Lua source bytes + NUL, and stores its address in `cmd_ptr`. The cave reads
  from that pointer. No hex-per-command encoding, no fixed inline buffer.
- **Self-clearing gate:** because the cave gets `L` in `rcx`, it computes
  `l_G = [L+8]` live and zeros the two gate flags right before `loadstring`. This
  removes the manual "clear flags before every fire" step entirely.
- **Real result slot:** `result_slot` records pcall's actual return code (0 = OK,
  1 = runtime error, 2 = syntax error, 3 = memory). The harness can surface
  failures reliably. (Also the cave can, on error, capture the error string that
  pcall left on the stack and copy it out — future nicety.)

## 4. Proposed MCP tool: `exec_lua`

```
exec_lua(
    src: string,        # the Lua source to run (raw, not hex)
    alloc_size?: int,   # default 2048
) -> { status, result_slot, result_string? }
```

Orchestration (driven in `trainlab-gui`, reusing existing primitives):

1. Ensure the generic cave is installed (idempotent — install once, keep for the
   session).
2. `VirtualAlloc`/allocate a buffer in the game process (DLL-side allocator, or the
   existing cave-adjacent scratch region). Write `src` bytes + NUL.
3. Set `cmd_ptr` to the buffer address (1 write).
4. Set `fire_flag` to 1 (1 write).
5. Poll `fire_flag` until it auto-clears (confirms the fire happened).
6. Read `result_slot`; return it (and optionally the result string).

This collapses the whole Helldivers 5-step recipe into a single tool call. It is
generic to any Lua-driven game once the `zlua_gettop` AOB and the two
anti-cheat-gate offsets are known (which a profile supplies).

## 5. Relation to `lua_command` cheat kind

`exec_lua` is the **low-level primitive**; `lua_command` (from the other proposal)
is the **profile/cheat-panel abstraction** on top of it. Recommend:

- Implement `exec_lua` MCP tool first (fast iteration during recon — exactly what
  this session needed).
- Then layer the `lua_command` cheat kind so a profile can expose a button that
  calls `exec_lua("SaveManager...research_samples=99990;")`.

`exec_lua` could also serve a `lua_toggle` (continuous) form: keep the gate flags
cleared and re-fire on a tick while enabled.

## 6. Gotchas to encode

- **Hot-path discipline:** this must remain a **fire-once gated** cave. Persistent
  capture/trampoline on `zlua_gettop` has crashed the game repeatedly this session.
  Idle path must be just the stolen-body replay + `ret`.
- **State not restart-stable:** `L` (and thus `l_G`) moves each launch. Always
  derive `l_G = [L+8]` from the live `L` captured on fire — never cache it.
- **Gate offsets are game-specific** (`+0x198`/`+0x199` relative to `l_G` for
  Helldivers); keep them in the profile, not hard-coded in the payload emitter.
- **Buffer lifetime:** the uploaded command buffer lives for the session (one
  `VirtualAlloc` reused, or re-alloc per call and freed on the next). Avoid leaking
  per call.
- **Result timing:** `result_slot` is written after the pcall returns, before the
  cave returns to gettop's caller. Poll after the fire flag clears — by then the
  slot is valid.

## 7. Files

- `docs/FEATURE_exec_lua_generic.md` — this proposal.
- Reference payload: Helldivers `lua_cave.payload.hex` + `lua_cave.asm` (game dir)
  — the basis for the generic emitter.
- `docs/FEATURE_lua_command_cheat.md` — the higher-level cheat-kind abstraction
  that builds on this.
- Working profile stub: Helldivers `helldivers.yaml`.
