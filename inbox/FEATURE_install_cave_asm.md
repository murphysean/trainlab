# Feature Request: `asm` field on `install_cave` (profile command + MCP tool)

**Status:** ✅ RESOLVED (verified implemented in `profile.rs` and `mcp.rs`)
**Priority:** [P1]
**crate:** `trainlab-core` (`profile.rs` `InstallCave`), `trainlab-gui` (`mcp.rs` `InstallCaveArgs`)
**Requested by:** Helldivers 1 Lua-injection session (2026-08-28)
**Date:** 2026-08-28

## Problem

The `asm:` field (CE-style assembly → shellcode) is currently only supported on
**toggle cheats** (`ProfileCheat.asm`). But the established pattern for installing a
fire-once code cave is the **`install_cave` command** in `init_commands`, which
exposes the cave address as a **marker** (e.g. `marker: codecave`) so the harness can
write to the cave's data slots (fire_flag, cmd_ptr, result_slot, etc.).

`install_cave` (both the profile `InstallCave` command and the MCP `install_cave`
tool) only accepts a hex `payload` string — **not `asm`**. So to author a cave in
readable asm, we'd have to either:
- (a) hand-assemble to hex and paste it into `payload` (defeats the asm-direct goal), or
- (b) use a toggle cheat's `asm:` field, but then the cave address is NOT exposed as
  a marker, so the harness can't write to the data slots.

## Requested

Add an optional `asm` field to `install_cave` (profile `InstallCave` command AND MCP
`InstallCaveArgs`), mutually exclusive with `payload`. When present, assemble it
(via `assemble_text`, origin = target) into the payload bytes, exactly like the
toggle-cheat path already does at `mcp.rs:1191-1200`. The `marker` field still
records the cave address.

```yaml
# init_commands
- type: install_cave
  target_ref: "zlua_gettop"
  hook: override
  jump: relative
  asm: |
    sub rax, [rcx + 0x10]
    sar rax, 3
    cmp byte ptr [rip + fire_flag], 1
    jne done
    ...
  marker: codecave
```

## Expected vs Actual

- **Expected:** `install_cave` accepts `asm`, assembles it, installs the cave, and
  records the address under `marker` — so the harness can write to `codecave+0x120`
  (fire_flag), `codecave+0x140` (cmd_ptr), etc.
- **Actual:** `install_cave` only accepts hex `payload`; `asm` is rejected/ignored.

## Notes for the agent

- The toggle-cheat asm path (`mcp.rs:1191-1200`) already does exactly the right
  thing: `assemble_text(asm_src, origin=target, &symbols)` → `block.bytes`. Reuse
  that logic in the `install_cave` handler.
- Profile `InstallCave` (`profile.rs:180-198`) needs an `asm: Option<String>` field
  (mirroring `ProfileCheat.asm`), and the profile-load path must assemble it.
- MCP `InstallCaveArgs` (`mcp.rs:411-427`) needs `asm: Option<String>` too.
- `asm` and `payload` should be mutually exclusive (error if both set).
- This is **generic** — any game that installs a code cave via `install_cave` and
  wants to author it in readable asm benefits.

## Workaround (in the meantime)

Author the cave as a **toggle cheat** with `asm:` to get it assembled, but the cave
address won't be a marker — so the harness can't write to the data slots. Not viable
for the eval cave. Alternatively hand-assemble to hex and paste into `payload`
(what we're trying to avoid).
