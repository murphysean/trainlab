# Feature Request: Short (relative) jump cave mode for tight patch windows

**Status:** ✅ implemented (2026-08-18, verified with tests; in working tree,
not yet committed at last check)
**Priority:** [P1]
**crate:** `trainlab-core` (cave_hook), `trainlab-cave` (cave.rs, emitter.rs),
  `trainlab-inject` (allocate near target), `trainlab-gui` (MCP `install_cave`)
**Requested by:** Helldivers 1 Lua-injection session (2026-08-18)
**Priority:** [P1]
**crate:** `trainlab-core` (cave_hook), `trainlab-cave` (cave.rs, emitter.rs),
  `trainlab-inject` (allocate near target), `trainlab-gui` (MCP `install_cave`)
**Requested by:** Helldivers 1 Lua-injection session (2026-08-18)

## Implemented

- `JumpStyle` enum in `cave_hook.rs` (`Absolute` | `Relative`, default `Absolute`).
- `cave.rs::install` branches on `JumpStyle`: `Relative` uses a 5-byte `E9 rel32`
  redirect (with ±2GB range check + NOP-pad the rest of the patch window), and uses
  `patch_len` min of 5 instead of `JMP_ABS_LEN`.
- `inject/lib.rs` `allocate_near(target, size, exec)` — address-hint allocation within
  ±2GB of the target so the relative jump's cave lands in range (Windows `VirtualAlloc`
  stepping in 64KB increments toward the target; Unix near-target hint).
- MCP `install_cave` gained `jump: "absolute" | "relative"` (default absolute).
- **⚠️ Needs a fresh goose session to load the new `install_cave` schema** (old tool
  def lacks `jump`). Deployment to Deck in progress.

## Problem

`install_cave` can only redirect a target with a **14-byte absolute long jump**
(`FF 25 rel32` + embedded 8-byte target slot). When the function we need to hook
is shorter than 14 bytes — or sits immediately next to another function we must
not clobber — we can't hook it without corrupting adjacent code.

Concrete case that motivated this: hooking the game's `zlua_gettop` so we can run
arbitrary Lua in the game's own thread (the cheat-table Lua-injection mechanism —
see `helldivers.CT`). The live layout:

```
0x1401a6254  48 2b 41 10   sub rax,[rcx+0x10]   ; 4 bytes
0x1401a6258  48 c1 f8 03   sar rax,3             ; 4 bytes
0x1401a625c  c3            ret                   ; 1 byte   ── 9 bytes total
0x1401a625d  cc            int3                  ; padding
0x1401a625e  cc            int3
0x1401a625f  cc            int3
0x1401a6260  40 53         push rbx              ; ← zlua_settop STARTS here
```

- `zlua_gettop` is **9 bytes**. The next function `zlua_settop` starts at
  `0x6260` — only **12 bytes** past the start of `zlua_gettop` (9 + 3 int3 padding).
- trainlab's `jmp_abs` needs **14 contiguous bytes**, so patching `zlua_gettop`
  with it would overwrite the first 2 bytes of `zlua_settop` (`push rbx`) and
  corrupt the game.

There are two fixes, and **we need the short-jump one** to hook `zlua_gettop` the
way the cheat table does (a cheap, side-effect-free function we call `loadstring` +
`pcall` from — no recursion). Hooking `zlua_pcall` directly instead (Option B) is
possible with the current long jump, but introduces nested re-entry complexity.

## What already exists

- `emitter::jmp_abs(target)` — the 14-byte absolute jump (`FF 25 rel32`, reads the
  8-byte absolute target from the slot after the instruction; clobbers no
  registers). This is the only jump `cave::install` uses for the redirect.
- `emitter::jmp_rel32(rel)` — a **5-byte** `E9 rel32` emitter **already exists**,
  but nothing uses it for the redirect (it's used for internal cave jump-backs).
- `cave::install` (`crates/trainlab-cave/src/cave.rs`) hardcodes
  `emitter::JMP_ABS_LEN` (14) for the patch window, and always writes
  `jmp_abs(cave)` at the target.
- `cave_hook::CaveHook` (`crates/trainlab-core/src/cave_hook.rs`) has
  `Trampoline { payload }` / `Override { payload }` but no notion of jump size.
- `allocate` (`crates/trainlab-inject/src/lib.rs`) uses `VirtualAlloc(null, ...)`
  / `mmap(null, ...)` — the OS picks an address with no constraint. For a
  relative jump the cave must land within **±2 GB** of the target, which an
  unconstrained allocation does **not** guarantee (especially under Wine where
  `mmap` often lands far from the game's image).

## Requested change

Add a **relative (short) jump** patch mode to `install_cave` so we can hook
functions in tight windows. Concretely:

1. **New hook kinds** on `CaveHook` / `HookKind`:
   - `TrampolineShort { payload }` / `OverrideShort { payload }` (or a single
     `JumpStyle` field: `Absolute` vs `Relative`, defaulting to `Absolute` for
     backward compatibility).
2. **Emitter**: use `jmp_rel32(cave - (target + 5))` for the redirect when the
   relative form is selected. The patch window becomes **5 bytes** (`E9 rel32`)
   instead of 14, so a 9-byte function like `zlua_gettop` fits easily (patch
   `sub`+`sar` = 8 bytes, `E9` + 3 nops) without touching the adjacent function.
   The stolen instructions are still replayed in the trampoline exactly as today.
3. **Cave allocator & 2-hop Relay Strategy**:
   - **Step A (Direct Near Alloc)**: Try `VirtualAlloc` near `target` (or `mmap` with address hint) within **±2 GB**.
   - **Step B (Code Alignment Padding Relay)**: If near-allocation fails or is blocked by memory layout/Wine limits:
     1. Search readable/executable `.text` memory within **±2 GB** of `target` for a run of contiguous alignment padding bytes (e.g. 14+ contiguous `0xCC` `int3` or `0x90` `nop` bytes between functions).
     2. Use that padding run as an **Intermediate Relay Cave**:
        - Target site `target` $\rightarrow$ 5-byte `E9 rel32` $\rightarrow$ **Padding Cave** (within ±2 GB).
        - **Padding Cave** $\rightarrow$ 14-byte `FF 25 rel32` absolute jump $\rightarrow$ **Main Allocated Cave** (anywhere).
        - **Main Allocated Cave** $\rightarrow$ runs payload, replays stolen instructions, then 14-byte `jmp_abs` back to `target + patch_len`.
4. **MCP `install_cave`**: expose the jump style, e.g.
   `hook: "trampoline" | "override"` + `jump: "absolute" | "relative"`
   (relative optional). Keep `absolute` the default so existing profiles/tests
   are unaffected.

### MCP `install_cave` args (proposed delta)

```rust
pub struct InstallCaveArgs {
    pub target: String,
    pub hook: String,              // "trampoline" | "override"
    #[serde(default)]
    pub jump: String,              // "absolute" (default) | "relative"
    #[serde(default)]
    pub payload: String,
}
```

Relative mode is only valid if the target has a **clean instruction-aligned
5-byte window** (no branch into the middle, no partial-instruction overwrite) —
the existing `instruction_aligned_len` logic should require `>= 5` for relative,
`>= 14` for absolute.

## Why this matters for the Helldivers Lua-injection work

The whole Lua path hinges on hooking `zlua_gettop` and running a fire-once
(idle-flag-gated) payload that calls `zluaL_loadstring` + `zlua_pcall` +
`zlua_settop` to set fields like `SaveManager...research_samples=9990`. The site
is 9 bytes and abuts `zlua_settop`, so the current 14-byte absolute jump cannot
hook it. This feature unlocks the proven cheat-table mechanism cleanly and
without recursing into the Lua API we're calling from.

## Acceptance criteria

1. `install_cave` with `jump: "relative"` patches a short target (e.g.
   `zlua_gettop`, 9 bytes) with a 5-byte `E9` and does **not** alter bytes past
   the instruction-aligned window (verify `zlua_settop`'s first bytes unchanged).
2. The cave is allocated within ±2 GB of the target (address-hint works on both
   Windows and Wine).
3. A trampoline relative hook replays the stolen instructions and the game keeps
   running (no crash, values tick normally).
4. `undo`/`restore` restores the original bytes for relative hooks.
5. Existing absolute-jump behavior and tests are unchanged (backward compatible).
6. Optional: a `cave_validate` example / test for the relative path.

## Related

- `docs/FEATURE_float_range_scan.md` — example of a prior P1 feature in this repo.
- Helldivers BOOTSTRAP.md §"primary path: Lua injection" for the target use case.
