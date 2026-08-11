# Cheat profile / cheat table — requirements & schema design

Status: **design / requirements** (not yet implemented). This documents what a
Cheat Engine cheat table is, what our YAML cheat profile should be, and how it
maps to trainlab's existing API.

## 1. Recon: the Cheat Engine `.CT` format

Cheat Engine's cheat table is a **`.CT` file** — an **XML** document. The root
is `<CheatTable>` with a `<CheatEntries>` list. Each entry is `<CheatEntry>`.

### What a CE entry stores

| CE field | Meaning | Our equivalent |
|----------|---------|----------------|
| `<Description>` | The human name ("wood", "God Mode") | cheat `label` |
| `<VariableType>` | byte / 2 bytes / 4 bytes / 8 bytes / float / double / string | cheat `value_type` |
| `<Address>` | The address — can be a plain address, or a **module-relative expression** like `"mono-2.0-bdwgc.dll+0x1234"`, or a Lua expression | `addr_to_module` string |
| `<Offsets>` + `<ModuleName>` + `<ModuleName+Address>` | For **pointer entries**: a stable module base + a list of field offsets (this is how CE survives ASLR / restarts) | `pointer_chase` (base + offsets) |
| `<Type>` | `0` single address, `2` pointer | value vs pointer cheat |
| `<CheatEntries>` | Nested entries (groups, scripts) | (nested grouping, future) |
| `<LuaScript>` | Lua code for script/toggle cheats | our **toggle / code-cave** cheats |

### How CE cheat tables are reused

- **Portable & shareable** — a `.CT` is a single file you can post on the CE
  forum or share; anyone loads it into CE.
- **Restart-stable via module+offset** — pointer entries don't store a raw
  address; they store a **module base + offset chain**, so the table still
  works after the game restarts (ASLR moves everything).
- **Community workflow** — someone discovers the table once, then it's shared;
  others load it and the cheats "just work" for that game build.

**Key takeaway for us:** the cheat table should store *how to find* values
(AOB patterns, pointer chains, module+offset), not just raw addresses. That's
what makes it reusable across launches and shareable.

## 2. Our goal: an LLM-friendly, versionable, scalable cheat profile

We want a **YAML** file (not XML) because:
- **LLM-friendly** — YAML is what agents read/write most naturally; XML is
  noisy and CE-specific.
- **Versionable / patchable** — a single text file, clean diffs in git, easy
  to review and merge (vs. CE's XML which is hard to diff).
- **Self-describing init** — the file should carry the *setup instructions* so
  a fresh attach can re-run discovery (AOB scans, pointer chains) to find
  addresses for the current launch.

### Files on disk

The GUI has a **cheats/ directory** next to the executable (e.g.
`cheats/Unrailed2.yaml`). On launch, the GUI **scans that directory**, reads
each profile, and uses its `game` field to match against running game exes. If
a profile's game is running, the GUI offers to attach + initialize.

## 3. Proposed YAML schema (v1)

```yaml
# trainlab cheat profile (v1)
schema: trainlab-profile/v1
game: Unrailed2.exe            # the game exe this profile targets
name: "Unrailed 2 — resources + god mode"
inject_dll: true               # whether to inject the agent DLL
version: "1.0.0"               # profile version (for sharing/patching)

# ---- Setup / initialization: how to find addresses for THIS launch ----
# These run in order after attach. They resolve the base/pointer chains the
# cheats reference. This is the CE 'how to find values' part.
setup:
  # 1. AOB scans to find code/static addresses, saved as named values.
  - aob_scan:
      name: god_mode_ret
      pattern: "48 8B 05 ?? ?? ?? ?? 83 F8 01"   # hex, ?? wildcards
      offset: +3                                   # bytes past the match
  # 2. Pointer chains, resolved against a module base each launch.
  - pointer_chain:
      name: player_base
      module: Unrailed2.exe        # resolved via enumerate_modules
      base: +0x0123A400            # module-relative base
      offsets: [0x10, 0x28, 0x40]  # field offsets (applied in order)
  # 3. Direct module-relative addresses (stable across launches).
  - address:
      name: wood_addr
      module: Unrailed2.exe
      offset: +0x4B7F4

# ---- Cheats: user-facing adjustable options (the Cheats panel) ----
cheats:
  # A value cheat, "set and forget" — one write, stays until the game overwrites it.
  - id: wood
    label: "Wood"
    kind: value
    value_type: i32
    # Reference a resolved setup value by name:
    address_ref: wood_addr
    # ...or provide an explicit address / chain inline:
    # address: 0x1234
    # chain: { module: Unrailed2.exe, base: +0x1000, offsets: [0x10] }
    note: "Wood resource stock"

  # A value cheat that RE-PINS every tick so the game can't overwrite it.
  # mechanism: "cave" (hook the game's own tick) or "timer" (re-write at a rate).
  - id: wood_pinned
    label: "Wood (pinned at value)"
    kind: value
    value_type: i32
    address_ref: wood_addr
    mechanism: cave          # or "timer" -> { rate_hz: 60 }
    value: 999               # the value to re-apply every tick
    note: "Force wood to 999 every game tick (robust) or at 60 Hz (simpler)"

  # A toggle cheat (god mode) via a code-cave hook inside the game's tick loop.
  - id: god_mode
    label: "God Mode (no damage)"
    kind: toggle
    # A code-cave hook at a resolved instruction (AOB-scanned):
    target_ref: damage_handler
    hook: override
    payload: "c3"                # shellcode payload (hex), e.g. 'ret'
    mechanism: cave              # hook the damage handler, re-apply each tick
    note: "Override the damage handler each tick so the player never takes damage"
```

## 4. How the pieces map to trainlab's API

| Profile concept | trainlab API |
|-----------------|--------------|
| `aob_scan` setup step | `aob_scan` (returns match addresses) |
| `pointer_chain` setup step | `enumerate_modules` + `pointer_chase` (base + offsets) |
| `address` (module + offset) | `addr_to_module` / `modinfo` module base + offset |
| value cheat | `add_cheat` (`CheatKind::Value`) + `set_cheat_value` |
| toggle cheat | `add_cheat` (`CheatKind::Toggle`) + `install_cave` / `set_cheat_toggle` |
| live value read/write | `read` / `write` |

## 5. Proposed flow at launch

1. **GUI starts**, scans `cheats/*.yaml`.
2. For each profile, compares `game` against `find_game_candidates()` /
   running processes.
3. If a profile's game is running: GUI shows "Detected Unrailed2 — attach +
   initialize profile?" → user (or agent via `attach_game`) confirms.
4. **Inject** DLL (per `inject_dll`), **connect**.
5. Run `setup` steps in order: AOB scans → pointer chains → addresses; store
   the resolved addresses as named values.
6. Materialize each cheat in `setup`-resolved addresses → **Cheats panel**
   populated with working, live addresses.
7. User adjusts cheats; the table can be **saved** (`save_profile`) to persist
   any tweaks, or **reloaded** (`load_profile`).

## 6. Pinning: `mechanism` (cave vs timer)

"Pinning" a value means keeping it at a target despite the game's own logic.
There are two mechanisms, and they trade robustness against simplicity:

- **`mechanism: cave`** — hook the actual instruction where the game writes the
  value each tick (AOB-scanned). Your payload runs *inside* the game's loop, so
  the value is re-applied in sync with the game tick. **Most robust** (no
  flicker/drift), but requires finding a stable instruction to hook.

- **`mechanism: timer`** — an external thread (in the trainer or DLL) re-writes
  the value at a fixed rate (`rate_hz`, e.g. 60 Hz). **Simpler** (no AOB/cave
  needed), but it races the game's tick — you may see flicker, and it drifts
  with frame rate.

This is the difference between the in-process loop patch and "a Python app that
writes at 60 Hz" — both are valid, and both are expressible in the profile.

## 7. MCP tools

- `list_profiles` — list discovered `cheats/*.yaml` files
- `load_profile` — load a profile by name, run its setup, materialize cheats
  (populates known values, does NOT enable any cheats)
- `save_profile` — serialize the current session's cheats to a `cheats/*.yaml`
- `detect_profile` — given a running game, which profile matches? (via
  `find_profile_for_game`; exposed through `list_profiles` + `load_profile`)

## 8. Design decisions / open questions

0. **`mechanism` (cave vs timer)** — **Resolved (see §6).** Both are valid ways
   to pin a value; the profile carries a `mechanism` field so either is
   expressible. `cave` = hook the game's tick instruction (robust); `timer` =
   re-write at `rate_hz` (simple, no AOB).
1. **`schema` field** — a versioned schema name (`trainlab-profile/v1`) so we
   can evolve the format without breaking old files. **Recommend yes.**
2. **Address resolution model** — cheat references a *named* setup value
   (`address_ref`/`target_ref`) OR an inline chain. This keeps the file DRY:
   one AOB scan feeds multiple cheats. **Recommend yes** (matches CE's "one
   pointer, many entries" pattern).
3. **Module-relative vs absolute** — we should prefer module+offset for
   stability, exactly like CE. Absolute addresses are a fallback. **Recommend:
   prefer module-relative; accept absolute.**
4. **Setup re-run per launch** — should the GUI auto-run setup on attach, or
   only on explicit load? CE auto-applies the table when you attach. **Recommend
   auto-run on attach if the profile is marked `inject_dll: true`.**
5. **Cave payload in the profile** — toggles carry shellcode. That's fine, but
   payloads are game/version-specific; keep them optional and versioned.
6. **Nested groups** — CE supports nested entries/groups. Do we want group
   headers in v1, or flat list? **Recommend flat for v1, groups later.**
7. **Where the resolved values live** — a resolved `SetupValue` map in the
   session (name → address), separate from cheats. **Recommend yes.**
8. **Security** — loading a profile runs AOB scans (read-only) and may inject.
   No writes until the user confirms a cheat. Loading an untrusted profile
   should be treated like loading an untrusted CE table.
