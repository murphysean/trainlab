# Feature Request: persist disassembly context + original bytes of AOB hook sites (for re-finding after game updates + clean restore)

**Status:** ✅ RESOLVED (2026-09-01)
**Priority:** P2
**crate:** trainlab (profile schema + setup steps)
**Requested by:** sins2 (Sins of a Solar Empire II), 2026-09-01
**Date:** 2026-09-01

## Problem

When a game updates, the AOB patterns in a profile frequently stop matching — the
surrounding code shifts, so the byte signature changes. Re-finding the hook then requires
re-discovering the new site from scratch (disassemble, compare context, re-scan), which is
slow and error-prone.

The Cheat Engine tables (e.g. `SOASE2_1.50.6+DLC_G25.CT`) solve this elegantly: **each
cheat entry stores the original bytes of its hook site** in the `[DISABLE]` section, plus
the full original code context in a comment block. This serves two purposes:

1. **Re-finding after updates:** the original bytes of the hook site are a stable signature.
   When the AOB pattern no longer matches, you can scan for the *original bytes* (which are
   the actual code at that location) to relocate the hook in the new build.
2. **Clean restore:** the exact original bytes are known, so disabling a cheat restores the
   game code to its pristine state byte-for-byte.

Trainlab currently does **not** persist the original bytes of AOB hook sites in the profile.
The undo log records original bytes *at runtime* (for reverting a mutation in the current
session), but that's ephemeral — it's lost on restart and not part of the profile. So after
a game update, there's no record of what the hook site's original bytes were.

## ⭐ The key ask: persist the FUNCTION SIGNATURE / disassembly context

The original bytes are only part of the relocation story. What actually worked this session
to re-find moved/changed AOB signatures was the **function signature** — the *surrounding
disassembly context* that identifies the site's purpose. When the CT AOB patterns were stale,
we re-found the hooks by knowing the semantic of each site and matching the disassembly
context around it:

| Hook | Function signature (disassembly context) |
|------|-------------------------------------------|
| Resource write | `movss [rsi+rdx*4+8],xmm0` (rsi=resource array base, rdx=index) |
| Fast orbital | `comiss xmm6,[r14+0x18]` (build-progress float compare) |
| Influence | `mov esi,[rdi+0xd8f8]; cmp [rbx+0x850],esi` |
| Starbase/phase gate | `mov [rsp],0f3f800000` + `divss` (build-progress) |

The function context is **more stable than the raw AOB bytes** because it captures the
*semantic* of the site — the instructions around it that tell you what the function does.
A game update may shift the exact byte offsets, but the surrounding instruction pattern
(often the same mnemonics with different register/offset operands) tends to survive.

**Ask:** persist the **disassembly context** of each hook site — e.g. the N instructions
before/after the injection point (the CT's `// ORIGINAL CODE - INJECTION POINT` comment
block is exactly this). Store it as a human-readable disassembly listing (or a normalized
mnemonic sequence) alongside the AOB pattern. When re-finding after an update, the agent can:
1. Scan for the original bytes (exact match).
2. If that fails, scan for a *looser* AOB derived from the function signature (mnemonics
   with wildcarded register/offset operands), or disassemble candidate regions and compare
   the context to the stored signature.

This is the mechanism that actually let us relocate the moved/changed AOB signatures this
session, and it's the most valuable thing to preserve for future game updates.

## What the CT does (concrete example)

From `SOASE2_1.50.6+DLC_G25.CT`, the `mil_supply` cheat:

```
aobscanmodule(mil_supply,sins2.exe,8b 3c 39 03 bb ? ? ? ? 48 8b 0b)
...
mil_supply:
  jmp newmem
  nop 4
return:
registersymbol(mil_supply)

[DISABLE]
mil_supply:
  db 8B 3C 39 03 BB 98 02 00 00     <- original bytes of the hook site
unregistersymbol(*)
dealloc(*)

{
// ORIGINAL CODE - INJECTION POINT: sins2.exe.text+A29DEE
sins2.exe.text+A29DC0: 48 8B 03              - mov rax,[rbx]
...
// ---------- INJECTING HERE ----------
sins2.exe.text+A29DEE: 8B 3C 39              - mov edi,[rcx+rdi]
// ---------- DONE INJECTING  ----------
}
```

The `db 8B 3C 39 03 BB 98 02 00 00` is the exact original bytes of the hook site. When the
game updates and `aobscanmodule` fails, you can scan for `8B 3C 39 03 BB 98 02 00 00` to
relocate the hook. And `[DISABLE]` restores those exact bytes.

## Resolution & Summary

1. **Profile Schema Extensions (`trainlab-core/src/profile.rs`)**:
   - Added `original_bytes: Option<String>` and `context: Option<String>` to:
     - `SetupStep::AobScan` and `SetupStep::Address`
     - `ProfileCheat`
     - `ProfileCommand::AobScan`
   - Example YAML representation:
     ```yaml
     setup:
       - type: aob_scan
         name: influence_hook
         pattern: "8B B7 ?? ?? ?? ?? 39 B3"
         offset: 0
         region: "sins2.exe"
         original_bytes: "8B B7 F8 D8 00 00 39 B3 50 08 00 00"
         context: |
           sins2.exe+0x5ceda8: 8B B7 F8 D8 00 00 - mov esi,[rdi+0xd8f8]
           sins2.exe+0x5cedae: 39 B3 50 08 00 00 - cmp [rbx+0x00000850],esi
     ```
2. **Automatic Relocation Fallback in Profile Resolution (`trainlab-gui/src/mcp.rs`)**:
   - Both `resolve_setup_step` and `ProfileCommand::AobScan` now implement automatic fallback scanning:
     - If the wildcarded `pattern` scan fails (e.g. surrounding bytes shifted after an update), the engine automatically scans for the exact `original_bytes`.
     - When found, it relocates the hook site and logs the relocation.
3. **Pristine Byte Restoration (`load_profile` & `save_profile`)**:
   - `load_profile` populates `original_bytes` on `Toggle` and `Patch` cheats so clean disabling/unhooking is guaranteed even across restarts.
   - `save_profile` serializes live `original_bytes` into the generated YAML.
