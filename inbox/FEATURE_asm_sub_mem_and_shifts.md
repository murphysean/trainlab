# Feature Request: `sub`/`add` with memory source + shift instructions (`sar`/`shl`/`shr`) in `assemble_asm`

**Status:** ✅ RESOLVED / VALIDATED (2026-09-01)
**Priority:** [P1]
**crate:** `trainlab-core` (`asm.rs` — the iced-x86 `CodeAssembler` wrapper)
**Requested by:** Helldivers 1 Lua-injection session (2026-08-28)
**Date:** 2026-08-28

## Problem

The `assemble_asm` engine still can't express two instruction families needed to
author a **code cave in pure asm** (no `db` hex workarounds). The eval cave (runs a
Lua chunk and captures its return value) needs to **replay the stolen body** of the
hooked function `zlua_gettop`, which is:

```asm
sub rax, [rcx + 0x10]   ; rax = rax_in - stackbase
sar rax, 3              ; rax = top
```

The engine's `sub`/`add` handlers only accept **register or immediate** sources —
not a **memory** source (`[rcx+0x10]`). And there is **no shift** support at all
(`sar`/`shl`/`shr`).

## Missing instructions (verified against `asm.rs`)

1. **`sub`/`add` with memory source** — e.g. `sub rax, [rcx+0x10]`, `add rax, [rbx+0x8]`.
   The current `sub`/`add` handlers do `parse_gpr64(args[1])` then `parse_u64_expr`,
   but never `parse_mem`. Add a `parse_mem` branch (mirroring how `mov` handles a
   memory source).
2. **Shift instructions** — `sar`, `shl`, `shr` (and ideally `sal`/`rol`/`ror`).
   Needed form: `sar rax, 3` (reg, imm8). iced-x86 `CodeAssembler` supports these
   natively; just add the mnemonic arms.

## Concrete asm the eval cave needs (the target)

```asm
; ---- stolen body (zlua_gettop) ----
sub rax, [rcx + 0x10]   ; <- needs sub-with-memory
sar rax, 3              ; <- needs sar

; ---- fire-once flag gate ----
cmp byte ptr [rip + fire_flag], 1
jne done
mov byte ptr [rip + fire_flag], 0
mov [rip + saved_state], rcx
mov [rip + saved_top], rax

; ... (rest is already supported: call/lea/cld/rep movsb/negative imm/64-bit abs)
```

## Expected vs Actual

- **Expected:** `assemble_asm` compiles the stolen body in pure asm, so the whole
  cave is authored in readable asm (no `db` hex).
- **Actual:** `sub rax, [rcx+0x10]` errors (memory source unsupported) and
  `sar rax, 3` errors (unsupported mnemonic).

## Notes for the agent

- `sub`/`add` memory source: in the existing `sub`/`add` handlers, add a
  `else if let Ok(mem) = parse_mem(args[1], ...)` branch that calls
  `a.sub(dst, mem)` / `a.add(dst, mem)`. `parse_mem` already handles `[rcx+0x10]`.
- Shifts: add `"sar" | "shl" | "shr"` (and optionally `"sal" | "rol" | "ror"`)
  arms. Form is `sar r64, imm8` (and `sar r64, cl` for variable shifts, if easy).
  iced-x86 `CodeAssembler` has `a.sar(reg, imm)`, `a.shl(...)`, `a.shr(...)`.
- This is **generic** — any game whose hook site has a memory-source arithmetic or
  shift in the stolen body needs it. Matches CE auto-assembler, which supports these
  natively.

## Workaround (in the meantime)

Emit the stolen body via `db` directives (`db 48 2b 41 10` / `db 48 c1 f8 03`).
Functional but defeats the pure-asm goal; will be replaced once this lands.
