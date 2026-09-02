# Feature Request: extend install_cave ASM assembler with common SSE/int-fallthrough forms

**Status:** ✅ RESOLVED / VALIDATED (2026-09-01)
**Priority:** P2
**crate:** trainlab (asm assembler used by `install_cave` / `add_cheat` `asm`)
**Requested by:** sins2 (Sins of a Solar Empire II), 2026-09-01

## Problem

The ASM->bytes assembler used by `install_cave` rejects several very common x86-64
instructions. I was trying to build a small "clamp float register to a floor, then
fall through to an existing store" cave at `sins2.exe+0xabec51` (game resource
income). Every one of these mnemonics errored with `-32603 unsupported mnemonic ...`:

- `pxor`
- `movd`
- `cvtsi2ss`
- `mov dword [rsi+rdx*4+0x8], imm32`

The last one is the standout: a plain `mov [reg+reg*scale+imm], imm32` store is
entirely standard and not an unusual form.

**IMPORTANT — the scaled-index SIB limitation is standalone.** It's not tied to the
SSE mnemonics. A plain `lea rax, [rdx+rdx*4]` also fails with
`invalid int 'rdx*4': invalid digit found in string`. So ANY `[reg+reg*scale+imm]`
addressing (SIB byte with index+scale) is rejected by the parser, regardless of
opcode. Only simple `[reg+imm]` (no index/scale) works:
`mov dword [r10], 200000` assembles fine.

**Also observed:** `movss xmm1, dword ptr [rip+0]` fails with "Displacement must fit
in an i32 : 0x0 movss xmm1,dword ptr [140ABEC51h]" — the assembler resolves `[rip+disp]`
against the *target* address, not the cave, so data-anchored rip-relative reads from
a scratch buffer can't be written directly either.

## Repro

```
install_cave target=sins2.exe+0xabec51 hook=override asm="
  cmp edx, 2
  ja back
  cmp edx, 0
  jne not_credit
  mov eax, 20000
  jmp store
  not_credit:
  mov eax, 10000
  store:
  movd xmm0, eax
  back:
"
```
→ `unsupported mnemonic 'movd'` (and similarly for pxor / cvtsi2ss /
`mov dword [rsi+rdx*4+0x8], eax`).

## Expected vs Actual

- **Expected:** common SSE move/convert instructions and scaled-index `mov` with an
  immediate memory operand assemble successfully.
- **Actual:** `-32603 unsupported mnemonic ...` / `unsupported mov operands`.

## Notes for the agent

- The iced-x86 assembler usually handles all of these. If trainlab is using a
  restricted subset (e.g. only 1-byte `jcc`/`mov` reg,imm), that's the lever to widen.
- For sins2 specifically: a full clamp would ideally be `movss/movsd` or a scaled
  `mov` store. If it's non-trivial to add, an acceptable fallback is to support
  `cvtsi2ss`/`movd`/`comiss` so a value clamp can be written with integer immediates
  (they assemble from clean scalar code).
- **Verified-working subset as of today (2026-09-01):** `cmp`, `mov r32,imm`,
  `mov dword [r10],imm`, `add`, `shl`, `jcc` (`ja`/`jne`/`je`). Everything else in
  the SSE-family and SIB-addressing space is a gap.
- **Confirmed workaround exists** (two registers, no SSE/SIB needed): compute the
  target address with `shl edx,2` + `add` into a scratch pointer reg, and keep the
  floor *value* in a separate reg; then `mov dword [scratch+8], value_reg`.
  Cave: store the float's *integer bit pattern* via the value register — do NOT
  reuse it as an address offset (my first correct-shaped attempt erroneously did
  `add r10d, edx` on the same reg and corrupted the target address; it was caught
  and reverted before it ran). This unblocks us even if no assembler changes land,
  but a cleaner scaled-index + SSE scalar path is still worth adding.

## ✅ VALIDATION (2026-09-01) — all previously-failing forms now assemble

Tested live on `sins2.exe+0x5ceda8` (influence hook) with benign trampoline payloads,
each installed then undone:

| Form | Before | Now |
|------|--------|-----|
| `lea rax, [rdx+rdx*4]` (SIB scaled-index) | `-32603 invalid int 'rdx*4'` | ✅ 5-byte payload |
| `pxor xmm0, xmm0` | `-32603 unsupported mnemonic` | ✅ |
| `movd xmm1, eax` | `-32603 unsupported mnemonic` | ✅ |
| `cvtsi2ss xmm2, eax` | `-32603 unsupported mnemonic` | ✅ |
| `mov dword [rsi+rdx*4+0x8], 20000` (scaled-index store) | `-32603 unsupported mov operands` | ✅ 21-byte payload |

**All 5 forms assemble cleanly.** The assembler widening is confirmed working. This
unblocks the restart-stable "Minimum Resources" floor-cave at `sins2.exe+0xabec55`
(needs `movss`/`movd`/`cvtsi2ss`/scaled-index `mov`).

⚠️ Note: the game process exited during this test (unclear if the trampoline on the hot
influence path caused it, or coincidental). Cave patch died with the process — no stale
patch. If it recurs, test on a colder site.
