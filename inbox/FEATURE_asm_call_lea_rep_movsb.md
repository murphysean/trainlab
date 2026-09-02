# Feature Request: Extend `assemble_asm` engine with `call`, `lea`, `rep movsb`/`cld`, and `movabs`-style absolute addressing

**Status:** ✅ RESOLVED / VALIDATED (2026-09-01)
**Priority:** [P1]
**crate:** `trainlab-core` (`asm.rs` — the iced-x86 `CodeAssembler` wrapper)
**Requested by:** Helldivers 1 Lua-injection session (2026-08-28)
**Date:** 2026-08-28

## Problem

The `assemble_asm` engine (the CE-style asm → shellcode compiler used by the
profile `asm:` field and the `assemble_asm` MCP tool) currently supports only a
**subset** of x86-64. It's missing several instructions that are needed to author
a **generic fire-once code cave** (the transport that runs arbitrary Lua in the
game) in readable asm instead of hand-encoded hex.

The missing instructions block the "eval cave" — a cave that runs a Lua chunk and
**captures its return value** into a cave buffer so the harness reads the output
directly (no aob_scan for interned strings). This is the fast-track for Lua field
discovery (armor, ammo, gunslinger reload driver, etc.).

## Missing instructions (verified against `asm.rs` mnemonic match)

The engine currently handles: `mov`, `movss`, `movsd`(?), `cmp`, `test`, `add`,
`sub`, `inc`, `dec`, `xor`/`xorps`, `mulss`, `divss`, `addss`, `subss`, `jmp`,
`je/jz/jne/jnz/jg/jge/jl/jle/ja/jae/jb/jbe/js/jns`, `push`, `pop`, `ret`, `nop`,
and `db`/`dd`/`dq` directives.

**NOT supported** (needed by the eval cave):
1. **`call`** — to invoke `luaL_loadstring` / `lua_pcall` / `lua_tolstring` /
   `lua_settop` (via `call r10` after `mov r10, <imm64>`). This is the single
   most important one — a code cave that runs a program fundamentally needs `call`.
2. **`lea`** — to compute `&result_len` (`lea r8, [rip + result_len]`) for the
   `lua_tolstring(L, -1, &len)` out-param.
3. **`cld` + `rep movsb`** — the copy loop that moves the captured return value
   from the Lua string into the cave's `result_buf`.
4. **`movabs` / 64-bit immediate into a register** — `mov r10, 0x1401ae260`
   (absolute function address). The engine's `mov` with an immediate may already
   handle this via `parse_u64_expr`, but it needs verification for 64-bit
   immediates that don't fit in 32 bits (the game's fixed base is `0x140000000`).

## Concrete asm the eval cave needs (the target)

```asm
; ... stolen body + fire gate + gate-clear (all supported today) ...
mov rcx, [rip + saved_state]
mov rdx, [rip + cmd_ptr]
mov r10, 0x1401ae260        ; zluaL_loadstring  <- needs movabs-style imm64
call r10                    ; <- needs call
mov [rip + result_slot], eax
test eax, eax
jnz balance
mov rcx, [rip + saved_state]
xor r9d, r9d
mov r8d, -1
xor edx, edx
mov r10, 0x1401a7ec0        ; zlua_pcall
call r10                    ; <- needs call
mov [rip + result_slot], eax
test eax, eax
jnz balance
mov rcx, [rip + saved_state]
mov edx, -1
lea r8, [rip + result_len]  ; <- needs lea
mov r10, [rip + tolstring_addr]
test r10, r10
jz balance
call r10                    ; lua_tolstring    <- needs call
test rax, rax
jz balance
cld                         ; <- needs cld
mov rsi, rax
lea rdi, [rip + result_buf] ; <- needs lea
mov rcx, [rip + result_len]
cmp rcx, 4095
jbe copy_ok
mov rcx, 4095
copy_ok:
rep movsb                   ; <- needs rep movsb
mov byte ptr [rdi], 0
balance:
mov rdx, [rip + saved_top]
mov rcx, [rip + saved_state]
mov r10, 0x1401a6260        ; zlua_settop
call r10                    ; <- needs call
ret
```

## Expected vs Actual

- **Expected:** `assemble_asm` compiles the above (and any CE-style cave) into
  shellcode, so the profile `asm:` field can express the full cave in readable asm.
- **Actual:** `assemble_asm` errors on `call`, `lea`, `cld`, `rep movsb` with
  "unsupported mnemonic" (the `other => Err(...)` fallthrough in
  `parse_and_emit_instruction`).

## Notes for the agent

- `iced-x86::code_asm::CodeAssembler` natively supports `call`, `lea`, `cld`,
  `rep movsb`, and 64-bit `mov` immediates — this is purely a matter of adding
  the mnemonic arms to `parse_and_emit_instruction` (and a `parse_mem`/`parse_gpr64`
  path for `lea`'s `[rip + label]` operand, which already exists for `mov`).
- `call` needs three operand forms: `call r10` (register), `call <imm64>` (absolute
  address, like `jmp` already does), and `call <label>` (local label).
- `rep movsb` is a single mnemonic with no operands (uses `rsi`/`rdi`/`rcx`).
- `lea` needs `lea r64, [rip + label]` and `lea r64, [r64 + imm]` forms.
- The `db` directive is a viable **workaround today** (embed raw bytes for the
  unsupported instructions), but it defeats the readability goal — the point of
  asm-direct is authoring caves in readable asm.
- This is a **generic** improvement: any game that uses a code-cave transport
  (Helldivers Lua, DRG Survivor GC hook, etc.) benefits. It matches how Cheat
  Table authors write caves.

## Workaround (in the meantime)

Author the eval cave with `db` directives for the unsupported bytes (`call`,
`lea`, `cld`, `rep movsb`), keeping the supported instructions in readable asm.
Functional but ugly; will be replaced by pure asm once this lands.
