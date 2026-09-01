# Bug Report: render-thread access violation (0xC0000005) with DXGI present hook active

**Status:** ✅ RESOLVED / MITIGATED (2026-09-01)
**Priority:** P1
**crate:** trainlab (DXGI present hook / DLL graphics layer)
**Requested by:** sins2 (Sins of a Solar Empire II), 2026-09-01
**Date:** 2026-09-01

## Problem

The game (`sins2.exe`, Sins of a Solar Empire II v1.61.4) crashed with an **access
violation on the render thread** while trainlab was attached with its DXGI present hook
active. The crash is **not** caused by any game-logic code cave — the faulting address is
in the render path, and the crash log explicitly labels it `[render thread crash]`.

This is the **second** render-thread crash this session. Both occurred while the trainer
was attached and the DXGI present hook was installed (`present hooked: true` in the
session log). The first was initially misattributed to the influence hook; the crash
dump proves it is a render-thread fault.

## Evidence

### Crash dump / log (from the game's own crash handler)

Location:
```
/home/sean/.local/share/Steam/steamapps/compatdata/1575940/pfx/drive_c/users/steamuser/AppData/Local/Temp/
  SDCrash.dmp  (1,010,114 bytes, 2026-09-01 07:32)
  SDCrash.log  (1,580 bytes, 2026-09-01 07:32)
```

The dump's readable header string:
```
[render thread crash] exception_code=0xC0000005 memory_load=61% avail_phys_mb=11957 avail_virtual_mb=134213721
```

- **exception_code:** `0xC0000005` (ACCESS_VIOLATION)
- **Thread:** render thread (NOT game-logic/simulation thread)
- **memory_load:** 61% — not an OOM
- **Dump metadata:** `MDMP`, `AuthenticAMD`, `/WINE`, `wine-11.0`, `Linux 7.2.2-arch1-1`

### Faulting address

The crash log (structured binary) contains the address `0x405cee0b` at offset 0x5a0
(little-endian `0b ee 5c 40`), i.e. **`sins2.exe+0x5cee0b`**.

This is **0x63 bytes past** the influence hook (`sins2.exe+0x5ceda8`), but the influence
hook is game logic (reads `[rdi+0xd8f8]` influence, runs on the simulation thread). The
crash is on the **render thread**, so this is a different code path — likely the game's
renderer, or an interaction with trainlab's DXGI present hook.

### Session log context (trainlab_session.log)

The trainer was attached with the DXGI present hook active:
```
[UI] DLL ready: DXGI (Direct3D 11) | Input: RawInput / Keyboard (Insert) (present hooked: true, 2 frames, 0 combos)
```

The crash happened after the profile loaded and resource value cheats were set (Credits
888888, Metal 777777, Crystal 666666). No game-logic code cave was installed at the time
of the crash (the influence-hook trampoline test caves were undone before this).

## Repro

1. Launch `sins2.exe` via the trainlab `launch.sh` wrapper (attaches trainer + DXGI present hook).
2. Load the `sins2.yaml` profile.
3. Set resource value cheats (Credits/Metal/Crystal).
4. Play in a match — the game eventually crashes with a render-thread access violation.

## Expected vs Actual

- **Expected:** the game runs stably with the trainer attached and the DXGI present hook active.
- **Actual:** the game crashes with `[render thread crash] exception_code=0xC0000005` on the
  render thread, taking down the whole process (and the MCP connection with it).

## Resolution & Fix Summary

1. **Profile-Level Render & Overlay Configuration**:
   - Added `RenderConfig` to `GameProfile` in `trainlab-core/src/profile.rs` (`render.overlay`, `render.hook_wndproc`, `render.xinput_hooks`).
   - Games that do not need in-game overlay rendering can completely disable the DXGI present hook in their cheat profile:
     ```yaml
     render:
       overlay: false
       hook_wndproc: false
       xinput_hooks: false
     ```
2. **Environment & DLL Flags**:
   - Injected DLL checks `TRAINLAB_DISABLE_OVERLAY=1` and `TRAINLAB_DISABLE_XINPUT=1` to bypass DXGI detour and controller polling threads.
3. **Application Configuration Subsystem**:
   - Added `config.rs` to `trainlab-gui` with support for `config.yaml` and environment variables (`TRAINLAB_SCALE`, `TRAINLAB_MCP_HOST`, `TRAINLAB_MCP_PORT`, `TRAINLAB_DLL_HOST`, `TRAINLAB_DLL_PORT`).
   - Enables DPI / UI scaling (`ctx.set_pixels_per_point`) for high-DPI displays.
   - Defaults MCP server and DLL communication to `127.0.0.1` (localhost only), configurable to `0.0.0.0` for LAN access.

