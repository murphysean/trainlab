# Bug Report: render-thread access violation (0xC0000005) with DXGI present hook active

**Status:** ⚠️ MITIGATED (More work to do)
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

## Root Cause Analysis (RCA)

Inspecting `crates/trainlab-inject/src/render/dxgi.rs` and `crates/trainlab-inject/src/render/d3d11.rs` revealed three underlying structural vulnerabilities in the graphics hook layer:

1. **Trampoline Hooking of DXVK/Wine `Present`**:
   - `init_dxgi_hook` uses a dummy swapchain to locate `IDXGISwapChain::Present` and installs an in-place **14-byte absolute jump trampoline** into executable code.
   - Under Proton/DXVK (Vulkan backend) or Wine, `Present` functions are frequently short, non-standard, or invoked concurrently by DXVK presentation threads. An inline 14-byte patch risks instruction tearing or race conditions across swapchain re-creation and presentation.
2. **Unsafe COM Pointer Querying in `hooked_present`**:
   - `hooked_present` extracts the game's `HWND` by directly invoking `vtable[12]` (`GetDesc`) on the passed `swapchain` pointer without calling `QueryInterface(IID_IDXGISwapChain)` or taking reference counts (`AddRef`).
   - If the game engine passes an internal wrapper, a deferred swapchain, or a swapchain in the middle of destruction / `ResizeBuffers`, invoking unverified VMT offsets triggers `0xC0000005`.
3. **Missing D3D11 Pipeline State Backup & Restore**:
   - In `d3d11.rs`, rendering the egui overlay directly binds viewports, shaders, rasterizer states, depth-stencil states, and render target views (`OMSetRenderTargets`, `RSSetViewports`, `IASetInputLayout`) to the immediate context.
   - It does not save the game's active pipeline state beforehand or restore it before returning to the original `Present`. Subsequent game render passes that expect existing render targets or shader states will access clobbered state and crash.

## Mitigation Implemented

1. **Profile-Level Opt-Out (`render` block in `GameProfile`)**:
   - Added `RenderConfig` to `GameProfile` in `trainlab-core/src/profile.rs` (`render.overlay`, `render.hook_wndproc`, `render.xinput_hooks`).
   - For games sensitive to render-thread hooking, the DXGI present hook can be completely disabled in the profile:
     ```yaml
     render:
       overlay: false       # Completely disables the DXGI Present hook
       hook_wndproc: false  # Disables message/hotkey hooking
       xinput_hooks: false  # Disables gamepad polling
     ```
2. **Environment Overrides**:
   - Injected DLL checks `TRAINLAB_DISABLE_OVERLAY=1` and `TRAINLAB_DISABLE_XINPUT=1` to skip DXGI and XInput hooking threads on demand.

## Future Work Required for Full Fix

- [ ] **VMT Swap Detours**: Replace in-place 14-byte code cave patching of `Present` with VMT table swapping or clean COM method replacement.
- [ ] **Safe COM Interface Probing**: Wrap swapchain operations in `QueryInterface` and add SEH exception boundaries to catch transient invalid swapchains during window resizes.
- [ ] **Full D3D11 Pipeline State Backup/Restore**: Implement a full state saver that records `OMGetRenderTargets`, `RSGetViewports`, `OMGetBlendState`, `IAGetInputLayout`, etc., before overlay drawing and restores them cleanly before invoking the original `Present`.


