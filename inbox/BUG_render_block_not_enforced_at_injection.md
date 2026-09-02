# Bug Report: `render:` profile block does not suppress DXGI Present hook at injection time

**Status:** ✅ RESOLVED (2026-09-01)
**Priority:** P1 (render-thread crash mitigation)
**Area:** DLL inject layer / profile parser (render block enforcement)
**Date:** 2026-09-01
**Game / Target:** sins2.exe (Sins of a Solar Empire II v1.61.4, appid 1575940)

---

## 1. Summary & Context
Follow-up to `docs/BUG_render_thread_crash.md`. The `render:` block (`overlay: false`,
`hook_wndproc: false`, `xinput_hooks: false`) was added to `sins2.yaml` as the workaround
for the render-thread 0xC0000005 crash. At the time it was noted that `get_render_status`
still showed `present_hooked: true` after a profile load — attributed to needing a "fresh
injection to take effect."

That hypothesis was disproven: the DLL previously spawned graphics and input hook threads
unconditionally upon `DllMain` load.

---

## 2. Solution Implemented
1. **Bare-Minimal DLL Injection**:
   - `render::init()` in `trainlab-inject` now only records detected third-party foreign overlays (Steam, OBS, Discord) without touching DirectX or input APIs.
2. **IPC-Driven Configuration**:
   - Added `Request::ConfigureRender` and `Response::RenderConfigured` to `trainlab-core::protocol`.
   - The injected DLL only begins DXGI or XInput hooking when explicitly instructed by the GUI via IPC.
3. **Profile & GUI Synchronization**:
   - Both `trainlab-gui`'s background attach/connect loop and `load_profile` MCP tool dispatch `Request::ConfigureRender` using the active game profile's `render:` block (`RenderConfig`) before executing setup commands or initializing graphics hooks.
   - For targets with `render.overlay: false` (such as `sins2.yaml`), zero DXGI or window procedure hooks are installed in the game process.

---

## 3. Verification
- `cargo test --workspace` passed cleanly including `test_configure_render_roundtrip`.

---

## Interim user guidance
Until fixed, the only reliable way to run sins2 with zero trainlab render hooks is to not
inject the graphics layer at all (or build a no-graphics-hook DLL variant). Loading the
profile after injection does NOT disable the present hook. Watch for the render-thread
crash signature (`[render thread crash]` in SDCrash.log) and treat it as a trainlab-side
crash, not a game bug.