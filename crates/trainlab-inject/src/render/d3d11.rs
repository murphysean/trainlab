//! Direct3D 11 in-game HUD overlay rasterizer.
//!
//! Renders textured/scissor-clipped 2D HUD elements directly onto the swapchain backbuffer.

use std::ffi::c_void;
use std::sync::atomic::{AtomicPtr, Ordering};

static DEVICE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static CONTEXT: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static RENDER_TARGET_VIEW: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

#[repr(C)]
struct D3D11_RECT {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
}

#[repr(C)]
struct D3D11_VIEWPORT {
    top_left_x: f32,
    top_left_y: f32,
    width: f32,
    height: f32,
    min_depth: f32,
    max_depth: f32,
}

/// Render in-game cheat overlay directly onto the active swapchain backbuffer.
pub unsafe fn render_overlay_frame(swapchain: *mut c_void) {
    if swapchain.is_null() {
        return;
    }

    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // 1. Resolve D3D11 Device and Context from SwapChain
        let mut dev = DEVICE.load(Ordering::Relaxed);
        if dev.is_null() {
            let sc_vtable = *(swapchain as *mut *mut usize);
            let get_dev_fn: unsafe extern "system" fn(
                *mut c_void,
                *const windows_sys::core::GUID,
                *mut *mut c_void,
            ) -> i32 = std::mem::transmute(*sc_vtable.add(7));

            // ID3D11Device GUID: {db6f6ddb-ac77-4e88-8253-819df9bbf140}
            let d3d11_device_guid = windows_sys::core::GUID {
                data1: 0xdb6f6ddb,
                data2: 0xac77,
                data3: 0x4e88,
                data4: [0x82, 0x53, 0x81, 0x9d, 0xf9, 0xbb, 0xf1, 0x40],
            };
            let mut dev_ptr: *mut c_void = std::ptr::null_mut();
            let hr = get_dev_fn(swapchain, &d3d11_device_guid, &mut dev_ptr);
            if hr == 0 && !dev_ptr.is_null() {
                dev = dev_ptr;
                DEVICE.store(dev_ptr, Ordering::SeqCst);

                let dev_vtable = *(dev_ptr as *mut *mut usize);
                let get_ctx_fn: unsafe extern "system" fn(*mut c_void, *mut *mut c_void) =
                    std::mem::transmute(*dev_vtable.add(40));
                let mut ctx_ptr: *mut c_void = std::ptr::null_mut();
                get_ctx_fn(dev_ptr, &mut ctx_ptr);
                if !ctx_ptr.is_null() {
                    CONTEXT.store(ctx_ptr, Ordering::SeqCst);
                }
            }
        }

        let ctx = CONTEXT.load(Ordering::Relaxed);
        if dev.is_null() || ctx.is_null() {
            return;
        }

        // 2. Resolve Backbuffer Render Target View if not cached
        let mut rtv = RENDER_TARGET_VIEW.load(Ordering::Relaxed);
        if rtv.is_null() {
            let sc_vtable = *(swapchain as *mut *mut usize);
            let get_buf_fn: unsafe extern "system" fn(
                *mut c_void,
                u32,
                *const windows_sys::core::GUID,
                *mut *mut c_void,
            ) -> i32 = std::mem::transmute(*sc_vtable.add(9));

            // ID3D11Texture2D GUID: {6f15aaf2-d208-4e89-9ab4-489535d34f9c}
            let tex2d_guid = windows_sys::core::GUID {
                data1: 0x6f15aaf2,
                data2: 0xd208,
                data3: 0x4e89,
                data4: [0x9a, 0xb4, 0x48, 0x95, 0x35, 0xd3, 0x4f, 0x9c],
            };
            let mut backbuffer: *mut c_void = std::ptr::null_mut();
            let hr = get_buf_fn(swapchain, 0, &tex2d_guid, &mut backbuffer);
            if hr == 0 && !backbuffer.is_null() {
                let dev_vtable = *(dev as *mut *mut usize);
                let create_rtv_fn: unsafe extern "system" fn(
                    *mut c_void,
                    *mut c_void,
                    *const c_void,
                    *mut *mut c_void,
                ) -> i32 = std::mem::transmute(*dev_vtable.add(9));

                let mut rtv_ptr: *mut c_void = std::ptr::null_mut();
                if create_rtv_fn(dev, backbuffer, std::ptr::null(), &mut rtv_ptr) == 0 && !rtv_ptr.is_null() {
                    rtv = rtv_ptr;
                    RENDER_TARGET_VIEW.store(rtv_ptr, Ordering::SeqCst);
                }

                // Release backbuffer COM handle
                let bb_vt = *(backbuffer as *mut *mut usize);
                let rel_fn: unsafe extern "system" fn(*mut c_void) -> u32 = std::mem::transmute(*bb_vt.add(2));
                rel_fn(backbuffer);
            }
        }

        // 3. Render Top-Left In-Game HUD Box (360x440 Menu Box)
        if !rtv.is_null() {
            let ctx_vtable = *(ctx as *mut *mut usize);
            let om_set_rt: unsafe extern "system" fn(
                *mut c_void,
                u32,
                *const *mut c_void,
                *mut c_void,
            ) = std::mem::transmute(*ctx_vtable.add(33));
            let rt_array = [rtv];
            om_set_rt(ctx, 1, rt_array.as_ptr(), std::ptr::null_mut());

            // Run in-game egui frame pass
            let _ = super::overlay::render_in_game_egui(1280.0, 800.0);

            // Set Scissor Rect to Top-Left Menu Box: x: 30..390, y: 30..470
            let set_scissor_fn: unsafe extern "system" fn(*mut c_void, u32, *const D3D11_RECT) =
                std::mem::transmute(*ctx_vtable.add(45));
            let menu_box = D3D11_RECT {
                left: 30,
                top: 30,
                right: 390,
                bottom: 470,
            };
            set_scissor_fn(ctx, 1, &menu_box);

            // ClearRenderTargetView with dark charcoal tint
            let clear_rtv: unsafe extern "system" fn(*mut c_void, *mut c_void, *const f32) =
                std::mem::transmute(*ctx_vtable.add(50));
            let dark_menu_color = [0.08f32, 0.10f32, 0.14f32, 0.90f32];
            clear_rtv(ctx, rtv, dark_menu_color.as_ptr());
        }
    }));
}
