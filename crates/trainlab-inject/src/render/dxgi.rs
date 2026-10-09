//! DXGI SwapChain Hooking (DirectX 11 & DirectX 12).
//!
//! Uses the dummy device technique to dynamically resolve the address of `IDXGISwapChain::Present`
//! (VMT index 8) from `d3d11.dll` / `dxgi.dll` and installs a detour hook.
//! On each Present call:
//! 1. Increments the global frame counter.
//! 2. Captures the game's HWND from DXGI_SWAP_CHAIN_DESC to install the WndProc hook.
//! 3. Invokes the original Present.

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::time::Duration;

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExA, DestroyWindow, UnregisterClassA, WNDCLASSA, WS_OVERLAPPEDWINDOW,
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DXGI_RATIONAL {
    pub numerator: u32,
    pub denominator: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DXGI_MODE_DESC {
    pub width: u32,
    pub height: u32,
    pub refresh_rate: DXGI_RATIONAL,
    pub format: u32,
    pub scanline_ordering: u32,
    pub scaling: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DXGI_SAMPLE_DESC {
    pub count: u32,
    pub quality: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DXGI_SWAP_CHAIN_DESC {
    pub buffer_desc: DXGI_MODE_DESC,
    pub sample_desc: DXGI_SAMPLE_DESC,
    pub buffer_usage: u32,
    pub buffer_count: u32,
    pub output_window: HWND,
    pub windowed: i32,
    pub swap_effect: u32,
    pub flags: u32,
}

type FnPresent = unsafe extern "system" fn(*mut c_void, u32, u32) -> i32;

type FnD3D11CreateDeviceAndSwapChain = unsafe extern "system" fn(
    *mut c_void, // pAdapter
    u32,         // DriverType (D3D_DRIVER_TYPE_HARDWARE = 1)
    *mut c_void, // Software
    u32,         // Flags
    *const u32,  // pFeatureLevels
    u32,         // FeatureLevels
    u32,         // SDKVersion (7)
    *const DXGI_SWAP_CHAIN_DESC,
    *mut *mut c_void, // ppSwapChain
    *mut *mut c_void, // ppDevice
    *mut u32,         // pFeatureLevel
    *mut *mut c_void, // ppImmediateContext
) -> i32;

static ORIGINAL_PRESENT: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static HOOK_INSTALLED: AtomicBool = AtomicBool::new(false);
static HWND_INITIALIZED: AtomicBool = AtomicBool::new(false);
static HOOK_TARGET_ADDR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static ORIGINAL_BYTES: std::sync::Mutex<Vec<u8>> = std::sync::Mutex::new(Vec::new());

/// Our hooked `IDXGISwapChain::Present` callback.
pub unsafe extern "system" fn hooked_present(
    swapchain: *mut c_void,
    sync_interval: u32,
    flags: u32,
) -> i32 {
    let orig = ORIGINAL_PRESENT.load(Ordering::Relaxed);

    // If shutting down or invalid swapchain pointer, bypass overlay and invoke original Present directly
    if super::is_shutting_down() || swapchain.is_null() {
        return if !orig.is_null() {
            let orig_fn: FnPresent = std::mem::transmute(orig);
            orig_fn(swapchain, sync_interval, flags)
        } else {
            0
        };
    }

    // 1. Increment live frame counter
    let fc = super::STATE.frame_count.fetch_add(1, Ordering::Relaxed) + 1;
    let vis = super::STATE.overlay_visible.load(Ordering::Relaxed);
    if fc == 1 || fc % 600 == 0 || (vis && fc % 60 == 0) {
        super::log_render(format!("hooked_present: frame={fc}, overlay_visible={vis}, swapchain={swapchain:?}"));
    }

    // 2. On the first few frames, extract the game's actual HWND from swapchain description safely
    if !HWND_INITIALIZED.load(Ordering::Relaxed) && !swapchain.is_null() {
        let vtable_ptr = *(swapchain as *mut *mut usize);
        if !vtable_ptr.is_null() {
            let mut desc: DXGI_SWAP_CHAIN_DESC = std::mem::zeroed();
            // GetDesc is VMT index 12 on IDXGISwapChain
            let get_desc_fn_ptr = *vtable_ptr.add(12);
            if get_desc_fn_ptr != 0 {
                let get_desc_fn: unsafe extern "system" fn(
                    *mut c_void,
                    *mut DXGI_SWAP_CHAIN_DESC,
                ) -> i32 = std::mem::transmute(get_desc_fn_ptr);

                if get_desc_fn(swapchain, &mut desc) == 0
                    && desc.output_window != std::ptr::null_mut()
                {
                    super::log_render(format!("hooked_present: captured game HWND={:?}", desc.output_window));
                    super::input::install_wndproc_hook(desc.output_window);
                    HWND_INITIALIZED.store(true, Ordering::Relaxed);
                    // Proactively assert foreground focus on the game window so Gamescope/Remote Play
                    // immediately latches onto the game instead of any background companion window.
                    super::input::focus_game_window();
                }
            }
        }
    }

    // 3. Run frame-synchronous cheat value pinning cadence
    super::overlay::execute_pinning_cadence();

    // 4. Run in-game overlay render pass if overlay is active
    if vis {
        if !super::d3d12::try_render_d3d12_overlay(swapchain) {
            super::d3d11::render_overlay_frame(swapchain);
        }
    }

    // 5. Call original Present trampoline
    if !orig.is_null() {
        let orig_fn: FnPresent = std::mem::transmute(orig);
        orig_fn(swapchain, sync_interval, flags)
    } else {
        0
    }
}

/// Creates a dummy window and D3D11 swapchain to discover the VMT pointer for `Present`.
unsafe fn find_dxgi_present_vmt() -> Option<*mut usize> {
    let d3d11_dll = LoadLibraryA(b"d3d11.dll\0".as_ptr());
    if d3d11_dll == std::ptr::null_mut() {
        super::log_render("find_dxgi_present_vmt: LoadLibraryA(d3d11.dll) returned NULL");
        return None;
    }

    let create_fn_ptr = GetProcAddress(d3d11_dll, b"D3D11CreateDeviceAndSwapChain\0".as_ptr());
    if create_fn_ptr.is_none() {
        super::log_render("find_dxgi_present_vmt: GetProcAddress(D3D11CreateDeviceAndSwapChain) is None");
        return None;
    }

    let d3d11_create: FnD3D11CreateDeviceAndSwapChain = std::mem::transmute(create_fn_ptr);

    let class_name = b"TrainlabDummyClass\0";
    let wnd_class = WNDCLASSA {
        style: 0,
        lpfnWndProc: Some(windows_sys::Win32::UI::WindowsAndMessaging::DefWindowProcA),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: std::ptr::null_mut(),
        hIcon: std::ptr::null_mut(),
        hCursor: std::ptr::null_mut(),
        hbrBackground: std::ptr::null_mut(),
        lpszMenuName: std::ptr::null(),
        lpszClassName: class_name.as_ptr(),
    };

    windows_sys::Win32::UI::WindowsAndMessaging::RegisterClassA(&wnd_class);

    let hwnd = CreateWindowExA(
        windows_sys::Win32::UI::WindowsAndMessaging::WS_EX_TOOLWINDOW,
        class_name.as_ptr(),
        b"TrainlabDummyWindow\0".as_ptr(),
        windows_sys::Win32::UI::WindowsAndMessaging::WS_POPUP
            | windows_sys::Win32::UI::WindowsAndMessaging::WS_DISABLED,
        0,
        0,
        100,
        100,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        std::ptr::null(),
    );

    if hwnd == std::ptr::null_mut() {
        super::log_render("find_dxgi_present_vmt: CreateWindowExA returned NULL");
        return None;
    }

    let mut swap_desc: DXGI_SWAP_CHAIN_DESC = std::mem::zeroed();
    swap_desc.buffer_count = 1;
    swap_desc.buffer_desc.format = 28; // DXGI_FORMAT_R8G8B8A8_UNORM = 28
    swap_desc.buffer_desc.width = 100;
    swap_desc.buffer_desc.height = 100;
    swap_desc.buffer_desc.refresh_rate.numerator = 60;
    swap_desc.buffer_desc.refresh_rate.denominator = 1;
    swap_desc.buffer_usage = 0x20; // DXGI_USAGE_RENDER_TARGET_OUTPUT = 0x20
    swap_desc.output_window = hwnd;
    swap_desc.sample_desc.count = 1;
    swap_desc.sample_desc.quality = 0;
    swap_desc.windowed = 1;
    swap_desc.swap_effect = 0; // DXGI_SWAP_EFFECT_DISCARD = 0

    let mut feature_level: u32 = 0;
    let mut device: *mut c_void = std::ptr::null_mut();
    let mut context: *mut c_void = std::ptr::null_mut();
    let mut swapchain: *mut c_void = std::ptr::null_mut();

    const D3D_DRIVER_TYPE_HARDWARE: u32 = 1;
    const D3D_DRIVER_TYPE_WARP: u32 = 2;
    const D3D11_SDK_VERSION: u32 = 7;

    let mut hr = d3d11_create(
        std::ptr::null_mut(),
        D3D_DRIVER_TYPE_HARDWARE,
        std::ptr::null_mut(),
        0,
        std::ptr::null(),
        0,
        D3D11_SDK_VERSION,
        &swap_desc,
        &mut swapchain,
        &mut device,
        &mut feature_level,
        &mut context,
    );

    if hr != 0 || swapchain.is_null() {
        super::log_render(format!("find_dxgi_present_vmt: HARDWARE driver failed (hr=0x{hr:08X}), trying WARP..."));
        hr = d3d11_create(
            std::ptr::null_mut(),
            D3D_DRIVER_TYPE_WARP,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
            0,
            D3D11_SDK_VERSION,
            &swap_desc,
            &mut swapchain,
            &mut device,
            &mut feature_level,
            &mut context,
        );
    }

    let mut present_addr = None;

    if hr == 0 && !swapchain.is_null() {
        let vtable = *(swapchain as *mut *mut usize);
        // Index 8 is IDXGISwapChain::Present
        let present_ptr = *vtable.add(8);
        super::log_render(format!("find_dxgi_present_vmt: SUCCESS! IDXGISwapChain::Present at 0x{present_ptr:X} (feature_level=0x{feature_level:X})"));
        present_addr = Some(present_ptr as *mut usize);

        // Release dummy COM objects
        let release_fn = |com_ptr: *mut usize| {
            if !com_ptr.is_null() {
                let vtable = *(com_ptr as *mut *mut usize);
                let release: unsafe extern "system" fn(*mut usize) -> u32 =
                    std::mem::transmute(*vtable.add(2));
                release(com_ptr);
            }
        };

        release_fn(swapchain as *mut usize);
        release_fn(device as *mut usize);
        release_fn(context as *mut usize);
    } else {
        super::log_render(format!("find_dxgi_present_vmt: FAILED to create D3D11 swapchain (hr=0x{hr:08X})"));
    }

    DestroyWindow(hwnd);
    UnregisterClassA(class_name.as_ptr(), std::ptr::null_mut());

    present_addr
}

/// Initialize the DXGI hook in a background retry loop.
pub fn init_dxgi_hook() {
    super::log_render("init_dxgi_hook started");
    // Wait briefly if third-party hooks (Steam / OBS / Discord) are initializing
    std::thread::sleep(Duration::from_millis(500));

    // Try finding DXGI Present
    for attempt in 1..=20 {
        if HOOK_INSTALLED.load(Ordering::SeqCst) {
            break;
        }

        unsafe {
            let dxgi_mod = GetModuleHandleA(b"dxgi.dll\0".as_ptr());
            let d3d11_mod = GetModuleHandleA(b"d3d11.dll\0".as_ptr());
            let d3d12_mod = GetModuleHandleA(b"d3d12.dll\0".as_ptr());

            if dxgi_mod != std::ptr::null_mut()
                || d3d11_mod != std::ptr::null_mut()
                || d3d12_mod != std::ptr::null_mut()
            {
                super::log_render(format!("init_dxgi_hook: attempt {attempt}, graphics modules found (dxgi={:?}, d3d11={:?})", dxgi_mod, d3d11_mod));
                if let Some(target_present) = find_dxgi_present_vmt() {
                    let target_u64 = target_present as u64;

                    // Payload is a jump to hooked_present
                    let callback_addr = hooked_present as *const () as u64;
                    let payload = trainlab_cave::emitter::jmp_abs(callback_addr);

                    let hook = trainlab_cave::cave::HookKind::Trampoline {
                        payload: payload.clone(),
                        jump: trainlab_cave::cave::JumpStyle::Absolute,
                    };

                    let mem = trainlab_core::memory::SelfProcess;
                    let read = |addr: u64, len: usize| -> Result<Vec<u8>, String> {
                        use trainlab_core::memory::ProcessMemory;
                        mem.read(addr, len).map_err(|e| e.to_string())
                    };
                    let write = |addr: u64, data: &[u8]| -> Result<usize, String> {
                        use trainlab_core::memory::ProcessMemory;
                        mem.write(addr, data).map_err(|e| e.to_string())
                    };
                    let allocate = |size: usize, exec: bool| -> Result<u64, String> {
                        crate::allocate(size, exec)
                    };

                    // Atomic reservation: only ONE thread in the entire process can attempt installation
                    if HOOK_INSTALLED.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
                        super::log_render("init_dxgi_hook: already installed by another thread, skipping");
                        break;
                    }

                    // Verify target site is not already detoured to our hooked_present callback
                    if let Ok(current_bytes) = read(target_u64, 14) {
                        if current_bytes.starts_with(&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]) {
                            let dest = u64::from_le_bytes(current_bytes[6..14].try_into().unwrap_or_default());
                            if dest == callback_addr {
                                super::log_render(format!(
                                    "init_dxgi_hook: target 0x{:X} is ALREADY hooked with our callback 0x{:X}, skipping install",
                                    target_u64, dest
                                ));
                                break;
                            }
                        }
                    }

                    match trainlab_cave::cave::install(target_u64, hook, read, write, allocate) {
                        Ok(installed) => {
                            // Save target address and original instructions for unhook on shutdown.
                            // CRITICAL: only store original bytes if not already captured to preserve
                            // true game instructions and never overwrite with a trainlab trampoline.
                            HOOK_TARGET_ADDR.store(installed.target, Ordering::SeqCst);
                            if let Ok(mut bytes) = ORIGINAL_BYTES.lock() {
                                if bytes.is_empty() {
                                    *bytes = installed.original.clone();
                                    super::log_render(format!(
                                        "init_dxgi_hook: captured {} true original bytes at 0x{:X}",
                                        bytes.len(),
                                        installed.target
                                    ));
                                }
                            }

                            // Point original present to the trampoline return path
                            ORIGINAL_PRESENT.store(
                                (installed.cave_addr + payload.len() as u64) as *mut c_void,
                                Ordering::SeqCst,
                            );
                            super::STATE.present_hooked.store(true, Ordering::SeqCst);

                            let api_name = if d3d12_mod != std::ptr::null_mut() {
                                "DXGI (Direct3D 12)"
                            } else {
                                "DXGI (Direct3D 11)"
                            };

                            if let Ok(mut name_lock) = super::STATE.api_name.lock() {
                                *name_lock = api_name.to_string();
                            }

                            super::log_render(format!(
                                "init_dxgi_hook: HOOK INSTALLED at 0x{:X} -> cave 0x{:X} ({})",
                                target_u64,
                                installed.cave_addr,
                                api_name
                            ));
                            break;
                        }
                        Err(err) => {
                            // Release reservation so a future attempt can retry if needed
                            HOOK_INSTALLED.store(false, Ordering::SeqCst);
                            super::log_render(format!(
                                "init_dxgi_hook: cave::install FAILED at 0x{:X}: {:?}",
                                target_u64,
                                err
                            ));
                        }
                    }
                }
            } else if attempt == 1 || attempt % 5 == 0 {
                super::log_render(format!("init_dxgi_hook: attempt {attempt}, waiting for dxgi/d3d11 modules..."));
            }
        }

        std::thread::sleep(Duration::from_millis(1000));
    }
}

/// Unhook DXGI Present trampoline and restore original code bytes at the hook site.
pub fn unhook_dxgi_present() {
    if !HOOK_INSTALLED.swap(false, Ordering::SeqCst) {
        return;
    }

    let target = HOOK_TARGET_ADDR.swap(0, Ordering::SeqCst);
    let original = if let Ok(mut bytes) = ORIGINAL_BYTES.lock() {
        std::mem::take(&mut *bytes)
    } else {
        Vec::new()
    };

    if target != 0 && !original.is_empty() {
        super::log_render(format!(
            "unhook_dxgi_present: restoring {} original bytes at 0x{:X}",
            original.len(),
            target
        ));

        let mem = trainlab_core::memory::SelfProcess;
        let write = |addr: u64, data: &[u8]| -> Result<usize, String> {
            use trainlab_core::memory::ProcessMemory;
            mem.write(addr, data).map_err(|e| e.to_string())
        };

        if let Err(e) = trainlab_cave::cave::restore(target, &original, write) {
            super::log_render(format!(
                "unhook_dxgi_present: FAILED to restore original bytes at 0x{:X}: {e}",
                target
            ));
        } else {
            super::log_render(format!(
                "unhook_dxgi_present: successfully restored Present hook site at 0x{:X}",
                target
            ));
        }
    }

    ORIGINAL_PRESENT.store(std::ptr::null_mut(), Ordering::SeqCst);
    super::STATE.present_hooked.store(false, Ordering::SeqCst);
}
