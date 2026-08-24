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
    *mut c_void,        // pAdapter
    u32,                // DriverType (D3D_DRIVER_TYPE_HARDWARE = 1)
    *mut c_void,        // Software
    u32,                // Flags
    *const u32,         // pFeatureLevels
    u32,                // FeatureLevels
    u32,                // SDKVersion (7)
    *const DXGI_SWAP_CHAIN_DESC,
    *mut *mut c_void,   // ppSwapChain
    *mut *mut c_void,   // ppDevice
    *mut u32,           // pFeatureLevel
    *mut *mut c_void,   // ppImmediateContext
) -> i32;

static ORIGINAL_PRESENT: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static HOOK_INSTALLED: AtomicBool = AtomicBool::new(false);
static HWND_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Our hooked `IDXGISwapChain::Present` callback.
pub unsafe extern "system" fn hooked_present(
    swapchain: *mut c_void,
    sync_interval: u32,
    flags: u32,
) -> i32 {
    // 1. Increment live frame counter
    super::STATE.frame_count.fetch_add(1, Ordering::Relaxed);

    // 2. On the first few frames, extract the game's actual HWND from swapchain description
    if !HWND_INITIALIZED.load(Ordering::Relaxed) && !swapchain.is_null() {
        let mut desc: DXGI_SWAP_CHAIN_DESC = unsafe { std::mem::zeroed() };
        let vtable = unsafe { *(swapchain as *mut *mut usize) };
        // GetDesc is VMT index 12 on IDXGISwapChain
        let get_desc_fn: unsafe extern "system" fn(*mut c_void, *mut DXGI_SWAP_CHAIN_DESC) -> i32 =
            unsafe { std::mem::transmute(*vtable.add(12)) };

        if unsafe { get_desc_fn(swapchain, &mut desc) } == 0 && desc.output_window != std::ptr::null_mut() {
            super::input::install_wndproc_hook(desc.output_window);
            HWND_INITIALIZED.store(true, Ordering::Relaxed);
        }
    }

    // 3. Call original Present trampoline
    let orig = ORIGINAL_PRESENT.load(Ordering::Relaxed);
    if !orig.is_null() {
        let orig_fn: FnPresent = unsafe { std::mem::transmute(orig) };
        unsafe { orig_fn(swapchain, sync_interval, flags) }
    } else {
        0
    }
}

/// Creates a dummy window and D3D11 swapchain to discover the VMT pointer for `Present`.
unsafe fn find_dxgi_present_vmt() -> Option<*mut usize> {
    let d3d11_dll = unsafe { LoadLibraryA(b"d3d11.dll\0".as_ptr()) };
    if d3d11_dll == std::ptr::null_mut() {
        return None;
    }

    let create_fn_ptr = unsafe { GetProcAddress(d3d11_dll, b"D3D11CreateDeviceAndSwapChain\0".as_ptr()) };
    if create_fn_ptr.is_none() {
        return None;
    }

    let d3d11_create: FnD3D11CreateDeviceAndSwapChain = unsafe { std::mem::transmute(create_fn_ptr) };

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

    unsafe { windows_sys::Win32::UI::WindowsAndMessaging::RegisterClassA(&wnd_class) };

    let hwnd = unsafe {
        CreateWindowExA(
            0,
            class_name.as_ptr(),
            b"TrainlabDummyWindow\0".as_ptr(),
            WS_OVERLAPPEDWINDOW,
            0,
            0,
            100,
            100,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null(),
        )
    };

    if hwnd == std::ptr::null_mut() {
        return None;
    }

    let mut swap_desc: DXGI_SWAP_CHAIN_DESC = unsafe { std::mem::zeroed() };
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

    let feature_levels = [0xb000u32]; // D3D_FEATURE_LEVEL_11_0 = 0xb000
    const D3D_DRIVER_TYPE_HARDWARE: u32 = 1;
    const D3D11_SDK_VERSION: u32 = 7;

    let hr = unsafe {
        d3d11_create(
            std::ptr::null_mut(),
            D3D_DRIVER_TYPE_HARDWARE,
            std::ptr::null_mut(),
            0,
            feature_levels.as_ptr(),
            1,
            D3D11_SDK_VERSION,
            &swap_desc,
            &mut swapchain,
            &mut device,
            &mut feature_level,
            &mut context,
        )
    };

    let mut present_addr = None;

    if hr == 0 && !swapchain.is_null() {
        let vtable = unsafe { *(swapchain as *mut *mut usize) };
        // Index 8 is IDXGISwapChain::Present
        let present_ptr = unsafe { *vtable.add(8) };
        present_addr = Some(present_ptr as *mut usize);

        // Release dummy COM objects
        let release_fn = |com_ptr: *mut usize| {
            if !com_ptr.is_null() {
                let vtable = unsafe { *(com_ptr as *mut *mut usize) };
                let release: unsafe extern "system" fn(*mut usize) -> u32 =
                    unsafe { std::mem::transmute(*vtable.add(2)) };
                unsafe { release(com_ptr) };
            }
        };

        release_fn(swapchain as *mut usize);
        release_fn(device as *mut usize);
        release_fn(context as *mut usize);
    }

    unsafe {
        DestroyWindow(hwnd);
        UnregisterClassA(class_name.as_ptr(), std::ptr::null_mut());
    }

    present_addr
}

/// Initialize the DXGI hook in a background retry loop.
pub fn init_dxgi_hook() {
    // Wait briefly if third-party hooks (Steam / OBS / Discord) are initializing
    std::thread::sleep(Duration::from_millis(500));

    // Try finding DXGI Present
    for _ in 0..10 {
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
                if let Some(target_present) = find_dxgi_present_vmt() {
                    let target_u64 = target_present as u64;

                    // Payload is a jump to hooked_present
                    let callback_addr = hooked_present as *const () as u64;
                    let payload = trainlab_cave::emitter::jmp_abs(callback_addr);

                    let hook = trainlab_cave::cave::HookKind::Trampoline {
                        payload,
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

                    match trainlab_cave::cave::install(
                        target_u64,
                        hook,
                        read,
                        write,
                        allocate,
                    ) {
                        Ok(installed) => {
                            // Point original present to the trampoline / cave return path
                            // (installed.cave_addr + payload.len() is where stolen instructions & jump-back live)
                            ORIGINAL_PRESENT.store(
                                (installed.cave_addr + 14) as *mut c_void,
                                Ordering::SeqCst,
                            );
                            HOOK_INSTALLED.store(true, Ordering::SeqCst);
                            super::STATE.present_hooked.store(true, Ordering::SeqCst);

                            let api_name = if d3d12_mod != std::ptr::null_mut() {
                                "DXGI (Direct3D 12)"
                            } else {
                                "DXGI (Direct3D 11)"
                            };

                            if let Ok(mut name_lock) = super::STATE.api_name.lock() {
                                *name_lock = api_name.to_string();
                            }

                            tracing::info!(
                                "Successfully hooked IDXGISwapChain::Present at 0x{:X} ({})",
                                target_u64,
                                api_name
                            );
                            break;
                        }
                        Err(err) => {
                            tracing::warn!("Failed to install Present hook at 0x{:X}: {:?}", target_u64, err);
                        }
                    }
                }
            }
        }

        std::thread::sleep(Duration::from_millis(1000));
    }
}
