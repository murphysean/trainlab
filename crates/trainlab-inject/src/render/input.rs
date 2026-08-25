//! Window message procedure (WndProc) interception for hotkeys and mouse/keyboard input capture.

use std::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, Ordering};
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::VK_INSERT;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CallWindowProcA, DefWindowProcA, SetWindowLongPtrA, GWLP_WNDPROC,
    WM_CHAR, WM_KEYDOWN, WM_KEYUP, WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MOUSEMOVE,
    WM_RBUTTONDOWN, WM_RBUTTONUP, WM_SYSKEYDOWN, WM_SYSKEYUP,
};

static ORIGINAL_WNDPROC: AtomicPtr<std::ffi::c_void> = AtomicPtr::new(std::ptr::null_mut());
static HOOKED_HWND: AtomicPtr<std::ffi::c_void> = AtomicPtr::new(std::ptr::null_mut());

// Window message constants
const WM_INPUT: u32 = 0x00FF;

// Shared atomic mouse state for egui
pub static MOUSE_X: AtomicI32 = AtomicI32::new(0);
pub static MOUSE_Y: AtomicI32 = AtomicI32::new(0);
pub static MOUSE_DOWN: AtomicBool = AtomicBool::new(false);

/// Safe WndProc hook callback.
pub unsafe extern "system" fn hooked_wndproc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    // 1. Check for Overlay Toggle Hotkey (INSERT key, F11, or Select/Back raw scan)
    if msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN {
        if wparam == VK_INSERT as usize || wparam == 0x7A /* VK_F11 */ {
            super::toggle_overlay();
            let count = super::STATE.combo_press_count.fetch_add(1, Ordering::Relaxed) + 1;
            let visible = super::STATE.overlay_visible.load(Ordering::Relaxed);
            tracing::info!("Overlay visibility toggled by key 0x{:X} (#{count}): {}", wparam, visible);
            return 0; // Consume the keypress
        }
    }

    // 2. Intercept RawInput (WM_INPUT) for gamepad / HID controller packets
    if msg == WM_INPUT {
        // Raw input delivery (e.g. mouse / joystick motion packets)
    }

    let overlay_active = super::STATE.overlay_visible.load(Ordering::Relaxed);

    // 2. Track mouse position & clicks for egui
    match msg {
        WM_MOUSEMOVE => {
            let x = (lparam & 0xFFFF) as i16 as f32;
            let y = ((lparam >> 16) & 0xFFFF) as i16 as f32;
            if overlay_active {
                super::overlay::push_pointer_event(x, y, None);
            }
        }
        WM_LBUTTONDOWN => {
            let x = (lparam & 0xFFFF) as i16 as f32;
            let y = ((lparam >> 16) & 0xFFFF) as i16 as f32;
            if overlay_active {
                super::overlay::push_pointer_event(x, y, Some(true));
                super::overlay::handle_click(x as i32, y as i32);
                return 0; // Block game from receiving the click
            }
        }
        WM_LBUTTONUP => {
            let x = (lparam & 0xFFFF) as i16 as f32;
            let y = ((lparam >> 16) & 0xFFFF) as i16 as f32;
            if overlay_active {
                super::overlay::push_pointer_event(x, y, Some(false));
                return 0;
            }
        }
        WM_RBUTTONDOWN | WM_RBUTTONUP => {
            if overlay_active {
                return 0;
            }
        }
        WM_CHAR | WM_KEYUP => {
            if overlay_active {
                // Keep game from receiving typing while overlay is active
            }
        }
        _ => {}
    }

    let orig = ORIGINAL_WNDPROC.load(Ordering::Relaxed);
    if !orig.is_null() {
        let orig_fn: unsafe extern "system" fn(HWND, u32, WPARAM, LPARAM) -> LRESULT =
            unsafe { std::mem::transmute(orig) };
        unsafe { CallWindowProcA(Some(orig_fn), hwnd, msg, wparam, lparam) }
    } else {
        unsafe { DefWindowProcA(hwnd, msg, wparam, lparam) }
    }
}

/// Attach WndProc hook to the game's HWND.
pub fn install_wndproc_hook(hwnd: HWND) -> bool {
    if hwnd == std::ptr::null_mut() {
        return false;
    }

    let existing = HOOKED_HWND.load(Ordering::Relaxed);
    if existing == hwnd {
        return true; // Already hooked this window
    }

    unsafe {
        let prev = SetWindowLongPtrA(
            hwnd,
            GWLP_WNDPROC,
            hooked_wndproc as *const () as isize,
        );

        if prev != 0 {
            ORIGINAL_WNDPROC.store(prev as *mut std::ffi::c_void, Ordering::SeqCst);
            HOOKED_HWND.store(hwnd, Ordering::SeqCst);
            super::STATE.wndproc_hooked.store(true, Ordering::SeqCst);
            tracing::info!("Successfully hooked game WndProc on HWND {:?}", hwnd);
            true
        } else {
            tracing::warn!("Failed to hook WndProc on HWND {:?}", hwnd);
            false
        }
    }
}
