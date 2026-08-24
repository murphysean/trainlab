//! Window message procedure (WndProc) interception for hotkeys and mouse/keyboard input capture.

use std::sync::atomic::{AtomicPtr, Ordering};
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::VK_INSERT;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CallWindowProcA, DefWindowProcA, SetWindowLongPtrA, GWLP_WNDPROC,
    WM_KEYDOWN, WM_SYSKEYDOWN,
};

static ORIGINAL_WNDPROC: AtomicPtr<std::ffi::c_void> = AtomicPtr::new(std::ptr::null_mut());
static HOOKED_HWND: AtomicPtr<std::ffi::c_void> = AtomicPtr::new(std::ptr::null_mut());

/// Safe WndProc hook callback.
pub unsafe extern "system" fn hooked_wndproc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    // Check for Overlay Toggle Hotkey (e.g. INSERT key)
    if msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN {
        if wparam == VK_INSERT as usize {
            super::toggle_overlay();
            let visible = super::STATE.overlay_visible.load(Ordering::Relaxed);
            tracing::info!("Overlay visibility toggled: {}", visible);
        }
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
