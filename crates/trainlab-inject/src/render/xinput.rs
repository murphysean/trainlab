//! XInput Controller interception for gamepad hotkeys (e.g. Select + Start / Back + Start).
//!
//! Hooks `XInputGetState` across `xinput1_4.dll`, `xinput1_3.dll`, and `xinput9_1_0.dll`
//! to detect controller combinations and toggle the in-game cheat overlay.

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::time::Duration;

use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct XINPUT_GAMEPAD {
    pub wButtons: u16,
    pub bLeftTrigger: u8,
    pub bRightTrigger: u8,
    pub sThumbLX: i16,
    pub sThumbLY: i16,
    pub sThumbRX: i16,
    pub sThumbRY: i16,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct XINPUT_STATE {
    pub dwPacketNumber: u32,
    pub Gamepad: XINPUT_GAMEPAD,
}

// Button bitmasks
pub const XINPUT_GAMEPAD_BACK: u16 = 0x0020;        // Select / View / Back
pub const XINPUT_GAMEPAD_START: u16 = 0x0010;       // Start / Menu
pub const XINPUT_GAMEPAD_LEFT_THUMB: u16 = 0x0040;  // L3 (Left Stick Click)
pub const XINPUT_GAMEPAD_RIGHT_THUMB: u16 = 0x0080; // R3 (Right Stick Click)

type FnXInputGetState = unsafe extern "system" fn(u32, *mut XINPUT_STATE) -> u32;

static ORIGINAL_XINPUT_GET_STATE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static COMBO_WAS_DOWN: AtomicBool = AtomicBool::new(false);

/// Hooked `XInputGetState` callback.
pub unsafe extern "system" fn hooked_xinput_get_state(
    user_index: u32,
    state: *mut XINPUT_STATE,
) -> u32 {
    let orig = ORIGINAL_XINPUT_GET_STATE.load(Ordering::Relaxed);
    let ret = if !orig.is_null() {
        let orig_fn: FnXInputGetState = unsafe { std::mem::transmute(orig) };
        unsafe { orig_fn(user_index, state) }
    } else {
        0
    };

    if ret == 0 && !state.is_null() {
        let buttons = unsafe { (*state).Gamepad.wButtons };
        let back_start = (buttons & (XINPUT_GAMEPAD_BACK | XINPUT_GAMEPAD_START))
            == (XINPUT_GAMEPAD_BACK | XINPUT_GAMEPAD_START);
        let sticks = (buttons & (XINPUT_GAMEPAD_LEFT_THUMB | XINPUT_GAMEPAD_RIGHT_THUMB))
            == (XINPUT_GAMEPAD_LEFT_THUMB | XINPUT_GAMEPAD_RIGHT_THUMB);

        if back_start || sticks {
            if !COMBO_WAS_DOWN.swap(true, Ordering::Relaxed) {
                // Combo just pressed: Toggle overlay!
                let count = super::STATE.combo_press_count.fetch_add(1, Ordering::Relaxed) + 1;
                super::toggle_overlay();
                let visible = super::STATE.overlay_visible.load(Ordering::Relaxed);
                tracing::info!("🎮 Controller combo #{count} toggled overlay: {visible}");

                // Write directly to in-game inject log file for verification
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open("trainlab_inject.log")
                {
                    use std::io::Write;
                    let _ = writeln!(f, "[COMBO] #{count} (back_start={back_start}, sticks={sticks}) -> overlay_visible={visible}");
                }
            }
        } else {
            COMBO_WAS_DOWN.store(false, Ordering::Relaxed);
        }
    }

    ret
}

static ACTIVE_INPUT_HOOK: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());

/// Get the active input hook subsystem description.
pub fn get_active_input_hook() -> String {
    let name = ACTIVE_INPUT_HOOK.lock().map(|s| s.clone()).unwrap_or_default();
    if name.is_empty() {
        "RawInput / Keyboard (Insert)".to_string()
    } else {
        name
    }
}

// SDL2 Controller Button Constants
const SDL_CONTROLLER_BUTTON_BACK: i32 = 4;
const SDL_CONTROLLER_BUTTON_START: i32 = 6;

static ORIGINAL_SDL_GET_BUTTON: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

/// Hooked `SDL_GameControllerGetButton` callback.
pub unsafe extern "C" fn hooked_sdl_get_button(
    controller: *mut c_void,
    button: i32,
) -> u8 {
    let orig = ORIGINAL_SDL_GET_BUTTON.load(Ordering::Relaxed);
    let ret = if !orig.is_null() {
        let orig_fn: unsafe extern "C" fn(*mut c_void, i32) -> u8 = unsafe { std::mem::transmute(orig) };
        unsafe { orig_fn(controller, button) }
    } else {
        0
    };

    // If back/start is polled, check if both are down
    if (button == SDL_CONTROLLER_BUTTON_BACK || button == SDL_CONTROLLER_BUTTON_START) && !orig.is_null() {
        let orig_fn: unsafe extern "C" fn(*mut c_void, i32) -> u8 = unsafe { std::mem::transmute(orig) };
        let back_down = unsafe { orig_fn(controller, SDL_CONTROLLER_BUTTON_BACK) } != 0;
        let start_down = unsafe { orig_fn(controller, SDL_CONTROLLER_BUTTON_START) } != 0;

        if back_down && start_down {
            if !COMBO_WAS_DOWN.swap(true, Ordering::Relaxed) {
                super::toggle_overlay();
                let visible = super::STATE.overlay_visible.load(Ordering::Relaxed);
                tracing::info!("🎮 SDL2 Controller combo (Select + Start) toggled overlay: {}", visible);
            }
            return 0; // Consume button so game menu doesn't trigger
        } else {
            COMBO_WAS_DOWN.store(false, Ordering::Relaxed);
        }
    }

    ret
}

/// Initialize XInput, SDL2, and RawInput hooking cascade in a background retry loop.
pub fn init_xinput_hook() {
    std::thread::sleep(Duration::from_millis(300));

    for _ in 0..10 {
        if !ORIGINAL_XINPUT_GET_STATE.load(Ordering::SeqCst).is_null()
            || !ORIGINAL_SDL_GET_BUTTON.load(Ordering::SeqCst).is_null() {
            break;
        }

        unsafe {
            // Tier 1: Try SDL2 Game Controller hook
            let sdl2_dll = GetModuleHandleA(b"SDL2.dll\0".as_ptr());
            if !sdl2_dll.is_null() {
                let fn_ptr = GetProcAddress(sdl2_dll, b"SDL_GameControllerGetButton\0".as_ptr());
                if let Some(target_fn) = fn_ptr {
                    let target_u64 = target_fn as u64;
                    let callback_addr = hooked_sdl_get_button as *const () as u64;
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

                    if let Ok(installed) = trainlab_cave::cave::install(target_u64, hook, read, write, allocate) {
                        ORIGINAL_SDL_GET_BUTTON.store((installed.cave_addr + 14) as *mut c_void, Ordering::SeqCst);
                        if let Ok(mut lock) = ACTIVE_INPUT_HOOK.lock() {
                            *lock = "SDL2 GameController".to_string();
                        }
                        tracing::info!("Successfully hooked SDL2 GameController (Select + Start) at 0x{:X}", target_u64);
                        break;
                    }
                }
            }

            // Tier 2: Try XInput hooks (ONLY if naturally loaded by the game binary)
            let xinput_dlls = [
                b"xinput1_4.dll\0".as_ptr(),
                b"xinput1_3.dll\0".as_ptr(),
                b"xinput9_1_0.dll\0".as_ptr(),
            ];

            for dll_name in xinput_dlls {
                let hmod = GetModuleHandleA(dll_name);
                if !hmod.is_null() {
                    let fn_ptr = GetProcAddress(hmod, b"XInputGetState\0".as_ptr());
                    if let Some(target_fn) = fn_ptr {
                        let target_u64 = target_fn as u64;
                        let callback_addr = hooked_xinput_get_state as *const () as u64;
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
                                ORIGINAL_XINPUT_GET_STATE.store(
                                    (installed.cave_addr + 14) as *mut c_void,
                                    Ordering::SeqCst,
                                );
                                if let Ok(mut lock) = ACTIVE_INPUT_HOOK.lock() {
                                    *lock = "XInput (Select + Start)".to_string();
                                }
                                tracing::info!(
                                    "Successfully hooked XInputGetState at 0x{:X} for Select + Start toggle",
                                    target_u64
                                );
                                break;
                            }
                            Err(err) => {
                                tracing::warn!("Failed to hook XInputGetState at 0x{:X}: {:?}", target_u64, err);
                            }
                        }
                    }
                }
            }

            // Tier 3: DirectInput8 / RawInput fallback
            let dinput_dll = GetModuleHandleA(b"dinput8.dll\0".as_ptr());
            if !dinput_dll.is_null() {
                if let Ok(mut lock) = ACTIVE_INPUT_HOOK.lock() {
                    if lock.is_empty() {
                        *lock = "DirectInput8 / RawInput".to_string();
                    }
                }
            }
        }

        std::thread::sleep(Duration::from_millis(500));
    }
}
