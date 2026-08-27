//! Optional XInput controller polling for standalone `trainlab-gui`.
//! Translates controller bumpers and stick navigation into GUI tab and focus actions
//! ONLY when the standalone window is focused.

use std::sync::atomic::AtomicBool;

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct XINPUT_GAMEPAD {
    pub w_buttons: u16,
    pub b_left_trigger: u8,
    pub b_right_trigger: u8,
    pub s_thumb_lx: i16,
    pub s_thumb_ly: i16,
    pub s_thumb_rx: i16,
    pub s_thumb_ry: i16,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct XINPUT_STATE {
    pub dw_packet_number: u32,
    pub gamepad: XINPUT_GAMEPAD,
}

type FnXInputGetState = unsafe extern "system" fn(u32, *mut XINPUT_STATE) -> u32;

pub const XINPUT_GAMEPAD_DPAD_UP: u16 = 0x0001;
pub const XINPUT_GAMEPAD_DPAD_DOWN: u16 = 0x0002;
pub const XINPUT_GAMEPAD_DPAD_LEFT: u16 = 0x0004;
pub const XINPUT_GAMEPAD_DPAD_RIGHT: u16 = 0x0008;
pub const XINPUT_GAMEPAD_LEFT_SHOULDER: u16 = 0x0100;
pub const XINPUT_GAMEPAD_RIGHT_SHOULDER: u16 = 0x0200;
pub const XINPUT_GAMEPAD_A: u16 = 0x1000;
pub const XINPUT_GAMEPAD_B: u16 = 0x2000;

static PREV_BUTTONS: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);
static STICK_TRIGGERED_Y: AtomicBool = AtomicBool::new(false);

#[derive(Default, Debug)]
pub struct ControllerAction {
    pub tab_prev: bool,
    pub tab_next: bool,
    pub move_up: bool,
    pub move_down: bool,
    pub select_action: bool,
    pub back_action: bool,
}

/// Poll XInput controller 0 and return debounced single-action triggers.
pub fn poll_controller() -> Option<ControllerAction> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
        static GET_STATE_PTR: std::sync::OnceLock<Option<FnXInputGetState>> = std::sync::OnceLock::new();

        let get_state = GET_STATE_PTR.get_or_init(|| {
            unsafe {
                let dll = LoadLibraryA(b"xinput1_4.dll\0".as_ptr());
                let dll = if dll.is_null() {
                    LoadLibraryA(b"xinput1_3.dll\0".as_ptr())
                } else {
                    dll
                };
                if !dll.is_null() {
                    let proc = GetProcAddress(dll, b"XInputGetState\0".as_ptr());
                    if let Some(p) = proc {
                        return Some(std::mem::transmute(p));
                    }
                }
                None
            }
        });

        if let Some(func) = get_state {
            let mut state = XINPUT_STATE::default();
            let ret = unsafe { func(0, &mut state) };
            if ret == 0 {
                let buttons = state.gamepad.w_buttons;
                let prev = PREV_BUTTONS.swap(buttons, Ordering::Relaxed);
                let just_pressed = buttons & !prev;

                // Stick debouncing
                let thumb_ly = state.gamepad.s_thumb_ly;
                let stick_up = thumb_ly > 22000;
                let stick_down = thumb_ly < -22000;
                let stick_neutral_y = thumb_ly.abs() < 12000;

                let mut move_up = (just_pressed & XINPUT_GAMEPAD_DPAD_UP) != 0;
                let mut move_down = (just_pressed & XINPUT_GAMEPAD_DPAD_DOWN) != 0;

                if stick_neutral_y {
                    STICK_TRIGGERED_Y.store(false, Ordering::Relaxed);
                } else if !STICK_TRIGGERED_Y.load(Ordering::Relaxed) {
                    if stick_up {
                        move_up = true;
                        STICK_TRIGGERED_Y.store(true, Ordering::Relaxed);
                    } else if stick_down {
                        move_down = true;
                        STICK_TRIGGERED_Y.store(true, Ordering::Relaxed);
                    }
                }

                let tab_prev = (just_pressed & XINPUT_GAMEPAD_LEFT_SHOULDER) != 0;
                let tab_next = (just_pressed & XINPUT_GAMEPAD_RIGHT_SHOULDER) != 0;
                let select_action = (just_pressed & XINPUT_GAMEPAD_A) != 0;
                let back_action = (just_pressed & XINPUT_GAMEPAD_B) != 0;

                if tab_prev || tab_next || move_up || move_down || select_action || back_action {
                    return Some(ControllerAction {
                        tab_prev,
                        tab_next,
                        move_up,
                        move_down,
                        select_action,
                        back_action,
                    });
                }
            }
        }
    }
    None
}
