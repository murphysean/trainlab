//! Windows Win32 `RegisterHotKey` implementation for global trainer hotkeys.
//!
//! Provides parsing for hotkey strings (e.g., "Numpad 1", "Shift+Alt+K", "F1", "Ctrl+1"),
//! registration via `RegisterHotKey`, and unregistration via `UnregisterHotKey`.

#[cfg(target_os = "windows")]
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{RegisterHotKey, UnregisterHotKey};

/// Parsed hotkey representation: modifier bitmask and virtual key code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HotkeySpec {
    pub modifiers: u32,
    pub vk: u32,
}

impl HotkeySpec {
    /// Parse a hotkey string such as "Numpad 1", "Numpad1", "Shift+Alt+K", "Ctrl+F1", "F5".
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if s.is_empty() {
            return Err("empty hotkey string".into());
        }

        let mut modifiers: u32 = 0;
        let parts: Vec<&str> = s.split('+').map(|p| p.trim()).collect();

        let (mod_parts, key_part) = if parts.len() > 1 {
            (&parts[..parts.len() - 1], parts[parts.len() - 1])
        } else {
            (&[][..], parts[0])
        };

        for m in mod_parts {
            match m.to_lowercase().as_str() {
                "ctrl" | "control" => modifiers |= 0x0002, // MOD_CONTROL
                "alt" => modifiers |= 0x0001,            // MOD_ALT
                "shift" => modifiers |= 0x0004,          // MOD_SHIFT
                "win" | "super" => modifiers |= 0x0008,   // MOD_WIN
                _ => return Err(format!("unknown modifier '{m}'")),
            }
        }

        let vk = parse_virtual_key(key_part)?;
        // Include MOD_NOREPEAT (0x4000) so holding down key doesn't spam WM_HOTKEY
        modifiers |= 0x4000;

        Ok(HotkeySpec { modifiers, vk })
    }

    /// Format back to human-readable string.
    pub fn display_string(&self) -> String {
        let mut parts = Vec::new();
        if (self.modifiers & 0x0002) != 0 {
            parts.push("Ctrl");
        }
        if (self.modifiers & 0x0001) != 0 {
            parts.push("Alt");
        }
        if (self.modifiers & 0x0004) != 0 {
            parts.push("Shift");
        }
        if (self.modifiers & 0x0008) != 0 {
            parts.push("Win");
        }
        parts.push(vk_to_name(self.vk));
        parts.join("+")
    }
}

fn parse_virtual_key(key: &str) -> Result<u32, String> {
    let normalized = key.to_lowercase().replace(' ', "");
    let vk = match normalized.as_str() {
        "numpad0" | "num0" => 0x60,
        "numpad1" | "num1" => 0x61,
        "numpad2" | "num2" => 0x62,
        "numpad3" | "num3" => 0x63,
        "numpad4" | "num4" => 0x64,
        "numpad5" | "num5" => 0x65,
        "numpad6" | "num6" => 0x66,
        "numpad7" | "num7" => 0x67,
        "numpad8" | "num8" => 0x68,
        "numpad9" | "num9" => 0x69,
        "numpadmultiply" | "num*" => 0x6A,
        "numpadadd" | "num+" => 0x6B,
        "numpadsubtract" | "num-" => 0x6D,
        "numpaddecimal" | "num." => 0x6E,
        "numpaddivide" | "num/" => 0x6F,
        "f1" => 0x70,
        "f2" => 0x71,
        "f3" => 0x72,
        "f4" => 0x73,
        "f5" => 0x74,
        "f6" => 0x75,
        "f7" => 0x76,
        "f8" => 0x77,
        "f9" => 0x78,
        "f10" => 0x79,
        "f11" => 0x7A,
        "f12" => 0x7B,
        "[" | "leftbracket" | "lbrack" => 0xDB, // VK_OEM_4
        "`" | "~" | "tilde" | "backtick" => 0xC0, // VK_OEM_3
        s if s.len() == 1 => {
            let ch = s.chars().next().unwrap();
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_uppercase() as u32
            } else {
                return Err(format!("unsupported key character '{ch}'"));
            }
        }
        _ => return Err(format!("unknown key '{key}'")),
    };
    Ok(vk)
}

fn vk_to_name(vk: u32) -> &'static str {
    match vk {
        0xDB => "[",
        0xC0 => "~",
        0x60 => "Num 0",
        0x61 => "Num 1",
        0x62 => "Num 2",
        0x63 => "Num 3",
        0x64 => "Num 4",
        0x65 => "Num 5",
        0x66 => "Num 6",
        0x67 => "Num 7",
        0x68 => "Num 8",
        0x69 => "Num 9",
        0x6A => "Num *",
        0x6B => "Num +",
        0x6D => "Num -",
        0x6E => "Num .",
        0x6F => "Num /",
        0x70 => "F1",
        0x71 => "F2",
        0x72 => "F3",
        0x73 => "F4",
        0x74 => "F5",
        0x75 => "F6",
        0x76 => "F7",
        0x77 => "F8",
        0x78 => "F9",
        0x79 => "F10",
        0x7A => "F11",
        0x7B => "F12",
        0x41..=0x5A => {
            const CHARS: [&str; 26] = [
                "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P",
                "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z",
            ];
            CHARS[(vk - 0x41) as usize]
        }
        0x30..=0x39 => {
            const DIGITS: [&str; 10] = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"];
            DIGITS[(vk - 0x30) as usize]
        }
        _ => "Unknown",
    }
}

/// Register a global hotkey with Win32 `RegisterHotKey`.
#[cfg(target_os = "windows")]
pub fn register_hotkey(hwnd: isize, id: i32, spec: HotkeySpec) -> Result<(), String> {
    let res = unsafe {
        RegisterHotKey(
            hwnd as _,
            id,
            spec.modifiers,
            spec.vk,
        )
    };
    if res != 0 {
        Ok(())
    } else {
        Err(format!(
            "RegisterHotKey failed for id {id} ({})",
            spec.display_string()
        ))
    }
}

/// Unregister a global hotkey with Win32 `UnregisterHotKey`.
#[cfg(target_os = "windows")]
pub fn unregister_hotkey(hwnd: isize, id: i32) {
    unsafe {
        UnregisterHotKey(hwnd as _, id);
    }
}

/// Poll the Win32 thread message queue for WM_HOTKEY events.
#[cfg(target_os = "windows")]
pub fn poll_wm_hotkey() -> Option<i32> {
    use windows_sys::Win32::UI::WindowsAndMessaging::{PeekMessageW, PM_REMOVE, WM_HOTKEY};
    unsafe {
        let mut msg: windows_sys::Win32::UI::WindowsAndMessaging::MSG = std::mem::zeroed();
        if PeekMessageW(&mut msg, std::ptr::null_mut(), WM_HOTKEY, WM_HOTKEY, PM_REMOVE) != 0 {
            return Some(msg.wParam as i32);
        }
    }
    None
}

#[cfg(not(target_os = "windows"))]
pub fn register_hotkey(_hwnd: isize, _id: i32, _spec: HotkeySpec) -> Result<(), String> {
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn unregister_hotkey(_hwnd: isize, _id: i32) {}

#[cfg(not(target_os = "windows"))]
pub fn poll_wm_hotkey() -> Option<i32> {
    None
}
