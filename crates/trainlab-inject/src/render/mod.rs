//! In-game render loop hooking and overlay runtime.
//!
//! Detects active graphics runtimes (DXGI/Direct3D 11/12, Direct3D 9, OpenGL),
//! hooks frame presentation (`Present` / `EndScene`), and hooks window messages
//! (`WndProc`) for hotkeys and input capture.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

#[cfg(windows)]
mod dxgi;
#[cfg(windows)]
mod input;
#[cfg(windows)]
pub mod xinput;
pub mod overlay;

/// Global render and overlay state tracked in-process.
pub struct RenderState {
    pub api_name: Mutex<String>,
    pub present_hooked: AtomicBool,
    pub wndproc_hooked: AtomicBool,
    pub frame_count: AtomicU64,
    pub combo_press_count: AtomicU64,
    pub overlay_visible: AtomicBool,
    pub detected_overlays: Mutex<Vec<String>>,
}

impl Default for RenderState {
    fn default() -> Self {
        Self {
            api_name: Mutex::new("Unknown".into()),
            present_hooked: AtomicBool::new(false),
            wndproc_hooked: AtomicBool::new(false),
            frame_count: AtomicU64::new(0),
            combo_press_count: AtomicU64::new(0),
            overlay_visible: AtomicBool::new(false),
            detected_overlays: Mutex::new(Vec::new()),
        }
    }
}

pub static STATE: RenderState = RenderState {
    api_name: Mutex::new(String::new()),
    present_hooked: AtomicBool::new(false),
    wndproc_hooked: AtomicBool::new(false),
    frame_count: AtomicU64::new(0),
    combo_press_count: AtomicU64::new(0),
    overlay_visible: AtomicBool::new(false),
    detected_overlays: Mutex::new(Vec::new()),
};

/// Scan the process for known third-party capture / overlay DLLs to prevent collisions.
#[cfg(windows)]
pub fn detect_foreign_overlays() -> Vec<String> {
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;

    let overlays = [
        ("Steam Overlay", "gameoverlayrenderer64.dll\0"),
        ("OBS Studio Graphics Hook", "graphics-hook64.dll\0"),
        ("Discord Overlay", "discordhook64.dll\0"),
        ("RivaTuner / RTSS", "RTSSHooks64.dll\0"),
        ("RivaTuner / RTSS 32", "RTSSHooks.dll\0"),
        ("GeForce Experience / Shadowplay", "nvspcap64.dll\0"),
        ("AMD Radeon Capture", "amdfx64.dll\0"),
        ("Medal.tv Hook", "medal-hook64.dll\0"),
    ];

    let mut detected = Vec::new();
    for (name, dll) in overlays {
        unsafe {
            let handle = GetModuleHandleA(dll.as_ptr());
            if handle != std::ptr::null_mut() {
                detected.push(name.to_string());
            }
        }
    }
    detected
}

#[cfg(not(windows))]
pub fn detect_foreign_overlays() -> Vec<String> {
    Vec::new()
}

/// Initialize render detection and hook threads.
pub fn init() {
    #[cfg(windows)]
    {
        // Populate detected third-party overlays
        let foreign = detect_foreign_overlays();
        if !foreign.is_empty() {
            tracing::info!("Detected third-party overlays in game: {:?}", foreign);
            if let Ok(mut lock) = STATE.detected_overlays.lock() {
                *lock = foreign;
            }
        }

        // Spawn background thread to wait for game window & hook DXGI / D3D
        std::thread::spawn(|| {
            dxgi::init_dxgi_hook();
        });

        // Spawn background thread for controller combo hook (Select + Start)
        std::thread::spawn(|| {
            xinput::init_xinput_hook();
        });
    }
}

/// Returns a snapshot of the current render status for the protocol.
pub fn get_status() -> (String, bool, bool, u64, bool, String, u64, Vec<String>) {
    let api = STATE.api_name.lock().map(|s| s.clone()).unwrap_or_else(|_| "Unknown".into());
    let present_hooked = STATE.present_hooked.load(Ordering::Relaxed);
    let wndproc_hooked = STATE.wndproc_hooked.load(Ordering::Relaxed);
    let frame_count = STATE.frame_count.load(Ordering::Relaxed);
    let combo_count = STATE.combo_press_count.load(Ordering::Relaxed);
    let overlay_visible = STATE.overlay_visible.load(Ordering::Relaxed);
    let input_hook = xinput::get_active_input_hook();
    let overlays = STATE.detected_overlays.lock().map(|s| s.clone()).unwrap_or_default();

    (api, present_hooked, wndproc_hooked, frame_count, overlay_visible, input_hook, combo_count, overlays)
}

/// Set overlay visibility.
pub fn set_overlay_visible(visible: bool) {
    STATE.overlay_visible.store(visible, Ordering::Relaxed);
}

/// Toggle overlay visibility.
pub fn toggle_overlay() {
    let current = STATE.overlay_visible.load(Ordering::Relaxed);
    STATE.overlay_visible.store(!current, Ordering::Relaxed);
}
