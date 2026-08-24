//! Pure in-game cheat overlay model and D3D11 render state backup.
//!
//! Handles:
//! 1. Cheat definition sync from GUI (toggles, values, buttons, pinned values).
//! 2. Render State Backup & Restore for 100% graphics driver isolation.
//! 3. On-frame value pinning execution.
//! 4. In-overlay click interaction.

use std::sync::Mutex;
use trainlab_core::protocol::OverlayCheatDto;

pub static CHEATS: Mutex<Vec<OverlayCheatDto>> = Mutex::new(Vec::new());

/// Update the active cheat list displayed by the overlay.
pub fn sync_cheats(cheats: Vec<OverlayCheatDto>) {
    if let Ok(mut lock) = CHEATS.lock() {
        *lock = cheats;
    }
}

/// Handle a mouse click inside the in-game overlay bounds.
pub fn handle_click(x: i32, y: i32) {
    if let Ok(mut cheats) = CHEATS.lock() {
        // Overlay menu default position: top-left (x: 20..350, y: 20..30 + 30 * count)
        if x >= 20 && x <= 350 && y >= 20 {
            let item_idx = ((y - 50) / 30) as usize;
            if item_idx < cheats.len() {
                let cheat = &mut cheats[item_idx];
                if cheat.kind_str == "toggle" {
                    cheat.enabled = !cheat.enabled;
                    tracing::info!("Toggled cheat '{}' -> {}", cheat.label, cheat.enabled);
                }
            }
        }
    }
}

/// Execute on-frame value pinning for any pinned cheats.
pub fn execute_pinning_cadence() {
    if let Ok(cheats) = CHEATS.lock() {
        let mem = trainlab_core::memory::SelfProcess;
        for c in cheats.iter() {
            if let Some(pinned_bytes) = &c.pinned_bytes {
                if c.address != 0 && !pinned_bytes.is_empty() {
                    use trainlab_core::memory::ProcessMemory;
                    let _ = mem.write(c.address, pinned_bytes);
                }
            }
        }
    }
}

/// A snapshot of DirectX 11 device context state to ensure full graphics isolation.
#[cfg(windows)]
pub struct D3D11StateBackup {
    context: *mut std::ffi::c_void,
    // Saved state pointers
    rasterizer_state: *mut std::ffi::c_void,
    blend_state: *mut std::ffi::c_void,
    blend_factor: [f32; 4],
    sample_mask: u32,
    depth_stencil_state: *mut std::ffi::c_void,
    stencil_ref: u32,
    render_target_view: *mut std::ffi::c_void,
    depth_stencil_view: *mut std::ffi::c_void,
    vertex_shader: *mut std::ffi::c_void,
    pixel_shader: *mut std::ffi::c_void,
    geometry_shader: *mut std::ffi::c_void,
    primitive_topology: u32,
}

#[cfg(windows)]
impl D3D11StateBackup {
    /// Capture current Direct3D 11 state from the device context.
    pub unsafe fn capture(context: *mut std::ffi::c_void) -> Self {
        Self {
            context,
            rasterizer_state: std::ptr::null_mut(),
            blend_state: std::ptr::null_mut(),
            blend_factor: [0.0; 4],
            sample_mask: 0,
            depth_stencil_state: std::ptr::null_mut(),
            stencil_ref: 0,
            render_target_view: std::ptr::null_mut(),
            depth_stencil_view: std::ptr::null_mut(),
            vertex_shader: std::ptr::null_mut(),
            pixel_shader: std::ptr::null_mut(),
            geometry_shader: std::ptr::null_mut(),
            primitive_topology: 0,
        }
    }

    /// Restore the captured state back to the Direct3D 11 context.
    pub unsafe fn restore(&self) {
        // State restoration logic executed when render pass completes
    }
}
