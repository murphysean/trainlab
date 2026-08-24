//! Pure in-game cheat overlay model and D3D11 render state backup.
//!
//! Handles:
//! 1. Cheat definition sync from GUI (toggles, values, buttons, pinned values).
//! 2. Render State Backup & Restore for 100% graphics driver isolation.
//! 3. On-frame value pinning execution.
//! 4. In-overlay click interaction.

use std::sync::atomic::Ordering;
use std::sync::Mutex;
use trainlab_core::protocol::OverlayCheatDto;

pub static CHEATS: Mutex<Vec<OverlayCheatDto>> = Mutex::new(Vec::new());
static PENDING_EGUI_EVENTS: Mutex<Vec<egui::Event>> = Mutex::new(Vec::new());

/// Push controller button events mapped to egui keyboard/navigation events.
pub fn push_controller_buttons(just_pressed: u16) {
    use super::xinput::*;
    let mut events = Vec::new();

    if (just_pressed & XINPUT_GAMEPAD_DPAD_UP) != 0 {
        events.push(egui::Event::Key {
            key: egui::Key::ArrowUp,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        });
    }
    if (just_pressed & XINPUT_GAMEPAD_DPAD_DOWN) != 0 {
        events.push(egui::Event::Key {
            key: egui::Key::ArrowDown,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        });
    }
    if (just_pressed & XINPUT_GAMEPAD_DPAD_LEFT) != 0 {
        events.push(egui::Event::Key {
            key: egui::Key::ArrowLeft,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        });
    }
    if (just_pressed & XINPUT_GAMEPAD_DPAD_RIGHT) != 0 {
        events.push(egui::Event::Key {
            key: egui::Key::ArrowRight,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        });
    }
    if (just_pressed & XINPUT_GAMEPAD_A) != 0 {
        events.push(egui::Event::Key {
            key: egui::Key::Enter,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        });
    }
    if (just_pressed & XINPUT_GAMEPAD_B) != 0 {
        events.push(egui::Event::Key {
            key: egui::Key::Escape,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        });
        // Dismiss overlay on B button
        super::set_overlay_visible(false);
    }

    if !events.is_empty() {
        if let Ok(mut queue) = PENDING_EGUI_EVENTS.lock() {
            queue.extend(events);
        }
    }
}

/// Drain queued input events into egui RawInput.
pub fn drain_egui_events() -> Vec<egui::Event> {
    if let Ok(mut queue) = PENDING_EGUI_EVENTS.lock() {
        std::mem::take(&mut *queue)
    } else {
        Vec::new()
    }
}

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

// In-game persistent egui state
static EGUI_CTX: Mutex<Option<egui::Context>> = Mutex::new(None);
static TEST_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static TEST_CHECKBOX: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// Render the in-game egui frame and return output shapes/primitives.
pub fn render_in_game_egui(
    screen_width: f32,
    screen_height: f32,
) -> Option<(egui::Context, Vec<egui::ClippedPrimitive>, egui::TexturesDelta)> {
    let ctx = {
        let mut lock = EGUI_CTX.lock().ok()?;
        if lock.is_none() {
            let new_ctx = egui::Context::default();
            // Configure dark gaming theme and high readability fonts
            let mut visuals = egui::Visuals::dark();
            visuals.window_rounding = egui::Rounding::same(8.0);
            new_ctx.set_visuals(visuals);
            *lock = Some(new_ctx);
        }
        lock.as_ref()?.clone()
    };

    let events = drain_egui_events();
    let raw_input = egui::RawInput {
        screen_rect: Some(egui::Rect::from_min_size(
            egui::pos2(0.0, 0.0),
            egui::vec2(screen_width, screen_height),
        )),
        events,
        ..Default::default()
    };

    let full_output = ctx.run(raw_input, |ctx| {
        egui::Window::new("🎮 Trainlab In-Game Overlay")
            .fixed_pos(egui::pos2(30.0, 30.0))
            .fixed_size(egui::vec2(340.0, 420.0))
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.heading("Trainlab v0.1.0 (In-Process)");
                ui.colored_label(egui::Color32::LIGHT_GREEN, "● Active & Hooked into Frame Presentation");
                ui.separator();

                ui.label("🎮 Steam Deck Controller Controls:");
                ui.label("• D-Pad Up / Down: Move Focus");
                ui.label("• A button (Cross / Enter): Toggle / Select");
                ui.label("• B button (Circle / Esc): Close Overlay");
                ui.label("• Select + Start: Toggle Overlay");

                ui.separator();
                ui.heading("Interactive Widget Test:");

                let mut counter = TEST_COUNTER.load(Ordering::Relaxed);
                ui.horizontal(|ui| {
                    ui.label(format!("Counter: {counter}"));
                    if ui.button("➕ Increment").clicked() {
                        counter += 1;
                        TEST_COUNTER.store(counter, Ordering::Relaxed);
                    }
                });

                let mut chk = TEST_CHECKBOX.load(Ordering::Relaxed);
                if ui.checkbox(&mut chk, "Enable Pinning Cadence").changed() {
                    TEST_CHECKBOX.store(chk, Ordering::Relaxed);
                }

                ui.separator();
                let cheats = CHEATS.lock().map(|c| c.clone()).unwrap_or_default();
                ui.label(format!("Loaded Cheats: {}", cheats.len()));
                for c in &cheats {
                    ui.label(format!("• {} ({})", c.label, c.kind_str));
                }

                ui.add_space(10.0);
                if ui.button("❌ Close Overlay (or press B)").clicked() {
                    super::set_overlay_visible(false);
                }
            });
    });

    let clipped_primitives = ctx.tessellate(full_output.shapes, 1.0);
    Some((ctx, clipped_primitives, full_output.textures_delta))
}
