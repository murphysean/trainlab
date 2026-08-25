//! In-game interactive overlay logic and input translation for `egui`.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use trainlab_core::protocol::OverlayCheatDto;

pub static CHEATS: Mutex<Vec<OverlayCheatDto>> = Mutex::new(Vec::new());

// Queued raw events destined for egui
static PENDING_EGUI_EVENTS: Mutex<Vec<egui::Event>> = Mutex::new(Vec::new());

// Selected item index for D-Pad / Analog navigation
static SELECTED_INDEX: AtomicU64 = AtomicU64::new(0);

// XInput Button Bitmasks
pub const XINPUT_GAMEPAD_DPAD_UP: u16 = 0x0001;
pub const XINPUT_GAMEPAD_DPAD_DOWN: u16 = 0x0002;
pub const XINPUT_GAMEPAD_DPAD_LEFT: u16 = 0x0004;
pub const XINPUT_GAMEPAD_DPAD_RIGHT: u16 = 0x0008;
pub const XINPUT_GAMEPAD_START: u16 = 0x0010;
pub const XINPUT_GAMEPAD_BACK: u16 = 0x0020;
pub const XINPUT_GAMEPAD_LEFT_THUMB: u16 = 0x0040;
pub const XINPUT_GAMEPAD_RIGHT_THUMB: u16 = 0x0080;
pub const XINPUT_GAMEPAD_LEFT_SHOULDER: u16 = 0x0100;
pub const XINPUT_GAMEPAD_RIGHT_SHOULDER: u16 = 0x0200;
pub const XINPUT_GAMEPAD_A: u16 = 0x1000;
pub const XINPUT_GAMEPAD_B: u16 = 0x2000;
pub const XINPUT_GAMEPAD_X: u16 = 0x4000;
pub const XINPUT_GAMEPAD_Y: u16 = 0x8000;

/// Push controller button state changes and analog stick deflection into egui events.
pub fn push_controller_input(just_pressed: u16, thumb_ly: i16, thumb_lx: i16) {
    let mut events = Vec::new();

    // D-Pad Up / Analog Stick Up
    if (just_pressed & XINPUT_GAMEPAD_DPAD_UP) != 0 || thumb_ly > 20000 {
        let cur = SELECTED_INDEX.load(Ordering::Relaxed);
        if cur > 0 {
            SELECTED_INDEX.store(cur - 1, Ordering::Relaxed);
        }
        events.push(egui::Event::Key {
            key: egui::Key::ArrowUp,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        });
    }

    // D-Pad Down / Analog Stick Down
    if (just_pressed & XINPUT_GAMEPAD_DPAD_DOWN) != 0 || thumb_ly < -20000 {
        let cur = SELECTED_INDEX.load(Ordering::Relaxed);
        SELECTED_INDEX.store(cur + 1, Ordering::Relaxed);
        events.push(egui::Event::Key {
            key: egui::Key::ArrowDown,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        });
    }

    // D-Pad Left / Analog Stick Left
    if (just_pressed & XINPUT_GAMEPAD_DPAD_LEFT) != 0 || thumb_lx < -20000 {
        events.push(egui::Event::Key {
            key: egui::Key::ArrowLeft,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        });
    }

    // D-Pad Right / Analog Stick Right
    if (just_pressed & XINPUT_GAMEPAD_DPAD_RIGHT) != 0 || thumb_lx > 20000 {
        events.push(egui::Event::Key {
            key: egui::Key::ArrowRight,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        });
    }

    // A Button (Cross / Enter) -> Toggle selected item
    if (just_pressed & XINPUT_GAMEPAD_A) != 0 {
        events.push(egui::Event::Key {
            key: egui::Key::Enter,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        });

        // Directly toggle the selected cheat in memory
        let sel = SELECTED_INDEX.load(Ordering::Relaxed) as usize;
        if let Ok(mut cheats) = CHEATS.lock() {
            if sel < cheats.len() {
                cheats[sel].enabled = !cheats[sel].enabled;
                tracing::info!("Toggled cheat '{}' via controller -> {}", cheats[sel].label, cheats[sel].enabled);
            }
        }
    }

    // B Button (Circle / Esc) -> Dismiss overlay
    if (just_pressed & XINPUT_GAMEPAD_B) != 0 {
        events.push(egui::Event::Key {
            key: egui::Key::Escape,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        });
        super::set_overlay_visible(false);
    }

    if !events.is_empty() {
        if let Ok(mut queue) = PENDING_EGUI_EVENTS.lock() {
            queue.extend(events);
        }
    }
}

/// Push mouse move and pointer button events from Touchscreen / Trackpad / Mouse.
pub fn push_pointer_event(x: f32, y: f32, pressed: Option<bool>) {
    let mut events = Vec::new();
    events.push(egui::Event::PointerMoved(egui::pos2(x, y)));

    if let Some(down) = pressed {
        events.push(egui::Event::PointerButton {
            pos: egui::pos2(x, y),
            button: egui::PointerButton::Primary,
            pressed: down,
            modifiers: egui::Modifiers::NONE,
        });
    }

    if let Ok(mut queue) = PENDING_EGUI_EVENTS.lock() {
        queue.extend(events);
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

/// Handle a mouse/touch click inside the in-game overlay bounds.
pub fn handle_click(x: i32, y: i32) {
    if let Ok(mut cheats) = CHEATS.lock() {
        if x >= 30 && x <= 370 && y >= 70 {
            let item_idx = ((y - 70) / 36) as usize;
            if item_idx < cheats.len() {
                let cheat = &mut cheats[item_idx];
                cheat.enabled = !cheat.enabled;
                tracing::info!("Touch click toggled cheat '{}' -> {}", cheat.label, cheat.enabled);
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
static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);
static TEST_CHECKBOX: AtomicBool = AtomicBool::new(true);

/// Render the in-game egui frame and return output shapes/primitives.
pub fn render_in_game_egui(
    screen_width: f32,
    screen_height: f32,
) -> Option<(egui::Context, Vec<egui::ClippedPrimitive>, egui::TexturesDelta)> {
    let ctx = {
        let mut lock = EGUI_CTX.lock().ok()?;
        if lock.is_none() {
            let new_ctx = egui::Context::default();
            let mut visuals = egui::Visuals::dark();
            visuals.window_rounding = egui::Rounding::same(10.0);
            visuals.window_fill = egui::Color32::from_rgba_premultiplied(12, 16, 24, 210);
            visuals.panel_fill = egui::Color32::from_rgba_premultiplied(16, 22, 34, 180);
            visuals.window_stroke = egui::Stroke::new(1.5, egui::Color32::from_rgba_premultiplied(30, 160, 240, 200));
            visuals.window_shadow = egui::epaint::Shadow {
                offset: egui::vec2(0.0, 8.0),
                blur: 16.0,
                spread: 0.0,
                color: egui::Color32::from_black_alpha(160),
            };
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
            .fixed_size(egui::vec2(340.0, 440.0))
            .frame(egui::Frame::window(&ctx.style()).fill(egui::Color32::from_rgba_premultiplied(12, 16, 24, 205)))
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.heading("Trainlab v0.1.0 (In-Process)");
                ui.colored_label(egui::Color32::LIGHT_GREEN, "● Active & Hooked into Frame Presentation");
                ui.separator();

                ui.label("🎮 Controls:");
                ui.label("• D-Pad / Left Stick: Select cheat");
                ui.label("• A Button / Touch: Toggle cheat");
                ui.label("• B Button / Select+Start: Close overlay");

                ui.separator();
                ui.heading("Active Cheats:");

                let selected_idx = SELECTED_INDEX.load(Ordering::Relaxed) as usize;
                let mut cheats = CHEATS.lock().map(|c| c.clone()).unwrap_or_default();

                if cheats.is_empty() {
                    ui.label("No profile cheats loaded yet.");
                    ui.add_space(8.0);
                    ui.label("Interactive Widget Test:");
                    let mut counter = TEST_COUNTER.load(Ordering::Relaxed);
                    ui.horizontal(|ui| {
                        ui.label(format!("Counter: {counter}"));
                        if ui.button("➕ Increment").clicked() {
                            counter += 1;
                            TEST_COUNTER.store(counter, Ordering::Relaxed);
                        }
                    });
                } else {
                    for (i, cheat) in cheats.iter_mut().enumerate() {
                        let is_selected = i == selected_idx;
                        let text = format!("{} {}", if cheat.enabled { "🟢" } else { "⚪" }, cheat.label);

                        let response = if is_selected {
                            // Highlight selected item with glowing background frame
                            egui::Frame::none()
                                .fill(egui::Color32::from_rgba_premultiplied(30, 140, 230, 90))
                                .stroke(egui::Stroke::new(1.5, egui::Color32::from_rgb(0, 200, 255)))
                                .rounding(egui::Rounding::same(6.0))
                                .show(ui, |ui| {
                                    ui.checkbox(&mut cheat.enabled, &text)
                                })
                                .inner
                        } else {
                            ui.checkbox(&mut cheat.enabled, &text)
                        };

                        if response.changed() {
                            if let Ok(mut lock) = CHEATS.lock() {
                                if i < lock.len() {
                                    lock[i].enabled = cheat.enabled;
                                }
                            }
                        }
                    }
                }

                ui.add_space(15.0);
                if ui.button("❌ Close Overlay (or press B)").clicked() {
                    super::set_overlay_visible(false);
                }
            });
    });

    let clipped_primitives = ctx.tessellate(full_output.shapes, 1.0);
    Some((ctx, clipped_primitives, full_output.textures_delta))
}
