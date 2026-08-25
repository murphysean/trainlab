//! In-game interactive overlay logic and input translation for `egui`.

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::Mutex;
use trainlab_core::protocol::OverlayCheatDto;

pub static CHEATS: Mutex<Vec<OverlayCheatDto>> = Mutex::new(Vec::new());

// Queued raw events destined for egui
static PENDING_EGUI_EVENTS: Mutex<Vec<egui::Event>> = Mutex::new(Vec::new());

// Navigation state: Active tab (0 = Cheats, 1 = Memory Pins)
static ACTIVE_TAB: AtomicU64 = AtomicU64::new(0);

// Selected item index in the current active tab
static SELECTED_INDEX: AtomicU64 = AtomicU64::new(0);

// Stick debounce / trigger state (prevents hyper-speed repeating on analog sticks)
static STICK_TRIGGERED_Y: AtomicBool = AtomicBool::new(false);
static STICK_TRIGGERED_X: AtomicBool = AtomicBool::new(false);

// Interactive Mock Cheats Tab
static TEST_GOD_MODE: AtomicBool = AtomicBool::new(true);
static TEST_INFINITE_AMMO: AtomicBool = AtomicBool::new(false);
static TEST_NO_RELOAD: AtomicBool = AtomicBool::new(true);
static TEST_INFINITE_STAMINA: AtomicBool = AtomicBool::new(false);
static TEST_SPEED_BOOST: AtomicBool = AtomicBool::new(false);

// Interactive Mock Memory / Pinned Values Tab
static TEST_HEALTH_VAL: AtomicI64 = AtomicI64::new(100);
static TEST_HEALTH_PIN: AtomicBool = AtomicBool::new(true);
static TEST_AMMO_VAL: AtomicI64 = AtomicI64::new(32);
static TEST_AMMO_PIN: AtomicBool = AtomicBool::new(true);
static TEST_SAMPLES_VAL: AtomicI64 = AtomicI64::new(500);
static TEST_SAMPLES_PIN: AtomicBool = AtomicBool::new(false);
static TEST_MEDKITS_VAL: AtomicI64 = AtomicI64::new(4);
static TEST_MEDKITS_PIN: AtomicBool = AtomicBool::new(true);

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

fn get_tab_item_count(tab: u64) -> u64 {
    match tab {
        0 => 5, // Cheats: God mode, Ammo, No Reload, Stamina, Speed
        1 => 4, // Memory: Health, Ammo, Samples, Medkits
        _ => 5,
    }
}

/// Push controller button state changes and analog stick deflection into egui events.
pub fn push_controller_input(just_pressed: u16, thumb_ly: i16, thumb_lx: i16) {
    let mut events = Vec::new();

    // 1. Tab Switching via Bumpers (LB / RB)
    if (just_pressed & XINPUT_GAMEPAD_LEFT_SHOULDER) != 0 {
        let cur_tab = ACTIVE_TAB.load(Ordering::Relaxed);
        let new_tab = if cur_tab == 0 { 1 } else { 0 };
        ACTIVE_TAB.store(new_tab, Ordering::Relaxed);
        SELECTED_INDEX.store(0, Ordering::Relaxed);
    }
    if (just_pressed & XINPUT_GAMEPAD_RIGHT_SHOULDER) != 0 {
        let cur_tab = ACTIVE_TAB.load(Ordering::Relaxed);
        let new_tab = if cur_tab == 1 { 0 } else { 1 };
        ACTIVE_TAB.store(new_tab, Ordering::Relaxed);
        SELECTED_INDEX.store(0, Ordering::Relaxed);
    }

    // 2. Analog Stick Debouncing (Only trigger step when stick enters deadzone threshold)
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

    let stick_left = thumb_lx < -22000;
    let stick_right = thumb_lx > 22000;
    let stick_neutral_x = thumb_lx.abs() < 12000;

    let mut move_left = (just_pressed & XINPUT_GAMEPAD_DPAD_LEFT) != 0;
    let mut move_right = (just_pressed & XINPUT_GAMEPAD_DPAD_RIGHT) != 0;

    if stick_neutral_x {
        STICK_TRIGGERED_X.store(false, Ordering::Relaxed);
    } else if !STICK_TRIGGERED_X.load(Ordering::Relaxed) {
        if stick_left {
            move_left = true;
            STICK_TRIGGERED_X.store(true, Ordering::Relaxed);
        } else if stick_right {
            move_right = true;
            STICK_TRIGGERED_X.store(true, Ordering::Relaxed);
        }
    }

    let cur_tab = ACTIVE_TAB.load(Ordering::Relaxed);
    let item_count = get_tab_item_count(cur_tab);

    // 3. Move Selection Up / Down
    if move_up {
        let cur = SELECTED_INDEX.load(Ordering::Relaxed);
        if cur > 0 {
            SELECTED_INDEX.store(cur - 1, Ordering::Relaxed);
        } else {
            SELECTED_INDEX.store(item_count - 1, Ordering::Relaxed);
        }
        events.push(egui::Event::Key {
            key: egui::Key::ArrowUp,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        });
    }

    if move_down {
        let cur = SELECTED_INDEX.load(Ordering::Relaxed);
        if cur + 1 < item_count {
            SELECTED_INDEX.store(cur + 1, Ordering::Relaxed);
        } else {
            SELECTED_INDEX.store(0, Ordering::Relaxed);
        }
        events.push(egui::Event::Key {
            key: egui::Key::ArrowDown,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        });
    }

    // 4. Left / Right for Value Adjustment in Memory Tab
    if cur_tab == 1 {
        let sel = SELECTED_INDEX.load(Ordering::Relaxed);
        let delta: i64 = if move_right { 10 } else if move_left { -10 } else { 0 };
        if delta != 0 {
            match sel {
                0 => {
                    let v = (TEST_HEALTH_VAL.load(Ordering::Relaxed) + delta).max(0);
                    TEST_HEALTH_VAL.store(v, Ordering::Relaxed);
                }
                1 => {
                    let v = (TEST_AMMO_VAL.load(Ordering::Relaxed) + delta).max(0);
                    TEST_AMMO_VAL.store(v, Ordering::Relaxed);
                }
                2 => {
                    let v = (TEST_SAMPLES_VAL.load(Ordering::Relaxed) + delta).max(0);
                    TEST_SAMPLES_VAL.store(v, Ordering::Relaxed);
                }
                3 => {
                    let v = (TEST_MEDKITS_VAL.load(Ordering::Relaxed) + (delta / 10)).max(0);
                    TEST_MEDKITS_VAL.store(v, Ordering::Relaxed);
                }
                _ => {}
            }
        }
    }

    // 5. A Button (Cross / Enter) -> Toggle or Pin
    if (just_pressed & XINPUT_GAMEPAD_A) != 0 {
        events.push(egui::Event::Key {
            key: egui::Key::Enter,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        });

        let sel = SELECTED_INDEX.load(Ordering::Relaxed);
        if cur_tab == 0 {
            // Cheats Tab
            match sel {
                0 => TEST_GOD_MODE.store(!TEST_GOD_MODE.load(Ordering::Relaxed), Ordering::Relaxed),
                1 => TEST_INFINITE_AMMO.store(!TEST_INFINITE_AMMO.load(Ordering::Relaxed), Ordering::Relaxed),
                2 => TEST_NO_RELOAD.store(!TEST_NO_RELOAD.load(Ordering::Relaxed), Ordering::Relaxed),
                3 => TEST_INFINITE_STAMINA.store(!TEST_INFINITE_STAMINA.load(Ordering::Relaxed), Ordering::Relaxed),
                4 => TEST_SPEED_BOOST.store(!TEST_SPEED_BOOST.load(Ordering::Relaxed), Ordering::Relaxed),
                _ => {}
            }
        } else {
            // Memory Tab -> Toggle Pin state on A
            match sel {
                0 => TEST_HEALTH_PIN.store(!TEST_HEALTH_PIN.load(Ordering::Relaxed), Ordering::Relaxed),
                1 => TEST_AMMO_PIN.store(!TEST_AMMO_PIN.load(Ordering::Relaxed), Ordering::Relaxed),
                2 => TEST_SAMPLES_PIN.store(!TEST_SAMPLES_PIN.load(Ordering::Relaxed), Ordering::Relaxed),
                3 => TEST_MEDKITS_PIN.store(!TEST_MEDKITS_PIN.load(Ordering::Relaxed), Ordering::Relaxed),
                _ => {}
            }
        }
    }

    // 6. B Button (Circle / Esc) -> Dismiss overlay
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
    let cur_tab = ACTIVE_TAB.load(Ordering::Relaxed);
    // Tab header clicks (y: 80..115)
    if y >= 80 && y <= 115 {
        if x >= 35 && x <= 180 {
            ACTIVE_TAB.store(0, Ordering::Relaxed);
            SELECTED_INDEX.store(0, Ordering::Relaxed);
            return;
        } else if x >= 190 && x <= 335 {
            ACTIVE_TAB.store(1, Ordering::Relaxed);
            SELECTED_INDEX.store(0, Ordering::Relaxed);
            return;
        }
    }

    // List item clicks (y >= 160)
    if x >= 30 && x <= 360 && y >= 160 {
        let item_idx = ((y - 160) / 38) as u64;
        SELECTED_INDEX.store(item_idx, Ordering::Relaxed);
        if cur_tab == 0 {
            match item_idx {
                0 => TEST_GOD_MODE.store(!TEST_GOD_MODE.load(Ordering::Relaxed), Ordering::Relaxed),
                1 => TEST_INFINITE_AMMO.store(!TEST_INFINITE_AMMO.load(Ordering::Relaxed), Ordering::Relaxed),
                2 => TEST_NO_RELOAD.store(!TEST_NO_RELOAD.load(Ordering::Relaxed), Ordering::Relaxed),
                3 => TEST_INFINITE_STAMINA.store(!TEST_INFINITE_STAMINA.load(Ordering::Relaxed), Ordering::Relaxed),
                4 => TEST_SPEED_BOOST.store(!TEST_SPEED_BOOST.load(Ordering::Relaxed), Ordering::Relaxed),
                _ => {}
            }
        } else {
            match item_idx {
                0 => TEST_HEALTH_PIN.store(!TEST_HEALTH_PIN.load(Ordering::Relaxed), Ordering::Relaxed),
                1 => TEST_AMMO_PIN.store(!TEST_AMMO_PIN.load(Ordering::Relaxed), Ordering::Relaxed),
                2 => TEST_SAMPLES_PIN.store(!TEST_SAMPLES_PIN.load(Ordering::Relaxed), Ordering::Relaxed),
                3 => TEST_MEDKITS_PIN.store(!TEST_MEDKITS_PIN.load(Ordering::Relaxed), Ordering::Relaxed),
                _ => {}
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
            .fixed_size(egui::vec2(360.0, 500.0))
            .frame(egui::Frame::window(&ctx.style()).fill(egui::Color32::from_rgba_premultiplied(12, 16, 24, 205)))
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                let mut active_tab = ACTIVE_TAB.load(Ordering::Relaxed);

                // 1. Tab Selector with Bumper Indicators
                ui.horizontal(|ui| {
                    let tab0_btn = if active_tab == 0 {
                        egui::Button::new("🎮 [LB] Cheats").fill(egui::Color32::from_rgb(20, 90, 160))
                    } else {
                        egui::Button::new("[LB] Cheats").fill(egui::Color32::from_rgb(30, 35, 45))
                    };
                    if ui.add_sized([160.0, 30.0], tab0_btn).clicked() {
                        active_tab = 0;
                        ACTIVE_TAB.store(0, Ordering::Relaxed);
                        SELECTED_INDEX.store(0, Ordering::Relaxed);
                    }

                    let tab1_btn = if active_tab == 1 {
                        egui::Button::new("🧠 [RB] Memory").fill(egui::Color32::from_rgb(20, 90, 160))
                    } else {
                        egui::Button::new("[RB] Memory").fill(egui::Color32::from_rgb(30, 35, 45))
                    };
                    if ui.add_sized([160.0, 30.0], tab1_btn).clicked() {
                        active_tab = 1;
                        ACTIVE_TAB.store(1, Ordering::Relaxed);
                        SELECTED_INDEX.store(0, Ordering::Relaxed);
                    }
                });

                ui.separator();
                let selected_idx = SELECTED_INDEX.load(Ordering::Relaxed) as usize;

                if active_tab == 0 {
                    // TAB 0: Cheats & Toggles
                    ui.colored_label(egui::Color32::LIGHT_GREEN, "● Active Cheats & Toggles");
                    ui.label("• LB/RB: Switch Tab | D-Pad: Move | A: Toggle");
                    ui.separator();

                    let items = [
                        (0, "🛡️ God Mode / Invulnerability", TEST_GOD_MODE.load(Ordering::Relaxed)),
                        (1, "🔫 Infinite Ammo", TEST_INFINITE_AMMO.load(Ordering::Relaxed)),
                        (2, "⚡ No Reload / Instant Fire", TEST_NO_RELOAD.load(Ordering::Relaxed)),
                        (3, "🏃 Infinite Stamina", TEST_INFINITE_STAMINA.load(Ordering::Relaxed)),
                        (4, "🚀 2x Movement Speed", TEST_SPEED_BOOST.load(Ordering::Relaxed)),
                    ];

                    for (idx, label, enabled) in items {
                        let is_selected = idx == selected_idx;
                        let text = format!("{} {}", if enabled { "🟢" } else { "⚪" }, label);

                        if is_selected {
                            egui::Frame::none()
                                .fill(egui::Color32::from_rgba_premultiplied(30, 140, 230, 100))
                                .stroke(egui::Stroke::new(2.0, egui::Color32::from_rgb(0, 220, 255)))
                                .rounding(egui::Rounding::same(6.0))
                                .inner_margin(egui::Margin::symmetric(8.0, 5.0))
                                .show(ui, |ui| {
                                    let mut val = enabled;
                                    if ui.checkbox(&mut val, &text).changed() {
                                        match idx {
                                            0 => TEST_GOD_MODE.store(val, Ordering::Relaxed),
                                            1 => TEST_INFINITE_AMMO.store(val, Ordering::Relaxed),
                                            2 => TEST_NO_RELOAD.store(val, Ordering::Relaxed),
                                            3 => TEST_INFINITE_STAMINA.store(val, Ordering::Relaxed),
                                            4 => TEST_SPEED_BOOST.store(val, Ordering::Relaxed),
                                            _ => {}
                                        }
                                    }
                                });
                        } else {
                            let mut val = enabled;
                            if ui.checkbox(&mut val, &text).changed() {
                                match idx {
                                    0 => TEST_GOD_MODE.store(val, Ordering::Relaxed),
                                    1 => TEST_INFINITE_AMMO.store(val, Ordering::Relaxed),
                                    2 => TEST_NO_RELOAD.store(val, Ordering::Relaxed),
                                    3 => TEST_INFINITE_STAMINA.store(val, Ordering::Relaxed),
                                    4 => TEST_SPEED_BOOST.store(val, Ordering::Relaxed),
                                    _ => {}
                                }
                            }
                        }
                    }
                } else {
                    // TAB 1: Memory Locations & Value Pinning
                    ui.colored_label(egui::Color32::from_rgb(0, 210, 255), "● Tracked Memory & Value Pinning");
                    ui.label("• Left/Right: Adjust Value | A: Toggle Pin (📌/🔓)");
                    ui.separator();

                    let mem_items = [
                        (0, "Health", "0x1428A4010", TEST_HEALTH_VAL.load(Ordering::Relaxed), TEST_HEALTH_PIN.load(Ordering::Relaxed)),
                        (1, "Primary Ammo", "0x1428A4018", TEST_AMMO_VAL.load(Ordering::Relaxed), TEST_AMMO_PIN.load(Ordering::Relaxed)),
                        (2, "Rare Samples", "0x1428A4020", TEST_SAMPLES_VAL.load(Ordering::Relaxed), TEST_SAMPLES_PIN.load(Ordering::Relaxed)),
                        (3, "Stim Packs", "0x1428A4028", TEST_MEDKITS_VAL.load(Ordering::Relaxed), TEST_MEDKITS_PIN.load(Ordering::Relaxed)),
                    ];

                    for (idx, name, addr_str, val, pinned) in mem_items {
                        let is_selected = idx == selected_idx;
                        let pin_icon = if pinned { "📌 PINNED" } else { "🔓 Unpinned" };
                        let pin_color = if pinned { egui::Color32::LIGHT_GREEN } else { egui::Color32::GRAY };

                        let row_content = |ui: &mut egui::Ui| {
                            ui.horizontal(|ui| {
                                ui.vertical(|ui| {
                                    ui.label(format!("{} [{}]", name, addr_str));
                                    ui.colored_label(pin_color, pin_icon);
                                });
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    ui.heading(format!("{val}"));
                                });
                            });
                        };

                        if is_selected {
                            egui::Frame::none()
                                .fill(egui::Color32::from_rgba_premultiplied(30, 140, 230, 100))
                                .stroke(egui::Stroke::new(2.0, egui::Color32::from_rgb(0, 220, 255)))
                                .rounding(egui::Rounding::same(6.0))
                                .inner_margin(egui::Margin::symmetric(8.0, 5.0))
                                .show(ui, |ui| {
                                    row_content(ui);
                                });
                        } else {
                            row_content(ui);
                        }
                        ui.separator();
                    }
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
