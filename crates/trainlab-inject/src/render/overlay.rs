//! In-game interactive overlay logic and input translation for `egui`.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use trainlab_core::protocol::{Event, OverlayCheatDto};

pub static CHEATS: Mutex<Vec<OverlayCheatDto>> = Mutex::new(Vec::new());

// Outbound event queue (events generated inside the overlay to be broadcasted over IPC)
pub static OUTBOUND_EVENTS: Mutex<Vec<Event>> = Mutex::new(Vec::new());

// Queued raw events destined for egui
static PENDING_EGUI_EVENTS: Mutex<Vec<egui::Event>> = Mutex::new(Vec::new());

// Navigation state: Active tab (0 = Cheats/Toggles, 1 = Memory/Pinned Values, 2 = Window Control)
static ACTIVE_TAB: AtomicU64 = AtomicU64::new(0);

// Selected item index in the current active tab
static SELECTED_INDEX: AtomicU64 = AtomicU64::new(0);

// Stick debounce / trigger state
static STICK_TRIGGERED_Y: AtomicBool = AtomicBool::new(false);
static STICK_TRIGGERED_X: AtomicBool = AtomicBool::new(false);

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

fn get_active_tab_item_count() -> usize {
    let tab = ACTIVE_TAB.load(Ordering::Relaxed);
    let cheats = CHEATS.lock().map(|c| c.clone()).unwrap_or_default();
    if tab == 0 {
        // Toggle / Button cheats
        cheats.iter().filter(|c| c.kind_str == "toggle" || c.kind_str == "button").count().max(1)
    } else if tab == 1 {
        // Value / Pinned memory cheats
        cheats.iter().filter(|c| c.kind_str == "value").count().max(1)
    } else {
        // Tab 2: Window actions (Show GUI, Hide GUI, Disconnect)
        3
    }
}

/// Push controller button state changes and analog stick deflection into egui events.
pub fn push_controller_input(just_pressed: u16, thumb_ly: i16, thumb_lx: i16) {
    let mut events = Vec::new();

    // 1. Tab Switching via Bumpers (LB / RB across 3 tabs: 0 -> 1 -> 2 -> 0)
    if (just_pressed & XINPUT_GAMEPAD_LEFT_SHOULDER) != 0 {
        let cur_tab = ACTIVE_TAB.load(Ordering::Relaxed);
        let new_tab = if cur_tab == 0 { 2 } else { cur_tab - 1 };
        ACTIVE_TAB.store(new_tab, Ordering::Relaxed);
        SELECTED_INDEX.store(0, Ordering::Relaxed);
    }
    if (just_pressed & XINPUT_GAMEPAD_RIGHT_SHOULDER) != 0 {
        let cur_tab = ACTIVE_TAB.load(Ordering::Relaxed);
        let new_tab = (cur_tab + 1) % 3;
        ACTIVE_TAB.store(new_tab, Ordering::Relaxed);
        SELECTED_INDEX.store(0, Ordering::Relaxed);
    }

    // 2. Analog Stick Debouncing
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

    let item_count = get_active_tab_item_count() as u64;

    // 3. Move Selection Up / Down
    if move_up {
        let cur = SELECTED_INDEX.load(Ordering::Relaxed);
        if cur > 0 {
            SELECTED_INDEX.store(cur - 1, Ordering::Relaxed);
        } else {
            SELECTED_INDEX.store(item_count.saturating_sub(1), Ordering::Relaxed);
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

    let cur_tab = ACTIVE_TAB.load(Ordering::Relaxed);

    // 4. Left / Right Value Adjustment in Memory Tab
    if cur_tab == 1 && (move_left || move_right) {
        let sel = SELECTED_INDEX.load(Ordering::Relaxed) as usize;
        let delta: i64 = if move_right { 10 } else { -10 };
        if let Ok(mut cheats) = CHEATS.lock() {
            let mut val_cheats: Vec<&mut OverlayCheatDto> = cheats.iter_mut().filter(|c| c.kind_str == "value").collect();
            if sel < val_cheats.len() {
                let cheat = &mut val_cheats[sel];
                let current: i64 = cheat.current_value.as_deref().unwrap_or("0").parse().unwrap_or(0);
                let new_val = (current + delta).max(0);
                let new_str = new_val.to_string();
                cheat.current_value = Some(new_str.clone());
                cheat.pinned_bytes = Some(new_val.to_le_bytes().to_vec());

                // Broadcast Event::CheatValueChanged
                if let Ok(mut out) = OUTBOUND_EVENTS.lock() {
                    out.push(Event::CheatValueChanged {
                        id: cheat.id,
                        value_str: new_str,
                        pinned_bytes: cheat.pinned_bytes.clone(),
                    });
                }
            }
        }
    }

    // 5. A Button (Cross / Enter) -> Toggle, Pin, or Window Command
    if (just_pressed & XINPUT_GAMEPAD_A) != 0 {
        events.push(egui::Event::Key {
            key: egui::Key::Enter,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        });

        let sel = SELECTED_INDEX.load(Ordering::Relaxed) as usize;
        if cur_tab == 0 {
            // Cheats / Toggles Tab
            if let Ok(mut cheats) = CHEATS.lock() {
                let mut toggles: Vec<&mut OverlayCheatDto> = cheats.iter_mut().filter(|c| c.kind_str == "toggle" || c.kind_str == "button").collect();
                if sel < toggles.len() {
                    let cheat = &mut toggles[sel];
                    cheat.enabled = !cheat.enabled;
                    let id = cheat.id;
                    let enabled = cheat.enabled;

                    // Emit Event::CheatToggled
                    if let Ok(mut out) = OUTBOUND_EVENTS.lock() {
                        out.push(Event::CheatToggled { id, enabled });
                    }
                    tracing::info!("Overlay toggled cheat #{} '{}' -> {}", id, cheat.label, enabled);
                }
            }
        } else if cur_tab == 1 {
            // Memory / Pinned Values Tab
            if let Ok(mut cheats) = CHEATS.lock() {
                let mut val_cheats: Vec<&mut OverlayCheatDto> = cheats.iter_mut().filter(|c| c.kind_str == "value").collect();
                if sel < val_cheats.len() {
                    let cheat = &mut val_cheats[sel];
                    cheat.enabled = !cheat.enabled;
                    let id = cheat.id;
                    let enabled = cheat.enabled;

                    if let Ok(mut out) = OUTBOUND_EVENTS.lock() {
                        out.push(Event::CheatToggled { id, enabled });
                    }
                    tracing::info!("Overlay toggled pin on memory item #{} '{}' -> {}", id, cheat.label, enabled);
                }
            }
        } else {
            // Tab 2: Window Controls (0 = Show GUI, 1 = Hide GUI, 2 = Toggle GUI)
            let cmd = match sel {
                0 => "show",
                1 => "hide",
                _ => "show",
            };
            if let Ok(mut out) = OUTBOUND_EVENTS.lock() {
                out.push(Event::WindowCommand { command: cmd.to_string() });
            }
            tracing::info!("Overlay requested main window command: {}", cmd);
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

    if !events.is_empty()
        && let Ok(mut queue) = PENDING_EGUI_EVENTS.lock() {
            queue.extend(events);
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

/// Apply a discrete Event arriving from the IPC Event Bus.
pub fn apply_event(event: Event) {
    match event {
        Event::CheatAdded { cheat } => {
            if let Ok(mut lock) = CHEATS.lock() {
                if let Some(existing) = lock.iter_mut().find(|c| c.id == cheat.id) {
                    *existing = cheat;
                } else {
                    lock.push(cheat);
                }
            }
        }
        Event::CheatToggled { id, enabled } => {
            if let Ok(mut lock) = CHEATS.lock()
                && let Some(cheat) = lock.iter_mut().find(|c| c.id == id) {
                    cheat.enabled = enabled;
                }
        }
        Event::CheatValueChanged { id, value_str, pinned_bytes } => {
            if let Ok(mut lock) = CHEATS.lock()
                && let Some(cheat) = lock.iter_mut().find(|c| c.id == id) {
                    cheat.current_value = Some(value_str);
                    cheat.pinned_bytes = pinned_bytes;
                }
        }
        Event::CheatRemoved { id } => {
            if let Ok(mut lock) = CHEATS.lock() {
                lock.retain(|c| c.id != id);
            }
        }
        Event::SyncCheats { cheats } => {
            if let Ok(mut lock) = CHEATS.lock() {
                *lock = cheats;
            }
        }
        Event::OverlayVisibilityChanged { visible } => {
            super::set_overlay_visible(visible);
        }
        _ => {}
    }
}

/// Take all pending outbound events generated inside the overlay to send over IPC.
pub fn drain_outbound_events() -> Vec<Event> {
    if let Ok(mut lock) = OUTBOUND_EVENTS.lock() {
        std::mem::take(&mut *lock)
    } else {
        Vec::new()
    }
}

/// Handle a mouse/touch click inside the in-game overlay bounds.
pub fn handle_click(x: i32, y: i32) {
    let cur_tab = ACTIVE_TAB.load(Ordering::Relaxed);
    // Tab header clicks (y: 30..70)
    if (30..=75).contains(&y) {
        if (30..=140).contains(&x) {
            ACTIVE_TAB.store(0, Ordering::Relaxed);
            SELECTED_INDEX.store(0, Ordering::Relaxed);
            return;
        } else if (145..=255).contains(&x) {
            ACTIVE_TAB.store(1, Ordering::Relaxed);
            SELECTED_INDEX.store(0, Ordering::Relaxed);
            return;
        } else if (260..=370).contains(&x) {
            ACTIVE_TAB.store(2, Ordering::Relaxed);
            SELECTED_INDEX.store(0, Ordering::Relaxed);
            return;
        }
    }

    // List item clicks (y >= 140)
    if (30..=380).contains(&x) && y >= 140 {
        let item_idx = ((y - 140) / 48) as usize;
        SELECTED_INDEX.store(item_idx as u64, Ordering::Relaxed);
        if cur_tab == 0 {
            if let Ok(mut cheats) = CHEATS.lock() {
                let mut toggles: Vec<&mut OverlayCheatDto> = cheats.iter_mut().filter(|c| c.kind_str == "toggle" || c.kind_str == "button").collect();
                if item_idx < toggles.len() {
                    let cheat = &mut toggles[item_idx];
                    cheat.enabled = !cheat.enabled;
                    let id = cheat.id;
                    let enabled = cheat.enabled;
                    if let Ok(mut out) = OUTBOUND_EVENTS.lock() {
                        out.push(Event::CheatToggled { id, enabled });
                    }
                }
            }
        } else if cur_tab == 1 {
            if let Ok(mut cheats) = CHEATS.lock() {
                let mut val_cheats: Vec<&mut OverlayCheatDto> = cheats.iter_mut().filter(|c| c.kind_str == "value").collect();
                if item_idx < val_cheats.len() {
                    let cheat = &mut val_cheats[item_idx];
                    cheat.enabled = !cheat.enabled;
                    let id = cheat.id;
                    let enabled = cheat.enabled;
                    if let Ok(mut out) = OUTBOUND_EVENTS.lock() {
                        out.push(Event::CheatToggled { id, enabled });
                    }
                }
            }
        } else {
            let cmd = match item_idx {
                0 => "show",
                1 => "hide",
                _ => "show",
            };
            if let Ok(mut out) = OUTBOUND_EVENTS.lock() {
                out.push(Event::WindowCommand { command: cmd.to_string() });
            }
        }
    }
}

/// Execute on-frame value pinning for any pinned cheats.
pub fn execute_pinning_cadence() {
    if let Ok(cheats) = CHEATS.lock() {
        let mem = trainlab_core::memory::SelfProcess;
        for c in cheats.iter() {
            if c.enabled
                && let Some(pinned_bytes) = &c.pinned_bytes
                    && c.address != 0 && !pinned_bytes.is_empty() {
                        use trainlab_core::memory::ProcessMemory;
                        let _ = mem.write(c.address, pinned_bytes);
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
            visuals.window_stroke = egui::Stroke::new(1.5_f32, egui::Color32::from_rgba_premultiplied(30, 160, 240, 200));
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

                // 1. Tab Selector with 3 Tabs (Cheats, Memory, Window)
                ui.horizontal(|ui| {
                    let tab0_btn = if active_tab == 0 {
                        egui::Button::new("🎮 Cheats").fill(egui::Color32::from_rgb(20, 90, 160))
                    } else {
                        egui::Button::new("🎮 Cheats").fill(egui::Color32::from_rgb(30, 35, 45))
                    };
                    if ui.add_sized([105.0, 28.0], tab0_btn).clicked() {
                        active_tab = 0;
                        ACTIVE_TAB.store(0, Ordering::Relaxed);
                        SELECTED_INDEX.store(0, Ordering::Relaxed);
                    }

                    let tab1_btn = if active_tab == 1 {
                        egui::Button::new("🧠 Memory").fill(egui::Color32::from_rgb(20, 90, 160))
                    } else {
                        egui::Button::new("🧠 Memory").fill(egui::Color32::from_rgb(30, 35, 45))
                    };
                    if ui.add_sized([105.0, 28.0], tab1_btn).clicked() {
                        active_tab = 1;
                        ACTIVE_TAB.store(1, Ordering::Relaxed);
                        SELECTED_INDEX.store(0, Ordering::Relaxed);
                    }

                    let tab2_btn = if active_tab == 2 {
                        egui::Button::new("🖥 Window").fill(egui::Color32::from_rgb(20, 90, 160))
                    } else {
                        egui::Button::new("🖥 Window").fill(egui::Color32::from_rgb(30, 35, 45))
                    };
                    if ui.add_sized([105.0, 28.0], tab2_btn).clicked() {
                        active_tab = 2;
                        ACTIVE_TAB.store(2, Ordering::Relaxed);
                        SELECTED_INDEX.store(0, Ordering::Relaxed);
                    }
                });

                ui.separator();
                let selected_idx = SELECTED_INDEX.load(Ordering::Relaxed) as usize;
                let mut cheats = CHEATS.lock().map(|c| c.clone()).unwrap_or_default();

                if active_tab == 0 {
                    // TAB 0: Cheats & Toggles
                    ui.colored_label(egui::Color32::LIGHT_GREEN, "● Active Cheats & Toggles");
                    ui.label("• LB/RB: Switch Tab | D-Pad: Move | A: Toggle");
                    ui.separator();

                    let mut toggle_cheats: Vec<&mut OverlayCheatDto> = cheats.iter_mut().filter(|c| c.kind_str == "toggle" || c.kind_str == "button").collect();

                    if toggle_cheats.is_empty() {
                        ui.colored_label(egui::Color32::GRAY, "No toggle cheats registered yet.");
                        ui.label("Add cheats in trainlab-gui, load a profile, or use an AI agent.");
                    } else {
                        for (idx, cheat) in toggle_cheats.iter_mut().enumerate() {
                            let is_selected = idx == selected_idx;
                            let text = format!("{} {}", if cheat.enabled { "🟢" } else { "⚪" }, cheat.label);

                            if is_selected {
                                egui::Frame::none()
                                    .fill(egui::Color32::from_rgba_premultiplied(30, 140, 230, 100))
                                    .stroke(egui::Stroke::new(2.0_f32, egui::Color32::from_rgb(0, 220, 255)))
                                    .rounding(egui::Rounding::same(6.0))
                                    .inner_margin(egui::Margin::symmetric(8.0, 5.0))
                                    .show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            ui.label(text);
                                        });
                                    });
                            } else {
                                ui.horizontal(|ui| {
                                    ui.label(text);
                                });
                            }
                            ui.separator();
                        }
                    }
                } else if active_tab == 1 {
                    // TAB 1: Memory Locations & Value Pinning
                    ui.colored_label(egui::Color32::from_rgb(0, 210, 255), "● Tracked Memory & Value Pinning");
                    ui.label("• Left/Right: Adjust Value | A: Toggle Pin (📌/🔓)");
                    ui.separator();

                    let mut val_cheats: Vec<&mut OverlayCheatDto> = cheats.iter_mut().filter(|c| c.kind_str == "value").collect();

                    if val_cheats.is_empty() {
                        ui.colored_label(egui::Color32::GRAY, "No memory items registered yet.");
                        ui.label("Add value cheats in trainlab-gui or run a memory scan.");
                    } else {
                        for (idx, cheat) in val_cheats.iter_mut().enumerate() {
                            let is_selected = idx == selected_idx;
                            let pin_icon = if cheat.enabled { "📌 PINNED" } else { "🔓 Unpinned" };
                            let pin_color = if cheat.enabled { egui::Color32::LIGHT_GREEN } else { egui::Color32::GRAY };
                            let val_display = cheat.current_value.as_deref().unwrap_or("?");

                            let row_content = |ui: &mut egui::Ui| {
                                ui.horizontal(|ui| {
                                    ui.vertical(|ui| {
                                        ui.label(format!("{} [{:#x}]", cheat.label, cheat.address));
                                        ui.colored_label(pin_color, pin_icon);
                                    });
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        ui.heading(val_display);
                                    });
                                });
                            };

                            if is_selected {
                                egui::Frame::none()
                                    .fill(egui::Color32::from_rgba_premultiplied(30, 140, 230, 100))
                                    .stroke(egui::Stroke::new(2.0_f32, egui::Color32::from_rgb(0, 220, 255)))
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
                } else {
                    // TAB 2: Window Actions
                    ui.colored_label(egui::Color32::from_rgb(255, 180, 0), "● GUI Window Controls");
                    ui.label("• LB/RB: Switch Tab | D-Pad: Move | A: Execute");
                    ui.separator();

                    let actions = [
                        ("👁 Reveal / Show GUI Window", "Restore the standalone Trainlab GUI window"),
                        ("🙈 Hide / Background GUI Window", "Minimize GUI to background for zero overhead"),
                        ("🔄 Restore GUI to Front", "Bring GUI window to foreground focus"),
                    ];

                    for (idx, (title, desc)) in actions.iter().enumerate() {
                        let is_selected = idx == selected_idx;
                        let row_content = |ui: &mut egui::Ui| {
                            ui.vertical(|ui| {
                                ui.label(egui::RichText::new(*title).strong());
                                ui.label(egui::RichText::new(*desc).color(egui::Color32::GRAY).small());
                            });
                        };

                        if is_selected {
                            egui::Frame::none()
                                .fill(egui::Color32::from_rgba_premultiplied(30, 140, 230, 100))
                                .stroke(egui::Stroke::new(2.0_f32, egui::Color32::from_rgb(0, 220, 255)))
                                .rounding(egui::Rounding::same(6.0))
                                .inner_margin(egui::Margin::symmetric(8.0, 6.0))
                                .show(ui, |ui| {
                                    row_content(ui);
                                });
                        } else {
                            egui::Frame::none()
                                .inner_margin(egui::Margin::symmetric(8.0, 6.0))
                                .show(ui, |ui| {
                                    row_content(ui);
                                });
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
