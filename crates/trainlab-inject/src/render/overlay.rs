//! In-game interactive overlay logic and input translation for `egui`.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use trainlab_core::protocol::{Event, OverlayCheatDto, PinOp, PinSpec};

pub static CHEATS: Mutex<Vec<OverlayCheatDto>> = Mutex::new(Vec::new());
pub static ACTIVE_PINS: Mutex<Vec<PinSpec>> = Mutex::new(Vec::new());

// Outbound event queue (events generated inside the overlay to be broadcasted over IPC)
pub static OUTBOUND_EVENTS: Mutex<Vec<Event>> = Mutex::new(Vec::new());

// Queued raw events destined for egui
static PENDING_EGUI_EVENTS: Mutex<Vec<egui::Event>> = Mutex::new(Vec::new());

// Navigation state: Active tab (0 = Cheats/Toggles, 1 = Window Control)
static ACTIVE_TAB: AtomicU64 = AtomicU64::new(0);

// Selected item index in the current active tab
static SELECTED_INDEX: AtomicU64 = AtomicU64::new(0);

// Stick debounce / trigger state
static STICK_TRIGGERED_Y: AtomicBool = AtomicBool::new(false);
static STICK_TRIGGERED_X: AtomicBool = AtomicBool::new(false);

// Active trigger flash feedback: (cheat_id, Instant of trigger)
static TRIGGER_FLASH: Mutex<Option<(u64, std::time::Instant)>> = Mutex::new(None);
// Status toast message: (Message text, is_success, Instant of event)
static STATUS_TOAST: Mutex<Option<(String, bool, std::time::Instant)>> = Mutex::new(None);

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

fn get_categories(cheats: &[OverlayCheatDto]) -> Vec<Option<String>> {
    let mut cats = Vec::new();
    // Tab 0 is always "All"
    cats.push(None);
    for c in cheats {
        if (c.kind_str == "toggle" || c.kind_str == "button")
            && let Some(g) = &c.group {
                let g_str = g.trim().to_string();
                if !g_str.is_empty() && !cats.iter().any(|existing| existing.as_deref() == Some(g_str.as_str())) {
                    cats.push(Some(g_str));
                }
            }
    }
    cats
}

fn get_active_tab_item_count() -> usize {
    let tab = ACTIVE_TAB.load(Ordering::Relaxed);
    let cheats = CHEATS.lock().map(|c| c.clone()).unwrap_or_default();
    let categories = get_categories(&cheats);
    let total_tabs = categories.len() + 1; // + 1 for Window Controls tab

    if (tab as usize) < categories.len() {
        let cat = &categories[tab as usize];
        cheats.iter().filter(|c| {
            (c.kind_str == "toggle" || c.kind_str == "button") && match cat {
                Some(g) => c.group.as_deref() == Some(g),
                None => true,
            }
        }).count().max(1)
    } else {
        // Window actions (Show GUI, Hide GUI, Disconnect)
        3
    }
}

/// Push controller button state changes and analog stick deflection into egui events.
pub fn push_controller_input(just_pressed: u16, thumb_ly: i16, thumb_lx: i16) {
    let mut events = Vec::new();
    let cheats_snap = CHEATS.lock().map(|c| c.clone()).unwrap_or_default();
    let categories = get_categories(&cheats_snap);
    let total_tabs = (categories.len() + 1) as u64;

    // 1. Tab Switching via Bumpers (LB / RB across dynamic groups + Window tab)
    if (just_pressed & XINPUT_GAMEPAD_LEFT_SHOULDER) != 0 {
        let cur_tab = ACTIVE_TAB.load(Ordering::Relaxed);
        let new_tab = if cur_tab == 0 { total_tabs.saturating_sub(1) } else { cur_tab - 1 };
        ACTIVE_TAB.store(new_tab, Ordering::Relaxed);
        SELECTED_INDEX.store(0, Ordering::Relaxed);
    }
    if (just_pressed & XINPUT_GAMEPAD_RIGHT_SHOULDER) != 0 {
        let cur_tab = ACTIVE_TAB.load(Ordering::Relaxed);
        let new_tab = (cur_tab + 1) % total_tabs.max(1);
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

    // 4. A Button (Cross / Enter) -> Toggle, Button Trigger, or Window Command
    if (just_pressed & XINPUT_GAMEPAD_A) != 0 {
        events.push(egui::Event::Key {
            key: egui::Key::Enter,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        });

        let sel = SELECTED_INDEX.load(Ordering::Relaxed) as usize;
        let cheats_snap = CHEATS.lock().map(|c| c.clone()).unwrap_or_default();
        let categories = get_categories(&cheats_snap);

        if (cur_tab as usize) < categories.len() {
            let cat = &categories[cur_tab as usize];
            if let Ok(mut cheats) = CHEATS.lock() {
                let mut toggles: Vec<&mut OverlayCheatDto> = cheats.iter_mut().filter(|c| {
                    (c.kind_str == "toggle" || c.kind_str == "button") && match cat {
                        Some(g) => c.group.as_deref() == Some(g),
                        None => true,
                    }
                }).collect();
                if sel < toggles.len() {
                    let cheat = &mut toggles[sel];
                    let id = cheat.id;
                    let is_button = cheat.kind_str == "button";

                    if is_button {
                        // Button cheat: emit CheatTriggered event
                        if let Ok(mut out) = OUTBOUND_EVENTS.lock() {
                            out.push(Event::CheatTriggered { id });
                        }
                        if let Ok(mut tf) = TRIGGER_FLASH.lock() {
                            *tf = Some((id, std::time::Instant::now()));
                        }
                        if let Ok(mut toast) = STATUS_TOAST.lock() {
                            *toast = Some((format!("Triggered '{}'", cheat.label), true, std::time::Instant::now()));
                        }
                        tracing::info!("Overlay triggered button cheat #{} '{}'", id, cheat.label);
                    } else {
                        cheat.enabled = !cheat.enabled;
                        let enabled = cheat.enabled;
                        // Emit Event::CheatToggled
                        if let Ok(mut out) = OUTBOUND_EVENTS.lock() {
                            out.push(Event::CheatToggled { id, enabled });
                        }
                        if let Ok(mut toast) = STATUS_TOAST.lock() {
                            *toast = Some((
                                format!("{} -> {}", cheat.label, if enabled { "ENABLED" } else { "DISABLED" }),
                                enabled,
                                std::time::Instant::now(),
                            ));
                        }
                        tracing::info!("Overlay toggled cheat #{} '{}' -> {}", id, cheat.label, enabled);
                    }
                }
            }
        } else {
            // Window Controls (0 = Show GUI, 1 = Hide GUI, 2 = Toggle GUI)
            let cmd = match sel {
                0 => "show",
                1 => "hide",
                _ => "show",
            };
            if let Ok(mut out) = OUTBOUND_EVENTS.lock() {
                out.push(Event::WindowCommand { command: cmd.to_string() });
            }
            if let Ok(mut toast) = STATUS_TOAST.lock() {
                *toast = Some((format!("Executed Window: {cmd}"), true, std::time::Instant::now()));
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

/// Execute on-frame value pinning for any pinned cheats and dynamic PinSpecs.
pub fn execute_pinning_cadence() {
    use trainlab_core::memory::ProcessMemory;
    let mem = trainlab_core::memory::SelfProcess;

    // 1. Legacy/simple cheat pinning
    if let Ok(cheats) = CHEATS.lock() {
        for c in cheats.iter() {
            if c.enabled
                && let Some(pinned_bytes) = &c.pinned_bytes
                    && c.address != 0 && !pinned_bytes.is_empty() {
                        let _ = mem.write(c.address, pinned_bytes);
                    }
        }
    }

    // 2. Dynamic multi-op PinSpecs (Tier 1 on-frame execution)
    if let Ok(pins) = ACTIVE_PINS.lock() {
        for pin in pins.iter() {
            if !pin.enabled {
                continue;
            }

            let mut abort_pin = false;
            for op in &pin.ops {
                if abort_pin {
                    break;
                }
                match op {
                    PinOp::AssertNotNull { address } => {
                        if *address == 0 {
                            abort_pin = true;
                            break;
                        }
                        // Check if pointer at address or the address itself is readable and non-null
                        if let Ok(buf) = mem.read(*address, 8) {
                            if buf.iter().all(|&b| b == 0) {
                                abort_pin = true;
                                break;
                            }
                        } else {
                            abort_pin = true;
                            break;
                        }
                    }
                    PinOp::WriteConstant { address, data } => {
                        if *address != 0 && !data.is_empty() {
                            let _ = mem.write(*address, data);
                        }
                    }
                    PinOp::CopyValue { src_address, dst_address, value_type, addend, max_only } => {
                        if *src_address == 0 || *dst_address == 0 {
                            abort_pin = true;
                            continue;
                        }
                        let size = value_type.size();
                        if let Ok(src_bytes) = mem.read(*src_address, size) {
                            let val_f64 = match value_type {
                                trainlab_core::scan::ValueType::I32 => {
                                    if src_bytes.len() >= 4 {
                                        i32::from_le_bytes(src_bytes[..4].try_into().unwrap()) as f64
                                    } else { 0.0 }
                                }
                                trainlab_core::scan::ValueType::U32 => {
                                    if src_bytes.len() >= 4 {
                                        u32::from_le_bytes(src_bytes[..4].try_into().unwrap()) as f64
                                    } else { 0.0 }
                                }
                                trainlab_core::scan::ValueType::F32 => {
                                    if src_bytes.len() >= 4 {
                                        f32::from_le_bytes(src_bytes[..4].try_into().unwrap()) as f64
                                    } else { 0.0 }
                                }
                                trainlab_core::scan::ValueType::I64 => {
                                    if src_bytes.len() >= 8 {
                                        i64::from_le_bytes(src_bytes[..8].try_into().unwrap()) as f64
                                    } else { 0.0 }
                                }
                                trainlab_core::scan::ValueType::U64 | trainlab_core::scan::ValueType::Ptr => {
                                    if src_bytes.len() >= 8 {
                                        u64::from_le_bytes(src_bytes[..8].try_into().unwrap()) as f64
                                    } else { 0.0 }
                                }
                                trainlab_core::scan::ValueType::F64 => {
                                    if src_bytes.len() >= 8 {
                                        f64::from_le_bytes(src_bytes[..8].try_into().unwrap())
                                    } else { 0.0 }
                                }
                            };

                            let final_val = if let Some(add) = addend {
                                val_f64 + add
                            } else {
                                val_f64
                            };

                            if *max_only {
                                if let Ok(dst_bytes) = mem.read(*dst_address, size) {
                                    let cur_dst = match value_type {
                                        trainlab_core::scan::ValueType::I32 => i32::from_le_bytes(dst_bytes[..4].try_into().unwrap_or_default()) as f64,
                                        trainlab_core::scan::ValueType::U32 => u32::from_le_bytes(dst_bytes[..4].try_into().unwrap_or_default()) as f64,
                                        trainlab_core::scan::ValueType::F32 => f32::from_le_bytes(dst_bytes[..4].try_into().unwrap_or_default()) as f64,
                                        trainlab_core::scan::ValueType::I64 => i64::from_le_bytes(dst_bytes[..8].try_into().unwrap_or_default()) as f64,
                                        trainlab_core::scan::ValueType::U64 | trainlab_core::scan::ValueType::Ptr => u64::from_le_bytes(dst_bytes[..8].try_into().unwrap_or_default()) as f64,
                                        trainlab_core::scan::ValueType::F64 => f64::from_le_bytes(dst_bytes[..8].try_into().unwrap_or_default()),
                                    };
                                    if cur_dst >= final_val {
                                        continue;
                                    }
                                }
                            }

                            let write_bytes = match value_type {
                                trainlab_core::scan::ValueType::I32 => (final_val as i32).to_le_bytes().to_vec(),
                                trainlab_core::scan::ValueType::U32 => (final_val as u32).to_le_bytes().to_vec(),
                                trainlab_core::scan::ValueType::F32 => (final_val as f32).to_le_bytes().to_vec(),
                                trainlab_core::scan::ValueType::I64 => (final_val as i64).to_le_bytes().to_vec(),
                                trainlab_core::scan::ValueType::U64 | trainlab_core::scan::ValueType::Ptr => (final_val as u64).to_le_bytes().to_vec(),
                                trainlab_core::scan::ValueType::F64 => final_val.to_le_bytes().to_vec(),
                            };
                            let _ = mem.write(*dst_address, &write_bytes);
                        } else {
                            abort_pin = true;
                        }
                    }
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
                let mut cheats = CHEATS.lock().map(|c| c.clone()).unwrap_or_default();
                let categories = get_categories(&cheats);
                let window_tab_idx = categories.len();

                // 1. Dynamic Tab Selector across categories + Window Controls
                ui.horizontal_wrapped(|ui| {
                    for (cat_idx, cat) in categories.iter().enumerate() {
                        let label = match cat {
                            Some(name) => format!("🎮 {name}"),
                            None => "🎮 All".to_string(),
                        };
                        let is_active = active_tab as usize == cat_idx;
                        let btn = if is_active {
                            egui::Button::new(&label).fill(egui::Color32::from_rgb(20, 90, 160))
                        } else {
                            egui::Button::new(&label).fill(egui::Color32::from_rgb(30, 35, 45))
                        };
                        if ui.add_sized([110.0, 26.0], btn).clicked() {
                            active_tab = cat_idx as u64;
                            ACTIVE_TAB.store(active_tab, Ordering::Relaxed);
                            SELECTED_INDEX.store(0, Ordering::Relaxed);
                        }
                    }

                    let is_win_active = active_tab as usize == window_tab_idx;
                    let win_btn = if is_win_active {
                        egui::Button::new("🖥 Window").fill(egui::Color32::from_rgb(20, 90, 160))
                    } else {
                        egui::Button::new("🖥 Window").fill(egui::Color32::from_rgb(30, 35, 45))
                    };
                    if ui.add_sized([110.0, 26.0], win_btn).clicked() {
                        active_tab = window_tab_idx as u64;
                        ACTIVE_TAB.store(active_tab, Ordering::Relaxed);
                        SELECTED_INDEX.store(0, Ordering::Relaxed);
                    }
                });

                ui.separator();
                let selected_idx = SELECTED_INDEX.load(Ordering::Relaxed) as usize;

                // Toast / action notification banner if active (< 2.5s)
                let toast_opt = STATUS_TOAST.lock().ok().and_then(|t| t.clone());
                if let Some((msg, is_ok, time)) = toast_opt {
                    let elapsed = time.elapsed().as_secs_f32();
                    if elapsed < 2.5 {
                        let alpha = ((2.5 - elapsed) / 0.5).clamp(0.0, 1.0);
                        let bg_color = if is_ok {
                            egui::Color32::from_rgba_premultiplied(10, 80, 40, (180.0 * alpha) as u8)
                        } else {
                            egui::Color32::from_rgba_premultiplied(120, 30, 30, (180.0 * alpha) as u8)
                        };
                        let text_color = if is_ok {
                            egui::Color32::from_rgba_premultiplied(150, 255, 180, (255.0 * alpha) as u8)
                        } else {
                            egui::Color32::from_rgba_premultiplied(255, 180, 180, (255.0 * alpha) as u8)
                        };

                        egui::Frame::none()
                            .fill(bg_color)
                            .rounding(egui::Rounding::same(4.0))
                            .inner_margin(egui::Margin::symmetric(8.0, 4.0))
                            .show(ui, |ui| {
                                ui.colored_label(text_color, format!("✔ {msg}"));
                            });
                        ui.add_space(2.0);
                    }
                }

                if (active_tab as usize) < categories.len() {
                    let cat = &categories[active_tab as usize];
                    let header_title = match cat {
                        Some(name) => format!("● Cheats: {name}"),
                        None => "● All Cheats & Actions".to_string(),
                    };
                    ui.colored_label(egui::Color32::LIGHT_GREEN, header_title);
                    ui.label("• LB/RB: Switch Category | D-Pad: Move | A: Toggle/Trigger");
                    ui.separator();

                    let mut toggle_cheats: Vec<&mut OverlayCheatDto> = cheats.iter_mut().filter(|c| {
                        (c.kind_str == "toggle" || c.kind_str == "button") && match cat {
                            Some(g) => c.group.as_deref() == Some(g),
                            None => true,
                        }
                    }).collect();

                    if toggle_cheats.is_empty() {
                        ui.colored_label(egui::Color32::GRAY, "No cheats or buttons registered yet.");
                        ui.label("Add cheats in trainlab-gui, load a profile, or use an AI agent.");
                    } else {
                        // Check if an item is actively flashing from a trigger
                        let active_flash = TRIGGER_FLASH.lock().ok().and_then(|f| *f);

                        for (idx, cheat) in toggle_cheats.iter_mut().enumerate() {
                            let is_selected = idx == selected_idx;
                            let is_btn = cheat.kind_str == "button";
                            let cheat_id = cheat.id;
                            let cur_enabled = cheat.enabled;

                            // Calculate flash animation (0.6s flash duration)
                            let is_flashing = match active_flash {
                                Some((id, t)) if id == cheat_id && t.elapsed().as_secs_f32() < 0.6 => true,
                                _ => false,
                            };

                            let icon = if is_flashing {
                                "⚡"
                            } else if is_btn {
                                "▶"
                            } else if cheat.enabled {
                                "🟢"
                            } else {
                                "⚪"
                            };

                            let text = format!("{icon} {}", cheat.label);
                            let mut clicked = false;

                            let (fill_col, stroke) = if is_flashing {
                                (
                                    egui::Color32::from_rgba_premultiplied(40, 200, 100, 180),
                                    egui::Stroke::new(2.5_f32, egui::Color32::from_rgb(100, 255, 180)),
                                )
                            } else if is_selected {
                                (
                                    egui::Color32::from_rgba_premultiplied(30, 140, 230, 100),
                                    egui::Stroke::new(2.0_f32, egui::Color32::from_rgb(0, 220, 255)),
                                )
                            } else {
                                (
                                    egui::Color32::from_rgba_premultiplied(20, 25, 35, 80),
                                    egui::Stroke::NONE,
                                )
                            };

                            let resp = egui::Frame::none()
                                .fill(fill_col)
                                .stroke(stroke)
                                .rounding(egui::Rounding::same(6.0))
                                .inner_margin(egui::Margin::symmetric(8.0, 5.0))
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        if is_flashing {
                                            ui.colored_label(egui::Color32::WHITE, egui::RichText::new(&text).strong());
                                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                                ui.colored_label(egui::Color32::LIGHT_GREEN, "FIRED!");
                                            });
                                        } else {
                                            ui.label(text);
                                        }
                                    })
                                });

                            if resp.response.interact(egui::Sense::click()).clicked() {
                                clicked = true;
                                if !is_selected {
                                    SELECTED_INDEX.store(idx as u64, Ordering::Relaxed);
                                }
                            }

                            if clicked {
                                if is_btn {
                                    if let Ok(mut out) = OUTBOUND_EVENTS.lock() {
                                        out.push(Event::CheatTriggered { id: cheat_id });
                                    }
                                    if let Ok(mut tf) = TRIGGER_FLASH.lock() {
                                        *tf = Some((cheat_id, std::time::Instant::now()));
                                    }
                                    if let Ok(mut toast) = STATUS_TOAST.lock() {
                                        *toast = Some((format!("Triggered '{}'", cheat.label), true, std::time::Instant::now()));
                                    }
                                    tracing::info!("Overlay clicked button cheat #{} '{}'", cheat_id, cheat.label);
                                } else {
                                    cheat.enabled = !cur_enabled;
                                    let new_en = cheat.enabled;
                                    if let Ok(mut out) = OUTBOUND_EVENTS.lock() {
                                        out.push(Event::CheatToggled { id: cheat_id, enabled: new_en });
                                    }
                                    if let Ok(mut toast) = STATUS_TOAST.lock() {
                                        *toast = Some((
                                            format!("{} -> {}", cheat.label, if new_en { "ENABLED" } else { "DISABLED" }),
                                            new_en,
                                            std::time::Instant::now(),
                                        ));
                                    }
                                    tracing::info!("Overlay clicked toggle cheat #{} '{}' -> {}", cheat_id, cheat.label, new_en);
                                }
                            }
                            ui.separator();
                        }
                    }
                } else {
                    // TAB 1: Window Actions
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

                        let mut clicked_action = false;
                        if is_selected {
                            let resp = egui::Frame::none()
                                .fill(egui::Color32::from_rgba_premultiplied(30, 140, 230, 100))
                                .stroke(egui::Stroke::new(2.0_f32, egui::Color32::from_rgb(0, 220, 255)))
                                .rounding(egui::Rounding::same(6.0))
                                .inner_margin(egui::Margin::symmetric(8.0, 6.0))
                                .show(ui, |ui| {
                                    row_content(ui);
                                });
                            if resp.response.interact(egui::Sense::click()).clicked() {
                                clicked_action = true;
                            }
                        } else {
                            let resp = egui::Frame::none()
                                .fill(egui::Color32::from_rgba_premultiplied(20, 25, 35, 80))
                                .rounding(egui::Rounding::same(6.0))
                                .inner_margin(egui::Margin::symmetric(8.0, 6.0))
                                .show(ui, |ui| {
                                    row_content(ui);
                                });
                            if resp.response.interact(egui::Sense::click()).clicked() {
                                clicked_action = true;
                                SELECTED_INDEX.store(idx as u64, Ordering::Relaxed);
                            }
                        }

                        if clicked_action {
                            let cmd = match idx {
                                0 => "show",
                                1 => "hide",
                                _ => "show",
                            };
                            if let Ok(mut out) = OUTBOUND_EVENTS.lock() {
                                out.push(Event::WindowCommand { command: cmd.to_string() });
                            }
                            if let Ok(mut toast) = STATUS_TOAST.lock() {
                                *toast = Some((format!("Executed Window: {cmd}"), true, std::time::Instant::now()));
                            }
                            tracing::info!("Overlay clicked window action #{} -> '{}'", idx, cmd);
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
