//! Portable cheat profiles (YAML cheat tables).
//!
//! A `GameProfile` describes a game's discovered layout: the setup steps to
//! find base addresses (AOB scans, pointer chains, module-relative addresses)
//! and the cheats that reference them. It's the "portable game file" — an
//! LLM-friendly, versionable YAML file that lives in a `cheats/` directory
//! next to the GUI executable.
//!
//! See `docs/CHEAT_PROFILE.md` for the full design.

use serde::{Deserialize, Serialize};

/// A versioned cheat profile for one game.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameProfile {
    /// Schema version tag, e.g. "trainlab-profile/v1".
    pub schema: String,
    /// The game executable this profile targets (e.g. "Unrailed2.exe").
    pub game: String,
    /// Human-readable name for the profile.
    pub name: String,
    /// Whether to inject the agent DLL on attach.
    #[serde(default = "default_true")]
    pub inject_dll: bool,
    /// Profile version (for sharing/patching).
    #[serde(default)]
    pub version: String,
    /// Target game version this profile was built upon (e.g. "1.1.73p", "1.0.239p").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub game_version: Option<String>,
    /// Date the profile was created / last verified (e.g. "2026-08-25").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    /// Profile author or source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    /// Setup steps that resolve base addresses for the current launch.
    #[serde(default)]
    pub setup: Vec<SetupStep>,
    /// Optional initialization commands executed automatically when profile attaches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub init_commands: Option<Vec<ProfileCommand>>,
    /// Optional render & overlay configuration for the injected DLL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub render: Option<RenderConfig>,
    /// The cheats that show up in the GUI Cheats panel.
    #[serde(default)]
    pub cheats: Vec<ProfileCheat>,
}

/// Optional overlay and graphics hook settings for the game profile.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RenderConfig {
    /// Whether to hook Present/EndScene and render the in-game overlay (default true).
    #[serde(default = "default_true")]
    pub overlay: bool,
    /// Whether to install WndProc message hooks for hotkeys (default true).
    #[serde(default = "default_true")]
    pub hook_wndproc: bool,
    /// Whether to poll XInput for controller shortcuts (default true).
    #[serde(default = "default_true")]
    pub xinput_hooks: bool,
}

fn default_true() -> bool {
    true
}

/// A setup step that resolves a named base address for the current launch.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SetupStep {
    /// AOB scan for a code/static pattern; the match (optionally + offset)
    /// becomes a named base address.
    AobScan {
        /// Name to store the resolved address under.
        name: String,
        /// AOB pattern in hex with `??` wildcards.
        pattern: String,
        /// Optional byte offset to add to the first match.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        offset: Option<i64>,
        /// Optional module name (e.g. "sins2.exe") or region marker to bound the scan to.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        region: Option<String>,
    },
    /// A pointer chain resolved against a module base each launch.
    PointerChain {
        /// Name to store the resolved address under.
        name: String,
        /// Module name (e.g. "Unrailed2.exe") to resolve the base against.
        module: String,
        /// Module-relative base offset.
        base: String,
        /// Field offsets applied in order.
        #[serde(default)]
        offsets: Vec<String>,
    },
    /// A direct module-relative address (stable across launches).
    Address {
        /// Name to store the resolved address under.
        name: String,
        /// Module name.
        module: String,
        /// Module-relative offset.
        offset: String,
    },
}

impl SetupStep {
    /// The name of this setup step (e.g. for storing its resolved base address).
    pub fn name(&self) -> &str {
        match self {
            SetupStep::AobScan { name, .. }
            | SetupStep::PointerChain { name, .. }
            | SetupStep::Address { name, .. } => name,
        }
    }
}

/// A user-facing adjustable game option in a profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileCheat {
    /// Unique id within the profile.
    pub id: String,
    /// Display label.
    pub label: String,
    /// Cheat kind: "value" or "toggle".
    pub kind: String,
    /// For value cheats: the value type (i32, u32, f32, i64, u64, f64, ptr).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_type: Option<String>,
    /// Reference to a named setup base address (from `setup`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_ref: Option<String>,
    /// For toggle cheats: reference to a named setup target instruction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_ref: Option<String>,
    /// For toggle cheats: hook kind ("trampoline" or "override").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hook: Option<String>,
    /// For toggle cheats: shellcode payload (hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    /// For toggle cheats: optional Cheat-Engine-style assembly text. If present, this is
    /// assembled (via the assemble_asm engine) into the shellcode payload bytes at profile load,
    /// so you can author the cheat in readable asm instead of hand-encoded hex. Supports
    /// `[rip + label]` constant slots, `dd (float)X` / `dd 100` / `dq ...` directives, etc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asm: Option<String>,
    /// For toggle cheats: jump style ("absolute" or "relative").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jump: Option<String>,
    /// Pinning mechanism: "cave" (in-loop) or "timer" (re-write at rate_hz).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mechanism: Option<String>,
    /// For timer mechanism: re-write rate in Hz.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_hz: Option<u32>,
    /// For value cheats: a known/initial value to populate (e.g. "400").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// For struct cheats: base address or marker expression (e.g. "$player_base").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
    /// For struct cheats: the list of child fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<crate::session::StructField>>,
    /// For button cheats: a sequence of commands to execute when pressed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commands: Option<Vec<ProfileCommand>>,
    /// Optional grouping/category name (e.g. "In Menu", "In Session", "Player", "Weapons").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Optional hotkey binding string (e.g. "Num 1", "Shift+Alt+K", "F1").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hotkey: Option<String>,
    /// Optional flag to hide this cheat from the user-facing GUI and in-game overlay (e.g. agent/WIP/transport cheats).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hidden: Option<bool>,
    /// Optional human note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// A single step in a button cheat's command sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProfileCommand {
    /// Write a value to memory.
    Write {
        /// Target address or reference (e.g. "wood_addr" or "0x1000").
        #[serde(default, skip_serializing_if = "Option::is_none")]
        address_ref: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        address: Option<String>,
        /// Value string (e.g. "99990" or "0xe890000").
        value: String,
        /// Optional value_type (e.g. "i32", "f32", "ptr").
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value_type: Option<String>,
        /// Optional note / comment.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    },
    /// Install or toggle a code cave hook.
    InstallCave {
        /// Target code address or reference.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target_ref: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target: Option<String>,
        /// Hook kind ("trampoline" or "override").
        #[serde(default = "default_hook_kind")]
        hook: String,
        /// Jump style ("absolute" for 14-byte long jump, "relative" for 5-byte short jump).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        jump: Option<String>,
        /// Shellcode payload hex string (mutually exclusive with asm).
        #[serde(default)]
        payload: String,
        /// Optional assembly source text (mutually exclusive with payload).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        asm: Option<String>,
        /// Optional marker label to store the cave address under.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        marker: Option<String>,
        /// Optional note / comment.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    },
    /// Allocate a string inside target memory.
    AllocateString {
        /// String text content (optional if size is provided).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        content: Option<String>,
        /// Buffer size in bytes (optional if content is provided).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        size: Option<usize>,
        /// Optional byte to fill allocated buffer with.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fill_byte: Option<u8>,
        /// Layout kind ("c", "rust", "json", "yaml", "xml", "js", "config").
        #[serde(default = "default_string_kind", rename = "kind")]
        string_kind: String,
        /// Optional marker label to store the allocated string pointer under.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        marker: Option<String>,
        /// Optional note / comment.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    },
    /// Allocate raw memory buffer of a specified size in bytes.
    AllocateMemory {
        /// Buffer size in bytes.
        size: usize,
        /// Optional marker label to store the allocated memory address under.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        marker: Option<String>,
        /// Optional fill byte value.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fill_byte: Option<u8>,
        /// Optional protection permissions ("rw", "rwx", "rx", "r").
        #[serde(default, skip_serializing_if = "Option::is_none")]
        permissions: Option<String>,
        /// Optional note / comment.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    },
    /// Free / deallocate a previously allocated memory region or buffer.
    FreeMemory {
        /// Address expression or marker name to free (e.g. "$scratch_buf").
        address: String,
        /// Optional size in bytes to decommit.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        size: Option<usize>,
        /// Optional note / comment.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    },
    /// Perform an AOB pattern scan and optionally store the first match in a marker.
    AobScan {
        /// Name of the marker to store the first match address in.
        marker: String,
        /// Hex pattern string with wildcards (e.g. "48 8b 05 ?? ?? ?? ??").
        pattern: String,
        /// Optional offset added to the match address.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        offset: Option<i64>,
        /// Optional module name (e.g. "sins2.exe") or region marker to bound the scan to.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        region: Option<String>,
        /// Optional note / comment.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    },
    /// Perform a pointer chase and store the final target address in a marker.
    PointerChase {
        /// Name of the marker to store the resolved pointer address in.
        marker: String,
        /// Base address expression (e.g. "game.exe+0x1b42e9" or "$my_marker").
        base: String,
        /// Pointer offsets (e.g. ["0x10", "0x28"]).
        #[serde(default)]
        offsets: Vec<String>,
        /// Optional note / comment.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    },
    /// Assert that memory at an address matches an expected value/expression (aborts sequence if failed).
    Assert {
        /// Address or marker reference to inspect.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        address_ref: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        address: Option<String>,
        /// Expected value string (e.g. "0x01", "9999", or non-null check "!0x0").
        expected: String,
        /// Optional value type ("i32", "f32", "ptr", "u32").
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value_type: Option<String>,
        /// Optional note / comment.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    },
    /// Set or compute a marker address in the session (e.g. derived slot from another marker).
    SetMarker {
        /// Name of the marker to create or update.
        marker: String,
        /// Address expression (marker + offset, module + offset, raw hex/dec).
        address: String,
        /// Optional note / comment.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    },
    /// Sleep/delay execution for a specified duration in milliseconds.
    Wait {
        /// Delay duration in milliseconds (e.g. 5000 for 5 seconds).
        ms: u64,
        /// Optional note / comment.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    },
}

fn default_hook_kind() -> String {
    "trampoline".to_string()
}

fn default_string_kind() -> String {
    "c".to_string()
}

impl GameProfile {
    /// The default schema tag for v1 profiles.
    pub const SCHEMA_V1: &'static str = "trainlab-profile/v1";

    /// Serialize this profile to YAML.
    pub fn to_yaml(&self) -> Result<String, String> {
        serde_yaml::to_string(self).map_err(|e| format!("yaml serialize: {e}"))
    }

    /// Parse a profile from YAML.
    pub fn from_yaml(s: &str) -> Result<Self, String> {
        serde_yaml::from_str(s).map_err(|e| format!("yaml parse: {e}"))
    }
}

/// The default directory (relative to the GUI exe) where profiles live.
pub const PROFILES_DIR: &str = "cheats";

/// Result of attempting to discover and load a profile file from disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DiscoveredProfile {
    /// Successfully parsed profile.
    Valid {
        file: String,
        profile: GameProfile,
    },
    /// Failed to parse profile YAML, containing the parse error.
    Invalid {
        file: String,
        error: String,
    },
}

/// Discover all profile files in `cheats/`, returning both valid profiles and any invalid files with errors.
pub fn discover_all_profiles() -> Vec<DiscoveredProfile> {
    let dir = profiles_dir_path();
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return out,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let is_yaml = path
            .extension()
            .map(|e| e == "yaml" || e == "yml")
            .unwrap_or(false);
        if !is_yaml {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        match std::fs::read_to_string(&path) {
            Ok(text) => match GameProfile::from_yaml(&text) {
                Ok(profile) => out.push(DiscoveredProfile::Valid { file: name, profile }),
                Err(err) => {
                    eprintln!("[PROFILE] failed to parse cheats/{name}: {err}");
                    out.push(DiscoveredProfile::Invalid { file: name, error: err });
                }
            },
            Err(e) => {
                eprintln!("[PROFILE] failed to read cheats/{name}: {e}");
                out.push(DiscoveredProfile::Invalid {
                    file: name,
                    error: format!("file read error: {e}"),
                });
            }
        }
    }
    out
}

/// Discover profile files in the `cheats/` directory next to the executable.
///
/// Returns a list of `(file_name, profile)` for every `*.yaml`/`*.yml` file
/// that parses as a valid `GameProfile`.
pub fn discover_profiles() -> Vec<(String, GameProfile)> {
    discover_all_profiles()
        .into_iter()
        .filter_map(|dp| match dp {
            DiscoveredProfile::Valid { file, profile } => Some((file, profile)),
            DiscoveredProfile::Invalid { .. } => None,
        })
        .collect()
}

/// The absolute path to the profiles directory (next to the GUI exe).
pub fn profiles_dir_path() -> std::path::PathBuf {
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent() {
            return dir.join(PROFILES_DIR);
        }
    std::path::PathBuf::from(PROFILES_DIR)
}

/// Find a profile whose `game` matches a running process name (case-insensitive).
pub fn find_profile_for_game<'a>(
    profiles: &'a [(String, GameProfile)],
    game_exe: &str,
) -> Option<&'a (String, GameProfile)> {
    let target = game_exe.to_lowercase();
    profiles
        .iter()
        .find(|(_, p)| p.game.to_lowercase() == target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_roundtrips_yaml() {
        let p = GameProfile {
            schema: GameProfile::SCHEMA_V1.into(),
            game: "Unrailed2.exe".into(),
            name: "Unrailed 2 resources".into(),
            inject_dll: true,
            version: "1.0.0".into(),
            game_version: None,
            date: None,
            author: None,
            setup: vec![
                SetupStep::AobScan {
                    name: "god_mode_ret".into(),
                    pattern: "48 8B 05 ?? ?? ?? ??".into(),
                    offset: Some(3),
                    region: None,
                },
                SetupStep::PointerChain {
                    name: "player_base".into(),
                    module: "Unrailed2.exe".into(),
                    base: "+0x0123A400".into(),
                    offsets: vec!["0x10".into(), "0x28".into()],
                },
            ],
            init_commands: None,
            render: None,
            cheats: vec![ProfileCheat {
                id: "wood".into(),
                label: "Wood".into(),
                kind: "value".into(),
                value_type: Some("i32".into()),
                address_ref: Some("wood_addr".into()),
                target_ref: None,
                hook: None,
                payload: None,
                asm: None,
                jump: None,
                mechanism: Some("cave".into()),
                rate_hz: None,
                value: Some("400".into()),
                base: None,
                fields: None,
                commands: None,
                group: None,
                hotkey: None,
                hidden: None,
                note: Some("wood stock".into()),
            }],
        };
        let yaml = p.to_yaml().expect("serialize");
        let back = GameProfile::from_yaml(&yaml).expect("parse");
        assert_eq!(back.game, "Unrailed2.exe");
        assert_eq!(back.cheats.len(), 1);
        assert_eq!(back.cheats[0].label, "Wood");
        assert_eq!(back.cheats[0].value.as_deref(), Some("400"));
        assert_eq!(back.setup.len(), 2);
    }

    #[test]
    fn find_profile_matches_game_case_insensitive() {
        let p = GameProfile {
            schema: GameProfile::SCHEMA_V1.into(),
            game: "Unrailed2.exe".into(),
            name: "x".into(),
            inject_dll: true,
            version: "".into(),
            game_version: None,
            date: None,
            author: None,
            setup: vec![],
            init_commands: None,
            render: None,
            cheats: vec![],
        };
        let profiles = vec![("Unrailed2.yaml".to_string(), p)];
        assert!(find_profile_for_game(&profiles, "unrailed2.EXE").is_some());
        assert!(find_profile_for_game(&profiles, "other.exe").is_none());
    }

    /// A toggle cheat may carry CE-style assembly text (`asm`) instead of (or in addition to)
    /// pre-assembled hex (`payload`). Verify the `asm` field round-trips through YAML.
    #[test]
    fn asm_field_roundtrips_yaml() {
        let p = GameProfile {
            schema: GameProfile::SCHEMA_V1.into(),
            game: "DRG Survivor.exe".into(),
            name: "asm test".into(),
            inject_dll: true,
            version: "".into(),
            game_version: None,
            date: None,
            author: None,
            setup: vec![],
            init_commands: None,
            render: None,
            cheats: vec![ProfileCheat {
                id: "mining_speed".into(),
                label: "Mining Speedhack (4x)".into(),
                kind: "toggle".into(),
                value_type: None,
                address_ref: None,
                target_ref: Some("mining_speed".into()),
                hook: Some("override".into()),
                payload: None,
                asm: Some("miningSpeedValue:\n  dd (float)4.0\ndivss xmm2, [rip + miningSpeedValue]".into()),
                jump: Some("relative".into()),
                mechanism: None,
                rate_hz: None,
                value: None,
                base: None,
                fields: None,
                commands: None,
                group: Some("Speed".into()),
                hotkey: None,
                hidden: None,
                note: Some("mining speed test".into()),
            }],
        };
        let yaml = p.to_yaml().expect("serialize");
        let back = GameProfile::from_yaml(&yaml).expect("parse");
        let c = &back.cheats[0];
        assert_eq!(c.id, "mining_speed");
        assert_eq!(c.kind, "toggle");
        assert_eq!(c.jump.as_deref(), Some("relative"));
        // The asm source must round-trip exactly.
        let expected_asm = "miningSpeedValue:\n  dd (float)4.0\ndivss xmm2, [rip + miningSpeedValue]";
        assert_eq!(c.asm.as_deref(), Some(expected_asm));
    }

    #[test]
    fn set_marker_command_roundtrips_yaml() {
        let yaml = r#"
schema: trainlab-profile/v1
game: DRG Survivor.exe
name: Test SetMarker
inject_dll: true
init_commands:
  - type: set_marker
    marker: gc_slot
    address: "gc_cave+0x44"
cheats: []
"#;
        let profile = GameProfile::from_yaml(yaml).expect("parse yaml");
        let init_cmds = profile.init_commands.as_ref().expect("init commands");
        assert_eq!(init_cmds.len(), 1);
        match &init_cmds[0] {
            ProfileCommand::SetMarker { marker, address, .. } => {
                assert_eq!(marker, "gc_slot");
                assert_eq!(address, "gc_cave+0x44");
            }
            _ => panic!("expected SetMarker variant"),
        }
        let serialized = profile.to_yaml().expect("serialize");
        let back = GameProfile::from_yaml(&serialized).expect("roundtrip parse");
        assert_eq!(back.name, "Test SetMarker");
    }

    #[test]
    fn install_cave_with_asm_roundtrips_yaml() {
        let yaml = r#"
schema: trainlab-profile/v1
game: helldivers.exe
name: Test InstallCave ASM
inject_dll: true
init_commands:
  - type: install_cave
    target_ref: zlua_gettop
    hook: override
    jump: relative
    asm: |
      sub rax, [rcx + 0x10]
      sar rax, 3
      ret
    marker: eval_cave
cheats: []
"#;
        let profile = GameProfile::from_yaml(yaml).expect("parse yaml");
        let init_cmds = profile.init_commands.as_ref().expect("init commands");
        assert_eq!(init_cmds.len(), 1);
        match &init_cmds[0] {
            ProfileCommand::InstallCave { target_ref, hook, jump, asm, marker, .. } => {
                assert_eq!(target_ref.as_deref(), Some("zlua_gettop"));
                assert_eq!(hook, "override");
                assert_eq!(jump.as_deref(), Some("relative"));
                assert!(asm.is_some());
                assert_eq!(marker.as_deref(), Some("eval_cave"));
            }
            _ => panic!("expected InstallCave variant"),
        }
        let serialized = profile.to_yaml().expect("serialize");
        let back = GameProfile::from_yaml(&serialized).expect("roundtrip parse");
        assert_eq!(back.name, "Test InstallCave ASM");
    }

    #[test]
    fn test_aob_scan_with_region_roundtrips_yaml() {
        let yaml = r#"
schema: trainlab-profile/v1
game: sins2.exe
name: Test Sins2 AobScan Region
setup:
  - type: aob_scan
    name: influence_hook
    pattern: "8B B7 ?? ?? ?? ?? 39 B3"
    offset: 0
    region: "sins2.exe"
cheats: []
"#;
        let profile = GameProfile::from_yaml(yaml).expect("parse yaml");
        assert_eq!(profile.setup.len(), 1);
        match &profile.setup[0] {
            SetupStep::AobScan { name, pattern, offset, region } => {
                assert_eq!(name, "influence_hook");
                assert_eq!(pattern, "8B B7 ?? ?? ?? ?? 39 B3");
                assert_eq!(*offset, Some(0));
                assert_eq!(region.as_deref(), Some("sins2.exe"));
            }
            _ => panic!("expected AobScan variant"),
        }
        let serialized = profile.to_yaml().expect("serialize");
        let back = GameProfile::from_yaml(&serialized).expect("roundtrip parse");
        assert_eq!(back.name, "Test Sins2 AobScan Region");
    }

    #[test]
    fn test_helldivers_yaml_with_command_notes_parses_cleanly() {
        let helldivers_yaml_path = std::path::Path::new("/home/sean/Documents/Gaming/helldivers/helldivers.yaml");
        if helldivers_yaml_path.exists() {
            let content = std::fs::read_to_string(helldivers_yaml_path).expect("read helldivers.yaml");
            let profile = GameProfile::from_yaml(&content).expect("helldivers.yaml must parse cleanly");
            assert_eq!(profile.game, "helldivers.exe");
            assert!(profile.init_commands.is_some());
            assert!(!profile.cheats.is_empty());
        }
    }
}
