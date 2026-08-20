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
    /// Setup steps that resolve base addresses for the current launch.
    #[serde(default)]
    pub setup: Vec<SetupStep>,
    /// The cheats that show up in the GUI Cheats panel.
    #[serde(default)]
    pub cheats: Vec<ProfileCheat>,
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
    /// Pinning mechanism: "cave" (in-loop) or "timer" (re-write at rate_hz).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mechanism: Option<String>,
    /// For timer mechanism: re-write rate in Hz.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_hz: Option<u32>,
    /// For value cheats: a known/initial value to populate (e.g. "400").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// For button cheats: a sequence of commands to execute when pressed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commands: Option<Vec<ProfileCommand>>,
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
        /// Shellcode payload hex string.
        #[serde(default)]
        payload: String,
        /// Optional marker label to store the cave address under.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        marker: Option<String>,
    },
    /// Allocate a string inside target memory.
    AllocateString {
        /// String text content.
        content: String,
        /// Layout kind ("c", "rust", "json", "yaml", "xml", "js", "config").
        #[serde(default = "default_string_kind")]
        kind: String,
        /// Optional marker label to store the allocated string pointer under.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        marker: Option<String>,
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

/// Discover profile files in the `cheats/` directory next to the executable.
///
/// Returns a list of `(file_name, profile)` for every `*.yaml`/`*.yml` file
/// that parses as a `GameProfile`.
pub fn discover_profiles() -> Vec<(String, GameProfile)> {
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
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(profile) = GameProfile::from_yaml(&text) {
                out.push((name, profile));
            }
        }
    }
    out
}

/// The absolute path to the profiles directory (next to the GUI exe).
pub fn profiles_dir_path() -> std::path::PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            return dir.join(PROFILES_DIR);
        }
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
            setup: vec![
                SetupStep::AobScan {
                    name: "god_mode_ret".into(),
                    pattern: "48 8B 05 ?? ?? ?? ??".into(),
                    offset: Some(3),
                },
                SetupStep::PointerChain {
                    name: "player_base".into(),
                    module: "Unrailed2.exe".into(),
                    base: "+0x0123A400".into(),
                    offsets: vec!["0x10".into(), "0x28".into()],
                },
            ],
            cheats: vec![ProfileCheat {
                id: "wood".into(),
                label: "Wood".into(),
                kind: "value".into(),
                value_type: Some("i32".into()),
                address_ref: Some("wood_addr".into()),
                target_ref: None,
                hook: None,
                payload: None,
                mechanism: Some("cave".into()),
                rate_hz: None,
                value: Some("400".into()),
                commands: None,
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
            setup: vec![],
            cheats: vec![],
        };
        let profiles = vec![("Unrailed2.yaml".to_string(), p)];
        assert!(find_profile_for_game(&profiles, "unrailed2.EXE").is_some());
        assert!(find_profile_for_game(&profiles, "other.exe").is_none());
    }
}
