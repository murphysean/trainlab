//! User and environment configuration for `trainlab-gui`.
//!
//! Loads options from `config.yaml` or `trainlab.yaml` placed in the current directory,
//! the executable's directory, or `%APPDATA%/trainlab/config.yaml`.
//!
//! Environment variables (e.g. `TRAINLAB_SCALE`, `TRAINLAB_MCP_HOST`, `TRAINLAB_MCP_PORT`,
//! `TRAINLAB_DLL_HOST`, `TRAINLAB_DLL_PORT`) override file settings.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use trainlab_core::protocol::InjectFeaturesConfig;

/// Root configuration structure.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    #[serde(default)]
    pub gui: GuiConfig,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub inject: InjectConfig,
    /// Injected DLL feature enablement configuration (permissive/opt-out defaults).
    #[serde(default)]
    pub inject_features: InjectFeaturesConfig,
}

/// GUI window & appearance settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuiConfig {
    /// UI scale multiplier (DPI scaling / pixels_per_point). Default is 1.0.
    /// On high-DPI displays or small laptop screens, set to e.g. 1.25, 1.5, or 2.0.
    #[serde(default = "default_scale")]
    pub scale: f32,
    /// Default window width in logical points (default 1280.0).
    #[serde(default = "default_width")]
    pub width: f32,
    /// Default window height in logical points (default 800.0).
    #[serde(default = "default_height")]
    pub height: f32,
    /// Force fullscreen / maximized mode.
    #[serde(default)]
    pub fullscreen: bool,
    /// UI Theme ("dark" or "light").
    #[serde(default = "default_theme")]
    pub theme: String,
}

impl Default for GuiConfig {
    fn default() -> Self {
        Self {
            scale: default_scale(),
            width: default_width(),
            height: default_height(),
            fullscreen: false,
            theme: default_theme(),
        }
    }
}

fn default_scale() -> f32 {
    1.0
}
fn default_width() -> f32 {
    1280.0
}
fn default_height() -> f32 {
    800.0
}
fn default_theme() -> String {
    "dark".to_string()
}

/// MCP & Web server binding options. Permissive 0.0.0.0 by default.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Host address to bind the MCP / HTTP web server on.
    /// Defaults to "0.0.0.0" for LAN access, configurable to "127.0.0.1" for localhost-only.
    #[serde(default = "default_mcp_host")]
    pub mcp_host: String,
    /// Port to listen on (default 8123).
    #[serde(default = "default_mcp_port")]
    pub mcp_port: u16,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            mcp_host: default_mcp_host(),
            mcp_port: default_mcp_port(),
        }
    }
}

fn default_mcp_host() -> String {
    "0.0.0.0".to_string()
}
fn default_mcp_port() -> u16 {
    8123
}

/// Injected DLL default connection settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectConfig {
    /// Host of the injected DLL listener (default "127.0.0.1").
    #[serde(default = "default_dll_host")]
    pub dll_host: String,
    /// Port of the injected DLL listener (default 31337).
    #[serde(default = "default_dll_port")]
    pub dll_port: u16,
    /// Default DLL binary path or filename.
    #[serde(default = "default_dll_path")]
    pub dll_path: String,
}

impl Default for InjectConfig {
    fn default() -> Self {
        Self {
            dll_host: default_dll_host(),
            dll_port: default_dll_port(),
            dll_path: default_dll_path(),
        }
    }
}

fn default_dll_host() -> String {
    "127.0.0.1".to_string()
}
fn default_dll_port() -> u16 {
    31337
}
fn default_dll_path() -> String {
    "trainlab_inject.dll".to_string()
}

impl AppConfig {
    /// Load configuration by searching standard paths, then applying environment overrides.
    pub fn load() -> Self {
        let mut cfg = Self::find_and_parse().unwrap_or_default();
        cfg.apply_env_overrides();
        cfg
    }

    /// Search candidate config file paths.
    fn find_and_parse() -> Option<Self> {
        let candidates = [
            PathBuf::from("config.yaml"),
            PathBuf::from("config.yml"),
            PathBuf::from("trainlab.yaml"),
            PathBuf::from("trainlab.yml"),
        ];

        for path in &candidates {
            if path.is_file()
                && let Ok(content) = std::fs::read_to_string(path)
                && let Ok(parsed) = serde_yaml::from_str::<Self>(&content) {
                    tracing::info!("Loaded configuration from {}", path.display());
                    return Some(parsed);
                }
        }

        // Check next to the executable if different from current dir
        if let Ok(exe_path) = std::env::current_exe()
            && let Some(exe_dir) = exe_path.parent() {
                for file_name in &["config.yaml", "config.yml", "trainlab.yaml", "trainlab.yml"] {
                    let candidate = exe_dir.join(file_name);
                    if candidate.is_file()
                        && let Ok(content) = std::fs::read_to_string(&candidate)
                        && let Ok(parsed) = serde_yaml::from_str::<Self>(&content) {
                            tracing::info!("Loaded configuration from {}", candidate.display());
                            return Some(parsed);
                        }
                }
            }

        None
    }

    /// Apply environment variable overrides (precedence over config file).
    pub fn apply_env_overrides(&mut self) {
        // GUI Scale / DPI factor
        if let Ok(val) = std::env::var("TRAINLAB_SCALE").or_else(|_| std::env::var("TRAINLAB_DPI_SCALE"))
            && let Ok(scale) = val.parse::<f32>()
            && scale > 0.1 {
                self.gui.scale = scale;
            }

        // GUI Dimensions
        if let Ok(val) = std::env::var("TRAINLAB_WIDTH")
            && let Ok(w) = val.parse::<f32>()
            && w > 200.0 {
                self.gui.width = w;
            }
        if let Ok(val) = std::env::var("TRAINLAB_HEIGHT")
            && let Ok(h) = val.parse::<f32>()
            && h > 200.0 {
                self.gui.height = h;
            }

        // Fullscreen
        if let Ok(val) = std::env::var("TRAINLAB_FULLSCREEN") {
            self.gui.fullscreen = val == "1" || val.eq_ignore_ascii_case("true");
        }

        // MCP Server Host (localhost vs 0.0.0.0 LAN)
        if let Ok(val) = std::env::var("TRAINLAB_MCP_HOST") {
            let trimmed = val.trim().to_string();
            if !trimmed.is_empty() {
                self.server.mcp_host = trimmed;
            }
        }

        // MCP Server Port
        if let Ok(val) = std::env::var("TRAINLAB_MCP_PORT")
            && let Ok(port) = val.parse::<u16>() {
                self.server.mcp_port = port;
            }

        // DLL Host & Port
        if let Ok(val) = std::env::var("TRAINLAB_DLL_HOST") {
            let trimmed = val.trim().to_string();
            if !trimmed.is_empty() {
                self.inject.dll_host = trimmed;
            }
        }
        if let Ok(val) = std::env::var("TRAINLAB_DLL_PORT")
            && let Ok(port) = val.parse::<u16>() {
                self.inject.dll_port = port;
            }
        if let Ok(val) = std::env::var("TRAINLAB_DLL_PATH") {
            let trimmed = val.trim().to_string();
            if !trimmed.is_empty() {
                self.inject.dll_path = trimmed;
            }
        }
    }
}
