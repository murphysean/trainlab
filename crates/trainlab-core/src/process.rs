//! Lightweight process discovery / enumeration helpers.
//!
//! These are used by the scanner and GUI to find a game process by name or
//! PID. On Linux we read `/proc`; on Windows we'd use the toolhelp API.

/// A discovered process.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: i32,
    pub name: String,
}

/// List all processes on the system.
#[cfg(unix)]
pub fn list() -> Vec<ProcessInfo> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Ok(pid) = name.parse::<i32>() {
                let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
                    .unwrap_or_default();
                let comm = comm.trim().to_string();
                if !comm.is_empty() {
                    out.push(ProcessInfo { pid, name: comm });
                }
            }
        }
    }
    out
}

/// List all processes on the system (non-Unix stub).
#[cfg(not(unix))]
pub fn list() -> Vec<ProcessInfo> {
    Vec::new()
}

/// Find a process by exact name match (case-insensitive).
pub fn find_by_name(name: &str) -> Option<ProcessInfo> {
    let lower = name.to_lowercase();
    list()
        .into_iter()
        .find(|p| p.name.to_lowercase() == lower)
}

/// Find a process by PID.
pub fn find_by_pid(pid: i32) -> Option<ProcessInfo> {
    list().into_iter().find(|p| p.pid == pid)
}
