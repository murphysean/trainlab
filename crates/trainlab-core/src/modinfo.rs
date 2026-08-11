//! Resolve an address to a loaded module (DLL/exe) — the restart-stable handle
//! used by pointer-chasing and "which function is this in?".
//!
//! A raw address like `0x73869f1d` is useless across launches, but
//! `Urbek.exe+0x12345` or `mono-2.0-bdwgc.dll+0x6789` is stable. This module
//! enumerates the target process's loaded modules and matches an address to
//! one of them.

use crate::memory::{MemoryError, Region};

/// A loaded module in a target process.
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    /// Module base address.
    pub base: u64,
    /// Module image size (not necessarily covering all of its mappings, but
    /// the base+size range is where its exported/entry code lives).
    pub size: u64,
    /// Module file name, e.g. "Urbek.exe" or "mono-2.0-bdwgc.dll".
    pub name: String,
    /// Full path if known.
    pub path: Option<String>,
}

impl ModuleInfo {
    /// True if `addr` falls within this module's base..base+size range.
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.base + self.size
    }

    /// Format `addr` as a module-relative offset, e.g. `Urbek.exe+0x1234`.
    pub fn format_offset(&self, addr: u64) -> String {
        format!("{}+0x{:x}", self.name, addr.wrapping_sub(self.base))
    }
}

/// Best-effort resolution of `addr` against a set of known modules.
///
/// `modules` is a list of loaded modules (see [`enumerate_windows`] or, on
/// non-Windows, a caller-provided list). Returns the first module whose range
/// contains `addr`.
pub fn find_module<'a>(modules: &'a [ModuleInfo], addr: u64) -> Option<&'a ModuleInfo> {
    modules.iter().find(|m| m.contains(addr))
}

/// Enumerate the loaded modules of process `pid` on Windows.
///
/// Uses `CreateToolhelp32Snapshot(TH32CS_SNAPMODULE)` + `Module32FirstW`.
/// Returns an empty vec on non-Windows builds.
#[cfg(windows)]
pub fn enumerate_windows(pid: u32) -> Result<Vec<ModuleInfo>, MemoryError> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
        TH32CS_SNAPMODULE,
    };

    // SAFETY: snapshot handle is a valid HANDLE; closed on all paths.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Ok(Vec::new()); // e.g. access denied or 64/32-bit mismatch
    }

    let mut entry: MODULEENTRY32W = unsafe { core::mem::zeroed() };
    entry.dwSize = core::mem::size_of::<MODULEENTRY32W>() as u32;

    let mut out = Vec::new();
    // SAFETY: entry points to a valid MODULEENTRY32W.
    if unsafe { Module32FirstW(snapshot, &mut entry) } != 0 {
        loop {
            let name = String::from_utf16_lossy(&entry.szModule[..])
                .trim_end_matches('\0')
                .to_string();
            let path = String::from_utf16_lossy(&entry.szExePath[..]);
            let path = path.trim_end_matches('\0').to_string();
            out.push(ModuleInfo {
                base: entry.modBaseAddr as u64,
                size: entry.modBaseSize as u64,
                name,
                path: if path.is_empty() { None } else { Some(path) },
            });
            // SAFETY: loop until Module32NextW fails.
            if unsafe { Module32NextW(snapshot, &mut entry) } == 0 {
                break;
            }
        }
    }

    // SAFETY: snapshot is a valid handle.
    unsafe { CloseHandle(snapshot) };
    Ok(out)
}

/// Non-Windows stub.
#[cfg(not(windows))]
pub fn enumerate_windows(_pid: u32) -> Result<Vec<ModuleInfo>, MemoryError> {
    Ok(Vec::new())
}

/// Resolve an address to a module-relative string, using regions as a fallback
/// for the module name when a real module list isn't available.
///
/// `modules` is optional; if provided it's tried first. Otherwise (or on a
/// miss) we fall back to matching `addr` against `regions` and report the
/// region's name + offset.
pub fn resolve(
    addr: u64,
    modules: Option<&[ModuleInfo]>,
    regions: &[Region],
) -> String {
    if let Some(ms) = modules {
        if let Some(m) = find_module(ms, addr) {
            return m.format_offset(addr);
        }
    }
    // Fall back to a region.
    for r in regions {
        if addr >= r.start && addr < r.end {
            let name = r.name.as_deref().unwrap_or("region");
            return format!("{name}+0x{:x}", addr.wrapping_sub(r.start));
        }
    }
    format!("{addr:#018x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_contains_and_offset() {
        let m = ModuleInfo {
            base: 0x1000,
            size: 0x2000,
            name: "game.dll".into(),
            path: None,
        };
        assert!(m.contains(0x1234));
        assert!(!m.contains(0x4000));
        assert_eq!(m.format_offset(0x1234), "game.dll+0x234");
    }

    #[test]
    fn find_module_matches() {
        let mods = vec![
            ModuleInfo { base: 0x1000, size: 0x1000, name: "a.dll".into(), path: None },
            ModuleInfo { base: 0x5000, size: 0x1000, name: "b.dll".into(), path: None },
        ];
        assert_eq!(find_module(&mods, 0x5600).map(|m| m.name.as_str()), Some("b.dll"));
        assert_eq!(find_module(&mods, 0x9000).map(|m| m.name.as_str()), None);
    }

    #[test]
    fn resolve_falls_back_to_region() {
        let mods = vec![ModuleInfo { base: 0x1000, size: 0x100, name: "a.dll".into(), path: None }];
        let regions = vec![Region {
            start: 0x9000,
            end: 0x9100,
            readable: true,
            writable: false,
            executable: true,
            name: Some("mono.dll".into()),
        }];
        // Address not in any module -> falls back to region.
        assert_eq!(resolve(0x9040, Some(&mods), &regions), "mono.dll+0x40");
        // Address in module -> module-relative.
        assert_eq!(resolve(0x1020, Some(&mods), &regions), "a.dll+0x20");
    }
}
