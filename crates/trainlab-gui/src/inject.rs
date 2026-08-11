//! Windows DLL injection for `trainlab-gui`.
//!
//! The GUI injects the Agent DLL (`trainlab-inject`) into the game process via
//! the classic `CreateRemoteThread` + `LoadLibrary` sequence (design decision
//! D6). Once the DLL loads, it starts its own TCP listener on
//! `127.0.0.1:31337`, which the GUI then connects to.
//!
//! This module is Windows-only; on other platforms the functions are stubs.

/// Find a running process by its executable name (case-insensitive).
///
/// Returns the PID of the first match, or `None` if no process with that name
/// is running. Uses `CreateToolhelp32Snapshot` + `Process32FirstW/NextW`.
#[cfg(windows)]
pub fn find_game(exe_name: &str) -> Option<u32> {
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};

    let target = exe_name.to_lowercase();
    // SAFETY: snapshot handle is a valid HANDLE; we close it on all paths.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return None;
    }

    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    let mut found = None;
    // SAFETY: entry is a valid pointer to a PROCESSENTRY32W.
    if unsafe { Process32FirstW(snapshot, &mut entry) } != 0 {
        loop {
            // szExeFile is a null-terminated UTF-16 string.
            let name = String::from_utf16_lossy(&entry.szExeFile[..]);
            let name = name.trim_end_matches('\0').to_lowercase();
            if name == target {
                found = Some(entry.th32ProcessID);
                break;
            }
            // SAFETY: entry is a valid pointer; loop until Process32NextW fails.
            if unsafe { Process32NextW(snapshot, &mut entry) } == 0 {
                break;
            }
        }
    }

    // SAFETY: snapshot is a valid handle.
    unsafe { CloseHandle(snapshot) };
    found
}

/// A running process: its executable name and PID.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub name: String,
    pub pid: u32,
}

/// Enumerate all running processes via `CreateToolhelp32Snapshot`.
///
/// Returns a list of `(name, pid)` for every process in the snapshot. This is
/// the raw API; use [`find_game_candidates`] to narrow to likely games.
#[cfg(windows)]
pub fn list_processes() -> Vec<ProcessInfo> {
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};

    let mut out = Vec::new();
    // SAFETY: snapshot handle is a valid HANDLE; we close it on all paths.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return out;
    }

    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    // SAFETY: entry is a valid pointer to a PROCESSENTRY32W.
    if unsafe { Process32FirstW(snapshot, &mut entry) } != 0 {
        loop {
            let name = String::from_utf16_lossy(&entry.szExeFile[..]);
            let name = name.trim_end_matches('\0').to_string();
            out.push(ProcessInfo {
                name,
                pid: entry.th32ProcessID,
            });
            // SAFETY: entry is a valid pointer; loop until Process32NextW fails.
            if unsafe { Process32NextW(snapshot, &mut entry) } == 0 {
                break;
            }
        }
    }

    // SAFETY: snapshot is a valid handle.
    unsafe { CloseHandle(snapshot) };
    out
}

/// Heuristic: is this process name likely a game (vs. a system/background app)?
///
/// We exclude well-known non-game processes and prefer names that look like
/// games (short, no obvious system/service suffix). This is intentionally
/// conservative — it's a *candidate* list, not a definitive answer.
#[cfg(windows)]
fn looks_like_game(name: &str) -> bool {
    let n = name.to_lowercase();
    // Exclude known system / background / tooling processes.
    const NON_GAMES: &[&str] = &[
        "svchost", "explorer", "csrss", "wininit", "winlogon", "services", "lsass",
        "smss", "dwm", "conhost", "cmd", "powershell", "pwsh", "taskmgr", "notepad",
        "wine", "wineserver", "winedevice", "services.exe", "rundll32", "dllhost",
        "sihost", "taskhostw", "fontdrvhost", "spoolsv", "searchindexer", "audiodg",
        "steam", "steamwebhelper", "steamservice", "steamclient", "gameoverlayui",
        "trainlab", "trainlab-gui", "trainlab_inject", "urbek",
    ];
    if NON_GAMES.iter().any(|s| n.contains(s)) {
        return false;
    }
    // Exclude obvious system DLL-hosting / service names.
    if n.ends_with(".dll") || n.ends_with(".sys") {
        return false;
    }
    // A game is usually a short .exe with no spaces or a recognizable name.
    // Heuristic: prefer .exe names that aren't obviously system utilities.
    n.ends_with(".exe") && !n.starts_with("ms") && !n.contains("setup") && !n.contains("install")
}

/// Find likely game processes among all running processes.
///
/// Returns a list of `(name, pid)` for processes that pass the [`looks_like_game`]
/// heuristic. The GUI can present these as a dropdown so the user picks the
/// right one, rather than hardcoding a single game name.
#[cfg(windows)]
pub fn find_game_candidates() -> Vec<ProcessInfo> {
    list_processes()
        .into_iter()
        .filter(|p| looks_like_game(&p.name))
        .collect()
}

/// Inject a DLL into the process with the given PID.
///
/// Performs the standard injection sequence:
/// 1. `OpenProcess` with full access.
/// 2. `VirtualAllocEx` to reserve space in the target for the DLL path.
/// 3. `WriteProcessMemory` to write the DLL path.
/// 4. `CreateRemoteThread` pointing at `LoadLibraryA` with the path as arg.
/// 5. Wait for the thread, then `VirtualFreeEx` and close handles.
///
/// Returns `Ok(())` on success, or an error string.
#[cfg(windows)]
pub fn inject_dll(pid: u32, dll_path: &str) -> Result<(), String> {
    use windows_sys::Win32::Foundation::{CloseHandle, BOOL, HANDLE};
    use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows_sys::Win32::System::Memory::{
        VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
    };
    use windows_sys::Win32::System::Threading::{
        CreateRemoteThread, OpenProcess, WaitForSingleObject, INFINITE, PROCESS_ALL_ACCESS,
    };

    // The path must be a null-terminated ANSI string for LoadLibraryA.
    let path = std::ffi::CString::new(dll_path).map_err(|e| format!("invalid DLL path: {e}"))?;
    let path_bytes = path.as_bytes_with_nul();
    let path_len = path_bytes.len();

    // SAFETY: OpenProcess with valid access rights and PID.
    let process: HANDLE = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if process.is_null() {
        return Err(format!("OpenProcess failed (pid {pid})"));
    }

    // SAFETY: VirtualAllocEx with a valid process handle and size.
    let remote_addr = unsafe {
        VirtualAllocEx(
            process,
            std::ptr::null(),
            path_len,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if remote_addr.is_null() {
        // SAFETY: process is a valid handle.
        unsafe { CloseHandle(process) };
        return Err("VirtualAllocEx failed".into());
    }

    // SAFETY: WriteProcessMemory writes path_bytes into the target's memory.
    let mut written: usize = 0;
    let ok: BOOL = unsafe {
        WriteProcessMemory(
            process,
            remote_addr,
            path_bytes.as_ptr() as *const _,
            path_len,
            &mut written,
        )
    };
    if ok == 0 {
        // SAFETY: valid handles/addresses.
        unsafe {
            VirtualFreeEx(process, remote_addr, 0, MEM_RELEASE);
            CloseHandle(process);
        }
        return Err("WriteProcessMemory failed".into());
    }

    // Resolve LoadLibraryA's address in kernel32 (same in every process).
    // SAFETY: GetModuleHandleA with a valid module name.
    let kernel32 = unsafe { GetModuleHandleA(b"kernel32.dll\0".as_ptr()) };
    if kernel32.is_null() {
        // SAFETY: valid handles/addresses.
        unsafe {
            VirtualFreeEx(process, remote_addr, 0, MEM_RELEASE);
            CloseHandle(process);
        }
        return Err("GetModuleHandleA(kernel32) failed".into());
    }
    // SAFETY: GetProcAddress with a valid module and proc name.
    let loadlib = unsafe { GetProcAddress(kernel32, b"LoadLibraryA\0".as_ptr()) };
    let Some(loadlib) = loadlib else {
        // SAFETY: valid handles/addresses.
        unsafe {
            VirtualFreeEx(process, remote_addr, 0, MEM_RELEASE);
            CloseHandle(process);
        }
        return Err("GetProcAddress(LoadLibraryA) failed".into());
    };

    // SAFETY: CreateRemoteThread with a valid process handle, start address,
    // and argument. The start address is LoadLibraryA's address.
    let mut thread_id: u32 = 0;
    let thread = unsafe {
        CreateRemoteThread(
            process,
            std::ptr::null(),
            0,
            Some(std::mem::transmute::<_, unsafe extern "system" fn(*mut core::ffi::c_void) -> u32>(
                loadlib,
            )),
            remote_addr as *const core::ffi::c_void,
            0,
            &mut thread_id,
        )
    };
    if thread.is_null() {
        // SAFETY: valid handles/addresses.
        unsafe {
            VirtualFreeEx(process, remote_addr, 0, MEM_RELEASE);
            CloseHandle(process);
        }
        return Err("CreateRemoteThread failed".into());
    }

    // Wait for the injected thread to finish (LoadLibraryA returns).
    // SAFETY: thread is a valid handle.
    unsafe { WaitForSingleObject(thread, INFINITE) };

    // Clean up.
    // SAFETY: valid handles/addresses.
    unsafe {
        CloseHandle(thread);
        VirtualFreeEx(process, remote_addr, 0, MEM_RELEASE);
        CloseHandle(process);
    }

    Ok(())
}

/// Non-Windows stubs so the crate still compiles on Linux.
#[cfg(not(windows))]
pub fn find_game(_exe_name: &str) -> Option<u32> {
    None
}

#[cfg(not(windows))]
pub fn inject_dll(_pid: u32, _dll_path: &str) -> Result<(), String> {
    Err("DLL injection is only supported on Windows".into())
}

#[cfg(not(windows))]
pub fn list_processes() -> Vec<ProcessInfo> {
    Vec::new()
}

#[cfg(not(windows))]
pub fn find_game_candidates() -> Vec<ProcessInfo> {
    Vec::new()
}
