//! Cross-platform primitives for reading and writing another process's
//! memory.
//!
//! On Linux this uses `process_vm_readv` / `process_vm_writev` (no ptrace
//! attach required for reading). On Windows it uses
//! `ReadProcessMemory` / `WriteProcessMemory`.
//!
//! The [`ProcessMemory`] trait is the seam that lets the injected DLL (which
//! operates on its *own* process) and the scanner (which operates on a
//! *foreign* process) share the same code paths.

use std::fmt;

use crate::scan::scan_buffer;

/// A handle to a process whose memory we can read and write.
pub trait ProcessMemory {
    /// Read `len` bytes at `address` into a fresh buffer.
    fn read(&self, address: u64, len: usize) -> Result<Vec<u8>, MemoryError>;
    /// Write `data` at `address`, returning the number of bytes written.
    fn write(&self, address: u64, data: &[u8]) -> Result<usize, MemoryError>;
    /// Enumerate readable memory regions.
    fn regions(&self) -> Result<Vec<Region>, MemoryError>;

    /// Scan a readable region for values matching `op`, returning matching
    /// `(address, value)` pairs.
    ///
    /// The default implementation bulk-reads the whole region into a buffer
    /// via [`Self::read`] and scans it. Implementations that can access
    /// memory without copying (e.g. the injected DLL operating on its own
    /// process) should override this to scan in-place — see
    /// [`SelfProcess`], which avoids allocating a full copy of large heaps
    /// (the copy itself was the cause of OOM/faults when scanning a Unity
    /// game's multi-hundred-MB heap).
    fn scan_region(
        &self,
        region: &Region,
        size: usize,
        alignment: usize,
        value_type: crate::scan::ValueType,
        op: crate::scan::ScanOp,
    ) -> Vec<(u64, f64)> {
        let start = region.start;
        let end = region.end;
        let len = (end - start) as usize;
        if len < size {
            return Vec::new();
        }
        let buf = match self.read(start, len) {
            Ok(b) => b,
            Err(_) => return Vec::new(), // region unreadable: skip it
        };
        scan_buffer(buf.as_slice(), start, size, alignment, value_type, op)
    }
}

/// A single memory region.
#[derive(Debug, Clone)]
pub struct Region {
    pub start: u64,
    pub end: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub name: Option<String>,
}

impl Region {
    pub fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Errors that can occur while accessing process memory.
#[derive(Debug)]
pub enum MemoryError {
    /// The OS call failed (e.g. permission denied, process exited).
    Os(String),
    /// The requested range was not fully readable.
    PartialRead { address: u64, len: usize, got: usize },
    /// The requested range was not fully writable.
    PartialWrite { address: u64, len: usize, wrote: usize },
    /// The address was outside any known region.
    OutOfRange { address: u64 },
}

impl fmt::Display for MemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemoryError::Os(e) => write!(f, "os error: {e}"),
            MemoryError::PartialRead { address, len, got } => {
                write!(f, "partial read at 0x{address:x}: wanted {len}, got {got}")
            }
            MemoryError::PartialWrite { address, len, wrote } => {
                write!(f, "partial write at 0x{address:x}: wanted {len}, wrote {wrote}")
            }
            MemoryError::OutOfRange { address } => {
                write!(f, "address 0x{address:x} outside known regions")
            }
        }
    }
}

impl std::error::Error for MemoryError {}

#[cfg(unix)]
pub mod unix {
    //! Linux implementation using `process_vm_readv` / `process_vm_writev`.

    use super::{MemoryError, ProcessMemory, Region};
    use std::os::unix::io::RawFd;

    /// A handle to a Linux process by PID.
    pub struct LinuxProcess {
        pid: i32,
    }

    impl LinuxProcess {
        pub fn new(pid: i32) -> Self {
            Self { pid }
        }
        pub fn pid(&self) -> i32 {
            self.pid
        }
    }

    impl ProcessMemory for LinuxProcess {
        fn read(&self, address: u64, len: usize) -> Result<Vec<u8>, MemoryError> {
            let mut buf = vec![0u8; len];
            let mut local = libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: len,
            };
            let mut remote = libc::iovec {
                iov_base: address as *mut libc::c_void,
                iov_len: len,
            };
            // SAFETY: buffers are valid for the duration of the call.
            let n = unsafe {
                libc::process_vm_readv(
                    self.pid,
                    &mut local as *mut libc::iovec,
                    1,
                    &mut remote as *mut libc::iovec,
                    1,
                    0,
                )
            };
            if n < 0 {
                return Err(MemoryError::Os(std::io::Error::last_os_error().to_string()));
            }
            let n = n as usize;
            if n != len {
                return Err(MemoryError::PartialRead { address, len, got: n });
            }
            Ok(buf)
        }

        fn write(&self, address: u64, data: &[u8]) -> Result<usize, MemoryError> {
            let mut local = libc::iovec {
                iov_base: data.as_ptr() as *mut libc::c_void,
                iov_len: data.len(),
            };
            let mut remote = libc::iovec {
                iov_base: address as *mut libc::c_void,
                iov_len: data.len(),
            };
            // SAFETY: buffers are valid for the duration of the call.
            let n = unsafe {
                libc::process_vm_writev(
                    self.pid,
                    &mut local as *mut libc::iovec,
                    1,
                    &mut remote as *mut libc::iovec,
                    1,
                    0,
                )
            };
            if n < 0 {
                return Err(MemoryError::Os(std::io::Error::last_os_error().to_string()));
            }
            Ok(n as usize)
        }

        fn regions(&self) -> Result<Vec<Region>, MemoryError> {
            let maps = std::fs::read_to_string(format!("/proc/{}/maps", self.pid))
                .map_err(|e| MemoryError::Os(e.to_string()))?;
            let mut out = Vec::new();
            for line in maps.lines() {
                // Format: start-end perms offset dev inode pathname
                let mut it = line.split_whitespace();
                let range = it.next().unwrap_or("");
                let perms = it.next().unwrap_or("");
                let name = it.nth(4).map(|s| s.to_string());
                let (start, end) = match range.split_once('-') {
                    Some((s, e)) => (
                        u64::from_str_radix(s, 16).unwrap_or(0),
                        u64::from_str_radix(e, 16).unwrap_or(0),
                    ),
                    None => continue,
                };
                let readable = perms.contains('r');
                let writable = perms.contains('w');
                let executable = perms.contains('x');
                out.push(Region {
                    start,
                    end,
                    readable,
                    writable,
                    executable,
                    name,
                });
            }
            Ok(out)
        }
    }

    /// Convenience: read a `RawFd`-style handle is not needed; PID is enough.
    pub fn from_fd(_fd: RawFd) -> LinuxProcess {
        unreachable!("use LinuxProcess::new(pid)")
    }
}

#[cfg(windows)]
pub mod windows {
    //! Windows implementation using `ReadProcessMemory` / `WriteProcessMemory`
    //! and `VirtualQueryEx` for region enumeration.

    use super::{MemoryError, ProcessMemory, Region};
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
    use windows_sys::Win32::System::Diagnostics::Debug::{
        ReadProcessMemory, WriteProcessMemory,
    };
    use windows_sys::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, MEM_MAPPED,
        PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
        PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
    };

    /// A handle to a Windows process, opened with `PROCESS_VM_READ |
    /// PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION`.
    pub struct WindowsProcess {
        handle: HANDLE,
    }

    impl WindowsProcess {
        /// Wrap an already-open process handle. The caller owns the handle;
        /// this type does **not** close it on drop (the GUI/inject layer
        /// manages handle lifetime).
        pub fn new(handle: HANDLE) -> Self {
            Self { handle }
        }

        /// Open a process by PID with read/write/query access.
        ///
        /// Returns `Err` if the process cannot be opened (e.g. it exited or
        /// access is denied).
        pub fn open(pid: u32) -> Result<Self, MemoryError> {
            use windows_sys::Win32::System::Threading::OpenProcess;
            use windows_sys::Win32::System::Threading::{
                PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
            };
            let access = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION;
            // SAFETY: passing a valid PID and access mask.
            let handle = unsafe { OpenProcess(access, 0, pid) };
            if handle.is_null() {
                return Err(MemoryError::Os(format!(
                    "OpenProcess failed: {}",
                    last_error()
                )));
            }
            Ok(Self { handle })
        }

        /// The raw OS handle.
        pub fn handle(&self) -> HANDLE {
            self.handle
        }
    }

    impl Drop for WindowsProcess {
        fn drop(&mut self) {
            // SAFETY: handle is a valid open handle owned by this struct.
            unsafe {
                CloseHandle(self.handle);
            }
        }
    }

    impl ProcessMemory for WindowsProcess {
        fn read(&self, address: u64, len: usize) -> Result<Vec<u8>, MemoryError> {
            let mut buf = vec![0u8; len];
            let mut read: usize = 0;
            // SAFETY: buf is valid for `len` bytes; address is a remote VA.
            let ok = unsafe {
                ReadProcessMemory(
                    self.handle,
                    address as *const core::ffi::c_void,
                    buf.as_mut_ptr() as *mut core::ffi::c_void,
                    len,
                    &mut read,
                )
            };
            if ok == 0 {
                return Err(MemoryError::Os(format!(
                    "ReadProcessMemory failed: {}",
                    last_error()
                )));
            }
            if read != len {
                return Err(MemoryError::PartialRead { address, len, got: read });
            }
            Ok(buf)
        }

        fn write(&self, address: u64, data: &[u8]) -> Result<usize, MemoryError> {
            let mut written: usize = 0;
            // SAFETY: data is valid for its length; address is a remote VA.
            let ok = unsafe {
                WriteProcessMemory(
                    self.handle,
                    address as *mut core::ffi::c_void,
                    data.as_ptr() as *const core::ffi::c_void,
                    data.len(),
                    &mut written,
                )
            };
            if ok == 0 {
                return Err(MemoryError::Os(format!(
                    "WriteProcessMemory failed: {}",
                    last_error()
                )));
            }
            Ok(written)
        }

        fn regions(&self) -> Result<Vec<Region>, MemoryError> {
            let mut out = Vec::new();
            let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { core::mem::zeroed() };
            let mut addr: usize = 0;
            loop {
                // SAFETY: mbi is valid; addr walks the address space.
                let n = unsafe {
                    VirtualQueryEx(
                        self.handle,
                        addr as *const core::ffi::c_void,
                        &mut mbi,
                        core::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                    )
                };
                if n == 0 {
                    // Either we've walked off the end of the address space or
                    // an error occurred. If addr is 0 we couldn't even start.
                    if addr == 0 {
                        return Err(MemoryError::Os(format!(
                            "VirtualQueryEx failed: {}",
                            last_error()
                        )));
                    }
                    break;
                }
                let start = mbi.BaseAddress as u64;
                let end = start + mbi.RegionSize as u64;
                // Skip free regions; only report committed memory.
                if mbi.State == MEM_COMMIT {
                    let protect = mbi.Protect;
                    out.push(Region {
                        start,
                        end,
                        readable: is_readable(protect),
                        writable: is_writable(protect),
                        executable: is_executable(protect),
                        name: region_name(mbi.Type),
                    });
                }
                // Advance to the next region. Guard against overflow / no
                // progress (a zero-size region would loop forever).
                if end <= addr as u64 {
                    break;
                }
                addr = end as usize;
            }
            Ok(out)
        }
    }

    /// Human-readable label for a region's allocation type.
    fn region_name(ty: u32) -> Option<String> {
        if ty == MEM_IMAGE {
            Some("image".into())
        } else if ty == MEM_MAPPED {
            Some("mapped".into())
        } else {
            Some("private".into())
        }
    }

    fn is_readable(protect: u32) -> bool {
        matches!(
            protect & 0xFF,
            PAGE_READONLY
                | PAGE_READWRITE
                | PAGE_WRITECOPY
                | PAGE_EXECUTE_READ
                | PAGE_EXECUTE_READWRITE
                | PAGE_EXECUTE_WRITECOPY
        )
    }

    fn is_writable(protect: u32) -> bool {
        matches!(
            protect & 0xFF,
            PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
        )
    }

    fn is_executable(protect: u32) -> bool {
        matches!(
            protect & 0xFF,
            PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
        )
    }

    fn last_error() -> String {
        // SAFETY: GetLastError takes no arguments.
        let code = unsafe { GetLastError() };
        format!("Win32 error {code}")
    }
}

/// Re-export the platform-specific process handle at the module level.
#[cfg(unix)]
pub use unix::LinuxProcess;
#[cfg(windows)]
pub use windows::WindowsProcess;

/// A process handle that operates on its *own* memory (used by the injected
/// DLL). Reads/writes are plain pointer dereferences.
pub struct SelfProcess;

impl ProcessMemory for SelfProcess {
    fn read(&self, address: u64, len: usize) -> Result<Vec<u8>, MemoryError> {
        if address == 0 {
            return Err(MemoryError::OutOfRange { address });
        }
        let ptr = address as *const u8;
        // SAFETY: caller is responsible for the address being valid in this
        // process. This is the injected-DLL use case.
        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
        Ok(slice.to_vec())
    }

    fn write(&self, address: u64, data: &[u8]) -> Result<usize, MemoryError> {
        if address == 0 {
            return Err(MemoryError::OutOfRange { address });
        }
        let ptr = address as *mut u8;
        // SAFETY: caller is responsible for the address being valid and
        // writable in this process.
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
        }
        Ok(data.len())
    }

    fn scan_region(
        &self,
        region: &Region,
        size: usize,
        alignment: usize,
        value_type: crate::scan::ValueType,
        op: crate::scan::ScanOp,
    ) -> Vec<(u64, f64)> {
        let start = region.start;
        let end = region.end;
        let len = (end - start) as usize;
        if len < size {
            return Vec::new();
        }
        // SAFETY: `start` is a readable address in this (the game's) process.
        // We scan the raw memory in-place — no full-region copy — which avoids
        // allocating a multi-hundred-MB buffer and faulting on the injected
        // path (the crash we hit). The caller guarantees `start`/`len` stay
        // within a readable region for the duration of the scan.
        let slice = unsafe { std::slice::from_raw_parts(start as *const u8, len) };
        crate::scan::scan_buffer(slice, start, size, alignment, value_type, op)
    }

    fn regions(&self) -> Result<Vec<Region>, MemoryError> {
        // Enumerate our own process's memory. The injected DLL runs inside the
        // game, so region enumeration uses the self-process path.
        #[cfg(unix)]
        {
            use std::fs;
            let maps = fs::read_to_string("/proc/self/maps")
                .map_err(|e| MemoryError::Os(e.to_string()))?;
            let mut out = Vec::new();
            for line in maps.lines() {
                // Format: start-end perms offset dev inode pathname
                let mut it = line.split_whitespace();
                let range = it.next().unwrap_or("");
                let perms = it.next().unwrap_or("");
                let name = it.nth(4).map(|s| s.to_string());
                let (start, end) = match range.split_once('-') {
                    Some((s, e)) => (
                        u64::from_str_radix(s, 16).unwrap_or(0),
                        u64::from_str_radix(e, 16).unwrap_or(0),
                    ),
                    None => continue,
                };
                let readable = perms.contains('r');
                let writable = perms.contains('w');
                let executable = perms.contains('x');
                out.push(Region {
                    start,
                    end,
                    readable,
                    writable,
                    executable,
                    name,
                });
            }
            Ok(out)
        }
        #[cfg(windows)]
        {
            // Enumerate our own address space with VirtualQuery (self-process).
            use windows_sys::Win32::System::Memory::{
                VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, MEM_MAPPED,
                PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, PAGE_EXECUTE_READ,
                PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_EXECUTE,
            };
            let mut out = Vec::new();
            let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { core::mem::zeroed() };
            let mut addr: usize = 0;
            loop {
                // SAFETY: mbi is valid; addr walks our own address space.
                let n = unsafe {
                    VirtualQuery(
                        addr as *const core::ffi::c_void,
                        &mut mbi,
                        core::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                    )
                };
                if n == 0 {
                    break;
                }
                let start = mbi.BaseAddress as u64;
                let end = start + mbi.RegionSize as u64;
                if mbi.State == MEM_COMMIT {
                    let protect = mbi.Protect;
                    out.push(Region {
                        start,
                        end,
                        readable: matches!(
                            protect & 0xFF,
                            PAGE_READONLY
                                | PAGE_READWRITE
                                | PAGE_WRITECOPY
                                | PAGE_EXECUTE_READ
                                | PAGE_EXECUTE_READWRITE
                                | PAGE_EXECUTE_WRITECOPY
                        ),
                        writable: matches!(
                            protect & 0xFF,
                            PAGE_READWRITE
                                | PAGE_WRITECOPY
                                | PAGE_EXECUTE_READWRITE
                                | PAGE_EXECUTE_WRITECOPY
                        ),
                        executable: matches!(
                            protect & 0xFF,
                            PAGE_EXECUTE
                                | PAGE_EXECUTE_READ
                                | PAGE_EXECUTE_READWRITE
                                | PAGE_EXECUTE_WRITECOPY
                        ),
                        name: if mbi.Type == MEM_IMAGE {
                            Some("image".into())
                        } else if mbi.Type == MEM_MAPPED {
                            Some("mapped".into())
                        } else {
                            Some("private".into())
                        },
                    });
                }
                if end <= addr as u64 {
                    break;
                }
                addr = end as usize;
            }
            Ok(out)
        }
        #[cfg(not(any(unix, windows)))]
        {
            Ok(Vec::new())
        }
    }
}
