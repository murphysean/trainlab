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

/// A handle to a process whose memory we can read and write.
pub trait ProcessMemory {
    /// Read `len` bytes at `address` into a fresh buffer.
    fn read(&self, address: u64, len: usize) -> Result<Vec<u8>, MemoryError>;
    /// Write `data` at `address`, returning the number of bytes written.
    fn write(&self, address: u64, data: &[u8]) -> Result<usize, MemoryError>;
    /// Enumerate readable memory regions.
    fn regions(&self) -> Result<Vec<Region>, MemoryError>;
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
    //! Windows implementation using `ReadProcessMemory` / `WriteProcessMemory`.
    //! (Stub — fill in with `windows-sys` when building on Windows.)

    use super::{MemoryError, ProcessMemory, Region};

    pub struct WindowsProcess {
        handle: usize,
    }

    impl WindowsProcess {
        pub fn new(handle: usize) -> Self {
            Self { handle }
        }
    }

    impl ProcessMemory for WindowsProcess {
        fn read(&self, _address: u64, _len: usize) -> Result<Vec<u8>, MemoryError> {
            Err(MemoryError::Os("windows backend not yet implemented".into()))
        }
        fn write(&self, _address: u64, _data: &[u8]) -> Result<usize, MemoryError> {
            Err(MemoryError::Os("windows backend not yet implemented".into()))
        }
        fn regions(&self) -> Result<Vec<Region>, MemoryError> {
            Err(MemoryError::Os("windows backend not yet implemented".into()))
        }
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

    fn regions(&self) -> Result<Vec<Region>, MemoryError> {
        // For the self-process case we don't enumerate regions by default;
        // the injected DLL can rely on the scanner for that.
        Ok(Vec::new())
    }
}
