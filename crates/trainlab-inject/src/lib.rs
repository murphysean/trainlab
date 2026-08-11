//! # trainlab-inject
//!
//! The injectable library that runs *inside* the game process. It is built as
//! a `cdylib` (`.dll` on Windows, `.so` on Linux) and loaded into the game via
//! a loader (or a Vulkan layer, or `LD_PRELOAD`).
//!
//! Once loaded it:
//!
//! 1. Spawns a background thread that listens on a local TCP socket.
//! 2. Serves [`trainlab_core::protocol::Request`] messages by reading and
//!    writing the *game's own* memory via [`trainlab_core::memory::SelfProcess`].
//!
//! Because it runs in-process, it can read/write any address directly — no
//! cross-process syscalls needed. This is what makes code caves and hooks
//! possible.

use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use trainlab_core::memory::{ProcessMemory, SelfProcess};
use trainlab_core::protocol::{self, Request, Response};

/// Windows-only debug machinery: hardware watchpoints (T-028) and int3
/// breakpoints (T-029) implemented with a vectored exception handler.
#[cfg(windows)]
mod watch;

/// Non-Windows stubs so the crate still builds (and behaves gracefully) on
/// Linux. All watchpoint/breakpoint requests return a "not supported" error.
#[cfg(not(windows))]
mod watch {
    /// A register + stack snapshot, mirroring the Windows variant's shape so
    /// the shared handling code compiles identically on both platforms.
    #[allow(dead_code)]
    pub struct HitInfo {
        pub rip: u64,
        pub rax: u64,
        pub rbx: u64,
        pub rcx: u64,
        pub rdx: u64,
        pub rsi: u64,
        pub rdi: u64,
        pub rsp: u64,
        pub rbp: u64,
        pub description: String,
        pub stack: Vec<String>,
    }

    pub fn arm_watch(_address: u64, _len: usize, _one_shot: bool) -> Result<(), String> {
        Err("hardware watchpoints are not supported on this platform".into())
    }

    pub fn arm_break(_address: u64, _one_shot: bool) -> Result<(), String> {
        Err("breakpoints are not supported on this platform".into())
    }

    pub fn poll_hit() -> Option<HitInfo> {
        None
    }

    pub fn clear() {}
}

/// Default port the injected DLL listens on.
pub const DEFAULT_PORT: u16 = 31337;

static STARTED: AtomicBool = AtomicBool::new(false);

/// Start the listener thread. Safe to call multiple times; only the first
/// call actually spawns the thread. Returns the bound port.
pub fn start(port: u16) -> std::io::Result<u16> {
    if STARTED.swap(true, Ordering::SeqCst) {
        // Already running; report the default port.
        return Ok(port);
    }

    let listener = TcpListener::bind(("127.0.0.1", port))?;
    let actual = listener.local_addr()?.port();
    tracing::info!(port = actual, "trainlab-inject listening");

    thread::Builder::new()
        .name("trainlab-inject".into())
        .spawn(move || {
            for conn in listener.incoming() {
                match conn {
                    Ok(stream) => {
                        let _ = stream.set_nodelay(true);
                        handle_connection(stream);
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "accept failed");
                    }
                }
            }
        })?;

    Ok(actual)
}

/// Handle a single client connection, processing requests until the client
/// disconnects.
fn handle_connection(mut stream: TcpStream) {
    use std::io::Write;
    let mem = SelfProcess;
    loop {
        // Read the 4-byte length prefix.
        let mut len_buf = [0u8; 4];
        if read_exact(&mut stream, &mut len_buf).is_err() {
            break;
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        if len == 0 || len > 64 * 1024 * 1024 {
            break;
        }
        let mut body = vec![0u8; len];
        if read_exact(&mut stream, &mut body).is_err() {
            break;
        }
        let mut frame = Vec::with_capacity(4 + len);
        frame.extend_from_slice(&len_buf);
        frame.extend_from_slice(&body);

        let response = match protocol::decode::<Request>(&frame) {
            Ok(req) => handle_request(&mem, req),
            Err(e) => Response::Error {
                message: format!("decode error: {e}"),
            },
        };

        let out = match protocol::encode(&response) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = %e, "failed to encode response");
                break;
            }
        };
        if stream.write_all(&out).is_err() {
            break;
        }
    }
}

fn handle_request(mem: &SelfProcess, req: Request) -> Response {
    match req {
        Request::Ping => Response::Pong {
            version: trainlab_core::VERSION.to_string(),
        },
        Request::Read { address, len } => match mem.read(address, len) {
            Ok(data) => Response::Read { data },
            Err(e) => Response::Error { message: e.to_string() },
        },
        Request::Write { address, data } => match mem.write(address, &data) {
            Ok(n) => Response::Write { bytes_written: n },
            Err(e) => Response::Error { message: e.to_string() },
        },
        Request::ScanAob { pattern, start, end } => {
            // Scan the game's readable regions for the pattern.
            let regions = match mem.regions() {
                Ok(r) => r,
                Err(e) => return Response::Error { message: e.to_string() },
            };
            let mut matches = Vec::new();
            for r in regions {
                if !r.readable {
                    continue;
                }
                if let Some(s) = start {
                    if r.end < s {
                        continue;
                    }
                }
                if let Some(e) = end {
                    if r.start > e {
                        continue;
                    }
                }
                let lo = start.map_or(r.start, |s| s.max(r.start));
                let hi = end.map_or(r.end, |e| e.min(r.end));
                if lo >= hi {
                    continue;
                }
                let len = (hi - lo) as usize;
                if let Ok(buf) = mem.read(lo, len) {
                    for off in trainlab_core::aob::find_all(&buf, &pattern) {
                        matches.push(lo + off as u64);
                    }
                }
            }
            Response::ScanAob { matches }
        }
        Request::Allocate { size, executable } => {
            match allocate(size, executable) {
                Ok(addr) => Response::Allocate { address: addr },
                Err(e) => Response::Error { message: e.to_string() },
            }
        }
        Request::Free { address } => {
            let ok = free(address);
            Response::Free { ok }
        }
        Request::InstallCave { target, hook } => {
            // In-process access via SelfProcess (read/write) + allocate.
            let read = |addr: u64, len: usize| -> Result<Vec<u8>, String> {
                mem.read(addr, len).map_err(|e| e.to_string())
            };
            let write = |addr: u64, data: &[u8]| -> Result<usize, String> {
                mem.write(addr, data).map_err(|e| e.to_string())
            };
            let alloc = |size: usize, exec: bool| -> Result<u64, String> {
                allocate(size, exec)
            };
            // Convert the wire hook kind into the installer's kind.
            let kind = match hook {
                trainlab_core::cave_hook::CaveHook::Trampoline { payload } => {
                    trainlab_cave::cave::HookKind::Trampoline { payload }
                }
                trainlab_core::cave_hook::CaveHook::Override { payload } => {
                    trainlab_cave::cave::HookKind::Override { payload }
                }
            };
            match trainlab_cave::cave::install(target, kind, read, write, alloc) {
                Ok(hook) => Response::CaveInstalled {
                    cave: hook.cave_addr,
                    target: hook.target,
                    original: hook.original,
                },
                Err(e) => Response::Error { message: e },
            }
        }
        Request::ListRegions => match mem.regions() {
            Ok(regions) => Response::ListRegions {
                regions: regions
                    .into_iter()
                    .map(|r| protocol::RegionInfo {
                        start: r.start,
                        end: r.end,
                        readable: r.readable,
                        writable: r.writable,
                        executable: r.executable,
                        name: r.name,
                    })
                    .collect(),
            },
            Err(e) => Response::Error { message: e.to_string() },
        },
        Request::Scan {
            value_type,
            alignment,
            op,
        } => {
            // Run a first value scan over the game's readable regions.
            let regions = match mem.regions() {
                Ok(r) => r,
                Err(e) => return Response::Error { message: e.to_string() },
            };
            let mut scan = trainlab_core::scan::Scan::new(value_type).with_alignment(alignment);
            match scan.first_scan(mem, &regions, op) {
                Ok(_) => Response::ScanResult {
                    matches: scan.matches().to_vec(),
                },
                Err(e) => Response::Error { message: e.to_string() },
            }
        }
        Request::Next {
            value_type,
            matches,
            op,
        } => {
            // Narrow an existing match set by re-reading each address.
            let mut scan = trainlab_core::scan::Scan::from_parts(value_type, matches);
            match scan.refine(mem, op) {
                Ok(_) => Response::ScanResult {
                    matches: scan.matches().to_vec(),
                },
                Err(e) => Response::Error { message: e.to_string() },
            }
        }
        Request::PointerScan { lo, hi } => {
            let regions = match mem.regions() {
                Ok(r) => r,
                Err(e) => return Response::Error { message: e.to_string() },
            };
            match trainlab_core::pointer::reverse_scan(mem, &regions, lo, hi) {
                Ok(matches) => Response::PointerScan { matches },
                Err(e) => Response::Error { message: e.to_string() },
            }
        }
        Request::PointerChase { base, offsets } => {
            match trainlab_core::pointer::chase(mem, base, &offsets) {
                Ok(hops) => Response::PointerChase { hops },
                Err(e) => Response::Error { message: e.to_string() },
            }
        }
        Request::WatchWrites {
            address,
            len,
            one_shot: _,
        } => match watch::arm_watch(address, len, true) {
            Ok(()) => Response::WatchArmed,
            Err(e) => Response::Error { message: e },
        },
        Request::BreakOnCode {
            address,
            one_shot: _,
        } => match watch::arm_break(address, true) {
            Ok(()) => Response::BreakArmed,
            Err(e) => Response::Error { message: e },
        },
        Request::ClearBreakpoints => {
            watch::clear();
            Response::BreakpointsCleared
        }
        Request::PollHit => match watch::poll_hit() {
            Some(hit) => Response::PollHit {
                hit: Some(hit_to_info(hit)),
            },
            None => Response::PollHit { hit: None },
        },
    }
}

/// Convert a [`watch::HitInfo`] into a [`Response::WatchHitInfo`] payload.
#[cfg(windows)]
fn hit_to_info(hit: watch::HitInfo) -> protocol::WatchHitInfo {
    protocol::WatchHitInfo {
        rip: hit.rip,
        rax: hit.rax,
        rbx: hit.rbx,
        rcx: hit.rcx,
        rdx: hit.rdx,
        rsi: hit.rsi,
        rdi: hit.rdi,
        rsp: hit.rsp,
        rbp: hit.rbp,
        description: hit.description,
        stack: hit.stack,
    }
}

/// Stub `hit_to_info` so the non-Windows build compiles.
#[cfg(not(windows))]
fn hit_to_info(_hit: watch::HitInfo) -> protocol::WatchHitInfo {
    protocol::WatchHitInfo {
        rip: 0,
        rax: 0,
        rbx: 0,
        rcx: 0,
        rdx: 0,
        rsi: 0,
        rdi: 0,
        rsp: 0,
        rbp: 0,
        description: "not supported".into(),
        stack: Vec::new(),
    }
}

/// Read exactly `buf.len()` bytes from the stream, or return an error.
fn read_exact(stream: &mut TcpStream, buf: &mut [u8]) -> std::io::Result<()> {
    use std::io::Read;
    let mut filled = 0;
    while filled < buf.len() {
        let n = stream.read(&mut buf[filled..])?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed",
            ));
        }
        filled += n;
    }
    Ok(())
}

/// Allocate a block of memory in the current process.
#[cfg(unix)]
fn allocate(size: usize, executable: bool) -> Result<u64, String> {
    let prot = if executable {
        libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC
    } else {
        libc::PROT_READ | libc::PROT_WRITE
    };
    // SAFETY: mmap with valid args.
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            prot,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(ptr as u64)
}

/// Free a block of memory allocated by [`allocate`].
#[cfg(unix)]
fn free(address: u64) -> bool {
    // We don't track sizes; this is a best-effort no-op for now.
    // A real implementation would keep a size map.
    let _ = address;
    true
}

#[cfg(windows)]
fn allocate(size: usize, executable: bool) -> Result<u64, String> {
    use windows_sys::Win32::System::Memory::{
        VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
    };
    // SAFETY: allocating `size` bytes in this process with commit+reserve.
    let prot = if executable {
        PAGE_EXECUTE_READWRITE
    } else {
        PAGE_READWRITE
    };
    let ptr = unsafe {
        VirtualAlloc(
            std::ptr::null(),
            size,
            MEM_COMMIT | MEM_RESERVE,
            prot,
        )
    };
    if ptr.is_null() {
        return Err(format!("VirtualAlloc failed: {}", last_error()));
    }
    Ok(ptr as u64)
}

#[cfg(windows)]
fn free(address: u64) -> bool {
    use windows_sys::Win32::System::Memory::{VirtualFree, MEM_RELEASE};
    // SAFETY: freeing a block previously allocated with MEM_RESERVE.
    let ok = unsafe { VirtualFree(address as *mut core::ffi::c_void, 0, MEM_RELEASE) };
    ok != 0
}

/// Format the last Win32 error as a string.
#[cfg(windows)]
fn last_error() -> String {
    use windows_sys::Win32::Foundation::GetLastError;
    // SAFETY: GetLastError has no preconditions.
    let code = unsafe { GetLastError() };
    format!("Win32 error {code}")
}

/// Entry point for `LD_PRELOAD` / manual loading on Linux. Callers can invoke
/// this symbol to start the listener.
#[unsafe(no_mangle)]
pub extern "C" fn trainlab_init() -> i32 {
    match start(DEFAULT_PORT) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("trainlab-init failed: {e}");
            -1
        }
    }
}

/// Windows `DllMain`. On `DLL_PROCESS_ATTACH` we start the listener thread so
/// that simply `LoadLibrary`-ing the DLL (via injection) brings up the TCP
/// server automatically.
#[cfg(windows)]
#[unsafe(no_mangle)]
pub extern "system" fn DllMain(
    _hinst: *mut core::ffi::c_void,
    reason: u32,
    _reserved: *mut core::ffi::c_void,
) -> i32 {
    const DLL_PROCESS_ATTACH: u32 = 1;
    if reason == DLL_PROCESS_ATTACH {
        // Start the listener in a detached thread so DllMain returns promptly.
        let _ = start(DEFAULT_PORT);
    }
    1 // TRUE
}

/// A small test binary entry (only used when compiled as a normal binary for
/// local testing).
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_roundtrip() {
        let req = Request::Read { address: 0x1234, len: 8 };
        let frame = protocol::encode(&req).unwrap();
        let back: Request = protocol::decode(&frame).unwrap();
        match back {
            Request::Read { address, len } => {
                assert_eq!(address, 0x1234);
                assert_eq!(len, 8);
            }
            _ => panic!("wrong variant"),
        }
    }
}
