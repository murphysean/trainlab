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
fn allocate(_size: usize, _executable: bool) -> Result<u64, String> {
    Err("windows allocate not yet implemented".into())
}

#[cfg(windows)]
fn free(_address: u64) -> bool {
    false
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
