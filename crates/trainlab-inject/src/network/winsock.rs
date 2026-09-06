//! Winsock TCP/UDP traffic interception hooks (`ws2_32.dll`).
//!
//! Detour hooks for:
//! - `send` (Outbound TCP)
//! - `recv` (Inbound TCP)
//! - `sendto` (Outbound UDP)
//! - `recvfrom` (Inbound UDP)

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::time::Duration;

use windows_sys::Win32::Networking::WinSock::{
    getpeername, getsockname, WSAGetLastError, AF_INET, AF_INET6, SOCKADDR, SOCKADDR_IN,
    SOCKADDR_IN6, SOCKET, WSA_IO_PENDING,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};

use trainlab_core::protocol::{PacketDirection, PacketKind};

type FnSend = unsafe extern "system" fn(SOCKET, *const u8, i32, i32) -> i32;
type FnRecv = unsafe extern "system" fn(SOCKET, *mut u8, i32, i32) -> i32;
type FnSendTo = unsafe extern "system" fn(SOCKET, *const u8, i32, i32, *const SOCKADDR, i32) -> i32;
type FnRecvFrom = unsafe extern "system" fn(SOCKET, *mut u8, i32, i32, *mut SOCKADDR, *mut i32) -> i32;

/// WSABUF structure used by Winsock WSA* functions.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct WSABUF {
    pub len: u32,
    pub buf: *mut u8,
}

type FnWSASendTo = unsafe extern "system" fn(
    SOCKET,
    *const WSABUF,
    u32,
    *mut u32,
    u32,
    *const SOCKADDR,
    i32,
    *mut c_void, // LPWSAOVERLAPPED
    *mut c_void, // LPWSAOVERLAPPED_COMPLETION_ROUTINE
) -> i32;

type FnWSARecvFrom = unsafe extern "system" fn(
    SOCKET,
    *const WSABUF,
    u32,
    *mut u32,
    *mut u32,
    *mut SOCKADDR,
    *mut i32,
    *mut c_void, // LPWSAOVERLAPPED
    *mut c_void, // LPWSAOVERLAPPED_COMPLETION_ROUTINE
) -> i32;

type FnWSASend = unsafe extern "system" fn(
    SOCKET,
    *const WSABUF,
    u32,
    *mut u32,
    u32,
    *mut c_void, // LPWSAOVERLAPPED
    *mut c_void, // LPWSAOVERLAPPED_COMPLETION_ROUTINE
) -> i32;

type FnWSARecv = unsafe extern "system" fn(
    SOCKET,
    *const WSABUF,
    u32,
    *mut u32,
    *mut u32,
    *mut c_void, // LPWSAOVERLAPPED
    *mut c_void, // LPWSAOVERLAPPED_COMPLETION_ROUTINE
) -> i32;

static ORIGINAL_SEND: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIGINAL_RECV: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIGINAL_SENDTO: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIGINAL_RECVFROM: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIGINAL_WSASENDTO: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIGINAL_WSARECVFROM: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIGINAL_WSASEND: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIGINAL_WSARECV: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

static WINSOCK_HOOKED: AtomicBool = AtomicBool::new(false);

/// Helper to copy payload bytes from WSABUF array up to max_len.
unsafe fn extract_wsabuf_data(buffers: *const WSABUF, count: u32, max_len: usize) -> Vec<u8> {
    if buffers.is_null() || count == 0 || max_len == 0 {
        return Vec::new();
    }
    let mut data = Vec::with_capacity(max_len.min(4096));
    let slice = unsafe { std::slice::from_raw_parts(buffers, count as usize) };
    for buf in slice {
        if buf.buf.is_null() || buf.len == 0 {
            continue;
        }
        let remaining = max_len - data.len();
        if remaining == 0 {
            break;
        }
        let take = (buf.len as usize).min(remaining);
        let part = unsafe { std::slice::from_raw_parts(buf.buf, take) };
        data.extend_from_slice(part);
    }
    data
}

/// Helper to format a sockaddr into an "IP:Port" string.
unsafe fn format_sockaddr(addr: *const SOCKADDR) -> Option<String> {
    if addr.is_null() {
        return None;
    }
    let sa_family = unsafe { (*addr).sa_family };
    if sa_family == AF_INET as u16 {
        let in4 = unsafe { &*(addr as *const SOCKADDR_IN) };
        let ip_u32 = unsafe { in4.sin_addr.S_un.S_addr };
        let ip_bytes = ip_u32.to_ne_bytes();
        let port = u16::from_be(in4.sin_port);
        Some(format!(
            "{}.{}.{}.{}:{}",
            ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3], port
        ))
    } else if sa_family == AF_INET6 as u16 {
        let in6 = unsafe { &*(addr as *const SOCKADDR_IN6) };
        let port = u16::from_be(in6.sin6_port);
        let b = unsafe { in6.sin6_addr.u.Byte };
        Some(format!(
            "[{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}]:{}",
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
            b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
            port
        ))
    } else {
        None
    }
}

/// Query local socket endpoint via `getsockname`.
unsafe fn query_local_endpoint(s: SOCKET) -> Option<String> {
    let mut ss: [u8; 128] = [0; 128];
    let mut len = ss.len() as i32;
    if unsafe { getsockname(s, ss.as_mut_ptr() as *mut SOCKADDR, &mut len) } == 0 {
        unsafe { format_sockaddr(ss.as_ptr() as *const SOCKADDR) }
    } else {
        None
    }
}

/// Query remote peer endpoint via `getpeername`.
unsafe fn query_peer_endpoint(s: SOCKET) -> Option<String> {
    let mut ss: [u8; 128] = [0; 128];
    let mut len = ss.len() as i32;
    if unsafe { getpeername(s, ss.as_mut_ptr() as *mut SOCKADDR, &mut len) } == 0 {
        unsafe { format_sockaddr(ss.as_ptr() as *const SOCKADDR) }
    } else {
        None
    }
}

/// Hooked `send` callback (TCP outbound).
pub unsafe extern "system" fn hooked_send(
    s: SOCKET,
    buf: *const u8,
    len: i32,
    flags: i32,
) -> i32 {
    let orig = ORIGINAL_SEND.load(Ordering::Relaxed);
    let ret = if !orig.is_null() {
        let orig_fn: FnSend = unsafe { std::mem::transmute(orig) };
        unsafe { orig_fn(s, buf, len, flags) }
    } else {
        -1
    };

    if ret > 0 && !buf.is_null() {
        let data_len = (ret as usize).min(len as usize);
        super::count_raw_packet(PacketKind::Tcp, PacketDirection::Outbound, data_len);
        let slice = unsafe { std::slice::from_raw_parts(buf, data_len) };
        let local = unsafe { query_local_endpoint(s) };
        let remote = unsafe { query_peer_endpoint(s) };

        super::record_packet(
            PacketKind::Tcp,
            PacketDirection::Outbound,
            local,
            remote,
            None,
            None,
            slice,
        );
    }

    ret
}

/// Hooked `recv` callback (TCP inbound).
pub unsafe extern "system" fn hooked_recv(
    s: SOCKET,
    buf: *mut u8,
    len: i32,
    flags: i32,
) -> i32 {
    let orig = ORIGINAL_RECV.load(Ordering::Relaxed);
    let ret = if !orig.is_null() {
        let orig_fn: FnRecv = unsafe { std::mem::transmute(orig) };
        unsafe { orig_fn(s, buf, len, flags) }
    } else {
        -1
    };

    if ret > 0 && !buf.is_null() {
        let data_len = (ret as usize).min(len as usize);
        super::count_raw_packet(PacketKind::Tcp, PacketDirection::Inbound, data_len);
        let slice = unsafe { std::slice::from_raw_parts(buf, data_len) };
        let local = unsafe { query_local_endpoint(s) };
        let remote = unsafe { query_peer_endpoint(s) };

        super::record_packet(
            PacketKind::Tcp,
            PacketDirection::Inbound,
            local,
            remote,
            None,
            None,
            slice,
        );
    }

    ret
}

/// Hooked `sendto` callback (UDP outbound).
pub unsafe extern "system" fn hooked_sendto(
    s: SOCKET,
    buf: *const u8,
    len: i32,
    flags: i32,
    to: *const SOCKADDR,
    tolen: i32,
) -> i32 {
    let orig = ORIGINAL_SENDTO.load(Ordering::Relaxed);
    let ret = if !orig.is_null() {
        let orig_fn: FnSendTo = unsafe { std::mem::transmute(orig) };
        unsafe { orig_fn(s, buf, len, flags, to, tolen) }
    } else {
        -1
    };

    if ret > 0 && !buf.is_null() {
        let data_len = (ret as usize).min(len as usize);
        super::count_raw_packet(PacketKind::Udp, PacketDirection::Outbound, data_len);
        let slice = unsafe { std::slice::from_raw_parts(buf, data_len) };
        let local = unsafe { query_local_endpoint(s) };
        let remote = unsafe { format_sockaddr(to) }.or_else(|| unsafe { query_peer_endpoint(s) });

        super::record_packet(
            PacketKind::Udp,
            PacketDirection::Outbound,
            local,
            remote,
            None,
            None,
            slice,
        );
    }

    ret
}

/// Hooked `recvfrom` callback (UDP inbound).
pub unsafe extern "system" fn hooked_recvfrom(
    s: SOCKET,
    buf: *mut u8,
    len: i32,
    flags: i32,
    from: *mut SOCKADDR,
    fromlen: *mut i32,
) -> i32 {
    let orig = ORIGINAL_RECVFROM.load(Ordering::Relaxed);
    let ret = if !orig.is_null() {
        let orig_fn: FnRecvFrom = unsafe { std::mem::transmute(orig) };
        unsafe { orig_fn(s, buf, len, flags, from, fromlen) }
    } else {
        -1
    };

    if ret > 0 && !buf.is_null() {
        let data_len = (ret as usize).min(len as usize);
        super::count_raw_packet(PacketKind::Udp, PacketDirection::Inbound, data_len);
        let slice = unsafe { std::slice::from_raw_parts(buf, data_len) };
        let local = unsafe { query_local_endpoint(s) };
        let remote = unsafe { format_sockaddr(from) }.or_else(|| unsafe { query_peer_endpoint(s) });

        super::record_packet(
            PacketKind::Udp,
            PacketDirection::Inbound,
            local,
            remote,
            None,
            None,
            slice,
        );
    }

    ret
}

/// Hooked `WSASendTo` callback (Modern UDP outbound).
pub unsafe extern "system" fn hooked_wsasendto(
    s: SOCKET,
    buffers: *const WSABUF,
    buffer_count: u32,
    number_of_bytes_sent: *mut u32,
    flags: u32,
    to: *const SOCKADDR,
    tolen: i32,
    overlapped: *mut c_void,
    completion_routine: *mut c_void,
) -> i32 {
    let orig = ORIGINAL_WSASENDTO.load(Ordering::Relaxed);
    let ret = if !orig.is_null() {
        let orig_fn: FnWSASendTo = unsafe { std::mem::transmute(orig) };
        unsafe { orig_fn(s, buffers, buffer_count, number_of_bytes_sent, flags, to, tolen, overlapped, completion_routine) }
    } else {
        -1
    };

    // On Windows/Proton, asynchronous/overlapped I/O returns SOCKET_ERROR (-1) with WSA_IO_PENDING (997).
    // The outbound data buffer is already valid and queued for send, so we can extract it.
    let is_success = ret == 0 || ret > 0;
    let is_pending = ret == -1 && unsafe { WSAGetLastError() } == WSA_IO_PENDING;

    if is_success || is_pending {
        let bytes_sent = if !number_of_bytes_sent.is_null() && unsafe { *number_of_bytes_sent } > 0 {
            (unsafe { *number_of_bytes_sent }) as usize
        } else {
            // Overlapped or pending byte count; calculate total requested bytes from buffers (up to 4096)
            let mut total_req = 0usize;
            if !buffers.is_null() && buffer_count > 0 {
                let slice = unsafe { std::slice::from_raw_parts(buffers, buffer_count as usize) };
                for b in slice {
                    total_req = total_req.saturating_add(b.len as usize);
                }
            }
            if total_req > 0 { total_req.min(4096) } else { 2048 }
        };

        if bytes_sent > 0 {
            super::count_raw_packet(PacketKind::Udp, PacketDirection::Outbound, bytes_sent);
            let data = unsafe { extract_wsabuf_data(buffers, buffer_count, bytes_sent) };
            if !data.is_empty() {
                let local = unsafe { query_local_endpoint(s) };
                let remote = unsafe { format_sockaddr(to) }.or_else(|| unsafe { query_peer_endpoint(s) });

                super::record_packet(
                    PacketKind::Udp,
                    PacketDirection::Outbound,
                    local,
                    remote,
                    None,
                    None,
                    &data,
                );
            }
        }
    }

    ret
}

/// Hooked `WSARecvFrom` callback (Modern UDP inbound).
pub unsafe extern "system" fn hooked_wsarecvfrom(
    s: SOCKET,
    buffers: *const WSABUF,
    buffer_count: u32,
    number_of_bytes_recvd: *mut u32,
    flags: *mut u32,
    from: *mut SOCKADDR,
    fromlen: *mut i32,
    overlapped: *mut c_void,
    completion_routine: *mut c_void,
) -> i32 {
    let orig = ORIGINAL_WSARECVFROM.load(Ordering::Relaxed);
    let ret = if !orig.is_null() {
        let orig_fn: FnWSARecvFrom = unsafe { std::mem::transmute(orig) };
        unsafe { orig_fn(s, buffers, buffer_count, number_of_bytes_recvd, flags, from, fromlen, overlapped, completion_routine) }
    } else {
        -1
    };

    if ret == 0 {
        let bytes_recvd = if !number_of_bytes_recvd.is_null() {
            (unsafe { *number_of_bytes_recvd }) as usize
        } else {
            0
        };

        if bytes_recvd > 0 {
            super::count_raw_packet(PacketKind::Udp, PacketDirection::Inbound, bytes_recvd);
            let data = unsafe { extract_wsabuf_data(buffers, buffer_count, bytes_recvd) };
            if !data.is_empty() {
                let local = unsafe { query_local_endpoint(s) };
                let remote = unsafe { format_sockaddr(from) }.or_else(|| unsafe { query_peer_endpoint(s) });

                super::record_packet(
                    PacketKind::Udp,
                    PacketDirection::Inbound,
                    local,
                    remote,
                    None,
                    None,
                    &data,
                );
            }
        }
    }

    ret
}

/// Hooked `WSASend` callback (WSA stream/connected datagram outbound).
pub unsafe extern "system" fn hooked_wsasend(
    s: SOCKET,
    buffers: *const WSABUF,
    buffer_count: u32,
    number_of_bytes_sent: *mut u32,
    flags: u32,
    overlapped: *mut c_void,
    completion_routine: *mut c_void,
) -> i32 {
    let orig = ORIGINAL_WSASEND.load(Ordering::Relaxed);
    let ret = if !orig.is_null() {
        let orig_fn: FnWSASend = unsafe { std::mem::transmute(orig) };
        unsafe { orig_fn(s, buffers, buffer_count, number_of_bytes_sent, flags, overlapped, completion_routine) }
    } else {
        -1
    };

    let is_success = ret == 0 || ret > 0;
    let is_pending = ret == -1 && unsafe { WSAGetLastError() } == WSA_IO_PENDING;

    if is_success || is_pending {
        let bytes_sent = if !number_of_bytes_sent.is_null() && unsafe { *number_of_bytes_sent } > 0 {
            (unsafe { *number_of_bytes_sent }) as usize
        } else {
            let mut total_req = 0usize;
            if !buffers.is_null() && buffer_count > 0 {
                let slice = unsafe { std::slice::from_raw_parts(buffers, buffer_count as usize) };
                for b in slice {
                    total_req = total_req.saturating_add(b.len as usize);
                }
            }
            if total_req > 0 { total_req.min(4096) } else { 2048 }
        };

        if bytes_sent > 0 {
            super::count_raw_packet(PacketKind::Tcp, PacketDirection::Outbound, bytes_sent);
            let data = unsafe { extract_wsabuf_data(buffers, buffer_count, bytes_sent) };
            if !data.is_empty() {
                let local = unsafe { query_local_endpoint(s) };
                let remote = unsafe { query_peer_endpoint(s) };

                super::record_packet(
                    PacketKind::Tcp,
                    PacketDirection::Outbound,
                    local,
                    remote,
                    None,
                    None,
                    &data,
                );
            }
        }
    }

    ret
}

/// Hooked `WSARecv` callback (WSA stream/connected datagram inbound).
pub unsafe extern "system" fn hooked_wsarecv(
    s: SOCKET,
    buffers: *const WSABUF,
    buffer_count: u32,
    number_of_bytes_recvd: *mut u32,
    flags: *mut u32,
    overlapped: *mut c_void,
    completion_routine: *mut c_void,
) -> i32 {
    let orig = ORIGINAL_WSARECV.load(Ordering::Relaxed);
    let ret = if !orig.is_null() {
        let orig_fn: FnWSARecv = unsafe { std::mem::transmute(orig) };
        unsafe { orig_fn(s, buffers, buffer_count, number_of_bytes_recvd, flags, overlapped, completion_routine) }
    } else {
        -1
    };

    if ret == 0 {
        let bytes_recvd = if !number_of_bytes_recvd.is_null() {
            (unsafe { *number_of_bytes_recvd }) as usize
        } else {
            0
        };

        if bytes_recvd > 0 {
            super::count_raw_packet(PacketKind::Tcp, PacketDirection::Inbound, bytes_recvd);
            let data = unsafe { extract_wsabuf_data(buffers, buffer_count, bytes_recvd) };
            if !data.is_empty() {
                let local = unsafe { query_local_endpoint(s) };
                let remote = unsafe { query_peer_endpoint(s) };

                super::record_packet(
                    PacketKind::Tcp,
                    PacketDirection::Inbound,
                    local,
                    remote,
                    None,
                    None,
                    &data,
                );
            }
        }
    }

    ret
}

/// Install detour hook for a specific Winsock function.
unsafe fn install_hook(
    proc_name: &[u8],
    callback_addr: u64,
    target_orig: &AtomicPtr<c_void>,
) -> (bool, String) {
    let proc_name_str = String::from_utf8_lossy(proc_name).trim_end_matches('\0').to_string();
    let ws2_mod = unsafe { GetModuleHandleA(b"ws2_32.dll\0".as_ptr()) };
    if ws2_mod.is_null() {
        return (false, format!("{}=FAIL(ws2_32.dll not loaded)", proc_name_str));
    }

    let fn_ptr = unsafe { GetProcAddress(ws2_mod, proc_name.as_ptr()) };
    if let Some(target_fn) = fn_ptr {
        let target_u64 = target_fn as u64;
        let payload = trainlab_cave::emitter::jmp_abs(callback_addr);
        let hook = trainlab_cave::cave::HookKind::Trampoline {
            payload: payload.clone(),
            jump: trainlab_cave::cave::JumpStyle::Absolute,
        };

        let mem = trainlab_core::memory::SelfProcess;
        let read = |addr: u64, len: usize| -> Result<Vec<u8>, String> {
            use trainlab_core::memory::ProcessMemory;
            mem.read(addr, len).map_err(|e| e.to_string())
        };
        let write = |addr: u64, data: &[u8]| -> Result<usize, String> {
            use trainlab_core::memory::ProcessMemory;
            mem.write(addr, data).map_err(|e| e.to_string())
        };
        let allocate = |size: usize, exec: bool| -> Result<u64, String> {
            crate::allocate(size, exec)
        };

        match trainlab_cave::cave::install(target_u64, hook, read, write, allocate) {
            Ok(installed) => {
                target_orig.store(
                    (installed.cave_addr + payload.len() as u64) as *mut c_void,
                    Ordering::SeqCst,
                );
                tracing::info!(
                    "Hooked Winsock {} at 0x{:X} -> trampoline at 0x{:X}",
                    proc_name_str,
                    target_u64,
                    installed.cave_addr
                );
                (true, format!("{}=Y", proc_name_str))
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to hook Winsock {}: {}",
                    proc_name_str,
                    e
                );
                (false, format!("{}=FAIL({})", proc_name_str, e))
            }
        }
    } else {
        tracing::warn!(
            "GetProcAddress failed for Winsock {}",
            proc_name_str
        );
        (false, format!("{}=FAIL(GetProcAddress failed)", proc_name_str))
    }
}

/// Initialize Winsock hooks with retry loop in background thread.
pub fn init_winsock_hooks() {
    std::thread::sleep(Duration::from_millis(600));

    unsafe {
        // Ensure ws2_32.dll is loaded if not already
        let mut ws2_mod = GetModuleHandleA(b"ws2_32.dll\0".as_ptr());
        if ws2_mod.is_null() {
            ws2_mod = LoadLibraryA(b"ws2_32.dll\0".as_ptr());
        }
        if ws2_mod.is_null() {
            tracing::warn!("ws2_32.dll not loaded in process; skipping Winsock hooks");
            if let Ok(mut out) = crate::render::overlay::OUTBOUND_EVENTS.lock() {
                out.push(trainlab_core::protocol::Event::NetworkHooksInstalled {
                    subsystem: "winsock".to_string(),
                    results: vec!["ws2_32.dll not loaded".to_string()],
                });
            }
            return;
        }

        let mut hooked_any = false;
        let mut results = Vec::new();

        // Legacy sockets API
        let (h_send, r_send) = install_hook(b"send\0", hooked_send as *const () as u64, &ORIGINAL_SEND);
        results.push(r_send);
        hooked_any |= h_send;

        let (h_recv, r_recv) = install_hook(b"recv\0", hooked_recv as *const () as u64, &ORIGINAL_RECV);
        results.push(r_recv);
        hooked_any |= h_recv;

        let (h_sendto, r_sendto) = install_hook(b"sendto\0", hooked_sendto as *const () as u64, &ORIGINAL_SENDTO);
        results.push(r_sendto);
        hooked_any |= h_sendto;

        let (h_recvfrom, r_recvfrom) = install_hook(b"recvfrom\0", hooked_recvfrom as *const () as u64, &ORIGINAL_RECVFROM);
        results.push(r_recvfrom);
        hooked_any |= h_recvfrom;

        // Modern WSA sockets API
        let (h_wsasendto, r_wsasendto) = install_hook(b"WSASendTo\0", hooked_wsasendto as *const () as u64, &ORIGINAL_WSASENDTO);
        results.push(r_wsasendto);
        hooked_any |= h_wsasendto;

        let (h_wsarecvfrom, r_wsarecvfrom) = install_hook(b"WSARecvFrom\0", hooked_wsarecvfrom as *const () as u64, &ORIGINAL_WSARECVFROM);
        results.push(r_wsarecvfrom);
        hooked_any |= h_wsarecvfrom;

        let (h_wsasend, r_wsasend) = install_hook(b"WSASend\0", hooked_wsasend as *const () as u64, &ORIGINAL_WSASEND);
        results.push(r_wsasend);
        hooked_any |= h_wsasend;

        let (h_wsarecv, r_wsarecv) = install_hook(b"WSARecv\0", hooked_wsarecv as *const () as u64, &ORIGINAL_WSARECV);
        results.push(r_wsarecv);
        hooked_any |= h_wsarecv;

        if hooked_any {
            WINSOCK_HOOKED.store(true, Ordering::SeqCst);
            tracing::info!(
                "[NETWORK] Winsock hooks installed: [{}]",
                results.join(", ")
            );
        } else {
            tracing::warn!(
                "[NETWORK] Failed to install any Winsock hooks: [{}]",
                results.join(", ")
            );
        }

        if let Ok(mut out) = crate::render::overlay::OUTBOUND_EVENTS.lock() {
            out.push(trainlab_core::protocol::Event::NetworkHooksInstalled {
                subsystem: "winsock".to_string(),
                results,
            });
        }
    }
}

