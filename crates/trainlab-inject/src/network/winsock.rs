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
    getpeername, getsockname, AF_INET, AF_INET6, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKET,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};

use trainlab_core::protocol::{PacketDirection, PacketKind};

type FnSend = unsafe extern "system" fn(SOCKET, *const u8, i32, i32) -> i32;
type FnRecv = unsafe extern "system" fn(SOCKET, *mut u8, i32, i32) -> i32;
type FnSendTo = unsafe extern "system" fn(SOCKET, *const u8, i32, i32, *const SOCKADDR, i32) -> i32;
type FnRecvFrom = unsafe extern "system" fn(SOCKET, *mut u8, i32, i32, *mut SOCKADDR, *mut i32) -> i32;

static ORIGINAL_SEND: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIGINAL_RECV: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIGINAL_SENDTO: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIGINAL_RECVFROM: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

static WINSOCK_HOOKED: AtomicBool = AtomicBool::new(false);

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

/// Install detour hook for a specific Winsock function.
unsafe fn install_hook(
    proc_name: &[u8],
    callback_addr: u64,
    target_orig: &AtomicPtr<c_void>,
) -> bool {
    let ws2_mod = unsafe { GetModuleHandleA(b"ws2_32.dll\0".as_ptr()) };
    if ws2_mod.is_null() {
        return false;
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
                    "Hooked {} at 0x{:X} -> trampoline at 0x{:X}",
                    String::from_utf8_lossy(proc_name),
                    target_u64,
                    installed.cave_addr
                );
                true
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to hook {}: {}",
                    String::from_utf8_lossy(proc_name),
                    e
                );
                false
            }
        }
    } else {
        false
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
            return;
        }

        let mut hooked_any = false;

        hooked_any |= install_hook(b"send\0", hooked_send as *const () as u64, &ORIGINAL_SEND);
        hooked_any |= install_hook(b"recv\0", hooked_recv as *const () as u64, &ORIGINAL_RECV);
        hooked_any |= install_hook(b"sendto\0", hooked_sendto as *const () as u64, &ORIGINAL_SENDTO);
        hooked_any |= install_hook(b"recvfrom\0", hooked_recvfrom as *const () as u64, &ORIGINAL_RECVFROM);

        if hooked_any {
            WINSOCK_HOOKED.store(true, Ordering::SeqCst);
            tracing::info!("Winsock TCP/UDP traffic interception hooks installed successfully");
        }
    }
}
