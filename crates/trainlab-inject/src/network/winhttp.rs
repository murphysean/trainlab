//! WinHTTP API interception hooks (`winhttp.dll`).
//!
//! Detour hooks for higher-level HTTP/REST inspection:
//! - `WinHttpOpenRequest`: Captures HTTP method, object name/path.
//! - `WinHttpSendRequest`: Captures request headers and optional post body data (outbound).
//! - `WinHttpReceiveResponse`: Captures response status and headers.
//! - `WinHttpReadData`: Captures inbound HTTP body response payload.

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};

use trainlab_core::protocol::{PacketDirection, PacketKind};

type HInternet = *mut c_void;

type FnWinHttpOpenRequest = unsafe extern "system" fn(
    HInternet,
    *const u16,
    *const u16,
    *const u16,
    *const u16,
    *const *const u16,
    u32,
) -> HInternet;

type FnWinHttpSendRequest = unsafe extern "system" fn(
    HInternet,
    *const u16,
    u32,
    *const c_void,
    u32,
    u32,
    usize,
) -> i32;

type FnWinHttpReceiveResponse = unsafe extern "system" fn(HInternet, *mut c_void) -> i32;

type FnWinHttpReadData = unsafe extern "system" fn(
    HInternet,
    *mut c_void,
    u32,
    *mut u32,
) -> i32;

type FnWinHttpCloseHandle = unsafe extern "system" fn(HInternet) -> i32;

static ORIGINAL_WINHTTP_OPEN_REQUEST: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIGINAL_WINHTTP_SEND_REQUEST: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIGINAL_WINHTTP_RECEIVE_RESPONSE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIGINAL_WINHTTP_READ_DATA: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIGINAL_WINHTTP_CLOSE_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

static WINHTTP_HOOKED: AtomicBool = AtomicBool::new(false);

/// Information tracked per active HInternet request handle.
#[derive(Debug, Clone, Default)]
struct RequestContext {
    verb: String,
    path: String,
    headers: String,
}

static ACTIVE_REQUESTS: Mutex<Option<HashMap<usize, RequestContext>>> = Mutex::new(None);

unsafe fn pwstr_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0;
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    String::from_utf16_lossy(slice)
}

/// Hooked `WinHttpOpenRequest` callback.
pub unsafe extern "system" fn hooked_winhttp_open_request(
    h_connect: HInternet,
    pwsz_verb: *const u16,
    pwsz_object_name: *const u16,
    pwsz_version: *const u16,
    pwsz_referrer: *const u16,
    ppwsz_accept_types: *const *const u16,
    dw_flags: u32,
) -> HInternet {
    let orig = ORIGINAL_WINHTTP_OPEN_REQUEST.load(Ordering::Relaxed);
    let handle = if !orig.is_null() {
        let orig_fn: FnWinHttpOpenRequest = unsafe { std::mem::transmute(orig) };
        unsafe {
            orig_fn(
                h_connect,
                pwsz_verb,
                pwsz_object_name,
                pwsz_version,
                pwsz_referrer,
                ppwsz_accept_types,
                dw_flags,
            )
        }
    } else {
        std::ptr::null_mut()
    };

    if !handle.is_null() {
        let verb = unsafe { pwstr_to_string(pwsz_verb) };
        let path = unsafe { pwstr_to_string(pwsz_object_name) };
        let mut req_ctx = RequestContext::default();
        req_ctx.verb = if verb.is_empty() { "GET".into() } else { verb };
        req_ctx.path = path;

        if let Ok(mut lock) = ACTIVE_REQUESTS.lock() {
            let map = lock.get_or_insert_with(HashMap::new);
            map.insert(handle as usize, req_ctx);
        }
    }

    handle
}

/// Hooked `WinHttpSendRequest` callback (outbound HTTP request).
pub unsafe extern "system" fn hooked_winhttp_send_request(
    h_request: HInternet,
    pwsz_headers: *const u16,
    dw_headers_length: u32,
    lp_optional: *const c_void,
    dw_optional_length: u32,
    dw_total_length: u32,
    dw_context: usize,
) -> i32 {
    let orig = ORIGINAL_WINHTTP_SEND_REQUEST.load(Ordering::Relaxed);
    let ret = if !orig.is_null() {
        let orig_fn: FnWinHttpSendRequest = unsafe { std::mem::transmute(orig) };
        unsafe {
            orig_fn(
                h_request,
                pwsz_headers,
                dw_headers_length,
                lp_optional,
                dw_optional_length,
                dw_total_length,
                dw_context,
            )
        }
    } else {
        0
    };

    if ret != 0 {
        let headers = if !pwsz_headers.is_null() {
            if dw_headers_length > 0 && dw_headers_length != u32::MAX {
                let slice = unsafe { std::slice::from_raw_parts(pwsz_headers, dw_headers_length as usize) };
                String::from_utf16_lossy(slice)
            } else {
                unsafe { pwstr_to_string(pwsz_headers) }
            }
        } else {
            String::new()
        };

        let mut verb = "POST".to_string();
        let mut path = "".to_string();

        if let Ok(mut lock) = ACTIVE_REQUESTS.lock() {
            if let Some(map) = lock.as_mut() {
                if let Some(ctx) = map.get_mut(&(h_request as usize)) {
                    ctx.headers = headers.clone();
                    verb = ctx.verb.clone();
                    path = ctx.path.clone();
                }
            }
        }

        let payload_slice = if !lp_optional.is_null() && dw_optional_length > 0 {
            unsafe { std::slice::from_raw_parts(lp_optional as *const u8, dw_optional_length as usize) }
        } else {
            &[]
        };

        let url_str = format!("{verb} {path}");
        super::count_raw_packet(PacketKind::Http, PacketDirection::Outbound, payload_slice.len());
        super::record_packet(
            PacketKind::Http,
            PacketDirection::Outbound,
            None,
            None,
            Some(url_str),
            if headers.is_empty() { None } else { Some(headers) },
            payload_slice,
        );
    }

    ret
}

/// Hooked `WinHttpReceiveResponse` callback.
pub unsafe extern "system" fn hooked_winhttp_receive_response(
    h_request: HInternet,
    lp_reserved: *mut c_void,
) -> i32 {
    let orig = ORIGINAL_WINHTTP_RECEIVE_RESPONSE.load(Ordering::Relaxed);
    if !orig.is_null() {
        let orig_fn: FnWinHttpReceiveResponse = unsafe { std::mem::transmute(orig) };
        unsafe { orig_fn(h_request, lp_reserved) }
    } else {
        0
    }
}

/// Hooked `WinHttpReadData` callback (inbound HTTP response payload).
pub unsafe extern "system" fn hooked_winhttp_read_data(
    h_request: HInternet,
    lp_buffer: *mut c_void,
    dw_number_of_bytes_to_read: u32,
    lpdw_number_of_bytes_read: *mut u32,
) -> i32 {
    let orig = ORIGINAL_WINHTTP_READ_DATA.load(Ordering::Relaxed);
    let ret = if !orig.is_null() {
        let orig_fn: FnWinHttpReadData = unsafe { std::mem::transmute(orig) };
        unsafe {
            orig_fn(
                h_request,
                lp_buffer,
                dw_number_of_bytes_to_read,
                lpdw_number_of_bytes_read,
            )
        }
    } else {
        0
    };

    if ret != 0 && !lpdw_number_of_bytes_read.is_null() {
        let read_bytes = unsafe { *lpdw_number_of_bytes_read } as usize;
        if read_bytes > 0 && !lp_buffer.is_null() {
            super::count_raw_packet(PacketKind::Http, PacketDirection::Inbound, read_bytes);
            let slice = unsafe { std::slice::from_raw_parts(lp_buffer as *const u8, read_bytes) };

            let mut path = "".to_string();
            let mut headers = "".to_string();

            if let Ok(lock) = ACTIVE_REQUESTS.lock() {
                if let Some(map) = lock.as_ref() {
                    if let Some(ctx) = map.get(&(h_request as usize)) {
                        path = ctx.path.clone();
                        headers = ctx.headers.clone();
                    }
                }
            }

            super::record_packet(
                PacketKind::Http,
                PacketDirection::Inbound,
                None,
                None,
                if path.is_empty() { None } else { Some(format!("RESP {path}")) },
                if headers.is_empty() { None } else { Some(headers) },
                slice,
            );
        }
    }

    ret
}

/// Hooked `WinHttpCloseHandle` callback to clean up active request metadata.
pub unsafe extern "system" fn hooked_winhttp_close_handle(h_internet: HInternet) -> i32 {
    if let Ok(mut lock) = ACTIVE_REQUESTS.lock() {
        if let Some(map) = lock.as_mut() {
            map.remove(&(h_internet as usize));
        }
    }

    let orig = ORIGINAL_WINHTTP_CLOSE_HANDLE.load(Ordering::Relaxed);
    if !orig.is_null() {
        let orig_fn: FnWinHttpCloseHandle = unsafe { std::mem::transmute(orig) };
        unsafe { orig_fn(h_internet) }
    } else {
        0
    }
}

/// Install detour hook for a specific WinHTTP function.
unsafe fn install_hook(
    proc_name: &[u8],
    callback_addr: u64,
    target_orig: &AtomicPtr<c_void>,
) -> (bool, String) {
    let proc_name_str = String::from_utf8_lossy(proc_name).trim_end_matches('\0').to_string();
    let winhttp_mod = unsafe { GetModuleHandleA(b"winhttp.dll\0".as_ptr()) };
    if winhttp_mod.is_null() {
        return (false, format!("{}=FAIL(winhttp.dll not loaded)", proc_name_str));
    }

    let fn_ptr = unsafe { GetProcAddress(winhttp_mod, proc_name.as_ptr()) };
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
                (true, format!("{}=Y", String::from_utf8_lossy(proc_name).trim_end_matches('\0')))
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to hook {}: {}",
                    String::from_utf8_lossy(proc_name),
                    e
                );
                (false, format!("{}=FAIL({})", String::from_utf8_lossy(proc_name).trim_end_matches('\0'), e))
            }
        }
    } else {
        (false, format!("{}=FAIL(GetProcAddress failed)", String::from_utf8_lossy(proc_name).trim_end_matches('\0')))
    }
}

/// Initialize WinHTTP hooks with background check.
pub fn init_winhttp_hooks() {
    std::thread::sleep(Duration::from_millis(800));

    unsafe {
        let mut winhttp_mod = GetModuleHandleA(b"winhttp.dll\0".as_ptr());
        if winhttp_mod.is_null() {
            winhttp_mod = LoadLibraryA(b"winhttp.dll\0".as_ptr());
        }
        if winhttp_mod.is_null() {
            tracing::info!("winhttp.dll not loaded in process; skipping WinHTTP hooks");
            if let Ok(mut out) = crate::render::overlay::OUTBOUND_EVENTS.lock() {
                out.push(trainlab_core::protocol::Event::NetworkHooksInstalled {
                    subsystem: "winhttp".to_string(),
                    results: vec!["winhttp.dll not loaded".to_string()],
                });
            }
            return;
        }

        let mut hooked_any = false;
        let mut results = Vec::new();

        let (h_open, r_open) = install_hook(
            b"WinHttpOpenRequest\0",
            hooked_winhttp_open_request as *const () as u64,
            &ORIGINAL_WINHTTP_OPEN_REQUEST,
        );
        results.push(r_open);
        hooked_any |= h_open;

        let (h_send, r_send) = install_hook(
            b"WinHttpSendRequest\0",
            hooked_winhttp_send_request as *const () as u64,
            &ORIGINAL_WINHTTP_SEND_REQUEST,
        );
        results.push(r_send);
        hooked_any |= h_send;

        let (h_recv, r_recv) = install_hook(
            b"WinHttpReceiveResponse\0",
            hooked_winhttp_receive_response as *const () as u64,
            &ORIGINAL_WINHTTP_RECEIVE_RESPONSE,
        );
        results.push(r_recv);
        hooked_any |= h_recv;

        let (h_read, r_read) = install_hook(
            b"WinHttpReadData\0",
            hooked_winhttp_read_data as *const () as u64,
            &ORIGINAL_WINHTTP_READ_DATA,
        );
        results.push(r_read);
        hooked_any |= h_read;

        let (h_close, r_close) = install_hook(
            b"WinHttpCloseHandle\0",
            hooked_winhttp_close_handle as *const () as u64,
            &ORIGINAL_WINHTTP_CLOSE_HANDLE,
        );
        results.push(r_close);
        hooked_any |= h_close;

        if hooked_any {
            WINHTTP_HOOKED.store(true, Ordering::SeqCst);
            tracing::info!("WinHTTP REST/API traffic interception hooks installed successfully: [{}]", results.join(", "));
        } else {
            tracing::warn!("Failed to install any WinHTTP hooks: [{}]", results.join(", "));
        }

        if let Ok(mut out) = crate::render::overlay::OUTBOUND_EVENTS.lock() {
            out.push(trainlab_core::protocol::Event::NetworkHooksInstalled {
                subsystem: "winhttp".to_string(),
                results,
            });
        }
    }
}
