//! SChannel TLS/HTTPS interception hooks (`secur32.dll` / `sspicli.dll`).
//!
//! Winsock hooks (`send`/`recv`) only see bytes *after* TLS encryption has
//! wrapped them into records. Because this DLL is loaded directly inside the
//! game's address space, we can instead intercept the plaintext buffers at the
//! SChannel boundary:
//!
//! - `EncryptMessage`: outbound plaintext application payload (HTTP requests,
//!   JSON, protobufs) *before* it is wrapped into a TLS record.
//! - `DecryptMessage`: inbound plaintext response payload *after* the TLS
//!   record has been unwrapped.
//!
//! Both functions take a `SecBufferDesc` whose `pBuffers` array contains one
//! or more `SecBuffer` entries. The buffer with `BufferType == SECBUFFER_DATA`
//! holds the raw application payload. We detour these functions, call the
//! original, then walk the buffer array to extract the plaintext.

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::time::Duration;

use windows_sys::Win32::Security::Authentication::Identity::{SecBufferDesc, SECBUFFER_DATA};
use windows_sys::Win32::Security::Credentials::SecHandle;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};

use trainlab_core::protocol::{PacketDirection, PacketKind};

/// `SEC_E_OK` — the success status returned by `EncryptMessage`/`DecryptMessage`.
const SEC_E_OK: i32 = 0;

type FnEncryptMessage = unsafe extern "system" fn(
    *const SecHandle,
    u32,
    *const SecBufferDesc,
    u32,
) -> i32;

type FnDecryptMessage = unsafe extern "system" fn(
    *const SecHandle,
    *const SecBufferDesc,
    u32,
    *mut u32,
) -> i32;

static ORIGINAL_ENCRYPT_MESSAGE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIGINAL_DECRYPT_MESSAGE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

static SCHANNEL_HOOKED: AtomicBool = AtomicBool::new(false);

/// Walk a `SecBufferDesc` and return the first `SECBUFFER_DATA` buffer's
/// payload pointer + length (if any). Returns `None` if there is no data
/// buffer.
///
/// ⚠️ The pointer's validity depends on which function is calling:
/// - `DecryptMessage` (post-call): the buffer holds fresh plaintext and
///   must be copied before returning.
/// - `EncryptMessage` (pre-call): the buffer holds plaintext only *before*
///   the original call runs; afterwards it holds ciphertext.
///
/// Callers must copy before returning either way.
unsafe fn data_buffer_payload(desc: *const SecBufferDesc) -> Option<(*const u8, usize)> {
    if desc.is_null() {
        return None;
    }
    let desc_ref = unsafe { &*desc };
    if desc_ref.pBuffers.is_null() || desc_ref.cBuffers == 0 {
        return None;
    }
    let buffers = unsafe { std::slice::from_raw_parts(desc_ref.pBuffers, desc_ref.cBuffers as usize) };
    for buf in buffers {
        if buf.BufferType == SECBUFFER_DATA && !buf.pvBuffer.is_null() && buf.cbBuffer > 0 {
            return Some((buf.pvBuffer as *const u8, buf.cbBuffer as usize));
        }
    }
    None
}

/// Hooked `EncryptMessage` callback (outbound plaintext, pre-TLS-wrap).
///
/// ⚠️ Buffer-lifetime asymmetry vs `hooked_decrypt_message`: SChannel's
/// `EncryptMessage` encrypts the caller's `SECBUFFER_DATA` buffer **in
/// place** — after the original returns, that buffer holds ciphertext
/// (app data followed by the TLS trailer: explicit nonce/MAC/tag bytes),
/// so reading it *after* the call yields the very ciphertext we were
/// trying to avoid. The outbound plaintext must therefore be copied
/// *before* invoking the original. (`DecryptMessage` is the reverse:
/// SChannel re-labels the buffer array on output, so the post-call
/// `SECBUFFER_DATA` buffer *is* the freshly decrypted plaintext.)
pub unsafe extern "system" fn hooked_encrypt_message(
    ph_context: *const SecHandle,
    f_qop: u32,
    p_message: *const SecBufferDesc,
    message_seq_no: u32,
) -> i32 {
    // Copy the plaintext request body while it is still plaintext.
    let plaintext = unsafe { data_buffer_payload(p_message) }
        .map(|(ptr, len)| unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec());

    let orig = ORIGINAL_ENCRYPT_MESSAGE.load(Ordering::Relaxed);
    let ret = if !orig.is_null() {
        let orig_fn: FnEncryptMessage = unsafe { std::mem::transmute(orig) };
        unsafe { orig_fn(ph_context, f_qop, p_message, message_seq_no) }
    } else {
        // Should never happen (hook installed with a valid original), but be safe.
        -1
    };

    // Only record when the encryption actually succeeded — a failed call
    // (e.g. handshake CONTINUE_NEEDED) did not send the plaintext anywhere.
    if ret == SEC_E_OK
        && let Some(payload) = plaintext.as_deref()
    {
        super::count_raw_packet(PacketKind::Http, PacketDirection::Outbound, payload.len());
        super::record_packet(
            PacketKind::Http,
            PacketDirection::Outbound,
            None,
            None,
            Some("TLS (SChannel) outbound".into()),
            None,
            payload,
        );
    }

    ret
}

/// Hooked `DecryptMessage` callback (inbound plaintext, post-TLS-unwrap).
pub unsafe extern "system" fn hooked_decrypt_message(
    ph_context: *const SecHandle,
    p_message: *const SecBufferDesc,
    message_seq_no: u32,
    pf_qop: *mut u32,
) -> i32 {
    let orig = ORIGINAL_DECRYPT_MESSAGE.load(Ordering::Relaxed);
    let ret = if !orig.is_null() {
        let orig_fn: FnDecryptMessage = unsafe { std::mem::transmute(orig) };
        unsafe { orig_fn(ph_context, p_message, message_seq_no, pf_qop) }
    } else {
        -1
    };

    if ret == SEC_E_OK {
        if let Some((ptr, len)) = unsafe { data_buffer_payload(p_message) } {
            super::count_raw_packet(PacketKind::Http, PacketDirection::Inbound, len);
            let payload = unsafe { std::slice::from_raw_parts(ptr, len) };
            super::record_packet(
                PacketKind::Http,
                PacketDirection::Inbound,
                None,
                None,
                Some("TLS (SChannel) inbound".into()),
                None,
                payload,
            );
        }
    }

    ret
}

/// Install a detour hook for a specific SChannel function.
unsafe fn install_hook(
    proc_name: &[u8],
    callback_addr: u64,
    target_orig: &AtomicPtr<c_void>,
) -> (bool, String) {
    let proc_name_str = String::from_utf8_lossy(proc_name).trim_end_matches('\0').to_string();
    // SChannel exports live in secur32.dll (and are forwarded from sspicli.dll).
    let secur32_mod = unsafe { GetModuleHandleA(b"secur32.dll\0".as_ptr()) };
    if secur32_mod.is_null() {
        return (false, format!("{}=FAIL(secur32.dll not loaded)", proc_name_str));
    }

    let fn_ptr = unsafe { GetProcAddress(secur32_mod, proc_name.as_ptr()) };
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

/// Initialize SChannel hooks with a background check.
pub fn init_schannel_hooks() {
    std::thread::sleep(Duration::from_millis(900));

    unsafe {
        // Ensure secur32.dll is loaded if not already.
        let mut secur32_mod = GetModuleHandleA(b"secur32.dll\0".as_ptr());
        if secur32_mod.is_null() {
            secur32_mod = LoadLibraryA(b"secur32.dll\0".as_ptr());
        }
        if secur32_mod.is_null() {
            tracing::info!("secur32.dll not loaded in process; skipping SChannel hooks");
            if let Ok(mut out) = crate::render::overlay::OUTBOUND_EVENTS.lock() {
                out.push(trainlab_core::protocol::Event::NetworkHooksInstalled {
                    subsystem: "schannel".to_string(),
                    results: vec!["secur32.dll not loaded".to_string()],
                });
            }
            return;
        }

        let mut hooked_any = false;
        let mut results = Vec::new();

        let (h_enc, r_enc) = install_hook(
            b"EncryptMessage\0",
            hooked_encrypt_message as *const () as u64,
            &ORIGINAL_ENCRYPT_MESSAGE,
        );
        results.push(r_enc);
        hooked_any |= h_enc;

        let (h_dec, r_dec) = install_hook(
            b"DecryptMessage\0",
            hooked_decrypt_message as *const () as u64,
            &ORIGINAL_DECRYPT_MESSAGE,
        );
        results.push(r_dec);
        hooked_any |= h_dec;

        if hooked_any {
            SCHANNEL_HOOKED.store(true, Ordering::SeqCst);
            tracing::info!(
                "[NETWORK] SChannel hooks installed: [{}]",
                results.join(", ")
            );
        } else {
            tracing::warn!(
                "[NETWORK] Failed to install any SChannel hooks: [{}]",
                results.join(", ")
            );
        }

        if let Ok(mut out) = crate::render::overlay::OUTBOUND_EVENTS.lock() {
            out.push(trainlab_core::protocol::Event::NetworkHooksInstalled {
                subsystem: "schannel".to_string(),
                results,
            });
        }
    }
}
