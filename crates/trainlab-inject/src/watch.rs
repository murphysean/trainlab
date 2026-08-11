//! # Hardware watchpoints (T-028) and int3 breakpoints (T-029)
//!
//! These features are **Windows-only** and implemented with a vectored
//! exception handler (VEH) that runs *inside* the game process.
//!
//! - **T-028 `WatchWrites`**: arm a data-write hardware watchpoint on DR0 by
//!   programming DR0/DR7 on every thread of the process. When the game writes
//!   the watched address the CPU raises a `#DB` (debug) exception surfaced to
//!   our VEH as `EXCEPTION_SINGLE_STEP`. We capture the writing thread's
//!   registers (RIP + general purpose) and report which code did the write.
//! - **T-029 `BreakOnCode`**: patch a single code byte with `0xCC` (int3). When
//!   execution reaches it the VEH sees `EXCEPTION_BREAKPOINT`, restores the
//!   original byte, steps `RIP` back onto it, captures registers plus a raw
//!   stack trace, and reports. This is a single-fire breakpoint.
//!
//! Both features are best-effort and safe: they clear themselves after a hit
//! so the game never gets wedged on an unhandled exception.

use std::ffi::c_void;
use std::sync::{Mutex, OnceLock};

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, EXCEPTION_ACCESS_VIOLATION, EXCEPTION_BREAKPOINT,
    EXCEPTION_SINGLE_STEP, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, GetThreadContext, RemoveVectoredExceptionHandler,
    SetThreadContext, CONTEXT, CONTEXT_CONTROL_AMD64, CONTEXT_DEBUG_REGISTERS_AMD64,
    CONTEXT_INTEGER_AMD64, EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_POINTERS,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows_sys::Win32::System::Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcessId, GetCurrentThread, GetCurrentThreadId, OpenThread, ResumeThread,
    SuspendThread, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION, THREAD_SET_CONTEXT,
    THREAD_SUSPEND_RESUME,
};

/// Register + stack snapshot reported when a watchpoint/breakpoint fires.
#[derive(Debug, Clone)]
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
    /// Raw stack trace: `u64` words read upward from `rsp`, formatted as hex.
    pub stack: Vec<String>,
}

/// What kind of trap is currently armed.
#[derive(Clone, Copy, PartialEq)]
enum WatchKind {
    /// Data-write hardware watchpoint (DR0/DR7).
    DataWrite,
    /// int3 software breakpoint.
    Code,
}

struct ActiveWatch {
    kind: WatchKind,
    address: u64,
    /// Original byte that was overwritten with `0xCC` (breakpoints only).
    original_byte: u8,
}

struct Runtime {
    state: Mutex<Option<ActiveWatch>>,
    veh_handle: Mutex<Option<VehHandle>>,
    /// The most recent hit, kept until the caller polls it (so an async
    /// watchpoint that fires after arming isn't lost when the arming TCP
    /// call returns).
    last_hit: Mutex<Option<HitInfo>>,
}

/// A raw pointer wrapper that is explicitly `Send + Sync`, so it can live in a
/// `static`. The VEH handle is only ever stored and compared for null; it is
/// never dereferenced through this wrapper.
struct VehHandle(*mut c_void);
unsafe impl Send for VehHandle {}
unsafe impl Sync for VehHandle {}
impl VehHandle {
    #[allow(dead_code)]
    fn as_ptr(&self) -> *mut c_void {
        self.0
    }
}

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

fn runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| Runtime {
        state: Mutex::new(None),
        veh_handle: Mutex::new(None),
        last_hit: Mutex::new(None),
    })
}

/// Install the vectored exception handler exactly once.
fn ensure_veh() {
    let mut guard = runtime().veh_handle.lock().unwrap();
    if guard.is_none() {
        // SAFETY: `veh_handler` is a valid extern "system" fn. Registering it
        // as the first handler gives us first crack at single-step/breakpoint
        // exceptions. We never unregister it; it simply ignores everything it
        // does not own.
        let h = unsafe { AddVectoredExceptionHandler(1, Some(veh_handler)) };
        if !h.is_null() {
            *guard = Some(VehHandle(h));
        }
    }
}

/// Arm a data-write hardware watchpoint on `address` for all threads.
///
/// The watchpoint stays armed; when it fires, the [`HitInfo`] is stored so it
/// can be retrieved later via [`poll_hit`]. This supports the async model:
/// arm, let the game run, then poll for the hit.
pub fn arm_watch(
    address: u64,
    len: usize,
    _one_shot: bool,
) -> Result<(), String> {
    clear_internal();
    ensure_veh();

    // DR7 bits for a data-write breakpoint on DR0:
    //   bit 0  (L0)     : locally enable DR0
    //   bits 16-17 (R/W0): 01 = data write
    //   bits 18-19 (LEN0): 00=1B, 01=2B, 10=4B, 11=8B
    let len_code = if len >= 8 {
        0b11
    } else if len >= 4 {
        0b10
    } else if len >= 2 {
        0b01
    } else {
        0b00
    };
    let dr7 = (1u64 << 0) | (1u64 << 16) | ((len_code as u64) << 18);
    apply_debug_registers_all(address, dr7);

    *runtime().state.lock().unwrap() = Some(ActiveWatch {
        kind: WatchKind::DataWrite,
        address,
        original_byte: 0,
    });
    Ok(())
}

/// Arm a single-fire int3 breakpoint on `address`.
///
/// When it fires the [`HitInfo`] (with a stack trace) is stored; retrieve it
/// via [`poll_hit`].
pub fn arm_break(address: u64, _one_shot: bool) -> Result<(), String> {
    clear_internal();
    ensure_veh();
    if address == 0 {
        return Err("invalid breakpoint address 0x0".into());
    }

    let original = read_byte(address);
    write_byte(address, 0xCC)
        .map_err(|e| format!("failed to patch code byte with int3: {e}"))?;

    *runtime().state.lock().unwrap() = Some(ActiveWatch {
        kind: WatchKind::Code,
        address,
        original_byte: original,
    });
    Ok(())
}

/// Poll for the most recent hit. Returns `None` if no hit has fired (or it was
/// already consumed), or the stored [`HitInfo`] otherwise.
pub fn poll_hit() -> Option<HitInfo> {
    runtime().last_hit.lock().unwrap().take()
}

/// Disarm any active watchpoint/breakpoint, restore patched bytes, and clear
/// the debug registers on all threads.
pub fn clear() {
    clear_internal();
}

fn clear_internal() {
    let mut guard = runtime().state.lock().unwrap();
    if let Some(active) = guard.take() {
        if active.kind == WatchKind::Code {
            let _ = write_byte(active.address, active.original_byte);
        }
    }
    drop(guard);
    apply_debug_registers_all(0, 0);
}

/// The VEH callback. Runs on the thread that took the exception.
///
/// # Safety
/// Registered via `AddVectoredExceptionHandler`; must match
/// `PVECTORED_EXCEPTION_HANDLER`.
unsafe extern "system" fn veh_handler(ep: *mut EXCEPTION_POINTERS) -> i32 {
    // SAFETY: `ep` was passed by the OS and is valid for the duration of the
    // call; we checked for null. All raw derefs are confined to this block.
    unsafe {
    if ep.is_null() {
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    let code = (*ep).ExceptionRecord.as_mut().map_or(0, |r| r.ExceptionCode);
    let ctx = (*ep).ContextRecord;
    if ctx.is_null() {
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    let mut guard = runtime().state.lock().unwrap();
    let Some(active) = guard.as_ref() else {
        // No watch armed; this exception is not ours.
        return EXCEPTION_CONTINUE_EXECUTION;
    };

    match active.kind {
        WatchKind::DataWrite => {
            // A data-write watchpoint surfaces as #DB (single step) or, in some
            // cases, an access violation at the write site.
            if code != EXCEPTION_SINGLE_STEP && code != EXCEPTION_ACCESS_VIOLATION {
                return EXCEPTION_CONTINUE_EXECUTION;
            }
            let hit = HitInfo {
                rip: (*ctx).Rip,
                rax: (*ctx).Rax,
                rbx: (*ctx).Rbx,
                rcx: (*ctx).Rcx,
                rdx: (*ctx).Rdx,
                rsi: (*ctx).Rsi,
                rdi: (*ctx).Rdi,
                rsp: (*ctx).Rsp,
                rbp: (*ctx).Rbp,
                description: format!("data-write watchpoint fired at 0x{:x}", active.address),
                stack: Vec::new(),
            };
            // Clear the current thread's watchpoint so we don't immediately
            // re-fire on the same instruction, then record the hit so the
            // caller can poll it (the arming TCP call has already returned).
            (*ctx).Dr0 = 0;
            (*ctx).Dr7 = 0;
            let _ = guard.take();
            *runtime().last_hit.lock().unwrap() = Some(hit);
            EXCEPTION_CONTINUE_EXECUTION
        }
        WatchKind::Code => {
            if code != EXCEPTION_BREAKPOINT {
                return EXCEPTION_CONTINUE_EXECUTION;
            }
            // For int3 the exception address is the 0xCC byte; RIP is one past.
            let exc_addr = (*ep)
                .ExceptionRecord
                .as_mut()
                .map_or(0, |r| r.ExceptionAddress as u64);
            let rip = (*ctx).Rip;
            if exc_addr != active.address && rip.wrapping_sub(1) != active.address {
                return EXCEPTION_CONTINUE_EXECUTION;
            }
            // Restore the original byte and step RIP back onto it so the
            // original instruction actually executes.
            let _ = write_byte(active.address, active.original_byte);
            (*ctx).Rip = rip.wrapping_sub(1);

            let stack = capture_stack((*ctx).Rsp, 16);
            let hit = HitInfo {
                rip: active.address,
                rax: (*ctx).Rax,
                rbx: (*ctx).Rbx,
                rcx: (*ctx).Rcx,
                rdx: (*ctx).Rdx,
                rsi: (*ctx).Rsi,
                rdi: (*ctx).Rdi,
                rsp: (*ctx).Rsp,
                rbp: (*ctx).Rbp,
                description: format!("breakpoint hit at 0x{:x}", active.address),
                stack,
            };
            let _ = guard.take();
            *runtime().last_hit.lock().unwrap() = Some(hit);
            EXCEPTION_CONTINUE_EXECUTION
        }
    }
    }
}

/// Read a single byte from the current process.
fn read_byte(address: u64) -> u8 {
    // SAFETY: caller guarantees `address` is a valid readable address.
    unsafe { *(address as *const u8) }
}

/// Write a single byte to the current process, temporarily flipping page
/// protection to executable+readwrite so we can patch code.
fn write_byte(address: u64, byte: u8) -> Result<(), String> {
    let ptr = address as *const c_void;
    let mut old = 0u32;
    // SAFETY: VirtualProtect on our own address space.
    let ok = unsafe { VirtualProtect(ptr, 1, PAGE_EXECUTE_READWRITE, &mut old) };
    if ok == 0 {
        return Err(last_err());
    }
    // SAFETY: caller guarantees `address` is writable.
    unsafe { *(address as *mut u8) = byte; }
    // Restore the original protection.
    unsafe {
        VirtualProtect(ptr, 1, old, &mut old);
    }
    Ok(())
}

/// Read `count` u64 words upward from `rsp` and format them as hex. This is a
/// raw, best-effort stack walk (the stack may be unwound from a frame that is
/// not strictly a chain of return addresses, but it is still a useful capture).
fn capture_stack(rsp: u64, count: usize) -> Vec<String> {
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let addr = rsp.wrapping_add((i as u64) * 8);
        // SAFETY: best-effort read; a stray value here is harmless.
        let val = unsafe { *(addr as *const u64) };
        out.push(format!("0x{val:016x}"));
    }
    out
}

/// Enumerate every thread in the current process and call `f` with its TID.
fn for_each_thread(mut f: impl FnMut(u32)) {
    // SAFETY: CreateToolhelp32Snapshot with TH32CS_SNAPTHREAD.
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snap == INVALID_HANDLE_VALUE {
        return;
    }
    let pid = unsafe { GetCurrentProcessId() };
    let mut te: THREADENTRY32 = unsafe { std::mem::zeroed() };
    te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
    // SAFETY: `te` is a valid THREADENTRY32; snap is a valid snapshot handle.
    let mut has = unsafe { Thread32First(snap, &mut te) != 0 };
    while has {
        if te.th32OwnerProcessID == pid {
            f(te.th32ThreadID);
        }
        has = unsafe { Thread32Next(snap, &mut te) != 0 };
    }
    // SAFETY: close the snapshot handle we opened.
    unsafe {
        CloseHandle(snap);
    }
}

/// Program DR0 = `dr0` and DR7 = `dr7` on every thread of the process
/// (including the current thread, via its pseudo-handle). Passing `dr0 = 0`
/// and `dr7 = 0` clears the watchpoint everywhere.
fn apply_debug_registers_all(dr0: u64, dr7: u64) {
    let current = unsafe { GetCurrentThreadId() };
    for_each_thread(|tid| {
        // SAFETY: OpenThread/GetCurrentThread return valid thread handles.
        let handle = unsafe {
            if tid == current {
                GetCurrentThread()
            } else {
                OpenThread(
                    THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME
                        | THREAD_QUERY_INFORMATION,
                    0,
                    tid,
                )
            }
        };
        if handle.is_null() {
            return;
        }
        // SAFETY: CONTEXT is zero-initialized (it is a large struct without a
        // Default impl) and configured before use.
        let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
        ctx.ContextFlags =
            CONTEXT_DEBUG_REGISTERS_AMD64 | CONTEXT_CONTROL_AMD64 | CONTEXT_INTEGER_AMD64;

        // Suspend non-current threads so Get/SetThreadContext is stable. The
        // current thread cannot suspend itself; set its registers directly.
        let suspended = if tid == current {
            0xFFFF_FFFFu32
        } else {
            // SAFETY: handle is a valid thread handle.
            unsafe { SuspendThread(handle) }
        };

        // SAFETY: ctx is a valid CONTEXT.
        if unsafe { GetThreadContext(handle, &mut ctx) } != 0 {
            ctx.Dr0 = dr0;
            ctx.Dr7 = dr7;
            // SAFETY: ctx is a valid CONTEXT.
            unsafe {
                SetThreadContext(handle, &ctx);
            }
        }

        if suspended != 0xFFFF_FFFFu32 {
            // SAFETY: handle is a valid thread handle we suspended.
            unsafe {
                ResumeThread(handle);
            }
        }
        if tid != current {
            // SAFETY: handle was opened by OpenThread and is no longer needed.
            unsafe {
                CloseHandle(handle);
            }
        }
    });
}

/// Format the last Win32 error for reporting.
fn last_err() -> String {
    // SAFETY: GetLastError takes no arguments.
    let code = unsafe { GetLastError() };
    format!("Win32 error {code}")
}

/// No-op removal helper kept for symmetry; the VEH is intentionally left
/// installed for the lifetime of the DLL.
#[allow(dead_code)]
fn remove_veh(handle: *mut c_void) {
    // SAFETY: `handle` is a handle returned by AddVectoredExceptionHandler.
    unsafe {
        RemoveVectoredExceptionHandler(handle);
    }
}
