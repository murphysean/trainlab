//! # Hardware watchpoints (T-028), Page Guard watchpoints, and int3 breakpoints (T-029)
//!
//! These features are **Windows-only** and implemented with a vectored
//! exception handler (VEH) that runs *inside* the game process.
//!
//! - **Hardware `WatchWrites`**: arm a data-write hardware watchpoint on DR0 by
//!   programming DR0/DR7 on threads of the process.
//! - **Page Guard `WatchWrites`**: mark the target memory page with `PAGE_GUARD`.
//!   When *any* thread (including any worker thread or thread pool worker)
//!   accesses or writes into the page, `STATUS_GUARD_PAGE_VIOLATION` is caught by
//!   the VEH.
//! - **`BreakOnCode`**: patch code with `0xCC` (int3). When execution reaches it
//!   the VEH sees `EXCEPTION_BREAKPOINT`, restores the original byte, and captures
//!   registers.
//!
//! ### Multi-Thread Resilience & Tombstoning
//! In highly concurrent game engines and thread pools, multiple threads frequently
//! hit the breakpoint or guard page in the exact same millisecond window.
//! When a breakpoint or watchpoint is disarmed (or armed in one-shot mode), a
//! `Tombstone` is maintained in a recent disarm ring buffer. Any in-flight threads
//! that hit the breakpoint address around or after disarm are recognized by the VEH:
//! their `RIP` is safely rewound, their register state is recorded as a concurrent hit,
//! and they are resumed together without wedging or crashing.

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, EXCEPTION_ACCESS_VIOLATION, EXCEPTION_BREAKPOINT,
    EXCEPTION_GUARD_PAGE, EXCEPTION_SINGLE_STEP, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, GetThreadContext,
    SetThreadContext, CONTEXT, CONTEXT_CONTROL_AMD64, CONTEXT_DEBUG_REGISTERS_AMD64,
    CONTEXT_INTEGER_AMD64, EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_POINTERS,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows_sys::Win32::System::Memory::{
    VirtualProtect, VirtualQuery, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE, PAGE_GUARD,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcessId, GetCurrentThread, GetCurrentThreadId, OpenThread, ResumeThread,
    SuspendThread, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION, THREAD_SET_CONTEXT,
    THREAD_SUSPEND_RESUME,
};

const TRAP_FLAG: u32 = 0x100;

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
    /// Memory protection fault watchpoint (PAGE_GUARD).
    PageGuard {
        page_base: u64,
        page_size: usize,
        original_protect: u32,
    },
    /// int3 software breakpoint.
    Code,
}

struct ActiveWatch {
    kind: WatchKind,
    address: u64,
    len: usize,
    one_shot: bool,
    /// Original byte that was overwritten with `0xCC` (breakpoints only).
    original_byte: u8,
}

/// Tombstone of a recently disarmed breakpoint or page guard.
/// Allows in-flight concurrent threads that hit the trap site around or after
/// disarm to safely recover, fix up RIP, record their hit, and resume without wedging.
#[derive(Clone)]
struct DisarmedTombstone {
    address: u64,
    original_byte: u8,
    disarmed_at: Instant,
}

/// Pending single-step re-arm state keyed by Thread ID.
#[derive(Clone, Copy)]
enum PendingStep {
    ReapplyCodeBreak { address: u64 },
    ReapplyPageGuard { page_base: u64, page_size: usize },
    ReapplyHardwareDr { dr7: u64 },
}

struct Runtime {
    state: Mutex<Option<ActiveWatch>>,
    veh_handle: Mutex<Option<VehHandle>>,
    /// Thread ID -> PendingStep awaiting single-step completion.
    pending_steps: Mutex<HashMap<u32, PendingStep>>,
    /// Bounded ring buffer of hits (accumulates up to 64 hits).
    hits: Mutex<Vec<HitInfo>>,
    /// Recently disarmed tombstones (kept for 10 seconds to catch concurrent stragglers).
    tombstones: Mutex<Vec<DisarmedTombstone>>,
}

const MAX_HITS_CAPACITY: usize = 64;
const MAX_TOMBSTONES: usize = 16;
const TOMBSTONE_TTL_SECS: u64 = 10;

struct VehHandle(*mut c_void);
unsafe impl Send for VehHandle {}
unsafe impl Sync for VehHandle {}

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

fn runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| Runtime {
        state: Mutex::new(None),
        veh_handle: Mutex::new(None),
        pending_steps: Mutex::new(HashMap::new()),
        hits: Mutex::new(Vec::new()),
        tombstones: Mutex::new(Vec::new()),
    })
}

/// Install the vectored exception handler exactly once.
fn ensure_veh() {
    let mut guard = runtime().veh_handle.lock().unwrap();
    if guard.is_none() {
        let h = unsafe { AddVectoredExceptionHandler(1, Some(veh_handler)) };
        if !h.is_null() {
            *guard = Some(VehHandle(h));
        }
    }
}

/// Arm a data-write watchpoint on `address`.
pub fn arm_watch(
    address: u64,
    len: usize,
    one_shot: bool,
    mechanism: Option<&str>,
) -> Result<(), String> {
    clear_internal();
    ensure_veh();

    let use_hardware = matches!(mechanism, Some("hardware"));

    if use_hardware {
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
            len,
            one_shot,
            original_byte: 0,
        });
    } else {
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let query_ret = unsafe {
            VirtualQuery(
                address as *const c_void,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if query_ret == 0 {
            return Err(format!("VirtualQuery failed for 0x{:x}: {}", address, last_err()));
        }

        let page_base = address & !0xFFFu64;
        let page_size = 0x1000usize;
        let mut old_protect = 0u32;
        let ok = unsafe {
            VirtualProtect(
                page_base as *mut c_void,
                page_size,
                mbi.Protect | PAGE_GUARD,
                &mut old_protect,
            )
        };
        if ok == 0 {
            return Err(format!("VirtualProtect PAGE_GUARD failed: {}", last_err()));
        }

        *runtime().state.lock().unwrap() = Some(ActiveWatch {
            kind: WatchKind::PageGuard {
                page_base,
                page_size,
                original_protect: old_protect,
            },
            address,
            len,
            one_shot,
            original_byte: 0,
        });
    }

    Ok(())
}

/// Arm a software breakpoint on `address` (int3 `0xCC`).
pub fn arm_break(address: u64, one_shot: bool) -> Result<(), String> {
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
        len: 1,
        one_shot,
        original_byte: original,
    });
    Ok(())
}

/// Poll for accumulated hits since last poll. Returns all hits recorded.
pub fn poll_hits() -> Vec<HitInfo> {
    let mut hits = runtime().hits.lock().unwrap();
    std::mem::take(&mut *hits)
}

/// Poll for the most recent single hit (backwards-compatible).
pub fn poll_hit() -> Option<HitInfo> {
    let mut hits = runtime().hits.lock().unwrap();
    if hits.is_empty() {
        None
    } else {
        Some(hits.remove(0))
    }
}

/// Disarm any active watchpoint/breakpoint, restore patched bytes/page protections,
/// and clear debug registers.
pub fn clear() {
    clear_internal();
}

fn add_tombstone(address: u64, original_byte: u8) {
    let mut tombstones = runtime().tombstones.lock().unwrap();
    tombstones.retain(|t| t.disarmed_at.elapsed().as_secs() < TOMBSTONE_TTL_SECS);
    if tombstones.len() >= MAX_TOMBSTONES {
        tombstones.remove(0);
    }
    tombstones.push(DisarmedTombstone {
        address,
        original_byte,
        disarmed_at: Instant::now(),
    });
}

fn find_tombstone(address: u64) -> Option<DisarmedTombstone> {
    let tombstones = runtime().tombstones.lock().unwrap();
    tombstones.iter().find(|t| t.address == address).cloned()
}

fn clear_internal() {
    let mut guard = runtime().state.lock().unwrap();
    if let Some(active) = guard.take() {
        match active.kind {
            WatchKind::Code => {
                let _ = write_byte(active.address, active.original_byte);
                add_tombstone(active.address, active.original_byte);
            }
            WatchKind::PageGuard { page_base, page_size, original_protect } => {
                let mut old = 0u32;
                unsafe {
                    VirtualProtect(
                        page_base as *mut c_void,
                        page_size,
                        original_protect & !PAGE_GUARD,
                        &mut old,
                    );
                }
                add_tombstone(active.address, 0);
            }
            WatchKind::DataWrite => {
                add_tombstone(active.address, 0);
            }
        }
    }
    drop(guard);
    runtime().pending_steps.lock().unwrap().clear();
    apply_debug_registers_all(0, 0);
}

fn record_hit(hit: HitInfo) {
    let mut hits = runtime().hits.lock().unwrap();
    if hits.len() >= MAX_HITS_CAPACITY {
        hits.remove(0);
    }
    hits.push(hit);
}

/// The VEH callback. Runs on whichever thread took the exception.
unsafe extern "system" fn veh_handler(ep: *mut EXCEPTION_POINTERS) -> i32 {
    unsafe {
        if ep.is_null() {
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        let code = (*ep).ExceptionRecord.as_mut().map_or(0, |r| r.ExceptionCode);
        let ctx = (*ep).ContextRecord;
        if ctx.is_null() {
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        let tid = GetCurrentThreadId();

        // 1. Handle single-step re-arm cadence (TF fired after stepping over an instruction)
        if code == EXCEPTION_SINGLE_STEP {
            let pending = {
                let mut map = runtime().pending_steps.lock().unwrap();
                map.remove(&tid)
            };

            if let Some(step) = pending {
                // Clear the Trap Flag so the thread resumes regular execution
                (*ctx).EFlags &= !TRAP_FLAG;

                match step {
                    PendingStep::ReapplyCodeBreak { address } => {
                        let _ = write_byte(address, 0xCC);
                    }
                    PendingStep::ReapplyPageGuard { page_base, page_size } => {
                        let mut old = 0u32;
                        let _ = VirtualProtect(
                            page_base as *mut c_void,
                            page_size,
                            PAGE_EXECUTE_READWRITE | PAGE_GUARD,
                            &mut old,
                        );
                    }
                    PendingStep::ReapplyHardwareDr { dr7 } => {
                        (*ctx).Dr7 = dr7;
                    }
                }
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }

        // 2. Check for active watch/break
        let mut guard = runtime().state.lock().unwrap();
        if let Some(active) = guard.as_ref() {
            match active.kind {
                WatchKind::PageGuard { page_base, page_size, original_protect } => {
                    if code == EXCEPTION_GUARD_PAGE {
                        let r = (*ep).ExceptionRecord.as_ref().unwrap();
                        let access_type = r.ExceptionInformation[0];
                        let fault_addr = r.ExceptionInformation[1] as u64;

                        let in_range = fault_addr >= active.address
                            && fault_addr < active.address.saturating_add(active.len as u64);
                        let is_write = access_type == 1;

                        if in_range && is_write {
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
                                description: format!(
                                    "page-guard write hit at 0x{:x} (target 0x{:x}) by thread {}",
                                    fault_addr, active.address, tid
                                ),
                                stack: capture_stack((*ctx).Rsp, 16),
                            };
                            record_hit(hit);

                            if active.one_shot {
                                let mut old = 0u32;
                                VirtualProtect(
                                    page_base as *mut c_void,
                                    page_size,
                                    original_protect & !PAGE_GUARD,
                                    &mut old,
                                );
                                add_tombstone(active.address, 0);
                                let _ = guard.take();
                                return EXCEPTION_CONTINUE_EXECUTION;
                            }
                        }

                        // Off-target or multi-shot: set TF to step over and reapply PAGE_GUARD
                        (*ctx).EFlags |= TRAP_FLAG;
                        runtime().pending_steps.lock().unwrap().insert(
                            tid,
                            PendingStep::ReapplyPageGuard { page_base, page_size },
                        );

                        return EXCEPTION_CONTINUE_EXECUTION;
                    }
                }

                WatchKind::DataWrite => {
                    if code == EXCEPTION_SINGLE_STEP || code == EXCEPTION_ACCESS_VIOLATION {
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
                            description: format!(
                                "data-write watchpoint fired at 0x{:x} by thread {}",
                                active.address, tid
                            ),
                            stack: capture_stack((*ctx).Rsp, 16),
                        };
                        record_hit(hit);

                        if active.one_shot {
                            (*ctx).Dr0 = 0;
                            (*ctx).Dr7 = 0;
                            add_tombstone(active.address, 0);
                            let _ = guard.take();
                            return EXCEPTION_CONTINUE_EXECUTION;
                        } else {
                            let dr7_saved = (*ctx).Dr7;
                            (*ctx).Dr7 = 0;
                            (*ctx).EFlags |= TRAP_FLAG;
                            runtime().pending_steps.lock().unwrap().insert(
                                tid,
                                PendingStep::ReapplyHardwareDr { dr7: dr7_saved },
                            );
                            return EXCEPTION_CONTINUE_EXECUTION;
                        }
                    }
                }

                WatchKind::Code => {
                    if code == EXCEPTION_BREAKPOINT {
                        let exc_addr = (*ep)
                            .ExceptionRecord
                            .as_mut()
                            .map_or(0, |r| r.ExceptionAddress as u64);
                        let rip = (*ctx).Rip;
                        if exc_addr == active.address || rip.wrapping_sub(1) == active.address {
                            // Restore original instruction byte immediately
                            let _ = write_byte(active.address, active.original_byte);
                            (*ctx).Rip = active.address;

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
                                description: format!(
                                    "breakpoint hit at 0x{:x} by thread {}",
                                    active.address, tid
                                ),
                                stack,
                            };
                            record_hit(hit);

                            if active.one_shot {
                                add_tombstone(active.address, active.original_byte);
                                let _ = guard.take();
                                return EXCEPTION_CONTINUE_EXECUTION;
                            } else {
                                (*ctx).EFlags |= TRAP_FLAG;
                                runtime().pending_steps.lock().unwrap().insert(
                                    tid,
                                    PendingStep::ReapplyCodeBreak { address: active.address },
                                );
                                return EXCEPTION_CONTINUE_EXECUTION;
                            }
                        }
                    }
                }
            }
        }

        // 3. Tombstone check: if state was already disarmed by another thread,
        // but this thread also trapped on the exact same breakpoint/page guard:
        drop(guard);

        if code == EXCEPTION_BREAKPOINT {
            let exc_addr = (*ep)
                .ExceptionRecord
                .as_mut()
                .map_or(0, |r| r.ExceptionAddress as u64);
            let rip = (*ctx).Rip;
            let target_addr = if let Some(t) = find_tombstone(exc_addr) {
                Some((exc_addr, t))
            } else if let Some(t) = find_tombstone(rip.wrapping_sub(1)) {
                Some((rip.wrapping_sub(1), t))
            } else {
                None
            };

            if let Some((addr, tombstone)) = target_addr {
                // Ensure original byte is restored
                let _ = write_byte(addr, tombstone.original_byte);
                // Rewind RIP to instruction start so thread executes normally
                (*ctx).Rip = addr;

                let stack = capture_stack((*ctx).Rsp, 16);
                let hit = HitInfo {
                    rip: addr,
                    rax: (*ctx).Rax,
                    rbx: (*ctx).Rbx,
                    rcx: (*ctx).Rcx,
                    rdx: (*ctx).Rdx,
                    rsi: (*ctx).Rsi,
                    rdi: (*ctx).Rdi,
                    rsp: (*ctx).Rsp,
                    rbp: (*ctx).Rbp,
                    description: format!(
                        "concurrent breakpoint hit at 0x{:x} by straggler thread {} (safely resumed)",
                        addr, tid
                    ),
                    stack,
                };
                record_hit(hit);
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }

        if code == EXCEPTION_GUARD_PAGE {
            let r = (*ep).ExceptionRecord.as_ref().unwrap();
            let fault_addr = r.ExceptionInformation[1] as u64;
            let page_base = fault_addr & !0xFFFu64;

            if let Some(tombstone) = find_tombstone(fault_addr).or_else(|| find_tombstone(page_base)) {
                // Page Guard was already disarmed or in teardown: resume instruction safely
                let mut old = 0u32;
                VirtualProtect(
                    page_base as *mut c_void,
                    0x1000,
                    PAGE_EXECUTE_READWRITE,
                    &mut old,
                );
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
                    description: format!(
                        "concurrent page guard hit at 0x{:x} (target 0x{:x}) by thread {} (safely resumed)",
                        fault_addr, tombstone.address, tid
                    ),
                    stack: capture_stack((*ctx).Rsp, 16),
                };
                record_hit(hit);
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }

        EXCEPTION_CONTINUE_EXECUTION
    }
}

/// Read a single byte from the current process.
fn read_byte(address: u64) -> u8 {
    unsafe { *(address as *const u8) }
}

/// Write a single byte to the current process, flipping page protection.
fn write_byte(address: u64, byte: u8) -> Result<(), String> {
    let ptr = address as *const c_void;
    let mut old = 0u32;
    let ok = unsafe { VirtualProtect(ptr, 1, PAGE_EXECUTE_READWRITE, &mut old) };
    if ok == 0 {
        return Err(last_err());
    }
    unsafe { *(address as *mut u8) = byte; }
    unsafe {
        VirtualProtect(ptr, 1, old, &mut old);
    }
    Ok(())
}

/// Read `count` u64 words upward from `rsp` and format them as hex.
fn capture_stack(rsp: u64, count: usize) -> Vec<String> {
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let addr = rsp.wrapping_add((i as u64) * 8);
        let val = unsafe { *(addr as *const u64) };
        out.push(format!("0x{val:016x}"));
    }
    out
}

/// Enumerate every thread in the current process and call `f` with its TID.
fn for_each_thread(mut f: impl FnMut(u32)) {
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snap == INVALID_HANDLE_VALUE {
        return;
    }
    let pid = unsafe { GetCurrentProcessId() };
    let mut te: THREADENTRY32 = unsafe { std::mem::zeroed() };
    te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
    let mut has = unsafe { Thread32First(snap, &mut te) != 0 };
    while has {
        if te.th32OwnerProcessID == pid {
            f(te.th32ThreadID);
        }
        has = unsafe { Thread32Next(snap, &mut te) != 0 };
    }
    unsafe {
        CloseHandle(snap);
    }
}

/// Program DR0 = `dr0` and DR7 = `dr7` on every thread of the process.
fn apply_debug_registers_all(dr0: u64, dr7: u64) {
    let current = unsafe { GetCurrentThreadId() };
    for_each_thread(|tid| {
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
        let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
        ctx.ContextFlags =
            CONTEXT_DEBUG_REGISTERS_AMD64 | CONTEXT_CONTROL_AMD64 | CONTEXT_INTEGER_AMD64;

        let suspended = if tid == current {
            0xFFFF_FFFFu32
        } else {
            unsafe { SuspendThread(handle) }
        };

        if unsafe { GetThreadContext(handle, &mut ctx) } != 0 {
            ctx.Dr0 = dr0;
            ctx.Dr7 = dr7;
            unsafe {
                SetThreadContext(handle, &ctx);
            }
        }

        if suspended != 0xFFFF_FFFFu32 {
            unsafe {
                ResumeThread(handle);
            }
        }
        if tid != current {
            unsafe {
                CloseHandle(handle);
            }
        }
    });
}

fn last_err() -> String {
    let code = unsafe { GetLastError() };
    format!("Win32 error {code}")
}
