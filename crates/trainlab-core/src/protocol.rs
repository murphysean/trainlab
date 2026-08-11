//! Wire protocol shared between the injected DLL and the GUI/scanner.
//!
//! Messages are serialized with `bincode` and framed with a 4-byte little
//! endian length prefix, then sent over a local TCP socket. Keeping the
//! protocol in `trainlab-core` means the GUI and the injected DLL can never
//! drift out of sync.

use serde::{Deserialize, Serialize};

/// A single request sent from the GUI/scanner to the injected DLL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    /// Ping the DLL to confirm it is alive and report its version.
    Ping,
    /// Read `len` bytes from the game process at `address`.
    Read { address: u64, len: usize },
    /// Write `data` into the game process at `address`.
    Write { address: u64, data: Vec<u8> },
    /// Scan the game's readable memory for an AOB pattern.
    ScanAob {
        /// The pattern, with `??` wildcards already resolved to `None`.
        pattern: Vec<Option<u8>>,
        /// Optional start address (defaults to lowest readable region).
        start: Option<u64>,
        /// Optional end address (defaults to highest readable region).
        end: Option<u64>,
    },
    /// Allocate a block of memory inside the game process (a code cave).
    Allocate { size: usize, executable: bool },
    /// Free a previously allocated block.
    Free { address: u64 },
    /// Install a code cave hook at `target`: allocate executable memory, build
    /// a cave body per `hook` semantics, patch the first whole instructions of
    /// `target` (instruction-aligned length >= a `jmp`) with an absolute `jmp`
    /// into the cave, and save the original bytes. Returns a handle (the cave
    /// address).
    InstallCave {
        /// Address of the instruction to redirect.
        target: u64,
        /// The hook to install: `trampoline` (transparent, replays stolen
        /// instructions, payload optional) or `override` (skips stolen, runs
        /// payload). Payload is hex shellcode bytes.
        hook: crate::cave_hook::CaveHook,
    },
    /// List readable memory regions of the game process.
    ListRegions,
    /// Perform a first value scan over the game's readable regions.
    ///
    /// The DLL runs the scan in-process (fast, direct memory access) and
    /// returns the match set. The GUI stores it in session state (D7).
    Scan {
        /// The value type to scan for.
        value_type: crate::scan::ValueType,
        /// Byte alignment for candidate addresses (0/1 = any).
        alignment: usize,
        /// The narrowing operation (Exact/Range) for the first scan.
        op: crate::scan::ScanOp,
    },
    /// Narrow an existing match set by re-reading each address.
    ///
    /// The GUI sends the current match set; the DLL re-reads each address and
    /// returns the narrowed set.
    Next {
        /// The value type of the scan.
        value_type: crate::scan::ValueType,
        /// The current match set as `(address, last_value)` pairs.
        matches: Vec<(u64, f64)>,
        /// The narrowing operation.
        op: crate::scan::ScanOp,
    },
    /// Reverse-reference scan: find addresses whose pointer value points into
    /// the range `[lo, hi]`.
    PointerScan {
        lo: u64,
        hi: u64,
    },
    /// Resolve a known pointer chain against the game's live memory.
    PointerChase {
        base: u64,
        offsets: Vec<u64>,
    },
    /// Arm a hardware watchpoint (DR0/DR7) on `address` so that when the game
    /// *writes* that location we capture the writing code's registers (T-028).
    ///
    /// When `one_shot` is true the watchpoint is disarmed after the first hit
    /// and the caller receives a `WatchHit`. When false it stays armed and the
    /// caller is expected to poll for hits via a later `WatchHit` (or clear it).
    WatchWrites {
        address: u64,
        len: usize,
        one_shot: bool,
    },
    /// Arm a lightweight single-fire software breakpoint (int3 `0xCC`) on a
    /// code address. When execution reaches `address` we capture registers and
    /// a stack trace, restore the original byte, and (unless `one_shot` is
    /// false) re-arm. The hit is reported as a [`Response::WatchHit`] (T-029).
    BreakOnCode {
        address: u64,
        one_shot: bool,
    },
    /// Disarm any active watchpoint or breakpoint and restore any patched bytes.
    ClearBreakpoints,
    /// Poll for a hit from an armed watchpoint/breakpoint that fired since the
    /// last poll. Returns `None` if none is pending.
    PollHit,
}

/// The response to a [`Request`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    /// Reply to [`Request::Ping`].
    Pong { version: String },
    /// Reply to [`Request::Read`].
    Read { data: Vec<u8> },
    /// Reply to [`Request::Write`].
    Write { bytes_written: usize },
    /// Reply to [`Request::ScanAob`].
    ScanAob { matches: Vec<u64> },
    /// Reply to [`Request::Allocate`].
    Allocate { address: u64 },
    /// Reply to [`Request::Free`].
    Free { ok: bool },
    /// Reply to [`Request::InstallCave`]. Carries the cave address (a handle)
    /// and the original bytes that were overwritten (for undo).
    CaveInstalled {
        /// The allocated cave address (the handle).
        cave: u64,
        /// The target call site that was patched.
        target: u64,
        /// The original bytes that were overwritten at `target`.
        original: Vec<u8>,
    },
    /// Reply to [`Request::ListRegions`].
    ListRegions { regions: Vec<RegionInfo> },
    /// Reply to [`Request::Scan`] or [`Request::Next`].
    ScanResult { matches: Vec<(u64, f64)> },
    /// Reply to [`Request::PointerScan`].
    PointerScan { matches: Vec<(u64, u64)> },
    /// Reply to [`Request::PointerChase`].
    PointerChase { hops: Vec<u64> },
    /// Reply to [`Request::WatchWrites`] or [`Request::BreakOnCode`] once the
    /// watchpoint/breakpoint has actually fired. Carries the captured register
    /// state plus (for breakpoints) a stack trace.
    WatchHit {
        rip: u64,
        rax: u64,
        rbx: u64,
        rcx: u64,
        rdx: u64,
        rsi: u64,
        rdi: u64,
        rsp: u64,
        rbp: u64,
        /// Human-readable description of the event.
        description: String,
        /// Stack trace as formatted hex addresses (T-029 breakpoints only).
        stack: Vec<String>,
    },
    /// Reply to [`Request::WatchWrites`] / [`Request::BreakOnCode`] confirming
    /// the hardware/software breakpoint is now armed.
    WatchArmed,
    /// Reply to [`Request::BreakOnCode`] confirming the int3 breakpoint is armed.
    BreakArmed,
    /// Reply to [`Request::ClearBreakpoints`].
    BreakpointsCleared,
    /// Reply to [`Request::PollHit`]. `hit` is `Some` if a watchpoint/breakpoint
    /// fired since the last poll.
    PollHit { hit: Option<WatchHitInfo> },
    /// An error occurred while handling the request.
    Error { message: String },
}

/// A memory region description, used by [`Request::ListRegions`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionInfo {
    pub start: u64,
    pub end: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    /// Human-readable label if known (e.g. a mapped file name).
    pub name: Option<String>,
}

/// The captured register + stack state of a watchpoint/breakpoint hit.
///
/// Shared payload for [`Response::WatchHit`] and [`Response::PollHit`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchHitInfo {
    pub rip: u64,
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    /// Human-readable description of the event.
    pub description: String,
    /// Stack trace as formatted hex addresses (breakpoints only).
    pub stack: Vec<String>,
}

/// Serialize a message into a length-prefixed frame.
pub fn encode<T: Serialize>(msg: &T) -> Result<Vec<u8>, bincode::Error> {
    let body = bincode::serialize(msg)?;
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Deserialize a length-prefixed frame.
pub fn decode<T: for<'de> Deserialize<'de>>(frame: &[u8]) -> Result<T, bincode::Error> {
    if frame.len() < 4 {
        return Err(bincode::ErrorKind::SizeLimit.into());
    }
    let len = u32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    if frame.len() < 4 + len {
        return Err(bincode::ErrorKind::SizeLimit.into());
    }
    bincode::deserialize(&frame[4..4 + len])
}
