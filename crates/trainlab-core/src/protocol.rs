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
    /// List readable memory regions of the game process.
    ListRegions,
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
    /// Reply to [`Request::ListRegions`].
    ListRegions { regions: Vec<RegionInfo> },
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
