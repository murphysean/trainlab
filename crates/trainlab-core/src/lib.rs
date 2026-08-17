//! # trainlab-core
//!
//! Shared foundation for the trainlab workspace. This crate contains the
//! pieces that every other crate depends on:
//!
//! - **`protocol`** — the wire format used between the injected DLL and the
//!   GUI/scanner (serde + bincode over a local TCP socket).
//! - **`memory`** — cross-platform primitives for reading/writing another
//!   process's memory.
//! - **`aob`** — array-of-bytes (AOB) pattern scanning, the bread and butter
//!   of finding code caves and interesting offsets.
//! - **`process`** — lightweight process discovery / enumeration helpers.

pub mod aob;
pub mod capture;
pub mod cave_hook;
pub mod disasm;
pub mod memory;
pub mod modinfo;
pub mod pointer;
pub mod process;
pub mod protocol;
pub mod scan;
#[cfg(unix)]
pub mod wine;

/// Re-export the version so other crates can report it consistently.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
