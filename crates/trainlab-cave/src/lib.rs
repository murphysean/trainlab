//! # trainlab-cave
//!
//! Code cave shellcode emission and installation for the trainlab trainer.
//!
//! A code cave hook lets us redirect a game's code flow to our own injected
//! payload (e.g. "always keep the player healthy", "override a resource value")
//! and then return to the original flow. This is the Phase 3 "mutating tools"
//! half of the architecture:
//!
//! - [`emitter`] builds the raw x86-64 bytes for common hook patterns and the
//!   jump/return trampolines.
//! - [`cave`] allocates executable memory, places the payload, patches a call
//!   site with a jump, and tracks original bytes for undo.
//!
//! This crate is pure logic (no process access) — it compiles for any target.
//! The injected DLL (`trainlab-inject`) provides the in-process `read`/`write`/
//! `allocate` closures that [`cave::install`] needs.

pub mod capture;
pub mod cave;
pub mod emitter;
