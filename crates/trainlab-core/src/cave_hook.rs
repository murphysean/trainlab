//! Serializable code-cave hook kinds, shared between the injected DLL, the GUI
//! proxy, and the `trainlab-cave` installer.
//!
//! Keeping this in `trainlab-core` (like the protocol) means the wire format and
//! the installer can't drift: the MCP tool builds a [`CaveHook`], it round-trips
//! through the protocol to the DLL, and the DLL converts it to the
//! `trainlab-cave` [`HookKind`](trainlab_cave::cave::HookKind).

use serde::{Deserialize, Serialize};

/// How a code-cave hook redirects a target instruction (see the `trainlab-cave`
/// installer for semantics). Serialized so an agent can choose the patch
/// strategy from the MCP tool.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CaveHook {
    /// Transparent hook: run `payload` (optional), then replay the stolen
    /// instructions relocated into the cave, then jump back. Original behavior
    /// is preserved (empty payload = pure no-op).
    Trampoline { payload: Vec<u8> },
    /// Replace hook: run `payload`, then jump back, skipping the stolen
    /// instructions.
    Override { payload: Vec<u8> },
}
