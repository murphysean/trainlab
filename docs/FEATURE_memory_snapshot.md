# Feature Request: Memory snapshot (dump a range to a downloadable file)

**Status:** ✅ implemented (2026-08-19, verified with tests)
**Priority:** [P1]
**crate:** `trainlab-gui` (MCP tool + file serving), `trainlab-core` (maybe a small helper)
**Requested by:** Helldivers 1 session (2026-08-18)

## Problem

The MCP `read` tool returns bytes as an inline hex string, which caps out at
practical sizes. We can only pull a few KB per call and the text comes back
over MCP. This makes it impossible to grab a large contiguous region for
**offline static analysis** — exactly what the Helldivers Lua-heap hunt needs.

Concretely: the game's authoritative Lua heap is the `0x0d` block,
`0x0d020000 → 0x0dffffff` (~15.8 MB of readable private memory). To reverse
how `research_points`/`samples` are stored (we now believe LuaJIT GC64
integer-tagged, e.g. combined value `12` = bytes `0c 00 00 00 00 00 f1 ff`),
we want to:

1. Snapshot the whole `0x0d` heap while on the PROFILE screen (values live).
2. Trigger a change (spend a research point / earn a sample).
3. Diff the two snapshots **offline** to find exactly which field changed and
   how (which also settles the "separate fields vs combined integer" question
   definitively).

A full-heap byte snapshot + offline diff is far more reliable than chasing
transient values with `scan`/`next` over a flaky wifi link (which keeps
dropping mid-session).

## What already exists

- `ProcessMemory::read(address, len) -> Result<Vec<u8>, MemoryError>`
  (`crates/trainlab-core/src/memory.rs`) — can already read an arbitrary byte
  range in one call. `scan_region` already bulk-reads whole regions.
- MCP `read` tool (`crates/trainlab-gui/src/mcp.rs`, `ReadArgs { address,
  len }`) returns bytes as inline hex — capped at whatever the MCP transport
  tolerates (practically a few KB).
- The GUI already runs an HTTP/WS layer (the MCP server is on
  `127.0.0.1:8123` and there's a controller/TCP host for the DLL fast
  channel). We can add a small file-serving endpoint on the same server.

## Requested change

Add a `snapshot` tool that writes a memory range to a file on the **host**
(where the trainer runs, e.g. the Steam Deck), and exposes a **download URL**
the client/agent can fetch to pull that file locally.

### MCP `snapshot` tool

```rust
pub struct SnapshotArgs {
    /// Start address (decimal or 0x hex).
    pub start: String,
    /// End address (exclusive, decimal or 0x hex). The snapshot length is
    /// `end - start`. Use this OR `len`.
    pub end: Option<String>,
    /// Byte length (use this OR `end`).
    pub len: Option<u64>,
    /// Optional filename hint. If omitted, derive from start/len
    /// (e.g. `snap_0x0d020000_15m.bin`). Default dir: a `snapshots/` folder
    /// next to the GUI.
    pub name: Option<String>,
}

// Response:
// { "path": "snapshots/snap_0x0d020000_15m.bin",
//   "size": 16580608,
//   "url": "http://<host>:<port>/snapshots/snap_0x0d020000_15m.bin" }
```

Behavior:
- Validate `end`/`len` (require exactly one; reject absurd sizes unless an
  explicit `max_len` override is given — default cap, e.g. 256 MB).
- Stream `proc.read` in chunks (e.g. 4 KB) to the file so we don't allocate a
  giant Vec for >100 MB ranges — reuse the chunked pattern, avoid OOM.
- Report progress in the response (bytes written) so the agent knows it
  completed.
- Return a stable URL the client can `GET` to download the file.

### File serving

- The GUI's HTTP/WS server (or a small sibling `axum`/`tiny_http` listener)
  serves `GET /snapshots/<file>` for files in the `snapshots/` dir.
- Bind to the same host the MCP is bound to (Steam Deck LAN IP) so the remote
  agent can fetch it; honor the existing `disable_allowed_hosts` behavior so
  LAN fetch works.

### Core change (if any)

`trainlab-core` already has `read`; a small `dump_range_to_file(proc, start,
len, path)` helper (chunked) is the only core addition. The heavy lifting is
GUI-side (tool + serving).

## Acceptance criteria

1. `snapshot start=0x0d020000 len=16580608` on the Helldivers PROFILE screen
   writes a ~15.8 MB file and returns its path + a working download URL.
2. The file can be `GET`-fetched from the host over LAN and byte-for-byte
   matches `proc.read` over the same range.
3. Running the tool twice (before/after a research-point spend) produces two
   files we can diff locally to find the changed field.
4. A >100 MB range works if explicitly allowed (`max_len`), streaming without
   OOM.
5. `read` / `dump` / `dump_struct` are unchanged (no regression).

## Why this matters

Offline snapshotting is the reliable way to reverse the Helldivers profile
storage. The LuaJIT integer-tag hypothesis needs a before/after diff over the
whole heap to confirm, and chasing transient values live has repeatedly hit
render-mirror noise and flaky wifi. With snapshots, we can also later diff
"PROFILE tab open" vs "Weapons tab" to see exactly which fields mount/unmount
per screen — which is how the CH trainer's research-points cheat works
(per-readme, only live on PROFILE). This tool generalizes to any game's
multi-MB heap.

## Notes

- The classic Cheat Engine workflow is exactly this: freeze, snapshot, act,
  snapshot, diff. We're adding the same primitive.
- Keep chunks small (4 KB) and reuse the existing read loop; the DLL
  fast-channel and the external `OpenProcess` read both go through
  `ProcessMemory::read`, so a single chunked writer covers both.

## Implementation sketch

1. `trainlab-core`: add `memory::dump_range_to_file(proc, start, len, path)`
   (chunked, returns bytes written / errors).
2. `trainlab-gui`: add `snapshot` MCP tool (validate args, call the helper,
   build the URL).
3. `trainlab-gui`: add a `GET /snapshots/<name>` handler on the existing
   server (serve files from a `snapshots/` dir next to the exe).
4. Unit test: `dump_range_to_file` over a mock region round-trips; integration
   test that the URL handler serves the file.
