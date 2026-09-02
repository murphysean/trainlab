# Bug Report: capture_reg `gate` parameter fails deserialization (sent as JSON string, server expects struct)

**Status:** ✅ RESOLVED (2026-09-01)
**Priority:** P2
**Area:** MCP Server (capture_reg params) / possibly client serialization
**Date:** 2026-09-01
**Game / Target:** sins2.exe (Sins of a Solar Empire II v1.61.4, local workstation MCP)

---

## 1. Summary & Context
Arming a `capture_reg` with a `gate` object via the MCP tool fails every time with a
deserialization error. The gate JSON arrives at the server as a **string** (escaped JSON),
not as a JSON object, so serde rejects it: `expected struct CaptureGateArgs`. Gateless
arming works fine.

This blocks gated captures — which matter for hot-path discipline (filter captures
in-DLL instead of flooding the ring buffer) and for the "capture only when register Y
compares Z" primitive.

Historical note: gates worked reliably in earlier sessions (Helldivers 2026-08-18/19,
exact + range both filtered cleanly, after the gate type-confusion fix). Either the MCP
params layer regressed, or the client that sends the tool call now double-encodes the
object. The error message suggests the value arrives as a string containing escaped JSON.

---

## 2. Reproduction Steps
Environment: local workstation, trainlab-gui.exe + trainlab_inject.dll v0.1.0 attached
to sins2.exe (pid 740 wine-side), MCP via streamable_http on 127.0.0.1:8123.

1. Call `capture_reg` with:
   - `target`: `sins2.exe+0x5ceda8`
   - `reg`: `rdi`, `value_type`: `ptr`, `jump`: `absolute`, `stop_on_match`: true
   - `gate`: JSON object `{"cmp": "ne", "reg": "rdi", "value": 0, "value_type": "ptr"}`
2. Observe error (reproduced 3x consecutively):
   ```
   failed to deserialize parameters: invalid type: string
   "{\"cmp\": \"ne\", \"reg\": \"rdi\", \"value\": 0, \"value_type\": \"ptr\"}",
   expected struct CaptureGateArgs
   ```
3. Call again with `gate` **omitted** → arms successfully (unconditional).

---

## 3. Expected vs Actual Behavior
- **Expected:** gate object deserializes into `CaptureGateArgs` and filters captures.
- **Actual:** the serialized request carries the gate as a JSON *string* (note the escaped
  quotes in the error), so the server tries to deserialize a string into a struct and the
  whole call fails with -32602-style invalid params. No capture is armed (clean failure).

---

## 4. Technical Details & Artifacts
- Full error text (3 identical occurrences):
  ```
  failed to deserialize parameters: invalid type: string
  "{\"cmp\": \"ne\", \"reg\": \"rdi\", \"value\": 0, \"value_type\": \"ptr\"}",
  expected struct CaptureGateArgs
  ```
- The escaped-string form strongly suggests double-encoding somewhere in the params path
  (tool args → server). The double-encoding could be in the goose `trainlab` MCP extension
  client OR in the server's arg pre-parse; the error text is server-side.
- Successful gateless call (same session, same target):
  ```
  armed non-stalling capture id 1 at 0x1405ceda8: capturing rdi as ptr (capacity 32)
  (unconditional; stop_on_match=true). scratch buffer: 0x36200000
  ```

---

## 5. Proposed Fix or Next Steps
- [x] Server-side tolerant deserialization regardless: accept `CaptureGateArgs` as either
      a struct or a JSON-encoded string (`deserialize_gate_opt` untagged enum parser). This is robust to any client.
- [x] Add a regression test: `test_capture_reg_gate_deserialization_struct_and_string` in `crates/trainlab-gui/src/mcp.rs`.

---

## Workaround (used this session)
Arm **without** `gate` (unconditional), with `stop_on_match: true` for one-shot discovery
captures, and filter manually in `read_captures` output. Acceptable for re-finding
`$player_base`; not acceptable when the site fires thousands of times per second and you
need in-DLL filtering to avoid a flood.