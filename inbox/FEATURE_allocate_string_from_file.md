# Feature Request: `allocate_string` from a local file path / HTTP upload (agent-side payload authoring)

**Status:** ⏳ considering (expedited approach via HTTP file upload)
**Priority:** [P2]
**crate:** `trainlab-core` (string allocator), `trainlab-gui` (HTTP file upload endpoint + MCP `allocate_string` tool)
**Requested by:** Helldivers 1 Lua-injection session (2026-08-29)
**Updated:** 2026-09-01

---

## 1. The problem

The agent (LLM) authors Lua probe/cheat programs and ships them into the game via
`allocate_string(content=..., kind="c", marker=...)`. The `content` is passed
**inline** as a tool argument.

This breaks down for **large payloads** (e.g. a 600–900 byte Lua probe that walks
`mission_manager.players` / `hud_info` health state). When the agent emits a large
`content` string inline, the model's **output token budget** is exhausted
mid-call, and the tool call is **truncated before it is sent**:

```
Tool arguments for steamdeck-trainlab__allocate_string (id call_...) were truncated
because the model reached its output token limit
```

This is a **model-side** failure, not an MCP-server response-size issue. The MCP
responses are tiny (`0`, `tiny_ok`, `NO_MISSION`). The problem is purely that the
agent must re-author the full payload inline on every `allocate_string` call, and
large payloads blow the output budget.

## 2. The desired capability & Recommended Upload Architecture

Allow the agent to develop scripts locally on its workstation/agent environment, upload
them to the trainer host HTTP server, and reference them by clean file path:

1. **Local Script Development:** Agent writes script locally (e.g. `probe.lua`).
2. **Push via HTTP / curl:** Agent uploads the file to the GUI's HTTP server via `curl -F file=@probe.lua http://<host>:8123/api/upload` (or similar POST endpoint).
3. **Response with Known Path:** The server stores it in a staging directory and returns the saved file path (e.g. `/tmp/trainlab_uploads/probe_xyz.lua`).
4. **Allocate via Path:** Agent calls `allocate_string(path="/tmp/trainlab_uploads/probe_xyz.lua", kind="c", marker="probe")` to allocate in-game.

This keeps paths clean, decouples file transfer across hosts (remote Steam Deck / local), and eliminates MCP tool argument token bloat.

## 3. Proposed API

```
allocate_string(
    content: string | null,   # existing inline content (unchanged, backward compatible)
    path: string | null,      # local file path on host to read content from (mutually exclusive with content)
    kind: string,             # "c" | "rust" | "json" | "yaml" | "xml" | "js" | "config"
    marker: string | null
) -> Layout
```

- If `path` is set, read the file bytes and use them as `content`.
- If both `content` and `path` are set, prefer `path` (or error).
- The path is on the **trainer host** (the Steam Deck), not the game process.

## 4. Repro

1. Author a ~700-byte Lua probe (e.g. the health-state walker).
2. Call `allocate_string(content=<700-byte lua>, kind="c", marker="probe")`.
3. Observe: the tool call is truncated with "model reached its output token limit"
   (the call never reaches the MCP server).

## 5. Expected vs Actual

- **Expected:** the agent can ship large payloads into the game without re-authoring
  them inline, by pointing at a local file.
- **Actual:** large inline `content` strings get truncated by the model's output
  budget, so the payload never reaches the game.

## 6. Notes & Next Steps

- Design and expose an HTTP multipart/POST upload route on the GUI's web/MCP server port.
- Implement the `path` argument support in `AllocateStringArgs` and `trainlab-core`.

