# Launching the trainer

`trainlab-gui` is a **game trainer** you launch alongside your game — in the
spirit of Cheat Engine, Aurora, or Fling. It is deliberately **launcher-agnostic**:
you ship a binary (and the injected DLL) and start it however you like. It is
**not** a game launcher and does **not** replace tools like Steam Tinker Launch
(STL) — it simply needs to run in the same Wine prefix / environment as the
game so it can inject the DLL.

This doc covers:
- how to launch it on each platform,
- the environment variables it reads,
- how to connect an agent (MCP),
- and how to reach it from a remote machine (Steam Deck, another PC, etc.).

## What you ship

A release is a small directory:

```
trainlab/
  trainlab-gui.exe       # the trainer (Windows PE32+ x86-64)
  trainlab_inject.dll    # the agent DLL, injected into the game
```

The GUI looks for the DLL next to the executable by default (the DLL path is
editable in the UI, or via the DLL field).

## Launching by platform

### Windows

Just run `trainlab-gui.exe`. It finds the game process by name, injects
`trainlab_inject.dll`, and connects to the DLL's listener. You can override the
target game with the `TRAINLAB_GAME` environment variable (see below).

### Linux / SteamOS (Proton/Wine)

`trainlab-gui.exe` is a Windows binary; it runs under Wine/Proton. Launch it so
it shares the game's Wine prefix, then it can inject the DLL via Windows APIs
(`OpenProcess` / `CreateRemoteThread`). You can start it:

- **from a terminal** inside the game's Wine prefix / Proton environment,
- via a **custom script** (yours, or a community one) that starts the game and
  the trainer together,
- via **Steam Tinker Launch (STL)** as one of several options — STL can
  *fork* the trainer alongside the game in the same prefix, or *inject* it
  after the game loads. This is a convenience, not a requirement.

Because launch tooling on SteamOS/Linux evolves quickly and varies by setup, we
deliberately don't ship launcher scripts — use whatever works for your
environment. Community guides (Cheat Engine / Fling-style "how to run alongside
a game") are a good starting point.

## Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `TRAINLAB_GAME` | `Urbek.exe` | The game process name the GUI looks for / injects into. Set it to your game's exe (e.g. `Unrailed2.exe`). |
| `TRAINLAB_MCP_HOST` | `0.0.0.0` | Bind address for the MCP server. `0.0.0.0` = reachable on the LAN; `127.0.0.1` = local only. |
| `TRAINLAB_MCP_PORT` | `8123` | Port for the MCP server (see `MCP_DEFAULT_PORT` in `main.rs`). |

## Connecting an agent (MCP)

The GUI hosts a Model Context Protocol server over **Streamable HTTP** at:

```
http://127.0.0.1:8123/mcp
```

The MCP tool surface is the recon/analysis API:

- **Attach / manage** — `find_games`, `attach_game` (find the process, inject
  the DLL, connect), `connection_status`, `set_connection`. This is the remote
  setup loop: an agent can bring up the whole trainer on a Steam Deck / Steam
  machine without touching the GUI.
- **Recon / analysis** — `ping`, `list_regions`, `read`, `dump`, `dump_struct`,
  `aob_scan`, `scan`, `next`, `pointer_scan`, `pointer_chase`, `disassemble`,
  `addr_to_module`, `set_marker`, `get_marker`, `list_markers`, `remove_marker`,
  `watch_writes`, `break_on_code`, `watch_poll`, `clear_breakpoints`.
- **Gated mutating** — `write`, `install_cave`, `undo` (which stage a change;
  `confirm_op` / `reject_op` / `list_pending` complete the confirmation gate).

To connect a goose session, add a `streamable_http` extension:

```yaml
  trainlab:
    type: streamable_http
    uri: http://127.0.0.1:8123/mcp
    enabled: false   # enable per-session with --with-streamable-http-extension
```

or enable it for a single session:

```bash
goose session --with-streamable-http-extension "http://127.0.0.1:8123/mcp"
```

### Remote setup loop (agent-driven)

Once connected via a `streamable_http` extension, an agent can run the whole
setup loop remotely — it doesn't need the GUI:

1. `find_games` → list candidate game processes.
2. `attach_game { "game": "Unrailed2.exe", "inject": true }` → find the process,
   inject the DLL, connect to its listener.
3. `connection_status` → confirm attached, see the game pid + DLL version.
4. Then recon/mutate with the rest of the tool surface.

On a Steam Deck / Steam machine, the GUI still has to be running (it hosts the
MCP server and injects the DLL), but once it's up the agent drives everything
from your desktop machine.

## Remote connectivity (Steam Deck / another machine)

The MCP server binds to `0.0.0.0` by default, so a laptop/desktop can reach the
trainer over the network. Choose the transport that fits your network:

- **Direct LAN** — point the agent at the trainer's LAN IP:
  `http://<trainer-ip>:8123/mcp`. No extra setup if they're on the same subnet.
  The trainer machine's firewall must allow inbound `8123/tcp`.

- **SSH tunnel** — reach a trainer on a machine you can SSH into, without
  exposing a port:
  ```bash
  ssh -L 8123:127.0.0.1:8123 user@trainer-host
  ```
  then point the agent at `http://127.0.0.1:8123/mcp` locally.

- **Tailscale / mesh VPN** — put both machines on the same tailnet, then use
  the trainer's Tailscale IP (or MagicDNS name) in place of `127.0.0.1`:
  `http://trainer-host:8123/mcp`.

### Security note

The MCP server has **no authentication** and, when bound to `0.0.0.0`, exposes
mutating tools (`confirm_op` can apply staged writes/caves). For anything beyond
a trusted local network, prefer an **SSH tunnel or Tailscale** over binding to
the public interface, and never bind to `0.0.0.0` on an untrusted network.
