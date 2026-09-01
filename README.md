# Trainlab 🎮

**Trainlab** is a modern game trainer framework and reverse-engineering tool built for **PC, SteamOS, and Steam Deck (Proton / Wine)**.

It provides a lightweight in-game DirectX 11 overlay, an interactive desktop GUI, a companion web dashboard, and an integrated **Model Context Protocol (MCP)** server for AI-assisted cheat development.

---

## ✨ Features

- 🎮 **In-Game DirectX 11 Overlay**: Fully gamepad/Steam Deck controller navigable HUD (D-Pad navigation, category tabs, and active action feedback).
- 📋 **YAML Cheat Profiles**: Restart-stable, human-readable game profiles with AOB scans, pointer chains, code caves, and action buttons.
- 🌐 **Web Companion & Desktop GUI**: Monitor game state, toggle cheats, and view live logs from a browser on your phone, tablet, or secondary monitor.
- 🤖 **AI-Assisted (MCP)**: Pair with an AI agent to scan memory, chase pointers, write assembly code caves, and generate cheat tables live.
- 🛡️ **Safe & Non-Destructive**: Reversible writes, confirmation gates, and memory-safe code cave patching.

---

## 🚀 Quickstart

### Launching on Steam Deck / SteamOS

1. Place `trainlab-gui.exe`, `trainlab_inject.dll`, and `launch.sh` in `~/Documents/Trainers/Trainlab/`.
2. Add your launch script or set Steam launch options:
   ```bash
   ~/Documents/Trainers/Trainlab/launch.sh %command%
   ```
3. Start your game. Trainlab automatically attaches, injects the companion overlay, and auto-loads matching cheat profiles.

### Launching on Windows

1. Run `trainlab-gui.exe`.
2. Select your running game from the dropdown or let auto-attach detect it.
3. Use the **Cheats Panel** or toggle cheats inside the game.

### Controls in Overlay
- **Open / Close Overlay**: Toggle hotkey or button combo.
- **LB / RB**: Switch cheat category tabs.
- **D-Pad Up / Down**: Navigate cheats.
- **A Button (Cross)**: Toggle cheat / trigger button action.
- **B Button (Circle)**: Dismiss overlay.

---

## 📁 Cheat Profiles

Cheat profiles live in the `cheats/` directory next to the application (e.g. `cheats/helldivers.yaml` or `cheats/DRGSurvivor.yaml`).

Profiles automatically resolve base addresses each launch using:
- **AOB Signatures**: Scans for static code patterns.
- **Pointer Chains**: Resolves module-relative dynamic heap chains.
- **Code Caves**: Injects pure x86-64 assembly hooks.

For cheat profile syntax and authoring details, see [`docs/CHEAT_PROFILE.md`](docs/CHEAT_PROFILE.md).

---

## 🤖 AI Agent Pairing (MCP)

Trainlab includes a built-in MCP server on port `8123` (`http://<ip>:8123/mcp`).

Point any MCP-compatible coding assistant (e.g., Goose) to Trainlab to enable live memory hunting:
```yaml
extensions:
  trainlab:
    type: streamable_http
    uri: http://127.0.0.1:8123/mcp
```
See [`docs/AGENT_GUIDE.md`](docs/AGENT_GUIDE.md) for full MCP workflow and tool definitions.

---

## 🛠 Documentation & Development

- [`DEVELOPMENT.md`](DEVELOPMENT.md) — Cross-compilation, build instructions, and crate architecture.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — In-depth technical architecture and IPC protocol.
- [`docs/CHEAT_PROFILE.md`](docs/CHEAT_PROFILE.md) — Cheat profile schema documentation.
- [`docs/CONCEPTS.md`](docs/CONCEPTS.md) — Memory hacking principles and Wine/Proton execution models.

---

## 📜 License

Dual-licensed under **MIT** ([LICENSE-MIT](LICENSE-MIT)) and **Apache-2.0** ([LICENSE-APACHE](LICENSE-APACHE)).
