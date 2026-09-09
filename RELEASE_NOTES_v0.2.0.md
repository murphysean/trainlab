## What's Changed in v0.2.0

### 🌐 Network Traffic & Packet Interception
- **Real-Time Traffic Accounting**: Added atomic packet and byte counters directly at hook invocation sites for all major subsystems (**UDP**, **TCP**, **HTTP/WinHTTP**, **SChannel TLS**, and **Steamworks**).
- **GUI & MCP Integration**:
  - Added live 1Hz traffic summary cards to the GUI **Network Traffic** tab displaying inbound/outbound packets, transferred volume, and dropped packet statistics.
  - Implemented the `get_network_status` MCP tool for fast on-demand query without per-packet IPC overhead.
- **Steamworks P2P (ISteamNetworking & ISteamNetworkingSockets)**:
  - Added `lsteamclient.dll` detour hooks for legacy **`SteamNetworking005`** (`SendP2PPacket` and `ReadP2PPacket`), unlocking full peer datagram capture for titles utilizing legacy P2P under Proton/Wine.
  - Added support for modern **`ISteamNetworkingSockets`** and **`ISteamNetworkingMessages`**.
  - Enhanced PE pattern scanner and function prologue detection across GCC/MinGW/Wine calling conventions.
- **Winsock UDP Datagram Hooks**:
  - Added hooks for `WSASendTo`, `WSARecvFrom`, `WSASend`, and `WSARecv` with full support for `WSA_IO_PENDING` overlapped asynchronous completion.

### 🛡️ Memory, Cave Injection & Session Safety
- **Cheat Verification**: Enforced strict live baseline byte verification on cheat toggles to prevent invalid state transitions and corrupted memory writes.
- **Cave Branch Verification**: Implemented verification for surrounding code steal windows to detect and prevent inward relative jumps.
- **Config Plumbing**: Fixed profile network settings initialization and re-filtering during live capture sessions.

---

### 📦 Build Artifacts

| Binary | Target | MD5 Checksum |
| :--- | :--- | :--- |
| `trainlab-gui.exe` | `x86_64-pc-windows-gnu` | `f07ed9d1515c64f14cdbd1b4d3299123` |
| `trainlab_inject.dll` | `x86_64-pc-windows-gnu` | `4be203c351ac92368a8caf31d53e1924` |
