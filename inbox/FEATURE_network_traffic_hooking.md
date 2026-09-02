# Feature Request: Network Traffic Hooking & Inspection (Peer Traffic, HTTP/REST, Sockets)

**Status:** open
**Priority:** P2
**crates:** `trainlab-inject` (Winsock/WinHTTP hooks, packet ring buffer), `trainlab-core` (wire events & protocol), `trainlab-gui` (MCP tools & GUI traffic inspector)
**Date:** 2026-09-01

---

## 1. Summary & Motivation

When reverse-engineering modern multiplayer or connected single-player games running under Wine/Proton, understanding network activity is critical for:
1. **Peer-to-Peer Game Traffic**: Discovering protocol structures, coordinates, state syncs, RPCs, and packet formats (`sendto`/`recvfrom`, `send`/`recv`).
2. **HTTP / REST Backend Queries**: Intercepting plain-text account queries, game configs, matchmaking endpoints, telemetry, and web API responses (`WinHttpSendRequest`/`WinHttpReadData`, `InternetReadFile`).
3. **Session Reconnaissance**: Tracing IP endpoints and ports without needing external tools (like Wireshark or `tcpdump`) that cannot see pre-encryption TLS or per-process socket state under Proton.

By leveraging `trainlab-inject` (already inside the target game process), we can hook Windows network APIs directly and stream captured packets to the GUI and LLM agent via the unified event bus.

---

## 2. Technical Architecture

### 2.1 Hooking Surface in `trainlab-inject`

1. **Winsock Layer (`ws2_32.dll` / `wsock32.dll`)** — Raw TCP & UDP:
   - `send`, `sendto`, `WSASend`, `WSASendTo` (Outbound)
   - `recv`, `recvfrom`, `WSARecv`, `WSARecvFrom` (Inbound)
   - `connect`, `WSAConnect` (Target IP:Port extraction)
   - *Data captured*: Socket descriptor, Remote Socket Address (`sockaddr_in` / `sockaddr_in6`), Direction (In/Out), Payload bytes, Timestamp.

2. **HTTP / REST Client Layer (`winhttp.dll` / `wininet.dll`)** — Plain-Text Web Traffic:
   - `WinHttpSendRequest`, `WinHttpReceiveResponse`, `WinHttpReadData`
   - `HttpSendRequestA/W`, `InternetReadFile`
   - *Data captured*: HTTP Method (GET/POST), Target URL/Path, Headers, Request Body, Response Status & Body (captured *before* TLS encryption / *after* TLS decryption).

3. **Optional SChannel/TLS Layer (`secur32.dll`)**:
   - `EncryptMessage` / `DecryptMessage` for general SSL/TLS stream interception.

---

### 2.2 In-Memory Buffering & Transport

1. **Lock-Free Network Ring Buffer**:
   - Maintain a circular buffer in `trainlab-inject` (similar to `captures::CaptureRing`) with a configurable capacity (e.g. 1,000–5,000 packets) to prevent heap allocation on high-frequency network threads.
2. **Autonomous Push Streaming**:
   - The proactive push thread in `trainlab-inject` drains captured packets and sends `Message::Event(Event::NetworkPacket { ... })` frames across the IPC connection.

---

### 2.3 Wire Protocol (`trainlab-core::protocol`)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PacketKind {
    Tcp,
    Udp,
    Http,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PacketDirection {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPacketDto {
    pub id: u64,
    pub timestamp_ms: u64,
    pub kind: PacketKind,
    pub direction: PacketDirection,
    pub local_endpoint: Option<String>,
    pub remote_endpoint: Option<String>,
    pub url: Option<String>,
    pub headers: Option<String>,
    pub payload_len: usize,
    pub payload_preview: Vec<u8>, // truncated for wire transport (e.g. first 256/1024 bytes)
    pub artifact_file: Option<String>, // if large payload was dumped to disk
}
```

---

### 2.4 MCP & Agent Tooling

Expose dedicated network recon tools to the MCP agent:
- `watch_network { filter_host?, filter_port?, kind?: "tcp"|"udp"|"http"|"all", max_packets?: usize }`
  - Captures network traffic matching optional endpoint filters and returns structured JSON packet logs.
- `get_network_log { limit?: usize, offset?: usize }`
  - Retrieves the latest packets from the session's active capture ring.
- `clear_network_log {}`
  - Resets the session packet buffer.

---

### 2.5 GUI Inspector Tab

Add a **"Network Traffic"** tab to `trainlab-gui`:
- Filterable table showing: `#`, `Time`, `Direction` (⬆/⬇), `Kind` (TCP/UDP/HTTP), `Remote Endpoint`, `Size`, and `Preview`.
- Detail inspection pane with dual **Hexdump / ASCII** viewer and auto-formatting for JSON/REST HTTP bodies.
- "Export Packet Capture (.pcap / .json)" button for offline analysis.

---

## 3. Implementation Plan

1. **Phase 1: Winsock TCP/UDP Interception**:
   - Hook `send`, `recv`, `sendto`, `recvfrom` in `trainlab-inject`.
   - Implement thread-safe packet ring buffer.
   - Stream `Event::NetworkPacket` over IPC.
2. **Phase 2: MCP Tools & Session Logging**:
   - Add `watch_network` and `get_network_log` to MCP server and core tool dispatcher.
3. **Phase 3: HTTP/WinHTTP Interception**:
   - Hook `WinHttpSendRequest` / `WinHttpReadData` for unencrypted REST body logging.
4. **Phase 4: GUI Inspector**:
   - Implement the `NetworkTraffic` view with hexdump and JSON formatting in `trainlab-gui`.
