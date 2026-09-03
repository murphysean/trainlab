//! Network traffic interception and inspection module.
//!
//! Provides a lock-free or mutex-guarded ring buffer for captured packets
//! and manages Winsock and WinHTTP detour hooks.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use trainlab_core::protocol::{Event, NetworkPacketDto, PacketDirection, PacketKind};

#[cfg(windows)]
pub mod winsock;
#[cfg(windows)]
pub mod winhttp;
#[cfg(windows)]
pub mod schannel;

/// Global network hook configuration and captured packet ring buffer.
static NETWORK_ENABLED: AtomicBool = AtomicBool::new(true);
static CAPTURE_LOOPBACK: AtomicBool = AtomicBool::new(false);
static IGNORE_PORTS: Mutex<Vec<u16>> = Mutex::new(Vec::new());
static PACKET_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Maximum packets retained in the in-memory push queue.
const MAX_QUEUED_PACKETS: usize = 2000;

/// Outbound queue of captured network packet events awaiting transmission over IPC.
static CAPTURED_PACKETS: Mutex<Vec<NetworkPacketDto>> = Mutex::new(Vec::new());

/// Whether network capture is globally active.
pub fn is_enabled() -> bool {
    NETWORK_ENABLED.load(Ordering::Relaxed)
}

/// Enable or disable network traffic capture.
pub fn set_enabled(enabled: bool) {
    NETWORK_ENABLED.store(enabled, Ordering::SeqCst);
}

/// Configure network capture filter: enable flag, ignored ports, and loopback capture toggle.
pub fn configure(enabled: bool, ignore_ports: &[u16], capture_loopback: bool) {
    NETWORK_ENABLED.store(enabled, Ordering::SeqCst);
    CAPTURE_LOOPBACK.store(capture_loopback, Ordering::SeqCst);
    if let Ok(mut ports) = IGNORE_PORTS.lock() {
        *ports = ignore_ports.to_vec();
    }
}

/// Helper to parse port from an endpoint string like "127.0.0.1:31337" or "[::1]:8123".
fn extract_port(endpoint: &str) -> Option<u16> {
    endpoint.rsplit(':').next()?.parse::<u16>().ok()
}

/// Check if an IP/host string is loopback (127.0.0.1, localhost, ::1).
fn is_loopback_endpoint(endpoint: &str) -> bool {
    let clean = endpoint.trim().to_lowercase();
    clean.starts_with("127.")
        || clean.starts_with("localhost")
        || clean.starts_with("[::1]")
        || clean.starts_with("::1")
}

/// Record a newly captured network packet, filtering out ignored ports and loopback traffic by default.
pub fn record_packet(
    kind: PacketKind,
    direction: PacketDirection,
    local_endpoint: Option<String>,
    remote_endpoint: Option<String>,
    url: Option<String>,
    headers: Option<String>,
    payload: &[u8],
) {
    if !is_enabled() {
        return;
    }

    // Check if either endpoint touches an ignored port (e.g. trainer IPC 31337 or MCP 8123)
    let local_port = local_endpoint.as_deref().and_then(extract_port);
    let remote_port = remote_endpoint.as_deref().and_then(extract_port);

    if let Ok(ignored) = IGNORE_PORTS.lock() {
        if let Some(lp) = local_port {
            if ignored.contains(&lp) {
                return;
            }
        }
        if let Some(rp) = remote_port {
            if ignored.contains(&rp) {
                return;
            }
        }
    }

    // Default: Ignore loopback / localhost traffic unless explicitly configured
    if !CAPTURE_LOOPBACK.load(Ordering::Relaxed) {
        let local_is_loopback = local_endpoint.as_deref().map(is_loopback_endpoint).unwrap_or(false);
        let remote_is_loopback = remote_endpoint.as_deref().map(is_loopback_endpoint).unwrap_or(false);
        let url_is_loopback = url.as_deref().map(|u| {
            let u_lower = u.to_lowercase();
            u_lower.contains("://127.") || u_lower.contains("://localhost") || u_lower.contains("://[::1]")
        }).unwrap_or(false);

        if (local_is_loopback && remote_is_loopback)
            || (remote_endpoint.is_none() && local_is_loopback)
            || (local_endpoint.is_none() && remote_is_loopback)
            || url_is_loopback
        {
            return;
        }
    }

    let id = PACKET_COUNTER.fetch_add(1, Ordering::Relaxed);
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    // Keep preview light for IPC wire transfer (first 256 bytes)
    let preview_len = payload.len().min(256);
    let payload_preview = payload[..preview_len].to_vec();

    let dto = NetworkPacketDto {
        id,
        timestamp_ms: now_ms,
        kind,
        direction,
        local_endpoint,
        remote_endpoint,
        url,
        headers,
        payload_len: payload.len(),
        payload_preview,
        artifact_file: None,
    };

    if let Ok(mut lock) = CAPTURED_PACKETS.lock() {
        if lock.len() >= MAX_QUEUED_PACKETS {
            lock.remove(0);
        }
        lock.push(dto);
    }
}

/// Drain captured packet events to send over IPC.
pub fn drain_network_events() -> Vec<Event> {
    if let Ok(mut lock) = CAPTURED_PACKETS.lock() {
        if lock.is_empty() {
            Vec::new()
        } else {
            lock.drain(..)
                .map(Event::NetworkPacket)
                .collect()
        }
    } else {
        Vec::new()
    }
}

/// Initialize network traffic hooks if supported on the platform with granular flags.
pub fn init_with_config(winsock: bool, winhttp: bool, schannel: bool) {
    #[cfg(windows)]
    {
        std::thread::Builder::new()
            .name("trainlab-net-init".into())
            .spawn(move || {
                if winsock {
                    winsock::init_winsock_hooks();
                }
                if winhttp {
                    winhttp::init_winhttp_hooks();
                }
                if schannel {
                    schannel::init_schannel_hooks();
                }
            })
            .ok();
    }
    #[cfg(not(windows))]
    {
        let _ = (winsock, winhttp, schannel);
        tracing::info!("network traffic hooking is not supported on non-Windows platforms (stubbed)");
    }
}

/// Initialize network traffic hooks with all enabled (legacy/default).
pub fn init() {
    init_with_config(true, true, true);
}

/// Probe loaded network modules in the process.
pub fn detect_network_modules() -> Vec<String> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;
        let mut modules = Vec::new();
        let targets = [
            ("ws2_32.dll", "ws2_32.dll\0"),
            ("winhttp.dll", "winhttp.dll\0"),
            ("wininet.dll", "wininet.dll\0"),
            ("secur32.dll", "secur32.dll\0"),
            ("sspicli.dll", "sspicli.dll\0"),
            ("steam_api64.dll", "steam_api64.dll\0"),
            ("steamnetworkingsockets.dll", "steamnetworkingsockets.dll\0"),
        ];
        for (name, dll_null) in targets {
            unsafe {
                if !GetModuleHandleA(dll_null.as_ptr()).is_null() {
                    modules.push(name.to_string());
                }
            }
        }
        modules
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn test_record_and_drain_packets() {
        let _guard = TEST_MUTEX.lock().unwrap();
        configure(true, &[], true); // allow loopback for test
        let _ = drain_network_events();
        record_packet(
            PacketKind::Tcp,
            PacketDirection::Outbound,
            Some("127.0.0.1:12345".into()),
            Some("127.0.0.1:80".into()),
            None,
            None,
            b"GET / HTTP/1.1\r\n\r\n",
        );

        let events = drain_network_events();
        assert_eq!(events.len(), 1);
        if let Event::NetworkPacket(p) = &events[0] {
            assert_eq!(p.kind, PacketKind::Tcp);
            assert_eq!(p.direction, PacketDirection::Outbound);
            assert_eq!(p.local_endpoint.as_deref(), Some("127.0.0.1:12345"));
            assert_eq!(p.remote_endpoint.as_deref(), Some("127.0.0.1:80"));
            assert_eq!(&p.payload_preview, b"GET / HTTP/1.1\r\n\r\n");
        } else {
            panic!("expected NetworkPacket event");
        }

        // Second drain is empty
        assert!(drain_network_events().is_empty());

        // Test disabled
        set_enabled(false);
        record_packet(
            PacketKind::Udp,
            PacketDirection::Inbound,
            None,
            None,
            None,
            None,
            b"test",
        );
        assert!(drain_network_events().is_empty());
        set_enabled(true);
    }

    #[test]
    fn test_loopback_and_port_filtering() {
        let _guard = TEST_MUTEX.lock().unwrap();
        // Default: loopback is false, ignore port 31337
        configure(true, &[31337], false);
        let _ = drain_network_events();

        // 1. Loopback packet should be ignored
        record_packet(
            PacketKind::Tcp,
            PacketDirection::Inbound,
            Some("127.0.0.1:54321".into()),
            Some("127.0.0.1:31337".into()),
            None,
            None,
            b"INTERNAL_IPC",
        );
        assert!(drain_network_events().is_empty());

        // 2. Ignored port on external IP should also be ignored
        record_packet(
            PacketKind::Tcp,
            PacketDirection::Outbound,
            Some("192.168.1.100:31337".into()),
            Some("192.168.1.50:5555".into()),
            None,
            None,
            b"INTERNAL_TRAFFIC",
        );
        assert!(drain_network_events().is_empty());

        // 3. Legitimate external game traffic should be captured
        record_packet(
            PacketKind::Udp,
            PacketDirection::Outbound,
            Some("192.168.1.100:49152".into()),
            Some("198.51.100.20:27015".into()),
            None,
            None,
            b"GAME_SERVER_PACKET",
        );
        let captured = drain_network_events();
        assert_eq!(captured.len(), 1);
        if let Event::NetworkPacket(p) = &captured[0] {
            assert_eq!(p.kind, PacketKind::Udp);
            assert_eq!(&p.payload_preview, b"GAME_SERVER_PACKET");
        }
    }

    #[test]
    fn test_http_packet_recording() {
        let _guard = TEST_MUTEX.lock().unwrap();
        configure(true, &[], false);
        let _ = drain_network_events();
        record_packet(
            PacketKind::Http,
            PacketDirection::Outbound,
            None,
            None,
            Some("POST /api/v1/auth".into()),
            Some("Authorization: Bearer secret\r\nContent-Type: application/json".into()),
            br#"{"username":"player1"}"#,
        );

        let events = drain_network_events();
        assert_eq!(events.len(), 1);
        if let Event::NetworkPacket(p) = &events[0] {
            assert_eq!(p.kind, PacketKind::Http);
            assert_eq!(p.direction, PacketDirection::Outbound);
            assert_eq!(p.url.as_deref(), Some("POST /api/v1/auth"));
            assert_eq!(p.headers.as_deref(), Some("Authorization: Bearer secret\r\nContent-Type: application/json"));
            assert_eq!(&p.payload_preview, br#"{"username":"player1"}"#);
        } else {
            panic!("expected NetworkPacket event");
        }
    }
}

