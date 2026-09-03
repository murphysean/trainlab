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

/// Global network hook configuration and captured packet ring buffer.
static NETWORK_ENABLED: AtomicBool = AtomicBool::new(true);
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

/// Record a newly captured network packet.
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

/// Initialize network traffic hooks if supported on the platform.
pub fn init() {
    #[cfg(windows)]
    {
        std::thread::Builder::new()
            .name("trainlab-net-init".into())
            .spawn(|| {
                winsock::init_winsock_hooks();
                winhttp::init_winhttp_hooks();
            })
            .ok();
    }
    #[cfg(not(windows))]
    {
        tracing::info!("network traffic hooking is not supported on non-Windows platforms (stubbed)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_and_drain_packets() {
        set_enabled(true);
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
    fn test_http_packet_recording() {
        set_enabled(true);
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

