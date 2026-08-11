//! Shared control logic for attaching to a game and managing the DLL.
//!
//! Both the GUI (`TrainlabApp`) and the MCP server (`TrainlabMcpServer`) drive
//! the same setup loop — find the game, inject the DLL, connect to its
//! listener, ping it — so an LLM can do the whole attach/connect flow remotely
//! (Steam Deck / Steam machine use case). This module centralizes that logic
//! and the low-level framed request/response over the DLL fast channel.

use std::io::Write;
use std::net::TcpStream;

use trainlab_core::protocol::{self, Request, Response};

use crate::session::SharedSession;

/// Default DLL fast-channel host/port (matches the injected DLL's listener).
const DEFAULT_DLL_HOST: &str = "127.0.0.1";
const DEFAULT_DLL_PORT: u16 = 31337;

/// Read a 4-byte length-prefixed frame from `stream`, returning the raw frame
/// (length prefix + body) ready for `protocol::decode`.
fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| format!("read length error: {e}"))?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 || len > 64 * 1024 * 1024 {
        return Err("bad frame length".into());
    }
    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .map_err(|e| format!("read body error: {e}"))?;
    let mut full = Vec::with_capacity(4 + len);
    full.extend_from_slice(&len_buf);
    full.extend_from_slice(&body);
    Ok(full)
}

/// Send a request to the DLL listener at `(host, port)` and return the response.
///
/// Returns a `String` error on any connection/framing/decode failure.
pub fn request_at(host: &str, port: u16, req: &Request) -> Result<Response, String> {
    let addr = format!("{host}:{port}");
    let mut stream = TcpStream::connect(&addr)
        .map_err(|e| format!("connect to DLL ({addr}) failed: {e}"))?;
    let _ = stream.set_nodelay(true);
    let frame = protocol::encode(req).map_err(|e| format!("encode error: {e}"))?;
    stream
        .write_all(&frame)
        .map_err(|e| format!("write error: {e}"))?;
    let full = read_frame(&mut stream)?;
    protocol::decode::<Response>(&full).map_err(|e| format!("decode error: {e}"))
}

/// Send a request to the DLL using the session's configured host/port.
pub fn request(session: &SharedSession, req: &Request) -> Result<Response, String> {
    let (host, port) = {
        let s = session
            .lock()
            .map_err(|_| "session lock poisoned".to_string())?;
        (s.dll_host().to_string(), s.dll_port())
    };
    request_at(&host, port, req)
}

/// Ping the DLL at the given host/port. Returns the reported version.
pub fn ping_at(host: &str, port: u16) -> Result<String, String> {
    match request_at(host, port, &Request::Ping) {
        Ok(Response::Pong { version }) => Ok(version),
        Ok(Response::Error { message }) => Err(message),
        Ok(_) => Err("unexpected ping response".into()),
        Err(e) => Err(e),
    }
}

/// Ping the DLL using the session's host/port, updating connection state.
pub fn check_connection(session: &SharedSession) -> Result<String, String> {
    apply_defaults(session);
    let (host, port) = {
        let s = session
            .lock()
            .map_err(|_| "session lock poisoned".to_string())?;
        (s.dll_host().to_string(), s.dll_port())
    };
    match ping_at(&host, port) {
        Ok(version) => {
            if let Ok(mut s) = session.lock() {
                s.set_connected(true);
                s.set_inject_version(Some(version.clone()));
            }
            Ok(version)
        }
        Err(e) => {
            if let Ok(mut s) = session.lock() {
                s.set_connected(false);
            }
            Err(e)
        }
    }
}

/// Find the game process by name and inject the DLL into it, then connect and
/// ping the DLL's listener. This is the full attach flow.
///
/// Returns the DLL version on success, or an error string.
pub fn find_inject_connect(session: &SharedSession) -> Result<String, String> {
    let (game_name, dll_path) = {
        let s = session
            .lock()
            .map_err(|_| "session lock poisoned".to_string())?;
        (s.game_name().to_string(), s.dll_path().to_string())
    };
    // Find the game process by name.
    let pid = crate::inject::find_game(&game_name)
        .ok_or_else(|| format!("game '{game_name}' not found"))?;
    // Record the PID in the session so scan-family tools can open it externally.
    {
        let mut s = session
            .lock()
            .map_err(|_| "session lock poisoned".to_string())?;
        s.set_game_pid(pid);
    }
    // Inject the DLL.
    crate::inject::inject_dll(pid, &dll_path).map_err(|e| format!("inject failed: {e}"))?;
    // Give the DLL a moment to start its listener, then ping it.
    std::thread::sleep(std::time::Duration::from_millis(500));
    check_connection(session)
}

/// Apply the session's default host/port (used when no explicit config is set).
pub fn apply_defaults(session: &SharedSession) {
    if let Ok(mut s) = session.lock() {
        if s.dll_host().is_empty() {
            s.set_dll_host(DEFAULT_DLL_HOST);
        }
        if s.dll_port() == 0 {
            s.set_dll_port(DEFAULT_DLL_PORT);
        }
    }
}
