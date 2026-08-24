//! Shared control logic for attaching to a game and managing the DLL.
//!
//! Both the GUI (`TrainlabApp`) and the MCP server (`TrainlabMcpServer`) drive
//! the same setup loop — find the game, inject the DLL, connect to its
//! listener, ping it — so an LLM can do the whole attach/connect flow remotely
//! (Steam Deck / Steam machine use case). This module centralizes that logic
//! and the low-level framed request/response over the DLL fast channel.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

use trainlab_core::protocol::{self, Message, Request, Response};

use crate::session::SharedSession;

/// Default DLL fast-channel host/port (matches the injected DLL's listener).
const DEFAULT_DLL_HOST: &str = "127.0.0.1";
const DEFAULT_DLL_PORT: u16 = 31337;

static NEXT_SEQ: AtomicU64 = AtomicU64::new(1);

struct PendingRequest {
    tx: oneshot::Sender<Response>,
}

/// A thread-safe handle to the single persistent multiplexed IPC client.
#[derive(Clone)]
pub struct IpcClient {
    tx: std::sync::mpsc::Sender<(u64, Request, oneshot::Sender<Response>)>,
}

static GLOBAL_CLIENT: Mutex<Option<(String, u16, IpcClient)>> = Mutex::new(None);

impl IpcClient {
    pub fn connect(host: String, port: u16) -> Result<Self, String> {
        let (tx, rx) = std::sync::mpsc::channel::<(u64, Request, oneshot::Sender<Response>)>();
        let target_addr = format!("{host}:{port}");

        std::thread::spawn(move || {
            use std::io::{Read, Write};
            use std::net::ToSocketAddrs;

            while let Ok((id, req, resp_tx)) = rx.recv() {
                // Connect with short timeout
                let mut resp_opt: Option<Response> = None;
                if let Ok(mut addrs) = target_addr.to_socket_addrs() {
                    if let Some(sock_addr) = addrs.next() {
                        if let Ok(mut stream) = std::net::TcpStream::connect_timeout(&sock_addr, Duration::from_millis(500)) {
                            let _ = stream.set_nodelay(true);
                            let _ = stream.set_read_timeout(Some(Duration::from_millis(1500)));
                            let _ = stream.set_write_timeout(Some(Duration::from_millis(1500)));

                            let msg = Message::Request { id, req };
                            if let Ok(frame) = protocol::encode(&msg) {
                                if stream.write_all(&frame).is_ok() {
                                    let mut len_buf = [0u8; 4];
                                    if stream.read_exact(&mut len_buf).is_ok() {
                                        let len = u32::from_le_bytes(len_buf) as usize;
                                        if len > 0 && len <= 64 * 1024 * 1024 {
                                            let mut body = vec![0u8; len];
                                            if stream.read_exact(&mut body).is_ok() {
                                                let mut full = Vec::with_capacity(4 + len);
                                                full.extend_from_slice(&len_buf);
                                                full.extend_from_slice(&body);
                                                if let Ok(msg) = protocol::decode::<Message>(&full) {
                                                    if let Message::Response { resp, .. } = msg {
                                                        resp_opt = Some(resp);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                let resp = resp_opt.unwrap_or_else(|| Response::Error {
                    message: "IPC request failed / timeout".into(),
                });
                let _ = resp_tx.send(resp);
            }
        });

        Ok(Self { tx })
    }

    pub fn request(&self, req: Request) -> Result<Response, String> {
        let seq = NEXT_SEQ.fetch_add(1, Ordering::Relaxed);
        let (resp_tx, mut resp_rx) = oneshot::channel();
        self.tx
            .send((seq, req, resp_tx))
            .map_err(|e| format!("IPC mailbox send failed: {e}"))?;
        
        // Non-infinite blocking with timeout so caller NEVER wedges
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_millis(2000) {
            match resp_rx.try_recv() {
                Ok(resp) => return Ok(resp),
                Err(oneshot::error::TryRecvError::Empty) => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(oneshot::error::TryRecvError::Closed) => {
                    return Err("IPC channel closed".into());
                }
            }
        }
        Err("IPC request timed out".into())
    }
}

/// Send a request to the DLL listener at `(host, port)` via the single multiplexed channel.
pub fn request_at(host: &str, port: u16, req: &Request) -> Result<Response, String> {
    let mut lock = GLOBAL_CLIENT.lock().unwrap();
    let client = match &*lock {
        Some((h, p, c)) if h == host && *p == port => c.clone(),
        _ => {
            let c = IpcClient::connect(host.to_string(), port)?;
            *lock = Some((host.to_string(), port, c.clone()));
            c
        }
    };
    drop(lock);
    client.request(req.clone())
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

    // Poll the DLL listener with retries while its thread spins up.
    let mut last_err = String::from("timed out waiting for DLL listener");
    for _ in 0..15 {
        std::thread::sleep(std::time::Duration::from_millis(300));
        match check_connection(session) {
            Ok(version) => return Ok(version),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
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
