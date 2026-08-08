//! # trainlab-gui
//!
//! A desktop GUI (built with `egui`/`eframe`) that connects to the injected
//! DLL and lets you:
//!
//! - Connect to a running `trainlab-inject` listener.
//! - Ping it to confirm it's alive.
//! - Read / write memory at arbitrary addresses.
//! - Run AOB pattern scans.
//! - Allocate / free code caves.
//! - List memory regions.
//!
//! This is the "control room" for your training sessions.

use std::io::{Read, Write};
use std::net::TcpStream;

use eframe::egui;
use trainlab_core::protocol::{self, Request, Response};

fn main() -> eframe::Result<()> {
    tracing_subscriber::fmt::init();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([900.0, 640.0]),
        ..Default::default()
    };
    eframe::run_native(
        "trainlab",
        options,
        Box::new(|_cc| Box::new(TrainlabApp::default())),
    )
}

/// A single memory read/write operation shown in the UI.
#[derive(Default, Clone)]
struct MemOp {
    address: String,
    value: String,
    result: String,
}

/// A single AOB scan shown in the UI.
#[derive(Default, Clone)]
struct AobScan {
    pattern: String,
    result: String,
}

struct TrainlabApp {
    // Connection
    host: String,
    port: String,
    connected: bool,
    status: String,

    // Panels
    mem_ops: Vec<MemOp>,
    aob_scans: Vec<AobScan>,
    regions: Vec<trainlab_core::protocol::RegionInfo>,
    log: Vec<String>,
}

impl Default for TrainlabApp {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: "31337".into(),
            connected: false,
            status: "not connected".into(),
            mem_ops: vec![MemOp::default()],
            aob_scans: vec![AobScan::default()],
            regions: Vec::new(),
            log: Vec::new(),
        }
    }
}

impl TrainlabApp {
    fn log(&mut self, msg: impl Into<String>) {
        self.log.push(msg.into());
        if self.log.len() > 500 {
            self.log.remove(0);
        }
    }

    /// Send a request and receive the response, or `None` on connection error.
    fn request(&mut self, req: &Request) -> Option<Response> {
        let addr = format!("{}:{}", self.host, self.port);
        let mut stream = match TcpStream::connect(&addr) {
            Ok(s) => s,
            Err(e) => {
                self.status = format!("connect failed: {e}");
                self.connected = false;
                return None;
            }
        };
        let _ = stream.set_nodelay(true);

        let frame = match protocol::encode(req) {
            Ok(f) => f,
            Err(e) => {
                self.status = format!("encode failed: {e}");
                return None;
            }
        };
        if stream.write_all(&frame).is_err() {
            self.status = "write failed".into();
            self.connected = false;
            return None;
        }

        let mut len_buf = [0u8; 4];
        if read_exact(&mut stream, &mut len_buf).is_err() {
            self.status = "read failed".into();
            self.connected = false;
            return None;
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        if len == 0 || len > 64 * 1024 * 1024 {
            self.status = "bad frame length".into();
            return None;
        }
        let mut body = vec![0u8; len];
        if read_exact(&mut stream, &mut body).is_err() {
            self.status = "read failed".into();
            self.connected = false;
            return None;
        }
        let mut full = Vec::with_capacity(4 + len);
        full.extend_from_slice(&len_buf);
        full.extend_from_slice(&body);

        match protocol::decode::<Response>(&full) {
            Ok(r) => {
                self.connected = true;
                self.status = "connected".into();
                Some(r)
            }
            Err(e) => {
                self.status = format!("decode failed: {e}");
                None
            }
        }
    }
}

fn read_exact(stream: &mut TcpStream, buf: &mut [u8]) -> std::io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = stream.read(&mut buf[filled..])?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "closed",
            ));
        }
        filled += n;
    }
    Ok(())
}

impl eframe::App for TrainlabApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("conn").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("Host:");
                ui.text_edit_singleline(&mut self.host);
                ui.label("Port:");
                ui.text_edit_singleline(&mut self.port);
                if ui.button("Connect").clicked() {
                    let req = Request::Ping;
                    match self.request(&req) {
                        Some(Response::Pong { version }) => {
                            self.log(format!("connected, inject v{version}"));
                        }
                        Some(Response::Error { message }) => {
                            self.log(format!("error: {message}"));
                        }
                        _ => {}
                    }
                }
                ui.separator();
                ui.colored_label(
                    if self.connected {
                        egui::Color32::GREEN
                    } else {
                        egui::Color32::RED
                    },
                    &self.status,
                );
            });
        });

        egui::SidePanel::left("nav")
            .resizable(true)
            .default_width(180.0)
            .show(ctx, |ui| {
                ui.heading("trainlab");
                ui.separator();
                ui.label("Panels:");
                // Simple tab state via a local enum stored in the app.
                // We'll just render all panels stacked for simplicity.
                ui.label("• Memory");
                ui.label("• AOB Scan");
                ui.label("• Regions");
                ui.label("• Log");
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Memory");
            ui.horizontal(|ui| {
                if ui.button("Read").clicked() {
                    let ops: Vec<(usize, u64, usize)> = self
                        .mem_ops
                        .iter()
                        .enumerate()
                        .filter_map(|(i, op)| {
                            parse_addr(&op.address)
                                .ok()
                                .map(|addr| (i, addr, parse_len(&op.value).unwrap_or(16)))
                        })
                        .collect();
                    for (i, addr, len) in ops {
                        let result = match self.request(&Request::Read { address: addr, len }) {
                            Some(Response::Read { data }) => hexdump(&data),
                            Some(Response::Error { message }) => message,
                            _ => "no response".into(),
                        };
                        if let Some(op) = self.mem_ops.get_mut(i) {
                            op.result = result;
                        }
                    }
                }
                if ui.button("Write").clicked() {
                    let ops: Vec<(usize, u64, Vec<u8>)> = self
                        .mem_ops
                        .iter()
                        .enumerate()
                        .filter_map(|(i, op)| {
                            parse_addr(&op.address)
                                .ok()
                                .map(|addr| (i, addr, parse_bytes(&op.value)))
                        })
                        .collect();
                    for (i, addr, data) in ops {
                        let result = match self.request(&Request::Write { address: addr, data }) {
                            Some(Response::Write { bytes_written }) => {
                                format!("wrote {bytes_written} bytes")
                            }
                            Some(Response::Error { message }) => message,
                            _ => "no response".into(),
                        };
                        if let Some(op) = self.mem_ops.get_mut(i) {
                            op.result = result;
                        }
                    }
                }
                if ui.button("+").clicked() {
                    self.mem_ops.push(MemOp::default());
                }
            });
            for op in self.mem_ops.iter_mut() {
                ui.horizontal(|ui| {
                    ui.label("Addr:");
                    ui.text_edit_singleline(&mut op.address);
                    ui.label("Value:");
                    ui.text_edit_singleline(&mut op.value);
                });
                ui.label(&op.result);
            }

            ui.separator();
            ui.heading("AOB Scan");
            ui.horizontal(|ui| {
                if ui.button("Scan").clicked() {
                    let scans: Vec<(usize, Vec<Option<u8>>)> = self
                        .aob_scans
                        .iter()
                        .enumerate()
                        .filter_map(|(i, s)| {
                            let p = trainlab_core::aob::parse(&s.pattern);
                            if p.is_empty() {
                                None
                            } else {
                                Some((i, p))
                            }
                        })
                        .collect();
                    for (i, pattern) in scans {
                        let result = match self.request(&Request::ScanAob {
                            pattern,
                            start: None,
                            end: None,
                        }) {
                            Some(Response::ScanAob { matches }) => {
                                let shown: Vec<String> = matches
                                    .iter()
                                    .take(20)
                                    .map(|m| format!("0x{m:x}"))
                                    .collect();
                                format!("{} matches: {}", matches.len(), shown.join(", "))
                            }
                            Some(Response::Error { message }) => message,
                            _ => "no response".into(),
                        };
                        if let Some(scan) = self.aob_scans.get_mut(i) {
                            scan.result = result;
                        }
                    }
                }
                if ui.button("+").clicked() {
                    self.aob_scans.push(AobScan::default());
                }
            });
            for scan in self.aob_scans.iter_mut() {
                ui.horizontal(|ui| {
                    ui.label("Pattern:");
                    ui.text_edit_singleline(&mut scan.pattern);
                });
                ui.label(&scan.result);
            }

            ui.separator();
            ui.heading("Regions");
            if ui.button("List regions").clicked() {
                match self.request(&Request::ListRegions) {
                    Some(Response::ListRegions { regions }) => {
                        self.regions = regions;
                        self.log(format!("listed {} regions", self.regions.len()));
                    }
                    Some(Response::Error { message }) => self.log(message),
                    _ => {}
                }
            }
            egui::ScrollArea::vertical()
                .max_height(200.0)
                .show(ui, |ui| {
                    for r in &self.regions {
                        let perms = format!(
                            "{}{}{}",
                            if r.readable { "r" } else { "-" },
                            if r.writable { "w" } else { "-" },
                            if r.executable { "x" } else { "-" }
                        );
                        ui.monospace(format!(
                            "0x{:016x} - 0x{:016x}  {}  {}",
                            r.start,
                            r.end,
                            perms,
                            r.name.as_deref().unwrap_or("")
                        ));
                    }
                });

            ui.separator();
            ui.heading("Log");
            egui::ScrollArea::vertical()
                .max_height(120.0)
                .show(ui, |ui| {
                    for line in &self.log {
                        ui.monospace(line);
                    }
                });
        });
    }
}

fn parse_addr(s: &str) -> Result<u64, std::num::ParseIntError> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
    } else {
        u64::from_str_radix(s, 16)
    }
}

fn parse_len(s: &str) -> Option<usize> {
    s.trim().parse::<usize>().ok()
}

/// Parse a value string as either a hex byte string ("48 8B 05") or a decimal
/// integer (which becomes a little-endian u64).
fn parse_bytes(s: &str) -> Vec<u8> {
    let s = s.trim();
    if s.is_empty() {
        return Vec::new();
    }
    // If it looks like a space-separated hex byte string, parse that.
    if s.contains(' ') || s.contains("0x") {
        let toks: Vec<&str> = s.split_whitespace().collect();
        if toks.iter().all(|t| t.len() <= 2 || t.starts_with("0x")) {
            let mut out = Vec::new();
            for t in toks {
                let t = t.strip_prefix("0x").unwrap_or(t);
                if let Ok(b) = u8::from_str_radix(t, 16) {
                    out.push(b);
                }
            }
            return out;
        }
    }
    // Otherwise treat as a decimal integer -> little-endian u64.
    if let Ok(v) = s.parse::<u64>() {
        return v.to_le_bytes().to_vec();
    }
    Vec::new()
}

fn hexdump(data: &[u8]) -> String {
    let mut out = String::new();
    for (i, b) in data.iter().enumerate() {
        if i > 0 && i % 16 == 0 {
            out.push('\n');
        }
        out.push_str(&format!("{b:02x} "));
    }
    out
}
