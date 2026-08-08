//! # trainlab-scanner
//!
//! A CLI memory hunting/scanning tool for digging into a game process. This
//! is the "scanmem / GameConqueror" style tool, but geared toward finding
//! anchors for code caves and hooks.
//!
//! Subcommands:
//!
//! - `list` — list processes (find the game's PID).
//! - `regions <pid>` — list readable memory regions of a process.
//! - `aob <pid> <pattern>` — scan a process's readable memory for an AOB
//!   pattern and print matching addresses.
//! - `read <pid> <address> <len>` — dump bytes at an address.
//! - `write <pid> <address> <hex>` — write bytes at an address.
//! - `scan <pid> <value>` — interactive value scan (first scan).
//! - `next <pid> <value>` — refine a previous value scan.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use trainlab_core::memory::{LinuxProcess, ProcessMemory};
use trainlab_core::process;

#[derive(Parser)]
#[command(name = "trainlab-scan", about = "Memory hunting/scanning for game training")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List processes to find the game's PID.
    List,
    /// List readable memory regions of a process.
    Regions { pid: i32 },
    /// Scan a process's readable memory for an AOB pattern.
    Aob {
        pid: i32,
        /// Pattern like "48 8B 05 ?? ?? ?? ??"
        pattern: String,
    },
    /// Dump bytes at an address.
    Read {
        pid: i32,
        address: String,
        len: usize,
    },
    /// Write bytes at an address.
    Write {
        pid: i32,
        address: String,
        /// Hex bytes, e.g. "90 90 90" or "0x909090"
        hex: String,
    },
    /// Interactive value scan (first scan).
    Scan { pid: i32, value: String },
    /// Refine a previous value scan.
    Next { pid: i32, value: String },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    match cli.command {
        Command::List => cmd_list(),
        Command::Regions { pid } => cmd_regions(pid),
        Command::Aob { pid, pattern } => cmd_aob(pid, &pattern),
        Command::Read { pid, address, len } => cmd_read(pid, &address, len),
        Command::Write { pid, address, hex } => cmd_write(pid, &address, &hex),
        Command::Scan { pid, value } => cmd_scan(pid, &value),
        Command::Next { pid, value } => cmd_next(pid, &value),
    }
}

fn cmd_list() -> Result<()> {
    let procs = process::list();
    println!("{:<8}  {}", "PID", "NAME");
    for p in procs {
        println!("{:<8}  {}", p.pid, p.name);
    }
    Ok(())
}

fn cmd_regions(pid: i32) -> Result<()> {
    let proc = LinuxProcess::new(pid);
    let regions = proc.regions().context("failed to read regions")?;
    println!("{:<18} {:<18}  {:<4}  {}", "START", "END", "PERMS", "NAME");
    for r in regions {
        if !r.readable {
            continue;
        }
        let perms = format!(
            "{}{}{}",
            if r.readable { "r" } else { "-" },
            if r.writable { "w" } else { "-" },
            if r.executable { "x" } else { "-" }
        );
        println!(
            "0x{:016x} 0x{:016x}  {:<4}  {}",
            r.start,
            r.end,
            perms,
            r.name.as_deref().unwrap_or("")
        );
    }
    Ok(())
}

fn cmd_aob(pid: i32, pattern: &str) -> Result<()> {
    let pat = trainlab_core::aob::parse(pattern);
    if pat.is_empty() {
        bail!("empty or invalid pattern");
    }
    let proc = LinuxProcess::new(pid);
    let regions = proc.regions().context("failed to read regions")?;
    let mut total = 0usize;
    for r in regions {
        if !r.readable {
            continue;
        }
        let len = r.len() as usize;
        if len == 0 {
            continue;
        }
        let buf = match proc.read(r.start, len) {
            Ok(b) => b,
            Err(_) => continue, // region may have changed; skip
        };
        for off in trainlab_core::aob::find_all(&buf, &pat) {
            let addr = r.start + off as u64;
            println!("0x{addr:016x}  {}", r.name.as_deref().unwrap_or(""));
            total += 1;
        }
    }
    eprintln!("{} match(es)", total);
    Ok(())
}

fn cmd_read(pid: i32, address: &str, len: usize) -> Result<()> {
    let addr = parse_addr(address)?;
    let proc = LinuxProcess::new(pid);
    let data = proc.read(addr, len).context("read failed")?;
    hexdump(addr, &data);
    Ok(())
}

fn cmd_write(pid: i32, address: &str, hex: &str) -> Result<()> {
    let addr = parse_addr(address)?;
    let data = parse_hex(hex)?;
    let proc = LinuxProcess::new(pid);
    let n = proc.write(addr, &data).context("write failed")?;
    println!("wrote {n} bytes to 0x{addr:x}");
    Ok(())
}

/// A simple in-memory "previous scan" store for the interactive scan/next
/// workflow. In a real tool this would persist across invocations; here we
/// keep it in-process for the demo.
fn cmd_scan(pid: i32, value: &str) -> Result<()> {
    let target = parse_value(value)?;
    let proc = LinuxProcess::new(pid);
    let regions = proc.regions().context("failed to read regions")?;
    let mut matches = Vec::new();
    for r in regions {
        if !r.readable || r.writable {
            continue; // focus on stable, non-writable regions for anchors
        }
        let len = r.len() as usize;
        if len == 0 {
            continue;
        }
        let buf = match proc.read(r.start, len) {
            Ok(b) => b,
            Err(_) => continue,
        };
        for (i, chunk) in buf.chunks_exact(8).enumerate() {
            let v = u64::from_le_bytes(chunk.try_into().unwrap());
            if v == target {
                matches.push(r.start + (i * 8) as u64);
            }
        }
    }
    println!("{} match(es)", matches.len());
    for m in matches.iter().take(50) {
        println!("0x{m:016x}");
    }
    Ok(())
}

fn cmd_next(pid: i32, value: &str) -> Result<()> {
    // Placeholder: a real implementation would re-scan the previous match set.
    let _ = (pid, value);
    bail!("`next` requires a persistent match set; use `scan` then refine in a future version")
}

fn parse_addr(s: &str) -> Result<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).context("invalid hex address")
    } else {
        u64::from_str_radix(s, 16).context("invalid address (use hex, e.g. 0x7f00)")
    }
}

fn parse_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    let s = s.replace(' ', "");
    if s.len() % 2 != 0 {
        bail!("hex string must have even length");
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16).context("invalid hex byte")?;
        out.push(byte);
    }
    Ok(out)
}

fn parse_value(s: &str) -> Result<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).context("invalid hex value")
    } else {
        s.parse::<u64>().context("invalid value")
    }
}

fn hexdump(start: u64, data: &[u8]) {
    for (i, chunk) in data.chunks(16).enumerate() {
        let addr = start + (i * 16) as u64;
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
            .collect();
        println!("0x{addr:016x}  {:<48}  {}", hex.join(" "), ascii);
    }
}
