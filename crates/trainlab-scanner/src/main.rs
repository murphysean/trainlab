//! # trainlab-scanner
//!
//! A CLI memory hunting/scanning tool for digging into a game process. This
//! is the "scanmem / GameConqueror" style tool, but geared toward finding
//! anchors for code caves and hooks.
//!
//! **Linux-only.** This tool reads `/proc/pid/mem` and imports
//! `trainlab_core::memory::LinuxProcess` (a `#[cfg(unix)]` type), so it must
//! not be built for the Windows target. The `#[cfg(unix)]` guards below
//! prevent `cargo build --target x86_64-pc-windows-gnu` (whole workspace)
//! from failing on this crate: on non-unix targets the binary compiles to a
//! stub that reports it is Linux-only.
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

use anyhow::bail;

#[cfg(unix)]
use anyhow::{Context, Result};
#[cfg(unix)]
use clap::{Parser, Subcommand};
#[cfg(unix)]
use trainlab_core::process;
#[cfg(unix)]
use trainlab_core::memory::{LinuxProcess, ProcessMemory};

#[cfg(unix)]
#[derive(Parser)]
#[command(name = "trainlab-scan", about = "Memory hunting/scanning for game training")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[cfg(unix)]
#[derive(Subcommand)]
enum WineCmd {
    /// List processes that are part of a Wine/Proton tree.
    List,
    /// Check whether a specific PID is a Wine/Proton process.
    Check { pid: i32 },
    /// List a process's memory regions tagged by kind (heap/stack/image/mapped).
    Regions { pid: i32 },
}

#[cfg(unix)]
#[derive(Subcommand)]
enum Command {
    /// List processes to find the game's PID.
    List,
    /// List readable memory regions of a process, tagged by kind.
    Regions { pid: i32 },
    /// Wine/Proton helpers: detect wine processes and tag regions.
    Wine {
        #[command(subcommand)]
        cmd: WineCmd,
    },
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
    /// First value scan.
    Scan {
        pid: i32,
        /// Value type: i32, u32, f32, or f64.
        #[arg(long, default_value = "i32")]
        r#type: String,
        /// Value to scan for (decimal, or 0x for hex).
        value: String,
    },
    /// Refine a previous value scan.
    Next {
        pid: i32,
        /// Operation: unchanged, changed, increased, decreased, exact, or range.
        op: String,
        /// For exact: the value. For range: "min,max". Omit for change ops.
        value: Option<String>,
    },
}

/// Non-unix stub: the scanner is Linux-only, so on other targets we just
/// report that and exit. This keeps the whole-workspace Windows build green.
#[cfg(not(unix))]
fn main() -> anyhow::Result<()> {
    bail!("trainlab-scanner is Linux-only (reads /proc/pid/mem); not available on this target")
}

#[cfg(unix)]
fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    match cli.command {
        Command::List => cmd_list(),
        Command::Regions { pid } => cmd_regions(pid),
        Command::Aob { pid, pattern } => cmd_aob(pid, &pattern),
        Command::Read { pid, address, len } => cmd_read(pid, &address, len),
        Command::Write { pid, address, hex } => cmd_write(pid, &address, &hex),
        Command::Scan { pid, r#type, value } => cmd_scan(pid, &r#type, &value),
        Command::Next { pid, op, value } => cmd_next(pid, &op, value.as_deref()),
        Command::Wine { cmd } => match cmd {
            WineCmd::List => cmd_wine_list(),
            WineCmd::Check { pid } => cmd_wine_check(pid),
            WineCmd::Regions { pid } => cmd_wine_regions(pid),
        },
    }
}

#[cfg(unix)]
fn cmd_wine_list() -> Result<()> {
    use trainlab_core::wine::is_wine_process;
    println!("{:<8}  {:<24}  {}", "PID", "NAME", "WINE?");
    for p in process::list() {
        let wine = if is_wine_process(p.pid) { "yes" } else { "" };
        println!("{:<8}  {:<24}  {}", p.pid, p.name, wine);
    }
    Ok(())
}

#[cfg(unix)]
fn cmd_wine_check(pid: i32) -> Result<()> {
    use trainlab_core::wine::is_wine_process;
    let wine = is_wine_process(pid);
    println!(
        "PID {pid} is {}a Wine/Proton process",
        if wine { "" } else { "NOT " }
    );
    Ok(())
}

#[cfg(unix)]
fn cmd_wine_regions(pid: i32) -> Result<()> {
    use trainlab_core::wine::{regions_of_kind, tag_regions, RegionKind};
    let tagged = tag_regions(pid).context("failed to read /proc/pid/maps")?;
    println!("{:<18} {:<18}  {:<4}  {:<8}  {}", "START", "END", "PERMS", "KIND", "NAME");
    for t in &tagged {
        if !t.region.readable {
            continue;
        }
        let perms = format!(
            "{}{}{}",
            if t.region.readable { "r" } else { "-" },
            if t.region.writable { "w" } else { "-" },
            if t.region.executable { "x" } else { "-" }
        );
        println!(
            "0x{:016x} 0x{:016x}  {:<4}  {:<8}  {}",
            t.region.start,
            t.region.end,
            perms,
            t.kind.label(),
            t.region.name.as_deref().unwrap_or("")
        );
    }
    // Summary of scan-worthy (heap) regions.
    let heap_total: u64 = regions_of_kind(&tagged, RegionKind::Heap)
        .map(|t| t.region.len())
        .sum();
    eprintln!("{} heap region(s), {heap_total} bytes total", regions_of_kind(&tagged, RegionKind::Heap).count());
    Ok(())
}

#[cfg(unix)]
fn cmd_list() -> Result<()> {
    let procs = process::list();
    println!("{:<8}  {}", "PID", "NAME");
    for p in procs {
        println!("{:<8}  {}", p.pid, p.name);
    }
    Ok(())
}

#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
fn cmd_read(pid: i32, address: &str, len: usize) -> Result<()> {
    let addr = parse_addr(address)?;
    let proc = LinuxProcess::new(pid);
    let data = proc.read(addr, len).context("read failed")?;
    hexdump(addr, &data);
    Ok(())
}

#[cfg(unix)]
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
#[cfg(unix)]
fn cmd_scan(pid: i32, type_str: &str, value: &str) -> Result<()> {
    use trainlab_core::scan::{Scan, ScanOp};
    use trainlab_core::wine::scan_regions;

    let vt = parse_value_type(type_str)?;
    // Parse the value as the chosen type's f64 representation.
    let target = parse_number_as_f64(value, vt)?;

    let proc = LinuxProcess::new(pid);
    // Scope the scan to private heap regions (the D5 approach), which are the
    // interesting scan targets and skip image/mapped/code.
    let regions = scan_regions(pid, trainlab_core::wine::ScanScope::Heap)
        .context("failed to scope regions")?;

    let mut scan = Scan::new(vt);
    scan.first_scan(&proc, &regions, ScanOp::Exact { value: target })
        .context("scan failed")?;
    save_state(pid, &scan)?;

    println!("{} match(es)", scan.len());
    for (addr, _) in scan.matches().iter().take(50) {
        println!("0x{addr:016x}");
    }
    Ok(())
}

#[cfg(unix)]
fn cmd_next(pid: i32, op: &str, value: Option<&str>) -> Result<()> {
    let mut scan = load_state(pid)?;
    let vt = scan.value_type();
    let scan_op = parse_op(op, value, vt)?;
    let proc = LinuxProcess::new(pid);
    let n = scan.refine(&proc, scan_op).context("refine failed")?;
    save_state(pid, &scan)?;
    println!("{} match(es)", n);
    for (addr, v) in scan.matches().iter().take(50) {
        println!("0x{addr:016x} = {v}");
    }
    Ok(())
}

/// Parse a value-type string into a [`ValueType`].
#[cfg(unix)]
fn parse_value_type(s: &str) -> Result<trainlab_core::scan::ValueType> {
    use trainlab_core::scan::ValueType;
    Ok(match s.to_lowercase().as_str() {
        "i32" => ValueType::I32,
        "u32" => ValueType::U32,
        "f32" => ValueType::F32,
        "i64" => ValueType::I64,
        "u64" => ValueType::U64,
        "f64" => ValueType::F64,
        "ptr" | "pointer" => ValueType::Ptr,
        other => bail!("unknown value type '{other}' (expected i32/u32/f32/i64/u64/f64/ptr)"),
    })
}

/// Parse a numeric literal into the `f64` domain appropriate for `vt`.
///
/// Handles `0x` hex and plain decimal. Floats accept a `.` or `e` exponent.
#[cfg(unix)]
fn parse_number_as_f64(s: &str, vt: trainlab_core::scan::ValueType) -> Result<f64> {
    let s = s.trim();
    match vt {
        trainlab_core::scan::ValueType::I32
        | trainlab_core::scan::ValueType::U32
        | trainlab_core::scan::ValueType::I64
        | trainlab_core::scan::ValueType::U64
        | trainlab_core::scan::ValueType::Ptr => {
            let n = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                u64::from_str_radix(hex, 16).context("invalid hex value")?
            } else {
                s.parse::<u64>().context("invalid value")?
            };
            Ok(n as f64)
        }
        trainlab_core::scan::ValueType::F32 | trainlab_core::scan::ValueType::F64 => {
            s.parse::<f64>().context("invalid float value")
        }
    }
}

/// Parse a `next` operation string into a [`ScanOp`].
#[cfg(unix)]
fn parse_op(op: &str, value: Option<&str>, vt: trainlab_core::scan::ValueType) -> Result<trainlab_core::scan::ScanOp> {
    use trainlab_core::scan::ScanOp;
    Ok(match op.to_lowercase().as_str() {
        "changed" => ScanOp::Changed,
        "unchanged" => ScanOp::Unchanged,
        "increased" => ScanOp::Increased,
        "decreased" => ScanOp::Decreased,
        "exact" => {
            let v = value.context("exact requires a value")?;
            ScanOp::Exact { value: parse_number_as_f64(v, vt)? }
        }
        "range" => {
            let v = value.context("range requires 'min,max'")?;
            let (min, max) = v
                .split_once(',')
                .context("range requires 'min,max'")?;
            ScanOp::Range {
                min: parse_number_as_f64(min, vt)?,
                max: parse_number_as_f64(max, vt)?,
            }
        }
        other => bail!("unknown op '{other}' (expected changed/unchanged/increased/decreased/exact/range)"),
    })
}

/// Path where a scan's persistent state is stored for a given PID.
#[cfg(unix)]
fn state_path(pid: i32) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("trainlab-scan-{pid}.bin"));
    p
}

/// Persist a scan's match set to a per-PID state file.
#[cfg(unix)]
fn save_state(pid: i32, scan: &trainlab_core::scan::Scan) -> Result<()> {
    let path = state_path(pid);
    let bytes = trainlab_core::protocol::encode(scan)?;
    std::fs::write(&path, bytes)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

/// Load a scan's match set from the per-PID state file, or error if none.
#[cfg(unix)]
fn load_state(pid: i32) -> Result<trainlab_core::scan::Scan> {
    let path = state_path(pid);
    if !path.exists() {
        bail!(
            "no scan state for PID {pid}; run `scan` first (state file: {})",
            path.display()
        );
    }
    let bytes = std::fs::read(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let scan: trainlab_core::scan::Scan = trainlab_core::protocol::decode(&bytes)?;
    Ok(scan)
}

#[cfg(unix)]
fn parse_addr(s: &str) -> Result<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).context("invalid hex address")
    } else {
        u64::from_str_radix(s, 16).context("invalid address (use hex, e.g. 0x7f00)")
    }
}

#[cfg(unix)]
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

#[cfg(unix)]


#[cfg(unix)]
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
