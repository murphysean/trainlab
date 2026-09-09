use anyhow::{Context, Result, bail};
use clap::Parser;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Parser, Debug)]
#[command(
    name = "trainlab-release",
    about = "Compiles, standardizes names, and preps a unified release directory for Trainlab"
)]
struct Args {
    /// Output release directory (default: target/release-dist)
    #[arg(long, default_value = "target/release-dist")]
    out_dir: PathBuf,

    /// Also copy prepared artifacts to local mirror (~/Documents/Trainers/Trainlab)
    #[arg(long, default_value_t = true)]
    sync_mirror: bool,

    /// Also deploy to target devices (Steam Deck & Steam Machine) via scp
    #[arg(long)]
    deploy: bool,

    /// Skip building and only package existing binaries
    #[arg(long)]
    skip_build: bool,
}

fn run_cmd(cmd: &str, args: &[&str]) -> Result<()> {
    println!(
        "\x1b[1;34m[release]\x1b[0m Running: {} {}",
        cmd,
        args.join(" ")
    );
    let status = Command::new(cmd)
        .args(args)
        .status()
        .with_context(|| format!("failed to execute {cmd}"))?;
    if !status.success() {
        bail!("command failed with status: {status}");
    }
    Ok(())
}

fn copy_artifact(src: &Path, dst: &Path, make_executable: bool) -> Result<()> {
    if !src.exists() {
        bail!("source artifact does not exist: {}", src.display());
    }
    fs::copy(src, dst)
        .with_context(|| format!("failed copying {} -> {}", src.display(), dst.display()))?;
    if make_executable {
        let mut perms = fs::metadata(dst)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(dst, perms)?;
    }
    println!("  -> Packaged: \x1b[1;32m{}\x1b[0m", dst.display());
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("failed to find workspace root");

    std::env::set_current_dir(root)?;

    if !args.skip_build {
        println!(
            "\x1b[1;36m=== 1. Building Native Linux Targets (trainlab, trainlab.so) ===\x1b[0m"
        );
        run_cmd(
            "cargo",
            &[
                "build",
                "--release",
                "-p",
                "trainlab-gui",
                "-p",
                "trainlab-inject",
            ],
        )?;

        println!(
            "\x1b[1;36m=== 2. Cross-compiling Windows Targets (trainlab.exe, trainlab.dll) ===\x1b[0m"
        );
        run_cmd(
            "cargo",
            &[
                "build",
                "--release",
                "--target",
                "x86_64-pc-windows-gnu",
                "-p",
                "trainlab-gui",
                "-p",
                "trainlab-inject",
            ],
        )?;
    }

    let dist_dir = if args.out_dir.is_absolute() {
        args.out_dir
    } else {
        root.join(&args.out_dir)
    };

    println!(
        "\x1b[1;36m=== 3. Packaging Artifacts into {} ===\x1b[0m",
        dist_dir.display()
    );
    fs::create_dir_all(&dist_dir)?;

    // 1. trainlab <- linux executable
    copy_artifact(
        &root.join("target/release/trainlab-gui"),
        &dist_dir.join("trainlab"),
        true,
    )?;

    // 2. trainlab.exe <- windows exe
    copy_artifact(
        &root.join("target/x86_64-pc-windows-gnu/release/trainlab-gui.exe"),
        &dist_dir.join("trainlab.exe"),
        true,
    )?;

    // 3. trainlab.dll <- windows dll
    copy_artifact(
        &root.join("target/x86_64-pc-windows-gnu/release/trainlab_inject.dll"),
        &dist_dir.join("trainlab.dll"),
        false,
    )?;

    // 4. trainlab.so <- linux so
    copy_artifact(
        &root.join("target/release/libtrainlab_inject.so"),
        &dist_dir.join("trainlab.so"),
        true,
    )?;

    // Also include launch.sh and config.yaml
    if root.join("scripts/launch.sh").exists() {
        copy_artifact(
            &root.join("scripts/launch.sh"),
            &dist_dir.join("launch.sh"),
            true,
        )?;
    }
    if root.join("config.yaml").exists() {
        copy_artifact(
            &root.join("config.yaml"),
            &dist_dir.join("config.yaml"),
            false,
        )?;
    }

    println!("\n\x1b[1;32m[release] Release directory successfully prepared!\x1b[0m");
    for entry in fs::read_dir(&dist_dir)? {
        let entry = entry?;
        let meta = entry.metadata()?;
        println!(
            "  {:20} ({:>10} bytes)",
            entry.file_name().to_string_lossy(),
            meta.len()
        );
    }

    if args.sync_mirror
        && let Some(home) = std::env::var_os("HOME")
    {
        let mirror = PathBuf::from(home).join("Documents/Trainers/Trainlab");
        fs::create_dir_all(&mirror)?;
        println!(
            "\n\x1b[1;36m=== 4. Syncing to Local Mirror ({}) ===\x1b[0m",
            mirror.display()
        );
        for item in &[
            "trainlab",
            "trainlab.exe",
            "trainlab.dll",
            "trainlab.so",
            "launch.sh",
            "config.yaml",
        ] {
            let src = dist_dir.join(item);
            let dst = mirror.join(item);
            if src.exists() {
                let is_exe = item.ends_with(".exe") || item == &"trainlab" || item.ends_with(".sh");
                copy_artifact(&src, &dst, is_exe)?;
            }
        }
    }

    if args.deploy {
        println!("\n\x1b[1;36m=== 5. Deploying to Remote Devices ===\x1b[0m");
        let targets = ["192.168.254.27", "192.168.254.143"];
        for ip in &targets {
            println!("Deploying to deck@{}...", ip);
            let files = [
                dist_dir.join("trainlab"),
                dist_dir.join("trainlab.exe"),
                dist_dir.join("trainlab.dll"),
                dist_dir.join("trainlab.so"),
                dist_dir.join("launch.sh"),
            ];
            let mut scp_args = Vec::new();
            for f in &files {
                if f.exists() {
                    scp_args.push(f.to_string_lossy().to_string());
                }
            }
            let dest = format!("deck@{ip}:~/Documents/Trainers/Trainlab/");
            scp_args.push(dest);

            let str_args: Vec<&str> = scp_args.iter().map(|s| s.as_str()).collect();
            if let Err(e) = run_cmd("scp", &str_args) {
                eprintln!("\x1b[1;33m[warn]\x1b[0m Remote deploy to {ip} failed: {e}");
            } else {
                let chmod_cmd = "chmod +x ~/Documents/Trainers/Trainlab/trainlab ~/Documents/Trainers/Trainlab/trainlab.exe ~/Documents/Trainers/Trainlab/launch.sh 2>/dev/null || true";
                let _ = run_cmd("ssh", &[&format!("deck@{ip}"), chmod_cmd]);
                println!("\x1b[1;32m[ok]\x1b[0m Successfully deployed to {ip}");
            }
        }
    }

    Ok(())
}
