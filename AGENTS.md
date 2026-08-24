# Agent Workflow: Windows Release Build & Steam Deck / Machine Deployment

This guide documents the procedures for compiling `trainlab` Windows release binaries (`trainlab-gui.exe` and `trainlab_inject.dll`) and deploying them to target Steam OS devices (Steam Deck & Steam Machine) over SSH/SCP.

---

## 1. Building Windows Release Binaries

To build release-optimized PE binaries (`.exe` and `.dll`) targeting 64-bit Windows (for execution under Wine/Proton):

```bash
cargo build --release --target x86_64-pc-windows-gnu --package trainlab-gui --package trainlab-inject
```

### Build Artifact Locations
- **GUI Application**: `target/x86_64-pc-windows-gnu/release/trainlab-gui.exe`
> [!IMPORTANT]
> **Build Synchronicity Rule**: ALWAYS wait for `cargo build --release` to completely finish execution before invoking `scp` to deploy binaries. Never launch `scp` while a background build task is still running.

---

## 2. Deploying to Steam Deck & Steam Machine via SCP

### Target Connection Info
- **Default User**: `deck`
- **Steam Deck IP**: `192.168.254.27` (or `deck@steamdeck.local`)
- **Steam Machine IP**: `192.168.254.143`
- **Target Folder**: `~/Documents/Trainers/Trainlab/`

### Copying Binaries & Launch Scripts

Use `scp` to transfer the release artifacts and launcher script to the target devices:

#### Deploy to Steam Deck:
```bash
scp target/x86_64-pc-windows-gnu/release/trainlab-gui.exe \
    target/x86_64-pc-windows-gnu/release/trainlab_inject.dll \
    scripts/launch.sh \
    deck@192.168.254.27:~/Documents/Trainers/Trainlab/
ssh deck@192.168.254.27 "chmod +x ~/Documents/Trainers/Trainlab/launch.sh"
```

#### Deploy to Steam Machine:
```bash
scp target/x86_64-pc-windows-gnu/release/trainlab-gui.exe \
    target/x86_64-pc-windows-gnu/release/trainlab_inject.dll \
    scripts/launch.sh \
    deck@192.168.254.143:~/Documents/Trainers/Trainlab/
ssh deck@192.168.254.143 "chmod +x ~/Documents/Trainers/Trainlab/launch.sh"
```


---

## 3. Remote Maintenance & Backup Cleanup

Clean up backup directories on target devices:

```bash
ssh deck@192.168.254.27 "rm -rf ~/Documents/Trainers/Trainlab/backup-*"
ssh deck@192.168.254.143 "rm -rf ~/Documents/Trainers/Trainlab/backup-*"
```

Verify deployment:

```bash
ssh deck@192.168.254.27 "ls -la ~/Documents/Trainers/Trainlab"
ssh deck@192.168.254.143 "ls -la ~/Documents/Trainers/Trainlab"
```
