# Agent Workflow: Windows Release Build & SteamOS Device Deployment

This guide documents the procedures for compiling `trainlab` Windows release binaries (`trainlab-gui.exe` and `trainlab_inject.dll`) and deploying them to target SteamOS devices (Steam Deck & Steam Machine) over SSH/SCP.

> [!NOTE]
> **Local Environment Overrides**: If `AGENTS.local.md` exists in the repository root, agents should inspect it for user-specific device IPs, target SSH hosts, and local configuration paths.

---

## 1. Building Windows Release Binaries

To build release-optimized PE binaries (`.exe` and `.dll`) targeting 64-bit Windows (for execution under Wine/Proton):

```bash
cargo build --release --target x86_64-pc-windows-gnu --package trainlab-gui --package trainlab-inject
```

### Build Artifact Locations
- **GUI Application**: `target/x86_64-pc-windows-gnu/release/trainlab-gui.exe`
- **Injected DLL**: `target/x86_64-pc-windows-gnu/release/trainlab_inject.dll`

> [!IMPORTANT]
> **Build Synchronicity Rule**: ALWAYS wait for `cargo build --release` to completely finish execution before invoking `scp` to deploy binaries. Never launch `scp` while a background build task is still running.

---

## 1b. Deploying Locally (this machine) — mirror directory

The target directory structure is mirrored **locally** on this workstation at
`~/Documents/Trainers/Trainlab/` (the same layout as on target devices). Keep
this local copy in sync with the release artifacts — it is the canonical
reference and the fallback whenever a remote device is unreachable:

```bash
mkdir -p ~/Documents/Trainers/Trainlab
cp target/x86_64-pc-windows-gnu/release/trainlab-gui.exe \
    target/x86_64-pc-windows-gnu/release/trainlab_inject.dll \
    ~/Documents/Trainers/Trainlab/
chmod +x ~/Documents/Trainers/Trainlab/trainlab-gui.exe
# verify MD5s match between the mirror and the build artifacts
```

---

## 2. Deploying to Steam Deck / SteamOS Devices via SCP

### Target Connection Configuration
Set target environment variables or configure your SSH alias:
- **Default User**: `deck` (or `$TARGET_USER`)
- **Device IP / Host**: `<STEAM_DECK_IP>` / `deck@steamdeck.local`
- **Target Directory**: `~/Documents/Trainers/Trainlab/`

### Copying Binaries & Launch Scripts

Use `scp` to transfer the release artifacts and launcher script to the target device:

```bash
scp target/x86_64-pc-windows-gnu/release/trainlab-gui.exe \
    target/x86_64-pc-windows-gnu/release/trainlab_inject.dll \
    scripts/launch.sh \
    deck@<DEVICE_IP>:~/Documents/Trainers/Trainlab/
ssh deck@<DEVICE_IP> "chmod +x ~/Documents/Trainers/Trainlab/launch.sh"
```

---

## 3. Remote Maintenance & Verification

Verify deployment files on the remote device:

```bash
ssh deck@<DEVICE_IP> "ls -la ~/Documents/Trainers/Trainlab"
```
