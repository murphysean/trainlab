# Agent Workflow: Windows Release Build & Steam Deck Deployment

This guide documents the procedures for compiling `trainlab` Windows release binaries (`trainlab-gui.exe` and `trainlab_inject.dll`) and deploying them to a target Steam Deck over SSH/SCP.

---

## 1. Building Windows Release Binaries

To build release-optimized PE binaries (`.exe` and `.dll`) targeting 64-bit Windows (for execution under Wine/Proton):

```bash
cargo build --release --target x86_64-pc-windows-gnu --package trainlab-gui --package trainlab-inject
```

### Build Artifact Locations
- **GUI Application**: `target/x86_64-pc-windows-gnu/release/trainlab-gui.exe`
- **Injected DLL**: `target/x86_64-pc-windows-gnu/release/trainlab_inject.dll`

---

## 2. Deploying to Steam Deck via SCP

### Steam Deck Connection Info
- **Default SSH User**: `deck`
- **Default IP**: `192.168.254.27` (or `deck@steamdeck.local` depending on mDNS resolution)
- **Target Folder**: `~/Documents/Trainers/Trainlab/`

### Copying Binaries

Use `scp` to transfer both built release artifacts over to the target directory:

```bash
scp target/x86_64-pc-windows-gnu/release/trainlab-gui.exe \
    target/x86_64-pc-windows-gnu/release/trainlab_inject.dll \
    deck@192.168.254.27:~/Documents/Trainers/Trainlab/
```

---

## 3. Remote Maintenance & Backup Cleanup

If temporary backup directories accumulate under the deployment directory on the Steam Deck, clean them up with:

```bash
ssh deck@192.168.254.27 "rm -rf ~/Documents/Trainers/Trainlab/backup-*"
```

Verify deployment:

```bash
ssh deck@192.168.254.27 "ls -la ~/Documents/Trainers/Trainlab"
```
