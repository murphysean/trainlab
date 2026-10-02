# Agent Workflow: Unified Release Build & Device Deployment

This guide documents the procedures for compiling `trainlab` release binaries, packaging them with standardized names into `target/release-dist/`, and deploying them to target SteamOS devices (Steam Deck & Steam Machine) over SSH/SCP.

---

## 1. Unified Naming Convention

All release artifacts share the clean, unified `trainlab` naming scheme:

| Artifact Name | Platform | Description |
| :--- | :--- | :--- |
| **`trainlab`** | Linux | Native ELF GUI & Memory Control Process |
| **`trainlab.exe`** | Windows | PE32+ GUI executable (executed under Wine/Proton) |
| **`trainlab.dll`** | Windows | PE32+ dynamic library injected into Windows games |
| **`trainlab.so`** | Linux | ELF shared object injected via `LD_PRELOAD` into Linux games |

---

## 2. Preparing Releases & Deploying

We provide automated cargo commands via `.cargo/config.toml` that compile both native Linux and Windows targets, stage them into `target/release-dist/`, sync the local mirror, and deploy over SSH:

### A. Build & Package Release Directory:
```bash
cargo prep-release
# or: cargo dist
```
This compiles all targets, stages them in `target/release-dist/`, and synchronizes the local mirror at `~/Documents/Trainers/Trainlab/`.

### B. Build, Package & Deploy to Devices:
```bash
cargo deploy
```
This performs the full compilation, packages the clean release directory, syncs the local mirror, and uses `scp` to push `trainlab`, `trainlab.exe`, `trainlab.dll`, `trainlab.so`, and `launch.sh` directly to the configured targets:
- Steam Deck (`deck@192.168.0.32` / `192.168.254.27`)
- Steam Machine (`deck@192.168.0.30` / `192.168.254.143`)
- Steam Frame (`steamos@192.168.0.36`)

### C. Package/Deploy without Rebuilding:
```bash
cargo prep-release -- --skip-build
cargo prep-release -- --skip-build --deploy
```

---

## 3. Local Mirror Directory (`~/Documents/Trainers/Trainlab/`)

The target directory structure is mirrored locally at `~/Documents/Trainers/Trainlab/`.
The release tool automatically maintains this mirror:

```bash
ls -la ~/Documents/Trainers/Trainlab/
# trainlab, trainlab.exe, trainlab.dll, trainlab.so, launch.sh, config.yaml
```

---

## 3. Remote Maintenance & Verification

Verify deployment files on the remote device:

```bash
ssh deck@<DEVICE_IP> "ls -la ~/Documents/Trainers/Trainlab"
```
