# Remote Forensic Imager (RFI)

![CI](https://github.com/Futhark1393/Remote-Forensic-Imager/actions/workflows/python-ci.yml/badge.svg)

**Author:** Futhark1393 · **Version:** 3.1.0 · **License:** MIT

Remote Forensic Imager (RFI) is a **case-first remote disk acquisition framework** built with **Python + PyQt6**. It enforces structured forensic workflows through an explicit session state machine, generates a cryptographically hash-chained audit trail (JSONL), and produces TXT/PDF forensic reports.

---

# Installation

## Quick Install (Recommended)

~~~bash
git clone https://github.com/Futhark1393/Remote-Forensic-Imager.git
cd Remote-Forensic-Imager
sudo bash RFI_install.sh
~~~

The installer:
- Detects your distro (Fedora/RHEL or Debian/Ubuntu/Kali) and installs system dependencies
- Downloads and compiles **libewf** (E01 format support)
- Creates a Python **virtual environment** (`.venv/`)
- Installs the RFI package inside the venv
- Symlinks `rfi`, `rfi-acquire`, `rfi-verify` → `/usr/local/bin` (available system-wide)
- Creates an application menu shortcut

### Install Options

| Flag | Effect |
|------|--------|
| *(none)* | Full install with E01 support |
| `--no-ewf` | Skip libewf compilation (faster, RAW only) |
| `--with-aff4` | Also install `pyaff4` for AFF4 format support |

~~~bash
sudo bash RFI_install.sh --no-ewf        # fast install, RAW only
sudo bash RFI_install.sh --with-aff4     # full install + AFF4
~~~

After install, open a **new terminal** and:

~~~bash
rfi                  # Launch GUI
rfi-acquire --help   # Headless acquisition
rfi-verify --help    # Audit chain verification
~~~

## Manual Install

<details>
<summary>Click to expand manual install steps</summary>

### 1) Clone

~~~bash
git clone https://github.com/Futhark1393/Remote-Forensic-Imager.git
cd Remote-Forensic-Imager
~~~

### 2) System Dependencies

**Ubuntu / Debian / Kali**

~~~bash
sudo apt update && sudo apt install -y \
  libegl1 libgl1 libglib2.0-0 libxkbcommon0 libxkbcommon-x11-0 \
  libxcb1 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-randr0 \
  libxcb-render0 libxcb-render-util0 libxcb-shape0 libxcb-shm0 libxcb-sync1 \
  libxcb-xfixes0 libxcb-xinerama0 libxcb-xkb1 libxrender1 libxi6 \
  libsm6 libice6 libfontconfig1 libfreetype6
~~~

**Fedora**

~~~bash
sudo dnf install -y qt6-qtbase qt6-qtbase-gui mesa-libEGL mesa-libGL
~~~

### 3) Python Virtual Environment

~~~bash
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .
~~~

### 4) Optional: E01 Support

~~~bash
sudo apt install -y libewf2 python3-libewf   # Debian/Ubuntu/Kali
# or
pip install libewf-python
~~~

### 5) Optional: AFF4 Support

~~~bash
pip install pyaff4
# or
pip install -e ".[aff4]"
~~~

</details>

---

# Running

## GUI Mode

~~~bash
rfi
# or without system install:
python main_qt6.py
~~~

## CLI Mode (Headless)

~~~bash
rfi-acquire \
  --ip 10.0.0.1 --user ubuntu --key ~/.ssh/key.pem \
  --disk /dev/sda --output-dir ./evidence \
  --case 2026-001 --examiner "Investigator" \
  --format RAW --verify --safe-mode
~~~

---

# Interface Preview

| Case Wizard | Main UI | Acquisition |
|:-----------:|:-------:|:-----------:|
| ![Case Wizard](screenshots/case_wizard.png) | ![Main UI](screenshots/main_ui_idle.png) | ![Acquisition](screenshots/acquisition_running.png) |

---

# Engineering Documentation

A detailed engineering write-up covering architecture decisions, audit trail hash-chain model, and threat considerations:

👉 https://kemalsebzeci-site.vercel.app/blog/rfi-architecture

---

# Core Capabilities

## Session State Machine

Forensic workflow ordering enforced through an explicit state machine:

~~~text
NEW → CONTEXT_BOUND → ACQUIRING → VERIFYING → SEALED → DONE
~~~

Illegal transitions raise `SessionStateError` and halt operation.

## Tamper-Evident Audit Logging (JSONL)

- Cryptographic chaining (`prev_hash → entry_hash`)
- Forced disk flush (`fsync`) per record
- Optional **Ed25519 digital signature** (detached `.sig` file)
- **Optional SIEM/Syslog forwarding** (RFC 5424 UDP/TCP, CEF mode)

## Acquisition & Integrity

- SSH-based acquisition (pure-Python, headless-testable)
- On-the-fly dual hashing (MD5 + SHA-256)
- Optional post-acquisition remote SHA-256 verification
- Safe Mode (`conv=noerror,sync`), write-blocker, throttling
- Automatic retry on connection loss (up to 3 retries with resume)
- Output formats: **RAW**, **E01**, **AFF4** (optional)

---

# CLI Tooling

## `rfi-acquire` — Headless Acquisition

All parameters:

| Parameter | Description |
|-----------|-------------|
| `--ip`, `--user`, `--key` | SSH connection details (required) |
| `--disk` | Target block device (required) |
| `--output-dir` | Evidence output directory (required) |
| `--case`, `--examiner` | Case metadata (required) |
| `--format RAW\|E01\|AFF4` | Evidence format (default: RAW) |
| `--verify` | Post-acquisition remote SHA-256 check |
| `--safe-mode` | `conv=noerror,sync` (default: on) |
| `--write-blocker` | Software write-blocker |
| `--throttle N` | Bandwidth limit in MB/s |
| `--signing-key PATH` | Ed25519 key for audit trail signing |

### Triage Parameters

| Parameter | Description |
|-----------|-------------|
| `--triage` | Enable live triage before acquisition |
| `--no-triage-network` | Skip network state collection |
| `--no-triage-processes` | Skip process list collection |
| `--triage-memory` | Collect memory metadata |
| `--no-hash-exes` | Skip per-process SHA-256 exe hashing |

### SIEM / Syslog Parameters

| Parameter | Description |
|-----------|-------------|
| `--siem-host HOST` | Syslog/SIEM server hostname or IP |
| `--siem-port PORT` | Syslog port (default: 514) |
| `--siem-protocol UDP\|TCP` | Protocol (default: UDP) |
| `--siem-cef` | CEF output instead of RFC 5424 |

Example with triage + SIEM:

~~~bash
rfi-acquire \
  --ip 10.0.0.1 --user ubuntu --key ~/.ssh/key.pem \
  --disk /dev/sda --output-dir ./evidence \
  --case 2026-001 --examiner "Investigator" \
  --triage --triage-memory \
  --siem-host 10.0.0.100 --siem-port 514 --siem-protocol TCP
~~~

## `rfi-verify` — Audit Chain Verification

~~~bash
rfi-verify AuditTrail_CASE_SESSION.jsonl
rfi-verify AuditTrail_CASE_SESSION.jsonl --pubkey rfi_signing.pub
rfi-verify AuditTrail_CASE_SESSION.jsonl --json   # machine-readable output
~~~

Exit codes: `0` = PASS · `2` = FAIL (tamper detected) · `1` = Error

## Generate Signing Keypair

~~~bash
python -c "from rfi.audit.signing import generate_signing_keypair; generate_signing_keypair('.')"
~~~

---

# Live Triage

Volatile evidence collected **before** acquisition. All operations are strictly **read-only** — nothing is written or loaded onto the target system.

| Module | Collects | Output |
|--------|----------|--------|
| Network | `ss`, ARP, routing, DNS | `NetworkState_<CASE>_<UTC>.txt` + `.json` |
| Processes | `ps aux` + per-exe SHA-256 | `ProcessList_<CASE>_<UTC>.txt` + `.json` |
| Memory | `/proc/meminfo`, modules, kcore stream | `MemoryState_<CASE>_<UTC>.json` |

> [!NOTE]
> RFI **never uploads kernel modules** to the target. LiME is only used if already loaded by an administrator before RFI connects.

---

# Architecture

~~~text
rfi/
├── cli/                        # Headless CLI tools
│   ├── acquire.py              # rfi-acquire (no Qt dependency)
│   └── verify.py               # rfi-verify (chain + sig verification)
├── triage/                     # Live triage collectors (read-only)
│   ├── orchestrator.py
│   ├── network.py
│   ├── processes.py
│   └── memory.py
├── ui/                         # Qt / GUI layer
│   ├── gui.py
│   └── workers.py
├── core/                       # Business logic (Qt-free, headless-testable)
│   ├── session.py              # Workflow state machine (NEW → DONE)
│   ├── hashing.py              # StreamHasher (MD5 + SHA-256)
│   ├── policy.py               # Write-blocker, dd command builder
│   └── acquisition/
│       ├── base.py             # AcquisitionEngine
│       ├── raw.py / ewf.py / aff4.py
│       └── verify.py
├── audit/                      # Tamper-evident logging + signing
│   ├── logger.py               # ForensicLogger (hash-chained JSONL)
│   ├── verify.py               # AuditChainVerifier
│   ├── signing.py              # Ed25519 key gen, sign, verify
│   └── syslog_handler.py       # RFC 5424 + CEF, UDP/TCP
└── report/
    └── report_engine.py        # TXT + PDF forensic reporting
~~~

---

# Output Artifacts

| File | Description |
|------|-------------|
| `evidence_<CASE>_<UTC>.raw` / `.E01` / `.aff4` | Disk image |
| `AuditTrail_<CASE>_<SESSION>.jsonl` | Tamper-evident audit log |
| `AuditTrail_<CASE>_<SESSION>.jsonl.sig` | Ed25519 detached signature |
| `Report_<CASE>_<UTC>.pdf` / `.txt` | Forensic report |
| `NetworkState_<CASE>_<UTC>.txt` / `.json` | Triage: network state |
| `ProcessList_<CASE>_<UTC>.txt` / `.json` | Triage: process list |
| `MemoryState_<CASE>_<UTC>.json` | Triage: memory metadata |

---

# Testing

~~~bash
python -m pytest tests/ -v
~~~

24 unit tests covering: session state machine, hashing, writing, dd command building, audit chain integrity, Ed25519 signing, report generation.

---

# License

MIT License — see [LICENSE](LICENSE)

**Author:** Futhark1393
