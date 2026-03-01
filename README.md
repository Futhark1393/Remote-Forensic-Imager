# ForenXtract (FX)

![CI](https://github.com/Futhark1393/ForenXtract/actions/workflows/python-ci.yml/badge.svg)

**Author:** Kemal Sebzeci · **Version:** 3.6.0 · **License:** Apache-2.0

ForenXtract (FX) is a **case-first forensic disk acquisition framework** built with **Python + PyQt6**. It supports both **Live (Remote/SSH)** and **Dead (Local)** acquisition through a tabbed interface. It enforces structured forensic workflows through an explicit session state machine, generates a cryptographically hash-chained audit trail (JSONL), and produces TXT/PDF forensic reports.

---

## Changelog — v3.6.0

### New Features
| # | Feature | Module |
|---|---------|--------|
| 19 | **E01 metadata embedding (end-to-end)** — Case number, examiner name, description, and notes written into the E01 header. Visible in EnCase, Autopsy, FTK Imager. Configurable via GUI fields + CLI `--description` / `--notes`. | `ewf.py`, `base.py`, `dead.py`, `workers.py`, `acquire.py`, `gui.py` |
| 20 | **Scrollable left panel** — UI rebuilt from scratch with `QScrollArea`, consistent spacing, and fixed-width labels. No more squished fields on smaller screens. | `forensic_qt6.ui` |
| 21 | **E01 metadata group box** — GUI shows Description + Notes fields when E01 format is selected; auto-disabled for other formats. | `forensic_qt6.ui`, `gui.py` |

---

## Changelog — v3.5.0

### HIGH Severity Fixes
| # | Fix | Module |
|---|------|--------|
| 6 | **Bad sector error map** — unreadable sectors logged with offset/length/error, saved as `.error_map.json` | `dead.py` |
| 7 | **Output re-verification** — written RAW image re-read and SHA-256 compared (FTK Imager-style) | `base.py`, `dead.py` |
| 8 | **E01 metadata headers** — case number, examiner name, description, notes via `set_header_value()` | `ewf.py` |
| 9 | **RawWriter fsync** — `flush()` + `os.fsync()` on close to guarantee data persistence | `raw.py` |
| 10 | **Triage artifact integrity** — every JSON/TXT triage file SHA-256 hashed in the audit trail | `orchestrator.py` |

### MEDIUM Severity Fixes
| # | Fix | Module |
|---|------|--------|
| 11 | **CLI SIGINT handler** — graceful Ctrl+C stops engine, seals audit trail, exits cleanly | `acquire.py` |
| 12 | **Offline dashboard** — Plotly.js bundled inline (no CDN, air-gapped labs) | `dashboard.py` |
| 13 | **Version consolidation** — single source of truth `fx.__version__`, replaces all hardcoded strings | `__init__.py`, CLI, syslog |
| 14 | **IPv6 & hostname support** — GUI validates IPv4, IPv6, and hostnames | `validation.py` |
| 15 | **Evidence writer factory** — `create_evidence_writer()` eliminates if/elif duplication | `base.py` |
| 16 | **Shared validation module** — GUI business logic extracted to `fx.core.validation` | `validation.py` |
| 17 | **Per-session genesis entropy** — genesis block includes `session_id` + `os.urandom(16)` | `logger.py` |
| 18 | **Signing key passphrase** — private keys can be encrypted with `BestAvailableEncryption` | `signing.py` |

---

# Installation

## Quick Install (Recommended)

~~~bash
git clone https://github.com/Futhark1393/ForenXtract.git
cd ForenXtract
sudo bash FX_install.sh
~~~

The installer:
- Detects your distro (Fedora/RHEL or Debian/Ubuntu/Kali) and installs system dependencies
- Downloads and compiles **libewf** (E01 format support)
- Creates a Python **virtual environment** (`.venv/`)
- Installs the FX package inside the venv
- Symlinks `fx`, `fx-acquire`, `fx-verify` → `/usr/local/bin` (available system-wide)
- Creates an application menu shortcut

### Install Options

| Flag | Effect |
|------|--------|
| *(none)* | Full install with E01 support |
| `--no-ewf` | Skip libewf compilation (faster, RAW only) |
| `--with-aff4` | Also install `pyaff4` for AFF4 format support |
| `--with-lz4` | Also install `lz4` for compression support |

~~~bash
sudo bash FX_install.sh --no-ewf        # fast install, RAW only
sudo bash FX_install.sh --with-aff4     # full install + AFF4
sudo bash FX_install.sh --with-lz4      # full install + LZ4 compression
~~~

After install, open a **new terminal** and:

~~~bash
fx                  # Launch GUI
fx-acquire --help   # Headless acquisition
fx-verify --help    # Audit chain verification
~~~

## Manual Install

<details>
<summary>Click to expand manual install steps</summary>

### 1) Clone

~~~bash
git clone https://github.com/Futhark1393/ForenXtract.git
cd ForenXtract
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
fx
# or without system install:
python main_qt6.py
~~~

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| **F5** | Reset session & start new acquisition (requires no acquisition running) |

Once an acquisition completes, press **F5** to reset the session state machine and begin a new investigation without restarting the application.

## CLI Mode (Headless)

### Live Acquisition (Remote)

~~~bash
fx-acquire \
  --ip 10.0.0.1 --user ubuntu --key ~/.ssh/key.pem \
  --disk /dev/sda --output-dir ./evidence \
  --case 2026-001 --examiner "Investigator" \
  --format RAW --verify --safe-mode
~~~

### Dead Acquisition (Local)

~~~bash
fx-acquire --dead \
  --source /dev/sdb --output-dir ./evidence \
  --case 2026-001 --examiner "Investigator" \
  --format E01 --verify --write-blocker \
  --description "Suspect laptop HDD - Dell Latitude" \
  --notes "Seized under warrant #12345"
~~~

For **directory (logical) acquisition**, the source folder is archived via deterministic `tar` and streamed directly to the forensic image:

~~~bash
fx-acquire --dead \
  --source /mnt/usb/evidence_folder/ --output-dir ./evidence \
  --case 2026-001 --examiner "Investigator" \
  --format RAW --verify
~~~

---

# Interface Preview

## v3.4.0 — Tabbed GUI + Dead Acquisition

![ForenXtract v3.4.0 GUI](screenshots/main_ui_v340.png)

The GUI is now organized into a **QTabWidget** with two acquisition modes:

| Tab | Description |
|-----|-------------|
| **Live Acquisition (Remote)** | SSH-based remote disk imaging — target IP, SSH key, remote disk selection, live triage |
| **Dead Acquisition (Local)** | Local block-device or **folder** (logical) imaging — auto-detect via lsblk, source folder picker |

Shared sections below the tabs:

| # | Section | Description |
|---|---------|-------------|
| 1 | Case Identification | Case number + Examiner (shared across modes) |
| 2 | Acquisition Options | **Format dropdown** (RAW / **RAW+LZ4** / E01 / AFF4), **E01 Metadata** (Description + Notes — auto-enabled when E01 selected), Safe Mode, Verify, Write-Blocker, Throttle |
| 3 | Advanced | **Signing key** picker + **SIEM/Syslog** fields (host, port, UDP/TCP, CEF) |

> **Note:** The left panel is now wrapped in a `QScrollArea` — all fields remain accessible on smaller screens without squishing.

### Workflow Screens

| Case Wizard | Disk Discovery | Dead Acquisition Tab |
|:-----------:|:--------------:|:--------------------:|
| ![Case Wizard](screenshots/case_wizard.png) | ![Disk Discovery](screenshots/disk_discovery.png) | ![Dead Acquisition](screenshots/dead_acquisition_tab.png) |

| Acquisition Running | Verification Progress |
|:-------------------:|:---------------------:|
| ![Acquisition](screenshots/acquisition_running.png) | ![Verification](screenshots/verification_progress.png) |

### CLI & Reports

| CLI Banner | CLI Test Run | Report Preview |
|:----------:|:------------:|:--------------:|
| ![CLI Banner](screenshots/cli_banner.png) | ![CLI Tests](screenshots/cli_tests.png) | ![Report Preview](screenshots/report_preview.png) |

---

# Engineering Documentation

A detailed engineering write-up covering architecture decisions, audit trail hash-chain model, and threat considerations:

👉 https://kemalsebzeci-site.vercel.app/blog/fx-architecture

---

# Core Capabilities

## Session State Machine

Forensic workflow ordering enforced through an explicit state machine:

~~~text
NEW → CONTEXT_BOUND → ACQUIRING → VERIFYING → SEALED → DONE
                         ↑    ↓
                         └ abort()
~~~

- Illegal transitions raise `SessionStateError` and halt operation.
- `abort()` returns the session to `CONTEXT_BOUND` after stop/error, allowing retry without a full reset.
- `reset()` (F5) returns the session to `NEW` for a completely fresh workflow.

## Tamper-Evident Audit Logging (JSONL)

- Cryptographic chaining (`prev_hash → entry_hash`)
- **Per-session genesis block** — genesis hash includes `session_id` + `os.urandom` entropy (no two sessions share the same chain root)
- Forced disk flush (`fsync`) per record
- Optional **Ed25519 digital signature** (detached `.sig` file) — **private keys encrypted with passphrase** (`BestAvailableEncryption`)
- **Optional SIEM/Syslog forwarding** (RFC 5424 UDP/TCP, CEF mode) — version string sourced from `fx.__version__`
- **File Protection** — audit trail sealed with `chmod 444` (read-only) + optional `chattr +i` (immutable on Linux ext4/XFS)

## Acquisition & Integrity

- SSH-based remote acquisition (pure-Python, headless-testable)
- **Dead (local) acquisition** — direct block-device reading or **directory (logical) acquisition** via deterministic tar streaming
- **Bad sector error map** — unreadable sectors logged with offset, length, and error message; saved as `.error_map.json` (ddrescue-style)
- **Output re-verification** — written RAW image is re-read and SHA-256 compared to stream hash (FTK Imager "Verify After Create") — works on both **Live** and **Dead** acquisition; results logged to console, audit trail, and reports
- **Privilege elevation** — `pkexec` (polkit GUI) for block-device access and write-blocker (no password in terminal)
- **Verification progress** — real-time speed, ETA, and percentage during post-acquisition hash verification
- On-the-fly dual hashing (MD5 + SHA-256)
- Optional post-acquisition remote SHA-256 verification
- Safe Mode (`conv=noerror,sync`), write-blocker, throttling
- **Evidence format factory** — unified `create_evidence_writer()` eliminates if/elif duplication across engines
- **E01 metadata headers** — case number, examiner name, description, and notes populated via `set_header_value()` (end-to-end: GUI fields + CLI `--description` / `--notes` → engine → pyewf)
- **RawWriter fsync** — `flush()` + `os.fsync()` on close to guarantee data reaches disk
- **Input validation** — disk paths validated against injection patterns and shell-quoted (`shlex.quote`); **IPv6 and hostname** support in GUI
- **Graceful CLI stop (Ctrl+C)** — SIGINT handler stops engine, seals audit trail, then exits cleanly
- **Graceful GUI stop** — SSH transport is force-closed to interrupt blocking reads immediately
- Automatic retry on connection loss (up to 3 retries with resume)
- Output formats: **RAW**, **RAW+LZ4** (compressed), **E01**, **AFF4** (optional)
- **Triage artifact integrity** — every triage JSON/TXT file SHA-256 hashed and recorded in the audit trail

---

# CLI Tooling

## `fx-acquire` — Headless Acquisition

### Mode Selection

| Parameter | Description |
|-----------|-------------|
| *(default)* | **Live mode** — remote acquisition via SSH |
| `--dead` | **Dead mode** — local block-device or directory (logical) acquisition |
| `--source PATH` | Source device or directory for dead mode (e.g., `/dev/sdb`, `/mnt/evidence/`) |

### Live Mode Parameters

| Parameter | Description |
|-----------|-------------|
| `--ip`, `--user`, `--key` | SSH connection details (required for live) |
| `--disk` | Target block device on remote host (required for live) |

### Shared Parameters

| Parameter | Description |
|-----------|-------------|
| `--output-dir` | Evidence output directory (required) |
| `--case`, `--examiner` | Case metadata (required) |
| `--format RAW\|RAW+LZ4\|E01\|AFF4` | Evidence format (default: RAW) |
| `--verify` | Post-acquisition SHA-256 verification |
| `--safe-mode` | Pad unreadable sectors with zeros (default: on) |
| `--write-blocker` | Software write-blocker |
| `--throttle N` | Bandwidth limit in MB/s |
| `--signing-key PATH` | Ed25519 key for audit trail signing |
| `--description TEXT` | E01 header: evidence description (embedded in E01 metadata) |
| `--notes TEXT` | E01 header: examiner notes (embedded in E01 metadata) |

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

Example — live acquisition with triage + SIEM:

~~~bash
fx-acquire \
  --ip 10.0.0.1 --user ubuntu --key ~/.ssh/key.pem \
  --disk /dev/sda --output-dir ./evidence \
  --case 2026-001 --examiner "Investigator" \
  --triage --triage-memory \
  --siem-host 10.0.0.100 --siem-port 514 --siem-protocol TCP
~~~

Example — dead acquisition (block device):

~~~bash
fx-acquire --dead \
  --source /dev/sdb --output-dir ./evidence \
  --case 2026-001 --examiner "Investigator" \
  --format RAW+LZ4 --verify --write-blocker
~~~

Example — dead acquisition (directory / logical):

~~~bash
fx-acquire --dead \
  --source /mnt/evidence/user_home/ --output-dir ./evidence \
  --case 2026-001 --examiner "Investigator" \
  --format RAW --verify
~~~

## `fx-verify` — Audit Chain Verification

~~~bash
fx-verify AuditTrail_CASE_SESSION.jsonl
fx-verify AuditTrail_CASE_SESSION.jsonl --pubkey fx_signing.pub
fx-verify AuditTrail_CASE_SESSION.jsonl --json   # machine-readable output
~~~

Exit codes: `0` = PASS · `2` = FAIL (tamper detected) · `1` = Error

---

# Evidence Formats

| Format | Extension | Pros | Cons | Requirements |
|--------|-----------|------|------|--------------|
| **RAW** | `.raw` | Fast, standard, decompress-anywhere | Large file size (uncompressed) | *(none)* |
| **RAW+LZ4** | `.raw.lz4` | Fast compression (~50% ratio), LZ4 frame standard | Requires `lz4` to decompress | `lz4>=4.0.0` |
| **E01** | `.E01` | EnCase compatible, industry standard | Slower, requires libewf | `libewf2` (system) + `pyewf` (Python) |
| **AFF4** | `.aff4` | Open standard, flexible container | Less industry adoption | `pyaff4` |

### Hash Computation

In all formats, evidence hash (MD5 + SHA-256) is computed on **raw disk data _before_ compression**. This ensures integrity of the original evidence, not the container format.

> [!WARNING]
> **Safe Mode ↔ Verification Incompatibility**
>
> If **Safe Mode** is enabled (`conv=noerror,sync`), unreadable disk sectors are padded with zeros during acquisition. This modifies the image data compared to the source disk.
> 
> Therefore, **source hash will NEVER match local image hash if Safe Mode is enabled**. 
>
> **Choose one:**
> - ✅ **Safe Mode ON** + Verification OFF (unreadable sectors padded with zeros)
> - ✅ **Safe Mode OFF** + Verification ON (unreadable sectors fail the acquisition)
> 
> Mixing both will always result in hash MISMATCH.

## Generate Signing Keypair

~~~bash
# Without passphrase (backward-compatible)
python -c "from fx.audit.signing import generate_signing_keypair; generate_signing_keypair('.')"

# With passphrase (recommended)
python -c "from fx.audit.signing import generate_signing_keypair; generate_signing_keypair('.', passphrase='my-secret')"
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
> ForenXtract **never uploads kernel modules** to the target. LiME is only used if already loaded by an administrator before ForenXtract connects.

---

# Triage Data Dashboard

**v3.4.0 — Interactive Triage Visualization**

![Triage Dashboard](screenshots/triage_dashboard.png)

If triage is enabled, ForenXtract automatically generates an **interactive HTML dashboard** with real-time visualizations:

## Features

| Chart | Description |
|-------|-------------|
| **Top CPU Consumers** | Bar chart of processes using most CPU (%) |
| **Top Memory Consumers** | Bar chart of processes using most RAM (%) |
| **Process Distribution by User** | Pie chart showing process count per user |
| **TTY Distribution** | Connection state distribution |
| **Network Connection States** | Pie chart (ESTABLISHED, LISTEN, TIME_WAIT, etc.) |
| **Protocol Distribution** | TCP vs UDP connections |
| **Memory Usage Gauge** | Real-time RAM utilization with status indicators |
| **Memory Breakdown** | Used vs Available memory (KB) |

## Dashboard Output

**File:** `TriageDashboard_<CASE>_<UTC>.html`

Open in any web browser to explore:
- ✅ Responsive design (mobile/tablet friendly)
- ✅ Interactive Plotly charts (zoom, pan, hover tooltips)
- ✅ **Fully offline** — Plotly.js bundled inline (works in air-gapped labs)
- ✅ Embedded statistics for each analysis
- ✅ Grouped layout by triage module (Processes, Network, Memory)
- ✅ Professional styling with case metadata

## Example Usage

```bash
fx-acquire \
  --ip 10.0.0.1 --user ubuntu --key ~/.ssh/key.pem \
  --disk /dev/sda --output-dir ./evidence \
  --case 2026-001 --examiner "Investigator" \
  --triage --triage-memory \
  --format RAW --verify
```

**Output artifacts:**
- `evidence_2026-001_<UTC>.raw` — Disk image
- `ProcessList_2026-001_<UTC>.json` — Process data (used for dashboard)
- `NetworkState_2026-001_<UTC>.json` — Network data (used for dashboard)
- `MemoryState_2026-001_<UTC>.json` — Memory data (used for dashboard)
- **`TriageDashboard_2026-001_<UTC>.html`** ← Open this in browser! 📊
- `Report_2026-001_<UTC>.pdf` — Audit report (includes dashboard reference)

---

# Architecture

~~~text
fx/
├── cli/                        # Headless CLI tools
│   ├── acquire.py              # fx-acquire (live + dead modes, SIGINT handler, no Qt)
│   └── verify.py               # fx-verify (chain + sig verification)
├── triage/                     # Live triage collectors (read-only)
│   ├── orchestrator.py         # SHA-256 hashing of all triage artifacts
│   ├── network.py
│   ├── processes.py
│   └── memory.py
├── ui/                         # Qt / GUI layer
│   ├── gui.py                  # Tabbed interface (Live + Dead tabs)
│   └── workers.py              # AcquisitionWorker + DeadAcquisitionWorker
├── core/                       # Business logic (Qt-free, headless-testable)
│   ├── session.py              # Workflow state machine (NEW → DONE)
│   ├── hashing.py              # StreamHasher (MD5 + SHA-256)
│   ├── policy.py               # Write-blocker, dd builder, input validation
│   ├── validation.py           # Shared validators (IPv4/IPv6/hostname, SIEM, signing key)
│   └── acquisition/
│       ├── base.py             # AcquisitionEngine (live) + create_evidence_writer() factory
│       ├── dead.py             # DeadAcquisitionEngine (bad sector map, output re-verify)
│       ├── raw.py              # RawWriter (with fsync)
│       ├── ewf.py              # EwfWriter (with E01 metadata headers)
│       ├── aff4.py / lz4_writer.py
│       └── verify.py
├── audit/                      # Tamper-evident logging + signing
│   ├── logger.py               # ForensicLogger (hash-chained JSONL, per-session genesis)
│   ├── verify.py               # AuditChainVerifier (dynamic genesis support)
│   ├── signing.py              # Ed25519 key gen (passphrase-encrypted), sign, verify
│   └── syslog_handler.py       # RFC 5424 + CEF, UDP/TCP
└── report/
    ├── report_engine.py        # TXT + PDF forensic reporting
    └── dashboard.py            # Interactive Plotly dashboard (offline, no CDN)
~~~

---

# Output Artifacts

| File | Description |
|------|-------------|
| `evidence_<CASE>_<UTC>.raw` / `.raw.lz4` / `.E01` / `.aff4` | Disk image (RAW, compressed, E01, or AFF4) |
| `evidence_<CASE>_<UTC>.error_map.json` | Bad sector error map (only if unreadable sectors were encountered) |
| `AuditTrail_<CASE>_<SESSION>.jsonl` | Tamper-evident audit log |
| `AuditTrail_<CASE>_<SESSION>.jsonl.sig` | Ed25519 detached signature |
| `Report_<CASE>_<UTC>.pdf` / `.txt` | Forensic report (includes dashboard reference) |
| `NetworkState_<CASE>_<UTC>.txt` / `.json` | Triage: network state |
| `ProcessList_<CASE>_<UTC>.txt` / `.json` | Triage: process list |
| `MemoryState_<CASE>_<UTC>.json` | Triage: memory metadata |
| **`TriageDashboard_<CASE>_<UTC>.html`** | Interactive triage visualizations (open in browser) |

---

# Testing

~~~bash
python -m pytest tests/ -v
~~~

**158 unit tests** across 3 test modules:

| Module | Tests | Coverage |
|--------|------:|----------|
| `test_core.py` | 78 | Session state machine (incl. reset & abort), StreamHasher, RawWriter, LZ4Writer (incl. double-close guard), dd command builder, disk path injection validation, AuditChainVerifier, ForensicLogger (hash chain, sealing, context, syslog integration), Ed25519 signing, SyslogHandler (RFC 5424 + CEF), EwfWriter, AFF4Writer, DependencyChecker, ReportEngine (TXT/PDF + executive summary variants) |
| `test_triage.py` | 23 | ProcessListCollector (ps parsing, artifact saving, SSH error handling), NetworkStateCollector (all commands, TXT/JSON output, error isolation), MemoryDumpCollector (meminfo, kallsyms, modules, LiME detection), TriageOrchestrator (all collectors, error isolation, directory creation, status callback) |
| `test_acquisition.py` | 57 | `ssh_exec` (basic/error/unicode), `apply_write_blocker` (success/setro fail/getro fail), `verify_source_hash` (success/fail/exception), AcquisitionEngine (init, stop, progress callback, percentage cap, unavailable format handling via mock for E01/AFF4/LZ4, full RAW acquisition with mock SSH, connection failure + retry), **DeadAcquisitionEngine** (file imaging, hash verification, source-not-found, zero-size, stop/abort, LZ4 format, throttle, **directory acquisition**, **directory verification**, **empty directory error**, **write-blocker skip for dirs**), `_get_source_size` (regular/empty file, **directory walk**), `_is_block_device` (regular file, nonexistent, mock block), `_apply_local_write_blocker` (success/setro fail/verify fail, **pkexec arg verification**), **pkexec elevation** (fallback on PermissionError, cancelled auth, non-block re-raise), **elevated open** (pkexec dd for block devices, tar for directories), **EwfWriter extension-stripping** (`.E01` stripped, `.e01` stripped, no-extension passthrough, `.raw` not stripped), **verify command injection** (semicolon rejected, backtick rejected, valid path quoted), **SSH host key policy** (WarningPolicy enforced), **safe mode seek** (OSError advances offset), **AFF4 close propagation** (error raised, success works), **write-blocker ordering** (blocker before triage) |

All optional-dependency tests (pyewf, pyaff4, lz4) use `unittest.mock.patch` to test both available and unavailable code paths regardless of installed packages — **zero skips**.

---

# License

Apache License 2.0 — see [LICENSE](LICENSE)

**Author:** Kemal Sebzeci

If ForenXtract has been helpful in your investigations, [consider buying me a coffee ☕](https://buymeacoffee.com/futhark) to support ongoing development!
