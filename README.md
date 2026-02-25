# Remote Forensic Imager (RFI)

![CI](https://github.com/Futhark1393/Remote-Forensic-Imager/actions/workflows/python-ci.yml/badge.svg)

**Author:** Futhark1393  
**Version:** 2.1.1  
**License:** MIT  

Remote Forensic Imager (RFI) is a **case-first remote disk acquisition framework** built with **Python + PyQt6**.

It enforces structured forensic workflows, generates a **cryptographically hash-chained audit trail (JSONL)**, supports optional **source-to-stream SHA-256 verification**, and produces **TXT/PDF forensic reports** suitable for evidentiary documentation.

---

## Engineering Documentation

A detailed engineering write-up covering:

- Architecture decisions  
- Audit trail hash-chain model  
- Integrity verification approach  
- Threat considerations  

is available here:

👉 https://kemalsebzeci-site.vercel.app/blog/rfi-architecture

---

## Interface Preview

Screenshots included in `./screenshots/`

- Case Wizard  
  ![Case Wizard](screenshots/case_wizard.png)

- Main UI (Idle)  
  ![Main UI Idle](screenshots/main_ui_idle.png)

- Remote Disk Discovery  
  ![Disk Discovery](screenshots/disk_discovery.png)

- Acquisition Running  
  ![Acquisition Running](screenshots/acquisition_running.png)

- Report Preview  
  ![Report Preview](screenshots/report_preview.png)

---

# Core Capabilities

## Case-First Workflow

- Mandatory Case Wizard at startup
- Case Number + Examiner required
- Evidence directory binding required
- No acquisition allowed without active case context

## Tamper-Evident Audit Logging (JSONL)

- Structured per-session audit trail
- Cryptographic chaining (`prev_hash → entry_hash`)
- Deterministic JSON serialization
- Forced disk flush (`fsync`) per record
- Optional sealing (best-effort):
  - `chmod 444`
  - `chattr +i` (if available)
- Offline chain verification support

## Acquisition & Integrity

- SSH-based acquisition
- Remote disk discovery (`lsblk`)
- On-the-fly hashing (MD5 + SHA-256)
- Optional post-acquisition remote SHA-256 verification
- Safe Mode (`conv=noerror,sync`)
- Optional write-blocker enforcement (best-effort)

## Reporting

- TXT forensic report
- PDF forensic report
- Includes:
  - Local hash values
  - Optional source hash
  - Verification result
  - Audit trail hash
  - Seal status

---

# CLI Tooling

RFI includes a command-line verifier for audit trails.

## Verify Audit Chain

~~~bash
python rfi_verify.py AuditTrail_CASE_SESSION.jsonl
~~~

Or if installed as alias:

~~~bash
rfi-verify AuditTrail_CASE_SESSION.jsonl
~~~

Exit codes:

- `0` → PASS  
- `2` → FAIL (tampering detected)  
- `1` → Error  

---

# Architecture

~~~text
codes/
├── gui.py
├── threads.py
├── logger.py
├── report_engine.py
├── dependency_checker.py
└── __init__.py
~~~

Separation of concerns:

- GUI → user interaction layer
- threads → acquisition execution
- logger → cryptographic audit engine
- report_engine → evidentiary documentation
- dependency_checker → runtime validation

Design goals:

- Fail-secure behavior
- Tamper-evident logging
- Deterministic record generation
- Minimal implicit trust assumptions

---

# Installation

## 1) Clone

~~~bash
git clone https://github.com/Futhark1393/Remote-Forensic-Imager.git
cd Remote-Forensic-Imager
~~~

---

## 2) System Dependencies (Linux)

### Ubuntu / Debian / Kali

~~~bash
sudo apt update
sudo apt install -y \
  libegl1 libgl1 libglib2.0-0 libxkbcommon0 libxkbcommon-x11-0 \
  libxcb1 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-randr0 \
  libxcb-render0 libxcb-render-util0 libxcb-shape0 libxcb-shm0 libxcb-sync1 \
  libxcb-xfixes0 libxcb-xinerama0 libxcb-xkb1 libxrender1 libxi6 \
  libsm6 libice6 libfontconfig1 libfreetype6
~~~

### Fedora

~~~bash
sudo dnf install -y qt6-qtbase qt6-qtbase-gui mesa-libEGL mesa-libGL
~~~

---

## 3) Python Dependencies

~~~bash
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
~~~

Minimal install:

~~~bash
pip install PyQt6 qt-material paramiko fpdf2
~~~

---

## 4) Optional: E01 (EWF) Support

E01 imaging requires **libewf + Python bindings**.

### Debian / Ubuntu / Kali

~~~bash
sudo apt install -y libewf2 python3-libewf
~~~

### Alternative (pip)

~~~bash
pip install libewf-python
~~~

If E01 bindings are not installed:

- RAW acquisition works normally
- E01 option will be unavailable

---

# Running

~~~bash
python main_qt6.py
~~~

Or:

~~~bash
rfi
~~~

---

# Output Artifacts

Inside the selected Evidence Directory:

- `evidence_<CASE>_<UTC>.raw` or `.E01`
- `AuditTrail_<CASE>_<SESSION>.jsonl`
- `AuditConsole_<CASE>.log`
- `Report_<CASE>_<UTC>.pdf`
- `Report_<CASE>_<UTC>.txt`

---

# Notes on Verification

- E01 is a container format.
- Integrity is calculated on the acquisition stream.
- If acquiring from a live system disk, post-acquisition `/dev/...` hashing may differ due to ongoing writes.
- For strict source-to-image equivalence:
  - Use snapshots
  - Use unmounted devices
  - Use hardware write-blockers

This is expected behavior and not a bug.

---

# Versioning

RFI follows Semantic Versioning:

- MAJOR → breaking changes
- MINOR → new features
- PATCH → bug fixes

Example:

- `2.0.0` → Case-first + forensic logger release
- `2.0.1` → Stability improvements
- `2.1.0` → New feature

---

# License

MIT License — see [LICENSE](LICENSE)

---

# Author

Futhark1393
