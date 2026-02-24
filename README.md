# Remote Forensic Imager (RFI)

**Author:** Futhark1393  
**Version:** 2.0.0  

Remote Forensic Imager (RFI) is a **case-first** remote disk acquisition tool built with **Python + PyQt6**.

It enforces a structured forensic workflow, generates a **cryptographically hash-chained audit trail (JSONL)**, supports optional **source-to-stream SHA-256 verification**, and produces **TXT/PDF** forensic reports for evidentiary documentation.

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

## Core Features

### Case-First Workflow
- Mandatory Case Wizard at startup
- Case Number + Examiner required
- Evidence directory binding required
- No acquisition without an active case context

### Forensic Audit Logging (JSONL)
- Structured per-session audit trail
- Cryptographic hash chaining (`prev_hash -> entry_hash`)
- Deterministic JSON serialization
- Forced disk flush (`fsync`) per entry
- Optional sealing (best-effort): `chmod 444` + `chattr +i` (if available)

### Acquisition & Integrity
- SSH-based acquisition
- Remote disk discovery (`lsblk`)
- On-the-fly hashing (MD5 + SHA-256)
- Optional post-acquisition **remote SHA-256** verification
- Safe Mode (`conv=noerror,sync`) padding unreadable blocks with zeros
- Optional write-blocker enforcement (best-effort)

### Reporting
- TXT forensic report
- PDF forensic report
- Includes:
  - Local hash values
  - Optional source hash
  - Verification result
  - Audit trail hash
  - Seal status

---

## Architecture

~~~text
codes/
├── gui.py
├── threads.py
├── logger.py
├── report_engine.py
└── dependency_checker.py
~~~

Design goals:
- Fail-secure behavior
- Tamper-evident logging
- Thread-safe acquisition
- Clear separation of responsibilities
- Minimal runtime assumptions

---

# Installation

## 1) Clone
~~~bash
git clone https://github.com/Futhark1393/Remote-Forensic-Imager.git
cd Remote-Forensic-Imager
~~~

## 2) System Dependencies (Linux)

RFI requires Qt runtime libraries (PyQt6).

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

## 3) Python Dependencies
~~~bash
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
~~~

If you prefer minimal manual install:
~~~bash
pip install PyQt6 qt-material paramiko fpdf2
~~~

---

## 4) Optional: E01 (EWF) Support

E01 requires **libewf + Python bindings**.

### Option A (recommended on Debian/Kali/Ubuntu): system package
~~~bash
sudo apt install -y libewf2 python3-libewf
~~~

### Option B (pip): libewf-python (may require build toolchain)
~~~bash
pip install libewf-python
~~~

> Note: the import name in Python is often `pyewf` even when the package name is `python3-libewf` or `libewf-python`.

If E01 bindings are not installed:
- RAW acquisition works normally
- E01 option should be treated as unavailable

---

# Running

~~~bash
python main_qt6.py
~~~

If you created an alias:
~~~bash
rfi
~~~

---

# Workflow

1. Start RFI → Case Wizard appears
2. Define Case Number + Examiner
3. Bind Evidence Directory
4. Enter SSH details
5. Discover disks (optional)
6. Select acquisition target
7. Choose format (RAW / E01)
8. Acquire → Report generated → Audit trail sealed (best-effort)

---

# Output Artifacts

Inside the selected Evidence Directory, RFI generates:
- `evidence_<CASE>_<UTC>.raw` or `evidence_<CASE>_<UTC>.E01`
- `AuditTrail_<CASE>_<SESSION>.jsonl`
- `AuditConsole_<CASE>.log`
- `Report_<CASE>_<UTC>.pdf`
- `Report_<CASE>_<UTC>.txt`

---

## Notes on Verification

- E01 is a container format. Verification is based on stream hashing + optional source hashing.
- If the target device is a **live system disk**, post-acquisition `/dev/...` hashing may differ due to ongoing writes.
- For strict source-to-image equivalence, acquire from a stable target (unmounted disk, snapshot, or write-blocked device).

---

## License

MIT License — see [LICENSE](LICENSE)

## Author
Futhark1393
