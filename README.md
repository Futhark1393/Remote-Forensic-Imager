# Remote Forensic Imager (RFI)

Author: Futhark1393

Remote Forensic Imager (RFI) is a forensic-grade remote disk acquisition tool built with Python and PyQt6.

It enforces a case-first workflow, produces a cryptographically chained audit trail (JSONL), supports optional source-to-stream verification, and generates forensic reports (TXT/PDF) for evidentiary documentation.

---

## Interface Preview

~~~text
screenshots/
├── case_wizard.png
├── main_ui_idle.png
├── disk_discovery.png
├── acquisition_running.png
└── report_preview.png
~~~

![Case Wizard](screenshots/case_wizard.png)

![Main UI (Idle)](screenshots/main_ui_idle.png)

![Remote Disk Discovery](screenshots/disk_discovery.png)

![Acquisition Running](screenshots/acquisition_running.png)

![Report Preview](screenshots/report_preview.png)

---

## Core Features

### Case-First Workflow
- Mandatory Case Wizard at startup
- Case Number + Examiner required
- Evidence directory binding required
- No acquisition without an active case context

### Forensic Audit Logging
- JSONL structured audit trail per case/session
- Cryptographic chaining (`prev_hash → entry_hash`)
- Deterministic JSON serialization
- Forced disk flush (`fsync`) for each record
- Optional file sealing (read-only + `chattr +i` when available)
- Offline chain verification supported

### Acquisition & Integrity
- SSH-based acquisition workflow
- Remote disk discovery (`lsblk`)
- On-the-fly hashing (MD5 + SHA-256) during acquisition
- Optional post-acquisition remote SHA-256 collection (verification mode)
- Safe Mode option (pads read errors with zeros)

### Reporting
- TXT report
- PDF report
- Includes integrity section (local + optional source hash)
- Includes audit trail hash and sealing status

---

## Architecture

~~~text
codes/
├── gui.py
├── threads.py
├── engine.py
├── logger.py
├── report_engine.py
└── dependency_checker.py
~~~

Design goals:
- Fail-secure behavior
- Tamper-evident logging
- Thread-safe audit output
- Clear separation between GUI, acquisition, logging, reporting

---

## Installation

### Clone

~~~bash
git clone https://github.com/Futhark1393/Remote-Forensic-Imager.git
cd Remote-Forensic-Imager
~~~

### Python Dependencies

~~~bash
pip install pyqt6 qt-material paramiko fpdf
~~~

### Optional: E01 Support (pyewf/libewf)

~~~bash
pip install pyewf
~~~

System libraries:

Debian / Ubuntu:
~~~bash
sudo apt install libewf-dev
~~~

Fedora:
~~~bash
sudo dnf install libewf-devel
~~~

---

## Running

~~~bash
python main_qt6.py
~~~

If you created an alias/entrypoint:
~~~bash
rfi
~~~

---

## Workflow

1) Start RFI and create/open a case in the Case Wizard  
2) Provide SSH details and select key  
3) Discover disks (optional)  
4) Select target device/partition  
5) Choose acquisition format (RAW / E01)  
6) Acquire + generate report + seal audit trail  

---

## Output Artifacts

Inside the selected Evidence Directory:

~~~text
AuditTrail_<case>_<session>.jsonl
AuditConsole_<case>.log
Report_<case>_<timestamp>.txt
Report_<case>_<timestamp>.pdf
evidence_<case>_<timestamp>.raw / .E01
~~~

---

## Audit Chain Verification

~~~python
from codes.logger import AuditChainVerifier

valid, message = AuditChainVerifier.verify_chain("AuditTrail_CASE_SESSION.jsonl")
print(valid, message)
~~~

Any modification, removal, or reordering of records should fail verification.

---

## Notes on Verification

- E01 is a container format. Integrity verification is performed against the acquisition stream hash and optional source hash collection.
- **If the target is a live system disk, source SHA-256 collected after acquisition may differ due to ongoing writes. Prefer snapshots or unmounted devices for strict equivalence.**
- This is expected behavior on live disks and should not be reported as a bug.

---

## License

This project is licensed under the MIT License.

You are free to:
- Use
- Modify
- Distribute
- Sublicense
- Use commercially

As long as the original copyright and license notice are included.

See the full license text in the `LICENSE` file.

---

## Author

Futhark1393
