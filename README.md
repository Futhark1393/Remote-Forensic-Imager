# 🕵️‍♂️ Remote Forensic Imager v2.0 (Enterprise Edition)

**Remote Forensic Imager** is a professional Python-based digital forensic tool designed for secure live disk and memory acquisition from remote servers (AWS EC2, VPS, etc.) over encrypted SSH channels.

Developed by **Futhark1393**, the tool automates the collection of bit-stream images while maintaining a strict **Chain of Custody (CoC)** and adhering to the **"Do No Harm"** forensic principle.

![Acquisition Running](screenshots/v2_running.png)

## 🚀 v2.0 Core Engine Devrimleri (The Paramiko Upgrade)

The v2.0 release completely overhauls the acquisition engine, transitioning from OS-level `subprocess` pipes to a robust, API-based TCP socket architecture:

* **API-Based SSH Streaming (Paramiko):** Eliminates `shell=True` subprocess dependencies and potential shell injection risks. Direct manipulation of the SSH TCP socket ensures absolute control over the data stream.
* **Chunk-Based Memory Management:** Data is streamed from the remote block device in 4MB chunks directly into the local RAM, preventing system I/O bottlenecks and GUI deadlocks.
* **On-The-Fly Hashing:** Dual-Hash (SHA-256 and MD5) signatures are calculated synchronously in-memory as each 4MB chunk arrives. This eliminates the need for post-process disk reading, proving the data's absolute integrity the millisecond the transfer concludes.
* **Asynchronous GUI (QThread):** The UI remains 100% responsive. Real-time metrics (MB/s, current bytes, live MD5) are passed via PyQt signals to the status bar without locking the main event loop.

![Acquisition Finished](screenshots/v2_finished.png)

---

## 🏗️ Modular Architecture

The tool is built with a highly decoupled structure:
* `main_qt6.py`: Application entry point.
* `codes/gui.py`: Manages the PyQt6 interface and PDF reporting engine.
* `codes/engine.py`: The core headless `ForensicAcquisitionEngine` handling Paramiko connections, read-only kernel enforcement (`blockdev`), and generator-based chunk streaming.
* `codes/threads.py`: `QThread` workers that bridge the headless engine with the GUI event loop.

---

## 🔗 Chain of Custody & Reporting

1. **Identification:** Logs exact IP, timestamps, and examiner details.
2. **Preservation:** Enforces Read-Only modes and secures images with Dual-Hash signatures.
3. **Documentation:** Automatically generates immutable `.txt` and professional `.pdf` Executive Summaries (EN/TR support).

> ⚖️ **NIST Compliance:** The acquisition methodology aligns with **NIST Special Publication 800-86** guidelines for verifiable data collection and cryptographic preservation.

---

## 🛠️ Environment & Installation

* **Supported OS:** Fedora Linux 43 (KDE Plasma), Ubuntu, CAINE, and other major Linux distributions.
* **Language:** Python 3.10+
* **Dependencies:** `PyQt6`, `fpdf2`, `paramiko`

### 1. Clone the Repository & Switch to v2 Branch
```bash
git clone [https://github.com/Futhark1393/Remote-Forensic-Imager.git](https://github.com/Futhark1393/Remote-Forensic-Imager.git)
cd Remote-Forensic-Imager
git checkout v2-development
```

### 2. Install Python Dependencies
```bash
pip install PyQt6 fpdf2 paramiko
```

### 3. Launch the Console
```bash
python3 main_qt6.py
```

---
**Developed by Futhark1393**
