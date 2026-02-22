# 🕵️‍♂️ Remote Forensic Imager

**Remote Forensic Imager** is a professional Python-based digital forensic tool designed for secure live disk and memory acquisition from remote servers (AWS EC2, VPS, etc.) over encrypted SSH channels.

Developed by **Futhark1393**, the tool automates the collection of bit-stream images while maintaining a strict **Chain of Custody (CoC)** and adhering to the **"Do No Harm"** forensic principle.

![Main Interface](screenshots/gui_main.png)

## 🚀 Technical Capabilities

* **Multiple Acquisition Formats:** Supports industry-standard **E01 (EnCase)** format with embedded metadata, as well as compressed RAW (`.img.gz`) formats via `libewf`.
* **Dynamic Real-Time Progress:** Features a live, zero-deadlock GUI progress bar that parses exact byte output from acquisition streams without bouncing.
* **Custom Workspace:** Interactive directory selection (QFileDialog) ensures evidence, triage data, and generated reports are stored in organized, case-specific folders.
* **Auto-Discovery:** Probes the remote server via single-shot SSH (`lsblk`) to display the physical disk layout directly in the console.
* **Live Triage:** Executes rapid volatile data collection (network connections, processes, logs) before disk acquisition.
* **Bandwidth Throttling:** Integrates with `pv` to limit transfer speeds and prevent network bottlenecks on live production servers.
* **Dual-Hash Verification:** Automatically calculates both **SHA-256** and **MD5** digital signatures for evidence integrity.
* **Software Write Blocker:** Sets the target block device to **Read-Only (RO)** mode at the kernel level (`blockdev --setro`).
* **Multi-Format Reporting:** Generates technical `.txt` logs and professional `.pdf` Executive Summaries with multi-language support (EN/TR).

![Acquisition Process](screenshots/gui_acquisition.png)

---

## 🏗️ Modular Architecture

The tool is built with a highly modular structure to ensure stability and future scalability:
* `main_qt6.py`: Application entry point and UI launcher (Includes KDE Plasma desktop compatibility).
* `codes/gui.py`: Manages the PyQt6 interface, user interactions, directory selection, and PDF reporting engine.
* `codes/acquisition.py`: Handles SSH tunneling, `dd` streaming, E01 stream encapsulation, bandwidth throttling, and Triage execution.
* `codes/analysis.py`: Performs post-acquisition tasks like SHA-256/MD5 hashing and binary header analysis.

---

## 🔥 Proof of Concept: Data Carving & Bit-Stream Accuracy

To verify that the tool performs a true physical (bit-stream) acquisition rather than just a logical file copy, a test was conducted on a 8 GB AWS EC2 partition (`/dev/nvme0n1`). 

The resulting `.E01` image was analyzed using **Autopsy**. During the analysis of the **Unallocated Space**, fragments of historical Linux documentation (a 1999 email from GNU FSF founder Richard Stallman regarding Readline libraries) were successfully carved and recovered. 

![Autopsy Data Carving](screenshots/autopsy_carving_body.png)

This artifact confirms that the Remote Forensic Imager successfully captures raw sector data, including data remanence and deleted files in unallocated space, proving its 100% lossless physical acquisition capability over an encrypted SSH stream.

---

## 🧪 Laboratory Setup & Testing

### 1. Target Preparation (Remote Side)
Connect to your remote instance and place a "secret" evidence file:
```bash
ssh -i your-key.pem ubuntu@remote-ip
echo "CONFIDENTIAL_DATA_FOUND_BY_FUTHARK1393" > evidence.txt
```

### 2. Evidence Collection (Local Side)
1. Run the application: `python3 main_qt6.py`.
2. Click **"Auto-Detect"** to identify the remote disks.
3. Enter the target disk (e.g., `/dev/nvme0n1`).
4. Click **"Take Image and Analyze"** to start the process.
5. Select the **Output Directory** where evidence and reports will be saved.
6. Choose the evidence format (**E01** or **RAW**) from the popup dialog.
7. Select the report language (EN/TR) from the popup menu after acquisition completes.

---

## 🔗 Chain of Custody (CoC) Protocol

In digital forensics, the **Chain of Custody** is the documentation recording the sequence of custody and transfer of evidence. This tool enforces CoC through:

1. **Identification:** Logs exact IP, SSH fingerprints, and timestamps.
2. **Preservation:** Enforces Read-Only modes and secures images with Dual-Hash signatures (SHA-256 & MD5) and E01 metadata embedding.
3. **Documentation:** Automatically generates a CoC report mapping the transfer from the target to the examiner.

![PDF Report Example](screenshots/pdf_report.png)

> ⚖️ **NIST Compliance:** The acquisition methodology aligns with **NIST Special Publication 800-86** guidelines for verifiable data collection and cryptographic preservation.

---

## 🛠️ Environment & Installation

* **Supported OS:** Fedora Linux 43 (KDE Plasma), Ubuntu, CAINE, and other major Linux distributions.
* **Language:** Python 3.10+
* **Dependencies:** `PyQt6`, `fpdf2`, `pv`, `libewf`

### 1. Clone the Repository
Download the tool to your local forensic workstation:
```bash
git clone [https://github.com/Futhark1393/Remote-Forensic-Imager.git](https://github.com/Futhark1393/Remote-Forensic-Imager.git)
cd Remote-Forensic-Imager
```

### 2. Install System Dependencies
The tool requires `pv` for bandwidth throttling and `ewf-tools` for E01 format support.

**For Fedora / RHEL:**
```bash
sudo dnf install pv libewf-tools
```

**For Ubuntu / Debian / CAINE:**
```bash
sudo apt update
sudo apt install pv ewf-tools
```

### 3. Install Python Dependencies
It is recommended to use a virtual environment or install directly via pip:
```bash
pip install PyQt6 fpdf2
```

### 4. Launch the Console
Run the main Python script to initialize the GUI:
```bash
python3 main_qt6.py
```

## ⚠️ Important Note
When acquiring RAM via `/proc/kcore`, the virtual file size may appear extremely large (TB range). It is recommended to use specific block counts or target physical memory offsets to avoid excessive data transfer and potential system hangs.

---
**Developed by Futhark1393**
