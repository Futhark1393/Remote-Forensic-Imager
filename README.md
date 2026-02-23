# 🕵️‍♂️ Remote Forensic Imager v2.1 (Enterprise Edition)

**Remote Forensic Imager** is a professional, bit-stream acquisition tool designed for secure live disk and memory forensics from remote servers (AWS EC2, VPS, etc.) over encrypted SSH channels.

Developed by **Futhark1393**, this tool automates evidence collection while maintaining a strict **Chain of Custody (CoC)** and adhering to the **"Do No Harm"** forensic principle.

![Acquisition Dashboard](screenshots/v2.1_dashboard.png)

## 🚀 v2.1 Enterprise UI & Engine Updates

The v2.1 release introduces a major visual overhaul and architectural refinements for high-stakes forensic environments:

* **Enterprise Material UI:** Integrated `qt-material` with a custom `dark_teal` theme for a professional, high-contrast dashboard experience.
* **Intuitive Grouped Layout:** UI components are now logically grouped into **Case Identification**, **Remote Server**, **Evidence Target**, and **Acquisition Options** for reduced human error.
* **Native E01 (EnCase) Support:** Direct integration with `libewf` allows for bit-stream acquisition directly into the industry-standard compressed E01 format with embedded metadata.
* **API-Based SSH Streaming (Paramiko):** Secure, direct TCP socket manipulation without OS-level shell dependencies.
* **On-The-Fly Hashing:** Dual-Hash (SHA-256 and MD5) signatures are calculated synchronously in-memory during transfer, ensuring immediate integrity verification.
* **Responsive Engine (QThread):** The GUI remains 100% responsive with real-time performance metrics (MB/s, bytes read) passed via PyQt signals.

![Acquisition Finished](screenshots/v2.1_finished.png)

---

## 🔥 Proof of Concept: Data Carving & Bit-Stream Accuracy

To verify that the tool performs a true physical acquisition, a test was conducted on a 100MB AWS EC2 partition. The resulting image was analyzed using **Autopsy**, successfully carving historical artifacts from unallocated space (e.g., 1999 GNU FSF documentation fragments).

**Carved Header Data:**
![Autopsy Data Carving Header](screenshots/autopsy_carving_header.png)

This artifact confirms that the Remote Forensic Imager successfully captures raw sector data, including data remanence and deleted files, proving its 100% lossless physical acquisition capability.

---

## 🏗️ Modular Architecture

The tool is built with a highly decoupled structure:
* `main_qt6.py`: Application entry point and theme application.
* `codes/gui.py`: Manages the PyQt6 Material interface and PDF reporting engine.
* `codes/engine.py`: The core headless `ForensicAcquisitionEngine` handling Paramiko connections and `pyewf` compression.
* `codes/threads.py`: `QThread` workers bridging the engine with the UI event loop.

---

## 🛠️ Environment & Installation

* **Tested OS:** Fedora Linux 43 (KDE Plasma), Ubuntu.
* **Language:** Python 3.10+
* **Dependencies:** `PyQt6`, `fpdf2`, `paramiko`, `qt-material`, `libewf`.

### ⚡ Automated Installation (Recommended)
The automated script installs all dependencies, compiles the `libewf` C-library, and sets up system-wide shortcuts (`rfi` command).

```bash
# 1. Clone the repository
git clone [https://github.com/Futhark1393/Remote-Forensic-Imager.git](https://github.com/Futhark1393/Remote-Forensic-Imager.git)
cd Remote-Forensic-Imager

# 2. Run the automated installer
chmod +x RFI_install.sh
./RFI_install.sh
```

### 🚀 Usage
Once installed, launch the tool from your terminal or application menu:
* **Terminal:** Type `rfi` and hit Enter.
* **GUI:** Search for **"Remote Forensic Imager"** in your KDE/GNOME launcher.

---

## ⚠️ Disclaimer & Legal Warning
This tool is for educational purposes, incident response, and authorized forensic investigations. The author (**Futhark1393**) is not responsible for any misuse or legal consequences. Always ensure you have explicit, written permission from the system owner.

---
**Developed by Futhark1393**
