# 🕵️‍♂️ Remote Forensic Imager - Professional Edition

**Remote Forensic Imager** is a professional-grade digital forensics tool designed to acquire full disk images from remote cloud servers (AWS EC2, VPS, etc.) with high integrity and automated reporting.

[cite_start]Developed with **Python** and **PyQt6** on **Fedora 43 Workstation** [cite: 20][cite_start], this tool follows forensic best practices to ensure a secure **Chain of Custody (CoC)**[cite: 30].

![GUI Preview](screenshots/gui_preview.png)

## 🚀 Key Features

* **Advanced Logging:** Captures acquisition start/end times, total duration, and remote IP logs.
* [cite_start]**Security Verification:** Automatically fetches and logs the **Remote SSH Fingerprint** [cite: 14] to ensure a secure connection.
* [cite_start]**Automated Forensic Reporting:** Generates a detailed `.txt` report including a **Chain of Custody** table, full command history, and SHA-256 hash values[cite: 30].
* [cite_start]**Safe Mode:** Implements `conv=noerror,sync` [cite: 17] to handle disk bad sectors without compromising the image.
* [cite_start]**Integrity Protection:** Encourages write-blocking with `chmod 444` [cite: 26] [cite_start]and performs post-acquisition hash verification[cite: 25].

---

## 🧪 Setting Up a Test Laboratory

To see the tool in action without a real incident, you can set up a test environment in minutes.

### 1. Prepare Your Target Server (AWS/VPS)
Connect to your remote server via SSH and create a "secret" evidence file to be discovered later:

```bash
# Connect to your server
ssh -i your-key.pem ubuntu@your-server-ip

# Create a dummy evidence file
echo "SECRET_EVIDENCE_DATA_FOUND_BY_FUTHARK" > secret_evidence.txt

# Verify the file is there
cat secret_evidence.txt
```

### 2. Run the Acquisition
1. Launch `python3 main_qt6.py` on your local machine.
2. Enter the **Case Number** (e.g., `2026-FINAL-001`) [cite: 1] and your name.
3. Fill in the server details (IP: `51.20.74.168` [cite: 9], Disk: `/dev/nvme0n1` [cite: 10]) and click **"Take Image and Analyze"**.

### 3. Verify and Find the Evidence
Once the acquisition is complete, use the following forensic commands in your terminal to find the hidden data:

```bash
# List the acquired file (It will be read-only)
ls -l evidence_*.img.gz

# Forensic search for the 'secret' keyword inside the compressed image
zgrep -a "SECRET_EVIDENCE" evidence_*.img.gz
```

---

## 🛡️ Automated Forensic Reporting & Chain of Custody

The tool automatically generates a comprehensive forensic report upon completion. [cite_start]This report is essential for maintaining the **Chain of Custody (CoC)**[cite: 30].



![Automated Report](screenshots/automated_report.png)
*Figure: Automated Forensic Report including Case Info, Remote SSH Fingerprint, and CoC Table.*

---

## 🛠️ Requirements & Installation

* [cite_start]**OS:** Linux (Tested on Fedora 43 / Gnome 49.3) 
* **Python:** 3.10+
* **Dependencies:** `pip install PyQt6`

```bash
# Clone the Repository
git clone [https://github.com/Futhark1393/Remote-Forensic-Imager.git](https://github.com/Futhark1393/Remote-Forensic-Imager.git)
cd Remote-Forensic-Imager

# Run the App
python3 main_qt6.py
```

## ⚠️ Disclaimer

This tool is intended for **authorized forensic investigations** only. The developer (**Futhark**)  is not responsible for any unauthorized use.

---

**Developed by Futhark**
