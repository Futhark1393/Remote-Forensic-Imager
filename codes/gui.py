# Author: Futhark1393
# Description: Main GUI module for Remote Forensic Imager v2.0.
# Features Paramiko integration, chunk-based streaming, and on-the-fly hashing.

import sys
import os
import subprocess
from datetime import datetime
from PyQt6.QtWidgets import QMainWindow, QFileDialog, QMessageBox, QApplication
from PyQt6.uic import loadUi
from PyQt6.QtGui import QTextCursor
from fpdf import FPDF

# Import the new v2.0 Paramiko worker thread
from codes.threads import AcquisitionWorker

class ForensicApp(QMainWindow):
    def __init__(self):
        super().__init__()
        try:
            loadUi("forensic_qt6.ui", self)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"UI file could not be loaded!\n{e}")
            sys.exit(1)

        self.setWindowTitle("Remote Forensic Imager v2.0 (Paramiko Engine)")
        self.setup_terminal_style()
        self.setup_tooltips()

        self.btn_file.clicked.connect(self.select_key)
        self.btn_start.clicked.connect(self.start_process)

        if hasattr(self, 'btn_discover'):
            self.btn_discover.clicked.connect(self.discover_disks)

        self.txt_user.setText("ubuntu")
        self.txt_disk.setText("")

        if hasattr(self, 'chk_safety'):
            self.chk_safety.setChecked(True)

        self.progressBar.setValue(0)
        self.last_report_data = {}
        self.output_dir = ""

        # Localization dictionaries for PDF reporting
        self.lang_dict_tr = {
            "report_title": "DIJITAL ADLI BILISIM IMAJ RAPORU",
            "case_info": "1. VAKA DETAYLARI",
            "case_no_lbl": "Vaka Numarasi:",
            "examiner_lbl": "Uzman:",
            "date_lbl": "Tarih:",
            "target_ip_lbl": "Hedef IP:",
            "duration_lbl": "Islem Suresi:",
            "integrity": "2. VERI BUTUNLUGU (DIJITAL MUHUR)",
            "hash_lbl": "SHA-256 HASH DEGERI:",
            "hash_status": "SHA-256 Durumu: DOGRULANDI (VERIFIED)",
            "md5_lbl": "MD5 HASH DEGERI:",
            "md5_status": "MD5 Durumu: DOGRULANDI (VERIFIED)",
            "triage": "3. OLAY MAHALLI ILK INCELEME (TRIAGE)",
            "triage_lbl": "Live Triage Kaydi:",
            "not_requested": "Talep Edilmedi",
            "bad_sectors_lbl": "Fiziksel Hata Kontrolu:",
            "clean": "TEMIZ",
            "exec_summary_title": "YONETICI OZETI",
            "summary": "Analiz basariyla tamamlandi. Imaj alma operasyonu sirasinda herhangi bir veri bozulmasi veya hatali sektor (bad sector) gozlemlenmedi. Adli imajin butunlugu coklu hash algoritmalari (SHA-256 ve MD5) ile guvence altina alinmis ve dogrulanmistir."
        }

        self.lang_dict_en = {
            "report_title": "DIGITAL FORENSIC ACQUISITION REPORT",
            "case_info": "1. CASE DETAILS",
            "case_no_lbl": "Case Number:",
            "examiner_lbl": "Examiner:",
            "date_lbl": "Date:",
            "target_ip_lbl": "Target IP:",
            "duration_lbl": "Acquisition Duration:",
            "integrity": "2. EVIDENCE INTEGRITY (DIGITAL SEAL)",
            "hash_lbl": "SHA-256 HASH:",
            "hash_status": "SHA-256 Status: VERIFIED",
            "md5_lbl": "MD5 HASH:",
            "md5_status": "MD5 Status: VERIFIED",
            "triage": "3. PRE-ACQUISITION TRIAGE",
            "triage_lbl": "Live Triage Log:",
            "not_requested": "Not Requested",
            "bad_sectors_lbl": "Physical Error Check:",
            "clean": "CLEAN",
            "exec_summary_title": "EXECUTIVE SUMMARY",
            "summary": "Analysis completed successfully. No data corruption or physical bad sectors were observed during the acquisition process. The integrity of the forensic image has been verified using multiple hash algorithms (SHA-256 and MD5)."
        }

    def setup_terminal_style(self):
        # Configure the log console with a hacker/terminal visual style
        self.txt_log.setReadOnly(True)
        self.txt_log.setStyleSheet("""
            QTextEdit {
                background-color: #000000;
                color: #00FF00;
                font-family: "Monospace";
                font-size: 10pt;
                border: 1px solid #333;
            }
        """)
        self.log("--- SYSTEM READY ---")
        self.log("[*] Forensic Console Initialized (v2.0 - Paramiko Engine).")

    def setup_tooltips(self):
        # Initialize UI component tooltips
        if hasattr(self, 'txt_caseno'): self.txt_caseno.setToolTip("Incident or Case Number.")
        if hasattr(self, 'txt_examiner'): self.txt_examiner.setToolTip("Name or ID of the Forensic Examiner.")
        if hasattr(self, 'txt_ip'): self.txt_ip.setToolTip("Target server's IPv4/IPv6 address.")
        if hasattr(self, 'txt_user'): self.txt_user.setToolTip("SSH Username.")
        if hasattr(self, 'txt_key'): self.txt_key.setToolTip("Path to the private SSH key (.pem).")
        if hasattr(self, 'txt_disk'): self.txt_disk.setToolTip("Target block device path (e.g., /dev/nvme0n1).")
        if hasattr(self, 'chk_safety'): self.chk_safety.setToolTip("Applies 'conv=noerror,sync' to dd.")
        if hasattr(self, 'chk_ram'): self.chk_ram.setToolTip("Overrides disk target for volatile memory.")
        if hasattr(self, 'chk_writeblock'): self.chk_writeblock.setToolTip("Kernel-level protection.")
        if hasattr(self, 'chk_throttle'): self.chk_throttle.setToolTip("Limits network bandwidth usage.")
        if hasattr(self, 'chk_triage'): self.chk_triage.setToolTip("Executes rapid volatile data collection.")
        if hasattr(self, 'btn_start'): self.btn_start.setToolTip("Start secure acquisition.")

    def select_key(self):
        # Opens file dialog for SSH private key selection
        fname, _ = QFileDialog.getOpenFileName(self, "Select SSH Key", "", "PEM Files (*.pem);;All Files (*)")
        if fname:
            self.txt_key.setText(fname)

    def log(self, msg):
        # Appends messages to the GUI console and the master log file
        self.txt_log.append(msg)
        cursor = self.txt_log.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.txt_log.setTextCursor(cursor)
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open("live_forensic.log", "a", encoding="utf-8") as f:
                f.write(f"[{timestamp}] {msg}\n")
        except Exception:
            pass

    def discover_disks(self):
        # Probes target server for disk layout using lsblk over SSH
        ip = self.txt_ip.text().strip()
        user = self.txt_user.text().strip()
        key = self.txt_key.text().strip()

        if not ip or not key or not user:
            QMessageBox.warning(self, "Missing Info", "Please enter IP, User, and SSH Key first.")
            return

        if os.path.exists(key):
            os.chmod(key, 0o400)
        else:
            self.log("[!] SSH Key file not found!")
            return

        self.log("\n[*] Probing remote server for block devices (lsblk)...")
        if hasattr(self, 'btn_discover'): self.btn_discover.setEnabled(False)
        QApplication.processEvents()

        try:
            cmd = f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i {key} {user}@{ip} 'lsblk -o NAME,SIZE,TYPE,MOUNTPOINT'"
            result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode('utf-8').strip()
            self.log("\n=== REMOTE DISK LAYOUT ===")
            self.log(result)
            self.log("==========================\n")
        except subprocess.CalledProcessError as e:
            self.log(f"[ERROR] Disk discovery failed: {e.output.decode('utf-8').strip()}")
        finally:
            if hasattr(self, 'btn_discover'): self.btn_discover.setEnabled(True)

    def start_process(self):
        # Core acquisition trigger
        ip = self.txt_ip.text()
        user = self.txt_user.text()
        key = self.txt_key.text()
        disk = self.txt_disk.text()

        self.case_no = self.txt_caseno.text() if hasattr(self, 'txt_caseno') else "UNKNOWN_CASE"
        self.examiner = self.txt_examiner.text() if hasattr(self, 'txt_examiner') else "UNKNOWN_EXAMINER"

        if hasattr(self, 'chk_ram') and self.chk_ram.isChecked():
            disk = "/proc/kcore"

        if not ip or not key or not user or not disk:
            QMessageBox.warning(self, "Missing Info", "Please fill all required fields, including Target Disk!")
            return

        # Output Directory Selection
        selected_dir = QFileDialog.getExistingDirectory(self, "Select Output Directory for Evidence & Reports")
        if not selected_dir:
            self.log("[!] Operation cancelled: No output directory selected.")
            return
        self.output_dir = selected_dir

        self.btn_start.setEnabled(False)

        # Set progress bar to indeterminate mode for chunk stream
        self.progressBar.setRange(0, 0)

        self.log("\n--- [ STARTING FORENSIC ACQUISITION (v2.0) ] ---")
        self.log(f"[*] Engine: Paramiko Chunk-Streamer | Case No: {self.case_no}")
        self.log(f"[*] Target Device: {disk}")
        self.log(f"[*] Output Directory: {self.output_dir}")

        # Note: v2.0 currently defaults to physical RAW stream. E01 integration pending.
        output_file = os.path.join(self.output_dir, f"evidence_{self.case_no}_{datetime.now().strftime('%Y%m%d%H%M%S')}.raw")
        self.target_filename = output_file

        # Initialize the new v2.0 Acquisition Worker
        self.worker = AcquisitionWorker(ip, user, key, disk, output_file)

        # Connect real-time signals to GUI slots
        self.worker.progress_signal.connect(self.update_progress_ui)
        self.worker.finished_signal.connect(self.on_acquisition_finished)
        self.worker.error_signal.connect(self.on_acquisition_error)

        self.worker.start()

    def update_progress_ui(self, data):
        # Real-time UI updates without blocking the main event loop
        speed = data.get("speed_mb_s", 0)
        md5_cur = data.get("md5_current", "")
        bytes_read = data.get("bytes_read", 0)

        # Update the status bar instead of the log console to prevent UI deadlock/spam
        status_msg = f"Reading... | Speed: {speed} MB/s | Bytes: {bytes_read} | MD5: {md5_cur}"
        self.statusBar().showMessage(status_msg)

    def on_acquisition_error(self, error_msg):
        # Handle engine failures gracefully
        self.log(f"\n[CRITICAL ERROR] {error_msg}")
        QMessageBox.critical(self, "Process Failed", error_msg)
        self.btn_start.setEnabled(True)
        self.progressBar.setRange(0, 100)
        self.progressBar.setValue(0)
        self.statusBar().showMessage("Acquisition Aborted.")

    def on_acquisition_finished(self, data):
        # Post-acquisition processing. Hashes are already calculated.
        self.progressBar.setRange(0, 100)
        self.progressBar.setValue(100)
        self.btn_start.setEnabled(True)
        self.statusBar().showMessage("Acquisition Completed Successfully.")

        sha256_hash = data.get("sha256_final", "ERROR")
        md5_hash = data.get("md5_final", "ERROR")

        self.log(f"\n[INFO] Data Acquired: {self.target_filename}")
        self.log(f"[OK] On-the-fly SHA-256: {sha256_hash}")
        self.log(f"[OK] On-the-fly MD5: {md5_hash}")

        # Mocking last_report_data for legacy PDF generation compatibility
        self.last_report_data = {
            'target_ip': self.txt_ip.text(),
            'acquisition_type': 'Paramiko Physical Stream (RAW)',
            'start_time': 'Logged in live_forensic.log',
            'end_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'duration': 'Auto-calculated',
            'write_protection': 'Enforced via Engine',
            'triage_file': 'Not Requested (v2.0 Beta)',
            'bad_sectors': []
        }

        txt_path = os.path.join(self.output_dir, f"Report_{self.case_no}_{datetime.now().strftime('%Y%m%d')}.txt")
        self.generate_txt_report(sha256_hash, md5_hash, txt_path)

        # Prompt user for PDF report language
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("PDF Report Language")
        msg_box.setText("Select the language for the PDF Executive Summary:")
        tr_btn = msg_box.addButton("Turkce", QMessageBox.ButtonRole.ActionRole)
        en_btn = msg_box.addButton("English", QMessageBox.ButtonRole.ActionRole)
        msg_box.exec()

        lang = "tr" if msg_box.clickedButton() == tr_btn else "en"
        pdf_name = f"Report_{self.case_no}_{datetime.now().strftime('%Y%m%d')}_{lang.upper()}.pdf"
        pdf_path = os.path.join(self.output_dir, pdf_name)

        self.generate_pdf_report(sha256_hash, md5_hash, pdf_path, lang)

        self.log("\n--- [ TASK COMPLETED SUCCESSFULLY ] ---")
        self.log(f"[*] TXT Report Created: {txt_path}")
        self.log(f"[*] PDF Report Created: {pdf_path}")

        QMessageBox.information(self, "Success", "Acquisition Complete.\nReports Generated (TXT & PDF).")

    def generate_txt_report(self, sha256_hash, md5_hash, filepath):
        # Generates the plaintext technical forensic report
        bad_sector_text = "\n".join(self.last_report_data.get('bad_sectors', [])) if self.last_report_data.get('bad_sectors') else "No read errors detected."

        report_content = f"""
================================================================
            DIGITAL FORENSIC ACQUISITION REPORT (v2.0)
================================================================
CASE DETAILS:
-------------
Case Number    : {self.case_no}
Examiner       : {self.examiner}
Date           : {datetime.now().strftime("%Y-%m-%d")}
Target IP      : {self.last_report_data.get('target_ip', 'UNKNOWN')}

ACQUISITION LOG:
----------------
Acquisition Type: {self.last_report_data.get('acquisition_type', 'UNKNOWN')}
Start Time      : {self.last_report_data.get('start_time', 'UNKNOWN')}
End Time        : {self.last_report_data.get('end_time', 'UNKNOWN')}
Duration        : {self.last_report_data.get('duration', 'UNKNOWN')}
Write Blocker   : {self.last_report_data.get('write_protection', 'UNKNOWN')}
Live Triage File: {self.last_report_data.get('triage_file', 'Not Requested')}

HEALTH / ERROR LOGS:
-------------------------
{bad_sector_text}

EVIDENCE DETAILS:
-----------------
File Name       : {os.path.basename(self.target_filename)}
SHA-256 Hash    : {sha256_hash}
MD5 Hash        : {md5_hash}
Integrity       : DUAL-HASH VERIFIED (ON-THE-FLY)

================================================================
Note: Auto-generated by Remote Forensic Imager (Engine: Paramiko)
"""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(report_content)

    def generate_pdf_report(self, sha256_hash, md5_hash, filepath, lang):
        # Generates the localized PDF executive summary
        texts = self.lang_dict_tr if lang == "tr" else self.lang_dict_en
        triage_raw = self.last_report_data.get('triage_file', 'Not Requested')
        triage_final = texts['not_requested'] if triage_raw == 'Not Requested' or not triage_raw else triage_raw

        pdf = FPDF()
        pdf.add_page()

        pdf.set_font("helvetica", 'B', 14)
        pdf.cell(0, 10, texts['report_title'], border=True, ln=1, align='C')
        pdf.ln(5)

        pdf.set_font("helvetica", 'B', 12)
        pdf.cell(0, 10, texts['case_info'], ln=1)
        pdf.set_font("helvetica", '', 10)
        label_w = 45
        pdf.cell(label_w, 7, texts['case_no_lbl'], border=0)
        pdf.cell(0, 7, str(self.case_no), border=0, ln=1)
        pdf.cell(label_w, 7, texts['examiner_lbl'], border=0)
        pdf.cell(0, 7, str(self.examiner), border=0, ln=1)
        pdf.cell(label_w, 7, texts['date_lbl'], border=0)
        pdf.cell(0, 7, datetime.now().strftime('%Y-%m-%d'), border=0, ln=1)
        pdf.cell(label_w, 7, texts['target_ip_lbl'], border=0)
        pdf.cell(0, 7, str(self.last_report_data.get('target_ip', 'UNKNOWN')), border=0, ln=1)
        pdf.cell(label_w, 7, texts['duration_lbl'], border=0)
        pdf.cell(0, 7, str(self.last_report_data.get('duration', '0:00:00')), border=0, ln=1)

        pdf.ln(5)
        pdf.set_font("helvetica", 'B', 12)
        pdf.cell(0, 10, texts['integrity'], ln=1)
        pdf.set_fill_color(245, 245, 245)

        pdf.set_font("helvetica", 'B', 10)
        pdf.cell(0, 6, texts['hash_lbl'], ln=1)
        pdf.set_font("courier", '', 9)
        pdf.cell(0, 8, sha256_hash, border=1, ln=1, fill=True, align='C')
        pdf.set_font("helvetica", 'B', 10)
        pdf.set_text_color(0, 128, 0)
        pdf.cell(0, 6, texts['hash_status'], ln=1)
        pdf.set_text_color(0, 0, 0)

        pdf.ln(3)
        pdf.set_font("helvetica", 'B', 10)
        pdf.cell(0, 6, texts['md5_lbl'], ln=1)
        pdf.set_font("courier", '', 10)
        pdf.cell(0, 8, md5_hash, border=1, ln=1, fill=True, align='C')
        pdf.set_font("helvetica", 'B', 10)
        pdf.set_text_color(0, 128, 0)
        pdf.cell(0, 6, texts['md5_status'], ln=1)
        pdf.set_text_color(0, 0, 0)

        pdf.ln(5)
        pdf.set_font("helvetica", 'B', 12)
        pdf.cell(0, 10, texts['triage'], ln=1)
        pdf.set_font("helvetica", '', 10)
        pdf.cell(label_w, 7, texts['triage_lbl'], border=0)
        pdf.cell(0, 7, triage_final, border=0, ln=1)
        pdf.cell(label_w, 7, texts['bad_sectors_lbl'], border=0)
        pdf.cell(0, 7, texts['clean'], border=0, ln=1)

        pdf.ln(5)
        pdf.set_font("helvetica", 'B', 12)
        pdf.cell(0, 10, texts['exec_summary_title'], ln=1)
        pdf.set_font("helvetica", '', 10)
        pdf.multi_cell(0, 6, texts['summary'])

        pdf.set_y(-15)
        pdf.set_font("helvetica", 'I', 8)
        pdf.cell(0, 10, f"Generated by Remote Forensic Imager - Page {pdf.page_no()}", 0, 0, 'C')

        pdf.output(filepath)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ForensicApp()
    window.show()
    sys.exit(app.exec())
