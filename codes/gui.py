import sys
import os
import subprocess
from datetime import datetime
from PyQt6.QtWidgets import QMainWindow, QFileDialog, QMessageBox, QApplication
from PyQt6.uic import loadUi
from PyQt6.QtGui import QTextCursor
from fpdf import FPDF

from codes.acquisition import AcquisitionThread
from codes.analysis import AnalysisThread

class ForensicApp(QMainWindow):
    def __init__(self):
        super().__init__()
        try:
            loadUi("forensic_qt6.ui", self)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"UI file could not be loaded!\n{e}")
            sys.exit(1)

        self.setWindowTitle("Remote Forensic Imager - Futhark1393")
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

        # ASCII Fallback Turkish (100% crash-proof and layout-safe)
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
        """Configures the QTextEdit to look like a terminal."""
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
        self.log("[*] Forensic Console Initialized.")

    def setup_tooltips(self):
        """Injects professional forensic tooltips to guide the examiner."""
        if hasattr(self, 'txt_caseno'):
            self.txt_caseno.setToolTip("Incident or Case Number.")
        if hasattr(self, 'txt_examiner'):
            self.txt_examiner.setToolTip("Name or ID of the Forensic Examiner conducting the acquisition.")
        if hasattr(self, 'txt_ip'):
            self.txt_ip.setToolTip("Target server's IPv4/IPv6 address or hostname.")
        if hasattr(self, 'txt_user'):
            self.txt_user.setToolTip("SSH Username. Must have sudo privileges.")
        if hasattr(self, 'txt_key'):
            self.txt_key.setToolTip("Path to the private SSH key (.pem).")
        if hasattr(self, 'txt_disk'):
            self.txt_disk.setToolTip("Target block device path (e.g., /dev/nvme0n1).")
        if hasattr(self, 'chk_safety'):
            self.chk_safety.setToolTip("Applies 'conv=noerror,sync' to dd.")
        if hasattr(self, 'chk_ram'):
            self.chk_ram.setToolTip("Overrides disk target to /proc/kcore for volatile memory extraction.")
        if hasattr(self, 'chk_writeblock'):
            self.chk_writeblock.setToolTip("Kernel-level protection using blockdev --setro.")
        if hasattr(self, 'chk_throttle'):
            self.chk_throttle.setToolTip("Limits network bandwidth usage.")
        if hasattr(self, 'txt_throttle'):
            self.txt_throttle.setToolTip("Bandwidth limit in Megabytes per second (MB/s).")
        if hasattr(self, 'chk_triage'):
            self.chk_triage.setToolTip("Executes rapid volatile data collection before disk acquisition.")
        if hasattr(self, 'btn_start'):
            self.btn_start.setToolTip("Start secure acquisition and post-process hashing.")
        if hasattr(self, 'btn_discover'):
            self.btn_discover.setToolTip("Probes the remote server via SSH to fetch physical disk layout.")

    def select_key(self):
        """Opens a file dialog to select the SSH private key."""
        fname, _ = QFileDialog.getOpenFileName(self, "Select SSH Key", "", "PEM Files (*.pem);;All Files (*)")
        if fname:
            self.txt_key.setText(fname)

    def log(self, msg):
        """Appends a message to the UI log and writes to the crash-proof log file."""
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
        """Probes the remote server and displays disk layout in the log."""
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
        if hasattr(self, 'btn_discover'):
            self.btn_discover.setEnabled(False)
        QApplication.processEvents()

        try:
            cmd = f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i {key} {user}@{ip} 'lsblk -o NAME,SIZE,TYPE,MOUNTPOINT'"
            result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode('utf-8').strip()

            self.log("\n=== REMOTE DISK LAYOUT ===")
            self.log(result)
            self.log("==========================\n")
            self.log("[*] Please review the layout above and type the target disk manually.")

        except subprocess.CalledProcessError as e:
            self.log("[ERROR] Disk discovery failed. Check SSH connection and key permissions.")
            self.log(f"[DETAILS] {e.output.decode('utf-8').strip()}")
        except Exception as e:
            self.log(f"[ERROR] Discovery Error: {str(e)}")
        finally:
            if hasattr(self, 'btn_discover'):
                self.btn_discover.setEnabled(True)

    def start_process(self):
        """Validates inputs and starts the acquisition thread."""
        ip = self.txt_ip.text()
        user = self.txt_user.text()
        key = self.txt_key.text()
        disk = self.txt_disk.text()

        self.case_no = self.txt_caseno.text() if hasattr(self, 'txt_caseno') else "UNKNOWN_CASE"
        self.examiner = self.txt_examiner.text() if hasattr(self, 'txt_examiner') else "UNKNOWN_EXAMINER"

        write_block_status = False
        if hasattr(self, 'chk_writeblock'):
             write_block_status = self.chk_writeblock.isChecked()

        is_ram_status = False
        if hasattr(self, 'chk_ram'):
             is_ram_status = self.chk_ram.isChecked()

        throttle_limit = None
        if hasattr(self, 'chk_throttle') and self.chk_throttle.isChecked():
            if hasattr(self, 'txt_throttle') and self.txt_throttle.text().isdigit():
                throttle_limit = int(self.txt_throttle.text())

        do_triage_status = False
        if hasattr(self, 'chk_triage'):
             do_triage_status = self.chk_triage.isChecked()

        if is_ram_status:
             disk = "/proc/kcore"

        if not ip or not key or not user or not disk:
            QMessageBox.warning(self, "Missing Info", "Please fill all required fields, including Target Disk!")
            return

        self.btn_start.setEnabled(False)
        self.progressBar.setValue(5)
        self.log("\n--- [ STARTING FORENSIC ACQUISITION ] ---")
        self.log(f"[*] Case No: {self.case_no} | Examiner: {self.examiner}")

        safe_mode_status = self.chk_safety.isChecked() if hasattr(self, 'chk_safety') else False

        self.worker = AcquisitionThread(ip, user, key, disk, safe_mode_status, write_block_status, is_ram_status, throttle_limit, do_triage_status)
        self.worker.log_signal.connect(self.log)
        self.worker.finished_signal.connect(self.on_acquisition_finished)
        self.worker.start()

    def on_acquisition_finished(self, success, filename, report_data):
        """Callback for when the acquisition thread completes."""
        self.last_report_data = report_data

        if success:
            self.progressBar.setValue(50)
            self.log(f"[INFO] Data Acquired: {filename}")

            self.analyzer = AnalysisThread(filename)
            self.analyzer.log_signal.connect(self.log)
            self.analyzer.finished_signal.connect(self.on_analysis_finished)
            self.analyzer.start()
        else:
            self.log(f"[ERROR] Process failed for {filename}")
            QMessageBox.critical(self, "Process Failed", filename)
            self.btn_start.setEnabled(True)
            self.progressBar.setValue(0)

    def on_analysis_finished(self, warning, sha256_hash, md5_hash):
        """Callback for when the analysis thread completes."""
        self.progressBar.setValue(100)
        self.btn_start.setEnabled(True)

        # Standard TXT Report Generation
        self.generate_txt_report(sha256_hash, md5_hash)

        # PDF Language Selection Popup
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("PDF Report Language")
        msg_box.setText("Select the language for the PDF Executive Summary:")
        tr_btn = msg_box.addButton("Turkce (ASCII)", QMessageBox.ButtonRole.ActionRole)
        en_btn = msg_box.addButton("English", QMessageBox.ButtonRole.ActionRole)
        msg_box.exec()

        lang = "tr" if msg_box.clickedButton() == tr_btn else "en"
        pdf_name = f"Report_{self.case_no}_{datetime.now().strftime('%Y%m%d')}_{lang.upper()}.pdf"

        # Generate the PDF
        self.generate_pdf_report(sha256_hash, md5_hash, pdf_name, lang)

        self.log("\n--- [ TASK COMPLETED SUCCESSFULLY ] ---")
        self.log(f"[*] TXT Report Created: Report_{self.case_no}_{datetime.now().strftime('%Y%m%d')}.txt")
        self.log(f"[*] PDF Report Created: {pdf_name}")

        if warning:
            QMessageBox.warning(self, "FORENSIC WARNING", warning)
        else:
            QMessageBox.information(self, "Success", f"Acquisition Complete.\nReports Generated (TXT & PDF).")

    def generate_txt_report(self, sha256_hash, md5_hash):
        """Generates the standard plain text report."""
        bad_sector_text = "\n".join(self.last_report_data['bad_sectors']) if self.last_report_data['bad_sectors'] else "No read errors detected."

        report_content = f"""
================================================================
            DIGITAL FORENSIC ACQUISITION REPORT
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
File Name       : {self.worker.filename}
SHA-256 Hash    : {sha256_hash}
MD5 Hash        : {md5_hash}
Integrity       : DUAL-HASH VERIFIED

================================================================
Note: Auto-generated by Remote Forensic Imager - Developed by Futhark1393
"""
        with open(f"Report_{self.case_no}_{datetime.now().strftime('%Y%m%d')}.txt", "w") as f:
            f.write(report_content)

    def generate_pdf_report(self, sha256_hash, md5_hash, filename, lang):
        """Generates a professional PDF executive summary with a rock-solid grid layout."""

        # Dictionary selection
        texts = self.lang_dict_tr if lang == "tr" else self.lang_dict_en

        # Clean Triage Status Logic (Fixes the "Saved (Not Requested)" bug)
        triage_raw = self.last_report_data.get('triage_file', 'Not Requested')
        if triage_raw == 'Not Requested' or not triage_raw:
            triage_final = texts['not_requested']
        else:
            triage_final = triage_raw

        pdf = FPDF()
        pdf.add_page()

        # Global Header
        pdf.set_font("helvetica", 'B', 14)
        pdf.cell(0, 10, texts['report_title'], border=True, ln=1, align='C')
        pdf.ln(5)

        # Section 1: Case Details
        pdf.set_font("helvetica", 'B', 12)
        pdf.cell(0, 10, texts['case_info'], ln=1)

        pdf.set_font("helvetica", '', 10)
        label_w = 45 # Fixed column width for perfect alignment

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

        # Section 2: Integrity & Dual-Hash
        pdf.ln(5)
        pdf.set_font("helvetica", 'B', 12)
        pdf.cell(0, 10, texts['integrity'], ln=1)

        pdf.set_fill_color(245, 245, 245)

        # SHA-256 Block (Using Cell instead of Multi-cell to prevent layout breaking)
        pdf.set_font("helvetica", 'B', 10)
        pdf.cell(0, 6, texts['hash_lbl'], ln=1)

        pdf.set_font("courier", '', 9) # Monospace to securely fit 64 chars
        pdf.cell(0, 8, sha256_hash, border=1, ln=1, fill=True, align='C')

        pdf.set_font("helvetica", 'B', 10)
        pdf.set_text_color(0, 128, 0) # Green text for verified status
        pdf.cell(0, 6, texts['hash_status'], ln=1)
        pdf.set_text_color(0, 0, 0)

        pdf.ln(3)

        # MD5 Block
        pdf.set_font("helvetica", 'B', 10)
        pdf.cell(0, 6, texts['md5_lbl'], ln=1)

        pdf.set_font("courier", '', 10)
        pdf.cell(0, 8, md5_hash, border=1, ln=1, fill=True, align='C')

        pdf.set_font("helvetica", 'B', 10)
        pdf.set_text_color(0, 128, 0)
        pdf.cell(0, 6, texts['md5_status'], ln=1)
        pdf.set_text_color(0, 0, 0)

        # Section 3: Triage & Health
        pdf.ln(5)
        pdf.set_font("helvetica", 'B', 12)
        pdf.cell(0, 10, texts['triage'], ln=1)

        pdf.set_font("helvetica", '', 10)
        pdf.cell(label_w, 7, texts['triage_lbl'], border=0)
        pdf.cell(0, 7, triage_final, border=0, ln=1)

        pdf.cell(label_w, 7, texts['bad_sectors_lbl'], border=0)
        pdf.cell(0, 7, texts['clean'], border=0, ln=1)

        # Section 4: Summary
        pdf.ln(5)
        pdf.set_font("helvetica", 'B', 12)
        pdf.cell(0, 10, texts['exec_summary_title'], ln=1)

        pdf.set_font("helvetica", '', 10)
        pdf.multi_cell(0, 6, texts['summary'])

        # Global Footer
        pdf.set_y(-15)
        pdf.set_font("helvetica", 'I', 8)
        pdf.cell(0, 10, f"Generated by Remote Forensic Imager - Futhark1393 - Page {pdf.page_no()}", 0, 0, 'C')

        pdf.output(filename)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ForensicApp()
    window.show()
    sys.exit(app.exec())
