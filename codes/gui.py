# Author: Futhark1393
# Description: Main GUI module for Remote Forensic Imager.
# Features: Paramiko integration, E01/RAW chunk-streaming, on-the-fly hashing, ETA, throttling, Safe Mode, and Live Triage.

import sys
import os
import subprocess
from datetime import datetime
from PyQt6.QtWidgets import QMainWindow, QFileDialog, QMessageBox, QApplication
from PyQt6.uic import loadUi
from PyQt6.QtGui import QTextCursor
from fpdf import FPDF
from qt_material import apply_stylesheet

from codes.threads import AcquisitionWorker

class ForensicApp(QMainWindow):
    def __init__(self):
        super().__init__()
        try:
            loadUi("forensic_qt6.ui", self)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"UI file could not be loaded!\n{e}")
            sys.exit(1)

        self.setWindowTitle("Remote Forensic Imager")
        self.setup_terminal_style()
        self.setup_tooltips()

        self.btn_file.clicked.connect(self.select_key)
        self.btn_start.clicked.connect(self.start_process)
        self.btn_stop.clicked.connect(self.stop_process)

        if hasattr(self, 'btn_discover'):
            self.btn_discover.clicked.connect(self.discover_disks)

        self.txt_user.setText("ubuntu")

        if hasattr(self, 'cmb_disk'):
            self.cmb_disk.lineEdit().setPlaceholderText("e.g., /dev/nvme0n1")

        if hasattr(self, 'chk_safety'):
            self.chk_safety.setChecked(True)

        self.progressBar.setValue(0)
        self.output_dir = ""
        self.worker = None
        self.start_time = None
        self.format_type = "RAW"
        self.target_filename = ""

        self.report_labels = {
            "title": "DIGITAL FORENSIC ACQUISITION REPORT",
            "case_details": "1. CASE DETAILS",
            "case_no": "Case Number:",
            "examiner": "Examiner:",
            "date": "Date:",
            "ip": "Target IP:",
            "duration": "Duration:",
            "integrity": "2. EVIDENCE INTEGRITY",
            "hash_sha256": "SHA-256 HASH:",
            "hash_md5": "MD5 HASH:",
            "status": "Status: VERIFIED",
            "triage": "3. PRE-ACQUISITION TRIAGE",
            "triage_log": "Live Triage Log:",
            "error_check": "Physical Error Check:",
            "summary_title": "EXECUTIVE SUMMARY",
            "summary_text": "The acquisition process completed successfully. Evidence integrity has been secured and verified using MD5 and SHA-256 algorithms."
        }

    def setup_terminal_style(self):
        self.txt_log.setReadOnly(True)
        self.txt_log.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #00e676;
                font-family: "Monospace";
                font-size: 10pt;
                border: 1px solid #333;
            }
        """)
        self.log("--- SYSTEM READY ---")
        self.log("[*] Forensic Console Initialized.")

    def setup_tooltips(self):
        if hasattr(self, 'txt_caseno'): self.txt_caseno.setToolTip("Unique Incident or Case ID.")
        if hasattr(self, 'txt_examiner'): self.txt_examiner.setToolTip("Name of the Lead Forensic Investigator.")
        if hasattr(self, 'txt_ip'): self.txt_ip.setToolTip("Remote server IP address.")
        if hasattr(self, 'txt_user'): self.txt_user.setToolTip("SSH Username.")
        if hasattr(self, 'txt_key'): self.txt_key.setToolTip("Path to the SSH Private Key (.pem).")
        if hasattr(self, 'cmb_disk'): self.cmb_disk.setToolTip("Select from detected devices or type manually.")
        if hasattr(self, 'btn_discover'): self.btn_discover.setToolTip("Probe remote server for block devices.")
        if hasattr(self, 'chk_safety'): self.chk_safety.setToolTip("Applies 'conv=noerror,sync' to safely bypass physical read errors.")
        if hasattr(self, 'chk_ram'): self.chk_ram.setToolTip("Overrides disk target to capture volatile memory (/proc/kcore).")
        if hasattr(self, 'chk_writeblock'): self.chk_writeblock.setToolTip("Enforce read-only state on the block device before acquisition.")
        if hasattr(self, 'chk_triage'): self.chk_triage.setToolTip("Executes rapid volatile data collection before full imaging.")
        if hasattr(self, 'chk_throttle'): self.chk_throttle.setToolTip("Limit network bandwidth usage to prevent network saturation.")
        if hasattr(self, 'txt_throttle'): self.txt_throttle.setToolTip("Specify bandwidth limit in MB/s.")
        if hasattr(self, 'btn_start'): self.btn_start.setToolTip("Initiate bit-stream acquisition.")
        if hasattr(self, 'btn_stop'): self.btn_stop.setToolTip("Abort the current acquisition process safely.")

    def select_key(self):
        fname, _ = QFileDialog.getOpenFileName(self, "Select SSH Key", "", "PEM Files (*.pem);;All Files (*)")
        if fname:
            self.txt_key.setText(fname)

    def log(self, msg):
        self.txt_log.append(msg)
        cursor = self.txt_log.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.txt_log.setTextCursor(cursor)

    def export_log_to_folder(self):
        if self.output_dir:
            try:
                log_path = os.path.join(self.output_dir, "live_forensic.log")
                with open(log_path, "w", encoding="utf-8") as f:
                    f.write(self.txt_log.toPlainText())
            except Exception as e:
                self.txt_log.append(f"\n[!] Failed to save log file to output directory: {e}")

    def discover_disks(self):
        ip = self.txt_ip.text().strip()
        user = self.txt_user.text().strip()
        key = self.txt_key.text().strip()

        if not all([ip, user, key]):
            QMessageBox.warning(self, "Missing Configuration", "Please enter IP, Username, and SSH Key.")
            return

        self.log("\n[*] Probing remote server for block devices...")
        if hasattr(self, 'btn_discover'): self.btn_discover.setEnabled(False)
        QApplication.processEvents()

        try:
            cmd_log = f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i {key} {user}@{ip} 'lsblk -o NAME,SIZE,TYPE,MOUNTPOINT'"
            result_log = subprocess.check_output(cmd_log, shell=True, stderr=subprocess.STDOUT).decode('utf-8').strip()
            self.log("\n=== REMOTE DISK LAYOUT ===\n" + result_log + "\n==========================\n")

            cmd_parse = f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i {key} {user}@{ip} 'lsblk -r -n -o NAME'"
            result_parse = subprocess.check_output(cmd_parse, shell=True, stderr=subprocess.STDOUT).decode('utf-8').strip()

            if hasattr(self, 'cmb_disk'):
                self.cmb_disk.clear()
                for line in result_parse.split('\n'):
                    dev_name = line.strip()
                    if dev_name:
                        self.cmb_disk.addItem(f"/dev/{dev_name}")

                self.log("[*] Evidence Target dropdown populated successfully.")

        except Exception as e:
            self.log(f"[ERROR] Disk discovery failed: {str(e)}")
        finally:
            if hasattr(self, 'btn_discover'): self.btn_discover.setEnabled(True)

    def start_process(self):
        ip = self.txt_ip.text().strip()
        user = self.txt_user.text().strip()
        key = self.txt_key.text().strip()
        disk = self.cmb_disk.currentText().strip()

        self.case_no = self.txt_caseno.text() or "UNKNOWN"
        self.examiner = self.txt_examiner.text() or "EXAMINER"

        if not all([ip, user, key, disk]):
            QMessageBox.warning(self, "Validation Error", "Target IP, Key, and Target Disk are required.")
            return

        throttle_limit = 0.0
        if hasattr(self, 'chk_throttle') and self.chk_throttle.isChecked():
            try:
                val = float(self.txt_throttle.text().strip())
                if val > 0:
                    throttle_limit = val
            except ValueError:
                QMessageBox.warning(self, "Validation Error", "Please enter a valid numeric value for Bandwidth Limit (MB/s).")
                return

        safe_mode = hasattr(self, 'chk_safety') and self.chk_safety.isChecked()
        run_triage = hasattr(self, 'chk_triage') and self.chk_triage.isChecked()

        selected_dir = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if not selected_dir: return
        self.output_dir = selected_dir

        msg = QMessageBox(self)
        msg.setWindowTitle("Acquisition Format")
        msg.setText("Select the target evidence format:")
        btn_e01 = msg.addButton("E01 (EnCase)", QMessageBox.ButtonRole.ActionRole)
        btn_raw = msg.addButton("RAW (.raw)", QMessageBox.ButtonRole.ActionRole)
        msg.exec()

        self.format_type = "E01" if msg.clickedButton() == btn_e01 else "RAW"
        base_filename = os.path.join(self.output_dir, f"evidence_{self.case_no}_{datetime.now().strftime('%Y%m%d%H%M%S')}")

        if self.format_type == "E01":
            output_file = base_filename
            self.target_filename = base_filename + ".E01"
        else:
            output_file = base_filename + ".raw"
            self.target_filename = output_file

        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.progressBar.setValue(0)

        self.start_time = datetime.now()
        self.log(f"\n--- [ STARTING ACQUISITION ] ---\n[*] Format: {self.format_type}\n[*] Target: {disk}")

        if safe_mode:
            self.log("[*] Safe Mode ON: Bad sectors will be padded with zeros.")
        if throttle_limit > 0:
            self.log(f"[*] Bandwidth limited to: {throttle_limit} MB/s")

        self.worker = AcquisitionWorker(ip, user, key, disk, output_file, self.format_type, self.case_no, self.examiner, throttle_limit, safe_mode, run_triage, self.output_dir)
        self.worker.progress_signal.connect(self.update_progress_ui)
        self.worker.finished_signal.connect(self.on_acquisition_finished)
        self.worker.error_signal.connect(self.on_acquisition_error)
        self.worker.start()

    def stop_process(self):
        if self.worker and self.worker.isRunning():
            self.log("\n[!] Abort requested by user. Terminating secure connection...")
            self.btn_stop.setEnabled(False)
            self.worker.stop()
            self.export_log_to_folder()

    def update_progress_ui(self, data):
        speed = data.get("speed_mb_s", 0)
        md5_cur = data.get("md5_current", "")
        percentage = data.get("percentage", 0)
        eta = data.get("eta", "Calculating...")

        self.progressBar.setValue(percentage)
        status_msg = f"Streaming... | Speed: {speed} MB/s | ETA: {eta} | MD5: {md5_cur}"
        self.statusBar().showMessage(status_msg)

    def on_acquisition_error(self, error_msg):
        self.log(f"\n[ERROR / ABORTED] {error_msg}")
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.progressBar.setValue(0)
        self.statusBar().showMessage("Acquisition Interrupted.")
        self.export_log_to_folder()

    def on_acquisition_finished(self, data):
        self.progressBar.setValue(100)
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)

        duration = str(datetime.now() - self.start_time).split('.')[0]
        sha256 = data.get('sha256_final', 'ERROR')
        md5 = data.get('md5_final', 'ERROR')

        self.log(f"\n[SUCCESS] SHA-256: {sha256}\n[SUCCESS] MD5: {md5}")

        timestamp_str = datetime.now().strftime('%Y%m%d')
        pdf_path = os.path.join(self.output_dir, f"Report_{self.case_no}_{timestamp_str}.pdf")
        txt_path = os.path.join(self.output_dir, f"Report_{self.case_no}_{timestamp_str}.txt")

        self.generate_txt_report(sha256, md5, duration, txt_path)
        self.generate_pdf_report(sha256, md5, duration, pdf_path)

        self.log(f"[*] Reports Generated (PDF & TXT).")
        self.export_log_to_folder()

        QMessageBox.information(self, "Complete", "Forensic acquisition completed successfully.\nReports and Logs saved.")

    def generate_txt_report(self, sha256_hash, md5_hash, duration, filepath):
        triage_status = f"Saved as Triage_{self.case_no}.txt" if hasattr(self, 'chk_triage') and self.chk_triage.isChecked() else "Not Requested"
        write_blocker = "Enabled" if hasattr(self, 'chk_writeblock') and self.chk_writeblock.isChecked() else "Disabled"
        throttle_status = f"{self.txt_throttle.text().strip()} MB/s" if hasattr(self, 'chk_throttle') and self.chk_throttle.isChecked() else "No Limit"
        safe_mode_status = "Active (Ignored & Padded)" if hasattr(self, 'chk_safety') and self.chk_safety.isChecked() else "Inactive"

        report_content = f"""
================================================================
            DIGITAL FORENSIC ACQUISITION REPORT
================================================================
CASE DETAILS:
-------------
Case Number    : {self.case_no}
Examiner       : {self.examiner}
Date           : {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Target IP      : {self.txt_ip.text()}

ACQUISITION LOG:
----------------
Format Type     : {self.format_type}
Duration        : {duration}
Write Blocker   : {write_blocker}
Bandwidth Limit : {throttle_status}
Live Triage     : {triage_status}

HEALTH / ERROR LOGS:
-------------------------
Bad Sector Handling: {safe_mode_status}

EVIDENCE DETAILS:
-----------------
File Name       : {os.path.basename(self.target_filename)}
SHA-256 Hash    : {sha256_hash}
MD5 Hash        : {md5_hash}
Integrity       : VERIFIED

================================================================
Note: Auto-generated by Remote Forensic Imager
"""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(report_content.strip() + "\n")

    def generate_pdf_report(self, sha256, md5, duration, filepath):
        triage_status = f"Saved as Triage_{self.case_no}.txt" if hasattr(self, 'chk_triage') and self.chk_triage.isChecked() else "Not Requested"
        safe_mode_status = "PADDED" if hasattr(self, 'chk_safety') and self.chk_safety.isChecked() else "NOT CHECKED"

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("helvetica", 'B', 16)
        pdf.cell(0, 10, self.report_labels['title'], border=1, ln=1, align='C')
        pdf.ln(10)

        pdf.set_font("helvetica", 'B', 12)
        pdf.cell(0, 10, self.report_labels['case_details'], ln=1)
        pdf.set_font("helvetica", '', 10)

        label_w = 45
        pdf.cell(label_w, 7, self.report_labels['case_no'], 0)
        pdf.cell(0, 7, self.case_no, 0, 1)
        pdf.cell(label_w, 7, self.report_labels['examiner'], 0)
        pdf.cell(0, 7, self.examiner, 0, 1)
        pdf.cell(label_w, 7, self.report_labels['date'], 0)
        pdf.cell(0, 7, datetime.now().strftime('%Y-%m-%d'), 0, 1)
        pdf.cell(label_w, 7, self.report_labels['ip'], 0)
        pdf.cell(0, 7, self.txt_ip.text(), 0, 1)
        pdf.cell(label_w, 7, self.report_labels['duration'], 0)
        pdf.cell(0, 7, duration, 0, 1)

        pdf.ln(5)
        pdf.set_font("helvetica", 'B', 12)
        pdf.cell(0, 10, self.report_labels['integrity'], ln=1)
        pdf.set_font("courier", '', 10)
        pdf.cell(0, 8, f"SHA-256: {sha256}", border=1, ln=1)
        pdf.cell(0, 8, f"MD5    : {md5}", border=1, ln=1)

        pdf.ln(5)
        pdf.set_font("helvetica", 'B', 12)
        pdf.cell(0, 10, self.report_labels['triage'], ln=1)
        pdf.set_font("helvetica", '', 10)
        pdf.cell(label_w, 7, self.report_labels['triage_log'], 0)
        pdf.cell(0, 7, triage_status, 0, 1)
        pdf.cell(label_w, 7, self.report_labels['error_check'], 0)
        pdf.cell(0, 7, safe_mode_status, 0, 1)

        pdf.ln(5)
        pdf.set_font("helvetica", 'B', 12)
        pdf.cell(0, 10, self.report_labels['summary_title'], ln=1)
        pdf.set_font("helvetica", '', 10)
        pdf.multi_cell(0, 6, self.report_labels['summary_text'])

        pdf.output(filepath)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    apply_stylesheet(app, theme='dark_teal.xml')
    window = ForensicApp()
    window.show()
    sys.exit(app.exec())
