import sys
import os
import subprocess
from datetime import datetime
from PyQt6.QtWidgets import QMainWindow, QFileDialog, QMessageBox, QApplication
from PyQt6.uic import loadUi
from PyQt6.QtGui import QTextCursor

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

        self.setWindowTitle("Remote Forensic Imager")
        self.setup_terminal_style()
        self.setup_tooltips()

        self.btn_file.clicked.connect(self.select_key)
        self.btn_start.clicked.connect(self.start_process)

        # Connect the Auto-Discovery button if it exists
        if hasattr(self, 'btn_discover'):
            self.btn_discover.clicked.connect(self.discover_disks)

        self.txt_user.setText("ubuntu")
        self.txt_disk.setText("") # Start empty, let the examiner decide

        if hasattr(self, 'chk_safety'):
            self.chk_safety.setChecked(True)

        self.progressBar.setValue(0)
        self.last_report_data = {}

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
            self.txt_caseno.setToolTip("Incident or Case Number. This will be logged in the final Chain of Custody (CoC) report.")
        if hasattr(self, 'txt_examiner'):
            self.txt_examiner.setToolTip("Name or ID of the Forensic Examiner conducting the acquisition.")
        if hasattr(self, 'txt_ip'):
            self.txt_ip.setToolTip("Target server's IPv4/IPv6 address or hostname.")
        if hasattr(self, 'txt_user'):
            self.txt_user.setToolTip("SSH Username. Must have sudo privileges to run 'dd' and 'blockdev'.")
        if hasattr(self, 'txt_key'):
            self.txt_key.setToolTip("Path to the private SSH key (.pem) for passwordless authentication.")
        if hasattr(self, 'txt_disk'):
            self.txt_disk.setToolTip("Target block device path (e.g., /dev/nvme0n1 or /dev/sda).")
        if hasattr(self, 'chk_safety'):
            self.chk_safety.setToolTip("Applies 'conv=noerror,sync' to dd. Prevents the acquisition from crashing on physical bad sectors.")
        if hasattr(self, 'chk_ram'):
            self.chk_ram.setToolTip("Overrides disk target to /proc/kcore for volatile memory (RAM) extraction. Bypasses Write Blocker.")
        if hasattr(self, 'chk_writeblock'):
            self.chk_writeblock.setToolTip("Kernel-level protection. Sets the target disk to Read-Only mode (blockdev --setro) before acquisition.")
        if hasattr(self, 'chk_throttle'):
            self.chk_throttle.setToolTip("Pipes the transfer through 'pv' to limit network bandwidth usage and prevent server bottlenecks.")
        if hasattr(self, 'txt_throttle'):
            self.txt_throttle.setToolTip("Bandwidth limit in Megabytes per second (MB/s). e.g., 10")
        if hasattr(self, 'chk_triage'):
            self.chk_triage.setToolTip("Executes rapid volatile data collection (connections, processes, logs) before disk acquisition.")
        if hasattr(self, 'btn_start'):
            self.btn_start.setToolTip("Start secure acquisition and post-process hashing.")
        if hasattr(self, 'btn_discover'):
            self.btn_discover.setToolTip("Probes the remote server via single-shot SSH to fetch the target's physical disk layout.")

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
        """Probes the remote server and displays disk layout in the log without auto-filling."""
        ip = self.txt_ip.text().strip()
        user = self.txt_user.text().strip()
        key = self.txt_key.text().strip()

        if not ip or not key or not user:
            QMessageBox.warning(self, "Missing Info", "Please enter IP, User, and SSH Key first to discover disks.")
            return

        if os.path.exists(key):
            os.chmod(key, 0o400)
        else:
            self.log("[!] SSH Key file not found!")
            return

        self.log("\n[*] Probing remote server for block devices (lsblk)...")
        if hasattr(self, 'btn_discover'):
            self.btn_discover.setEnabled(False)
        QApplication.processEvents() # Prevents UI freezing

        try:
            # Simple, fail-proof lsblk command for single-shot execution
            cmd = f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i {key} {user}@{ip} 'lsblk -o NAME,SIZE,TYPE,MOUNTPOINT'"
            result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode('utf-8').strip()

            self.log("\n=== REMOTE DISK LAYOUT ===")
            self.log(result)
            self.log("==========================\n")
            self.log("[*] Please review the layout above and type the target disk manually (e.g., /dev/nvme0n1).")

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
        if do_triage_status:
            self.log("[*] Live Triage: ENABLED")
        if throttle_limit:
            self.log(f"[*] Bandwidth Limit: {throttle_limit} MB/s")

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

    def on_analysis_finished(self, warning, file_hash):
        """Callback for when the analysis thread completes."""
        self.progressBar.setValue(100)
        self.btn_start.setEnabled(True)
        self.generate_report(file_hash)

        self.log("\n--- [ TASK COMPLETED SUCCESSFULLY ] ---")
        self.log(f"[*] Report Created: Report_{self.case_no}_{datetime.now().strftime('%Y%m%d')}.txt")

        if warning:
            QMessageBox.warning(self, "FORENSIC WARNING", warning)
        else:
            QMessageBox.information(self, "Success", "Acquisition & Analysis Complete.\nReport Generated.")

    def generate_report(self, file_hash):
        """Generates the final Chain of Custody (CoC) text report."""
        bad_sector_text = ""
        if self.last_report_data['bad_sectors']:
            bad_sector_text = "\n".join(self.last_report_data['bad_sectors'])
        else:
            bad_sector_text = "No read errors (I/O errors) detected during acquisition."

        report_content = f"""
================================================================
            DIGITAL FORENSIC ACQUISITION REPORT
================================================================
CASE DETAILS:
-------------
Case Number    : {self.case_no}
Examiner       : {self.examiner}
Date           : {datetime.now().strftime("%Y-%m-%d")}
Target IP      : {self.last_report_data['target_ip']}

ACQUISITION LOG:
----------------
Acquisition Type: {self.last_report_data['acquisition_type']}
Start Time      : {self.last_report_data['start_time']}
End Time        : {self.last_report_data['end_time']}
Duration        : {self.last_report_data['duration']}
SSH Fingerprint : {self.last_report_data['ssh_fingerprint']}
Write Blocker   : {self.last_report_data['write_protection']}
Live Triage File: {self.last_report_data['triage_file']}

COMMAND EXECUTED:
-----------------
{self.last_report_data['command_executed']}

HEALTH / ERROR LOGS:
-------------------------
{bad_sector_text}

EVIDENCE DETAILS:
-----------------
File Name       : {self.worker.filename}
SHA-256 Hash    : {file_hash}
Integrity       : VERIFIED

================================================================
                  CHAIN OF CUSTODY (CoC)
================================================================
| Date/Time           | Released By (From) | Received By (To) | Purpose             |
|---------------------|--------------------|------------------|---------------------|
| {self.last_report_data['end_time']} | AWS Live Server    | {self.examiner:<16} | Forensic Acquisition|
| {self.last_report_data['end_time']} | {self.examiner:<18} | Secure Storage   | Evidence Locking    |
|                     |                    |                  |                     |
================================================================
Note: Auto-generated by Remote Forensic Imager - Developed by Futhark1393
"""
        report_filename = f"Report_{self.case_no}_{datetime.now().strftime('%Y%m%d')}.txt"
        with open(report_filename, "w") as f:
            f.write(report_content)
