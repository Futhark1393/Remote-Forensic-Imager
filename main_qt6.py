import sys
import os
import subprocess
import time
from datetime import datetime
from PyQt6.QtWidgets import QApplication, QMainWindow, QFileDialog, QMessageBox
from PyQt6.uic import loadUi
from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtGui import QTextCursor

# ==========================================
# WORKER 1: DISK IMAGE ACQUISITION
# ==========================================
class AcquisitionThread(QThread):
    log_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str)

    def __init__(self, ip, user, key, disk, safe_mode):
        super().__init__()
        self.ip = ip
        self.user = user
        self.key = key
        self.disk = disk
        self.safe_mode = safe_mode
        # Filename format: evidence_YYYYMMDD_HHMMSS.img.gz
        self.filename = f"evidence_{datetime.now().strftime('%Y%m%d_%H%M%S')}.img.gz"

    def run(self):
        try:
            self.log_signal.emit(f"[*] Initiating Connection: {self.ip}")
            
            # 1. Key Security Check (AWS requires 400 permissions)
            if os.path.exists(self.key):
                os.chmod(self.key, 0o400)
            else:
                self.finished_signal.emit(False, "SSH Key file not found!")
                return

            # 2. Command Preparation
            # Safe Mode: Skip bad sectors (noerror), pad with zeros (sync)
            dd_flags = "conv=noerror,sync" if self.safe_mode else ""
            
            # Command: SSH -> Sudo DD -> Gzip -> Local File
            # StrictHostKeyChecking=no: Prevents "yes/no" prompt on first connect
            cmd = [
                "ssh", "-o", "StrictHostKeyChecking=no", "-i", self.key,
                f"{self.user}@{self.ip}",
                f"sudo dd if={self.disk} bs=64K {dd_flags} status=progress | gzip -1 -"
            ]

            self.log_signal.emit(f"[*] Sending Command: {' '.join(cmd)}")
            self.log_signal.emit("[*] Data stream started (Please wait)...")

            # 3. Execute Process
            with open(self.filename, "wb") as f:
                # Capture stderr for dd progress
                process = subprocess.Popen(cmd, stdout=f, stderr=subprocess.PIPE)
                process.wait()

            if process.returncode == 0:
                self.log_signal.emit("[SUCCESS] Data transfer completed.")
                self.finished_signal.emit(True, self.filename)
            else:
                # Read error message
                err = process.stderr.read().decode()
                self.finished_signal.emit(False, f"SSH/DD Error: {err}")

        except Exception as e:
            self.finished_signal.emit(False, str(e))

# ==========================================
# WORKER 2: ZIP BOMB / MALWARE ANALYSIS
# ==========================================
class AnalysisThread(QThread):
    log_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(str)

    def __init__(self, filename):
        super().__init__()
        self.filename = filename

    def run(self):
        self.log_signal.emit("\n--- [ SECURITY SCAN INITIATED ] ---")
        self.log_signal.emit(f"[*] Target File: {self.filename}")
        self.log_signal.emit("[*] Analyzing Binary Headers...")
        
        try:
            # Count ZIP headers (PK..) inside the file using Linux 'grep'
            # -a: Treat binary as text
            # -P: Use Perl regex
            # -c: Count only
            # \x50\x4B\x03\x04 -> Standard ZIP Header Signature
            cmd = f"grep -aPc '\\x50\\x4B\\x03\\x04' {self.filename}"
            
            # Execute command
            result = subprocess.check_output(cmd, shell=True).decode().strip()
            zip_count = int(result) if result.isdigit() else 0
            
            self.log_signal.emit(f"[*] Detected compressed block count: {zip_count}")

            warning_msg = ""
            # Threshold: 1000. If more than 1000 zip headers, it's suspicious.
            if zip_count > 1000:
                self.log_signal.emit("[!!!] THREAT DETECTED [!!!]")
                self.log_signal.emit("[!] File structure is overly complex or contains nested archives.")
                warning_msg = (
                    "WARNING: POTENTIAL ZIP BOMB DETECTED!\n"
                    f"The image contains {zip_count} compressed blocks.\n"
                    "Do not 'unzip' automatically. Use isolated forensic tools (Autopsy/FTK)."
                )
            else:
                self.log_signal.emit("[OK] File structure appears clean.")
                self.log_signal.emit("[OK] Ready for forensic analysis.")

            self.finished_signal.emit(warning_msg)

        except Exception as e:
            self.log_signal.emit(f"[!] Analysis error: {e}")
            self.finished_signal.emit("")

# ==========================================
# MAIN WINDOW (GUI)
# ==========================================
class ForensicApp(QMainWindow):
    def __init__(self):
        super().__init__()
        
        # 1. Load UI
        try:
            # Ensure your .ui file is named correctly here
            loadUi("forensic_qt6.ui", self)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not load UI File!\n{e}")
            sys.exit(1)

        # --- SET WINDOW TITLE ---
        self.setWindowTitle("Remote Forensic Imager - Developed by Futhark")
        # ------------------------

        # 2. Setup Hacker Style Log Console
        self.setup_terminal_style()

        # 3. Connect Buttons
        self.btn_file.clicked.connect(self.select_key)
        self.btn_start.clicked.connect(self.start_process)
        
        # 4. Set Defaults
        self.txt_user.setText("ubuntu")
        self.txt_disk.setText("/dev/nvme0n1") # Default for AWS T3/Nitro
        self.chk_safety.setChecked(True) # Safe Mode on by default
        self.progressBar.setValue(0)

    def setup_terminal_style(self):
        """Configures the log text area to look like a terminal."""
        self.txt_log.setReadOnly(True)
        style_sheet = """
            QTextEdit {
                background-color: #000000;
                color: #00FF00;
                font-family: "Monospace", "Courier New", "Consolas";
                font-size: 10pt;
                border: 1px solid #333;
                selection-background-color: #00FF00;
                selection-color: #000000;
            }
        """
        self.txt_log.setStyleSheet(style_sheet)
        self.log("--- SYSTEM READY ---")
        self.log("[*] Forensic Console Initialized.")
        self.log("[*] Standing by...")

    def select_key(self):
        fname, _ = QFileDialog.getOpenFileName(self, "Select SSH Key", "", "PEM Files (*.pem);;All Files (*)")
        if fname:
            self.txt_key.setText(fname)

    def log(self, msg):
        """Appends text to the log console and auto-scrolls."""
        self.txt_log.append(msg)
        # Scroll to bottom logic
        cursor = self.txt_log.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.txt_log.setTextCursor(cursor)

    def start_process(self):
        # Get Inputs
        ip = self.txt_ip.text()
        user = self.txt_user.text()
        key = self.txt_key.text()
        disk = self.txt_disk.text()

        # Basic Validation
        if not ip or not key or not user:
            QMessageBox.warning(self, "Missing Information", "Please fill in IP, User, and Key fields!")
            return

        # Lock UI
        self.btn_start.setEnabled(False)
        self.progressBar.setValue(5)
        self.log("\n--- [ STARTING NEW TASK ] ---")
        
        # Start Worker Thread
        self.worker = AcquisitionThread(ip, user, key, disk, self.chk_safety.isChecked())
        self.worker.log_signal.connect(self.log)
        self.worker.finished_signal.connect(self.on_acquisition_finished)
        self.worker.start()

    def on_acquisition_finished(self, success, result):
        if success:
            self.progressBar.setValue(50)
            self.log(f"[INFO] File saved: {result}")
            
            # Start Analysis Thread
            self.analyzer = AnalysisThread(result)
            self.analyzer.log_signal.connect(self.log)
            self.analyzer.finished_signal.connect(self.on_analysis_finished)
            self.analyzer.start()
        else:
            self.log(f"[ERROR] {result}")
            QMessageBox.critical(self, "Operation Failed", result)
            self.btn_start.setEnabled(True)
            self.progressBar.setValue(0)

    def on_analysis_finished(self, warning):
        self.progressBar.setValue(100)
        self.btn_start.setEnabled(True)
        self.log("\n--- [ TASK COMPLETED ] ---")
        
        if warning:
            QMessageBox.warning(self, "FORENSIC WARNING", warning)
        else:
            QMessageBox.information(self, "Success", "Image acquired successfully and marked as secure.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ForensicApp()
    window.show()
    sys.exit(app.exec())
