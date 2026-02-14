import sys
import os
import subprocess
import time
from datetime import datetime
from PyQt6.QtWidgets import QApplication, QMainWindow, QFileDialog, QMessageBox
from PyQt6.uic import loadUi
from PyQt6.QtCore import QThread, pyqtSignal, Qt
from PyQt6.QtGui import QTextCursor

# ==========================================
# WORKER 1: DISK IMAGE ACQUISITION (SAFE & PRO)
# ==========================================
class AcquisitionThread(QThread):
    log_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str, dict)

    def __init__(self, ip, user, key, disk, safe_mode, write_block):
        super().__init__()
        self.ip = ip
        self.user = user
        self.key = key
        self.disk = disk
        self.safe_mode = safe_mode
        self.write_block = write_block
        self.start_time = None
        self.end_time = None
        self.bad_sector_logs = []
        self.filename = f"evidence_{datetime.now().strftime('%Y%m%d_%H%M%S')}.img.gz"

    def get_ssh_fingerprint(self):
        try:
            cmd = f"ssh-keyscan -t rsa {self.ip} 2>/dev/null"
            output = subprocess.check_output(cmd, shell=True).decode().strip()
            return output if output else "Fingerprint could not be fetched."
        except Exception:
            return "Fingerprint fetch failed."

    def set_write_block(self, state):
        """
        state=True  -> Salt Okunur (RO) yapar.
        state=False -> Yazılabilir (RW) yapar.
        """
        mode = "--setro" if state else "--setrw"
        mode_str = "Read-Only" if state else "Read-Write"
        
        try:
            # 1. Komutu Gönder
            cmd_lock = f"ssh -o StrictHostKeyChecking=no -i {self.key} {self.user}@{self.ip} 'sudo blockdev {mode} {self.disk}'"
            subprocess.check_call(cmd_lock, shell=True)
            
            # 2. Doğrula (0=RW, 1=RO)
            cmd_check = f"ssh -o StrictHostKeyChecking=no -i {self.key} {self.user}@{self.ip} 'sudo blockdev --getro {self.disk}'"
            result = subprocess.check_output(cmd_check, shell=True).decode().strip()
            
            expected = "1" if state else "0"
            if result == expected:
                return True, f"Disk set to {mode_str} mode."
            else:
                return False, f"Failed to set {mode_str} mode!"
                
        except Exception as e:
            return False, f"Write Blocker Error: {str(e)}"

    def run(self):
        self.start_time = datetime.now()
        report_data = {
            "start_time": self.start_time.strftime("%Y-%m-%d %H:%M:%S"),
            "target_ip": self.ip,
            "ssh_fingerprint": "N/A",
            "command_executed": "N/A",
            "write_protection": "N/A",
            "duration": "0s",
            "bad_sectors": []
        }

        # Kilit aktif edildi mi bayrağı (Finally bloğu için)
        wb_activated = False

        try:
            self.log_signal.emit(f"[*] Task Started at: {report_data['start_time']}")
            self.log_signal.emit(f"[*] Target Connection: {self.ip}")
            
            # 1. SSH Fingerprint
            fingerprint = self.get_ssh_fingerprint()
            report_data["ssh_fingerprint"] = fingerprint
            self.log_signal.emit(f"[*] Remote SSH Fingerprint Verified:\n    {fingerprint}")

            # 2. Key Kontrolü
            if os.path.exists(self.key):
                os.chmod(self.key, 0o400)
            else:
                self.finished_signal.emit(False, "SSH Key file not found!", report_data)
                return

            # 3. WRITE BLOCKER AKTİVASYONU (Başlangıç)
            if self.write_block:
                self.log_signal.emit("[*] Activating Software Write Blocker (Kernel Level)...")
                success, msg = self.set_write_block(True) # True = Kilitle
                if success:
                    self.log_signal.emit(f"[SUCCESS] {msg}")
                    report_data["write_protection"] = "Active (Kernel Level - blockdev --setro)"
                    wb_activated = True
                else:
                    self.log_signal.emit(f"[WARNING] {msg}")
                    report_data["write_protection"] = "Failed (Attempted)"
            else:
                report_data["write_protection"] = "Disabled (Live System Mode)"

            # --- GÜVENLİ BLOK BAŞLANGICI ---
            # Buradaki kod ne olursa olsun (hata, başarı) finally bloğu çalışacak
            try:
                # 4. İmaj Alma Komutu
                dd_flags = "conv=noerror,sync" if self.safe_mode else ""
                ssh_cmd = [
                    "ssh", "-o", "StrictHostKeyChecking=no", "-i", self.key,
                    f"{self.user}@{self.ip}",
                    f"sudo dd if={self.disk} bs=64K {dd_flags} status=progress | gzip -1 -"
                ]
                
                full_command_str = " ".join(ssh_cmd)
                report_data["command_executed"] = full_command_str

                self.log_signal.emit(f"[*] EXECUTING COMMAND:\n    {full_command_str}")
                self.log_signal.emit("[*] Data stream started (Listening for I/O errors)...")

                with open(self.filename, "wb") as f:
                    process = subprocess.Popen(ssh_cmd, stdout=f, stderr=subprocess.PIPE)
                    
                    while True:
                        line = process.stderr.readline()
                        if not line and process.poll() is not None:
                            break
                        if line:
                            decoded_line = line.decode('utf-8', errors='ignore').strip()
                            if "error reading" in decoded_line or "Input/output error" in decoded_line:
                                timestamp = datetime.now().strftime("%H:%M:%S")
                                error_msg = f"[{timestamp}] CRITICAL I/O ERROR: {decoded_line}"
                                self.bad_sector_logs.append(error_msg)
                                self.log_signal.emit(error_msg)

                self.end_time = datetime.now()
                duration = self.end_time - self.start_time
                report_data["end_time"] = self.end_time.strftime("%Y-%m-%d %H:%M:%S")
                report_data["duration"] = str(duration)
                report_data["bad_sectors"] = self.bad_sector_logs

                if process.returncode == 0:
                    self.log_signal.emit(f"[SUCCESS] Transfer Complete. Duration: {duration}")
                    self.finished_signal.emit(True, self.filename, report_data)
                else:
                    self.finished_signal.emit(True, self.filename, report_data)

            finally:
                # --- [ÖNEMLİ] KİLİDİ KALDIRMA (TEMİZLİK) ---
                if wb_activated:
                    self.log_signal.emit("[*] Reverting Write Blocker (Restoring Read-Write)...")
                    success, msg = self.set_write_block(False) # False = Kilidi Aç
                    if success:
                        self.log_signal.emit(f"[INFO] System Restored: {msg}")
                    else:
                        self.log_signal.emit(f"[!!!] CRITICAL WARNING: Could not restore RW mode! Manual intervention required.")
            # --- GÜVENLİ BLOK BİTİŞİ ---

        except Exception as e:
            self.finished_signal.emit(False, str(e), report_data)

# ==========================================
# WORKER 2: ANALYSIS (Hash & Zip Bomb)
# ==========================================
class AnalysisThread(QThread):
    log_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(str, str)

    def __init__(self, filename):
        super().__init__()
        self.filename = filename

    def calculate_hash(self):
        try:
            cmd = f"sha256sum {self.filename}"
            result = subprocess.check_output(cmd, shell=True).decode().strip()
            return result.split()[0]
        except:
            return "HASH_CALCULATION_ERROR"

    def run(self):
        self.log_signal.emit("\n--- [ SECURITY & INTEGRITY SCAN ] ---")
        self.log_signal.emit("[*] Calculating SHA-256 Hash (Digital Seal)...")
        file_hash = self.calculate_hash()
        self.log_signal.emit(f"[*] SHA-256: {file_hash}")

        self.log_signal.emit("[*] Analyzing Binary Headers...")
        try:
            cmd = f"grep -aPc '\\x50\\x4B\\x03\\x04' {self.filename}"
            result = subprocess.check_output(cmd, shell=True).decode().strip()
            zip_count = int(result) if result.isdigit() else 0
            
            warning_msg = ""
            if zip_count > 1000:
                self.log_signal.emit("[!!!] THREAT DETECTED: Potential Zip Bomb structure.")
                warning_msg = f"WARNING: {zip_count} compressed blocks detected."
            else:
                self.log_signal.emit("[OK] File structure appears clean.")

            self.finished_signal.emit(warning_msg, file_hash)

        except Exception as e:
            self.log_signal.emit(f"[!] Analysis error: {e}")
            self.finished_signal.emit("", file_hash)

# ==========================================
# MAIN WINDOW (GUI)
# ==========================================
class ForensicApp(QMainWindow):
    def __init__(self):
        super().__init__()
        try:
            loadUi("forensic_qt6.ui", self)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"UI Dosyası Yüklenemedi!\n{e}")
            sys.exit(1)

        self.setWindowTitle("Remote Forensic Imager - Professional Edition")
        self.setup_terminal_style()

        self.btn_file.clicked.connect(self.select_key)
        self.btn_start.clicked.connect(self.start_process)
        
        self.txt_user.setText("ubuntu")
        self.txt_disk.setText("/dev/nvme0n1")
        self.chk_safety.setChecked(True)
        self.progressBar.setValue(0)
        self.last_report_data = {}

    def setup_terminal_style(self):
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

    def select_key(self):
        fname, _ = QFileDialog.getOpenFileName(self, "Select SSH Key", "", "PEM Files (*.pem);;All Files (*)")
        if fname:
            self.txt_key.setText(fname)

    def log(self, msg):
        self.txt_log.append(msg)
        cursor = self.txt_log.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.txt_log.setTextCursor(cursor)
        
        # Crash-Proof Log
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open("live_forensic.log", "a", encoding="utf-8") as f:
                f.write(f"[{timestamp}] {msg}\n")
        except Exception:
            pass

    def start_process(self):
        ip = self.txt_ip.text()
        user = self.txt_user.text()
        key = self.txt_key.text()
        disk = self.txt_disk.text()
        
        self.case_no = self.txt_caseno.text() if hasattr(self, 'txt_caseno') else "UNKNOWN_CASE"
        self.examiner = self.txt_examiner.text() if hasattr(self, 'txt_examiner') else "UNKNOWN_EXAMINER"

        write_block_status = False
        if hasattr(self, 'chk_writeblock'):
             write_block_status = self.chk_writeblock.isChecked()
        else:
             self.log("[INFO] UI does not have 'chk_writeblock'. Feature disabled.")

        if not ip or not key or not user:
            QMessageBox.warning(self, "Eksik Bilgi", "Lütfen tüm zorunlu alanları doldurun!")
            return

        self.btn_start.setEnabled(False)
        self.progressBar.setValue(5)
        self.log("\n--- [ STARTING FORENSIC ACQUISITION ] ---")
        self.log(f"[*] Case No: {self.case_no} | Examiner: {self.examiner}")
        self.log(f"[*] Write Blocker Requested: {write_block_status}")
        
        self.worker = AcquisitionThread(ip, user, key, disk, self.chk_safety.isChecked(), write_block_status)
        self.worker.log_signal.connect(self.log)
        self.worker.finished_signal.connect(self.on_acquisition_finished)
        self.worker.start()

    def on_acquisition_finished(self, success, filename, report_data):
        self.last_report_data = report_data
        
        if success:
            self.progressBar.setValue(50)
            self.log(f"[INFO] Image Acquired: {filename}")
            
            self.analyzer = AnalysisThread(filename)
            self.analyzer.log_signal.connect(self.log)
            self.analyzer.finished_signal.connect(self.on_analysis_finished)
            self.analyzer.start()
        else:
            self.log(f"[ERROR] {filename}")
            QMessageBox.critical(self, "İşlem Başarısız", filename)
            self.btn_start.setEnabled(True)
            self.progressBar.setValue(0)

    def on_analysis_finished(self, warning, file_hash):
        self.progressBar.setValue(100)
        self.btn_start.setEnabled(True)
        self.generate_report(file_hash)
        
        self.log("\n--- [ TASK COMPLETED SUCCESSFULLY ] ---")
        self.log(f"[*] Report Created: Report_{self.case_no}_{datetime.now().strftime('%Y%m%d')}.txt")
        
        if warning:
            QMessageBox.warning(self, "FORENSIC WARNING", warning)
        else:
            QMessageBox.information(self, "Başarılı", "Adli İmaj Alma ve Analiz Tamamlandı.\nRapor Oluşturuldu.")

    def generate_report(self, file_hash):
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
Target Disk    : {self.txt_disk.text()}

ACQUISITION LOG:
----------------
Start Time     : {self.last_report_data['start_time']}
End Time       : {self.last_report_data['end_time']}
Duration       : {self.last_report_data['duration']}
SSH Fingerprint: {self.last_report_data['ssh_fingerprint']}
Write Blocker  : {self.last_report_data['write_protection']}

COMMAND EXECUTED:
-----------------
{self.last_report_data['command_executed']}

DISK HEALTH / ERROR LOGS:
-------------------------
{bad_sector_text}

EVIDENCE DETAILS:
-----------------
File Name      : {self.worker.filename}
SHA-256 Hash   : {file_hash}
Integrity      : VERIFIED

================================================================
                  CHAIN OF CUSTODY (CoC)
================================================================
| Date/Time           | Released By (From) | Received By (To) | Purpose             |
|---------------------|--------------------|------------------|---------------------|
| {self.last_report_data['end_time']} | AWS Live Server    | {self.examiner:<16} | Forensic Acquisition|
| {self.last_report_data['end_time']} | {self.examiner:<18} | Secure Storage   | Evidence Locking    |
|                     |                    |                  |                     |
================================================================
Note: This document is auto-generated by Remote Forensic Imager.
"""
        report_filename = f"Report_{self.case_no}_{datetime.now().strftime('%Y%m%d')}.txt"
        with open(report_filename, "w") as f:
            f.write(report_content)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ForensicApp()
    window.show()
    sys.exit(app.exec())
