import os
import subprocess
from PyQt6.QtCore import QThread, pyqtSignal

class AnalysisThread(QThread):
    log_signal = pyqtSignal(str)
    # Signal now emits: warning_message, sha256_hash, md5_hash
    finished_signal = pyqtSignal(str, str, str)

    def __init__(self, filename):
        super().__init__()
        self.filename = filename

    def calculate_sha256(self):
        """Calculates SHA-256 hash of the evidence file."""
        try:
            cmd = f"sha256sum {self.filename}"
            result = subprocess.check_output(cmd, shell=True).decode().strip()
            return result.split()[0]
        except:
            return "SHA256_CALCULATION_ERROR"

    def calculate_md5(self):
        """Calculates MD5 hash of the evidence file."""
        try:
            cmd = f"md5sum {self.filename}"
            result = subprocess.check_output(cmd, shell=True).decode().strip()
            return result.split()[0]
        except:
            return "MD5_CALCULATION_ERROR"

    def run(self):
        self.log_signal.emit("\n--- [ SECURITY & INTEGRITY SCAN ] ---")

        self.log_signal.emit("[*] Calculating SHA-256 Hash...")
        sha256_hash = self.calculate_sha256()
        self.log_signal.emit(f"[*] SHA-256: {sha256_hash}")

        self.log_signal.emit("[*] Calculating MD5 Hash...")
        md5_hash = self.calculate_md5()
        self.log_signal.emit(f"[*] MD5: {md5_hash}")

        self.log_signal.emit("[*] Analyzing Binary Headers...")
        try:
            cmd = f"grep -aPc '\\x50\\x4B\\x03\\x04' {self.filename}"
            process = subprocess.run(cmd, shell=True, capture_output=True, text=True)

            if process.returncode in [0, 1]:
                zip_count = int(process.stdout.strip()) if process.stdout.strip().isdigit() else 0

                warning_msg = ""
                if zip_count > 1000:
                    self.log_signal.emit("[!!!] THREAT DETECTED: Potential Zip Bomb structure.")
                    warning_msg = f"WARNING: {zip_count} compressed blocks detected."
                else:
                    self.log_signal.emit("[OK] File structure appears clean. No Zip Bomb detected.")

                self.finished_signal.emit(warning_msg, sha256_hash, md5_hash)
            else:
                self.log_signal.emit(f"[!] Analysis error: Command failed with code {process.returncode}")
                self.finished_signal.emit("", sha256_hash, md5_hash)

        except Exception as e:
            self.log_signal.emit(f"[!] Analysis error: {str(e)}")
            self.finished_signal.emit("", sha256_hash, md5_hash)
