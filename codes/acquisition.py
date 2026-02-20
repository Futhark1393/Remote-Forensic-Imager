import os
import subprocess
import time
import re
from datetime import datetime
from PyQt6.QtCore import QThread, pyqtSignal

class AcquisitionThread(QThread):
    log_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int)
    finished_signal = pyqtSignal(bool, str, dict)

    def __init__(self, ip, user, key, disk, safe_mode, write_block, is_ram, throttle, do_triage, format_type, case_no, examiner):
        super().__init__()
        self.ip = ip
        self.user = user
        self.key = key
        self.disk = disk
        self.safe_mode = safe_mode
        self.write_block = write_block
        self.is_ram = is_ram
        self.throttle = throttle
        self.do_triage = do_triage
        self.format_type = format_type
        self.case_no = case_no
        self.examiner = examiner

        self.base_filename = f"evidence_{datetime.now().strftime('%Y%m%d%H%M%S')}"

        # Determine final extension based on format
        if self.is_ram:
            self.filename = f"{self.base_filename}.img"
        elif self.format_type == "E01":
            self.filename = f"{self.base_filename}.E01"
        else:
            self.filename = f"{self.base_filename}.img.gz"

    def run(self):
        report_data = {
            "target_ip": self.ip,
            "start_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "acquisition_type": "Live RAM (1GB Limit)" if self.is_ram else f"Physical Disk ({self.format_type})",
            "write_protection": "Enabled (blockdev --setro)" if self.write_block else "Disabled",
            "triage_file": "Not Requested",
            "bad_sectors": [],
            "duration": "0:00:00"
        }

        try:
            # Execute Triage
            if self.do_triage:
                self.log_signal.emit("[*] Executing Live Triage...")
                t_file = f"triage_{datetime.now().strftime('%Y%m%d%H%M%S')}.txt"
                t_cmd = f"ssh -o StrictHostKeyChecking=no -i {self.key} {self.user}@{self.ip} 'netstat -tulnp; ps aux; w; dmesg | tail -n 50' > {t_file}"
                subprocess.run(t_cmd, shell=True)
                report_data["triage_file"] = t_file
                self.log_signal.emit(f"[OK] Triage saved to {t_file}")

            # Enable Write Blocker
            if self.write_block and not self.is_ram:
                self.log_signal.emit(f"[*] Applying Kernel Write-Blocker to {self.disk}...")
                subprocess.run(f"ssh -o StrictHostKeyChecking=no -i {self.key} {self.user}@{self.ip} 'sudo blockdev --setro {self.disk}'", shell=True)

            # Calculate Size
            total_bytes = 0
            if not self.is_ram:
                self.log_signal.emit("[*] Calculating total disk size for progress tracking...")
                size_cmd = f"ssh -o StrictHostKeyChecking=no -i {self.key} {self.user}@{self.ip} 'sudo blockdev --getsize64 {self.disk}'"
                size_proc = subprocess.run(size_cmd, shell=True, capture_output=True, text=True)
                if size_proc.returncode == 0 and size_proc.stdout.strip().isdigit():
                    total_bytes = int(size_proc.stdout.strip())
                    self.log_signal.emit(f"[*] Target Size: {total_bytes / (1024**3):.2f} GB")
            else:
                total_bytes = 1024 * 1024 * 1024

            safe_conv = "conv=noerror,sync" if self.safe_mode else ""

            pv_base = "pv -n -f"
            if total_bytes > 0:
                pv_base += f" -s {total_bytes}"
            if self.throttle:
                pv_base += f" -L {self.throttle}m"

            # Build Command
            if self.is_ram:
                block_size_kb = 64
                count_limit = (1024 * 1024) // block_size_kb
                cmd = f"ssh -o StrictHostKeyChecking=no -i {self.key} {self.user}@{self.ip} 'sudo dd if={self.disk} bs={block_size_kb}K count={count_limit}' | {pv_base} > {self.filename}"
            elif self.format_type == "E01":
                ewf_cmd = f"ewfacquirestream -c fast -m fixed -C \"{self.case_no}\" -e \"{self.examiner}\" -t \"{self.base_filename}\""
                cmd = f"ssh -o StrictHostKeyChecking=no -i {self.key} {self.user}@{self.ip} 'sudo dd if={self.disk} bs=64K {safe_conv}' | {pv_base} | {ewf_cmd}"
            else:
                cmd = f"ssh -o StrictHostKeyChecking=no -i {self.key} {self.user}@{self.ip} 'sudo dd if={self.disk} bs=64K {safe_conv}' | {pv_base} | gzip -1 - > {self.filename}"

            self.log_signal.emit(f"[*] EXECUTING: {cmd}")

            # Merge stderr into stdout to prevent OS pipe buffer deadlocks
            process = subprocess.Popen(cmd, shell=True, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)

            buffer = b""
            while True:
                # Read from merged stdout channel
                char = process.stdout.read(1)
                if not char and process.poll() is not None:
                    break

                if char in [b'\r', b'\n']:
                    try:
                        line = buffer.decode('utf-8').strip()
                    except:
                        line = ""

                    buffer = b""
                    if not line:
                        continue

                    if line.isdigit():
                        val = int(line)
                        gui_progress = 5 + int((val / total_bytes) * 0.45 * 100) if total_bytes > 0 else 5
                        if gui_progress > 50: gui_progress = 50
                        self.progress_signal.emit(gui_progress)

                    elif "error" in line.lower() or "input/output" in line.lower() or "failed" in line.lower():
                        # Ignore false positive "error" words generated by ewfacquirestream config outputs
                        if "ewfacquirestream" not in line.lower() and "error granularity" not in line.lower() and "read error" not in line.lower():
                            report_data["bad_sectors"].append(line)
                            self.log_signal.emit(f"[!!!] I/O ERROR: {line}")
                        else:
                            self.log_signal.emit(f"[STREAM] {line}")
                    else:
                        self.log_signal.emit(f"[STREAM] {line}")
                else:
                    buffer += char

            process.wait()

            report_data["end_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            start_dt = datetime.strptime(report_data["start_time"], "%Y-%m-%d %H:%M:%S")
            end_dt = datetime.strptime(report_data["end_time"], "%Y-%m-%d %H:%M:%S")
            report_data["duration"] = str(end_dt - start_dt)

            if os.path.exists(self.filename) and os.path.getsize(self.filename) > 0:
                self.progress_signal.emit(50)
                self.finished_signal.emit(True, self.filename, report_data)
            else:
                self.log_signal.emit("[ERROR] Evidence file was not created or is 0 bytes.")
                self.finished_signal.emit(False, self.filename, report_data)

        except Exception as e:
            self.log_signal.emit(f"[ERROR] Thread Crash: {str(e)}")
            report_data["end_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.finished_signal.emit(False, self.filename, report_data)
