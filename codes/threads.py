# Author: Futhark1393
# Description: Acquisition Worker thread. Handles Paramiko SSH stream, on-the-fly hashing, ETA, throttling, Safe Mode, and Live Triage.

import os
import time
import hashlib
from PyQt6.QtCore import QThread, pyqtSignal
import paramiko

# Optional libewf support
try:
    import pyewf
    EWF_AVAILABLE = True
except ImportError:
    EWF_AVAILABLE = False

class AcquisitionWorker(QThread):
    progress_signal = pyqtSignal(dict)
    finished_signal = pyqtSignal(dict)
    error_signal = pyqtSignal(str)

    def __init__(self, ip, user, key_path, disk, output_file, format_type, case_no, examiner, throttle_limit=0.0, safe_mode=True, run_triage=False, output_dir=""):
        super().__init__()
        self.ip = ip
        self.user = user
        self.key_path = key_path
        self.disk = disk
        self.output_file = output_file
        self.format_type = format_type
        self.case_no = case_no
        self.examiner = examiner
        self.throttle_limit = throttle_limit
        self.safe_mode = safe_mode
        self.run_triage = run_triage
        self.output_dir = output_dir

        self._is_running = True
        self.chunk_size = 4 * 1024 * 1024  # 4 MB

    def stop(self):
        # Triggered by GUI Stop Button
        self._is_running = False

    def run(self):
        try:
            md5_hash = hashlib.md5()
            sha256_hash = hashlib.sha256()
            total_bytes = 0
            target_bytes = 0
            start_time = time.time()

            # 1. Open local evidence file
            if self.format_type == "E01" and EWF_AVAILABLE:
                out_target = pyewf.handle()
                out_target.open([self.output_file], "w")
            else:
                out_target = open(self.output_file, "wb")

            retries = 0
            max_retries = 3
            success = False

            # 2. Network and Chunk Streaming Loop
            while self._is_running and retries <= max_retries:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                try:
                    if retries > 0:
                        self.progress_signal.emit({
                            "bytes_read": total_bytes,
                            "speed_mb_s": 0.0,
                            "md5_current": md5_hash.hexdigest(),
                            "percentage": int((total_bytes / target_bytes) * 100) if target_bytes > 0 else 0,
                            "eta": f"Connection lost. Retrying ({retries}/{max_retries})..."
                        })
                        time.sleep(3)

                    ssh.connect(self.ip, username=self.user, key_filename=self.key_path, timeout=10)

                    # RUN LIVE TRIAGE BEFORE ACQUISITION (Only on first successful connect)
                    if target_bytes == 0:
                        if self.run_triage and self.output_dir:
                            self.progress_signal.emit({
                                "bytes_read": 0, "speed_mb_s": 0.0, "md5_current": "", "percentage": 0,
                                "eta": "Running Live Triage..."
                            })
                            triage_file_path = os.path.join(self.output_dir, f"Triage_{self.case_no}.txt")
                            try:
                                triage_script = "echo '=== SYSTEM & DATE ==='; uname -a; date; uptime; " \
                                                "echo '\n=== NETWORK CONNECTIONS ==='; ss -tulnp || netstat -tulnp; " \
                                                "echo '\n=== RUNNING PROCESSES ==='; ps aux"
                                t_in, t_out, t_err = ssh.exec_command(f"sudo sh -c \"{triage_script}\"")
                                with open(triage_file_path, "w", encoding="utf-8") as tf:
                                    tf.write(t_out.read().decode('utf-8', errors='ignore'))
                            except Exception:
                                pass # Silently skip if triage fails to not block main acquisition

                        # Get Disk Size
                        size_stdin, size_stdout, size_stderr = ssh.exec_command(f"sudo blockdev --getsize64 {self.disk}")
                        size_str = size_stdout.read().decode('utf-8').strip()
                        target_bytes = int(size_str) if size_str.isdigit() else 0

                    # Apply Safe Mode logic
                    conv_flag = " conv=noerror,sync" if self.safe_mode else ""
                    command = f"sudo dd if={self.disk} bs=4M skip={total_bytes} iflag=skip_bytes{conv_flag} status=none"

                    stdin, stdout, stderr = ssh.exec_command(command)

                    while self._is_running:
                        chunk_start_time = time.time()

                        chunk = stdout.read(self.chunk_size)
                        if not chunk:
                            success = True
                            break

                        total_bytes += len(chunk)
                        md5_hash.update(chunk)
                        sha256_hash.update(chunk)

                        if self.format_type == "E01" and EWF_AVAILABLE:
                            out_target.write_buffer(chunk)
                        else:
                            out_target.write(chunk)

                        # Throttling
                        if self.throttle_limit > 0:
                            chunk_mb = len(chunk) / (1024 * 1024)
                            expected_time = chunk_mb / self.throttle_limit
                            actual_time = time.time() - chunk_start_time
                            if actual_time < expected_time:
                                time.sleep(expected_time - actual_time)

                        elapsed = time.time() - start_time
                        mb_per_sec = (total_bytes / (1024 * 1024)) / elapsed if elapsed > 0 else 0

                        percentage = 0
                        eta_str = "Calculating..."
                        if target_bytes > 0:
                            percentage = int((total_bytes / target_bytes) * 100)
                            if mb_per_sec > 0:
                                bytes_per_sec = mb_per_sec * 1024 * 1024
                                remaining_bytes = target_bytes - total_bytes
                                eta_seconds = remaining_bytes / bytes_per_sec
                                eta_str = time.strftime('%H:%M:%S', time.gmtime(eta_seconds))

                        self.progress_signal.emit({
                            "bytes_read": total_bytes,
                            "speed_mb_s": round(mb_per_sec, 2),
                            "md5_current": md5_hash.hexdigest(),
                            "percentage": percentage,
                            "eta": eta_str
                        })

                    if success or not self._is_running:
                        break

                except Exception as e:
                    retries += 1
                    if retries > max_retries:
                        self.error_signal.emit(f"Network failure. Max retries exceeded: {str(e)}")
                        break
                finally:
                    ssh.close()

            out_target.close()

            if success and self._is_running:
                self.finished_signal.emit({
                    "sha256_final": sha256_hash.hexdigest(),
                    "md5_final": md5_hash.hexdigest(),
                    "total_bytes": total_bytes
                })
            elif not self._is_running:
                self.error_signal.emit("Process aborted by user.")

        except Exception as e:
            self.error_signal.emit(f"Initialization Error: {str(e)}")
