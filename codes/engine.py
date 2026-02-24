# Author: Futhark1393
# Description: Core acquisition engine for Remote Forensic Imager v2.0
# Utilizing Paramiko for direct SSH API abstraction, chunk-based streaming, on-the-fly hashing, and E01 support.

import paramiko
import hashlib
import time
import os

try:
    import pyewf  # Optional (E01 support)
except ImportError:
    pyewf = None

class ForensicAcquisitionEngine:
    def __init__(self, host, username, key_path, target_device, output_file, format_type="RAW", case_no="UNKNOWN", examiner="UNKNOWN"):
        self.host = host
        self.username = username
        self.key_path = key_path
        self.target_device = target_device
        self.output_file = output_file
        self.format_type = format_type
        self.case_no = case_no
        self.examiner = examiner
        self.ssh_client = None
        self.chunk_size = 4 * 1024 * 1024  # 4MB chunks for optimal memory management

    def connect(self):
        # Initialize SSH client and connect using key-based authentication
        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        private_key = paramiko.RSAKey.from_private_key_file(self.key_path)
        self.ssh_client.connect(hostname=self.host, username=self.username, pkey=private_key)

    def enforce_write_blocker(self):
        # Apply software write-blocker at the kernel level
        command = f"sudo blockdev --setro {self.target_device}"
        stdin, stdout, stderr = self.ssh_client.exec_command(command)
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0:
            error_msg = stderr.read().decode('utf-8')
            raise Exception(f"Failed to enforce write-blocker: {error_msg}")

    def get_target_size(self):
        # Retrieve exact byte size of the target block device for E01 headers
        command = f"sudo blockdev --getsize64 {self.target_device}"
        stdin, stdout, stderr = self.ssh_client.exec_command(command)
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0:
            error_msg = stderr.read().decode('utf-8')
            raise Exception(f"Failed to get device size: {error_msg}")
        return int(stdout.read().decode('utf-8').strip())

    def acquire_and_hash(self):
        # Main generator function for chunk-based streaming and on-the-fly hashing
        if self.format_type == "E01" and pyewf is None:
            raise RuntimeError("E01 support requires pyewf/libewf. Install system libewf + pyewf to enable E01.")
        
        self.enforce_write_blocker()

        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()

        f_out = None
        ewf_handle = None

        # Setup output handler based on selected format
        if self.format_type == "E01":
            target_size = self.get_target_size()
            ewf_handle = pyewf.handle()

            # Gracefully handle missing metadata attributes in experimental pyewf versions
            try:
                ewf_handle.set_case_number(self.case_no)
            except AttributeError:
                pass

            try:
                ewf_handle.set_examiner_name(self.examiner)
            except AttributeError:
                pass

            try:
                ewf_handle.set_media_size(target_size)
            except AttributeError:
                pass

            try:
                ewf_handle.set_bytes_per_sector(512)
            except AttributeError:
                pass

            # EWF requires a list of filenames for segmenting
            ewf_handle.open([self.output_file], "w")
        else:
            f_out = open(self.output_file, 'wb')

        # Execute dd command to stream raw bytes over SSH TCP socket
        command = f"sudo dd if={self.target_device} bs=4M status=none"
        stdin, stdout, stderr = self.ssh_client.exec_command(command)

        total_bytes_read = 0
        start_time = time.time()

        try:
            while True:
                # Read exactly chunk_size bytes directly from the SSH channel
                chunk = stdout.channel.recv(self.chunk_size)
                if not chunk:
                    break

                # 1. Update hashes on-the-fly (in-memory)
                md5_hash.update(chunk)
                sha256_hash.update(chunk)

                # 2. Write physical chunk to disk (E01 or RAW)
                if self.format_type == "E01":
                    ewf_handle.write_buffer(chunk)
                else:
                    f_out.write(chunk)

                # 3. Calculate real-time performance metrics
                total_bytes_read += len(chunk)
                elapsed_time = time.time() - start_time
                speed_mb_s = (total_bytes_read / (1024 * 1024)) / elapsed_time if elapsed_time > 0 else 0

                # 4. Yield state to decouple logic from GUI updates
                yield {
                    "status": "running",
                    "bytes_read": total_bytes_read,
                    "speed_mb_s": round(speed_mb_s, 2),
                    "md5_current": md5_hash.hexdigest(),
                    "sha256_current": sha256_hash.hexdigest()
                }

            exit_status = stdout.channel.recv_exit_status()
            if exit_status != 0:
                error_msg = stderr.read().decode('utf-8')
                yield {"status": "error", "message": error_msg}
                return

            yield {
                "status": "completed",
                "bytes_read": total_bytes_read,
                "md5_final": md5_hash.hexdigest(),
                "sha256_final": sha256_hash.hexdigest()
            }

        finally:
            # Securely close handlers
            if self.format_type == "E01" and ewf_handle:
                ewf_handle.close()
            elif f_out:
                f_out.close()

    def disconnect(self):
        # Close SSH connection securely
        if self.ssh_client:
            self.ssh_client.close()
