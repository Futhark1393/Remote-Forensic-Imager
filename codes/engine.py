# Author: Futhark1393
# Description: Core acquisition engine for Remote Forensic Imager v2.0
# Utilizing Paramiko for direct SSH API abstraction, chunk-based streaming, and on-the-fly hashing.

import paramiko
import hashlib
import time
import os

class ForensicAcquisitionEngine:
    def __init__(self, host, username, key_path, target_device, output_file):
        self.host = host
        self.username = username
        self.key_path = key_path
        self.target_device = target_device
        self.output_file = output_file
        self.ssh_client = None
        self.chunk_size = 4 * 1024 * 1024  # 4MB chunks for optimal memory management

    def connect(self):
        # Initialize SSH client and connect using key-based authentication
        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Enforce key-based authentication (password auth is disabled for security)
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

    def acquire_and_hash(self):
        # Main generator function for chunk-based streaming and on-the-fly hashing
        self.enforce_write_blocker()

        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()

        # Execute dd command to stream raw bytes.
        # status=none prevents dd from writing to stderr and polluting our TCP stream.
        command = f"sudo dd if={self.target_device} bs=4M status=none"
        stdin, stdout, stderr = self.ssh_client.exec_command(command)

        total_bytes_read = 0
        start_time = time.time()

        with open(self.output_file, 'wb') as f_out:
            while True:
                # Read exactly chunk_size bytes directly from the SSH TCP channel
                chunk = stdout.channel.recv(self.chunk_size)
                if not chunk:
                    break

                # 1. Update hashes on-the-fly (in-memory)
                md5_hash.update(chunk)
                sha256_hash.update(chunk)

                # 2. Write physical chunk to local disk
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

        # Finalize and verify command execution
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

    def disconnect(self):
        # Close SSH connection securely
        if self.ssh_client:
            self.ssh_client.close()
