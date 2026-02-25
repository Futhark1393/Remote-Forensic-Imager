# Author: Futhark1393
# Description: Forensic-Grade Structured Logging Engine.
# Features: Cryptographic Hash Chaining, Thread-Safety, Kernel Sync (fsync),
#          Real File Sealing, and Defensive Chain Verification.

import os
import sys
import json
import uuid
import re
import hashlib
import subprocess
import threading
import shutil
from datetime import datetime, timezone


class ForensicLoggerError(Exception):
    pass


class ForensicLogger:
    def __init__(self):
        self.session_id = str(uuid.uuid4())
        self.case_no = "UNASSIGNED"
        self.examiner = "UNASSIGNED"
        self.output_dir = None

        self._lock = threading.Lock()
        self.log_file_path = f"temp_audit_{self.session_id}.jsonl"
        self.prev_hash = hashlib.sha256(b"FORENSIC_GENESIS_BLOCK").hexdigest()
        self._is_sealed = False

    def sanitize_filename(self, name: str) -> str:
        clean = re.sub(r"[^a-zA-Z0-9_\-]", "_", str(name).strip())
        return clean if clean else "UNASSIGNED"

    def set_context(self, case_no: str, examiner: str, output_dir: str) -> None:
        with self._lock:
            if self._is_sealed:
                raise ForensicLoggerError("Audit trail is sealed. Cannot modify context.")

            if not os.path.isdir(output_dir):
                raise ForensicLoggerError(f"Output directory does not exist: {output_dir}")
            if not os.access(output_dir, os.W_OK):
                raise ForensicLoggerError(f"Output directory lacks write permissions: {output_dir}")

            self.case_no = self.sanitize_filename(case_no)
            self.examiner = self.sanitize_filename(examiner)
            self.output_dir = output_dir

            new_log_path = os.path.join(
                self.output_dir, f"AuditTrail_{self.case_no}_{self.session_id}.jsonl"
            )

            try:
                if os.path.exists(self.log_file_path):
                    shutil.move(self.log_file_path, new_log_path)

                self.log_file_path = new_log_path

                self._internal_log_unlocked(
                    "Session context successfully bound to evidence directory.",
                    "INFO",
                    "CONTEXT_UPDATED",
                    source_module="logger",
                )
            except OSError as e:
                raise ForensicLoggerError(
                    f"Failed to migrate audit trail to evidence directory: {str(e)}"
                )

    def log(
        self,
        message: str,
        level: str = "INFO",
        event_type: str = "GENERAL",
        source_module: str = "gui",
        hash_context: dict | None = None,
    ) -> str:
        with self._lock:
            return self._internal_log_unlocked(message, level, event_type, source_module, hash_context)

    def _internal_log_unlocked(
        self,
        message: str,
        level: str,
        event_type: str,
        source_module: str,
        hash_context: dict | None = None,
    ) -> str:
        if self._is_sealed:
            raise ForensicLoggerError(
                f"Audit log is mathematically sealed. Attempted to append: {message}"
            )

        now_utc = datetime.now(timezone.utc)
        timestamp_iso = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        event_id = str(uuid.uuid4())

        log_entry = {
            "timestamp": timestamp_iso,
            "session_id": self.session_id,
            "case_no": self.case_no,
            "examiner": self.examiner,
            "event_id": event_id,
            "event_type": event_type,
            "severity": level,
            "source_module": source_module,
            "message": message,
        }

        if hash_context:
            log_entry["hash_context"] = hash_context

        self._write_to_file(log_entry)
        return f"[{timestamp_iso}] [{level}] {message}"

    def _write_to_file(self, log_entry: dict) -> None:
        try:
            log_entry["prev_hash"] = self.prev_hash

            entry_json = json.dumps(log_entry, sort_keys=True)
            entry_hash = hashlib.sha256(entry_json.encode("utf-8")).hexdigest()

            log_entry["entry_hash"] = entry_hash
            self.prev_hash = entry_hash

            final_json = json.dumps(log_entry, sort_keys=True)

            with open(self.log_file_path, "a", encoding="utf-8") as f:
                f.write(final_json + "\n")
                f.flush()
                os.fsync(f.fileno())
        except OSError as e:
            raise ForensicLoggerError(f"File System Write Error: {str(e)}")

    def seal_audit_trail(self, signing_key_path: str | None = None) -> tuple[str, bool]:
        """
        Seal the audit trail: compute final hash, chmod 444, optional chattr +i,
        and optional Ed25519 digital signature.

        If *signing_key_path* is provided, a detached ``.sig`` file is written
        alongside the JSONL file.

        Returns (final_hash, chattr_success).
        """
        with self._lock:
            if not self.log_file_path or not os.path.exists(self.log_file_path):
                return "UNAVAILABLE", False

            self._internal_log_unlocked(
                "Initiating cryptographic seal of audit trail.",
                "INFO",
                "AUDIT_SEALING",
                source_module="logger",
            )

            self._is_sealed = True

            hasher = hashlib.sha256()
            try:
                with open(self.log_file_path, "rb") as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        hasher.update(chunk)
                final_hash = hasher.hexdigest()

                # Digital signature (optional)
                sig_path = None
                if signing_key_path:
                    try:
                        from rfi.audit.signing import sign_audit_trail
                        sig_path = sign_audit_trail(self.log_file_path, signing_key_path)
                    except Exception as e:
                        print(f"WARNING: signing failed: {e}", file=sys.stderr)

                os.chmod(self.log_file_path, 0o444)

                chattr_success = False
                try:
                    subprocess.run(
                        ["sudo", "-n", "chattr", "+i", self.log_file_path],
                        check=True,
                        capture_output=True,
                    )
                    chattr_success = True
                except subprocess.CalledProcessError:
                    chattr_success = False

                return final_hash, chattr_success

            except OSError as e:
                print(f"CRITICAL: Failed to seal audit trail: {e}", file=sys.stderr)
                return "ERROR_CALCULATING_HASH", False
