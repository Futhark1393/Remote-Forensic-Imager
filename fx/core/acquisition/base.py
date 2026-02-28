# Author: Futhark1393
# Description: Pure-Python acquisition engine — no Qt dependency.
# Features: SSH streaming, on-the-fly hashing, ETA, throttling, resume-on-disconnect,
#          live triage, optional write-blocker, and post-acquisition hash verification.

import os
import socket
import time
from typing import Callable

import paramiko

from fx.core.hashing import StreamHasher
from fx.core.policy import ssh_exec, apply_write_blocker, build_dd_command
from fx.core.acquisition.raw import RawWriter
from fx.core.acquisition.lz4_writer import LZ4Writer, LZ4_AVAILABLE
from fx.core.acquisition.ewf import EwfWriter, EWF_AVAILABLE
from fx.core.acquisition.aff4 import AFF4Writer, AFF4_AVAILABLE
from fx.core.acquisition.verify import verify_source_hash
from fx.triage.orchestrator import TriageOrchestrator


class AcquisitionError(Exception):
    """Raised on unrecoverable acquisition failure."""
    pass


class AcquisitionEngine:
    """
    Pure-Python forensic acquisition engine. No Qt imports.

    Progress is reported via an ``on_progress(data: dict)`` callback so
    the caller (Qt worker, CLI tool, test harness) can handle it however
    it likes.
    """

    CHUNK_SIZE = 4 * 1024 * 1024  # 4 MB
    MAX_RETRIES = 3

    def __init__(
        self,
        ip: str,
        user: str,
        key_path: str,
        disk: str,
        output_file: str,
        format_type: str,
        case_no: str,
        examiner: str,
        throttle_limit: float = 0.0,
        safe_mode: bool = True,
        run_triage: bool = False,
        triage_network: bool = True,
        triage_processes: bool = True,
        triage_memory: bool = False,
        triage_hash_exes: bool = True,
        output_dir: str = "",
        verify_hash: bool = False,
        write_blocker: bool = False,
        on_progress: Callable[[dict], None] | None = None,
    ):
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
        self.triage_network = triage_network
        self.triage_processes = triage_processes
        self.triage_memory = triage_memory
        self.triage_hash_exes = triage_hash_exes
        self.output_dir = output_dir
        self.verify_hash = verify_hash
        self.write_blocker = write_blocker
        self.on_progress = on_progress or (lambda d: None)

        self._is_running = True
        self._triage_summary = {}
        self._active_ssh = None

    def stop(self) -> None:
        """Request a graceful stop of the acquisition loop."""
        self._is_running = False
        # Force-close the SSH transport so blocking reads are interrupted
        if hasattr(self, '_active_ssh') and self._active_ssh:
            try:
                transport = self._active_ssh.get_transport()
                if transport:
                    transport.close()
            except Exception:
                pass

    @property
    def is_running(self) -> bool:
        return self._is_running

    # ── Progress helper ─────────────────────────────────────────────────

    def _emit(self, bytes_read: int, speed: float, md5: str, pct: int, eta: str) -> None:
        self.on_progress({
            "bytes_read": bytes_read,
            "speed_mb_s": round(speed, 2),
            "md5_current": md5,
            "percentage": min(100, pct),
            "eta": eta,
        })

    # ── Triage ──────────────────────────────────────────────────────────

    def _run_triage(self, ssh: paramiko.SSHClient) -> None:
        if not (self.run_triage and self.output_dir):
            return

        def _status(msg: str) -> None:
            self._emit(0, 0.0, "", 0, msg)

        orchestrator = TriageOrchestrator(
            run_network=self.triage_network,
            run_processes=self.triage_processes,
            run_memory=self.triage_memory,
            hash_exes=self.triage_hash_exes,
            attempt_kcore=False,   # read-only: never write to target
            on_status=_status,
        )
        try:
            triage_summary = orchestrator.run(ssh, self.case_no, self.output_dir)
            # Store triage results for later use (dashboard, etc.)
            self._triage_summary = triage_summary
        except Exception:
            pass  # triage is best-effort — acquisition must not fail

    # ── Main loop ───────────────────────────────────────────────────────

    def run(self) -> dict:
        """
        Execute the full acquisition pipeline.

        Returns a dict on success:
            sha256_final, md5_final, total_bytes, remote_sha256, hash_match

        Raises AcquisitionError on failure.
        """
        hasher = StreamHasher()
        total_bytes = 0
        target_bytes = 0
        start_time = time.time()

        # Open evidence writer
        if self.format_type == "AFF4":
            if not AFF4_AVAILABLE:
                raise AcquisitionError(
                    "AFF4 format selected but pyaff4 is not installed.\n"
                    "Install with: pip install pyaff4"
                )
            writer = AFF4Writer(self.output_file)
        elif self.format_type == "E01":
            if not EWF_AVAILABLE:
                raise AcquisitionError(
                    "E01 format selected but pyewf/libewf support is not available.\n"
                    "Install system libewf and the Python bindings (pyewf)."
                )
            writer = EwfWriter(self.output_file)
        elif self.format_type == "RAW+LZ4":
            if not LZ4_AVAILABLE:
                raise AcquisitionError(
                    "RAW+LZ4 format selected but lz4 is not installed.\n"
                    "Install with: pip install lz4>=4.0.0"
                )
            writer = LZ4Writer(self.output_file)
        else:
            writer = RawWriter(self.output_file)

        def _safe_close_writer() -> None:
            try:
                writer.close()
            except Exception:
                # Never mask the primary acquisition failure with a close/finalize error.
                pass

        retries = 0
        success = False
        ssh = None

        try:
            while self._is_running and retries <= self.MAX_RETRIES:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                self._active_ssh = ssh

                try:
                    if retries > 0:
                        pct = int((total_bytes / target_bytes) * 100) if target_bytes > 0 else 0
                        self._emit(total_bytes, 0.0, hasher.md5_hex, pct,
                                   f"Connection lost. Retrying ({retries}/{self.MAX_RETRIES})...")
                        time.sleep(3)

                    ssh.connect(self.ip, username=self.user, key_filename=self.key_path, timeout=10)

                    # One-time preflight
                    if target_bytes == 0:
                        self._run_triage(ssh)

                        out, err, code = ssh_exec(ssh, f"sudo -n blockdev --getsize64 {self.disk}")
                        if code != 0 or not out.strip().isdigit():
                            raise AcquisitionError(f"Failed to read disk size. {err}")
                        target_bytes = int(out.strip())

                        if self.write_blocker:
                            self._emit(0, 0.0, "", 0, "Applying Write-Blocker...")
                            apply_write_blocker(ssh, self.disk)

                    # Start dd
                    command = build_dd_command(self.disk, total_bytes, self.safe_mode)
                    stdin_ch, stdout_ch, stderr_ch = ssh.exec_command(command)

                    # Set read timeout so stop() can interrupt blocking reads
                    stdout_ch.channel.settimeout(2.0)

                    while self._is_running:
                        chunk_start = time.time()
                        try:
                            chunk = stdout_ch.read(self.CHUNK_SIZE)
                        except socket.timeout:
                            continue  # Re-check _is_running
                        except OSError:
                            if not self._is_running:
                                break  # Transport closed by stop()
                            raise
                        if not chunk:
                            success = True
                            break

                        total_bytes += len(chunk)
                        hasher.update(chunk)
                        writer.write(chunk)

                        # Throttling
                        if self.throttle_limit > 0:
                            chunk_mb = len(chunk) / (1024 * 1024)
                            expected = chunk_mb / self.throttle_limit
                            actual = time.time() - chunk_start
                            if actual < expected:
                                time.sleep(expected - actual)

                        elapsed = time.time() - start_time
                        mb_per_sec = (total_bytes / (1024 * 1024)) / elapsed if elapsed > 0 else 0

                        pct = 0
                        eta_str = "Calculating..."
                        if target_bytes > 0:
                            pct = int((total_bytes / target_bytes) * 100)
                            if mb_per_sec > 0:
                                remaining = max(0, target_bytes - total_bytes)
                                eta_seconds = remaining / (mb_per_sec * 1024 * 1024)
                                eta_str = time.strftime("%H:%M:%S", time.gmtime(eta_seconds))

                        self._emit(total_bytes, mb_per_sec, hasher.md5_hex, pct, eta_str)

                    # Check dd exit status
                    exit_status = stdout_ch.channel.recv_exit_status()
                    if exit_status != 0 and self._is_running:
                        err_text = stderr_ch.read().decode("utf-8", errors="ignore").strip()
                        raise AcquisitionError(f"dd failed: {err_text}")

                    if success or not self._is_running:
                        break

                except AcquisitionError:
                    raise
                except Exception as e:
                    retries += 1
                    if retries > self.MAX_RETRIES:
                        raise AcquisitionError(
                            f"Network/acquisition failure. Max retries exceeded: {e}"
                        )
                finally:
                    self._active_ssh = None
                    if ssh and not (success and self.verify_hash):
                        ssh.close()

            # In the success path, a close error indicates an invalid/unfinished evidence file.
            try:
                writer.close()
            except Exception as e:
                raise AcquisitionError(f"Evidence writer finalization failed: {e}") from e

            # Post-acquisition hash verification
            remote_sha256 = "SKIPPED"
            hash_match = None

            if success and self._is_running and self.verify_hash:
                self._emit(total_bytes, 0.0, hasher.md5_hex, 100,
                           "Verifying Source Hash (Please Wait)...")
                try:
                    remote_sha256, _ = verify_source_hash(ssh, self.disk)
                    if remote_sha256 not in ("ERROR",):
                        hash_match = (remote_sha256 == hasher.sha256_hex)
                    else:
                        hash_match = False
                finally:
                    if ssh:
                        ssh.close()

            if not self._is_running:
                raise AcquisitionError("Process aborted by user.")

            if not success:
                raise AcquisitionError("Acquisition did not complete successfully.")

            return {
                "sha256_final": hasher.sha256_hex,
                "md5_final": hasher.md5_hex,
                "total_bytes": total_bytes,
                "remote_sha256": remote_sha256,
                "hash_match": hash_match,
                "triage_summary": self._triage_summary,
            }

        except AcquisitionError:
            _safe_close_writer()
            if ssh:
                try:
                    ssh.close()
                except Exception:
                    pass
            raise
        except Exception as e:
            _safe_close_writer()
            if ssh:
                try:
                    ssh.close()
                except Exception:
                    pass
            raise AcquisitionError(f"Initialization Error: {e}")
