# Author: Kemal Sebzeci
# Description: Local (dead) forensic acquisition engine — no network dependency.
# Features: Direct block-device / image-file reading, on-the-fly dual hashing,
# ETA, throttling, optional write-blocker, post-acquisition verification.

import fcntl
import os
import struct
import subprocess
import time
from typing import Callable

from fx.core.hashing import StreamHasher
from fx.core.acquisition.raw import RawWriter
from fx.core.acquisition.lz4_writer import LZ4Writer, LZ4_AVAILABLE
from fx.core.acquisition.ewf import EwfWriter, EWF_AVAILABLE
from fx.core.acquisition.aff4 import AFF4Writer, AFF4_AVAILABLE


class DeadAcquisitionError(Exception):
    """Raised on unrecoverable dead-acquisition failure."""
    pass


# Linux ioctl constant for BLKGETSIZE64
_BLKGETSIZE64 = 0x80081272


def _get_source_size(path: str) -> int:
    """Return the byte-size of a block device or regular file."""
    mode = os.stat(path).st_mode
    import stat as _stat
    if _stat.S_ISBLK(mode):
        with open(path, "rb") as f:
            buf = fcntl.ioctl(f.fileno(), _BLKGETSIZE64, b"\x00" * 8)
            return struct.unpack("Q", buf)[0]
    return os.path.getsize(path)


def _apply_local_write_blocker(disk: str) -> None:
    """Set the local block device read-only via blockdev --setro."""
    result = subprocess.run(
        ["sudo", "-n", "blockdev", "--setro", disk],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise DeadAcquisitionError(
            f"Write-blocker failed (blockdev --setro): {result.stderr.strip()}"
        )
    # Verify
    result = subprocess.run(
        ["sudo", "-n", "blockdev", "--getro", disk],
        capture_output=True, text=True,
    )
    if result.returncode != 0 or result.stdout.strip() != "1":
        raise DeadAcquisitionError(
            "Write-blocker verification failed: device is not read-only."
        )


class DeadAcquisitionEngine:
    """
    Local forensic acquisition engine for dead / offline disks.

    Reads directly from a locally-attached block device or image file.
    Progress is reported via an ``on_progress(data: dict)`` callback.
    """

    CHUNK_SIZE = 4 * 1024 * 1024  # 4 MB

    def __init__(
        self,
        source_path: str,
        output_file: str,
        format_type: str,
        case_no: str,
        examiner: str,
        throttle_limit: float = 0.0,
        safe_mode: bool = True,
        verify_hash: bool = False,
        write_blocker: bool = False,
        on_progress: Callable[[dict], None] | None = None,
    ):
        self.source_path = source_path
        self.output_file = output_file
        self.format_type = format_type
        self.case_no = case_no
        self.examiner = examiner
        self.throttle_limit = throttle_limit
        self.safe_mode = safe_mode
        self.verify_hash = verify_hash
        self.write_blocker = write_blocker
        self.on_progress = on_progress or (lambda d: None)

        self._is_running = True

    def stop(self) -> None:
        """Request a graceful stop of the acquisition loop."""
        self._is_running = False

    @property
    def is_running(self) -> bool:
        return self._is_running

    # ── Progress helper ─────────────────────────────────────────────

    def _emit(self, bytes_read: int, speed: float, md5: str, pct: int, eta: str) -> None:
        self.on_progress({
            "bytes_read": bytes_read,
            "speed_mb_s": round(speed, 2),
            "md5_current": md5,
            "percentage": min(100, pct),
            "eta": eta,
        })

    # ── Writer factory ──────────────────────────────────────────────

    def _create_writer(self):
        if self.format_type == "AFF4":
            if not AFF4_AVAILABLE:
                raise DeadAcquisitionError(
                    "AFF4 format selected but pyaff4 is not installed.\n"
                    "Install with: pip install pyaff4"
                )
            return AFF4Writer(self.output_file)
        elif self.format_type == "E01":
            if not EWF_AVAILABLE:
                raise DeadAcquisitionError(
                    "E01 format selected but pyewf/libewf support is not available.\n"
                    "Install system libewf and the Python bindings (pyewf)."
                )
            return EwfWriter(self.output_file)
        elif self.format_type == "RAW+LZ4":
            if not LZ4_AVAILABLE:
                raise DeadAcquisitionError(
                    "RAW+LZ4 format selected but lz4 is not installed.\n"
                    "Install with: pip install lz4>=4.0.0"
                )
            return LZ4Writer(self.output_file)
        else:
            return RawWriter(self.output_file)

    # ── Post-acquisition verification ───────────────────────────────

    def _verify_source(self, target_bytes: int) -> str:
        """Re-read source and compute SHA-256 for verification."""
        import hashlib
        sha = hashlib.sha256()
        try:
            with open(self.source_path, "rb") as src:
                remaining = target_bytes
                while remaining > 0 and self._is_running:
                    to_read = min(self.CHUNK_SIZE, remaining)
                    chunk = src.read(to_read)
                    if not chunk:
                        break
                    sha.update(chunk)
                    remaining -= len(chunk)
            return sha.hexdigest()
        except Exception:
            return "ERROR"

    # ── Main loop ───────────────────────────────────────────────────

    def run(self) -> dict:
        """
        Execute the local acquisition pipeline.

        Returns a dict on success:
            sha256_final, md5_final, total_bytes, source_sha256, hash_match

        Raises DeadAcquisitionError on failure.
        """
        # Validate source exists and is readable
        if not os.path.exists(self.source_path):
            raise DeadAcquisitionError(f"Source not found: {self.source_path}")

        # Get source size
        try:
            target_bytes = _get_source_size(self.source_path)
        except Exception as e:
            raise DeadAcquisitionError(f"Cannot determine source size: {e}") from e

        if target_bytes == 0:
            raise DeadAcquisitionError("Source has zero size.")

        # Write-blocker (block devices only)
        if self.write_blocker:
            self._emit(0, 0.0, "", 0, "Applying Write-Blocker...")
            _apply_local_write_blocker(self.source_path)

        hasher = StreamHasher()
        total_bytes = 0
        start_time = time.time()
        writer = self._create_writer()

        def _safe_close_writer() -> None:
            try:
                writer.close()
            except Exception:
                pass

        try:
            with open(self.source_path, "rb") as src:
                while self._is_running:
                    chunk_start = time.time()

                    if self.safe_mode:
                        try:
                            chunk = src.read(self.CHUNK_SIZE)
                        except OSError:
                            # Pad unreadable sectors with zeros (forensic safe mode)
                            chunk = b"\x00" * self.CHUNK_SIZE
                    else:
                        chunk = src.read(self.CHUNK_SIZE)

                    if not chunk:
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

                    # Progress
                    elapsed = time.time() - start_time
                    mb_per_sec = (total_bytes / (1024 * 1024)) / elapsed if elapsed > 0 else 0

                    pct = int((total_bytes / target_bytes) * 100) if target_bytes > 0 else 0
                    eta_str = "Calculating..."
                    if mb_per_sec > 0:
                        remaining = max(0, target_bytes - total_bytes)
                        eta_seconds = remaining / (mb_per_sec * 1024 * 1024)
                        eta_str = time.strftime("%H:%M:%S", time.gmtime(eta_seconds))

                    self._emit(total_bytes, mb_per_sec, hasher.md5_hex, pct, eta_str)

            # Finalize writer
            try:
                writer.close()
            except Exception as e:
                raise DeadAcquisitionError(
                    f"Evidence writer finalization failed: {e}"
                ) from e

            if not self._is_running:
                raise DeadAcquisitionError("Process aborted by user.")

            # Post-acquisition hash verification
            source_sha256 = "SKIPPED"
            hash_match = None

            if self.verify_hash:
                self._emit(total_bytes, 0.0, hasher.md5_hex, 100,
                           "Verifying Source Hash (re-reading device)...")
                source_sha256 = self._verify_source(target_bytes)
                if source_sha256 not in ("ERROR",):
                    hash_match = (source_sha256 == hasher.sha256_hex)
                else:
                    hash_match = False

            return {
                "sha256_final": hasher.sha256_hex,
                "md5_final": hasher.md5_hex,
                "total_bytes": total_bytes,
                "source_sha256": source_sha256,
                "hash_match": hash_match,
            }

        except DeadAcquisitionError:
            _safe_close_writer()
            raise
        except Exception as e:
            _safe_close_writer()
            raise DeadAcquisitionError(f"Dead acquisition failed: {e}") from e
