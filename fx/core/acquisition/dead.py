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
from fx.core.acquisition.bad_sector_map import BadSectorMap


class DeadAcquisitionError(Exception):
    """Raised on unrecoverable dead-acquisition failure."""
    pass


# Linux ioctl constant for BLKGETSIZE64
_BLKGETSIZE64 = 0x80081272


def _is_block_device(path: str) -> bool:
    """Return True if *path* is a block device."""
    import stat as _stat
    try:
        return _stat.S_ISBLK(os.stat(path).st_mode)
    except OSError:
        return False


def _get_source_size(path: str) -> int:
    """Return the byte-size of a block device, regular file, or directory.

    For directories the total size of all contained files is returned
    (used as an *approximate* progress target; the actual tar stream
    will be slightly larger due to headers / padding).

    For block devices the function first tries a direct ioctl; if that
    fails with PermissionError it falls back to ``pkexec blockdev --getsize64``.
    """
    # Directory: walk and sum file sizes
    if os.path.isdir(path):
        total = 0
        for root, _dirs, files in os.walk(path):
            for fname in files:
                try:
                    total += os.path.getsize(os.path.join(root, fname))
                except OSError:
                    pass
        return total

    import stat as _stat
    mode = os.stat(path).st_mode
    if _stat.S_ISBLK(mode):
        # Try direct ioctl first (works when running as root)
        try:
            with open(path, "rb") as f:
                buf = fcntl.ioctl(f.fileno(), _BLKGETSIZE64, b"\x00" * 8)
                return struct.unpack("Q", buf)[0]
        except PermissionError:
            pass

        # Fallback: pkexec elevated blockdev
        result = subprocess.run(
            ["pkexec", "blockdev", "--getsize64", path],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            return int(result.stdout.strip())
        raise PermissionError(
            f"Cannot read device size for {path}. "
            "pkexec authentication was cancelled or failed."
        )
    return os.path.getsize(path)


def _apply_local_write_blocker(disk: str) -> None:
    """Set the local block device read-only via ``pkexec blockdev --setro``."""
    result = subprocess.run(
        ["pkexec", "blockdev", "--setro", disk],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise DeadAcquisitionError(
            f"Write-blocker failed (blockdev --setro): {result.stderr.strip()}"
        )
    # Verify
    result = subprocess.run(
        ["pkexec", "blockdev", "--getro", disk],
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
        description: str = "",
        notes: str = "",
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
        self.description = description
        self.notes = notes

        self._is_running = True
        self._elevated_proc: subprocess.Popen | None = None
        # Bad sector error map (DDSecure / ddrescue-style)
        self._bad_sector_map = BadSectorMap(
            source=source_path,
            output=output_file,
            chunk_size=self.CHUNK_SIZE,
        )
        # Legacy compatibility
        self._bad_sectors: list[dict] = []

    def stop(self) -> None:
        """Request a graceful stop of the acquisition loop."""
        self._is_running = False
        # Kill elevated subprocess if one is running
        if self._elevated_proc is not None:
            try:
                self._elevated_proc.terminate()
            except Exception:
                pass

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
            "bad_sector_count": self._bad_sector_map.count,
            "bad_sector_bytes": self._bad_sector_map.total_bad_bytes,
        })

    # ── Writer factory ──────────────────────────────────────────────

    def _create_writer(self):
        from fx.core.acquisition.base import create_evidence_writer
        return create_evidence_writer(
            self.format_type, self.output_file,
            case_number=self.case_no, examiner_name=self.examiner,
            description=self.description, notes=self.notes,
        )

    # ── Post-acquisition verification ───────────────────────────────

    def _verify_output(self, expected_sha256: str) -> tuple[str, bool | None]:
        """Re-read the written output file and verify its SHA-256 matches.

        This is the FTK Imager-style “re-verification” step: the image
        on disk is read back and hashed independently to confirm it was
        written correctly.

        Returns (output_sha256, match_flag).
        """
        import hashlib
        if not os.path.isfile(self.output_file):
            return "ERROR", False
        sha = hashlib.sha256()
        try:
            fsize = os.path.getsize(self.output_file)
            verified = 0
            start = time.time()
            with open(self.output_file, "rb") as f:
                while True:
                    chunk = f.read(self.CHUNK_SIZE)
                    if not chunk:
                        break
                    sha.update(chunk)
                    verified += len(chunk)
                    self._emit_verify_progress(verified, fsize, start)
            digest = sha.hexdigest()
            return digest, (digest == expected_sha256)
        except Exception:
            return "ERROR", False

    def _verify_source(self, target_bytes: int) -> str:
        """Re-read source and compute SHA-256 for verification.

        Emits progress events so the UI can display verification speed/ETA.
        """
        import hashlib
        sha = hashlib.sha256()
        verified_bytes = 0
        start_time = time.time()
        try:
            src = self._open_source()
            try:
                if os.path.isdir(self.source_path):
                    # Directory (tar stream): read until EOF
                    while self._is_running:
                        chunk = src.read(self.CHUNK_SIZE)
                        if not chunk:
                            break
                        sha.update(chunk)
                        verified_bytes += len(chunk)
                        self._emit_verify_progress(verified_bytes, target_bytes, start_time)
                else:
                    remaining = target_bytes
                    while remaining > 0 and self._is_running:
                        to_read = min(self.CHUNK_SIZE, remaining)
                        chunk = src.read(to_read)
                        if not chunk:
                            break
                        sha.update(chunk)
                        remaining -= len(chunk)
                        verified_bytes += len(chunk)
                        self._emit_verify_progress(verified_bytes, target_bytes, start_time)
            finally:
                self._close_source(src)
                # Clean up elevated / tar subprocess
                if self._elevated_proc is not None:
                    try:
                        self._elevated_proc.wait(timeout=5)
                    except Exception:
                        self._elevated_proc.kill()
                    self._elevated_proc = None
            return sha.hexdigest()
        except Exception:
            return "ERROR"

    def _emit_verify_progress(self, verified_bytes: int, target_bytes: int, start_time: float) -> None:
        """Emit a progress event during the verification re-read phase."""
        elapsed = time.time() - start_time
        mb_per_sec = (verified_bytes / (1024 * 1024)) / elapsed if elapsed > 0 else 0
        pct = int((verified_bytes / target_bytes) * 100) if target_bytes > 0 else 0

        eta_str = "Calculating..."
        if mb_per_sec > 0:
            remaining = max(0, target_bytes - verified_bytes)
            eta_seconds = remaining / (mb_per_sec * 1024 * 1024)
            eta_str = time.strftime("%H:%M:%S", time.gmtime(eta_seconds))

        self.on_progress({
            "bytes_read": verified_bytes,
            "speed_mb_s": round(mb_per_sec, 2),
            "md5_current": "",
            "percentage": min(100, pct),
            "eta": f"Verifying… {eta_str}",
        })

    # ── Source I/O helpers (direct or pkexec-elevated) ───────────────

    def _open_source(self):
        """Open source for reading.  Returns a file-like object.

        * **Directory** → ``tar cf -`` (deterministic, sorted) piped to stdout.
        * **Block device** → direct ``open()``; on PermissionError falls back
          to ``pkexec dd``.
        * **Regular file** → direct ``open()``.
        """
        # Directory: logical acquisition via deterministic tar stream
        if os.path.isdir(self.source_path):
            abs_path = os.path.abspath(self.source_path)
            cmd = [
                "tar", "cf", "-",
                "--sort=name",
                "--numeric-owner",
                "-C", os.path.dirname(abs_path),
                os.path.basename(abs_path),
            ]
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self._elevated_proc = proc
            return proc.stdout

        try:
            return open(self.source_path, "rb")
        except PermissionError:
            if not _is_block_device(self.source_path):
                raise
            # Elevated read via pkexec dd (single polkit prompt)
            cmd = [
                "pkexec", "dd",
                f"if={self.source_path}",
                f"bs={self.CHUNK_SIZE}",
                "status=none",
            ]
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self._elevated_proc = proc
            return proc.stdout

    @staticmethod
    def _close_source(src) -> None:
        """Close the file-like returned by ``_open_source``."""
        try:
            src.close()
        except Exception:
            pass

    # ── DDSecure-style granular bad sector retry ────────────────────

    # Retry granularity levels: 4 MB → 64 KB → 4 KB → 512 B
    _RETRY_BLOCK_SIZES = [64 * 1024, 4096, 512]

    def _read_with_granular_retry(
        self,
        src,
        chunk_offset: int,
        chunk_length: int,
        original_error: str,
    ) -> bytes:
        """Read a failed chunk using progressively smaller block sizes.

        DDSecure-style: when a large read fails, subdivide the region into
        smaller blocks and retry each one.  Successfully read sub-blocks are
        kept; still-unreadable sub-blocks are zero-padded and recorded in
        the bad sector map with their *exact* offset and length.

        Returns a bytes object of exactly *chunk_length* bytes.
        """
        result = bytearray()
        sub_offset = chunk_offset
        remaining = chunk_length

        # Determine the smallest retry block size to use
        retry_sizes = [bs for bs in self._RETRY_BLOCK_SIZES if bs < chunk_length]
        if not retry_sizes:
            # Chunk is already at minimum size — record and zero-pad
            self._bad_sector_map.record(chunk_offset, chunk_length, original_error, retry_count=0)
            self._bad_sectors.append({
                "offset": chunk_offset, "length": chunk_length, "error": original_error,
            })
            try:
                src.seek(chunk_length, os.SEEK_CUR)
            except (OSError, AttributeError):
                pass
            return b"\x00" * chunk_length

        smallest_block = retry_sizes[-1]  # e.g. 512

        # Try to seek back to the start of the failed region
        try:
            src.seek(chunk_offset, os.SEEK_SET)
        except (OSError, AttributeError):
            # Non-seekable stream (tar/pipe): just zero-pad the whole chunk
            self._bad_sector_map.record(chunk_offset, chunk_length, original_error, retry_count=0)
            self._bad_sectors.append({
                "offset": chunk_offset, "length": chunk_length, "error": original_error,
            })
            return b"\x00" * chunk_length

        # Read in smallest-block increments to find exact bad offsets
        while remaining > 0 and self._is_running:
            to_read = min(smallest_block, remaining)
            retry_count = 0
            max_retries = 3
            read_ok = False

            while retry_count < max_retries:
                try:
                    data = src.read(to_read)
                    if data:
                        result.extend(data)
                        sub_offset += len(data)
                        remaining -= len(data)
                        read_ok = True
                        break
                    else:
                        # EOF
                        remaining = 0
                        read_ok = True
                        break
                except OSError as sub_err:
                    retry_count += 1
                    if retry_count >= max_retries:
                        # Truly unreadable — zero-pad and log
                        self._bad_sector_map.record(
                            sub_offset, to_read, str(sub_err), retry_count=retry_count,
                        )
                        self._bad_sectors.append({
                            "offset": sub_offset, "length": to_read, "error": str(sub_err),
                        })
                        result.extend(b"\x00" * to_read)
                        sub_offset += to_read
                        remaining -= to_read
                        read_ok = True
                        # Skip past the bad region
                        try:
                            src.seek(sub_offset, os.SEEK_SET)
                        except (OSError, AttributeError):
                            pass
                        break
                    # Retry: seek back to the sub-block start
                    try:
                        src.seek(sub_offset, os.SEEK_SET)
                    except (OSError, AttributeError):
                        break

            if not read_ok:
                # Fallback: zero-pad remainder
                self._bad_sector_map.record(
                    sub_offset, remaining, original_error, retry_count=retry_count,
                )
                self._bad_sectors.append({
                    "offset": sub_offset, "length": remaining, "error": original_error,
                })
                result.extend(b"\x00" * remaining)
                remaining = 0

        # Ensure we return exactly chunk_length bytes
        if len(result) < chunk_length:
            result.extend(b"\x00" * (chunk_length - len(result)))
        return bytes(result[:chunk_length])

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
            if os.path.isdir(self.source_path):
                raise DeadAcquisitionError("Source directory contains no files.")
            raise DeadAcquisitionError("Source has zero size.")

        # Write-blocker (block devices only — not applicable to directories)
        if self.write_blocker and not os.path.isdir(self.source_path):
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
            src = self._open_source()
            try:
                while self._is_running:
                    chunk_start = time.time()

                    if self.safe_mode:
                        try:
                            chunk = src.read(self.CHUNK_SIZE)
                        except OSError as _read_err:
                            # DDSecure-style: retry with smaller blocks to
                            # pinpoint exact bad sector offsets
                            chunk = self._read_with_granular_retry(
                                src, total_bytes, self.CHUNK_SIZE, str(_read_err),
                            )
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
            finally:
                self._close_source(src)
                # Clean up elevated process
                if self._elevated_proc is not None:
                    try:
                        self._elevated_proc.wait(timeout=5)
                    except Exception:
                        self._elevated_proc.kill()
                    self._elevated_proc = None

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
                # Reset progress to 0% — verification re-reads the full source
                self._emit_verify_progress(0, target_bytes, time.time())
                source_sha256 = self._verify_source(target_bytes)
                if source_sha256 not in ("ERROR",):
                    hash_match = (source_sha256 == hasher.sha256_hex)
                else:
                    hash_match = False

            # Write DDSecure-style bad-sector error map if any sectors failed
            error_map_paths = {}
            if self._bad_sector_map.has_errors():
                self._bad_sector_map.coalesce()
                try:
                    error_map_paths = self._bad_sector_map.export_all(
                        self.output_file, device_size=target_bytes,
                    )
                except OSError:
                    pass

            # Post-acquisition output re-verification (re-read written file)
            output_sha256 = "SKIPPED"
            output_match = None
            if self._is_running and self.format_type == "RAW":
                output_sha256, output_match = self._verify_output(hasher.sha256_hex)

            return {
                "sha256_final": hasher.sha256_hex,
                "md5_final": hasher.md5_hex,
                "total_bytes": total_bytes,
                "source_sha256": source_sha256,
                "hash_match": hash_match,
                "bad_sectors": self._bad_sector_map.count,
                "bad_sector_bytes": self._bad_sector_map.total_bad_bytes,
                "bad_sector_summary": self._bad_sector_map.summary(),
                "error_map_paths": error_map_paths,
                "output_sha256": output_sha256,
                "output_match": output_match,
            }

        except DeadAcquisitionError:
            _safe_close_writer()
            raise
        except Exception as e:
            _safe_close_writer()
            raise DeadAcquisitionError(f"Dead acquisition failed: {e}") from e
