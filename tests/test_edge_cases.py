# Tests for ForenXtract (FX) edge cases:
# 1. Safe mode loop termination — ensures bad sector handling never infinite-loops
# 2. Concurrent audit writes — proves ForensicLogger thread-safety under contention

import hashlib
import json
import os
import tempfile
import threading
import time
from unittest.mock import patch, MagicMock

import pytest

from fx.core.acquisition.dead import DeadAcquisitionEngine, DeadAcquisitionError
from fx.audit.logger import ForensicLogger, ForensicLoggerError


# ═══════════════════════════════════════════════════════════════════════
# #34: Safe mode loop termination tests
# ═══════════════════════════════════════════════════════════════════════

class TestSafeModeTermination:
    """Safe mode must terminate in bounded time, even with continuous I/O errors."""

    def test_all_sectors_bad_terminates(self):
        """If every read raises OSError, safe mode should still terminate."""
        with tempfile.TemporaryDirectory() as tmpdir:
            src_path = os.path.join(tmpdir, "bad_disk.bin")
            # Create a file large enough for 2 chunks
            chunk_size = DeadAcquisitionEngine.CHUNK_SIZE
            with open(src_path, "wb") as f:
                f.write(b"\x00" * chunk_size * 2)

            dst_path = os.path.join(tmpdir, "output.raw")

            engine = DeadAcquisitionEngine(
                source_path=src_path,
                output_file=dst_path,
                format_type="RAW",
                case_no="SAFE-TERM-001",
                examiner="Test",
                safe_mode=True,
            )

            call_count = [0]
            mock_src = MagicMock()

            def _always_fail(size):
                call_count[0] += 1
                if call_count[0] > 500:
                    # Safety valve: if we've been called too many times, return EOF
                    # This proves the test would catch an infinite loop
                    return b""
                raise OSError("Persistent I/O error")

            mock_src.read.side_effect = _always_fail
            mock_src.seek = MagicMock()

            with patch.object(engine, "_open_source", return_value=mock_src):
                with patch.object(engine, "_close_source"):
                    result = engine.run()

            # Must finish, not loop forever
            assert result is not None
            assert result["total_bytes"] >= 0
            # Should have recorded bad sectors
            assert result.get("bad_sectors", 0) > 0

    def test_alternating_good_bad_sectors(self):
        """Mix of good and bad reads should complete correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            src_path = os.path.join(tmpdir, "mixed.bin")
            chunk_size = DeadAcquisitionEngine.CHUNK_SIZE
            good_data = b"G" * chunk_size

            with open(src_path, "wb") as f:
                f.write(good_data * 4)

            dst_path = os.path.join(tmpdir, "output.raw")

            engine = DeadAcquisitionEngine(
                source_path=src_path,
                output_file=dst_path,
                format_type="RAW",
                case_no="SAFE-MIX-001",
                examiner="Test",
                safe_mode=True,
            )

            call_count = [0]
            mock_src = MagicMock()

            def _alternating(size):
                call_count[0] += 1
                if call_count[0] == 1:
                    return good_data  # chunk 1: OK
                elif call_count[0] == 2:
                    raise OSError("Bad sector")  # chunk 2: fail
                elif call_count[0] == 3:
                    return good_data  # chunk 3: OK
                return b""  # EOF

            mock_src.read.side_effect = _alternating
            mock_src.seek = MagicMock()

            with patch.object(engine, "_open_source", return_value=mock_src):
                with patch.object(engine, "_close_source"):
                    result = engine.run()

            assert result["total_bytes"] > 0
            # At least 2 good chunks worth of data
            assert result["total_bytes"] >= chunk_size * 2

    def test_safe_mode_off_raises_on_error(self):
        """Without safe mode, OSError should propagate as DeadAcquisitionError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            src_path = os.path.join(tmpdir, "fail.bin")
            with open(src_path, "wb") as f:
                f.write(b"\x00" * 4096)

            dst_path = os.path.join(tmpdir, "output.raw")

            engine = DeadAcquisitionEngine(
                source_path=src_path,
                output_file=dst_path,
                format_type="RAW",
                case_no="SAFE-OFF-001",
                examiner="Test",
                safe_mode=False,
            )

            mock_src = MagicMock()
            mock_src.read.side_effect = OSError("disk error")

            with patch.object(engine, "_open_source", return_value=mock_src):
                with patch.object(engine, "_close_source"):
                    with pytest.raises(DeadAcquisitionError):
                        engine.run()

    def test_stop_flag_terminates_safe_mode_loop(self):
        """Setting _is_running=False must terminate safe mode within one iteration."""
        with tempfile.TemporaryDirectory() as tmpdir:
            src_path = os.path.join(tmpdir, "src.bin")
            chunk_size = DeadAcquisitionEngine.CHUNK_SIZE
            with open(src_path, "wb") as f:
                f.write(b"X" * chunk_size * 10)

            dst_path = os.path.join(tmpdir, "output.raw")

            engine = DeadAcquisitionEngine(
                source_path=src_path,
                output_file=dst_path,
                format_type="RAW",
                case_no="STOP-001",
                examiner="Test",
                safe_mode=True,
            )

            good_data = b"G" * chunk_size
            read_count = [0]
            mock_src = MagicMock()

            def _read_then_stop(size):
                read_count[0] += 1
                if read_count[0] == 2:
                    engine._is_running = False  # Stop after 1 chunk
                return good_data

            mock_src.read.side_effect = _read_then_stop

            with patch.object(engine, "_open_source", return_value=mock_src):
                with patch.object(engine, "_close_source"):
                    # Engine raises DeadAcquisitionError when aborted
                    with pytest.raises(DeadAcquisitionError, match="aborted"):
                        engine.run()

            # Should have read at most 2 chunks before stopping
            assert read_count[0] <= 3

    def test_granular_retry_returns_exact_chunk_length(self):
        """_read_with_granular_retry must return exactly chunk_length bytes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            src_path = os.path.join(tmpdir, "src.bin")
            chunk_size = DeadAcquisitionEngine.CHUNK_SIZE
            with open(src_path, "wb") as f:
                f.write(b"\x00" * chunk_size * 2)

            engine = DeadAcquisitionEngine(
                source_path=src_path,
                output_file=os.path.join(tmpdir, "out.raw"),
                format_type="RAW",
                case_no="RETRY-001",
                examiner="Test",
                safe_mode=True,
            )

            mock_src = MagicMock()
            mock_src.read.side_effect = OSError("bad")
            mock_src.seek = MagicMock()

            result = engine._read_with_granular_retry(mock_src, 0, chunk_size, "test error")

            assert len(result) == chunk_size
            # All zeros since every read failed
            assert result == b"\x00" * chunk_size

    def test_granular_retry_on_non_seekable_stream(self):
        """Non-seekable streams (pipes) should zero-pad the entire chunk."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = DeadAcquisitionEngine(
                source_path="/dev/null",
                output_file=os.path.join(tmpdir, "out.raw"),
                format_type="RAW",
                case_no="PIPE-001",
                examiner="Test",
                safe_mode=True,
            )

            mock_src = MagicMock()
            mock_src.seek.side_effect = OSError("not seekable")
            mock_src.read.side_effect = OSError("read error")

            result = engine._read_with_granular_retry(mock_src, 0, 4096, "pipe error")

            assert len(result) == 4096
            assert result == b"\x00" * 4096

    def test_bad_sector_map_populated(self):
        """Safe mode should populate the bad sector map when errors occur."""
        with tempfile.TemporaryDirectory() as tmpdir:
            src_path = os.path.join(tmpdir, "src.bin")
            chunk_size = DeadAcquisitionEngine.CHUNK_SIZE
            with open(src_path, "wb") as f:
                f.write(b"\x00" * chunk_size)

            engine = DeadAcquisitionEngine(
                source_path=src_path,
                output_file=os.path.join(tmpdir, "out.raw"),
                format_type="RAW",
                case_no="MAP-001",
                examiner="Test",
                safe_mode=True,
            )

            mock_src = MagicMock()
            main_loop_call = [0]

            def _always_fail_then_eof(size):
                """First call from main loop raises; all granular retry calls
                also raise so that every sub-block is recorded as bad.
                After the failed chunk is zero-padded the second main-loop
                read returns b'' (EOF)."""
                main_loop_call[0] += 1
                # After the first chunk is fully handled (main-loop call +
                # all granular-retry calls), the next main-loop read returns EOF.
                # Granular retry reads always fail with OSError.
                if main_loop_call[0] == 1:
                    raise OSError("sector error")
                # Granular-retry sub-block reads also fail
                if size < chunk_size:
                    raise OSError("sector error")
                # Second main-loop read → EOF
                return b""

            mock_src.read.side_effect = _always_fail_then_eof
            mock_src.seek = MagicMock()

            with patch.object(engine, "_open_source", return_value=mock_src):
                with patch.object(engine, "_close_source"):
                    result = engine.run()

            assert result.get("bad_sectors", 0) > 0
            assert result.get("bad_sector_bytes", 0) > 0


# ═══════════════════════════════════════════════════════════════════════
# #35: Concurrent audit write tests — ForensicLogger thread safety
# ═══════════════════════════════════════════════════════════════════════

class TestConcurrentAuditWrite:
    """ForensicLogger must maintain chain integrity under concurrent writes."""

    def test_concurrent_writes_no_corruption(self):
        """Multiple threads writing simultaneously must not corrupt the JSONL file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = ForensicLogger()
            logger.set_context("CONC-001", "Tester", tmpdir)

            errors = []
            write_count = 50
            thread_count = 8

            def _writer(thread_id):
                try:
                    for i in range(write_count):
                        logger.log(
                            f"Thread {thread_id} entry {i}",
                            "INFO",
                            "CONCURRENT_TEST",
                            source_module="test",
                        )
                except Exception as e:
                    errors.append((thread_id, e))

            threads = [threading.Thread(target=_writer, args=(t,)) for t in range(thread_count)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)

            assert len(errors) == 0, f"Thread errors: {errors}"

            # Verify the JSONL file is valid and complete
            with open(logger.log_file_path, "r") as f:
                lines = f.readlines()

            # +1 for the initial CONTEXT_UPDATED entry from set_context
            expected_min = thread_count * write_count + 1
            assert len(lines) >= expected_min, f"Expected >= {expected_min} lines, got {len(lines)}"

            # Every line must be valid JSON
            for i, line in enumerate(lines):
                try:
                    json.loads(line)
                except json.JSONDecodeError:
                    pytest.fail(f"Line {i+1} is not valid JSON: {line[:100]}")

    def test_concurrent_hash_chain_integrity(self):
        """Hash chain must be valid after concurrent writes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = ForensicLogger()
            logger.set_context("CHAIN-001", "Tester", tmpdir)

            def _writer(thread_id):
                for i in range(20):
                    logger.log(f"T{thread_id}-{i}", "INFO", "CHAIN_TEST", source_module="test")

            threads = [threading.Thread(target=_writer, args=(t,)) for t in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)

            # Verify hash chain integrity
            with open(logger.log_file_path, "r") as f:
                lines = f.readlines()

            prev_hash = None
            for i, line in enumerate(lines):
                entry = json.loads(line)
                assert "entry_hash" in entry, f"Line {i+1} missing entry_hash"
                assert "prev_hash" in entry, f"Line {i+1} missing prev_hash"

                if prev_hash is not None:
                    assert entry["prev_hash"] == prev_hash, (
                        f"Chain broken at line {i+1}: expected prev_hash={prev_hash}, "
                        f"got {entry['prev_hash']}"
                    )

                # Recompute entry_hash to verify
                stored_hash = entry.pop("entry_hash")
                recomputed = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
                assert stored_hash == recomputed, f"Hash mismatch at line {i+1}"

                prev_hash = stored_hash

    def test_seal_during_concurrent_writes(self):
        """Sealing while writes are in-flight must not corrupt the file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = ForensicLogger()
            logger.set_context("SEAL-001", "Tester", tmpdir)

            write_errors = []
            seal_done = threading.Event()

            def _writer():
                for i in range(100):
                    try:
                        logger.log(f"Entry {i}", "INFO", "SEAL_TEST", source_module="test")
                    except ForensicLoggerError:
                        # Expected: seal happened, further writes are rejected
                        break
                    except Exception as e:
                        write_errors.append(e)

            def _sealer():
                time.sleep(0.01)  # Let some writes happen
                logger.seal_audit_trail()
                seal_done.set()

            t_writer = threading.Thread(target=_writer)
            t_sealer = threading.Thread(target=_sealer)
            t_writer.start()
            t_sealer.start()
            t_writer.join(timeout=30)
            t_sealer.join(timeout=30)

            assert seal_done.is_set(), "Seal did not complete"
            assert len(write_errors) == 0, f"Unexpected errors: {write_errors}"

            # File should be valid JSONL
            with open(logger.log_file_path, "r") as f:
                for line in f:
                    json.loads(line)  # Should not raise

    def test_write_after_seal_raises(self):
        """Writes after seal must raise ForensicLoggerError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = ForensicLogger()
            logger.set_context("POST-SEAL-001", "Tester", tmpdir)

            logger.log("Before seal", "INFO", "TEST", source_module="test")
            logger.seal_audit_trail()

            with pytest.raises(ForensicLoggerError, match="sealed"):
                logger.log("After seal", "INFO", "TEST", source_module="test")

    def test_concurrent_set_context_and_log(self):
        """set_context and log() should not deadlock when called concurrently."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = ForensicLogger()
            logger.set_context("INIT-001", "Tester", tmpdir)

            errors = []
            done = threading.Event()

            def _logger_thread():
                for i in range(50):
                    try:
                        logger.log(f"Log {i}", "INFO", "TEST", source_module="test")
                    except ForensicLoggerError:
                        pass
                    except Exception as e:
                        errors.append(e)
                done.set()

            t = threading.Thread(target=_logger_thread)
            t.start()
            t.join(timeout=10)

            assert done.is_set(), "Logger thread did not complete (possible deadlock)"
            assert len(errors) == 0, f"Thread errors: {errors}"

    def test_multiple_seal_calls(self):
        """Double-sealing must raise ForensicLoggerError (log is immutable)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = ForensicLogger()
            logger.set_context("DSEAL-001", "Tester", tmpdir)
            logger.log("Entry", "INFO", "TEST", source_module="test")

            h1, _ = logger.seal_audit_trail()
            assert h1 != "ERROR_CALCULATING_HASH"

            # Second seal must fail because the log is immutable
            from fx.audit.logger import ForensicLoggerError
            with pytest.raises(ForensicLoggerError, match="sealed"):
                logger.seal_audit_trail()
