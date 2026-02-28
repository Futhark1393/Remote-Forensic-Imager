# Tests for ForenXtract (FX) core modules: Session, StreamHasher, RawWriter, policy helpers.
# Tests for audit: ForensicLogger, Ed25519 signing, SyslogHandler, AuditChainVerifier.
# Tests for report: ReportEngine TXT/PDF generation.
# Tests for deps: dependency_checker.
# Tests for writers: EwfWriter, AFF4Writer.

import hashlib
import json
import os
import socket
import tempfile
from unittest.mock import patch, MagicMock
import pytest

from fx.core.session import Session, SessionState, SessionStateError
from fx.core.hashing import StreamHasher
from fx.core.acquisition.raw import RawWriter
from fx.core.acquisition.lz4_writer import LZ4Writer, LZ4_AVAILABLE
from fx.core.acquisition.ewf import EwfWriter, EWF_AVAILABLE
from fx.core.acquisition.aff4 import AFF4Writer, AFF4_AVAILABLE, AFF4NotAvailableError
from fx.core.policy import build_dd_command, _validate_disk_path
from fx.audit.logger import ForensicLogger, ForensicLoggerError
from fx.audit.verify import AuditChainVerifier
from fx.audit.syslog_handler import SyslogHandler
from fx.deps.dependency_checker import run_dependency_check


# ═══════════════════════════════════════════════════════════════════════
# Session state machine tests
# ═══════════════════════════════════════════════════════════════════════

class TestSession:
    def test_initial_state_is_new(self):
        s = Session()
        assert s.state == SessionState.NEW

    def test_happy_path_full_workflow(self):
        s = Session()
        s.bind_context("CASE-001", "Investigator", "/tmp/evidence")
        assert s.state == SessionState.CONTEXT_BOUND
        assert s.case_no == "CASE-001"

        s.begin_acquisition()
        assert s.state == SessionState.ACQUIRING

        s.begin_verification()
        assert s.state == SessionState.VERIFYING

        s.seal()
        assert s.state == SessionState.SEALED

        s.finalize()
        assert s.state == SessionState.DONE

    def test_skip_verification(self):
        """ACQUIRING → SEALED is valid when verify is not requested."""
        s = Session()
        s.bind_context("CASE-002", "Examiner", "/tmp")
        s.begin_acquisition()
        s.seal()
        assert s.state == SessionState.SEALED
        s.finalize()
        assert s.state == SessionState.DONE

    def test_illegal_new_to_acquiring(self):
        s = Session()
        with pytest.raises(SessionStateError, match="Illegal transition"):
            s.begin_acquisition()

    def test_illegal_double_bind(self):
        s = Session()
        s.bind_context("C1", "E1", "/tmp")
        with pytest.raises(SessionStateError):
            s.bind_context("C2", "E2", "/tmp")

    def test_illegal_seal_from_new(self):
        s = Session()
        with pytest.raises(SessionStateError):
            s.seal()

    def test_illegal_finalize_from_acquiring(self):
        s = Session()
        s.bind_context("C", "E", "/tmp")
        s.begin_acquisition()
        with pytest.raises(SessionStateError):
            s.finalize()

    def test_no_transition_after_done(self):
        s = Session()
        s.bind_context("C", "E", "/tmp")
        s.begin_acquisition()
        s.seal()
        s.finalize()
        with pytest.raises(SessionStateError):
            s.begin_acquisition()

    def test_reset_returns_to_new(self):
        """reset() must return session to NEW and clear metadata."""
        s = Session()
        s.bind_context("C", "E", "/tmp")
        s.begin_acquisition()
        s.seal()
        s.finalize()
        s.reset()
        assert s.state == SessionState.NEW
        assert s.case_no is None
        assert s.examiner is None
        assert s.evidence_dir is None

    def test_reset_allows_new_workflow(self):
        """After reset, a full workflow should work again."""
        s = Session()
        s.bind_context("C1", "E1", "/tmp")
        s.begin_acquisition()
        s.seal()
        s.finalize()
        s.reset()
        # New workflow
        s.bind_context("C2", "E2", "/tmp")
        assert s.state == SessionState.CONTEXT_BOUND
        assert s.case_no == "C2"
        s.begin_acquisition()
        s.begin_verification()
        s.seal()
        s.finalize()

    def test_abort_from_acquiring(self):
        """abort() should transition ACQUIRING → CONTEXT_BOUND."""
        s = Session()
        s.bind_context("C", "E", "/tmp")
        s.begin_acquisition()
        s.abort()
        assert s.state == SessionState.CONTEXT_BOUND

    def test_abort_allows_retry(self):
        """After abort(), user can start a new acquisition without reset."""
        s = Session()
        s.bind_context("C", "E", "/tmp")
        s.begin_acquisition()
        s.abort()
        # Retry should work
        s.begin_acquisition()
        assert s.state == SessionState.ACQUIRING

    def test_abort_from_wrong_state_raises(self):
        """abort() from CONTEXT_BOUND should raise."""
        s = Session()
        s.bind_context("C", "E", "/tmp")
        with pytest.raises(SessionStateError):
            s.abort()
        # State unchanged after failed transition
        assert s.state == SessionState.CONTEXT_BOUND

    def test_reset_from_acquiring(self):
        """reset() should work from any state, not just DONE."""
        s = Session()
        s.bind_context("C", "E", "/tmp")
        s.begin_acquisition()
        s.reset()
        assert s.state == SessionState.NEW


# ═══════════════════════════════════════════════════════════════════════
# StreamHasher tests
# ═══════════════════════════════════════════════════════════════════════

class TestStreamHasher:
    def test_empty_hash(self):
        h = StreamHasher()
        assert h.md5_hex == hashlib.md5(b"").hexdigest()
        assert h.sha256_hex == hashlib.sha256(b"").hexdigest()

    def test_known_data(self):
        data = b"forensic evidence stream test data"
        h = StreamHasher()
        h.update(data)
        assert h.md5_hex == hashlib.md5(data).hexdigest()
        assert h.sha256_hex == hashlib.sha256(data).hexdigest()

    def test_incremental_matches_bulk(self):
        chunks = [b"chunk1", b"chunk2", b"chunk3"]
        h = StreamHasher()
        for c in chunks:
            h.update(c)

        combined = b"".join(chunks)
        assert h.md5_hex == hashlib.md5(combined).hexdigest()
        assert h.sha256_hex == hashlib.sha256(combined).hexdigest()


# ═══════════════════════════════════════════════════════════════════════
# RawWriter tests
# ═══════════════════════════════════════════════════════════════════════

class TestRawWriter:
    def test_write_and_read_back(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".raw") as tmp:
            path = tmp.name

        try:
            w = RawWriter(path)
            w.write(b"hello ")
            w.write(b"world")
            w.close()

            with open(path, "rb") as f:
                assert f.read() == b"hello world"
        finally:
            os.unlink(path)

    def test_empty_write(self):
        """Writing no data should produce an empty file."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".raw") as tmp:
            path = tmp.name
        try:
            w = RawWriter(path)
            w.close()
            assert os.path.getsize(path) == 0
        finally:
            os.unlink(path)

    def test_binary_data(self):
        """Should correctly write binary data including null bytes."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".raw") as tmp:
            path = tmp.name
        try:
            data = bytes(range(256)) * 100
            w = RawWriter(path)
            w.write(data)
            w.close()
            with open(path, "rb") as f:
                assert f.read() == data
        finally:
            os.unlink(path)


# ═══════════════════════════════════════════════════════════════════════
# LZ4Writer tests
# ═══════════════════════════════════════════════════════════════════════

@pytest.mark.skipif(not LZ4_AVAILABLE, reason="lz4 not installed")
class TestLZ4Writer:
    def test_lz4_compress_and_decompress(self):
        """Write compressed data and verify decompression."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".raw.lz4") as tmp:
            path = tmp.name

        try:
            # Write data through LZ4Writer
            test_data = b"hello " * 100 + b"world" * 50  # Repetitive data compresses well
            w = LZ4Writer(path)
            w.write(test_data)
            w.close()

            # Verify compressed file is smaller
            compressed_size = os.path.getsize(path)
            original_size = len(test_data)
            assert compressed_size < original_size, "Compression did not reduce file size"

            # Decompress and verify
            import lz4.frame
            with open(path, "rb") as f:
                decompressed = lz4.frame.decompress(f.read())
            assert decompressed == test_data

        finally:
            os.unlink(path)

    def test_lz4_incremental_writes(self):
        """Test multiple write() calls produce correct compressed output."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".raw.lz4") as tmp:
            path = tmp.name

        try:
            # Write in chunks
            w = LZ4Writer(path)
            chunk1 = b"chunk1 " * 50
            chunk2 = b"chunk2 " * 50
            chunk3 = b"chunk3 " * 50
            w.write(chunk1)
            w.write(chunk2)
            w.write(chunk3)
            w.close()

            # Decompress and verify
            import lz4.frame
            with open(path, "rb") as f:
                decompressed = lz4.frame.decompress(f.read())
            expected = chunk1 + chunk2 + chunk3
            assert decompressed == expected

        finally:
            os.unlink(path)

    def test_lz4_empty_file(self):
        """Test LZ4 compression of empty data."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".raw.lz4") as tmp:
            path = tmp.name

        try:
            w = LZ4Writer(path)
            w.close()

            # File should have LZ4 frame header but no data
            file_size = os.path.getsize(path)
            assert file_size > 0, "LZ4 frame should have header even for empty data"

            # Decompress and verify empty result
            import lz4.frame
            with open(path, "rb") as f:
                decompressed = lz4.frame.decompress(f.read())
            assert decompressed == b""

        finally:
            os.unlink(path)

    def test_lz4_large_binary_data(self):
        """Test with larger binary-like data (similar to disk imaging)."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".raw.lz4") as tmp:
            path = tmp.name

        try:
            # Simulate 100 MB of semi-random data
            chunk_size = 1024 * 1024  # 1 MB
            test_data = b""
            w = LZ4Writer(path)
            
            for i in range(10):  # 10 MB total
                chunk = bytes([(j + i) % 256 for j in range(chunk_size)])
                test_data += chunk
                w.write(chunk)
            w.close()

            # Verify compression ratio
            compressed_size = os.path.getsize(path)
            original_size = len(test_data)
            ratio = compressed_size / original_size
            assert ratio < 0.95, f"Compression ratio {ratio:.2%} should be < 95% for repetitive data"

            # Decompress and verify
            import lz4.frame
            with open(path, "rb") as f:
                decompressed = lz4.frame.decompress(f.read())
            assert decompressed == test_data

        finally:
            os.unlink(path)

    def test_lz4_double_close_safe(self):
        """Double-close must not raise (idempotent guard)."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".raw.lz4") as tmp:
            path = tmp.name
        try:
            w = LZ4Writer(path)
            w.write(b"data")
            w.close()
            w.close()  # Second close must be a no-op
            assert os.path.isfile(path)
        finally:
            os.unlink(path)


# ═══════════════════════════════════════════════════════════════════════
# Policy / dd command tests
# ═══════════════════════════════════════════════════════════════════════

class TestPolicy:
    def test_dd_command_safe_mode(self):
        cmd = build_dd_command("/dev/sda", 0, safe_mode=True)
        assert "conv=noerror,sync" in cmd
        assert "if=/dev/sda" in cmd
        assert "skip=0" in cmd

    def test_dd_command_no_safe_mode(self):
        cmd = build_dd_command("/dev/sdb", 4096, safe_mode=False)
        assert "conv=" not in cmd
        assert "skip=4096" in cmd

    def test_dd_command_resume_offset(self):
        cmd = build_dd_command("/dev/sda", 1048576, safe_mode=True)
        assert "skip=1048576" in cmd
        assert "iflag=skip_bytes" in cmd

    def test_dd_command_contains_sudo(self):
        cmd = build_dd_command("/dev/sda", 0, safe_mode=True)
        assert cmd.startswith("sudo")

    def test_dd_command_block_size(self):
        cmd = build_dd_command("/dev/sda", 0, safe_mode=False)
        assert "bs=4M" in cmd

    def test_dd_status_none(self):
        """dd should suppress its own progress output."""
        cmd = build_dd_command("/dev/sda", 0, safe_mode=True)
        assert "status=none" in cmd

    def test_validate_disk_path_valid(self):
        """Valid device paths should pass validation."""
        for path in ["/dev/sda", "/dev/sda1", "/dev/nvme0n1", "/dev/mapper/vg0-root"]:
            _validate_disk_path(path)  # Should not raise

    def test_validate_disk_path_rejects_injection(self):
        """Paths with shell metacharacters must be rejected."""
        for bad in ["/dev/sda; rm -rf /", "/dev/sda && cat /etc/shadow", "$(whoami)", "/dev/sda|reboot"]:
            with pytest.raises(ValueError, match="Invalid disk path"):
                _validate_disk_path(bad)

    def test_build_dd_rejects_bad_disk(self):
        """build_dd_command must reject obviously malicious disk paths."""
        with pytest.raises(ValueError, match="Invalid disk path"):
            build_dd_command("/dev/sda; rm -rf /", 0, safe_mode=True)


# ═══════════════════════════════════════════════════════════════════════
# ForensicLogger tests
# ═══════════════════════════════════════════════════════════════════════

class TestAuditChainVerifier:
    """Direct tests for AuditChainVerifier."""

    def test_verify_valid_chain(self):
        """A properly constructed chain should verify."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = ForensicLogger()
            logger.set_context("VERIFY-001", "Tester", tmpdir)
            logger.log("entry 1", "INFO", "TEST")
            logger.log("entry 2", "INFO", "TEST")
            ok, msg = AuditChainVerifier.verify_chain(logger.log_file_path)
            assert ok

    def test_verify_missing_file(self):
        ok, msg = AuditChainVerifier.verify_chain("/nonexistent/file.jsonl")
        assert not ok
        assert "not found" in msg.lower()

    def test_verify_empty_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            path = f.name
        try:
            ok, msg = AuditChainVerifier.verify_chain(path)
            # Empty file = 0 records, should pass (no chain to break)
            assert ok
        finally:
            os.unlink(path)

    def test_verify_corrupted_json(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write("not valid json\n")
            path = f.name
        try:
            ok, msg = AuditChainVerifier.verify_chain(path)
            assert not ok
        finally:
            os.unlink(path)

    def test_verify_missing_entry_hash(self):
        """Entry without entry_hash should fail."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            genesis = hashlib.sha256(b"FORENSIC_GENESIS_BLOCK").hexdigest()
            entry = {"message": "test", "prev_hash": genesis}
            f.write(json.dumps(entry, sort_keys=True) + "\n")
            path = f.name
        try:
            ok, msg = AuditChainVerifier.verify_chain(path)
            assert not ok
            assert "entry_hash" in msg.lower() or "missing" in msg.lower()
        finally:
            os.unlink(path)

    def test_verify_broken_prev_hash(self):
        """Wrong prev_hash should break the chain."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            entry = {"message": "test", "prev_hash": "wrong_hash"}
            entry_json = json.dumps(entry, sort_keys=True)
            entry_hash = hashlib.sha256(entry_json.encode()).hexdigest()
            entry["entry_hash"] = entry_hash
            f.write(json.dumps(entry, sort_keys=True) + "\n")
            path = f.name
        try:
            ok, msg = AuditChainVerifier.verify_chain(path)
            assert not ok
            assert "chain broken" in msg.lower() or "expected" in msg.lower()
        finally:
            os.unlink(path)


class TestForensicLogger:
    def test_log_and_verify_chain(self):
        """Write multiple entries, then verify the hash chain is intact."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = ForensicLogger()
            logger.set_context("TEST-001", "Tester", tmpdir)

            logger.log("First entry", "INFO", "TEST_EVENT")
            logger.log("Second entry", "INFO", "TEST_EVENT")
            logger.log("Third entry", "WARNING", "TEST_EVENT")

            log_path = logger.log_file_path

            # Verify chain before sealing
            ok, msg = AuditChainVerifier.verify_chain(log_path)
            assert ok, f"Chain verification failed: {msg}"

    def test_seal_blocks_writes(self):
        """After sealing, further log() calls must raise ForensicLoggerError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = ForensicLogger()
            logger.set_context("TEST-SEAL", "Tester", tmpdir)
            logger.log("Before seal", "INFO", "TEST_EVENT")

            logger.seal_audit_trail()

            with pytest.raises(ForensicLoggerError, match="sealed"):
                logger.log("After seal", "INFO", "TEST_EVENT")

    def test_sealed_chain_is_valid(self):
        """Chain must remain valid after sealing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = ForensicLogger()
            logger.set_context("TEST-VALID", "Tester", tmpdir)
            logger.log("Entry 1", "INFO", "TEST")
            logger.log("Entry 2", "INFO", "TEST")

            log_path = logger.log_file_path
            logger.seal_audit_trail()

            ok, msg = AuditChainVerifier.verify_chain(log_path)
            assert ok, f"Sealed chain verification failed: {msg}"

    def test_tampered_chain_detected(self):
        """Modifying a log entry must break chain verification."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = ForensicLogger()
            logger.set_context("TEST-TAMPER", "Tester", tmpdir)
            logger.log("Entry 1", "INFO", "TEST")
            logger.log("Entry 2", "INFO", "TEST")
            logger.log("Entry 3", "INFO", "TEST")

            log_path = logger.log_file_path

            # Tamper: modify the second line
            with open(log_path, "r") as f:
                lines = f.readlines()
            entry = json.loads(lines[1])
            entry["message"] = "TAMPERED"
            lines[1] = json.dumps(entry, sort_keys=True) + "\n"
            with open(log_path, "w") as f:
                f.writelines(lines)

            ok, msg = AuditChainVerifier.verify_chain(log_path)
            assert not ok, "Tampered chain should fail verification"

    def test_sanitize_filename(self):
        """sanitize_filename must strip non-alphanumeric characters."""
        logger = ForensicLogger()
        assert logger.sanitize_filename("CASE-001") == "CASE-001"
        assert logger.sanitize_filename("hello world!") == "hello_world_"
        assert logger.sanitize_filename("../../../etc") == "_________etc"
        assert logger.sanitize_filename("") == "UNASSIGNED"
        assert logger.sanitize_filename("  ") == "UNASSIGNED"

    def test_set_context_nonexistent_dir(self):
        """set_context with a non-existent directory must raise."""
        logger = ForensicLogger()
        with pytest.raises(ForensicLoggerError, match="does not exist"):
            logger.set_context("C", "E", "/nonexistent/path/xyz")

    def test_set_context_creates_audit_subdir(self):
        """set_context must create an 'audit' subdirectory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = ForensicLogger()
            logger.set_context("CTX-001", "Examiner", tmpdir)
            assert os.path.isdir(os.path.join(tmpdir, "audit"))
            assert "audit" in logger.log_file_path

    def test_set_context_after_seal_raises(self):
        """Cannot modify context after sealing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = ForensicLogger()
            logger.set_context("C", "E", tmpdir)
            logger.log("test", "INFO", "TEST")
            logger.seal_audit_trail()
            with pytest.raises(ForensicLoggerError, match="sealed"):
                logger.set_context("C2", "E2", tmpdir)

    def test_log_with_hash_context(self):
        """hash_context dict should be embedded in the log entry."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = ForensicLogger()
            logger.set_context("HC-001", "Tester", tmpdir)
            ctx = {"md5": "abc", "sha256": "def"}
            logger.log("hash event", "INFO", "HASH", hash_context=ctx)

            with open(logger.log_file_path, "r") as f:
                lines = f.readlines()
            # Last line should contain hash_context
            last_entry = json.loads(lines[-1])
            assert last_entry.get("hash_context") == ctx

    def test_seal_returns_hash(self):
        """seal_audit_trail must return a valid hex hash."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = ForensicLogger()
            logger.set_context("SEAL-H", "T", tmpdir)
            logger.log("e1", "INFO", "TEST")
            final_hash, _ = logger.seal_audit_trail()
            assert len(final_hash) == 64  # SHA-256 hex
            assert all(c in "0123456789abcdef" for c in final_hash)

    def test_logger_with_syslog_handler(self):
        """Logger should forward entries to syslog handler without errors."""
        mock_handler = MagicMock()
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = ForensicLogger(syslog_handler=mock_handler)
            logger.set_context("SYSLOG-001", "Tester", tmpdir)
            logger.log("syslog test", "INFO", "TEST")
            # emit should have been called at least twice (set_context + log)
            assert mock_handler.emit.call_count >= 2

    def test_logger_session_id_is_uuid(self):
        """session_id must be a valid UUID."""
        import uuid
        logger = ForensicLogger()
        uuid.UUID(logger.session_id)  # raises ValueError if invalid


# ═══════════════════════════════════════════════════════════════════════
# Ed25519 Signing tests
# ═══════════════════════════════════════════════════════════════════════

class TestAuditSigning:
    def test_keygen_sign_verify_roundtrip(self):
        """Generate keypair → sign → verify must pass."""
        from fx.audit.signing import (
            generate_signing_keypair,
            sign_audit_trail,
            verify_audit_signature,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a dummy audit file
            audit_path = os.path.join(tmpdir, "test_audit.jsonl")
            with open(audit_path, "w") as f:
                f.write('{"event": "test", "entry_hash": "abc123"}\n')

            # Generate keys
            priv_path, pub_path = generate_signing_keypair(tmpdir)
            assert os.path.exists(priv_path)
            assert os.path.exists(pub_path)

            # Sign
            sig_path = sign_audit_trail(audit_path, priv_path)
            assert os.path.exists(sig_path)
            assert sig_path.endswith(".sig")

            # Verify
            ok, msg = verify_audit_signature(audit_path, sig_path, pub_path)
            assert ok, f"Signature verification failed: {msg}"

    def test_tampered_file_fails_signature(self):
        """Modifying the file after signing must fail verification."""
        from fx.audit.signing import (
            generate_signing_keypair,
            sign_audit_trail,
            verify_audit_signature,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            audit_path = os.path.join(tmpdir, "tampered_audit.jsonl")
            with open(audit_path, "w") as f:
                f.write('{"event": "original"}\n')

            priv_path, pub_path = generate_signing_keypair(tmpdir)
            sig_path = sign_audit_trail(audit_path, priv_path)

            # Tamper
            with open(audit_path, "a") as f:
                f.write('{"event": "injected"}\n')

            ok, msg = verify_audit_signature(audit_path, sig_path, pub_path)
            assert not ok, "Tampered file should fail signature verification"

    def test_missing_sig_file(self):
        """Verify must fail gracefully when .sig file is missing."""
        from fx.audit.signing import verify_audit_signature

        with tempfile.TemporaryDirectory() as tmpdir:
            audit_path = os.path.join(tmpdir, "audit.jsonl")
            with open(audit_path, "w") as f:
                f.write('{"event": "test"}\n')

            ok, msg = verify_audit_signature(audit_path, audit_path + ".sig", "/nonexistent.pub")
            assert not ok


# ═══════════════════════════════════════════════════════════════════════
# ReportEngine tests
# ═══════════════════════════════════════════════════════════════════════

class TestReportEngine:
    def _sample_report_data(self, tmpdir: str) -> dict:
        return {
            "case_no": "TEST-RPT",
            "examiner": "Tester",
            "ip": "10.0.0.1",
            "timestamp_utc": "2026-02-25T18:00:00Z",
            "duration": "00:05:23",
            "format_type": "RAW",
            "target_filename": "evidence_TEST.raw",
            "triage_requested": False,
            "writeblock_requested": False,
            "write_blocker": False,
            "throttle_enabled": False,
            "throttle_val": "0",
            "safe_mode": True,
            "remote_sha256": "SKIPPED",
            "local_sha256": "abcd1234" * 8,
            "local_md5": "ef567890" * 4,
            "hash_match": None,
            "audit_hash": "deadbeef" * 8,
            "kernel_seal_success": False,
            "txt_path": os.path.join(tmpdir, "Report_TEST.txt"),
            "pdf_path": os.path.join(tmpdir, "Report_TEST.pdf"),
        }

    def test_txt_report_generated(self):
        from fx.report.report_engine import ReportEngine

        with tempfile.TemporaryDirectory() as tmpdir:
            data = self._sample_report_data(tmpdir)
            ReportEngine.generate_reports(data)

            assert os.path.exists(data["txt_path"]), "TXT report not created"
            content = open(data["txt_path"]).read()
            assert "TEST-RPT" in content
            assert "FORENSIC ACQUISITION REPORT" in content

    def test_pdf_report_generated(self):
        from fx.report.report_engine import ReportEngine

        with tempfile.TemporaryDirectory() as tmpdir:
            data = self._sample_report_data(tmpdir)
            ReportEngine.generate_reports(data)

            assert os.path.exists(data["pdf_path"]), "PDF report not created"
            assert os.path.getsize(data["pdf_path"]) > 0, "PDF is empty"

    def test_executive_summary_skipped(self):
        """When remote hash is SKIPPED, summary should be neutral."""
        from fx.report.report_engine import ReportEngine
        summary = ReportEngine._executive_summary("SKIPPED", None, "aabbcc", False)
        assert "completed" in summary.lower()
        assert "SKIPPED" not in summary  # should not say hash match/mismatch

    def test_executive_summary_match(self):
        from fx.report.report_engine import ReportEngine
        summary = ReportEngine._executive_summary("abc123", True, "aabbcc", True)
        assert "PASSED" in summary

    def test_executive_summary_mismatch(self):
        from fx.report.report_engine import ReportEngine
        summary = ReportEngine._executive_summary("abc123", False, "aabbcc", False)
        assert "FAILED" in summary
        assert "NOT VERIFIED" in summary

    def test_executive_summary_safe_mode_note(self):
        from fx.report.report_engine import ReportEngine
        summary = ReportEngine._executive_summary("SKIPPED", None, "aabbcc", False, safe_mode=True)
        assert "zero" in summary.lower() or "padded" in summary.lower()

    def test_report_contains_case_data(self):
        """TXT report should contain all critical fields."""
        from fx.report.report_engine import ReportEngine

        with tempfile.TemporaryDirectory() as tmpdir:
            data = self._sample_report_data(tmpdir)
            ReportEngine.generate_reports(data)
            content = open(data["txt_path"]).read()
            assert "TEST-RPT" in content
            assert "Tester" in content
            assert "10.0.0.1" in content
            assert "RAW" in content
            assert "EXECUTIVE SUMMARY" in content


# ═══════════════════════════════════════════════════════════════════════
# SyslogHandler tests
# ═══════════════════════════════════════════════════════════════════════

class TestSyslogHandler:
    def test_invalid_protocol_raises(self):
        with pytest.raises(ValueError, match="Unsupported"):
            SyslogHandler("127.0.0.1", protocol="INVALID")

    def test_udp_format_rfc5424(self):
        """RFC 5424 formatting should produce a valid syslog message."""
        with patch("socket.socket"):
            handler = SyslogHandler("127.0.0.1", 514, protocol="UDP")
            entry = {
                "timestamp": "2026-02-28T12:00:00Z",
                "session_id": "test-session",
                "case_no": "CASE-001",
                "event_type": "TEST",
                "severity": "INFO",
                "event_id": "evt-1",
                "source_module": "test",
                "message": "test message",
            }
            payload = handler._format_rfc5424(entry)
            assert isinstance(payload, bytes)
            decoded = payload.decode("utf-8")
            assert "CASE-001" in decoded
            assert "test message" in decoded
            assert "fx" in decoded
            handler.close()

    def test_cef_format(self):
        """CEF formatting should produce a CEF-prefixed message."""
        with patch("socket.socket"):
            handler = SyslogHandler("127.0.0.1", 514, protocol="UDP", cef_mode=True)
            entry = {
                "severity": "WARNING",
                "event_type": "DISK_ACCESS",
                "message": "test CEF",
                "case_no": "C-002",
                "examiner": "Tester",
                "session_id": "sid",
                "event_id": "eid",
                "source_module": "engine",
                "timestamp": "2026-02-28T12:00:00Z",
            }
            payload = handler._format_cef(entry)
            assert payload.startswith(b"CEF:0|")
            assert b"ForenXtract" in payload
            handler.close()

    def test_emit_best_effort(self):
        """emit() should never raise even on socket error."""
        with patch("socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock.sendto.side_effect = OSError("send failed")
            mock_sock_cls.return_value = mock_sock
            handler = SyslogHandler("127.0.0.1", 514, protocol="UDP")
            # Should not raise
            handler.emit({"severity": "INFO", "message": "test"})
            handler.close()

    def test_close_idempotent(self):
        """Calling close multiple times should not raise."""
        with patch("socket.socket"):
            handler = SyslogHandler("127.0.0.1", 514, protocol="UDP")
            handler.close()
            handler.close()  # second call should be safe


# ═══════════════════════════════════════════════════════════════════════
# EwfWriter tests
# ═══════════════════════════════════════════════════════════════════════

class TestEwfWriter:
    def test_ewf_not_available_raises(self):
        """EwfWriter must raise RuntimeError when pyewf is missing."""
        with patch("fx.core.acquisition.ewf.EWF_AVAILABLE", False):
            with pytest.raises(RuntimeError, match="pyewf"):
                EwfWriter("/tmp/test.E01")

    @pytest.mark.skipif(not EWF_AVAILABLE, reason="pyewf not installed")
    def test_ewf_write_and_close(self):
        """Basic EwfWriter write + close with pyewf available."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".E01") as tmp:
            path = tmp.name
        try:
            w = EwfWriter(path)
            w.write(b"evidence data " * 100)
            w.close()
            assert os.path.exists(path)
        finally:
            if os.path.exists(path):
                os.unlink(path)

    @pytest.mark.skipif(not EWF_AVAILABLE, reason="pyewf not installed")
    def test_ewf_close_idempotent(self):
        """Calling close() twice should not raise."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".E01") as tmp:
            path = tmp.name
        try:
            w = EwfWriter(path)
            w.write(b"data")
            w.close()
            w.close()  # second call should be safe
        finally:
            if os.path.exists(path):
                os.unlink(path)


# ═══════════════════════════════════════════════════════════════════════
# AFF4Writer tests
# ═══════════════════════════════════════════════════════════════════════

class TestAFF4Writer:
    def test_aff4_not_available_raises(self):
        """AFF4Writer must raise AFF4NotAvailableError when pyaff4 is missing."""
        with patch("fx.core.acquisition.aff4.AFF4_AVAILABLE", False):
            with pytest.raises(AFF4NotAvailableError):
                AFF4Writer("/tmp/test.aff4")

    def _make_aff4_writer(self):
        """Create an AFF4Writer with mocked internals (no pyaff4 needed)."""
        with patch("fx.core.acquisition.aff4.AFF4_AVAILABLE", True):
            # Bypass __init__'s pyaff4 calls by constructing manually
            w = AFF4Writer.__new__(AFF4Writer)
            w._output_path = "/tmp/test.aff4"
            w._resolver = MagicMock()
            w._volume = MagicMock()
            w._stream = MagicMock()
            w._bytes_written = 0
            w._closed = False
            return w

    def test_aff4_write_and_close(self):
        """AFF4Writer write/close via mock when pyaff4 is not installed."""
        w = self._make_aff4_writer()
        w.write(b"evidence " * 50)
        assert w.bytes_written == len(b"evidence " * 50)
        w._stream.Write.assert_called()
        w.close()
        assert w._closed is True

    def test_aff4_close_idempotent(self):
        """Calling close() twice should not raise."""
        w = self._make_aff4_writer()
        w.write(b"data")
        w.close()
        w.close()  # second call should be safe

    def test_aff4_write_after_close_raises(self):
        """Writing after close must raise IOError."""
        w = self._make_aff4_writer()
        w.close()
        with pytest.raises(IOError):
            w.write(b"should fail")

    def test_aff4_empty_write_ignored(self):
        """Writing empty bytes should be a no-op."""
        w = self._make_aff4_writer()
        w.write(b"")
        assert w.bytes_written == 0
        w._stream.Write.assert_not_called()
        w.close()


# ═══════════════════════════════════════════════════════════════════════
# DependencyChecker tests
# ═══════════════════════════════════════════════════════════════════════

class TestDependencyChecker:
    def test_returns_two_lists(self):
        """run_dependency_check must return (py_missing, native_missing)."""
        py_missing, native_missing = run_dependency_check()
        assert isinstance(py_missing, list)
        assert isinstance(native_missing, list)

    def test_paramiko_available(self):
        """paramiko should be installed in our environment."""
        py_missing, _ = run_dependency_check()
        assert "paramiko" not in py_missing

    def test_fpdf_available(self):
        """fpdf should be installed in our environment."""
        py_missing, _ = run_dependency_check()
        assert "fpdf" not in py_missing
