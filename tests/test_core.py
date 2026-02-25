# Tests for rfi core modules: Session, StreamHasher, RawWriter, policy helpers.
# Tests for audit: ForensicLogger, Ed25519 signing.
# Tests for report: ReportEngine TXT/PDF generation.

import hashlib
import json
import os
import tempfile
import pytest

from rfi.core.session import Session, SessionState, SessionStateError
from rfi.core.hashing import StreamHasher
from rfi.core.acquisition.raw import RawWriter
from rfi.core.policy import build_dd_command
from rfi.audit.logger import ForensicLogger, ForensicLoggerError
from rfi.audit.verify import AuditChainVerifier


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


# ═══════════════════════════════════════════════════════════════════════
# ForensicLogger tests
# ═══════════════════════════════════════════════════════════════════════

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


# ═══════════════════════════════════════════════════════════════════════
# Ed25519 Signing tests
# ═══════════════════════════════════════════════════════════════════════

class TestAuditSigning:
    def test_keygen_sign_verify_roundtrip(self):
        """Generate keypair → sign → verify must pass."""
        from rfi.audit.signing import (
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
        from rfi.audit.signing import (
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
        from rfi.audit.signing import verify_audit_signature

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
        from rfi.report.report_engine import ReportEngine

        with tempfile.TemporaryDirectory() as tmpdir:
            data = self._sample_report_data(tmpdir)
            ReportEngine.generate_reports(data)

            assert os.path.exists(data["txt_path"]), "TXT report not created"
            content = open(data["txt_path"]).read()
            assert "TEST-RPT" in content
            assert "FORENSIC ACQUISITION REPORT" in content

    def test_pdf_report_generated(self):
        from rfi.report.report_engine import ReportEngine

        with tempfile.TemporaryDirectory() as tmpdir:
            data = self._sample_report_data(tmpdir)
            ReportEngine.generate_reports(data)

            assert os.path.exists(data["pdf_path"]), "PDF report not created"
            assert os.path.getsize(data["pdf_path"]) > 0, "PDF is empty"
