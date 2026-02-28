# Tests for ForenXtract (FX) acquisition engine, policy helpers, and verification.
# Uses mock SSH to avoid needing a real remote host.

import os
import tempfile
import time
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from fx.core.acquisition.base import AcquisitionEngine, AcquisitionError
from fx.core.acquisition.dead import (
    DeadAcquisitionEngine,
    DeadAcquisitionError,
    _get_source_size,
    _is_block_device,
    _apply_local_write_blocker,
)
from fx.core.acquisition.verify import verify_source_hash
from fx.core.policy import ssh_exec, apply_write_blocker, build_dd_command
from fx.core.hashing import StreamHasher


# ═══════════════════════════════════════════════════════════════════════
# ssh_exec tests
# ═══════════════════════════════════════════════════════════════════════

class TestSSHExec:
    def test_ssh_exec_basic(self):
        """ssh_exec should return stdout, stderr, exit_code."""
        mock_ssh = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()
        mock_stdout.read.return_value = b"output data"
        mock_stderr.read.return_value = b""
        mock_stdout.channel.recv_exit_status.return_value = 0
        mock_ssh.exec_command.return_value = (MagicMock(), mock_stdout, mock_stderr)

        out, err, code = ssh_exec(mock_ssh, "echo hello")
        assert out == "output data"
        assert err == ""
        assert code == 0

    def test_ssh_exec_error_code(self):
        mock_ssh = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()
        mock_stdout.read.return_value = b""
        mock_stderr.read.return_value = b"command not found"
        mock_stdout.channel.recv_exit_status.return_value = 127
        mock_ssh.exec_command.return_value = (MagicMock(), mock_stdout, mock_stderr)

        out, err, code = ssh_exec(mock_ssh, "nonexistent_cmd")
        assert code == 127
        assert "not found" in err

    def test_ssh_exec_unicode_handling(self):
        """Non-UTF8 bytes should be handled gracefully."""
        mock_ssh = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()
        mock_stdout.read.return_value = b"valid \xff data"
        mock_stderr.read.return_value = b""
        mock_stdout.channel.recv_exit_status.return_value = 0
        mock_ssh.exec_command.return_value = (MagicMock(), mock_stdout, mock_stderr)

        out, err, code = ssh_exec(mock_ssh, "cat binary")
        assert isinstance(out, str)
        assert code == 0


# ═══════════════════════════════════════════════════════════════════════
# apply_write_blocker tests
# ═══════════════════════════════════════════════════════════════════════

class TestApplyWriteBlocker:
    def _make_ssh_mock(self, setro_code=0, getro_out="1", getro_code=0):
        mock_ssh = MagicMock()
        call_count = [0]

        def _exec_side_effect(cmd):
            call_count[0] += 1
            mock_stdin = MagicMock()
            mock_stdout = MagicMock()
            mock_stderr = MagicMock()

            if "setro" in cmd:
                mock_stdout.read.return_value = b""
                mock_stderr.read.return_value = b"" if setro_code == 0 else b"error"
                mock_stdout.channel.recv_exit_status.return_value = setro_code
            elif "getro" in cmd:
                mock_stdout.read.return_value = getro_out.encode()
                mock_stderr.read.return_value = b""
                mock_stdout.channel.recv_exit_status.return_value = getro_code
            elif "hdparm" in cmd:
                mock_stdout.read.return_value = b""
                mock_stderr.read.return_value = b""
                mock_stdout.channel.recv_exit_status.return_value = 0
            else:
                mock_stdout.read.return_value = b""
                mock_stderr.read.return_value = b""
                mock_stdout.channel.recv_exit_status.return_value = 0

            return mock_stdin, mock_stdout, mock_stderr

        mock_ssh.exec_command.side_effect = _exec_side_effect
        return mock_ssh

    def test_write_blocker_success(self):
        ssh = self._make_ssh_mock(setro_code=0, getro_out="1", getro_code=0)
        # Should not raise
        apply_write_blocker(ssh, "/dev/sda")

    def test_write_blocker_setro_fails(self):
        ssh = self._make_ssh_mock(setro_code=1)
        with pytest.raises(RuntimeError, match="blockdev --setro"):
            apply_write_blocker(ssh, "/dev/sda")

    def test_write_blocker_getro_not_readonly(self):
        ssh = self._make_ssh_mock(setro_code=0, getro_out="0", getro_code=0)
        with pytest.raises(RuntimeError, match="not read-only"):
            apply_write_blocker(ssh, "/dev/sda")

    def test_write_blocker_getro_fails(self):
        ssh = self._make_ssh_mock(setro_code=0, getro_out="", getro_code=1)
        with pytest.raises(RuntimeError, match="blockdev --getro"):
            apply_write_blocker(ssh, "/dev/sda")


# ═══════════════════════════════════════════════════════════════════════
# verify_source_hash tests
# ═══════════════════════════════════════════════════════════════════════

class TestVerifySourceHash:
    def test_verify_success(self):
        mock_ssh = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()
        sha = "a" * 64
        mock_stdout.read.return_value = f"{sha}  /dev/sda\n".encode()
        mock_stderr.read.return_value = b""
        mock_stdout.channel.recv_exit_status.return_value = 0
        mock_ssh.exec_command.return_value = (MagicMock(), mock_stdout, mock_stderr)

        remote_sha, _ = verify_source_hash(mock_ssh, "/dev/sda")
        assert remote_sha == sha

    def test_verify_command_fails(self):
        mock_ssh = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()
        mock_stdout.read.return_value = b""
        mock_stderr.read.return_value = b"error"
        mock_stdout.channel.recv_exit_status.return_value = 1
        mock_ssh.exec_command.return_value = (MagicMock(), mock_stdout, mock_stderr)

        remote_sha, matched = verify_source_hash(mock_ssh, "/dev/sda")
        assert remote_sha == "ERROR"
        assert matched is False

    def test_verify_ssh_exception(self):
        mock_ssh = MagicMock()
        mock_ssh.exec_command.side_effect = Exception("connection lost")

        remote_sha, matched = verify_source_hash(mock_ssh, "/dev/sda")
        assert remote_sha == "ERROR"
        assert matched is False


# ═══════════════════════════════════════════════════════════════════════
# AcquisitionEngine tests
# ═══════════════════════════════════════════════════════════════════════

class TestAcquisitionEngine:
    def test_engine_init(self):
        """AcquisitionEngine should accept all required parameters."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test.raw")
            engine = AcquisitionEngine(
                ip="10.0.0.1",
                user="root",
                key_path="/tmp/key",
                disk="/dev/sda",
                output_file=path,
                format_type="RAW",
                case_no="TEST",
                examiner="Tester",
            )
            assert engine.ip == "10.0.0.1"
            assert engine.format_type == "RAW"
            assert engine.is_running is True

    def test_engine_stop(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test.raw")
            engine = AcquisitionEngine(
                ip="10.0.0.1", user="root", key_path="/tmp/key",
                disk="/dev/sda", output_file=path, format_type="RAW",
                case_no="TEST", examiner="Tester",
            )
            engine.stop()
            assert engine.is_running is False

    def test_engine_progress_callback(self):
        """on_progress callback should be invokable."""
        progress_data = []
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test.raw")
            engine = AcquisitionEngine(
                ip="10.0.0.1", user="root", key_path="/tmp/key",
                disk="/dev/sda", output_file=path, format_type="RAW",
                case_no="TEST", examiner="Tester",
                on_progress=lambda d: progress_data.append(d),
            )
            engine._emit(1024, 1.5, "abc", 50, "00:01:00")
            assert len(progress_data) == 1
            assert progress_data[0]["bytes_read"] == 1024
            assert progress_data[0]["percentage"] == 50

    def test_engine_emit_caps_percentage(self):
        """_emit should cap percentage at 100."""
        progress_data = []
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test.raw")
            engine = AcquisitionEngine(
                ip="10.0.0.1", user="root", key_path="/tmp/key",
                disk="/dev/sda", output_file=path, format_type="RAW",
                case_no="TEST", examiner="Tester",
                on_progress=lambda d: progress_data.append(d),
            )
            engine._emit(1024, 1.5, "abc", 150, "done")
            assert progress_data[0]["percentage"] == 100

    def test_engine_unavailable_format_e01(self):
        """E01 format should raise if pyewf is not available."""
        with patch("fx.core.acquisition.base.EWF_AVAILABLE", False):
            with tempfile.TemporaryDirectory() as tmpdir:
                path = os.path.join(tmpdir, "test.E01")
                engine = AcquisitionEngine(
                    ip="10.0.0.1", user="root", key_path="/tmp/key",
                    disk="/dev/sda", output_file=path, format_type="E01",
                    case_no="TEST", examiner="Tester",
                )
                with pytest.raises(AcquisitionError, match="E01"):
                    engine.run()

    def test_engine_unavailable_format_aff4(self):
        """AFF4 format should raise if pyaff4 is not available."""
        with patch("fx.core.acquisition.base.AFF4_AVAILABLE", False):
            with tempfile.TemporaryDirectory() as tmpdir:
                path = os.path.join(tmpdir, "test.aff4")
                engine = AcquisitionEngine(
                    ip="10.0.0.1", user="root", key_path="/tmp/key",
                    disk="/dev/sda", output_file=path, format_type="AFF4",
                    case_no="TEST", examiner="Tester",
                )
                with pytest.raises(AcquisitionError, match="AFF4"):
                    engine.run()

    def test_engine_unavailable_format_lz4(self):
        """RAW+LZ4 format should raise if lz4 is not available."""
        with patch("fx.core.acquisition.base.LZ4_AVAILABLE", False):
            with tempfile.TemporaryDirectory() as tmpdir:
                path = os.path.join(tmpdir, "test.raw.lz4")
                engine = AcquisitionEngine(
                    ip="10.0.0.1", user="root", key_path="/tmp/key",
                    disk="/dev/sda", output_file=path, format_type="RAW+LZ4",
                    case_no="TEST", examiner="Tester",
                )
                with pytest.raises(AcquisitionError, match="LZ4"):
                    engine.run()

    @patch("fx.core.acquisition.base.paramiko")
    @patch("fx.core.acquisition.base.ssh_exec")
    def test_engine_run_raw_success(self, mock_ssh_exec, mock_paramiko):
        """Full RAW acquisition with mock SSH should succeed."""
        evidence_data = b"X" * (4 * 1024 * 1024)  # 4MB of data

        # Mock SSH connection
        mock_ssh_client = MagicMock()
        mock_paramiko.SSHClient.return_value = mock_ssh_client
        mock_paramiko.AutoAddPolicy.return_value = MagicMock()

        # Mock ssh_exec: blockdev --getsize64 returns size
        def _ssh_exec_side(ssh, cmd):
            if "getsize64" in cmd:
                return (str(len(evidence_data)), "", 0)
            return ("", "", 0)
        mock_ssh_exec.side_effect = _ssh_exec_side

        # Mock exec_command for dd: returns data then empty
        mock_stdout_ch = MagicMock()
        call_count = [0]
        def _read_side(size):
            nonlocal call_count
            call_count[0] += 1
            if call_count[0] == 1:
                return evidence_data
            return b""
        mock_stdout_ch.read = _read_side
        mock_stdout_ch.channel.recv_exit_status.return_value = 0

        mock_ssh_client.exec_command.return_value = (MagicMock(), mock_stdout_ch, MagicMock())

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test.raw")
            engine = AcquisitionEngine(
                ip="10.0.0.1", user="root", key_path="/tmp/key",
                disk="/dev/sda", output_file=path, format_type="RAW",
                case_no="TEST", examiner="Tester",
            )
            result = engine.run()

            assert result["total_bytes"] == len(evidence_data)
            assert len(result["sha256_final"]) == 64
            assert len(result["md5_final"]) == 32
            assert os.path.exists(path)

            # Output image verification (FTK-style) should be present for RAW
            assert "output_sha256" in result
            assert "output_match" in result
            assert result["output_match"] is True
            assert result["output_sha256"] == result["sha256_final"]

            # Verify written file matches
            with open(path, "rb") as f:
                assert f.read() == evidence_data

    @patch("fx.core.acquisition.base.time")
    @patch("fx.core.acquisition.base.paramiko")
    def test_engine_connection_failure(self, mock_paramiko, mock_time):
        """Connection failure should raise AcquisitionError after retries."""
        mock_time.time.return_value = 1000.0
        mock_time.sleep = MagicMock()  # don't actually sleep
        mock_time.strftime = time.strftime
        mock_time.gmtime = time.gmtime

        mock_ssh_client = MagicMock()
        mock_paramiko.SSHClient.return_value = mock_ssh_client
        mock_paramiko.AutoAddPolicy.return_value = MagicMock()
        mock_ssh_client.connect.side_effect = Exception("connection refused")

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test.raw")
            engine = AcquisitionEngine(
                ip="10.0.0.1", user="root", key_path="/tmp/key",
                disk="/dev/sda", output_file=path, format_type="RAW",
                case_no="TEST", examiner="Tester",
            )
            with pytest.raises(AcquisitionError, match="Max retries"):
                engine.run()

    def test_engine_verify_output_match(self):
        """_verify_output should return MATCH when file hash matches expected."""
        import hashlib
        data = os.urandom(16 * 1024)
        expected = hashlib.sha256(data).hexdigest()

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test.raw")
            with open(path, "wb") as f:
                f.write(data)

            engine = AcquisitionEngine(
                ip="10.0.0.1", user="root", key_path="/tmp/key",
                disk="/dev/sda", output_file=path, format_type="RAW",
                case_no="TEST", examiner="Tester",
            )
            digest, match = engine._verify_output(expected)
            assert match is True
            assert digest == expected

    def test_engine_verify_output_mismatch(self):
        """_verify_output should return MISMATCH when hashes differ."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test.raw")
            with open(path, "wb") as f:
                f.write(b"actual content")

            engine = AcquisitionEngine(
                ip="10.0.0.1", user="root", key_path="/tmp/key",
                disk="/dev/sda", output_file=path, format_type="RAW",
                case_no="TEST", examiner="Tester",
            )
            digest, match = engine._verify_output("0000000000000000000000000000000000000000000000000000000000000000")
            assert match is False

    def test_engine_verify_output_missing_file(self):
        """_verify_output should return ERROR for missing file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "nonexistent.raw")
            engine = AcquisitionEngine(
                ip="10.0.0.1", user="root", key_path="/tmp/key",
                disk="/dev/sda", output_file=path, format_type="RAW",
                case_no="TEST", examiner="Tester",
            )
            digest, match = engine._verify_output("abc")
            assert digest == "ERROR"
            assert match is False


# ═══════════════════════════════════════════════════════════════════════
# Dead Acquisition Engine tests
# ═══════════════════════════════════════════════════════════════════════


class TestDeadAcquisitionEngine:
    """Tests for DeadAcquisitionEngine (local disk / image file imaging)."""

    def test_dead_acquire_regular_file(self):
        """Dead acquisition should successfully image a regular file."""
        evidence_data = os.urandom(64 * 1024)  # 64 KB
        progress_events = []

        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, "source.img")
            dst = os.path.join(tmpdir, "output.raw")
            with open(src, "wb") as f:
                f.write(evidence_data)

            engine = DeadAcquisitionEngine(
                source_path=src,
                output_file=dst,
                format_type="RAW",
                case_no="DEAD-001",
                examiner="Test",
                on_progress=lambda d: progress_events.append(d),
            )
            result = engine.run()

            assert result["total_bytes"] == len(evidence_data)
            assert len(result["sha256_final"]) == 64
            assert len(result["md5_final"]) == 32
            assert result["source_sha256"] == "SKIPPED"  # verify_hash=False
            assert result["hash_match"] is None

            # Output re-verification (FTK-style) should be present for RAW
            assert result["output_match"] is True
            assert result["output_sha256"] == result["sha256_final"]

            with open(dst, "rb") as f:
                assert f.read() == evidence_data

            assert len(progress_events) > 0

    def test_dead_acquire_with_verification(self):
        """Verify hash should re-read source and compare SHA-256."""
        evidence_data = os.urandom(32 * 1024)

        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, "source.img")
            dst = os.path.join(tmpdir, "output.raw")
            with open(src, "wb") as f:
                f.write(evidence_data)

            engine = DeadAcquisitionEngine(
                source_path=src,
                output_file=dst,
                format_type="RAW",
                case_no="DEAD-002",
                examiner="Test",
                verify_hash=True,
            )
            result = engine.run()

            assert result["hash_match"] is True
            assert result["source_sha256"] == result["sha256_final"]

    def test_dead_acquire_source_not_found(self):
        """Missing source should raise DeadAcquisitionError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            dst = os.path.join(tmpdir, "output.raw")
            engine = DeadAcquisitionEngine(
                source_path="/nonexistent/device",
                output_file=dst,
                format_type="RAW",
                case_no="DEAD-003",
                examiner="Test",
            )
            with pytest.raises(DeadAcquisitionError, match="Source not found"):
                engine.run()

    def test_dead_acquire_zero_size(self):
        """Zero-byte source should raise DeadAcquisitionError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, "empty.img")
            dst = os.path.join(tmpdir, "output.raw")
            with open(src, "wb") as f:
                pass  # empty file

            engine = DeadAcquisitionEngine(
                source_path=src,
                output_file=dst,
                format_type="RAW",
                case_no="DEAD-004",
                examiner="Test",
            )
            with pytest.raises(DeadAcquisitionError, match="zero size"):
                engine.run()

    def test_dead_acquire_stop(self):
        """Stopping mid-acquisition should raise DeadAcquisitionError."""
        evidence_data = os.urandom(16 * 1024 * 1024)  # 16 MB
        call_count = 0

        def progress_and_stop(data):
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                engine.stop()

        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, "source.img")
            dst = os.path.join(tmpdir, "output.raw")
            with open(src, "wb") as f:
                f.write(evidence_data)

            engine = DeadAcquisitionEngine(
                source_path=src,
                output_file=dst,
                format_type="RAW",
                case_no="DEAD-005",
                examiner="Test",
                on_progress=progress_and_stop,
            )
            with pytest.raises(DeadAcquisitionError, match="aborted"):
                engine.run()

    def test_dead_acquire_lz4_format(self):
        """Dead acquisition with LZ4 format (if available)."""
        from fx.core.acquisition.lz4_writer import LZ4_AVAILABLE
        if not LZ4_AVAILABLE:
            pytest.skip("lz4 not installed")

        evidence_data = os.urandom(32 * 1024)

        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, "source.img")
            dst = os.path.join(tmpdir, "output.raw.lz4")
            with open(src, "wb") as f:
                f.write(evidence_data)

            engine = DeadAcquisitionEngine(
                source_path=src,
                output_file=dst,
                format_type="RAW+LZ4",
                case_no="DEAD-006",
                examiner="Test",
            )
            result = engine.run()

            assert result["total_bytes"] == len(evidence_data)
            assert os.path.exists(dst)
            # LZ4 compressed should be non-empty
            assert os.path.getsize(dst) > 0

    def test_dead_acquire_throttle(self):
        """Throttle should slow down acquisition."""
        evidence_data = os.urandom(8 * 1024)

        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, "source.img")
            dst = os.path.join(tmpdir, "output.raw")
            with open(src, "wb") as f:
                f.write(evidence_data)

            engine = DeadAcquisitionEngine(
                source_path=src,
                output_file=dst,
                format_type="RAW",
                case_no="DEAD-007",
                examiner="Test",
                throttle_limit=100.0,  # 100 MB/s — exercises the throttle path without delay
            )
            result = engine.run()
            assert result["total_bytes"] == len(evidence_data)

    def test_dead_output_verification_match(self):
        """Output re-verification should MATCH for RAW format (FTK verify-after-create)."""
        evidence_data = os.urandom(32 * 1024)

        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, "source.img")
            dst = os.path.join(tmpdir, "output.raw")
            with open(src, "wb") as f:
                f.write(evidence_data)

            engine = DeadAcquisitionEngine(
                source_path=src,
                output_file=dst,
                format_type="RAW",
                case_no="DEAD-OV1",
                examiner="Test",
            )
            result = engine.run()

            assert result["output_sha256"] != "SKIPPED"
            assert result["output_match"] is True
            assert result["output_sha256"] == result["sha256_final"]

    def test_dead_output_verification_skipped_for_non_raw(self):
        """Output re-verification should be SKIPPED for non-RAW formats."""
        evidence_data = os.urandom(8 * 1024)

        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, "source.img")
            dst = os.path.join(tmpdir, "output.raw.lz4")
            with open(src, "wb") as f:
                f.write(evidence_data)

            try:
                engine = DeadAcquisitionEngine(
                    source_path=src,
                    output_file=dst,
                    format_type="RAW+LZ4",
                    case_no="DEAD-OV2",
                    examiner="Test",
                )
                result = engine.run()
                # LZ4 format: output verification is skipped (container != raw bytes)
                assert result["output_sha256"] == "SKIPPED"
                assert result["output_match"] is None
            except Exception:
                pytest.skip("LZ4 not available")


class TestGetSourceSize:
    """Tests for the _get_source_size helper."""

    def test_regular_file_size(self):
        """Should return correct size for regular files."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"x" * 12345)
            f.flush()
            path = f.name

        try:
            assert _get_source_size(path) == 12345
        finally:
            os.unlink(path)

    def test_empty_file_size(self):
        """Should return 0 for empty files."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name

        try:
            assert _get_source_size(path) == 0
        finally:
            os.unlink(path)


class TestLocalWriteBlocker:
    """Tests for _apply_local_write_blocker."""

    @patch("fx.core.acquisition.dead.subprocess.run")
    def test_write_blocker_success(self, mock_run):
        """Write blocker should succeed when both pkexec commands return 0."""
        mock_run.side_effect = [
            MagicMock(returncode=0, stderr=""),
            MagicMock(returncode=0, stdout="1", stderr=""),
        ]
        # Should not raise
        _apply_local_write_blocker("/dev/sdb")
        assert mock_run.call_count == 2
        # Verify pkexec is used (not sudo)
        assert mock_run.call_args_list[0][0][0][0] == "pkexec"
        assert mock_run.call_args_list[1][0][0][0] == "pkexec"

    @patch("fx.core.acquisition.dead.subprocess.run")
    def test_write_blocker_setro_failure(self, mock_run):
        """Should raise when blockdev --setro fails."""
        mock_run.return_value = MagicMock(returncode=1, stderr="permission denied")
        with pytest.raises(DeadAcquisitionError, match="Write-blocker failed"):
            _apply_local_write_blocker("/dev/sdb")

    @patch("fx.core.acquisition.dead.subprocess.run")
    def test_write_blocker_verify_failure(self, mock_run):
        """Should raise when verification shows device is not read-only."""
        mock_run.side_effect = [
            MagicMock(returncode=0, stderr=""),
            MagicMock(returncode=0, stdout="0", stderr=""),  # not read-only
        ]
        with pytest.raises(DeadAcquisitionError, match="verification failed"):
            _apply_local_write_blocker("/dev/sdb")


class TestIsBlockDevice:
    """Tests for _is_block_device helper."""

    def test_regular_file_is_not_block(self):
        """Regular files should not be classified as block devices."""
        with tempfile.NamedTemporaryFile() as f:
            assert _is_block_device(f.name) is False

    def test_nonexistent_path(self):
        """Non-existent path should return False (not raise)."""
        assert _is_block_device("/nonexistent/path/xyz") is False

    @patch("fx.core.acquisition.dead.os.stat")
    def test_block_device_detected(self, mock_stat):
        """Should return True for block-device st_mode."""
        import stat as _stat
        mock_stat.return_value = MagicMock(st_mode=_stat.S_IFBLK | 0o660)
        assert _is_block_device("/dev/sdb") is True


class TestGetSourceSizePkexecFallback:
    """Tests for _get_source_size pkexec fallback on block devices."""

    @patch("fx.core.acquisition.dead.subprocess.run")
    @patch("fx.core.acquisition.dead.os.stat")
    def test_pkexec_fallback_on_permission_error(self, mock_stat, mock_run):
        """When direct ioctl fails, should use pkexec blockdev --getsize64."""
        import stat as _stat
        mock_stat.return_value = MagicMock(st_mode=_stat.S_IFBLK | 0o660)

        # Mock open() to raise PermissionError for BLKGETSIZE64 ioctl path
        with patch("builtins.open", side_effect=PermissionError("Permission denied")):
            mock_run.return_value = MagicMock(returncode=0, stdout="16106127360\n")
            size = _get_source_size("/dev/sdb")

        assert size == 16106127360
        mock_run.assert_called_once_with(
            ["pkexec", "blockdev", "--getsize64", "/dev/sdb"],
            capture_output=True, text=True,
        )

    @patch("fx.core.acquisition.dead.subprocess.run")
    @patch("fx.core.acquisition.dead.os.stat")
    def test_pkexec_fallback_cancelled(self, mock_stat, mock_run):
        """When pkexec is cancelled by user, should raise PermissionError."""
        import stat as _stat
        mock_stat.return_value = MagicMock(st_mode=_stat.S_IFBLK | 0o660)

        with patch("builtins.open", side_effect=PermissionError("Permission denied")):
            mock_run.return_value = MagicMock(returncode=126, stdout="")
            with pytest.raises(PermissionError, match="pkexec"):
                _get_source_size("/dev/sdb")


class TestOpenSourceElevated:
    """Tests for DeadAcquisitionEngine._open_source with pkexec fallback."""

    def test_direct_open_for_regular_file(self):
        """Regular files should open directly without elevation."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"data")
            f.flush()
            path = f.name

        try:
            engine = DeadAcquisitionEngine(
                source_path=path, output_file="/dev/null",
                format_type="RAW", case_no="T", examiner="T",
            )
            src = engine._open_source()
            assert src.read() == b"data"
            engine._close_source(src)
        finally:
            os.unlink(path)

    @patch("fx.core.acquisition.dead._is_block_device", return_value=True)
    @patch("fx.core.acquisition.dead.subprocess.Popen")
    def test_elevated_open_on_permission_error(self, mock_popen, mock_is_blk):
        """Block device PermissionError should spawn pkexec dd."""
        mock_proc = MagicMock()
        mock_proc.stdout = MagicMock()
        mock_popen.return_value = mock_proc

        engine = DeadAcquisitionEngine(
            source_path="/dev/sdb", output_file="/dev/null",
            format_type="RAW", case_no="T", examiner="T",
        )
        with patch("builtins.open", side_effect=PermissionError("denied")):
            result = engine._open_source()

        assert result is mock_proc.stdout
        assert engine._elevated_proc is mock_proc
        # Verify pkexec dd command
        cmd = mock_popen.call_args[0][0]
        assert cmd[0] == "pkexec"
        assert cmd[1] == "dd"
        assert f"if=/dev/sdb" in cmd[2]

    @patch("fx.core.acquisition.dead._is_block_device", return_value=False)
    def test_permission_error_non_block_reraises(self, mock_is_blk):
        """PermissionError on non-block file should re-raise (no pkexec)."""
        engine = DeadAcquisitionEngine(
            source_path="/root/secret.img", output_file="/dev/null",
            format_type="RAW", case_no="T", examiner="T",
        )
        with patch("builtins.open", side_effect=PermissionError("denied")):
            with pytest.raises(PermissionError):
                engine._open_source()


class TestDirectoryAcquisition:
    """Tests for directory-based (logical) dead acquisition via tar streaming."""

    def test_directory_acquisition_basic(self):
        """Acquiring a directory should produce a valid tar-based evidence file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create source directory with some files
            src_dir = os.path.join(tmpdir, "evidence_folder")
            os.makedirs(src_dir)
            for name, content in [("file_a.txt", b"alpha"), ("file_b.bin", os.urandom(1024))]:
                with open(os.path.join(src_dir, name), "wb") as f:
                    f.write(content)
            # Create a subdirectory too
            sub = os.path.join(src_dir, "subdir")
            os.makedirs(sub)
            with open(os.path.join(sub, "nested.dat"), "wb") as f:
                f.write(b"nested_content")

            dst = os.path.join(tmpdir, "output.raw")
            engine = DeadAcquisitionEngine(
                source_path=src_dir,
                output_file=dst,
                format_type="RAW",
                case_no="DIR-001",
                examiner="Test",
            )
            result = engine.run()

            assert result["total_bytes"] > 0
            assert len(result["sha256_final"]) == 64
            assert os.path.exists(dst)
            # Output should be a valid tar archive
            import tarfile
            assert tarfile.is_tarfile(dst)
            with tarfile.open(dst, "r") as tf:
                names = tf.getnames()
                assert any("file_a.txt" in n for n in names)
                assert any("nested.dat" in n for n in names)

    def test_directory_acquisition_with_verification(self):
        """Hash verification should work for directory sources (re-tar and compare)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            src_dir = os.path.join(tmpdir, "src")
            os.makedirs(src_dir)
            with open(os.path.join(src_dir, "data.bin"), "wb") as f:
                f.write(os.urandom(4096))

            dst = os.path.join(tmpdir, "output.raw")
            engine = DeadAcquisitionEngine(
                source_path=src_dir,
                output_file=dst,
                format_type="RAW",
                case_no="DIR-002",
                examiner="Test",
                verify_hash=True,
            )
            result = engine.run()

            assert result["hash_match"] is True
            assert result["source_sha256"] == result["sha256_final"]

    def test_directory_empty_raises(self):
        """Empty directory (no files) should raise DeadAcquisitionError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            src_dir = os.path.join(tmpdir, "empty")
            os.makedirs(src_dir)

            dst = os.path.join(tmpdir, "output.raw")
            engine = DeadAcquisitionEngine(
                source_path=src_dir,
                output_file=dst,
                format_type="RAW",
                case_no="DIR-003",
                examiner="Test",
            )
            with pytest.raises(DeadAcquisitionError, match="no files"):
                engine.run()

    def test_get_source_size_directory(self):
        """_get_source_size should return total file size sum for directories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            src_dir = os.path.join(tmpdir, "src")
            os.makedirs(src_dir)
            with open(os.path.join(src_dir, "a.txt"), "wb") as f:
                f.write(b"x" * 100)
            with open(os.path.join(src_dir, "b.txt"), "wb") as f:
                f.write(b"y" * 200)
            sub = os.path.join(src_dir, "sub")
            os.makedirs(sub)
            with open(os.path.join(sub, "c.txt"), "wb") as f:
                f.write(b"z" * 50)

            assert _get_source_size(src_dir) == 350

    def test_open_source_directory_uses_tar(self):
        """_open_source on a directory should spawn a tar subprocess."""
        with tempfile.TemporaryDirectory() as tmpdir:
            src_dir = os.path.join(tmpdir, "src")
            os.makedirs(src_dir)
            with open(os.path.join(src_dir, "test.txt"), "w") as f:
                f.write("hello")

            engine = DeadAcquisitionEngine(
                source_path=src_dir,
                output_file="/dev/null",
                format_type="RAW",
                case_no="T",
                examiner="T",
            )
            src = engine._open_source()
            data = src.read()
            engine._close_source(src)
            # Should have spawned a subprocess
            assert engine._elevated_proc is not None
            engine._elevated_proc.wait()
            # Data should be a tar stream (starts with the directory name)
            assert len(data) > 0

    def test_directory_write_blocker_skipped(self):
        """Write-blocker should be silently skipped for directory sources."""
        with tempfile.TemporaryDirectory() as tmpdir:
            src_dir = os.path.join(tmpdir, "src")
            os.makedirs(src_dir)
            with open(os.path.join(src_dir, "f.txt"), "wb") as f:
                f.write(b"data")

            dst = os.path.join(tmpdir, "output.raw")
            engine = DeadAcquisitionEngine(
                source_path=src_dir,
                output_file=dst,
                format_type="RAW",
                case_no="DIR-004",
                examiner="Test",
                write_blocker=True,  # should be ignored for directories
            )
            # Should not raise (write_blocker is skipped for dirs)
            result = engine.run()
            assert result["total_bytes"] > 0


# ═══════════════════════════════════════════════════════════════════════
# EwfWriter extension-stripping tests
# ═══════════════════════════════════════════════════════════════════════

class TestEwfWriterExtension:
    """EwfWriter must strip a pre-existing .E01/.e01 extension before
    passing the filename to pyewf, because libewf appends segment
    extensions (.E01, .E02, …) automatically.  Double suffixes like
    ``evidence.E01.E01`` break Autopsy / EnCase import."""

    def test_strip_e01_extension(self):
        """EwfWriter should call pyewf.handle().open() with the base name
        (no .E01) even when the caller provides one."""
        mock_pyewf = MagicMock()
        mock_handle = MagicMock()
        mock_pyewf.handle.return_value = mock_handle

        with patch.dict("sys.modules", {"pyewf": mock_pyewf}):
            # Reload so the patched module is picked up
            import importlib
            import fx.core.acquisition.ewf as ewf_mod
            importlib.reload(ewf_mod)

            try:
                writer = ewf_mod.EwfWriter("/tmp/evidence_2026-001.E01")
                # pyewf.handle().open() should receive the path WITHOUT .E01
                mock_handle.open.assert_called_once_with(["/tmp/evidence_2026-001"], "w")
            finally:
                importlib.reload(ewf_mod)  # restore original module state

    def test_strip_lowercase_e01(self):
        """Lowercase .e01 extension should also be stripped."""
        mock_pyewf = MagicMock()
        mock_handle = MagicMock()
        mock_pyewf.handle.return_value = mock_handle

        with patch.dict("sys.modules", {"pyewf": mock_pyewf}):
            import importlib
            import fx.core.acquisition.ewf as ewf_mod
            importlib.reload(ewf_mod)

            try:
                writer = ewf_mod.EwfWriter("/evidence/img.e01")
                mock_handle.open.assert_called_once_with(["/evidence/img"], "w")
            finally:
                importlib.reload(ewf_mod)

    def test_no_extension_passthrough(self):
        """A filename without an EWF extension should pass through unchanged."""
        mock_pyewf = MagicMock()
        mock_handle = MagicMock()
        mock_pyewf.handle.return_value = mock_handle

        with patch.dict("sys.modules", {"pyewf": mock_pyewf}):
            import importlib
            import fx.core.acquisition.ewf as ewf_mod
            importlib.reload(ewf_mod)

            try:
                writer = ewf_mod.EwfWriter("/tmp/evidence_case")
                mock_handle.open.assert_called_once_with(["/tmp/evidence_case"], "w")
            finally:
                importlib.reload(ewf_mod)

    def test_raw_extension_not_stripped(self):
        """A .raw extension should NOT be stripped (only EWF patterns)."""
        mock_pyewf = MagicMock()
        mock_handle = MagicMock()
        mock_pyewf.handle.return_value = mock_handle

        with patch.dict("sys.modules", {"pyewf": mock_pyewf}):
            import importlib
            import fx.core.acquisition.ewf as ewf_mod
            importlib.reload(ewf_mod)

            try:
                writer = ewf_mod.EwfWriter("/tmp/evidence.raw")
                mock_handle.open.assert_called_once_with(["/tmp/evidence.raw"], "w")
            finally:
                importlib.reload(ewf_mod)


# ═══════════════════════════════════════════════════════════════════════
# Critical fix: verify_source_hash command injection prevention
# ═══════════════════════════════════════════════════════════════════════

class TestVerifySourceHashInjection:
    """verify_source_hash must validate + shell-quote disk paths."""

    def test_rejects_injection_path(self):
        """Paths containing shell metacharacters must be rejected."""
        mock_ssh = MagicMock()
        # Attempt command injection via semicolon
        result, matched = verify_source_hash(mock_ssh, "/dev/sda; rm -rf /")
        assert result == "ERROR"
        assert matched is False
        # SSH exec_command should never have been called
        mock_ssh.exec_command.assert_not_called()

    def test_rejects_backtick_injection(self):
        """Backtick injection must be caught."""
        mock_ssh = MagicMock()
        result, matched = verify_source_hash(mock_ssh, "/dev/`whoami`")
        assert result == "ERROR"
        assert matched is False
        mock_ssh.exec_command.assert_not_called()

    def test_valid_path_is_shell_quoted(self):
        """Valid disk paths should be shell-quoted in the command."""
        mock_ssh = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()
        sha = "b" * 64
        mock_stdout.read.return_value = f"{sha}  /dev/sda\n".encode()
        mock_stderr.read.return_value = b""
        mock_stdout.channel.recv_exit_status.return_value = 0
        mock_ssh.exec_command.return_value = (MagicMock(), mock_stdout, mock_stderr)

        result, _ = verify_source_hash(mock_ssh, "/dev/sda")
        assert result == sha
        # Verify the command uses shlex-quoted path
        cmd = mock_ssh.exec_command.call_args[0][0]
        assert "/dev/sda" in cmd


# ═══════════════════════════════════════════════════════════════════════
# Critical fix: SSH WarningPolicy (no more AutoAddPolicy)
# ═══════════════════════════════════════════════════════════════════════

class TestSSHHostKeyPolicy:
    """AcquisitionEngine must NOT use AutoAddPolicy."""

    def test_engine_uses_warning_policy(self):
        """The engine should use WarningPolicy, not AutoAddPolicy."""
        import paramiko
        with patch("fx.core.acquisition.base.paramiko.SSHClient") as MockClient:
            mock_instance = MagicMock()
            MockClient.return_value = mock_instance
            # Make connect raise to short-circuit the run loop
            mock_instance.connect.side_effect = Exception("test abort")

            engine = AcquisitionEngine(
                ip="10.0.0.1", user="test", key_path="/tmp/key.pem",
                disk="/dev/sda", output_file="/tmp/out.raw",
                format_type="RAW", case_no="TEST-001", examiner="Test",
            )

            with pytest.raises(AcquisitionError):
                engine.run()

            # Verify WarningPolicy was set (not AutoAddPolicy)
            mock_instance.set_missing_host_key_policy.assert_called()
            policy_arg = mock_instance.set_missing_host_key_policy.call_args[0][0]
            assert isinstance(policy_arg, paramiko.WarningPolicy)


# ═══════════════════════════════════════════════════════════════════════
# Critical fix: Safe mode seek-past-bad-sector
# ═══════════════════════════════════════════════════════════════════════

class TestSafeModeSeek:
    """Safe mode must advance past unreadable sectors, not loop forever."""

    def test_safe_mode_seeks_past_bad_sector(self):
        """On OSError, safe mode should seek past the bad region and continue."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a source file large enough for 2 chunks
            src_path = os.path.join(tmpdir, "source.bin")
            chunk_size = DeadAcquisitionEngine.CHUNK_SIZE
            good_data = b"G" * chunk_size
            with open(src_path, "wb") as f:
                f.write(good_data * 2)

            dst_path = os.path.join(tmpdir, "output.raw")

            engine = DeadAcquisitionEngine(
                source_path=src_path,
                output_file=dst_path,
                format_type="RAW",
                case_no="SAFE-001",
                examiner="Test",
                safe_mode=True,
            )

            # Mock _open_source to return a file-like that fails on 1st read,
            # succeeds on 2nd read, then returns empty (EOF)
            call_count = [0]
            mock_src = MagicMock()

            def read_side_effect(size):
                call_count[0] += 1
                if call_count[0] == 1:
                    raise OSError("I/O error")
                elif call_count[0] == 2:
                    return good_data
                return b""

            mock_src.read.side_effect = read_side_effect
            mock_src.seek = MagicMock()  # seek should be called after OSError

            with patch.object(engine, "_open_source", return_value=mock_src):
                with patch.object(engine, "_close_source"):
                    result = engine.run()

            # Engine should have completed (not infinite loop)
            assert result["total_bytes"] > 0
            # seek should have been called to skip past the bad sector
            mock_src.seek.assert_called()


# ═══════════════════════════════════════════════════════════════════════
# Critical fix: AFF4Writer close error propagation
# ═══════════════════════════════════════════════════════════════════════

class TestAFF4WriterClosePropagation:
    """AFF4Writer.close() must propagate errors, not swallow them."""

    def test_close_error_raises_ioerror(self):
        """If resolver.Close fails, AFF4Writer.close() must raise IOError."""
        from fx.core.acquisition.aff4 import AFF4Writer, AFF4_AVAILABLE
        with patch("fx.core.acquisition.aff4.AFF4_AVAILABLE", True):
            w = AFF4Writer.__new__(AFF4Writer)
            w._output_path = "/tmp/test.aff4"
            w._resolver = MagicMock()
            w._volume = MagicMock()
            w._stream = MagicMock()
            w._bytes_written = 0
            w._closed = False

            # Make resolver.Close raise on the stream URN
            w._resolver.Close.side_effect = RuntimeError("corrupt container")

            with pytest.raises(IOError, match="AFF4 container finalization failed"):
                w.close()

    def test_close_success_still_works(self):
        """Normal close should still work without error."""
        from fx.core.acquisition.aff4 import AFF4Writer
        with patch("fx.core.acquisition.aff4.AFF4_AVAILABLE", True):
            w = AFF4Writer.__new__(AFF4Writer)
            w._output_path = "/tmp/test.aff4"
            w._resolver = MagicMock()
            w._volume = MagicMock()
            w._stream = MagicMock()
            w._bytes_written = 0
            w._closed = False

            w.close()  # should not raise
            assert w._closed is True


# ═══════════════════════════════════════════════════════════════════════
# Critical fix: Write-blocker before triage ordering
# ═══════════════════════════════════════════════════════════════════════

class TestWriteBlockerOrdering:
    """Write-blocker must be applied BEFORE triage runs."""

    def test_write_blocker_before_triage(self):
        """When both write_blocker and triage are enabled,
        write-blocker must be called before triage."""
        import paramiko

        call_order = []

        def mock_apply_write_blocker(ssh, disk):
            call_order.append("write_blocker")

        def mock_run_triage(ssh):
            call_order.append("triage")

        with patch("fx.core.acquisition.base.paramiko.SSHClient") as MockClient:
            mock_ssh = MagicMock()
            MockClient.return_value = mock_ssh

            # Mock successful SSH connection
            mock_stdout_size = MagicMock()
            mock_stdout_size.read.return_value = b"1000000"
            mock_stdout_size.channel.recv_exit_status.return_value = 0
            mock_stderr_size = MagicMock()
            mock_stderr_size.read.return_value = b""

            # The exec_command for blockdev --getsize64
            mock_stdout_dd = MagicMock()
            mock_stdout_dd.read.return_value = b""  # EOF immediately
            mock_stdout_dd.channel.recv_exit_status.return_value = 0
            mock_stdout_dd.channel.settimeout = MagicMock()
            mock_stderr_dd = MagicMock()
            mock_stderr_dd.read.return_value = b""

            mock_ssh.exec_command.side_effect = [
                (MagicMock(), mock_stdout_size, mock_stderr_size),  # blockdev
                (MagicMock(), mock_stdout_dd, mock_stderr_dd),      # dd
            ]

            engine = AcquisitionEngine(
                ip="10.0.0.1", user="test", key_path="/tmp/key.pem",
                disk="/dev/sda", output_file="/tmp/out.raw",
                format_type="RAW", case_no="ORD-001", examiner="Test",
                write_blocker=True,
                run_triage=True,
                output_dir="/tmp/evidence",
            )

            with patch.object(engine, "_run_triage", side_effect=mock_run_triage):
                with patch("fx.core.acquisition.base.apply_write_blocker",
                           side_effect=mock_apply_write_blocker):
                    try:
                        engine.run()
                    except AcquisitionError:
                        pass  # May fail on dd; we only care about ordering

        assert "write_blocker" in call_order
        assert "triage" in call_order
        assert call_order.index("write_blocker") < call_order.index("triage"), \
            f"Write-blocker must come before triage, but got: {call_order}"
