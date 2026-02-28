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
        """Write blocker should succeed when both commands return 0."""
        mock_run.side_effect = [
            MagicMock(returncode=0, stderr=""),
            MagicMock(returncode=0, stdout="1", stderr=""),
        ]
        # Should not raise
        _apply_local_write_blocker("/dev/sdb")
        assert mock_run.call_count == 2

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
