# Tests for ForenXtract (FX) CLI entry-points: parse_args, main() integration,
# interactive wizard helpers, pre-acquisition confirmation, and format_bytes.
# All tests use mock I/O — no real SSH or disk access.

import os
import sys
import tempfile
from io import StringIO
from unittest.mock import patch, MagicMock, PropertyMock

import pytest

from fx.cli.acquire import parse_args, cli_progress, main
from fx.core.validation import format_bytes


# ═══════════════════════════════════════════════════════════════════════
# format_bytes utility
# ═══════════════════════════════════════════════════════════════════════

class TestFormatBytes:
    def test_zero(self):
        assert format_bytes(0) == "0 B"

    def test_bytes(self):
        assert format_bytes(512) == "512 B"

    def test_kilobytes(self):
        assert format_bytes(1024) == "1.00 KB"

    def test_megabytes(self):
        assert format_bytes(10 * 1024 * 1024) == "10.00 MB"

    def test_gigabytes(self):
        assert format_bytes(500 * 1024**3) == "500.00 GB"

    def test_terabytes(self):
        assert format_bytes(2 * 1024**4) == "2.00 TB"

    def test_negative(self):
        assert format_bytes(-1) == "Unknown"

    def test_fractional_gb(self):
        result = format_bytes(int(1.5 * 1024**3))
        assert "1.50 GB" == result


# ═══════════════════════════════════════════════════════════════════════
# parse_args tests
# ═══════════════════════════════════════════════════════════════════════

class TestParseArgs:
    """CLI argument parser must recognize all flags correctly."""

    def test_dead_mode_minimal(self):
        with patch("sys.argv", ["fx-acquire", "--dead", "--source", "/dev/sdb",
                                 "--output-dir", "/tmp", "--case", "C1", "--examiner", "E1"]):
            args = parse_args()
            assert args.dead is True
            assert args.source == "/dev/sdb"
            assert args.case == "C1"

    def test_live_mode_minimal(self):
        with patch("sys.argv", ["fx-acquire", "--ip", "1.2.3.4", "--user", "u",
                                 "--key", "/k.pem", "--disk", "/dev/sda",
                                 "--output-dir", "/tmp", "--case", "C2", "--examiner", "E2"]):
            args = parse_args()
            assert args.dead is False
            assert args.ip == "1.2.3.4"

    def test_yes_flag(self):
        with patch("sys.argv", ["fx-acquire", "--dead", "--source", "/dev/sdb",
                                 "--output-dir", "/tmp", "--case", "C1", "--examiner", "E1", "-y"]):
            args = parse_args()
            assert args.yes is True

    def test_yes_long_flag(self):
        with patch("sys.argv", ["fx-acquire", "--dead", "--source", "/dev/sdb",
                                 "--output-dir", "/tmp", "--case", "C1", "--examiner", "E1", "--yes"]):
            args = parse_args()
            assert args.yes is True

    def test_format_choices(self):
        for fmt in ("RAW", "RAW+LZ4", "E01", "AFF4"):
            with patch("sys.argv", ["fx-acquire", "--dead", "--source", "/dev/sdb",
                                     "--output-dir", "/tmp", "--case", "C", "--examiner", "E",
                                     "--format", fmt]):
                args = parse_args()
                assert args.format == fmt

    def test_invalid_format_rejected(self):
        with patch("sys.argv", ["fx-acquire", "--format", "INVALID"]):
            with pytest.raises(SystemExit):
                parse_args()

    def test_interactive_flag(self):
        with patch("sys.argv", ["fx-acquire", "-i"]):
            args = parse_args()
            assert args.interactive is True

    def test_split_size_flag(self):
        with patch("sys.argv", ["fx-acquire", "--dead", "--source", "/dev/sdb",
                                 "--output-dir", "/tmp", "--case", "C", "--examiner", "E",
                                 "--split-size", "2G"]):
            args = parse_args()
            assert args.split_size == "2G"


# ═══════════════════════════════════════════════════════════════════════
# cli_progress terminal output
# ═══════════════════════════════════════════════════════════════════════

class TestCliProgress:
    def test_progress_output(self, capsys):
        data = {
            "percentage": 50,
            "speed_mb_s": 100.0,
            "eta": "00:01:00",
            "md5_current": "abc",
            "bytes_read": 500 * 1024 * 1024,
            "bad_sector_count": 0,
        }
        cli_progress(data)
        captured = capsys.readouterr()
        assert "50%" in captured.out
        assert "100.0 MB/s" in captured.out

    def test_progress_with_bad_sectors(self, capsys):
        data = {
            "percentage": 10,
            "speed_mb_s": 50.0,
            "eta": "00:10:00",
            "md5_current": "",
            "bytes_read": 100 * 1024 * 1024,
            "bad_sector_count": 3,
        }
        cli_progress(data)
        captured = capsys.readouterr()
        assert "BAD:3" in captured.out


# ═══════════════════════════════════════════════════════════════════════
# main() integration — dead mode with mocked engine
# ═══════════════════════════════════════════════════════════════════════

class TestMainDeadIntegration:
    """End-to-end main() for dead mode using mocks."""

    def test_main_dead_mode_success(self):
        """main() should return 0 on successful dead acquisition."""
        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, "source.bin")
            with open(src, "wb") as f:
                f.write(b"A" * 4096)

            args = [
                "fx-acquire", "--dead",
                "--source", src,
                "--output-dir", tmpdir,
                "--case", "INT-001",
                "--examiner", "Test",
                "--yes",
            ]

            mock_result = {
                "sha256_final": "a" * 64,
                "md5_final": "b" * 32,
                "total_bytes": 4096,
                "source_sha256": "SKIPPED",
                "hash_match": None,
            }

            with patch("sys.argv", args):
                with patch("fx.cli.acquire.DeadAcquisitionEngine") as MockEngine:
                    instance = MockEngine.return_value
                    instance.run.return_value = mock_result
                    instance.stop = MagicMock()

                    ret = main()
                    assert ret == 0
                    MockEngine.assert_called_once()

    def test_main_missing_output_dir(self):
        """main() should return 1 when output-dir does not exist."""
        with patch("sys.argv", ["fx-acquire", "--dead", "--source", "/dev/null",
                                 "--output-dir", "/nonexistent/dir",
                                 "--case", "C", "--examiner", "E", "--yes"]):
            ret = main()
            assert ret == 1

    def test_main_missing_source(self):
        """main() should return 1 when source is not provided in dead mode."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("sys.argv", ["fx-acquire", "--dead",
                                     "--output-dir", tmpdir,
                                     "--case", "C", "--examiner", "E"]):
                ret = main()
                assert ret == 1

    def test_main_missing_required_fields(self):
        """main() should return 1 when case/examiner missing."""
        with patch("sys.argv", ["fx-acquire", "--dead", "--source", "/dev/null",
                                 "--output-dir", "/tmp"]):
            ret = main()
            assert ret == 1

    def test_main_live_mode_missing_ip(self):
        """main() should return 1 when live mode has no --ip."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("sys.argv", ["fx-acquire", "--output-dir", tmpdir,
                                     "--case", "C", "--examiner", "E"]):
                ret = main()
                assert ret == 1


class TestMainDeadAcquisitionFailure:
    """main() should return 1 when the engine raises an error."""

    def test_main_engine_failure(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, "source.bin")
            with open(src, "wb") as f:
                f.write(b"A" * 4096)

            with patch("sys.argv", ["fx-acquire", "--dead", "--source", src,
                                     "--output-dir", tmpdir, "--case", "C", "--examiner", "E",
                                     "--yes"]):
                with patch("fx.cli.acquire.DeadAcquisitionEngine") as MockEngine:
                    from fx.core.acquisition.dead import DeadAcquisitionError
                    instance = MockEngine.return_value
                    instance.run.side_effect = DeadAcquisitionError("disk vanished")
                    instance.stop = MagicMock()

                    ret = main()
                    assert ret == 1


# ═══════════════════════════════════════════════════════════════════════
# Pre-acquisition confirmation prompt
# ═══════════════════════════════════════════════════════════════════════

class TestPreAcquisitionConfirmation:
    """The --yes flag should skip the confirmation prompt."""

    def test_yes_skips_confirmation(self):
        """With -y, main() should NOT call input() for confirmation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, "src.bin")
            with open(src, "wb") as f:
                f.write(b"X" * 1024)

            mock_result = {
                "sha256_final": "a" * 64,
                "md5_final": "b" * 32,
                "total_bytes": 1024,
                "source_sha256": "SKIPPED",
                "hash_match": None,
            }

            with patch("sys.argv", ["fx-acquire", "--dead", "--source", src,
                                     "--output-dir", tmpdir, "--case", "C", "--examiner", "E", "-y"]):
                with patch("fx.cli.acquire.DeadAcquisitionEngine") as MockEngine:
                    instance = MockEngine.return_value
                    instance.run.return_value = mock_result
                    instance.stop = MagicMock()

                    with patch("builtins.input") as mock_input:
                        ret = main()
                        # input() should NOT be called when --yes is used
                        mock_input.assert_not_called()
                        assert ret == 0

    def test_no_answer_aborts(self):
        """Answering 'n' to confirmation should abort with return 0."""
        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, "src.bin")
            with open(src, "wb") as f:
                f.write(b"X" * 1024)

            with patch("sys.argv", ["fx-acquire", "--dead", "--source", src,
                                     "--output-dir", tmpdir, "--case", "C", "--examiner", "E"]):
                with patch("builtins.input", return_value="n"):
                    ret = main()
                    assert ret == 0


# ═══════════════════════════════════════════════════════════════════════
# Interactive wizard helpers
# ═══════════════════════════════════════════════════════════════════════

class TestInteractiveHelpers:
    """Test interactive wizard prompt functions with simulated input."""

    def test_prompt_bool_default_true(self):
        from fx.cli.interactive import _prompt_bool
        with patch("builtins.input", return_value=""):
            assert _prompt_bool("Test?", default=True) is True

    def test_prompt_bool_default_false(self):
        from fx.cli.interactive import _prompt_bool
        with patch("builtins.input", return_value=""):
            assert _prompt_bool("Test?", default=False) is False

    def test_prompt_bool_yes(self):
        from fx.cli.interactive import _prompt_bool
        with patch("builtins.input", return_value="y"):
            assert _prompt_bool("Test?", default=False) is True

    def test_prompt_bool_no(self):
        from fx.cli.interactive import _prompt_bool
        with patch("builtins.input", return_value="n"):
            assert _prompt_bool("Test?", default=True) is False

    def test_prompt_returns_value(self):
        from fx.cli.interactive import _prompt
        with patch("builtins.input", return_value="hello"):
            assert _prompt("Label") == "hello"

    def test_prompt_returns_default(self):
        from fx.cli.interactive import _prompt
        with patch("builtins.input", return_value=""):
            assert _prompt("Label", default="fallback") == "fallback"

    def test_prompt_choice_by_number(self):
        from fx.cli.interactive import _prompt_choice
        with patch("builtins.input", return_value="2"):
            result = _prompt_choice("Pick:", ["A", "B", "C"])
            assert result == "B"

    def test_prompt_choice_default(self):
        from fx.cli.interactive import _prompt_choice
        with patch("builtins.input", return_value=""):
            result = _prompt_choice("Pick:", ["A", "B", "C"], default="B")
            assert result == "B"
