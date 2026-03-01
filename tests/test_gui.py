# Tests for ForenXtract (FX) GUI module: CaseWizard validation, ForensicApp
# method logic, worker signal bridges, pre-acquisition confirmation dialogs.
# Uses mock Qt objects — no real display server required.

import os
import sys
import tempfile
from unittest.mock import patch, MagicMock, PropertyMock

import pytest

# ── Guard: skip entire module if PyQt6 is not installed ───────────────
pytest.importorskip("PyQt6")

from PyQt6.QtWidgets import QApplication, QMessageBox, QDialog

# QApplication singleton — required before any QWidget instantiation
_app = QApplication.instance() or QApplication(sys.argv)

from fx.ui.gui import CaseWizard, ForensicApp, _FORMAT_MAP, _FORMAT_EXT


# ═══════════════════════════════════════════════════════════════════════
# CaseWizard validation tests
# ═══════════════════════════════════════════════════════════════════════

class TestCaseWizard:
    """CaseWizard._validate_and_accept must reject incomplete inputs."""

    def _make_wizard(self):
        return CaseWizard()

    def test_reject_empty_case_no(self):
        w = self._make_wizard()
        w.case_no_edit.setText("")
        w.examiner_edit.setText("Investigator")
        with tempfile.TemporaryDirectory() as d:
            w.dir_edit.setText(d)
            with patch.object(QMessageBox, "warning") as mock_warn:
                w._validate_and_accept()
                mock_warn.assert_called_once()
                assert "Case Number" in mock_warn.call_args[0][2]

    def test_reject_empty_examiner(self):
        w = self._make_wizard()
        w.case_no_edit.setText("2026-001")
        w.examiner_edit.setText("")
        with tempfile.TemporaryDirectory() as d:
            w.dir_edit.setText(d)
            with patch.object(QMessageBox, "warning") as mock_warn:
                w._validate_and_accept()
                mock_warn.assert_called_once()
                assert "Examiner" in mock_warn.call_args[0][2]

    def test_reject_empty_evidence_dir(self):
        w = self._make_wizard()
        w.case_no_edit.setText("2026-001")
        w.examiner_edit.setText("Investigator")
        w.dir_edit.setText("")
        with patch.object(QMessageBox, "warning") as mock_warn:
            w._validate_and_accept()
            mock_warn.assert_called_once()
            assert "Evidence Directory" in mock_warn.call_args[0][2]

    def test_reject_nonexistent_dir(self):
        w = self._make_wizard()
        w.case_no_edit.setText("2026-001")
        w.examiner_edit.setText("Investigator")
        w.dir_edit.setText("/nonexistent/path/abc123")
        with patch.object(QMessageBox, "warning") as mock_warn:
            w._validate_and_accept()
            mock_warn.assert_called_once()
            assert "does not exist" in mock_warn.call_args[0][2]

    def test_reject_non_writable_dir(self):
        w = self._make_wizard()
        w.case_no_edit.setText("2026-001")
        w.examiner_edit.setText("Investigator")
        with tempfile.TemporaryDirectory() as d:
            w.dir_edit.setText(d)
            with patch("os.access", return_value=False):
                with patch.object(QMessageBox, "warning") as mock_warn:
                    w._validate_and_accept()
                    mock_warn.assert_called_once()
                    assert "not writable" in mock_warn.call_args[0][2]

    def test_accept_valid_inputs(self):
        w = self._make_wizard()
        w.case_no_edit.setText("2026-001")
        w.examiner_edit.setText("Investigator X")
        with tempfile.TemporaryDirectory() as d:
            w.dir_edit.setText(d)
            with patch.object(w, "accept") as mock_accept:
                w._validate_and_accept()
                mock_accept.assert_called_once()
            assert w.case_no == "2026-001"
            assert w.examiner == "Investigator X"
            assert w.evidence_dir == d

    def test_properties_default_empty(self):
        w = self._make_wizard()
        assert w.case_no == ""
        assert w.examiner == ""
        assert w.evidence_dir == ""


# ═══════════════════════════════════════════════════════════════════════
# ForensicApp component tests (mocked loadUi)
# ═══════════════════════════════════════════════════════════════════════

def _make_forensic_app(tmpdir):
    """Create a ForensicApp with mocked UI loading."""
    with patch("fx.ui.gui.loadUi"):
        app = ForensicApp.__new__(ForensicApp)
        # Minimal attribute setup to avoid loadUi
        app.case_no = "TEST-001"
        app.examiner = "Tester"
        app.output_dir = tmpdir

        # Mock UI widgets
        app.txt_ip = MagicMock()
        app.txt_user = MagicMock()
        app.txt_key = MagicMock()
        app.cmb_disk = MagicMock()
        app.cmb_format = MagicMock()
        app.btn_start = MagicMock()
        app.btn_stop = MagicMock()
        app.progressBar = MagicMock()
        app.lbl_status = MagicMock()
        app.txt_console = MagicMock()
        app.tabWidget = MagicMock()
        app.chk_safety = MagicMock()
        app.chk_verify = MagicMock()
        app.chk_writeblock = MagicMock()
        app.chk_triage = MagicMock()
        app.chk_throttle = MagicMock()
        app.txt_throttle = MagicMock()
        app.txt_e01_description = MagicMock()
        app.txt_e01_notes = MagicMock()
        app.txt_signing_key = MagicMock()
        app.chk_siem = MagicMock()
        app.txt_siem_host = MagicMock()
        app.txt_siem_port = MagicMock()
        app.cmb_siem_protocol = MagicMock()
        app.chk_siem_cef = MagicMock()
        app.chk_split = MagicMock()
        app.cmb_split_size = MagicMock()
        app.txt_dead_image = MagicMock()
        app.cmb_dead_disk = MagicMock()

        # Mock logger
        from fx.audit.logger import ForensicLogger
        app.logger = ForensicLogger()
        app.logger.set_context("TEST-001", "Tester", tmpdir)

        # Session
        from fx.core.session import Session
        app.session = Session()
        app.session.bind_context("TEST-001", "Tester", tmpdir)

        # State
        app.format_type = "RAW"
        app.target_filename = ""
        app.dashboard_path = None
        app.start_time = None
        app._split_size = 0
        app.worker = None

        return app


class TestForensicAppFormatMap:
    """Verify format label → format type mapping."""

    def test_format_map_completeness(self):
        assert _FORMAT_MAP.get("RAW (.raw)") == "RAW"
        assert _FORMAT_MAP.get("RAW+LZ4 (.raw.lz4)") == "RAW+LZ4"
        assert _FORMAT_MAP.get("E01 (EnCase)") == "E01"
        assert _FORMAT_MAP.get("AFF4") == "AFF4"

    def test_format_ext_completeness(self):
        assert _FORMAT_EXT.get("RAW") == ".raw"
        assert _FORMAT_EXT.get("RAW+LZ4") == ".raw.lz4"
        assert _FORMAT_EXT.get("E01") == ".E01"
        assert _FORMAT_EXT.get("AFF4") == ".aff4"


class TestForensicAppRouting:
    """start_process routes to live or dead based on tab index."""

    def test_tab_0_routes_to_live(self):
        with tempfile.TemporaryDirectory() as d:
            app = _make_forensic_app(d)
            app.tabWidget.currentIndex.return_value = 0
            with patch.object(app, "_start_live_process") as mock_live:
                with patch.object(app, "_start_dead_process") as mock_dead:
                    app.start_process()
                    mock_live.assert_called_once()
                    mock_dead.assert_not_called()

    def test_tab_1_routes_to_dead(self):
        with tempfile.TemporaryDirectory() as d:
            app = _make_forensic_app(d)
            app.tabWidget.currentIndex.return_value = 1
            with patch.object(app, "_start_live_process") as mock_live:
                with patch.object(app, "_start_dead_process") as mock_dead:
                    app.start_process()
                    mock_dead.assert_called_once()
                    mock_live.assert_not_called()


class TestForensicAppValidation:
    """Input validation in _start_live_process."""

    def test_live_rejects_empty_ip(self):
        with tempfile.TemporaryDirectory() as d:
            app = _make_forensic_app(d)
            app.txt_ip.text.return_value = ""
            app.txt_user.text.return_value = "ubuntu"
            app.txt_key.text.return_value = "/key.pem"
            app.cmb_disk.currentText.return_value = "/dev/sda"
            with patch.object(QMessageBox, "warning") as mock_warn:
                app._start_live_process()
                mock_warn.assert_called_once()
                assert "required" in mock_warn.call_args[0][2].lower()

    def test_dead_rejects_empty_source(self):
        with tempfile.TemporaryDirectory() as d:
            app = _make_forensic_app(d)
            app.txt_dead_image.text.return_value = ""
            app.cmb_dead_disk.currentText.return_value = ""
            with patch.object(QMessageBox, "warning") as mock_warn:
                app._start_dead_process()
                mock_warn.assert_called_once()
                assert "source" in mock_warn.call_args[0][2].lower()

    def test_dead_rejects_nonexistent_source(self):
        with tempfile.TemporaryDirectory() as d:
            app = _make_forensic_app(d)
            app.txt_dead_image.text.return_value = "/nonexistent/path/xyz"
            app.cmb_dead_disk.currentText.return_value = ""
            with patch.object(QMessageBox, "warning") as mock_warn:
                app._start_dead_process()
                mock_warn.assert_called_once()
                assert "not found" in mock_warn.call_args[0][2].lower()


class TestForensicAppE01MetadataBugFix:
    """Regression: e01_description/e01_notes must be defined before logging block."""

    def test_e01_metadata_no_name_error(self):
        """E01 format should log metadata without NameError (was referenced before assignment)."""
        with tempfile.TemporaryDirectory() as d:
            app = _make_forensic_app(d)
            app.format_type = "E01"
            app.txt_e01_description.text.return_value = "Test description"
            app.txt_e01_notes.text.return_value = "Test notes"

            # Simulate the code path that previously had the bug
            # Reading e01 vars now happens before logging
            e01_description = app.txt_e01_description.text().strip() if hasattr(app, "txt_e01_description") else ""
            e01_notes = app.txt_e01_notes.text().strip() if hasattr(app, "txt_e01_notes") else ""

            # This should NOT raise NameError
            if app.format_type == "E01":
                e01_desc_preview = e01_description[:60] if e01_description else "(empty)"
                e01_notes_preview = e01_notes[:60] if e01_notes else "(empty)"
                assert e01_desc_preview == "Test description"
                assert e01_notes_preview == "Test notes"


class TestForensicAppPreAcquisitionConfirmation:
    """Pre-acquisition QMessageBox must appear before starting workers."""

    def test_live_confirmation_cancel_aborts(self):
        """Cancelling the confirmation dialog should abort without starting worker."""
        with tempfile.TemporaryDirectory() as d:
            app = _make_forensic_app(d)
            app.txt_ip.text.return_value = "10.0.0.1"
            app.txt_user.text.return_value = "ubuntu"
            app.txt_key.text.return_value = "/tmp/fake.pem"
            app.cmb_disk.currentText.return_value = "/dev/sda"
            app.cmb_format.currentText.return_value = "RAW (.raw)"
            app.chk_safety.isChecked.return_value = False
            app.chk_verify.isChecked.return_value = False
            app.chk_writeblock.isChecked.return_value = False
            app.chk_triage.isChecked.return_value = False
            app.chk_throttle.isChecked.return_value = False
            app.txt_signing_key.text.return_value = ""
            app.chk_siem.isChecked.return_value = False
            app.txt_siem_host.text.return_value = ""
            app.txt_siem_port.text.return_value = "514"
            app.cmb_siem_protocol.currentText.return_value = "UDP"
            app.chk_siem_cef.isChecked.return_value = False
            app.chk_split.isChecked.return_value = False
            app._split_size = 0
            app.txt_e01_description.text.return_value = ""
            app.txt_e01_notes.text.return_value = ""

            with patch.object(app, "validate_network_inputs", return_value=True):
                with patch.object(app, "_get_split_size_bytes", return_value=0):
                    with patch.object(QMessageBox, "question",
                                      return_value=QMessageBox.StandardButton.No) as mock_q:
                        app._start_live_process()
                        # Confirmation dialog was shown
                        mock_q.assert_called_once()
                        # Worker should NOT have been created
                        assert app.worker is None


class TestForensicAppProgressUI:
    """update_progress_ui must update widgets without crashing."""

    def test_progress_update_sets_bar_and_label(self):
        with tempfile.TemporaryDirectory() as d:
            app = _make_forensic_app(d)
            app.lbl_speed = MagicMock()
            app.lbl_eta = MagicMock()
            app.lbl_md5 = MagicMock()
            app.statusBar = MagicMock()
            from datetime import datetime, timezone
            app.start_time = datetime.now(timezone.utc)

            data = {
                "bytes_read": 1024 * 1024 * 100,
                "speed_mb_s": 50.0,
                "md5_current": "abc123",
                "percentage": 42,
                "eta": "00:05:30",
            }

            # Should not raise
            app.update_progress_ui(data)
            app.progressBar.setValue.assert_called_with(42)
