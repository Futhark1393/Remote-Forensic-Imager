# Author: Kemal Sebzeci
# Description: Main GUI module for ForenXtract (FX).
# Features: Case Wizard workflow, structured forensic logging, secure acquisition orchestration,
# Optional write-blocker, post-acq verification, report generation, triage, SIEM, signing.
# Supports both Live (Remote/SSH) and Dead (Local) acquisition modes via tabbed interface.

import subprocess
import sys
import os
import re
import webbrowser
import paramiko
from datetime import datetime, timezone
from importlib import resources

from PyQt6.QtWidgets import (
    QMainWindow,
    QFileDialog,
    QMessageBox,
    QApplication,
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QFormLayout,
    QToolTip,
)
from PyQt6.uic import loadUi
from PyQt6.QtGui import QTextCursor, QKeySequence, QShortcut, QColor, QPalette
from PyQt6.QtCore import Qt, QTimer

from fx.deps.dependency_checker import run_dependency_check
from fx.audit.logger import ForensicLogger, ForensicLoggerError
from fx.report.report_engine import ReportEngine
from fx.ui.workers import AcquisitionWorker, DeadAcquisitionWorker
from fx.core.session import Session, SessionState, SessionStateError
from fx.core.validation import (
    validate_target_address,
    validate_ssh_username,
    validate_signing_key,
    validate_siem_config,
    build_evidence_filename,
)


_FORMAT_MAP = {
    "RAW (.raw)": "RAW",
    "RAW+LZ4 (.raw.lz4)": "RAW+LZ4",
    "E01 (EnCase)": "E01",
    "AFF4": "AFF4",
}
_FORMAT_EXT = {
    "RAW": ".raw",
    "RAW+LZ4": ".raw.lz4",
    "E01": ".E01",
    "AFF4": ".aff4",
}


class CaseWizard(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Create / Open Case")

        self._case_no = ""
        self._examiner = ""
        self._evidence_dir = ""

        root = QVBoxLayout(self)

        header = QLabel("Case Initialization")
        header.setStyleSheet("font-size: 14pt; font-weight: 600;")
        root.addWidget(header)

        form = QFormLayout()
        self.case_no_edit = QLineEdit()
        self.case_no_edit.setPlaceholderText("e.g., 2026-001")
        self.examiner_edit = QLineEdit()
        self.examiner_edit.setPlaceholderText("Lead Investigator Name")
        form.addRow(QLabel("Case Number:"), self.case_no_edit)
        form.addRow(QLabel("Examiner:"), self.examiner_edit)
        root.addLayout(form)

        dir_row = QHBoxLayout()
        self.dir_edit = QLineEdit()
        self.dir_edit.setPlaceholderText("Select evidence output directory")
        self.dir_btn = QPushButton("Browse...")
        self.dir_btn.clicked.connect(self._pick_dir)
        dir_row.addWidget(self.dir_edit)
        dir_row.addWidget(self.dir_btn)
        root.addWidget(QLabel("Evidence Directory:"))
        root.addLayout(dir_row)

        btn_row = QHBoxLayout()
        btn_row.addStretch(1)
        self.cancel_btn = QPushButton("Cancel")
        self.start_btn = QPushButton("Start Investigation")
        self.cancel_btn.clicked.connect(self.reject)
        self.start_btn.clicked.connect(self._validate_and_accept)
        btn_row.addWidget(self.cancel_btn)
        btn_row.addWidget(self.start_btn)
        root.addLayout(btn_row)

        self.setMinimumWidth(520)

    def _pick_dir(self):
        selected_dir = QFileDialog.getExistingDirectory(self, "Select Evidence Directory")
        if selected_dir:
            self.dir_edit.setText(selected_dir)

    def _validate_and_accept(self):
        case_no = self.case_no_edit.text().strip()
        examiner = self.examiner_edit.text().strip()
        evidence_dir = self.dir_edit.text().strip()

        if not case_no:
            QMessageBox.warning(self, "Validation Error", "Case Number is required.")
            return
        if not examiner:
            QMessageBox.warning(self, "Validation Error", "Examiner is required.")
            return
        if not evidence_dir:
            QMessageBox.warning(self, "Validation Error", "Evidence Directory is required.")
            return
        if not os.path.isdir(evidence_dir):
            QMessageBox.warning(self, "Validation Error", "Evidence Directory does not exist.")
            return
        if not os.access(evidence_dir, os.W_OK):
            QMessageBox.warning(self, "Validation Error", "Evidence Directory is not writable.")
            return

        self._case_no = case_no
        self._examiner = examiner
        self._evidence_dir = evidence_dir
        self.accept()

    @property
    def case_no(self) -> str:
        return self._case_no

    @property
    def examiner(self) -> str:
        return self._examiner

    @property
    def evidence_dir(self) -> str:
        return self._evidence_dir


class ForensicApp(QMainWindow):
    def __init__(self, case_no: str, examiner: str, evidence_dir: str):
        super().__init__()

        try:
            ui_ref = resources.files("fx.ui").joinpath("resources", "forensic_qt6.ui")
            with resources.as_file(ui_ref) as ui_path:
                loadUi(str(ui_path), self)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"UI file could not be loaded!\n{e}")
            sys.exit(1)

        self.setWindowTitle("ForenXtract (FX)")

        # ── Session state machine ────────────────────────────────────
        self.session = Session()

        self.logger = ForensicLogger()
        self.output_dir = evidence_dir

        try:
            self.logger.set_context(case_no, examiner, self.output_dir)
            self.case_no = self.logger.case_no
            self.examiner = self.logger.examiner
            self.session.bind_context(self.case_no, self.examiner, self.output_dir)
        except ForensicLoggerError as e:
            QMessageBox.critical(self, "Critical Audit Failure", f"Could not initialize Audit Trail.\n\nError: {e}")
            sys.exit(1)

        self.setup_terminal_style()
        self.setup_tooltips()
        self.setup_connections()
        self.setup_defaults()

        self.progressBar.setValue(0)
        self.worker = None
        self.start_time = None
        self.format_type = "RAW"
        self.target_filename = ""
        self.dashboard_path = None

    # ── Setup ────────────────────────────────────────────────────────

    def setup_connections(self):
        self.btn_file.clicked.connect(self.select_key)
        self.btn_start.clicked.connect(self.start_process)
        self.btn_stop.clicked.connect(self.stop_process)

        if hasattr(self, "btn_discover"):
            self.btn_discover.clicked.connect(self.discover_disks)

        # Dead acquisition tab connections
        if hasattr(self, "btn_dead_discover"):
            self.btn_dead_discover.clicked.connect(self.discover_local_disks)
        if hasattr(self, "btn_dead_image"):
            self.btn_dead_image.clicked.connect(self.select_source_image)

        # Mutual exclusion: device dropdown ↔ source folder
        if hasattr(self, "cmb_dead_disk"):
            self.cmb_dead_disk.currentIndexChanged.connect(self._on_dead_device_selected)
        if hasattr(self, "txt_dead_image"):
            self.txt_dead_image.textChanged.connect(self._on_dead_image_changed)

        if hasattr(self, "btn_signing_key"):
            self.btn_signing_key.clicked.connect(self.select_signing_key)

        # E01 metadata: enable/disable when format changes
        if hasattr(self, "cmb_format"):
            self.cmb_format.currentIndexChanged.connect(self._on_format_changed)

        # Split image: enable/disable combo when checkbox toggled
        if hasattr(self, "chk_split"):
            self.chk_split.toggled.connect(self._on_split_toggled)

        # Open Dashboard button (if exists)
        if hasattr(self, "btn_open_dashboard"):
            self.btn_open_dashboard.clicked.connect(self.open_dashboard)
            self.btn_open_dashboard.setEnabled(False)

        # Triage sub-options: enable/disable when chk_triage toggled
        if hasattr(self, "chk_triage"):
            self.chk_triage.toggled.connect(self._on_triage_toggled)

        # SIEM fields: enable/disable when chk_siem toggled
        if hasattr(self, "chk_siem"):
            self.chk_siem.toggled.connect(self._on_siem_toggled)

        # Tab switch → update readiness hint
        if hasattr(self, "tabWidget"):
            self.tabWidget.currentChanged.connect(lambda _: self._update_readiness_hint())

        # F5 shortcut for session reset
        self.f5_shortcut = QShortcut(QKeySequence("F5"), self)
        self.f5_shortcut.activated.connect(self.reset_session)

        # F1 shortcut — show keyboard shortcuts help
        self.f1_shortcut = QShortcut(QKeySequence("F1"), self)
        self.f1_shortcut.activated.connect(self.show_shortcuts_help)

        # Ctrl+Q shortcut — quit
        self.quit_shortcut = QShortcut(QKeySequence("Ctrl+Q"), self)
        self.quit_shortcut.activated.connect(self.close)

        # Help button (if added from .ui)
        if hasattr(self, "btn_help"):
            self.btn_help.clicked.connect(self.show_shortcuts_help)

        # ── Real-time input validation ────────────────────────────
        self._setup_realtime_validation()

    # ── Real-time Validation ──────────────────────────────────────────

    _VALID_STYLE = "border: 1px solid #4caf50;"    # green border
    _INVALID_STYLE = "border: 1px solid #f44336;"  # red border
    _NEUTRAL_STYLE = ""                             # default

    def _setup_realtime_validation(self):
        """Connect text fields to live validators with debounce."""
        self._validation_timer = QTimer(self)
        self._validation_timer.setSingleShot(True)
        self._validation_timer.setInterval(400)  # 400ms debounce
        self._validation_timer.timeout.connect(self._run_validation)

        # IP field
        if hasattr(self, "txt_ip"):
            self.txt_ip.textChanged.connect(lambda: self._validation_timer.start())
            self.txt_ip.setPlaceholderText("e.g., 10.0.0.1 — validates live")

        # Username field
        if hasattr(self, "txt_user"):
            self.txt_user.textChanged.connect(lambda: self._validation_timer.start())

        # SSH key field
        if hasattr(self, "txt_key"):
            self.txt_key.textChanged.connect(lambda: self._validation_timer.start())

        # SIEM host
        if hasattr(self, "txt_siem_host"):
            self.txt_siem_host.textChanged.connect(lambda: self._validation_timer.start())

        # SIEM port
        if hasattr(self, "txt_siem_port"):
            self.txt_siem_port.textChanged.connect(lambda: self._validation_timer.start())

        # Signing key
        if hasattr(self, "txt_signing_key"):
            self.txt_signing_key.textChanged.connect(lambda: self._validation_timer.start())

    def _run_validation(self):
        """Validate all input fields and update border colors."""
        # IP
        if hasattr(self, "txt_ip"):
            ip = self.txt_ip.text().strip()
            if not ip:
                self.txt_ip.setStyleSheet(self._NEUTRAL_STYLE)
            else:
                ok, _ = validate_target_address(ip)
                self.txt_ip.setStyleSheet(self._VALID_STYLE if ok else self._INVALID_STYLE)

        # Username
        if hasattr(self, "txt_user"):
            user = self.txt_user.text().strip()
            if not user:
                self.txt_user.setStyleSheet(self._NEUTRAL_STYLE)
            else:
                ok, _ = validate_ssh_username(user)
                self.txt_user.setStyleSheet(self._VALID_STYLE if ok else self._INVALID_STYLE)

        # SSH key file
        if hasattr(self, "txt_key"):
            key = self.txt_key.text().strip()
            if not key:
                self.txt_key.setStyleSheet(self._NEUTRAL_STYLE)
            elif os.path.isfile(key):
                self.txt_key.setStyleSheet(self._VALID_STYLE)
            else:
                self.txt_key.setStyleSheet(self._INVALID_STYLE)

        # Signing key
        if hasattr(self, "txt_signing_key"):
            sk = self.txt_signing_key.text().strip()
            if not sk:
                self.txt_signing_key.setStyleSheet(self._NEUTRAL_STYLE)
            else:
                ok, _ = validate_signing_key(sk)
                self.txt_signing_key.setStyleSheet(self._VALID_STYLE if ok else self._INVALID_STYLE)

        # SIEM host (basic: non-empty when SIEM is enabled)
        if hasattr(self, "txt_siem_host") and hasattr(self, "chk_siem"):
            if self.chk_siem.isChecked():
                host = self.txt_siem_host.text().strip()
                if not host:
                    self.txt_siem_host.setStyleSheet(self._INVALID_STYLE)
                else:
                    self.txt_siem_host.setStyleSheet(self._VALID_STYLE)

        # SIEM port
        if hasattr(self, "txt_siem_port") and hasattr(self, "chk_siem"):
            if self.chk_siem.isChecked():
                port_str = self.txt_siem_port.text().strip()
                try:
                    port = int(port_str) if port_str else 0
                    ok = 1 <= port <= 65535
                except ValueError:
                    ok = False
                self.txt_siem_port.setStyleSheet(self._VALID_STYLE if ok else self._INVALID_STYLE)

        # Update status bar with readiness hint
        self._update_readiness_hint()

    def _update_readiness_hint(self):
        """Show a quick readiness status in the status bar."""
        tab_index = self.tabWidget.currentIndex() if hasattr(self, "tabWidget") else 0

        issues = []
        if tab_index == 0:  # Live
            if hasattr(self, "txt_ip") and not self.txt_ip.text().strip():
                issues.append("Target IP")
            if hasattr(self, "txt_key") and not self.txt_key.text().strip():
                issues.append("SSH Key")
            if hasattr(self, "cmb_disk") and not self.cmb_disk.currentText().strip():
                issues.append("Target Disk")
        else:  # Dead
            has_device = hasattr(self, "cmb_dead_disk") and self.cmb_dead_disk.currentText().strip()
            has_folder = hasattr(self, "txt_dead_image") and self.txt_dead_image.text().strip()
            if not has_device and not has_folder:
                issues.append("Source Device/Folder")

        if issues:
            missing = ", ".join(issues)
            self.statusBar().showMessage(f"Missing: {missing}  |  F1: Shortcuts  |  F5: Reset Session")
        else:
            self.statusBar().showMessage("Ready to acquire  |  F1: Shortcuts  |  F5: Reset Session")

    def show_shortcuts_help(self):
        """Show a dialog with available keyboard shortcuts and tips."""
        help_text = (
            "<h3>Keyboard Shortcuts</h3>"
            "<table cellpadding='4'>"
            "<tr><td><b>F1</b></td><td>Show this help</td></tr>"
            "<tr><td><b>F5</b></td><td>Reset session for new acquisition</td></tr>"
            "<tr><td><b>Ctrl+Q</b></td><td>Quit application</td></tr>"
            "</table>"
            "<br>"
            "<h3>Quick Tips</h3>"
            "<ul>"
            "<li>Input fields turn <span style='color:#4caf50'>green</span> when valid, "
            "<span style='color:#f44336'>red</span> when invalid.</li>"
            "<li>The status bar shows which fields still need to be filled.</li>"
            "<li><b>Auto-Detect (lsblk)</b> button discovers disks automatically.</li>"
            "<li>Safe Mode + Verify conflict is detected before acquisition starts.</li>"
            "<li>After acquisition, use <b>Open Dashboard</b> to view triage results.</li>"
            "</ul>"
            "<br>"
            "<h3>CLI Interactive Mode</h3>"
            "<p>Run <code>fx-acquire -i</code> or <code>fx-acquire --interactive</code> "
            "for a guided step-by-step wizard in the terminal — no flags needed!</p>"
        )
        QMessageBox.information(self, "ForenXtract — Help & Shortcuts", help_text)

    def setup_defaults(self):
        if hasattr(self, "txt_caseno"):
            self.txt_caseno.setText(self.case_no)
            self.txt_caseno.setReadOnly(True)
        if hasattr(self, "txt_examiner"):
            self.txt_examiner.setText(self.examiner)
            self.txt_examiner.setReadOnly(True)
        if hasattr(self, "txt_user"):
            self.txt_user.setText("ubuntu")
        if hasattr(self, "chk_safety"):
            self.chk_safety.setChecked(True)
        if hasattr(self, "chk_verify"):
            self.chk_verify.setChecked(True)

        # Triage sub defaults (on, checked)
        for name in ("chk_triage_network", "chk_triage_processes", "chk_triage_hash_exes"):
            if hasattr(self, name):
                getattr(self, name).setChecked(True)
                getattr(self, name).setEnabled(False)  # disabled until triage enabled

        if hasattr(self, "chk_triage_memory"):
            self.chk_triage_memory.setChecked(False)
            self.chk_triage_memory.setEnabled(False)

        if hasattr(self, "txt_siem_port"):
            self.txt_siem_port.setText("514")

    def setup_terminal_style(self):
        self.txt_log.setReadOnly(True)
        self.txt_log.setStyleSheet(
            """
            QTextEdit {
                background-color: #1e1e1e;
                color: #00e676;
                font-family: "Monospace";
                font-size: 10pt;
                border: 1px solid #333;
            }
            """
        )
        self.log("--- SYSTEM READY ---", "INFO", "SYSTEM_BOOT")
        self.log(f"[*] Session ID: {self.logger.session_id}", "INFO", "SYSTEM_BOOT")
        self.log(f"[*] Case Bound: {self.case_no} | Examiner: {self.examiner}", "INFO", "CONTEXT_UPDATED")
        self.log(f"[*] Evidence Directory: {self.output_dir}", "INFO", "CONTEXT_UPDATED")
        self.log("[*] Press F1 for keyboard shortcuts & tips.", "INFO", "SYSTEM_BOOT")
        # Show initial readiness hint
        QTimer.singleShot(100, self._update_readiness_hint)

    def setup_tooltips(self):
        if hasattr(self, "chk_writeblock"):
            self.chk_writeblock.setToolTip("Attempt to set the target block device read-only (blockdev --setro).")
        if hasattr(self, "chk_verify"):
            self.chk_verify.setToolTip("Compute source SHA-256 after acquisition and compare to stream hash.")
        if hasattr(self, "chk_safety"):
            self.chk_safety.setToolTip("Safe mode: conv=noerror,sync (pads unreadable blocks with zeros).")
        if hasattr(self, "chk_triage"):
            self.chk_triage.setToolTip("Collect volatile evidence before acquisition (read-only, no modifications to target).")
        if hasattr(self, "chk_triage_memory"):
            self.chk_triage_memory.setToolTip("Stream /proc/kcore or /proc/meminfo (requires root on target).")
        if hasattr(self, "chk_triage_hash_exes"):
            self.chk_triage_hash_exes.setToolTip("SHA-256 hash each process executable via /proc/<pid>/exe.")
        if hasattr(self, "txt_signing_key"):
            self.txt_signing_key.setToolTip("Ed25519 private key for signing the audit trail. Leave empty to skip signing.")
        if hasattr(self, "chk_siem"):
            self.chk_siem.setToolTip("Forward audit log entries to a remote syslog/SIEM server in real-time.")
        if hasattr(self, "chk_siem_cef"):
            self.chk_siem_cef.setToolTip("Use CEF (Common Event Format) instead of RFC 5424 syslog format.")
        if hasattr(self, "cmb_format"):
            self.cmb_format.setToolTip("RAW: raw disk image. RAW+LZ4: LZ4 compressed (fast, ~50% ratio). E01: EnCase format (needs libewf). AFF4: requires pyaff4.")
        if hasattr(self, "txt_e01_description"):
            self.txt_e01_description.setToolTip("Embedded in the E01 header. Visible in EnCase, Autopsy, FTK.")
        if hasattr(self, "txt_e01_notes"):
            self.txt_e01_notes.setToolTip("Examiner notes embedded in the E01 header. Visible in EnCase, Autopsy, FTK.")

    # ── Slot helpers ─────────────────────────────────────────────────

    def _on_triage_toggled(self, checked: bool) -> None:
        for name in ("chk_triage_network", "chk_triage_processes",
                     "chk_triage_memory", "chk_triage_hash_exes"):
            if hasattr(self, name):
                getattr(self, name).setEnabled(checked)

    def _on_siem_toggled(self, checked: bool) -> None:
        for name in ("txt_siem_host", "txt_siem_port", "cmb_siem_protocol", "chk_siem_cef"):
            if hasattr(self, name):
                getattr(self, name).setEnabled(checked)

    def _on_format_changed(self, index: int) -> None:
        """Enable E01 metadata fields only when E01 format is selected."""
        format_label = self.cmb_format.currentText() if hasattr(self, "cmb_format") else ""
        is_e01 = _FORMAT_MAP.get(format_label, "") == "E01"
        if hasattr(self, "groupBox_e01_metadata"):
            self.groupBox_e01_metadata.setEnabled(is_e01)

    def _on_split_toggled(self, checked: bool) -> None:
        """Enable split size combo when checkbox is toggled."""
        if hasattr(self, "cmb_split_size"):
            self.cmb_split_size.setEnabled(checked)

    def _get_split_size_bytes(self) -> int:
        """Read split size from GUI widgets. Returns 0 if disabled."""
        if not (hasattr(self, "chk_split") and self.chk_split.isChecked()):
            return 0
        raw = self.cmb_split_size.currentText().strip() if hasattr(self, "cmb_split_size") else ""
        if not raw:
            return 0
        # Strip parenthesized hint  e.g. "2G (FAT32)" → "2G"
        token = raw.split("(")[0].strip().split()[0]
        try:
            from fx.core.acquisition.split_writer import parse_split_size
            return parse_split_size(token)
        except (ValueError, KeyError):
            return 0

    # ── File pickers ─────────────────────────────────────────────────

    def select_key(self):
        fname, _ = QFileDialog.getOpenFileName(self, "Select SSH Key", "", "PEM Files (*.pem);;All Files (*)")
        if fname and hasattr(self, "txt_key"):
            self.txt_key.setText(fname)

    def select_signing_key(self):
        fname, _ = QFileDialog.getOpenFileName(self, "Select Ed25519 Signing Key", "", "Key Files (*.key);;All Files (*)")
        if fname and hasattr(self, "txt_signing_key"):
            self.txt_signing_key.setText(fname)

    def select_source_image(self):
        """Open a directory picker for dead-acquisition source folder."""
        folder = QFileDialog.getExistingDirectory(
            self, "Select Source Folder",
            "",
            QFileDialog.Option.ShowDirsOnly,
        )
        if folder and hasattr(self, "txt_dead_image"):
            self.txt_dead_image.setText(folder)

    # ── Dead tab: mutual exclusion ────────────────────────────────────

    def _on_dead_device_selected(self, index: int) -> None:
        """When a device is chosen from the dropdown, clear the source folder field."""
        if index >= 0 and hasattr(self, "cmb_dead_disk"):
            device_text = self.cmb_dead_disk.currentText().strip()
            if device_text and hasattr(self, "txt_dead_image"):
                self.txt_dead_image.blockSignals(True)
                self.txt_dead_image.clear()
                self.txt_dead_image.blockSignals(False)

    def _on_dead_image_changed(self, text: str) -> None:
        """When a source folder path is entered, deselect the device dropdown."""
        if text.strip() and hasattr(self, "cmb_dead_disk"):
            self.cmb_dead_disk.blockSignals(True)
            self.cmb_dead_disk.setCurrentIndex(-1)
            self.cmb_dead_disk.blockSignals(False)

    def open_dashboard(self):
        """Open the generated triage dashboard in the default web browser."""
        if self.dashboard_path and os.path.exists(self.dashboard_path):
            try:
                webbrowser.open(f"file://{os.path.abspath(self.dashboard_path)}")
                self._log_ui_only(f"[+] Opening dashboard: {self.dashboard_path}")
            except Exception as e:
                self._log_ui_only(f"[!] Failed to open dashboard: {e}")
                QMessageBox.warning(self, "Error", f"Could not open dashboard:\n{e}")
        else:
            QMessageBox.warning(self, "Not Available", "Dashboard was not generated or file not found.")

    # ── Logging ───────────────────────────────────────────────────────

    def _log_ui_only(self, msg: str) -> None:
        """Log to UI only (no audit trail). Used after logger is sealed."""
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        ui_msg = f"[{timestamp}] {msg}"
        self.txt_log.append(ui_msg)
        cursor = self.txt_log.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.txt_log.setTextCursor(cursor)

    def log(self, msg, level="INFO", event_type="GENERAL", hash_context=None):
        try:
            ui_msg = self.logger.log(msg, level, event_type, source_module="gui", hash_context=hash_context)
            self.txt_log.append(ui_msg)
            cursor = self.txt_log.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
            self.txt_log.setTextCursor(cursor)
        except ForensicLoggerError as e:
            # If logger is sealed, just log to UI without audit trail
            if "mathematically sealed" in str(e).lower():
                self._log_ui_only(f"[SEALED] {msg}")
            else:
                # Real failure - halt
                if self.worker and self.worker.isRunning():
                    self.worker.stop()
                QMessageBox.critical(self, "Critical Audit Failure", f"Logging mechanism failed! Halting.\n\nDetails: {str(e)}")

    def export_console_to_folder(self):
        if self.output_dir:
            try:
                audit_dir = os.path.join(self.output_dir, "audit")
                os.makedirs(audit_dir, exist_ok=True)
                with open(os.path.join(audit_dir, f"AuditConsole_{self.case_no}.log"), "w", encoding="utf-8") as f:
                    f.write(self.txt_log.toPlainText())
            except OSError:
                pass

    def reset_session(self):
        """Reset session for new acquisition (F5 shortcut)."""
        if self.worker and self.worker.isRunning():
            QMessageBox.warning(self, "Cannot Reset", "Acquisition is in progress. Stop it first (Ctrl+C or Stop button).")
            return

        try:
            # Reset session state machine
            self.session.reset()
            
            # Create new logger with fresh session
            self.logger = ForensicLogger()
            self.logger.set_context(self.case_no, self.examiner, self.output_dir)
            
            # Re-bind context
            self.session.bind_context(self.case_no, self.examiner, self.output_dir)
            
            # Reset UI state
            self.progressBar.setValue(0)
            self.btn_start.setEnabled(True)
            self.btn_stop.setEnabled(False)
            self.dashboard_path = None
            
            if hasattr(self, "btn_open_dashboard"):
                self.btn_open_dashboard.setEnabled(False)
            
            # Clear and re-initialize log
            self.txt_log.clear()
            self.setup_terminal_style()
            
            self.log(f"[~] Session reset. Ready for new acquisition (F5)", "INFO", "SESSION_RESET")
            
        except Exception as e:
            QMessageBox.critical(self, "Reset Error", f"Failed to reset session:\n{e}")
            self._log_ui_only(f"[!] Session reset failed: {e}")

    # ── Validation ────────────────────────────────────────────────────

    def validate_network_inputs(self, ip, user):
        ok, err = validate_target_address(ip)
        if not ok:
            QMessageBox.warning(self, "Validation Error", err)
            return False
        ok, err = validate_ssh_username(user)
        if not ok:
            QMessageBox.warning(self, "Validation Error", err)
            return False
        return True

    # ── Disk Discovery ────────────────────────────────────────────────

    def discover_disks(self):
        ip = self.txt_ip.text().strip() if hasattr(self, "txt_ip") else ""
        user = self.txt_user.text().strip() if hasattr(self, "txt_user") else ""
        key = self.txt_key.text().strip() if hasattr(self, "txt_key") else ""

        if not all([ip, user, key]):
            QMessageBox.warning(self, "Missing Configuration", "Please enter IP, Username, and SSH Key.")
            return
        if not self.validate_network_inputs(ip, user):
            return

        self.log("Probing remote server for block devices...", "INFO", "RECON_START")
        if hasattr(self, "btn_discover"):
            self.btn_discover.setEnabled(False)
        QApplication.processEvents()

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.WarningPolicy())

        try:
            ssh.connect(ip, username=user, key_filename=key, timeout=10)

            _, stdout_log, _ = ssh.exec_command("lsblk -o NAME,SIZE,TYPE,MOUNTPOINT")
            result_log = stdout_log.read().decode("utf-8").strip()
            self.log(f"\n=== REMOTE DISK LAYOUT ===\n{result_log}\n==========================", "INFO", "RECON_RESULT")

            _, stdout_parse, _ = ssh.exec_command("lsblk -r -n -o NAME")
            result_parse = stdout_parse.read().decode("utf-8").strip()

            if hasattr(self, "cmb_disk"):
                self.cmb_disk.clear()
                for line in result_parse.split("\n"):
                    dev_name = line.strip()
                    if dev_name:
                        self.cmb_disk.addItem(f"/dev/{dev_name}")
                self.log("Evidence Target dropdown populated successfully.", "INFO", "RECON_SUCCESS")

        except Exception as e:
            self.log(f"Disk discovery failed: {str(e)}", "ERROR", "RECON_FAILED")
        finally:
            ssh.close()
            if hasattr(self, "btn_discover"):
                self.btn_discover.setEnabled(True)

    # ── Local Disk Discovery (Dead Acquisition) ──────────────────────

    def discover_local_disks(self):
        """Detect locally attached block devices for dead acquisition."""
        self.log("Probing local system for block devices...", "INFO", "RECON_LOCAL_START")
        if hasattr(self, "btn_dead_discover"):
            self.btn_dead_discover.setEnabled(False)
        QApplication.processEvents()

        try:
            # Log full layout
            result_log = subprocess.run(
                ["lsblk", "-o", "NAME,SIZE,TYPE,MOUNTPOINT"],
                capture_output=True, text=True, timeout=10,
            )
            if result_log.returncode == 0:
                self.log(
                    f"\n=== LOCAL DISK LAYOUT ===\n{result_log.stdout.strip()}\n==========================",
                    "INFO", "RECON_LOCAL_RESULT",
                )

            # Parse device names
            result_parse = subprocess.run(
                ["lsblk", "-r", "-n", "-o", "NAME,TYPE"],
                capture_output=True, text=True, timeout=10,
            )
            if result_parse.returncode == 0 and hasattr(self, "cmb_dead_disk"):
                self.cmb_dead_disk.clear()
                for line in result_parse.stdout.strip().split("\n"):
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        dev_name, dev_type = parts[0], parts[1]
                        if dev_type in ("disk", "part"):
                            self.cmb_dead_disk.addItem(f"/dev/{dev_name}")
                self.log("Local disk dropdown populated successfully.", "INFO", "RECON_LOCAL_SUCCESS")

        except subprocess.TimeoutExpired:
            self.log("Local disk discovery timed out.", "ERROR", "RECON_LOCAL_FAILED")
        except FileNotFoundError:
            self.log("lsblk not found. Cannot auto-detect local disks.", "ERROR", "RECON_LOCAL_FAILED")
        except Exception as e:
            self.log(f"Local disk discovery failed: {str(e)}", "ERROR", "RECON_LOCAL_FAILED")
        finally:
            if hasattr(self, "btn_dead_discover"):
                self.btn_dead_discover.setEnabled(True)

    # ── Acquisition ───────────────────────────────────────────────────

    def start_process(self):
        """Route to live or dead acquisition based on the active tab."""
        tab_index = self.tabWidget.currentIndex() if hasattr(self, "tabWidget") else 0
        if tab_index == 0:
            self._start_live_process()
        else:
            self._start_dead_process()

    def _start_live_process(self):
        ip = self.txt_ip.text().strip() if hasattr(self, "txt_ip") else ""
        user = self.txt_user.text().strip() if hasattr(self, "txt_user") else ""
        key = self.txt_key.text().strip() if hasattr(self, "txt_key") else ""
        disk = self.cmb_disk.currentText().strip() if hasattr(self, "cmb_disk") else ""

        if not all([ip, user, key, disk]):
            QMessageBox.warning(self, "Validation Error", "Target IP, Key, and Target Disk are required.")
            return
        if not self.validate_network_inputs(ip, user):
            return

        # Session state guard
        try:
            self.session.begin_acquisition()
        except SessionStateError as e:
            QMessageBox.warning(self, "Workflow Error", str(e))
            return

        # ── Read all options ─────────────────────────────────────────

        # Format (from dropdown)
        format_label = self.cmb_format.currentText() if hasattr(self, "cmb_format") else "RAW (.raw)"
        self.format_type = _FORMAT_MAP.get(format_label, "RAW")

        # Split image
        self._split_size = self._get_split_size_bytes()

        throttle_limit = 0.0
        if hasattr(self, "chk_throttle") and self.chk_throttle.isChecked():
            try:
                throttle_limit = float(self.txt_throttle.text().strip())
            except ValueError:
                QMessageBox.warning(self, "Validation Error", "Please enter a valid numeric value for Bandwidth Limit.")
                return

        safe_mode      = hasattr(self, "chk_safety")    and self.chk_safety.isChecked()
        verify_hash    = hasattr(self, "chk_verify")    and self.chk_verify.isChecked()
        write_blocker  = hasattr(self, "chk_writeblock") and self.chk_writeblock.isChecked()
        run_triage     = hasattr(self, "chk_triage")    and self.chk_triage.isChecked()

        # ── Safe Mode + Verify incompatibility check ─────────────────
        # Safe Mode zero-pads unreadable sectors, which changes the image hash.
        # Source hash will never match if Safe Mode was used.
        if safe_mode and verify_hash:
            reply = QMessageBox.question(
                self, 
                "Incompatible Options",
                "Safe Mode (zero-padding unreadable sectors) is incompatible with hash verification.\n\n"
                "The source disk hash will NOT match the local image hash if Safe Mode is enabled.\n\n"
                "• Yes → Disable verification (recommended with Safe Mode)\n"
                "• No → Disable Safe Mode and keep verification\n"
                "• Cancel → Abort and go back to settings",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Yes
            )
            if reply == QMessageBox.StandardButton.Yes:
                verify_hash = False
                self.log("[*] Safe Mode detected: Verification disabled to avoid hash mismatch.", "WARNING", "ACQUISITION_PARAMS")
            elif reply == QMessageBox.StandardButton.No:
                safe_mode = False
                self.log("[*] Disabling Safe Mode to enable verification.", "WARNING", "ACQUISITION_PARAMS")
            else:
                # User chose Cancel — abort, revert session state
                try:
                    self.session.abort()
                except SessionStateError:
                    pass
                return

        triage_network   = (not run_triage) or (hasattr(self, "chk_triage_network")   and self.chk_triage_network.isChecked())
        triage_processes = (not run_triage) or (hasattr(self, "chk_triage_processes") and self.chk_triage_processes.isChecked())
        triage_memory    = run_triage       and (hasattr(self, "chk_triage_memory")    and self.chk_triage_memory.isChecked())
        triage_hash_exes = (not run_triage) or (hasattr(self, "chk_triage_hash_exes") and self.chk_triage_hash_exes.isChecked())

        # Signing key
        signing_key = ""
        if hasattr(self, "txt_signing_key"):
            signing_key = self.txt_signing_key.text().strip()

        # SIEM / Syslog
        siem_enabled = hasattr(self, "chk_siem") and self.chk_siem.isChecked()
        siem_host    = self.txt_siem_host.text().strip()       if siem_enabled and hasattr(self, "txt_siem_host")      else ""
        siem_port_s  = self.txt_siem_port.text().strip()       if siem_enabled and hasattr(self, "txt_siem_port")      else "514"
        siem_proto   = self.cmb_siem_protocol.currentText()    if siem_enabled and hasattr(self, "cmb_siem_protocol")  else "UDP"
        siem_cef     = siem_enabled and hasattr(self, "chk_siem_cef") and self.chk_siem_cef.isChecked()

        ok, err = validate_signing_key(signing_key)
        if not ok:
            QMessageBox.warning(self, "Validation Error", err)
            return

        ok, err, siem_port = validate_siem_config(siem_enabled, siem_host, siem_port_s)
        if not ok:
            QMessageBox.warning(self, "Validation Error", err)
            return

        # ── Rebuild ForensicLogger with SIEM handler if needed ───────
        if siem_enabled and siem_host:
            from fx.audit.syslog_handler import SyslogHandler
            syslog_handler = SyslogHandler(
                host=siem_host,
                port=siem_port,
                protocol=siem_proto,
                cef_mode=siem_cef,
            )
            # Re-create logger with syslog (session is already bound, swap handler only)
            self.logger._syslog = syslog_handler
            self.log(f"[*] SIEM forwarding enabled → {siem_host}:{siem_port} ({siem_proto}{'  CEF' if siem_cef else ''})", "INFO", "SIEM_CONNECTED")

        # ── Apply signing key to logger ───────────────────────────────
        if signing_key:
            self.logger._signing_key_path = signing_key
            self.log(f"[*] Audit signing key loaded: {os.path.basename(signing_key)}", "INFO", "SIGNING_KEY_SET")

        # ── Build output filename ─────────────────────────────────────
        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        ext = _FORMAT_EXT.get(self.format_type, ".raw")
        
        # Create evidence subdirectory
        evidence_dir = os.path.join(self.output_dir, "evidence")
        os.makedirs(evidence_dir, exist_ok=True)
        
        base_filename = os.path.join(evidence_dir, f"evidence_{self.case_no}_{timestamp_str}")
        self.target_filename = base_filename + ext
        # EwfWriter takes base path without extension; AFF4Writer and RawWriter take full path
        # pyewf/libewf determine segment type from extension (.E01/.E02...).
        # Always pass a concrete first segment filename for E01.
        output_file = self.target_filename

        # ── UI state ──────────────────────────────────────────────────
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.progressBar.setValue(0)
        self.start_time = datetime.now(timezone.utc)

        self.log("--- [ STARTING ACQUISITION ] ---", "INFO", "ACQUISITION_START")
        self.log(f"Format: {self.format_type} | Target: {disk}", "INFO", "ACQUISITION_PARAMS")
        self.log(
            f"Safe: {safe_mode} | Verify: {verify_hash} | Triage: {run_triage} | "
            f"Throttle: {throttle_limit} | WBlock: {write_blocker}",
            "INFO", "ACQUISITION_PARAMS",
        )
        if run_triage:
            self.log(
                f"Triage → Network: {triage_network} | Processes: {triage_processes} | "
                f"Memory: {triage_memory} | HashExes: {triage_hash_exes}",
                "INFO", "TRIAGE_PARAMS",
            )

        # Log E01 metadata if applicable
        if self.format_type == "E01":
            e01_desc_preview = e01_description[:60] if e01_description else "(empty)"
            e01_notes_preview = e01_notes[:60] if e01_notes else "(empty)"
            self.log(f"E01 Header → Description: {e01_desc_preview} | Notes: {e01_notes_preview}", "INFO", "E01_METADATA")

        # Log split image setting
        if self._split_size > 0:
            from fx.core.acquisition.split_writer import format_split_size
            self.log(f"Split Image → {format_split_size(self._split_size)} per segment", "INFO", "SPLIT_IMAGE")

        # ── Launch worker ─────────────────────────────────────────────
        # E01 metadata (description + notes)
        e01_description = self.txt_e01_description.text().strip() if hasattr(self, "txt_e01_description") else ""
        e01_notes = self.txt_e01_notes.text().strip() if hasattr(self, "txt_e01_notes") else ""

        self.worker = AcquisitionWorker(
            ip=ip,
            user=user,
            key_path=key,
            disk=disk,
            output_file=output_file,
            format_type=self.format_type,
            case_no=self.case_no,
            examiner=self.examiner,
            throttle_limit=throttle_limit,
            safe_mode=safe_mode,
            run_triage=run_triage,
            triage_network=triage_network,
            triage_processes=triage_processes,
            triage_memory=triage_memory,
            triage_hash_exes=triage_hash_exes,
            output_dir=self.output_dir,
            verify_hash=verify_hash,
            write_blocker=write_blocker,
            description=e01_description,
            notes=e01_notes,
            split_size=getattr(self, "_split_size", 0),
        )
        self.worker.progress_signal.connect(self.update_progress_ui)
        self.worker.finished_signal.connect(self.on_acquisition_finished)
        self.worker.error_signal.connect(self.on_acquisition_error)
        self.worker.start()

    # ── Dead Acquisition (Local) ──────────────────────────────────────

    def _start_dead_process(self):
        """Start a dead (local) forensic acquisition."""
        # Determine source: folder/image overrides device combo
        source_folder = self.txt_dead_image.text().strip() if hasattr(self, "txt_dead_image") else ""
        source_device = self.cmb_dead_disk.currentText().strip() if hasattr(self, "cmb_dead_disk") else ""
        source_path = source_folder or source_device

        if not source_path:
            QMessageBox.warning(self, "Validation Error", "Select a source device or folder.")
            return

        if not os.path.exists(source_path):
            QMessageBox.warning(self, "Validation Error", f"Source not found:\n{source_path}")
            return

        # Session state guard
        try:
            self.session.begin_acquisition()
        except SessionStateError as e:
            QMessageBox.warning(self, "Workflow Error", str(e))
            return

        # ── Read shared options ──────────────────────────────────────
        format_label = self.cmb_format.currentText() if hasattr(self, "cmb_format") else "RAW (.raw)"
        self.format_type = _FORMAT_MAP.get(format_label, "RAW")

        # Split image
        self._split_size = self._get_split_size_bytes()

        throttle_limit = 0.0
        if hasattr(self, "chk_throttle") and self.chk_throttle.isChecked():
            try:
                throttle_limit = float(self.txt_throttle.text().strip())
            except ValueError:
                QMessageBox.warning(self, "Validation Error", "Please enter a valid numeric value for Bandwidth Limit.")
                return

        safe_mode     = hasattr(self, "chk_safety")     and self.chk_safety.isChecked()
        verify_hash   = hasattr(self, "chk_verify")     and self.chk_verify.isChecked()
        write_blocker = hasattr(self, "chk_writeblock") and self.chk_writeblock.isChecked()

        # Safe Mode + Verify incompatibility (same as live)
        if safe_mode and verify_hash:
            reply = QMessageBox.question(
                self,
                "Incompatible Options",
                "Safe Mode (zero-padding unreadable sectors) is incompatible with hash verification.\n\n"
                "The source hash will NOT match the local image hash if Safe Mode is enabled.\n\n"
                "• Yes → Disable verification (recommended with Safe Mode)\n"
                "• No → Disable Safe Mode and keep verification\n"
                "• Cancel → Abort and go back to settings",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Yes
            )
            if reply == QMessageBox.StandardButton.Yes:
                verify_hash = False
                self.log("[*] Safe Mode detected: Verification disabled to avoid hash mismatch.", "WARNING", "ACQUISITION_PARAMS")
            elif reply == QMessageBox.StandardButton.No:
                safe_mode = False
                self.log("[*] Disabling Safe Mode to enable verification.", "WARNING", "ACQUISITION_PARAMS")
            else:
                try:
                    self.session.abort()
                except SessionStateError:
                    pass
                return

        # Signing key
        signing_key = ""
        if hasattr(self, "txt_signing_key"):
            signing_key = self.txt_signing_key.text().strip()

        # SIEM / Syslog
        siem_enabled = hasattr(self, "chk_siem") and self.chk_siem.isChecked()
        siem_host    = self.txt_siem_host.text().strip()       if siem_enabled and hasattr(self, "txt_siem_host")      else ""
        siem_port_s  = self.txt_siem_port.text().strip()       if siem_enabled and hasattr(self, "txt_siem_port")      else "514"
        siem_proto   = self.cmb_siem_protocol.currentText()    if siem_enabled and hasattr(self, "cmb_siem_protocol")  else "UDP"
        siem_cef     = siem_enabled and hasattr(self, "chk_siem_cef") and self.chk_siem_cef.isChecked()

        ok, err = validate_signing_key(signing_key)
        if not ok:
            QMessageBox.warning(self, "Validation Error", err)
            return

        ok, err, siem_port = validate_siem_config(siem_enabled, siem_host, siem_port_s)
        if not ok:
            QMessageBox.warning(self, "Validation Error", err)
            return

        if siem_enabled and siem_host:
            from fx.audit.syslog_handler import SyslogHandler
            syslog_handler = SyslogHandler(
                host=siem_host, port=siem_port, protocol=siem_proto, cef_mode=siem_cef,
            )
            self.logger._syslog = syslog_handler
            self.log(f"[*] SIEM forwarding enabled → {siem_host}:{siem_port} ({siem_proto}{'  CEF' if siem_cef else ''})", "INFO", "SIEM_CONNECTED")

        if signing_key:
            self.logger._signing_key_path = signing_key
            self.log(f"[*] Audit signing key loaded: {os.path.basename(signing_key)}", "INFO", "SIGNING_KEY_SET")

        # ── Build output filename ─────────────────────────────────────
        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        ext = _FORMAT_EXT.get(self.format_type, ".raw")

        evidence_dir = os.path.join(self.output_dir, "evidence")
        os.makedirs(evidence_dir, exist_ok=True)

        base_filename = os.path.join(evidence_dir, f"evidence_{self.case_no}_{timestamp_str}")
        self.target_filename = base_filename + ext
        output_file = self.target_filename

        # ── UI state ──────────────────────────────────────────────────
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.progressBar.setValue(0)
        self.start_time = datetime.now(timezone.utc)

        self.log("--- [ STARTING DEAD ACQUISITION (LOCAL) ] ---", "INFO", "DEAD_ACQUISITION_START")
        self.log(f"Source: {source_path}", "INFO", "DEAD_ACQUISITION_PARAMS")
        self.log(f"Format: {self.format_type} | Output: {output_file}", "INFO", "DEAD_ACQUISITION_PARAMS")
        self.log(
            f"Safe: {safe_mode} | Verify: {verify_hash} | "
            f"Throttle: {throttle_limit} | WBlock: {write_blocker}",
            "INFO", "DEAD_ACQUISITION_PARAMS",
        )

        # ── Launch dead worker ────────────────────────────────────────
        # E01 metadata (description + notes)
        e01_description = self.txt_e01_description.text().strip() if hasattr(self, "txt_e01_description") else ""
        e01_notes = self.txt_e01_notes.text().strip() if hasattr(self, "txt_e01_notes") else ""

        # Log E01 metadata if applicable
        if self.format_type == "E01":
            e01_desc_preview = e01_description[:60] if e01_description else "(empty)"
            e01_notes_preview = e01_notes[:60] if e01_notes else "(empty)"
            self.log(f"E01 Header → Description: {e01_desc_preview} | Notes: {e01_notes_preview}", "INFO", "E01_METADATA")

        # Log split image setting
        if self._split_size > 0:
            from fx.core.acquisition.split_writer import format_split_size
            self.log(f"Split Image → {format_split_size(self._split_size)} per segment", "INFO", "SPLIT_IMAGE")

        self.worker = DeadAcquisitionWorker(
            source_path=source_path,
            output_file=output_file,
            format_type=self.format_type,
            case_no=self.case_no,
            examiner=self.examiner,
            throttle_limit=throttle_limit,
            safe_mode=safe_mode,
            verify_hash=verify_hash,
            write_blocker=write_blocker,
            description=e01_description,
            notes=e01_notes,
            split_size=getattr(self, "_split_size", 0),
        )
        self.worker.progress_signal.connect(self.update_progress_ui)
        self.worker.finished_signal.connect(self.on_acquisition_finished)
        self.worker.error_signal.connect(self.on_acquisition_error)
        self.worker.start()

    def stop_process(self):
        if self.worker and self.worker.isRunning():
            self.log("Abort requested by user. Terminating secure connection...", "WARNING", "ACQUISITION_ABORTED")
            self.btn_stop.setEnabled(False)
            self.worker.stop()
            self.export_console_to_folder()

    def update_progress_ui(self, data):
        pct = data.get("percentage", 0)
        speed = data.get("speed_mb_s", 0)
        eta = data.get("eta", "")
        md5 = data.get("md5_current", "")

        self.progressBar.setValue(pct)

        # During verification phase the ETA field starts with "Verifying…"
        if isinstance(eta, str) and eta.startswith("Verifying"):
            self.statusBar().showMessage(
                f"Verifying Source Hash… | Speed: {speed} MB/s | {eta} | {pct}%"
            )
        else:
            self.statusBar().showMessage(
                f"Streaming... | Speed: {speed} MB/s | ETA: {eta} | MD5: {md5}"
            )

    def on_acquisition_error(self, error_msg):
        self.log(f"Process Error: {error_msg}", "ERROR", "ACQUISITION_FAILED")
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.progressBar.setValue(0)
        self.statusBar().showMessage("Acquisition Interrupted.")
        self.export_console_to_folder()
        # Reset session so user can retry without F5
        try:
            self.session.abort()
        except SessionStateError:
            pass

    def on_acquisition_finished(self, data):
        self.progressBar.setValue(100)
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)

        sha256 = data.get("sha256_final", "ERROR")
        md5 = data.get("md5_final", "ERROR")
        # Live uses "remote_sha256", dead uses "source_sha256"
        remote_sha256 = data.get("remote_sha256", data.get("source_sha256", "SKIPPED"))
        hash_match = data.get("hash_match", None)

        verify_hash = hasattr(self, "chk_verify") and self.chk_verify.isChecked()
        try:
            if verify_hash and remote_sha256 != "SKIPPED":
                self.session.begin_verification()
            self.session.seal()
        except SessionStateError as e:
            self.log(f"Session state warning: {e}", "WARNING", "SESSION_WARNING")

        duration = "UNKNOWN"
        if self.start_time:
            duration = str(datetime.now(timezone.utc) - self.start_time).split(".")[0]

        self.log("Local hashes calculated successfully.", "INFO", "INTEGRITY_LOCAL", hash_context={
            "local_sha256": sha256,
            "local_md5": md5,
            "remote_sha256": None if remote_sha256 == "SKIPPED" else remote_sha256,
            "verified": hash_match,
        })

        if remote_sha256 != "SKIPPED":
            if hash_match is True:
                self.log("Source and Local hashes MATCH exactly.", "INFO", "INTEGRITY_VERIFIED")
            elif hash_match is False:
                self.log("WARNING: Source and Local hashes do NOT match.", "ERROR", "INTEGRITY_MISMATCH")
            else:
                self.log("Verification status unknown.", "WARNING", "INTEGRITY_UNKNOWN")

        # ── Output image re-verification (FTK "Verify After Create") ─────
        output_sha256 = data.get("output_sha256", "SKIPPED")
        output_match = data.get("output_match", None)
        if output_sha256 not in ("SKIPPED", None):
            self.log(f"Output image SHA-256: {output_sha256}", "INFO", "OUTPUT_VERIFY",
                     hash_context={"output_sha256": output_sha256, "output_match": output_match})
            if output_match is True:
                self.log("Output image verification: ✅ MATCH — written file matches stream hash.",
                         "INFO", "OUTPUT_VERIFY_MATCH")
            elif output_match is False:
                self.log("Output image verification: ❌ MISMATCH — written file does NOT match stream hash!",
                         "ERROR", "OUTPUT_VERIFY_MISMATCH")
            else:
                self.log("Output image verification: ⚠️  UNKNOWN", "WARNING", "OUTPUT_VERIFY_UNKNOWN")

        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        
        # Create organized subdirectories
        reports_dir = os.path.join(self.output_dir, "reports")
        audit_dir = os.path.join(self.output_dir, "audit")
        os.makedirs(reports_dir, exist_ok=True)
        os.makedirs(audit_dir, exist_ok=True)
        
        txt_path = os.path.join(reports_dir, f"Report_{self.case_no}_{timestamp_str}.txt")
        pdf_path = os.path.join(reports_dir, f"Report_{self.case_no}_{timestamp_str}.pdf")

        self.log("Generating reports (TXT & PDF)...", "INFO", "REPORT_START")

        audit_hash, chattr_success = self.logger.seal_audit_trail()

        report_data = {
            "case_no": self.case_no,
            "examiner": self.examiner,
            "ip": self.txt_ip.text().strip() if hasattr(self, "txt_ip") else "",
            "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "duration": duration,
            "format_type": self.format_type,
            "target_filename": self.target_filename,
            "triage_requested": hasattr(self, "chk_triage") and self.chk_triage.isChecked(),
            "writeblock_requested": hasattr(self, "chk_writeblock") and self.chk_writeblock.isChecked(),
            "throttle_enabled": hasattr(self, "chk_throttle") and self.chk_throttle.isChecked(),
            "throttle_val": self.txt_throttle.text().strip() if hasattr(self, "txt_throttle") else "0",
            "safe_mode": hasattr(self, "chk_safety") and self.chk_safety.isChecked(),
            "remote_sha256": remote_sha256,
            "local_sha256": sha256,
            "local_md5": md5,
            "hash_match": hash_match,
            "audit_hash": audit_hash,
            "kernel_seal_success": chattr_success,
            "output_sha256": output_sha256,
            "output_match": output_match,
            "txt_path": txt_path,
            "pdf_path": pdf_path,
            "output_dir": self.output_dir,
        }

        # Acquisition mode indicator for reports
        is_dead = (hasattr(self, "tabWidget") and self.tabWidget.currentIndex() == 1)
        report_data["acquisition_mode"] = "DEAD (Local)" if is_dead else "LIVE (Remote)"

        # Extract triage JSON paths from triage_summary
        triage_summary = data.get("triage_summary", {})
        if triage_summary:
            # Extract process JSON path
            if "collectors" in triage_summary and "processes" in triage_summary["collectors"]:
                processes_json = triage_summary["collectors"]["processes"].get("json_path")
                if processes_json:
                    report_data["processes_json_path"] = processes_json

            # Extract network JSON path
            if "collectors" in triage_summary and "network" in triage_summary["collectors"]:
                network_json = triage_summary["collectors"]["network"].get("json_path")
                if network_json:
                    report_data["network_json_path"] = network_json

            # Extract memory JSON path
            if "collectors" in triage_summary and "memory" in triage_summary["collectors"]:
                memory_json = triage_summary["collectors"]["memory"].get("json_path")
                if memory_json:
                    report_data["memory_json_path"] = memory_json

        ReportEngine.generate_reports(report_data)

        # Store dashboard path for "Open Dashboard" button
        self.dashboard_path = report_data.get("dashboard_path")

        try:
            self.session.finalize()
        except SessionStateError as e:
            self._log_ui_only(f"[Session] Session state warning: {e}")

        self.export_console_to_folder()

        # Enable Open Dashboard button if dashboard was generated
        if hasattr(self, "btn_open_dashboard") and self.dashboard_path:
            self.btn_open_dashboard.setEnabled(True)
        
        # Show completion dialog with optional dashboard button
        msg = "Forensic acquisition completed.\nReports saved.\n\nAudit trail is sealed."
        if self.dashboard_path and os.path.exists(self.dashboard_path):
            reply = QMessageBox.information(
                self, "Complete", msg,
                QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Open,
                QMessageBox.StandardButton.Ok
            )
            if reply == QMessageBox.StandardButton.Open:
                self.open_dashboard()
        else:
            QMessageBox.information(self, "Complete", msg)


def main() -> None:
    py_missing, native_missing = run_dependency_check()
    if py_missing:
        error_msg = "Missing Dependencies Detected:\n\n"
        if py_missing:
            error_msg += "Python Packages:\n" + "\n".join([f" - {p}" for p in py_missing]) + "\n"

        app = QApplication(sys.argv)
        QMessageBox.critical(None, "Dependency Error", error_msg + "\n\nPlease install required components before running.")
        sys.exit(1)

    app = QApplication(sys.argv)

    # Native libraries are optional at startup; they gate specific formats (e.g., E01/libewf).
    # Warn, but allow the GUI to run so users can still acquire RAW/LZ4.
    if native_missing:
        warn_msg = (
            "Optional system components are missing:\n\n"
            + "\n".join([f" - {l}" for l in native_missing])
            + "\n\nSome evidence formats may be unavailable (e.g., E01)."
        )
        QMessageBox.warning(None, "Optional Components Missing", warn_msg)

    # qt-material generates icon resources under a cache directory.
    # If the environment is read-only (restricted containers, sandboxing),
    # don't crash the entire GUI just because theming cannot initialize.
    try:
        from qt_material import apply_stylesheet
        cache_root = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
        theme_dir = os.path.join(cache_root, "forenxtract", "qt_material")
        os.makedirs(theme_dir, exist_ok=True)
        apply_stylesheet(app, theme="dark_teal.xml", parent="." + theme_dir)
    except Exception:
        pass

    wizard = CaseWizard()
    if wizard.exec() != QDialog.DialogCode.Accepted:
        sys.exit(0)

    window = ForensicApp(wizard.case_no, wizard.examiner, wizard.evidence_dir)
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
