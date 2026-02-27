# Author: Futhark1393
# Description: Main GUI module for ForenXtract (FX).
# Features: Case Wizard workflow, structured forensic logging, secure acquisition orchestration,
#          optional write-blocker, post-acq verification, report generation, triage, SIEM, signing.

import sys
import os
import re
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
)
from PyQt6.uic import loadUi
from PyQt6.QtGui import QTextCursor

from fx.deps.dependency_checker import run_dependency_check
from fx.audit.logger import ForensicLogger, ForensicLoggerError
from fx.report.report_engine import ReportEngine
from fx.ui.workers import AcquisitionWorker
from fx.core.session import Session, SessionState, SessionStateError


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

    # ── Setup ────────────────────────────────────────────────────────

    def setup_connections(self):
        self.btn_file.clicked.connect(self.select_key)
        self.btn_start.clicked.connect(self.start_process)
        self.btn_stop.clicked.connect(self.stop_process)

        if hasattr(self, "btn_discover"):
            self.btn_discover.clicked.connect(self.discover_disks)

        if hasattr(self, "btn_signing_key"):
            self.btn_signing_key.clicked.connect(self.select_signing_key)

        # Triage sub-options: enable/disable when chk_triage toggled
        if hasattr(self, "chk_triage"):
            self.chk_triage.toggled.connect(self._on_triage_toggled)

        # SIEM fields: enable/disable when chk_siem toggled
        if hasattr(self, "chk_siem"):
            self.chk_siem.toggled.connect(self._on_siem_toggled)

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

    # ── File pickers ─────────────────────────────────────────────────

    def select_key(self):
        fname, _ = QFileDialog.getOpenFileName(self, "Select SSH Key", "", "PEM Files (*.pem);;All Files (*)")
        if fname and hasattr(self, "txt_key"):
            self.txt_key.setText(fname)

    def select_signing_key(self):
        fname, _ = QFileDialog.getOpenFileName(self, "Select Ed25519 Signing Key", "", "Key Files (*.key);;All Files (*)")
        if fname and hasattr(self, "txt_signing_key"):
            self.txt_signing_key.setText(fname)

    # ── Logging ───────────────────────────────────────────────────────

    def log(self, msg, level="INFO", event_type="GENERAL", hash_context=None):
        try:
            ui_msg = self.logger.log(msg, level, event_type, source_module="gui", hash_context=hash_context)
            self.txt_log.append(ui_msg)
            cursor = self.txt_log.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
            self.txt_log.setTextCursor(cursor)
        except ForensicLoggerError as e:
            if self.worker and self.worker.isRunning():
                self.worker.stop()
            QMessageBox.critical(self, "Critical Audit Failure", f"Logging mechanism failed! Halting.\n\nDetails: {str(e)}")

    def export_console_to_folder(self):
        if self.output_dir:
            try:
                with open(os.path.join(self.output_dir, f"AuditConsole_{self.case_no}.log"), "w", encoding="utf-8") as f:
                    f.write(self.txt_log.toPlainText())
            except OSError:
                pass

    # ── Validation ────────────────────────────────────────────────────

    def validate_network_inputs(self, ip, user):
        ipv4_re = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        if not re.match(ipv4_re, ip):
            QMessageBox.warning(self, "Validation Error", "Invalid IPv4 Address format.")
            return False
        if not re.match(r"^[a-z_][a-z0-9_-]{0,31}$", user):
            QMessageBox.warning(self, "Validation Error", "Invalid SSH Username format.")
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
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

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

    # ── Acquisition ───────────────────────────────────────────────────

    def start_process(self):
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

        if siem_enabled and not siem_host:
            QMessageBox.warning(self, "Validation Error", "SIEM host is required when SIEM forwarding is enabled.")
            return

        try:
            siem_port = int(siem_port_s) if siem_port_s else 514
        except ValueError:
            QMessageBox.warning(self, "Validation Error", "SIEM port must be a number.")
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
            if not os.path.isfile(signing_key):
                QMessageBox.warning(self, "Validation Error", f"Signing key not found:\n{signing_key}")
                return
            self.logger._signing_key_path = signing_key
            self.log(f"[*] Audit signing key loaded: {os.path.basename(signing_key)}", "INFO", "SIGNING_KEY_SET")

        # ── Build output filename ─────────────────────────────────────
        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        ext = _FORMAT_EXT.get(self.format_type, ".raw")
        base_filename = os.path.join(self.output_dir, f"evidence_{self.case_no}_{timestamp_str}")
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

        # ── Launch worker ─────────────────────────────────────────────
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
        self.progressBar.setValue(data.get("percentage", 0))
        self.statusBar().showMessage(
            f"Streaming... | Speed: {data.get('speed_mb_s', 0)} MB/s | ETA: {data.get('eta', '')} | MD5: {data.get('md5_current', '')}"
        )

    def on_acquisition_error(self, error_msg):
        self.log(f"Process Error: {error_msg}", "ERROR", "ACQUISITION_FAILED")
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.progressBar.setValue(0)
        self.statusBar().showMessage("Acquisition Interrupted.")
        self.export_console_to_folder()

    def on_acquisition_finished(self, data):
        self.progressBar.setValue(100)
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)

        sha256 = data.get("sha256_final", "ERROR")
        md5 = data.get("md5_final", "ERROR")
        remote_sha256 = data.get("remote_sha256", "SKIPPED")
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

        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        txt_path = os.path.join(self.output_dir, f"Report_{self.case_no}_{timestamp_str}.txt")
        pdf_path = os.path.join(self.output_dir, f"Report_{self.case_no}_{timestamp_str}.pdf")

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
            "txt_path": txt_path,
            "pdf_path": pdf_path,
        }

        ReportEngine.generate_reports(report_data)

        try:
            self.session.finalize()
        except SessionStateError as e:
            self.log(f"Session state warning: {e}", "WARNING", "SESSION_WARNING")

        self.export_console_to_folder()
        QMessageBox.information(self, "Complete", "Forensic acquisition completed.\nReports saved.\n\nAudit trail is sealed.")


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
