# Author: Futhark1393
# Description: Triage orchestrator — runs all live triage collectors in sequence.
# Each collector is best-effort: a failure in one does not halt others or acquisition.

import os
from datetime import datetime, timezone
from typing import Callable

from fx.triage.network import NetworkStateCollector
from fx.triage.processes import ProcessListCollector
from fx.triage.memory import MemoryDumpCollector


class TriageOrchestrator:
    """
    Coordinates all live triage collectors over an existing SSH connection.

    Usage::

        orchestrator = TriageOrchestrator(
            run_network=True,
            run_processes=True,
            run_memory=True,
            attempt_kcore=False,   # safest default
        )
        results = orchestrator.run(ssh, case_no="2026-001", output_dir="/evidence")

    All collectors are read-only and best-effort.
    """

    def __init__(
        self,
        run_network: bool = True,
        run_processes: bool = True,
        run_memory: bool = True,
        hash_exes: bool = True,
        attempt_kcore: bool = False,
        on_status: Callable[[str], None] | None = None,
    ):
        self.run_network = run_network
        self.run_processes = run_processes
        self.run_memory = run_memory
        self.hash_exes = hash_exes
        self.attempt_kcore = attempt_kcore
        self._on_status = on_status or (lambda msg: None)

    def _status(self, msg: str) -> None:
        self._on_status(msg)

    def run(self, ssh, case_no: str, output_dir: str) -> dict:
        """
        Run all enabled triage collectors.

        Returns a summary dict with per-collector results and any errors.
        """
        summary: dict = {
            "triage_timestamp_utc": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
            "case_no": case_no,
            "output_dir": output_dir,
            "collectors": {},
        }

        # ── Network State ─────────────────────────────────────────────
        if self.run_network:
            self._status("Triage: Collecting Network State...")
            try:
                result = NetworkStateCollector().collect(ssh, case_no, output_dir)
                summary["collectors"]["network"] = {
                    "status": "OK",
                    "txt_path": result.get("txt_path"),
                    "json_path": result.get("json_path"),
                }
            except Exception as e:
                summary["collectors"]["network"] = {"status": "ERROR", "error": str(e)}

        # ── Running Processes ─────────────────────────────────────────
        if self.run_processes:
            self._status("Triage: Collecting Process List...")
            try:
                result = ProcessListCollector().collect(
                    ssh, case_no, output_dir, hash_exes=self.hash_exes
                )
                summary["collectors"]["processes"] = {
                    "status": "OK",
                    "process_count": result.get("process_count", 0),
                    "txt_path": result.get("txt_path"),
                    "json_path": result.get("json_path"),
                }
            except Exception as e:
                summary["collectors"]["processes"] = {"status": "ERROR", "error": str(e)}

        # ── Memory State ──────────────────────────────────────────────
        if self.run_memory:
            self._status("Triage: Collecting Memory State...")
            try:
                result = MemoryDumpCollector().collect(
                    ssh, case_no, output_dir, attempt_kcore=self.attempt_kcore
                )
                summary["collectors"]["memory"] = {
                    "status": "OK",
                    "kcore_status": result.get("kcore", {}).get("status", "UNKNOWN"),
                    "lime_device": result.get("lime_device", {}).get("lime_device"),
                    "json_path": result.get("json_path"),
                }
            except Exception as e:
                summary["collectors"]["memory"] = {"status": "ERROR", "error": str(e)}

        self._status("Triage: Complete.")
        return summary
