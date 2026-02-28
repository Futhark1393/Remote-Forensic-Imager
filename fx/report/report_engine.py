# Author: Futhark1393
# Description: Report engine for ForenXtract (FX).
# Features: TXT + PDF forensic reporting with integrity-aware executive summary.
#           Includes Triage Data Dashboard with interactive visualizations.

import os
import warnings
from datetime import datetime, timezone
from fpdf import FPDF
from typing import Optional

try:
    from fx.report.dashboard import TriageDashboard
except ImportError:
    TriageDashboard = None


class ReportEngine:
    @staticmethod
    def _executive_summary(remote_sha256: str, hash_match, audit_hash: str, kernel_seal_success: bool, safe_mode: bool = False) -> str:
        """
        Integrity-aware summary.
        - If remote hash verification is requested and mismatches, summary must reflect failure.
        - If remote hash is skipped, summary should be neutral (local integrity only).
        - If safe_mode is True, note that unreadable sectors were zero-padded.
        """
        seal_str = "SUCCESS" if kernel_seal_success else "FAILED (No Passwordless Sudo)"
        safe_mode_note = " (Note: Unreadable sectors were padded with zeros due to Safe Mode.)" if safe_mode else ""

        if remote_sha256 == "SKIPPED" or remote_sha256 is None:
            return (
                "The acquisition process completed. Local integrity hashes (SHA-256/MD5) were computed and recorded. "
                f"The audit trail was sealed (Audit SHA-256: {audit_hash}). Kernel seal: {seal_str}.{safe_mode_note}"
            )

        if hash_match is True:
            return (
                "The acquisition process completed successfully. Source-to-image verification PASSED. "
                f"Evidence integrity has been verified by matching source and local SHA-256 values. "
                f"Audit SHA-256: {audit_hash}. Kernel seal: {seal_str}.{safe_mode_note}"
            )

        if hash_match is False:
            return (
                "The acquisition process completed, but source-to-image verification FAILED. "
                "Source SHA-256 does NOT match the local SHA-256. Treat this evidence image as NOT VERIFIED. "
                f"Audit SHA-256: {audit_hash}. Kernel seal: {seal_str}.{safe_mode_note}"
            )

        return (
            "The acquisition process completed. Source hash was collected, but verification status is UNKNOWN. "
            f"Audit SHA-256: {audit_hash}. Kernel seal: {seal_str}.{safe_mode_note}"
        )

    @staticmethod
    def generate_reports(report_data: dict) -> None:
        """
        report_data required keys:
        - case_no, examiner, ip, timestamp_utc, duration
        - format_type, target_filename
        - safe_mode, triage_requested, writeblock_requested (or write_blocker for backward compatibility)
        - remote_sha256, local_sha256, local_md5, hash_match
        - audit_hash, kernel_seal_success
        - txt_path, pdf_path
        
        Optional dashboard keys:
        - processes_json_path: Path to triage process JSON
        - network_json_path: Path to triage network JSON
        - memory_json_path: Path to triage memory JSON
        - output_dir: Directory for dashboard output
        """
        txt_path = report_data["txt_path"]
        pdf_path = report_data["pdf_path"]

        summary = ReportEngine._executive_summary(
            report_data.get("remote_sha256"),
            report_data.get("hash_match"),
            report_data.get("audit_hash", "UNKNOWN"),
            report_data.get("kernel_seal_success", False),
            report_data.get("safe_mode", False),
        )

        ReportEngine._generate_txt(report_data, summary, txt_path)
        ReportEngine._generate_pdf(report_data, summary, pdf_path)
        
        # Generate Triage Data Dashboard if data is available
        if TriageDashboard and report_data.get("triage_requested"):
            try:
                output_dir = report_data.get("output_dir", os.path.dirname(txt_path))
                dashboard = TriageDashboard(
                    case_no=report_data.get("case_no"),
                    output_dir=output_dir
                )
                
                dashboard_path = dashboard.generate_dashboard(
                    processes_json_path=report_data.get("processes_json_path"),
                    network_json_path=report_data.get("network_json_path"),
                    memory_json_path=report_data.get("memory_json_path")
                )
                
                if dashboard_path:
                    report_data["dashboard_path"] = dashboard_path
            except Exception as e:
                print(f"[!] Warning: Could not generate dashboard: {e}")

    @staticmethod
    def _generate_txt(d: dict, summary: str, filepath: str) -> None:
        verification_result = "SKIPPED"
        if d.get("remote_sha256") != "SKIPPED":
            if d.get("hash_match") is True:
                verification_result = "MATCH (VERIFIED)"
            elif d.get("hash_match") is False:
                verification_result = "MISMATCH (FAILED)"
            else:
                verification_result = "UNKNOWN"

        kernel_seal_str = "SUCCESS" if d.get("kernel_seal_success") else "FAILED (No Passwordless Sudo)"
        triage_status = "REQUESTED" if d.get("triage_requested") else "NOT REQUESTED"
        writeblock_enabled = bool(d.get("writeblock_requested", d.get("write_blocker")))
        dashboard_note = ""
        if d.get("triage_requested") and d.get("dashboard_path"):
            dashboard_note = f"\n\n5. TRIAGE DATA DASHBOARD\n--------------------------\nInteractive Dashboard: {d.get('dashboard_path')}\nView in web browser for detailed charts and statistics.\n"

        content = f"""
================================================================
            DIGITAL FORENSIC ACQUISITION REPORT
================================================================

1. CASE DETAILS
----------------
Case Number     : {d.get("case_no")}
Examiner        : {d.get("examiner")}
Date (UTC)      : {d.get("timestamp_utc")}
Target IP       : {d.get("ip")}
Duration        : {d.get("duration")}

2. EVIDENCE INTEGRITY
---------------------
Source SHA-256   : {d.get("remote_sha256")}
Local  SHA-256   : {d.get("local_sha256")}
Local  MD5       : {d.get("local_md5")}
Verification     : {verification_result}

Audit Log Hash   : {d.get("audit_hash")}
Kernel Seal      : {kernel_seal_str}

3. ACQUISITION PARAMETERS
--------------------------
Safe Mode        : {"ENABLED" if d.get("safe_mode") else "DISABLED"}
Write-Blocker    : {"ENABLED" if writeblock_enabled else "DISABLED"}
Format Type      : {d.get("format_type")}

{"Note: In Safe Mode, unreadable sectors are padded with zeros." if d.get("safe_mode") else ""}

4. PRE-ACQUISITION TRIAGE
--------------------------
Live Triage Log  : {triage_status}
{dashboard_note}

EXECUTIVE SUMMARY
------------------
{summary}

================================================================
Note: Auto-generated by ForenXtract (FX)
"""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content.strip() + "\n")

    @staticmethod
    def _generate_pdf(d: dict, summary: str, filepath: str) -> None:
        verification_result = "SKIPPED"
        if d.get("remote_sha256") != "SKIPPED":
            if d.get("hash_match") is True:
                verification_result = "MATCH (VERIFIED)"
            elif d.get("hash_match") is False:
                verification_result = "MISMATCH (FAILED)"
            else:
                verification_result = "UNKNOWN"

        kernel_seal_str = "SUCCESS" if d.get("kernel_seal_success") else "FAILED (No Passwordless Sudo)"
        triage_status = "REQUESTED" if d.get("triage_requested") else "NOT REQUESTED"
        writeblock_enabled = bool(d.get("writeblock_requested", d.get("write_blocker")))

        # Suppress fpdf2 deprecation warnings for ln parameter (not yet available as of fpdf2 2.8.5)
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=DeprecationWarning)

            pdf = FPDF()
            pdf.add_page()
            pdf.set_auto_page_break(auto=True, margin=15)

            pdf.set_font("helvetica", "B", 16)
            pdf.cell(0, 12, "DIGITAL FORENSIC ACQUISITION REPORT", border=1, ln=1, align="C")
            pdf.ln(6)

            pdf.set_font("helvetica", "B", 12)
            pdf.cell(0, 10, "1. CASE DETAILS", ln=1)
            pdf.set_font("helvetica", "", 11)

            label_w = 45
            def row(label, value):
                pdf.cell(label_w, 8, label, 0)
                pdf.cell(0, 8, str(value), 0, 1)

            row("Case Number:", d.get("case_no"))
            row("Examiner:", d.get("examiner"))
            row("Date (UTC):", d.get("timestamp_utc"))
            row("Target IP:", d.get("ip"))
            row("Duration:", d.get("duration"))

            pdf.ln(4)
            pdf.set_font("helvetica", "B", 12)
            pdf.cell(0, 10, "2. EVIDENCE INTEGRITY", ln=1)

            pdf.set_font("courier", "", 10)
            pdf.cell(0, 8, f"Source SHA256 : {d.get('remote_sha256')}", border=1, ln=1)
            pdf.cell(0, 8, f"Local  SHA256 : {d.get('local_sha256')}", border=1, ln=1)
            pdf.cell(0, 8, f"Local  MD5    : {d.get('local_md5')}", border=1, ln=1)

            pdf.set_font("helvetica", "B", 11)
            pdf.cell(0, 8, f"Verification  : {verification_result}", border=1, ln=1)

            pdf.set_font("courier", "", 10)
            pdf.cell(0, 8, f"Audit Log Hash: {d.get('audit_hash')}", border=1, ln=1)
            pdf.cell(0, 8, f"Kernel Seal   : {kernel_seal_str}", border=1, ln=1)

            pdf.ln(4)
            pdf.set_font("helvetica", "B", 12)
            pdf.cell(0, 10, "3. ACQUISITION PARAMETERS", ln=1)
            pdf.set_font("helvetica", "", 11)
            row("Safe Mode:", "ENABLED" if d.get("safe_mode") else "DISABLED")
            row("Write-Blocker:", "ENABLED" if writeblock_enabled else "DISABLED")
            row("Format Type:", d.get("format_type"))

            if d.get("safe_mode"):
                pdf.set_font("helvetica", "I", 10)
                pdf.multi_cell(0, 5, "Note: In Safe Mode, unreadable sectors are padded with zeros.")

            pdf.ln(4)
            pdf.set_font("helvetica", "B", 12)
            pdf.cell(0, 10, "4. PRE-ACQUISITION TRIAGE", ln=1)
            pdf.set_font("helvetica", "", 11)
            row("Live Triage Log:", triage_status)

            # Dashboard reference
            if d.get("triage_requested") and d.get("dashboard_path"):
                pdf.ln(4)
                pdf.set_font("helvetica", "B", 12)
                pdf.cell(0, 10, "5. TRIAGE DATA DASHBOARD", ln=1)
                pdf.set_font("helvetica", "", 11)
                pdf.multi_cell(0, 6, f"Interactive HTML Dashboard: {d.get('dashboard_path')}\n\nOpen the HTML file in a web browser to view detailed interactive charts and statistics including process analysis, network connections, and memory usage.")

            pdf.ln(6)
            pdf.set_font("helvetica", "B", 12)
            pdf.cell(0, 10, "EXECUTIVE SUMMARY", ln=1)
            pdf.set_font("helvetica", "", 11)
            pdf.multi_cell(0, 6, summary)

            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            pdf.output(filepath)
