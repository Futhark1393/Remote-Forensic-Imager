#!/usr/bin/env python3
# Author: Kemal Sebzeci
# Description: CLI-only forensic acquisition — no GUI, no Qt dependency.
# Supports both Live (Remote/SSH) and Dead (Local) acquisition modes.
#
# Live:  fx-acquire --ip 10.0.0.1 --user ubuntu --key ~/.ssh/key.pem \
#                   --disk /dev/sda --output-dir ./evidence \
#                   --case 2026-001 --examiner "Investigator"
#
# Dead:  fx-acquire --dead --source /dev/sdb --output-dir ./evidence \
#                   --case 2026-001 --examiner "Investigator"

import argparse
import os
import sys
import time
from datetime import datetime, timezone

from fx.core.session import Session, SessionStateError
from fx.core.acquisition.base import AcquisitionEngine, AcquisitionError
from fx.core.acquisition.dead import DeadAcquisitionEngine, DeadAcquisitionError
from fx.audit.logger import ForensicLogger, ForensicLoggerError
from fx.report.report_engine import ReportEngine


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="fx-acquire",
        description="ForenXtract (FX) — headless CLI acquisition (live & dead modes).",
    )

    # Mode
    p.add_argument("--dead", action="store_true", help="Dead (local) acquisition mode — image a locally attached device")
    p.add_argument("--source", help="Source device or file for dead acquisition (e.g., /dev/sdb, image.raw)")

    # Live-mode required (not needed for dead)
    p.add_argument("--ip", help="Target IP address (live mode)")
    p.add_argument("--user", help="SSH username (live mode)")
    p.add_argument("--key", help="Path to SSH private key .pem (live mode)")
    p.add_argument("--disk", help="Target block device on remote host (live mode, e.g., /dev/sda)")

    # Shared required
    p.add_argument("--output-dir", required=True, help="Evidence output directory")
    p.add_argument("--case", required=True, help="Case number")
    p.add_argument("--examiner", required=True, help="Examiner name")

    # Optional — acquisition
    p.add_argument("--format", choices=["RAW", "RAW+LZ4", "E01", "AFF4"], default="RAW", help="Evidence format (default: RAW)")
    p.add_argument("--verify", action="store_true", help="Post-acquisition remote SHA-256 verification")
    p.add_argument("--safe-mode", action="store_true", default=True, help="Safe mode: conv=noerror,sync (default: on)")
    p.add_argument("--no-safe-mode", action="store_true", help="Disable safe mode")
    p.add_argument("--write-blocker", action="store_true", help="Apply software write-blocker")
    p.add_argument("--throttle", type=float, default=0.0, help="Bandwidth limit in MB/s (0 = unlimited)")
    p.add_argument("--signing-key", help="Path to Ed25519 private key for audit trail signing")

    # Optional — triage
    p.add_argument("--triage", action="store_true", help="Run live triage (network + processes) before acquisition")
    p.add_argument("--triage-network", action="store_true", default=True, help="Triage: collect network state (default: on with --triage)")
    p.add_argument("--no-triage-network", action="store_true", help="Triage: skip network state collection")
    p.add_argument("--triage-processes", action="store_true", default=True, help="Triage: collect process list (default: on with --triage)")
    p.add_argument("--no-triage-processes", action="store_true", help="Triage: skip process list collection")
    p.add_argument("--triage-memory", action="store_true", help="Triage: collect memory metadata (/proc/meminfo, modules)")
    p.add_argument("--no-hash-exes", action="store_true", help="Triage: skip per-process SHA-256 exe hashing")

    # Optional — SIEM / Syslog
    p.add_argument("--siem-host", help="Syslog/SIEM server hostname or IP")
    p.add_argument("--siem-port", type=int, default=514, help="Syslog/SIEM server port (default: 514)")
    p.add_argument("--siem-protocol", choices=["UDP", "TCP"], default="UDP", help="Syslog protocol (default: UDP)")
    p.add_argument("--siem-cef", action="store_true", help="Use CEF output format instead of RFC 5424")

    return p.parse_args()


def cli_progress(data: dict) -> None:
    """Print acquisition progress to terminal."""
    pct = data.get("percentage", 0)
    speed = data.get("speed_mb_s", 0)
    eta = data.get("eta", "")
    md5 = data.get("md5_current", "")
    bytes_read = data.get("bytes_read", 0)

    mb_read = bytes_read / (1024 * 1024)
    bar_len = 30
    filled = int(bar_len * pct / 100)
    bar = "█" * filled + "░" * (bar_len - filled)

    line = f"\r  [{bar}] {pct:3d}% | {mb_read:,.0f} MB | {speed:.1f} MB/s | ETA: {eta}"
    sys.stdout.write(line)
    sys.stdout.flush()


def main() -> int:
    args = parse_args()

    # ── Mode validation ──────────────────────────────────────────────
    is_dead = args.dead

    if is_dead:
        if not args.source:
            print("ERROR: --source is required for dead acquisition mode.", file=sys.stderr)
            return 1
        if not os.path.exists(args.source):
            print(f"ERROR: Source not found: {args.source}", file=sys.stderr)
            return 1
    else:
        for name in ("ip", "user", "key", "disk"):
            if not getattr(args, name, None):
                print(f"ERROR: --{name} is required for live acquisition mode.", file=sys.stderr)
                return 1

    safe_mode = True
    if args.no_safe_mode:
        safe_mode = False

    triage_network   = not args.no_triage_network
    triage_processes = not args.no_triage_processes
    triage_memory    = args.triage_memory
    triage_hash_exes = not args.no_hash_exes

    output_dir = os.path.abspath(args.output_dir)
    if not os.path.isdir(output_dir):
        print(f"ERROR: Output directory does not exist: {output_dir}", file=sys.stderr)
        return 1

    # ── Optional SIEM / Syslog handler ───────────────────────────────
    syslog_handler = None
    if args.siem_host:
        from fx.audit.syslog_handler import SyslogHandler
        syslog_handler = SyslogHandler(
            host=args.siem_host,
            port=args.siem_port,
            protocol=args.siem_protocol,
            cef_mode=args.siem_cef,
        )

    # ── Session ──────────────────────────────────────────────────────
    session = Session()

    # ── Logger ───────────────────────────────────────────────────────
    logger = ForensicLogger(syslog_handler=syslog_handler)
    try:
        logger.set_context(args.case, args.examiner, output_dir)
    except ForensicLoggerError as e:
        print(f"ERROR: Audit trail initialization failed: {e}", file=sys.stderr)
        return 1

    case_no = logger.case_no
    examiner = logger.examiner

    try:
        session.bind_context(case_no, examiner, output_dir)
    except SessionStateError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    # ── Banner ───────────────────────────────────────────────────────
    C0 = "\033[0m"       # reset
    C1 = "\033[1;36m"    # bold cyan
    C2 = "\033[0;36m"    # cyan
    C3 = "\033[1;37m"    # bold white
    DIM = "\033[2m"      # dim

    logo = [
        f"{C1} ███████╗  ██╗  ██╗",
        f"{C1} ██╔════╝  ╚██╗██╔╝",
        f"{C1} █████╗     ╚███╔╝",
        f"{C2} ██╔══╝     ██╔██╗",
        f"{C2} ██║       ██╔╝ ██╗",
        f"{C2} ╚═╝       ╚═╝  ╚═╝",
    ]

    info = [
        f"{C3}ForenXtract{C0}",
        f"{C3}v3.4.0{C0}",
        f"{DIM}{'Dead (Local) Acquisition' if is_dead else 'Remote Forensic Acquisition'}{C0}",
        "",
        f"{C3}Session{C0}   {DIM}{logger.session_id}{C0}",
        f"{C3}Case{C0}      {case_no}",
        f"{C3}Examiner{C0}  {examiner}",
        f"{C3}Mode{C0}      {'DEAD (Local)' if is_dead else 'LIVE (Remote)'}",
        f"{C3}Target{C0}    {args.source if is_dead else f'{args.user}@{args.ip}:{args.disk}'}",
        f"{C3}Format{C0}    {args.format}",
        f"{C3}Output{C0}    {output_dir}",
        f"{C3}Verify{C0}    {'✓' if args.verify else '✗'}  {C3}Safe{C0} {'✓' if safe_mode else '✗'}  {C3}WBlock{C0} {'✓' if args.write_blocker else '✗'}",
        f"{C3}Triage{C0}    {'✓' if (not is_dead and args.triage) else '✗'}{' (N/A for dead)' if is_dead else ''}  {C3}SIEM{C0} {'✓ ' + args.siem_host if args.siem_host else '✗'}",
    ]

    print()
    for i in range(max(len(logo), len(info))):
        left = logo[i] if i < len(logo) else ""
        right = f"   {info[i]}" if i < len(info) else ""
        print(f"  {left}{right}")
    print()

    logger.log("CLI acquisition initiated.", "INFO", "ACQUISITION_START", source_module="cli")
    logger.log(
        f"Mode: {'DEAD' if is_dead else 'LIVE'} | "
        f"Target: {args.source if is_dead else f'{args.user}@{args.ip}:{args.disk}'} | "
        f"Format: {args.format} | Verify: {args.verify} | Safe: {safe_mode} | WriteBlock: {args.write_blocker}",
        "INFO", "ACQUISITION_PARAMS", source_module="cli",
    )

    # ── Build output filename ────────────────────────────────────────
    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    base_filename = os.path.join(output_dir, f"evidence_{case_no}_{timestamp_str}")
    _CLI_FORMAT_EXT = {"RAW": ".raw", "RAW+LZ4": ".raw.lz4", "E01": ".E01", "AFF4": ".aff4"}
    ext = _CLI_FORMAT_EXT.get(args.format, ".raw")
    target_filename = base_filename + ext
    # pyewf/libewf determine segment type from extension (.E01/.E02...).
    # Always pass a concrete first segment filename for E01.
    output_file = target_filename

    # ── Acquire ──────────────────────────────────────────────────────
    try:
        session.begin_acquisition()
    except SessionStateError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    start_time = datetime.now(timezone.utc)
    print(f"\n  Starting {'dead' if is_dead else 'live'} acquisition at {start_time.strftime('%H:%M:%S UTC')}...\n")

    if is_dead:
        engine = DeadAcquisitionEngine(
            source_path=args.source,
            output_file=output_file,
            format_type=args.format,
            case_no=case_no,
            examiner=examiner,
            throttle_limit=args.throttle,
            safe_mode=safe_mode,
            verify_hash=args.verify,
            write_blocker=args.write_blocker,
            on_progress=cli_progress,
        )
    else:
        engine = AcquisitionEngine(
            ip=args.ip,
            user=args.user,
            key_path=args.key,
            disk=args.disk,
            output_file=output_file,
            format_type=args.format,
            case_no=case_no,
            examiner=examiner,
            throttle_limit=args.throttle,
            safe_mode=safe_mode,
            run_triage=args.triage,
            triage_network=triage_network,
            triage_processes=triage_processes,
            triage_memory=triage_memory,
            triage_hash_exes=triage_hash_exes,
            output_dir=output_dir,
            verify_hash=args.verify,
            write_blocker=args.write_blocker,
            on_progress=cli_progress,
        )

    try:
        result = engine.run()
    except (AcquisitionError, DeadAcquisitionError) as e:
        print(f"\n\n  ACQUISITION FAILED: {e}\n", file=sys.stderr)
        logger.log(f"Acquisition failed: {e}", "ERROR", "ACQUISITION_FAILED", source_module="cli")
        return 1

    # ── Results ──────────────────────────────────────────────────────
    print("\n\n" + "=" * 60)
    print("  ACQUISITION COMPLETE")
    print("=" * 60)

    sha256 = result["sha256_final"]
    md5 = result["md5_final"]
    total_bytes = result["total_bytes"]
    remote_sha256 = result.get("remote_sha256", result.get("source_sha256", "SKIPPED"))
    hash_match = result.get("hash_match")

    duration = str(datetime.now(timezone.utc) - start_time).split(".")[0]

    print(f"  Duration     : {duration}")
    print(f"  Total Bytes  : {total_bytes:,}")
    print(f"  Local SHA-256: {sha256}")
    print(f"  Local MD5    : {md5}")

    logger.log("Acquisition completed.", "INFO", "INTEGRITY_LOCAL", source_module="cli", hash_context={
        "local_sha256": sha256,
        "local_md5": md5,
        "remote_sha256": None if remote_sha256 == "SKIPPED" else remote_sha256,
        "verified": hash_match,
    })

    # Verification
    if args.verify:
        try:
            session.begin_verification()
        except SessionStateError:
            pass
        print(f"  Remote SHA256: {remote_sha256}")
        if hash_match is True:
            print("  Verification : ✅ MATCH")
            logger.log("Source and local hashes MATCH.", "INFO", "INTEGRITY_VERIFIED", source_module="cli")
        elif hash_match is False:
            print("  Verification : ❌ MISMATCH")
            logger.log("Source and local hashes MISMATCH.", "ERROR", "INTEGRITY_MISMATCH", source_module="cli")
        else:
            print("  Verification : ⚠️  UNKNOWN")

    # ── Seal ─────────────────────────────────────────────────────────
    try:
        session.seal()
    except SessionStateError:
        pass

    signing_key = getattr(args, "signing_key", None)
    audit_hash, chattr_success = logger.seal_audit_trail(signing_key_path=signing_key)

    print(f"\n  Audit Hash   : {audit_hash}")
    print(f"  Kernel Seal  : {'SUCCESS' if chattr_success else 'FAILED (no sudo)'}")

    # ── Reports ──────────────────────────────────────────────────────
    txt_path = os.path.join(output_dir, f"Report_{case_no}_{timestamp_str}.txt")
    pdf_path = os.path.join(output_dir, f"Report_{case_no}_{timestamp_str}.pdf")

    report_data = {
        "case_no": case_no,
        "examiner": examiner,
        "acquisition_mode": "DEAD (Local)" if is_dead else "LIVE (Remote)",
        "ip": args.source if is_dead else args.ip,
        "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "duration": duration,
        "format_type": args.format,
        "target_filename": target_filename,
        "triage_requested": (not is_dead) and args.triage,
        "writeblock_requested": args.write_blocker,
        "throttle_enabled": args.throttle > 0,
        "throttle_val": str(args.throttle),
        "safe_mode": safe_mode,
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
    print(f"\n  Reports saved to: {output_dir}")

    try:
        session.finalize()
    except SessionStateError:
        pass

    # ── Cleanup SIEM handler ────────────────────────────────────
    if syslog_handler is not None:
        syslog_handler.close()

    print("=" * 60)
    print("  DONE — Audit trail sealed.")
    print("=" * 60)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
