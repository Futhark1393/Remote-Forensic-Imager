#!/usr/bin/env python3
# Author: Futhark1393
# Description: fx-verify — standalone CLI for forensic audit trail verification.
#              Verifies JSONL hash chain integrity and optional Ed25519 signature.
#
# Usage:
#   fx-verify AuditTrail_CASE_SESSION.jsonl
#   fx-verify AuditTrail_CASE_SESSION.jsonl --pubkey fx_signing.pub
#   fx-verify AuditTrail_CASE_SESSION.jsonl --json
#   fx-verify AuditTrail_CASE_SESSION.jsonl --quiet

import argparse
import json
import os
import sys


def _print_banner() -> None:
    C1 = "\033[1;35m"
    C2 = "\033[0;35m"
    DIM = "\033[2m"
    C0 = "\033[0m"

    logo = [
        f"{C1} ███████╗  ██╗  ██╗",
        f"{C1} ██╔════╝  ╚██╗██╔╝",
        f"{C1} █████╗     ╚███╔╝",
        f"{C2} ██╔══╝     ██╔██╗",
        f"{C2} ██║       ██╔╝ ██╗",
        f"{C2} ╚═╝       ╚═╝  ╚═╝",
    ]

    info = [
        f"{C1}ForenXtract{C0}",
        f"{C1}v3.4.0{C0}",
        f"{DIM}Audit Trail Verifier{C0}",
    ]

    print()
    for i in range(max(len(logo), len(info))):
        left = logo[i] if i < len(logo) else " " * 24
        right = f"   {info[i]}" if i < len(info) else ""
        print(f"  {left}{C0}{right}")
    print()


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="fx-verify",
        description="Verify ForenXtract JSONL audit chain integrity (prev_hash → entry_hash).",
    )
    p.add_argument(
        "audit_file",
        help="Path to AuditTrail_*.jsonl file",
    )
    p.add_argument(
        "--pubkey",
        help="Path to Ed25519 public key (.pub) for signature verification.",
    )
    p.add_argument(
        "--quiet",
        action="store_true",
        help="Only print PASS/FAIL (no extra text or banner).",
    )
    p.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="Output results as JSON (machine-readable). Implies --quiet banner.",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()

    if not args.quiet and not args.json_output:
        _print_banner()

    path = args.audit_file

    result = {
        "audit_file": path,
        "chain": {"ok": False, "message": ""},
        "signature": None,
        "overall": "FAIL",
    }

    if not os.path.exists(path):
        msg = f"file not found: {path}"
        if args.json_output:
            result["chain"]["message"] = msg
            print(json.dumps(result, indent=2))
        elif args.quiet:
            print("FAIL")
        else:
            print(f"FAIL: {msg}")
        return 2

    # ── Chain verification ────────────────────────────────────────────
    from fx.audit.verify import AuditChainVerifier
    try:
        chain_ok, chain_msg = AuditChainVerifier.verify_chain(path)
    except Exception as e:
        msg = f"verifier crashed: {e}"
        if args.json_output:
            result["chain"]["message"] = msg
            print(json.dumps(result, indent=2))
        elif args.quiet:
            print("FAIL")
        else:
            print(f"ERROR: {msg}")
        return 1

    result["chain"] = {"ok": chain_ok, "message": chain_msg}

    if not chain_ok:
        if args.json_output:
            print(json.dumps(result, indent=2))
        elif args.quiet:
            print("FAIL")
        else:
            print(f"  ❌ CHAIN FAIL: {chain_msg}")
        return 2

    if not args.quiet and not args.json_output:
        print(f"  ✅ CHAIN PASS: {chain_msg}")

    # ── Signature verification (optional) ────────────────────────────
    if args.pubkey:
        sig_path = path + ".sig"
        try:
            from fx.audit.signing import verify_audit_signature
            sig_ok, sig_msg = verify_audit_signature(path, sig_path, args.pubkey)
        except ImportError:
            sig_ok, sig_msg = False, "cryptography library not installed (pip install cryptography)"
        except Exception as e:
            sig_ok, sig_msg = False, f"signature verifier crashed: {e}"

        result["signature"] = {"ok": sig_ok, "message": sig_msg}

        if not sig_ok:
            if args.json_output:
                print(json.dumps(result, indent=2))
            elif args.quiet:
                print("FAIL")
            else:
                print(f"  ❌ SIG  FAIL: {sig_msg}")
            return 2

        if not args.quiet and not args.json_output:
            print(f"  ✅ SIG  PASS: {sig_msg}")

    result["overall"] = "PASS"

    if args.json_output:
        print(json.dumps(result, indent=2))
    elif args.quiet:
        print("PASS")
    else:
        print()
        print("  ══════════════════════════════")
        print("  RESULT: PASS — Audit trail integrity verified.")
        print("  ══════════════════════════════")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
