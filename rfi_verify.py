#!/usr/bin/env python3
# Author: Futhark1393
# Description: CLI verifier for RFI forensic audit trails (JSONL hash chain)
#              and optional Ed25519 digital signature verification.

import argparse
import os
import sys

from rfi.audit.verify import AuditChainVerifier


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="rfi-verify",
        description="Verify RFI JSONL audit chain integrity (prev_hash -> entry_hash).",
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
        help="Only print PASS/FAIL (no extra text).",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()
    path = args.audit_file

    if not os.path.exists(path):
        if args.quiet:
            print("FAIL")
        else:
            print(f"FAIL: file not found: {path}")
        return 2

    # ── Chain verification ───────────────────────────────────────────
    try:
        ok, message = AuditChainVerifier.verify_chain(path)
    except Exception as e:
        if args.quiet:
            print("FAIL")
        else:
            print(f"ERROR: verifier crashed: {e}")
        return 1

    if not ok:
        if args.quiet:
            print("FAIL")
        else:
            print(f"FAIL: {message}")
        return 2

    if not args.quiet:
        print(f"PASS: {message}")

    # ── Signature verification (optional) ────────────────────────────
    if args.pubkey:
        sig_path = path + ".sig"
        try:
            from rfi.audit.signing import verify_audit_signature
            sig_ok, sig_msg = verify_audit_signature(path, sig_path, args.pubkey)
        except ImportError:
            if args.quiet:
                print("FAIL")
            else:
                print("FAIL: cryptography library not installed (pip install cryptography)")
            return 1
        except Exception as e:
            if args.quiet:
                print("FAIL")
            else:
                print(f"ERROR: signature verifier crashed: {e}")
            return 1

        if sig_ok:
            if not args.quiet:
                print(f"SIG PASS: {sig_msg}")
        else:
            if args.quiet:
                print("FAIL")
            else:
                print(f"SIG FAIL: {sig_msg}")
            return 2

    if args.quiet:
        print("PASS")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
