# Author: Futhark1393
# Description: Audit trail hash-chain verifier.
# Verifies the cryptographic integrity of JSONL forensic audit logs.

import os
import json
import hashlib


class AuditChainVerifier:
    @staticmethod
    def verify_chain(filepath: str) -> tuple[bool, str]:
        if not os.path.exists(filepath):
            return False, "File not found."

        current_prev_hash = hashlib.sha256(b"FORENSIC_GENESIS_BLOCK").hexdigest()
        line_number = 0

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                for line in f:
                    line_number += 1
                    if not line.strip():
                        continue

                    entry = json.loads(line)
                    entry_copy = dict(entry)

                    claimed_prev = entry_copy.get("prev_hash")
                    claimed_entry = entry_copy.pop("entry_hash", None)

                    if not claimed_entry:
                        return False, (
                            f"Tampering detected: 'entry_hash' missing at line {line_number}."
                        )

                    if claimed_prev != current_prev_hash:
                        return (
                            False,
                            f"Chain broken at line {line_number}. Expected prev: {current_prev_hash}, found: {claimed_prev}",
                        )

                    reconstructed_json = json.dumps(entry_copy, sort_keys=True)
                    reconstructed_hash = hashlib.sha256(reconstructed_json.encode("utf-8")).hexdigest()

                    if reconstructed_hash != claimed_entry:
                        return False, f"Entry manipulation detected at line {line_number}. Hash mismatch."

                    current_prev_hash = claimed_entry

            return True, f"Chain verified successfully. {line_number} cryptographic records intact."
        except Exception as e:
            return False, f"Verification error at line {line_number}: {str(e)}"
