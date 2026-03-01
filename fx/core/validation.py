# Author: Kemal Sebzeci
# Description: Shared validation helpers extracted from GUI business logic.
# Used by both GUI and CLI to enforce forensic input rules consistently.

import os
import re


def validate_target_address(address: str) -> tuple[bool, str]:
    """Validate a target address (IPv4, IPv6, or hostname).

    Returns (ok, error_message). If ok is True, error_message is empty.
    """
    if not address:
        return False, "Target address is required."

    ipv4_re = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    ipv6_re = r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$"
    hostname_re = r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z]{2,}$"

    if re.match(ipv4_re, address) or re.match(ipv6_re, address) or re.match(hostname_re, address):
        return True, ""
    return False, "Invalid target address. Enter a valid IPv4, IPv6, or hostname."


def validate_ssh_username(user: str) -> tuple[bool, str]:
    """Validate an SSH username.

    Returns (ok, error_message).
    """
    if not user:
        return False, "SSH username is required."
    if not re.match(r"^[a-z_][a-z0-9_-]{0,31}$", user):
        return False, "Invalid SSH username format."
    return True, ""


def validate_signing_key(path: str) -> tuple[bool, str]:
    """Validate that a signing key file exists and is readable.

    Returns (ok, error_message). If path is empty, returns True (optional).
    """
    if not path:
        return True, ""  # signing key is optional
    if not os.path.isfile(path):
        return False, f"Signing key not found: {path}"
    if not os.access(path, os.R_OK):
        return False, f"Signing key is not readable: {path}"
    return True, ""


def validate_siem_config(
    enabled: bool, host: str, port_str: str
) -> tuple[bool, str, int]:
    """Validate SIEM / Syslog configuration.

    Returns (ok, error_message, parsed_port).
    """
    if not enabled:
        return True, "", 514
    if not host:
        return False, "SIEM host is required when SIEM forwarding is enabled.", 0
    try:
        port = int(port_str) if port_str else 514
    except ValueError:
        return False, "SIEM port must be a number.", 0
    if not (1 <= port <= 65535):
        return False, "SIEM port must be between 1 and 65535.", 0
    return True, "", port


def format_bytes(size_bytes: int) -> str:
    """Format a byte count into a human-readable string (e.g., '500.00 GB')."""
    if size_bytes < 0:
        return "Unknown"
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if abs(size_bytes) < 1024.0 or unit == "PB":
            if unit == "B":
                return f"{size_bytes} {unit}"
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"


def build_evidence_filename(
    output_dir: str, case_no: str, format_type: str, timestamp_str: str
) -> str:
    """Build the full evidence output file path.

    Creates the evidence subdirectory if it doesn't exist.
    """
    _FORMAT_EXT = {
        "RAW": ".raw",
        "RAW+LZ4": ".raw.lz4",
        "E01": ".E01",
        "AFF4": ".aff4",
    }
    evidence_dir = os.path.join(output_dir, "evidence")
    os.makedirs(evidence_dir, exist_ok=True)
    ext = _FORMAT_EXT.get(format_type, ".raw")
    return os.path.join(evidence_dir, f"evidence_{case_no}_{timestamp_str}{ext}")
