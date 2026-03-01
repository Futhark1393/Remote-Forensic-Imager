#!/usr/bin/env python3
# Author: Kemal Sebzeci
# Description: Interactive CLI wizard for fx-acquire.
# Guides the user through forensic acquisition parameters step by step,
# with color-coded prompts, default values, and real-time validation.

import os
import readline
import sys
from typing import Optional

from fx.core.validation import (
    validate_target_address,
    validate_ssh_username,
    validate_signing_key,
    validate_siem_config,
)

# ── ANSI color helpers ────────────────────────────────────────────────
C0 = "\033[0m"        # reset
BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[1;36m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
RED = "\033[1;31m"
WHITE = "\033[1;37m"
MAGENTA = "\033[1;35m"
UNDERLINE = "\033[4m"


def _banner() -> None:
    from fx import __version__ as ver
    print(f"""
  {CYAN}┌──────────────────────────────────────────┐
  │  ForenXtract (FX) — Interactive Wizard   │
  │  v{ver:<37s}│
  └──────────────────────────────────────────┘{C0}
""")


def _section(title: str, num: int) -> None:
    """Print a numbered section header."""
    print(f"\n  {MAGENTA}━━━ {num}. {title} ━━━{C0}\n")


def _prompt(label: str, default: str = "", required: bool = True,
            validator=None, hint: str = "") -> str:
    """Prompt for a single value with optional default, validation, and hint."""
    suffix = f" [{GREEN}{default}{C0}]" if default else ""
    req_tag = f" {RED}*{C0}" if required and not default else ""
    hint_tag = f"  {DIM}({hint}){C0}" if hint else ""

    while True:
        try:
            raw = input(f"  {WHITE}{label}{C0}{req_tag}{suffix}{hint_tag}: ").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n\n  {RED}Aborted by user.{C0}")
            sys.exit(130)

        value = raw if raw else default

        if required and not value:
            print(f"    {RED}✗ This field is required.{C0}")
            continue

        if validator and value:
            result = validator(value)
            # validator returns (ok, msg) or (ok, msg, extra)
            if isinstance(result, tuple):
                ok = result[0]
                msg = result[1]
            else:
                ok, msg = result, ""
            if not ok:
                print(f"    {RED}✗ {msg}{C0}")
                continue

        return value


def _prompt_bool(label: str, default: bool = True, hint: str = "") -> bool:
    """Prompt for a yes/no answer."""
    yn = "Y/n" if default else "y/N"
    hint_tag = f"  {DIM}({hint}){C0}" if hint else ""

    while True:
        try:
            raw = input(f"  {WHITE}{label}{C0} [{GREEN}{yn}{C0}]{hint_tag}: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print(f"\n\n  {RED}Aborted by user.{C0}")
            sys.exit(130)

        if not raw:
            return default
        if raw in ("y", "yes"):
            return True
        if raw in ("n", "no"):
            return False
        print(f"    {YELLOW}Please enter y or n.{C0}")


def _prompt_choice(label: str, choices: list[str], default: str = "",
                   hint: str = "") -> str:
    """Prompt the user to pick from a numbered list of choices."""
    hint_tag = f"  {DIM}({hint}){C0}" if hint else ""
    print(f"  {WHITE}{label}{C0}{hint_tag}")

    default_idx = None
    for i, c in enumerate(choices, 1):
        marker = ""
        if c == default:
            marker = f" {GREEN}← default{C0}"
            default_idx = i
        print(f"    {CYAN}{i}{C0}) {c}{marker}")

    while True:
        try:
            prompt_str = f"  {WHITE}Choice{C0}"
            if default_idx is not None:
                prompt_str += f" [{GREEN}{default_idx}{C0}]"
            raw = input(f"{prompt_str}: ").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n\n  {RED}Aborted by user.{C0}")
            sys.exit(130)

        if not raw and default_idx is not None:
            return default

        try:
            idx = int(raw)
            if 1 <= idx <= len(choices):
                return choices[idx - 1]
        except ValueError:
            # Allow direct text match
            for c in choices:
                if raw.upper() == c.upper():
                    return c

        print(f"    {YELLOW}Please enter a number between 1 and {len(choices)}.{C0}")


def _prompt_path(label: str, default: str = "", must_exist: bool = False,
                 must_be_dir: bool = False, required: bool = True,
                 hint: str = "") -> str:
    """Prompt for a filesystem path with tab-completion."""
    # Enable readline tab-completion for paths
    old_completer = readline.get_completer()
    old_delims = readline.get_completer_delims()

    def _path_completer(text, state):
        """Complete filesystem paths."""
        if "~" in text:
            text = os.path.expanduser(text)
        dirname = os.path.dirname(text) or "."
        basename = os.path.basename(text)
        try:
            entries = os.listdir(dirname)
        except OSError:
            entries = []
        matches = []
        for e in sorted(entries):
            if e.startswith(basename):
                full = os.path.join(dirname, e)
                if os.path.isdir(full):
                    full += "/"
                matches.append(full)
        return matches[state] if state < len(matches) else None

    readline.set_completer(_path_completer)
    readline.set_completer_delims(" \t\n")
    readline.parse_and_bind("tab: complete")

    def _path_validator(p):
        expanded = os.path.expanduser(p)
        if must_exist and not os.path.exists(expanded):
            return False, f"Path not found: {expanded}"
        if must_be_dir and not os.path.isdir(expanded):
            return False, f"Not a directory: {expanded}"
        return True, ""

    result = _prompt(label, default=default, required=required,
                     validator=_path_validator if (must_exist or must_be_dir) else None,
                     hint=hint)

    # Restore previous readline state
    readline.set_completer(old_completer)
    readline.set_completer_delims(old_delims)

    return os.path.expanduser(result) if result else result


def _prompt_float(label: str, default: float = 0.0, min_val: float = 0.0,
                  hint: str = "") -> float:
    """Prompt for a float value."""
    def _validator(v):
        try:
            f = float(v)
            if f < min_val:
                return False, f"Value must be >= {min_val}"
            return True, ""
        except ValueError:
            return False, "Please enter a valid number."

    raw = _prompt(label, default=str(default), required=False,
                  validator=_validator, hint=hint)
    return float(raw) if raw else default


def _prompt_int(label: str, default: int = 0, min_val: int = 0,
                max_val: int = 65535, hint: str = "") -> int:
    """Prompt for an integer value."""
    def _validator(v):
        try:
            i = int(v)
            if not (min_val <= i <= max_val):
                return False, f"Value must be between {min_val} and {max_val}."
            return True, ""
        except ValueError:
            return False, "Please enter a valid integer."

    raw = _prompt(label, default=str(default), required=False,
                  validator=_validator, hint=hint)
    return int(raw) if raw else default


def run_interactive_wizard() -> dict:
    """Run the full interactive wizard and return a dict of user selections.

    Returns a dict compatible with argparse.Namespace fields.
    """
    _banner()

    # ── 1. Acquisition Mode ──────────────────────────────────────────
    _section("Acquisition Mode", 1)
    mode = _prompt_choice(
        "Which acquisition mode?",
        ["Live (Remote — SSH)", "Dead (Local — attached device/folder)"],
        default="Live (Remote — SSH)",
    )
    is_dead = "Dead" in mode

    params = {
        "dead": is_dead,
        "source": None,
        "ip": None, "user": None, "key": None, "disk": None,
    }

    # ── 2. Target Details ────────────────────────────────────────────
    _section("Target Details", 2)

    if is_dead:
        params["source"] = _prompt_path(
            "Source device or folder",
            hint="e.g., /dev/sdb or /mnt/evidence",
            must_exist=True,
        )
    else:
        params["ip"] = _prompt(
            "Target IP / hostname",
            hint="e.g., 10.0.0.1 or forensic-server.lan",
            validator=validate_target_address,
        )
        params["user"] = _prompt(
            "SSH username",
            default="ubuntu",
            validator=validate_ssh_username,
        )
        params["key"] = _prompt_path(
            "SSH private key (.pem)",
            hint="tab completion supported",
            must_exist=True,
        )
        params["disk"] = _prompt(
            "Target disk on remote host",
            default="/dev/sda",
            hint="e.g., /dev/sda, /dev/nvme0n1",
        )

    # ── 3. Case Information ──────────────────────────────────────────
    _section("Case Information", 3)
    params["case"] = _prompt("Case number", hint="e.g., 2026-001")
    params["examiner"] = _prompt("Examiner name", hint="Lead investigator")
    params["output_dir"] = _prompt_path(
        "Output directory",
        default="./evidence",
        must_be_dir=True,
        hint="Evidence files will be saved here",
    )

    # ── 4. Evidence Format ───────────────────────────────────────────
    _section("Evidence Format", 4)
    format_choices = ["RAW", "RAW+LZ4", "E01", "AFF4"]
    params["format"] = _prompt_choice(
        "Evidence format:",
        format_choices,
        default="RAW",
        hint="RAW=raw disk, LZ4=fast compression, E01=EnCase, AFF4=advanced",
    )

    # E01 metadata
    params["description"] = ""
    params["notes"] = ""
    if params["format"] == "E01":
        print(f"\n  {DIM}E01 header metadata (embedded in the image file):{C0}")
        params["description"] = _prompt(
            "Evidence description",
            required=False,
            hint="e.g., Suspect laptop HDD",
        )
        params["notes"] = _prompt(
            "Examiner notes",
            required=False,
            hint="e.g., Seized under warrant #12345",
        )

    # Split image
    params["split_size"] = ""
    if _prompt_bool("Split image into segments?", default=False,
                    hint="useful for FAT32 / DVD / transport"):
        split_choice = _prompt_choice(
            "Segment size:",
            ["650M (CD)", "2G (FAT32)", "4G (DVD-DL)", "Custom"],
            default="2G (FAT32)",
            hint="choose a preset or enter a custom size",
        )
        _split_map = {
            "650M (CD)": "650M",
            "2G (FAT32)": "2G",
            "4G (DVD-DL)": "4G",
        }
        if split_choice == "Custom":
            params["split_size"] = _prompt(
                "Custom segment size",
                hint="e.g., 500M, 1G, 3500M — minimum 1M",
            )
        else:
            params["split_size"] = _split_map[split_choice]

    # ── 5. Acquisition Options ───────────────────────────────────────
    _section("Acquisition Options", 5)
    params["safe_mode"] = _prompt_bool(
        "Safe Mode?",
        default=True,
        hint="conv=noerror,sync — pads unreadable sectors with zeros",
    )
    params["verify"] = _prompt_bool(
        "Post-acquisition hash verification?",
        default=True,
        hint="compare source SHA-256 to stream hash",
    )

    # Warn about safe mode + verify incompatibility
    if params["safe_mode"] and params["verify"]:
        print(f"\n    {YELLOW}⚠  Safe Mode + Verification: source hash won't match if bad sectors exist.{C0}")
        keep_both = _prompt_bool("Keep both enabled anyway?", default=True)
        if not keep_both:
            disable_verify = _prompt_bool("Disable verification? (No = disable safe mode instead)", default=True)
            if disable_verify:
                params["verify"] = False
            else:
                params["safe_mode"] = False

    params["write_blocker"] = _prompt_bool(
        "Enable software write-blocker?",
        default=False,
        hint="blockdev --setro on target device",
    )

    params["throttle"] = 0.0
    if _prompt_bool("Limit bandwidth?", default=False, hint="useful for remote acquisition"):
        params["throttle"] = _prompt_float("Bandwidth limit (MB/s)", default=50.0, min_val=0.1)

    # ── 6. Live Triage (only for live mode) ──────────────────────────
    params["triage"] = False
    params["triage_network"] = True
    params["triage_processes"] = True
    params["triage_memory"] = False
    params["no_hash_exes"] = False

    if not is_dead:
        _section("Live Triage", 6)
        params["triage"] = _prompt_bool(
            "Run live triage before acquisition?",
            default=False,
            hint="network state, processes, memory — read-only",
        )
        if params["triage"]:
            params["triage_network"] = _prompt_bool("  Collect network state?", default=True)
            params["triage_processes"] = _prompt_bool("  Collect process list?", default=True)
            params["triage_memory"] = _prompt_bool("  Collect memory metadata?", default=False)
            hash_exes = _prompt_bool("  Hash process executables?", default=True)
            params["no_hash_exes"] = not hash_exes

    # ── 7. Advanced Options ──────────────────────────────────────────
    _section("Advanced Options", 7 if not is_dead else 6)

    params["signing_key"] = ""
    if _prompt_bool("Sign audit trail with Ed25519 key?", default=False):
        params["signing_key"] = _prompt_path(
            "Ed25519 private key path",
            must_exist=True,
            hint="Signing key for audit trail integrity",
        )

    # SIEM
    params["siem_host"] = ""
    params["siem_port"] = 514
    params["siem_protocol"] = "UDP"
    params["siem_cef"] = False

    if _prompt_bool("Forward audit logs to SIEM/Syslog?", default=False):
        params["siem_host"] = _prompt("SIEM host", hint="e.g., 10.0.0.100")
        params["siem_port"] = _prompt_int("SIEM port", default=514, min_val=1, max_val=65535)
        params["siem_protocol"] = _prompt_choice("Protocol:", ["UDP", "TCP"], default="UDP")
        params["siem_cef"] = _prompt_bool("Use CEF format?", default=False, hint="instead of RFC 5424")

    # ── Summary ──────────────────────────────────────────────────────
    _print_summary(params)

    confirm = _prompt_bool(f"\n  {GREEN}Proceed with acquisition?{C0}", default=True)
    if not confirm:
        print(f"\n  {YELLOW}Aborted.{C0}\n")
        sys.exit(0)

    # Also print the equivalent CLI command for the user's reference
    _print_equivalent_command(params)

    return params


def _print_summary(p: dict) -> None:
    """Print a formatted summary of all selected options."""
    print(f"""
  {CYAN}╔══════════════════════════════════════════════════╗
  ║           ACQUISITION SUMMARY                    ║
  ╚══════════════════════════════════════════════════╝{C0}
""")
    mode_str = "DEAD (Local)" if p["dead"] else "LIVE (Remote)"
    target_str = p["source"] if p["dead"] else f"{p['user']}@{p['ip']}:{p['disk']}"

    rows = [
        ("Mode",           mode_str),
        ("Target",         target_str),
        ("Case",           p["case"]),
        ("Examiner",       p["examiner"]),
        ("Output",         p["output_dir"]),
        ("Format",         p["format"]),
        ("Split Size",     p["split_size"] if p.get("split_size") else "None"),
        ("Safe Mode",      "✓" if p["safe_mode"] else "✗"),
        ("Verify Hash",    "✓" if p["verify"] else "✗"),
        ("Write-Blocker",  "✓" if p["write_blocker"] else "✗"),
        ("Throttle",       f"{p['throttle']} MB/s" if p["throttle"] > 0 else "Unlimited"),
    ]

    if not p["dead"]:
        rows.append(("Triage", "✓" if p["triage"] else "✗"))

    if p["signing_key"]:
        rows.append(("Signing Key", os.path.basename(p["signing_key"])))
    if p["siem_host"]:
        rows.append(("SIEM", f"{p['siem_host']}:{p['siem_port']} ({p['siem_protocol']})"))

    for label, value in rows:
        print(f"  {WHITE}{label:<16}{C0} {value}")


def _print_equivalent_command(p: dict) -> None:
    """Print the equivalent fx-acquire CLI command for reproducibility."""
    parts = ["fx-acquire"]

    if p["dead"]:
        parts.append("--dead")
        parts.append(f"--source {p['source']}")
    else:
        parts.append(f"--ip {p['ip']}")
        parts.append(f"--user {p['user']}")
        parts.append(f"--key {p['key']}")
        parts.append(f"--disk {p['disk']}")

    parts.append(f"--case {p['case']}")
    parts.append(f"--examiner \"{p['examiner']}\"")
    parts.append(f"--output-dir {p['output_dir']}")
    parts.append(f"--format {p['format']}")

    if p.get("split_size"):
        parts.append(f"--split-size {p['split_size']}")

    if p["verify"]:
        parts.append("--verify")
    if not p["safe_mode"]:
        parts.append("--no-safe-mode")
    if p["write_blocker"]:
        parts.append("--write-blocker")
    if p["throttle"] > 0:
        parts.append(f"--throttle {p['throttle']}")
    if not p["dead"] and p["triage"]:
        parts.append("--triage")
    if p["signing_key"]:
        parts.append(f"--signing-key {p['signing_key']}")
    if p["siem_host"]:
        parts.append(f"--siem-host {p['siem_host']}")
        parts.append(f"--siem-port {p['siem_port']}")
        parts.append(f"--siem-protocol {p['siem_protocol']}")
        if p["siem_cef"]:
            parts.append("--siem-cef")
    if p["format"] == "E01":
        if p.get("description"):
            parts.append(f"--description \"{p['description']}\"")
        if p.get("notes"):
            parts.append(f"--notes \"{p['notes']}\"")

    cmd = " \\\n    ".join(parts)
    print(f"\n  {DIM}Equivalent CLI command (for future reference / scripting):{C0}")
    print(f"  {DIM}{'─' * 50}{C0}")
    print(f"  {CYAN}{cmd}{C0}")
    print(f"  {DIM}{'─' * 50}{C0}\n")
