# Author: Futhark1393
# Description: Syslog / SIEM forwarding handler for ForenXtract (FX) audit events.
# Supports: RFC 5424 syslog (UDP/TCP) + CEF (Common Event Format) output.
# Design: best-effort — connection failures warn but never halt acquisition.

import json
import socket
import sys
import threading
from datetime import datetime, timezone


# RFC 5424 severity mapping
_SEVERITY_MAP = {
    "DEBUG":    7,
    "INFO":     6,
    "NOTICE":   5,
    "WARNING":  4,
    "ERROR":    3,
    "CRITICAL": 2,
    "ALERT":    1,
    "EMERG":    0,
}

_FACILITY_LOCAL0 = 16   # local0 — standard for security tools
_APP_NAME = "fx"


class SyslogHandler:
    """
    Forwards ForenXtract (FX) audit log entries to a remote syslog / SIEM server.

    Protocols: UDP (RFC 5424, fire-and-forget) or TCP (RFC 6587 framing).
    Output format: standard RFC 5424 syslog or CEF (Common Event Format).

    Usage::

        handler = SyslogHandler("10.0.0.5", 514, protocol="UDP")
        handler.emit(log_entry_dict)   # called by ForensicLogger
        handler.close()

    On any network error the handler logs to stderr and continues.
    """

    def __init__(
        self,
        host: str,
        port: int = 514,
        protocol: str = "UDP",
        cef_mode: bool = False,
        timeout: float = 3.0,
    ):
        self.host = host
        self.port = port
        self.protocol = protocol.upper()
        self.cef_mode = cef_mode
        self.timeout = timeout

        self._lock = threading.Lock()
        self._sock: socket.socket | None = None
        self._failed = False   # suppress repeated warnings after first failure

        if self.protocol not in ("UDP", "TCP"):
            raise ValueError(f"Unsupported syslog protocol: {protocol}. Use UDP or TCP.")

        self._connect()

    # ── Connection management ─────────────────────────────────────────

    def _connect(self) -> None:
        try:
            if self.protocol == "UDP":
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._sock.settimeout(self.timeout)
            else:  # TCP
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._sock.settimeout(self.timeout)
                self._sock.connect((self.host, self.port))
            self._failed = False
        except Exception as e:
            self._sock = None
            if not self._failed:
                print(
                    f"WARNING [SyslogHandler]: Cannot connect to {self.host}:{self.port} "
                    f"({self.protocol}): {e} — audit events will not be forwarded.",
                    file=sys.stderr,
                )
            self._failed = True

    # ── Message formatting ────────────────────────────────────────────

    def _format_rfc5424(self, log_entry: dict) -> bytes:
        """Build an RFC 5424 syslog message from a ForensicLogger entry dict."""
        severity = _SEVERITY_MAP.get(log_entry.get("severity", "INFO"), 6)
        priority = _FACILITY_LOCAL0 * 8 + severity
        timestamp = log_entry.get("timestamp", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
        hostname = socket.gethostname()
        proc_id = log_entry.get("session_id", "-")[:36]
        msg_id = log_entry.get("event_type", "-")
        message = log_entry.get("message", "")

        # Structured data (SD) — embed case_no + event_id
        sd = (
            f'[fx@47218 '
            f'case_no="{log_entry.get("case_no", "-")}" '
            f'event_id="{log_entry.get("event_id", "-")}" '
            f'source_module="{log_entry.get("source_module", "-")}"]'
        )

        syslog_msg = (
            f"<{priority}>1 {timestamp} {hostname} {_APP_NAME} "
            f"{proc_id} {msg_id} {sd} {message}"
        )
        return syslog_msg.encode("utf-8")

    def _format_cef(self, log_entry: dict) -> bytes:
        """
        Build a CEF (Common Event Format) message.
        CEF:Version|Device Vendor|Device Product|Device Version|Event Class ID|Name|Severity|Extension
        """
        severity_str = log_entry.get("severity", "INFO")
        cef_severity = {
            "DEBUG": "0", "INFO": "3", "NOTICE": "4",
            "WARNING": "6", "ERROR": "8", "CRITICAL": "10",
        }.get(severity_str, "3")

        event_type = log_entry.get("event_type", "GENERAL")
        message = log_entry.get("message", "").replace("|", "\\|").replace("=", "\\=")

        # Extension fields
        ext_parts = [
            f"cs1Label=case_no cs1={log_entry.get('case_no', '-')}",
            f"cs2Label=examiner cs2={log_entry.get('examiner', '-')}",
            f"cs3Label=session_id cs3={log_entry.get('session_id', '-')}",
            f"cs4Label=event_id cs4={log_entry.get('event_id', '-')}",
            f"cs5Label=source_module cs5={log_entry.get('source_module', '-')}",
            f"msg={message}",
            f"rt={log_entry.get('timestamp', '-')}",
        ]
        extension = " ".join(ext_parts)

        cef_msg = (
            f"CEF:0|Futhark1393|ForenXtract|3.3.0|"
            f"{event_type}|{message}|{cef_severity}|{extension}"
        )
        return cef_msg.encode("utf-8")

    # ── Emit ─────────────────────────────────────────────────────────

    def emit(self, log_entry: dict) -> None:
        """
        Send a ForensicLogger audit entry to the syslog server.
        Best-effort — never raises; failed sends print a single warning.
        """
        with self._lock:
            if self._sock is None:
                self._connect()
                if self._sock is None:
                    return   # still no connection — give up silently

            try:
                payload = (
                    self._format_cef(log_entry)
                    if self.cef_mode
                    else self._format_rfc5424(log_entry)
                )

                if self.protocol == "UDP":
                    self._sock.sendto(payload, (self.host, self.port))
                else:  # TCP — RFC 6587 octet counting
                    framed = f"{len(payload)} ".encode("ascii") + payload
                    self._sock.sendall(framed)

                self._failed = False

            except Exception as e:
                if not self._failed:
                    print(
                        f"WARNING [SyslogHandler]: Failed to forward audit event to "
                        f"{self.host}:{self.port}: {e}",
                        file=sys.stderr,
                    )
                self._failed = True
                # Attempt reconnect next time (for TCP)
                try:
                    self._sock.close()
                except Exception:
                    pass
                self._sock = None

    def close(self) -> None:
        """Close the syslog socket."""
        with self._lock:
            if self._sock is not None:
                try:
                    self._sock.close()
                except Exception:
                    pass
                self._sock = None
