# Author: Futhark1393
# Description: Live network state collection via SSH (read-only, no target modification).
# Collects: active connections, ARP table, routing table, neighbour table, DNS config.

import json
import os
from datetime import datetime, timezone

from fx.core.policy import ssh_exec


class NetworkStateCollector:
    """
    Collects network state from a remote host over SSH.
    All operations are strictly read-only — nothing is written to the target.
    """

    COMMANDS = {
        "connections": "ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null || echo 'UNAVAILABLE'",
        "arp_table":   "arp -n 2>/dev/null || ip neigh show 2>/dev/null || echo 'UNAVAILABLE'",
        "routes":      "ip route show 2>/dev/null || route -n 2>/dev/null || echo 'UNAVAILABLE'",
        "neighbours":  "ip neigh show 2>/dev/null || echo 'UNAVAILABLE'",
        "dns_config":  "cat /etc/resolv.conf 2>/dev/null || echo 'UNAVAILABLE'",
        "interfaces":  "ip addr show 2>/dev/null || ifconfig 2>/dev/null || echo 'UNAVAILABLE'",
        "hostname":    "hostname -f 2>/dev/null || hostname 2>/dev/null || echo 'UNAVAILABLE'",
    }

    def collect(self, ssh, case_no: str, output_dir: str) -> dict:
        """
        Run all read-only network commands on the remote host.

        Returns a dict with all collected data and saves TXT + JSON artifacts
        to output_dir.
        """
        timestamp_utc = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        results: dict[str, str] = {}

        for key, cmd in self.COMMANDS.items():
            try:
                out, err, _ = ssh_exec(ssh, cmd)
                results[key] = out.strip() if out.strip() else f"(empty — stderr: {err.strip()})"
            except Exception as e:
                results[key] = f"ERROR: {e}"

        artifact = {
            "collection_timestamp_utc": timestamp_utc,
            "case_no": case_no,
            "data": results,
        }

        # ── Write TXT ─────────────────────────────────────────────────
        txt_path = os.path.join(output_dir, f"NetworkState_{case_no}_{timestamp_utc}.txt")
        try:
            with open(txt_path, "w", encoding="utf-8") as f:
                f.write(f"=== ForenXtract (FX) LIVE NETWORK STATE COLLECTION ===\n")
                f.write(f"Case    : {case_no}\n")
                f.write(f"Captured: {timestamp_utc}\n\n")
                for section, content in results.items():
                    f.write(f"--- {section.upper().replace('_', ' ')} ---\n")
                    f.write(content + "\n\n")
        except OSError:
            txt_path = None

        # ── Write JSON ────────────────────────────────────────────────
        json_path = os.path.join(output_dir, f"NetworkState_{case_no}_{timestamp_utc}.json")
        try:
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(artifact, f, indent=2, ensure_ascii=False)
        except OSError:
            json_path = None

        artifact["txt_path"] = txt_path
        artifact["json_path"] = json_path
        return artifact
