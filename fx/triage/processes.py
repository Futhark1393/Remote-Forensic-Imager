# Author: Futhark1393
# Description: Remote process list collection via SSH (read-only, no target modification).
# Collects: running processes (ps aux), per-process executable hash via /proc/<pid>/exe.

import json
import os
from datetime import datetime, timezone

from fx.core.policy import ssh_exec


class ProcessListCollector:
    """
    Collects the running process list from a remote host over SSH.
    Optionally hashes each process executable via /proc/<pid>/exe.
    All operations are strictly read-only.
    """

    def _parse_ps_output(self, raw: str) -> list[dict]:
        """Parse `ps aux --no-headers` output into a list of process dicts."""
        processes = []
        for line in raw.strip().splitlines():
            parts = line.split(None, 10)
            if len(parts) < 11:
                continue
            processes.append({
                "user":    parts[0],
                "pid":     parts[1],
                "cpu":     parts[2],
                "mem":     parts[3],
                "vsz":     parts[4],
                "rss":     parts[5],
                "tty":     parts[6],
                "stat":    parts[7],
                "start":   parts[8],
                "time":    parts[9],
                "command": parts[10],
            })
        return processes

    def _hash_executables(self, ssh, processes: list[dict], max_hashes: int = 50) -> list[dict]:
        """
        Attempt SHA-256 hashing of /proc/<pid>/exe for each process.
        Caps at max_hashes to avoid excessive runtime.
        Skips kernel threads (empty exe link) silently.
        """
        # Batch the sha256sum calls into a single SSH command for efficiency
        pids = [p["pid"] for p in processes[:max_hashes]]
        if not pids:
            return processes

        # Build a one-liner that tries each pid and outputs "pid:hash" or "pid:ERROR"
        sub_cmds = " ".join(
            f"sha256sum /proc/{pid}/exe 2>/dev/null && echo '__PID__{pid}' || echo '__PID__{pid} ERROR'"
            for pid in pids
        )
        combined_cmd = f"for p in {' '.join(pids)}; do r=$(sha256sum /proc/$p/exe 2>/dev/null); if [ $? -eq 0 ]; then echo \"$p:$(echo $r | cut -d' ' -f1)\"; else echo \"$p:UNAVAILABLE\"; fi; done"

        try:
            out, _, _ = ssh_exec(ssh, combined_cmd)
            hash_map: dict[str, str] = {}
            for line in out.strip().splitlines():
                if ":" in line:
                    pid_part, hash_part = line.split(":", 1)
                    hash_map[pid_part.strip()] = hash_part.strip()

            pid_hash_lookup = {}
            for pid, hash_val in hash_map.items():
                pid_hash_lookup[pid] = hash_val
        except Exception:
            pid_hash_lookup = {}

        for proc in processes:
            proc["exe_sha256"] = pid_hash_lookup.get(proc["pid"], "UNAVAILABLE")

        return processes

    def collect(self, ssh, case_no: str, output_dir: str, hash_exes: bool = True) -> dict:
        """
        Collect process list from remote host. Optionally hash executables.

        Returns a dict with process list and saves TXT + JSON artifacts.
        """
        timestamp_utc = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

        # Collect process list
        raw_ps = ""
        try:
            raw_ps, err, _ = ssh_exec(ssh, "ps aux --no-headers 2>/dev/null")
        except Exception as e:
            raw_ps = f"ERROR: {e}"

        processes = self._parse_ps_output(raw_ps) if raw_ps and not raw_ps.startswith("ERROR") else []

        if hash_exes and processes:
            processes = self._hash_executables(ssh, processes)

        artifact = {
            "collection_timestamp_utc": timestamp_utc,
            "case_no": case_no,
            "process_count": len(processes),
            "processes": processes,
        }

        # ── Write TXT ─────────────────────────────────────────────────
        txt_path = os.path.join(output_dir, f"ProcessList_{case_no}_{timestamp_utc}.txt")
        try:
            with open(txt_path, "w", encoding="utf-8") as f:
                f.write(f"=== ForenXtract (FX) LIVE PROCESS LIST COLLECTION ===\n")
                f.write(f"Case    : {case_no}\n")
                f.write(f"Captured: {timestamp_utc}\n")
                f.write(f"Count   : {len(processes)}\n\n")
                f.write(f"{'USER':<12} {'PID':<8} {'%CPU':<6} {'%MEM':<6} {'STAT':<6} {'SHA-256':<64} COMMAND\n")
                f.write("-" * 120 + "\n")
                for p in processes:
                    f.write(
                        f"{p['user']:<12} {p['pid']:<8} {p['cpu']:<6} {p['mem']:<6} "
                        f"{p['stat']:<6} {p.get('exe_sha256', 'N/A'):<64} {p['command']}\n"
                    )
        except OSError:
            txt_path = None

        # ── Write JSON ────────────────────────────────────────────────
        json_path = os.path.join(output_dir, f"ProcessList_{case_no}_{timestamp_utc}.json")
        try:
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(artifact, f, indent=2, ensure_ascii=False)
        except OSError:
            json_path = None

        artifact["txt_path"] = txt_path
        artifact["json_path"] = json_path
        return artifact
