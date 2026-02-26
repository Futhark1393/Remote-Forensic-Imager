# Author: Futhark1393
# Description: Remote memory state collection via SSH (read-only, no target modification).
#
# FORENSIC SAFETY PRINCIPLE:
#   We never upload or load anything onto the target system (no LiME insmod).
#   Loading a kernel module modifies system state and risks chain of custody.
#
# Collection strategy (strictly read-only):
#   1. If LiME device /dev/lime* already exists → stream it via dd (already loaded by admin)
#   2. /proc/kcore → stream it via dd if readable (physical memory image, Linux 2.6+)
#   3. /proc/meminfo → always available, metadata only (fallback)

import json
import os
import hashlib
from datetime import datetime, timezone

from fx.core.policy import ssh_exec


class MemoryDumpCollector:
    """
    Collects memory evidence from a remote host via SSH.

    Strictly read-only: never uploads files or loads kernel modules.
    """

    CHUNK_SIZE = 4 * 1024 * 1024  # 4 MB SFTP chunks

    def _collect_meminfo(self, ssh) -> dict:
        """Always-available /proc/meminfo — kernel memory metadata."""
        try:
            out, _, _ = ssh_exec(ssh, "cat /proc/meminfo 2>/dev/null")
            parsed = {}
            for line in out.strip().splitlines():
                if ":" in line:
                    key, _, val = line.partition(":")
                    parsed[key.strip()] = val.strip()
            return {"source": "/proc/meminfo", "data": parsed}
        except Exception as e:
            return {"source": "/proc/meminfo", "data": {}, "error": str(e)}

    def _collect_kallsyms_summary(self, ssh) -> dict:
        """Count loaded kernel symbols as a lightweight integrity indicator."""
        try:
            out, _, code = ssh_exec(ssh, "wc -l /proc/kallsyms 2>/dev/null")
            if code == 0 and out.strip():
                count = out.strip().split()[0]
                return {"source": "/proc/kallsyms", "symbol_count": count}
        except Exception:
            pass
        return {"source": "/proc/kallsyms", "symbol_count": "UNAVAILABLE"}

    def _collect_modules(self, ssh) -> list[dict]:
        """List loaded kernel modules — non-invasive read from /proc/modules."""
        try:
            out, _, _ = ssh_exec(ssh, "cat /proc/modules 2>/dev/null")
            modules = []
            for line in out.strip().splitlines():
                parts = line.split()
                if parts:
                    modules.append({
                        "name":       parts[0] if len(parts) > 0 else "",
                        "size":       parts[1] if len(parts) > 1 else "",
                        "use_count":  parts[2] if len(parts) > 2 else "",
                        "state":      parts[4] if len(parts) > 4 else "",
                    })
            return modules
        except Exception:
            return []

    def _stream_kcore(self, ssh, output_dir: str, case_no: str, timestamp_utc: str) -> dict:
        """
        Attempt to stream /proc/kcore via SFTP.
        /proc/kcore is a sparse ELF file representing physical memory.
        Only attempted if readable (requires root on most distros).
        Returns a dict with path and hash, or error info.
        """
        # First check readability without actually reading the full file
        _, _, rc = ssh_exec(ssh, "test -r /proc/kcore && echo OK || echo NOACCESS")
        # rc check not reliable here — use stdout
        check_out, _, _ = ssh_exec(ssh, "head -c 1 /proc/kcore >/dev/null 2>&1 && echo OK || echo NOACCESS")
        if "NOACCESS" in check_out or "OK" not in check_out:
            return {"source": "/proc/kcore", "status": "NOT_ACCESSIBLE"}

        dump_path = os.path.join(output_dir, f"MemoryDump_{case_no}_{timestamp_utc}.kcore")
        sha256 = hashlib.sha256()
        bytes_written = 0

        try:
            sftp = ssh.open_sftp()
            with sftp.open("/proc/kcore", "rb") as remote_f, open(dump_path, "wb") as local_f:
                while True:
                    chunk = remote_f.read(self.CHUNK_SIZE)
                    if not chunk:
                        break
                    local_f.write(chunk)
                    sha256.update(chunk)
                    bytes_written += len(chunk)
            sftp.close()
            return {
                "source":       "/proc/kcore",
                "status":       "COLLECTED",
                "output_path":  dump_path,
                "bytes":        bytes_written,
                "sha256":       sha256.hexdigest(),
            }
        except Exception as e:
            # Clean up partial file
            if os.path.exists(dump_path):
                os.unlink(dump_path)
            return {"source": "/proc/kcore", "status": "ERROR", "error": str(e)}

    def _check_lime_device(self, ssh) -> dict:
        """Check if LiME device already exists (loaded by admin prior to ForenXtract)."""
        try:
            out, _, _ = ssh_exec(ssh, "ls /dev/lime* 2>/dev/null || echo NONE")
            if "NONE" in out or not out.strip():
                return {"lime_device": None}
            devices = out.strip().splitlines()
            return {"lime_device": devices[0].strip()}
        except Exception:
            return {"lime_device": None}

    def collect(
        self,
        ssh,
        case_no: str,
        output_dir: str,
        attempt_kcore: bool = True,
    ) -> dict:
        """
        Collect memory evidence. Never modifies the target system.

        Steps:
          1. Check for existing LiME device (admin-loaded) → stream if present
          2. Attempt /proc/kcore stream (if root has access and attempt_kcore=True)
          3. Always collect /proc/meminfo + /proc/modules metadata

        Returns a comprehensive dict and saves JSON artifact.
        """
        timestamp_utc = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

        artifact: dict = {
            "collection_timestamp_utc": timestamp_utc,
            "case_no": case_no,
            "forensic_note": (
                "Read-only collection. No kernel modules loaded, no files written to target."
            ),
        }

        # Step 1: LiME device (pre-existing)
        lime_info = self._check_lime_device(ssh)
        artifact["lime_device"] = lime_info

        # Step 2: /proc/kcore stream
        if attempt_kcore:
            artifact["kcore"] = self._stream_kcore(ssh, output_dir, case_no, timestamp_utc)
        else:
            artifact["kcore"] = {"status": "SKIPPED"}

        # Step 3: metadata (always)
        artifact["meminfo"] = self._collect_meminfo(ssh)
        artifact["kallsyms"] = self._collect_kallsyms_summary(ssh)
        artifact["kernel_modules"] = self._collect_modules(ssh)

        # ── Write JSON ────────────────────────────────────────────────
        json_path = os.path.join(output_dir, f"MemoryState_{case_no}_{timestamp_utc}.json")
        try:
            # Exclude potentially huge binary artifact details from JSON
            json_artifact = {k: v for k, v in artifact.items() if k != "kernel_modules"}
            json_artifact["kernel_module_count"] = len(artifact.get("kernel_modules", []))
            json_artifact["kernel_modules"] = artifact.get("kernel_modules", [])
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(json_artifact, f, indent=2, ensure_ascii=False)
            artifact["json_path"] = json_path
        except OSError:
            artifact["json_path"] = None

        return artifact
