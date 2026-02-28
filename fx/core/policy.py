# Author: Futhark1393
# Description: Forensic acquisition policy helpers.
# Features: Software write-blocker enforcement, dd flag construction.

import re
import shlex

import paramiko


def _validate_disk_path(disk: str) -> None:
    """Reject obviously malicious device paths to prevent command injection."""
    if not re.match(r"^/dev/[a-zA-Z0-9/_-]+$", disk):
        raise ValueError(f"Invalid disk path: {disk!r}")


def ssh_exec(ssh: paramiko.SSHClient, cmd: str) -> tuple[str, str, int]:
    """Execute a command over SSH and return (stdout, stderr, exit_code)."""
    stdin, stdout, stderr = ssh.exec_command(cmd)
    out = stdout.read().decode("utf-8", errors="ignore").strip()
    err = stderr.read().decode("utf-8", errors="ignore").strip()
    code = stdout.channel.recv_exit_status()
    return out, err, code


def apply_write_blocker(ssh: paramiko.SSHClient, disk: str) -> None:
    """
    Best-effort software write-block on the remote device.
    Raises RuntimeError if the device cannot be set read-only.
    """
    _validate_disk_path(disk)
    safe_disk = shlex.quote(disk)

    # 1) Try blockdev --setro
    _, err, code = ssh_exec(ssh, f"sudo -n blockdev --setro {safe_disk}")
    if code != 0:
        raise RuntimeError(f"Write-blocker failed (blockdev --setro). {err}")

    # 2) Validate read-only flag
    out, err, code = ssh_exec(ssh, f"sudo -n blockdev --getro {safe_disk}")
    if code != 0:
        raise RuntimeError(f"Write-blocker check failed (blockdev --getro). {err}")

    if out.strip() != "1":
        raise RuntimeError(
            "Write-blocker check failed: device is not read-only (blockdev --getro != 1)."
        )

    # 3) Optional hdparm read-only bit (best-effort, ignore failure)
    ssh_exec(ssh, f"sudo hdparm -r1 {safe_disk}")


def build_dd_command(disk: str, skip_bytes: int, safe_mode: bool) -> str:
    """Construct the remote dd command for streaming acquisition."""
    _validate_disk_path(disk)
    safe_disk = shlex.quote(disk)
    conv_flag = " conv=noerror,sync" if safe_mode else ""
    return f"sudo dd if={safe_disk} bs=4M skip={skip_bytes} iflag=skip_bytes{conv_flag} status=none"
