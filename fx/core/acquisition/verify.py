# Author: Futhark1393
# Description: Post-acquisition remote hash verification.

import paramiko

from fx.core.policy import ssh_exec


def verify_source_hash(
    ssh: paramiko.SSHClient, disk: str
) -> tuple[str, bool | None]:
    """
    Compute SHA-256 of the source disk on the remote host and compare
    against the local stream hash.

    Returns (remote_sha256, matched_or_none).
    On error, returns ("ERROR", False).
    """
    try:
        out, err, code = ssh_exec(ssh, f"sudo -n sha256sum {disk}")
        if code != 0 or not out:
            return "ERROR", False
        remote_sha256 = out.split()[0]
        return remote_sha256, None  # caller compares against local hash
    except Exception:
        return "ERROR", False
