# Author: Futhark1393
# Description: Incremental stream hasher for forensic acquisition.
# Wraps paired MD5 + SHA-256 hash objects for single-responsibility use.

import hashlib


class StreamHasher:
    """Dual MD5 + SHA-256 incremental hasher for forensic evidence streams."""

    def __init__(self):
        self._md5 = hashlib.md5()
        self._sha256 = hashlib.sha256()

    def update(self, data: bytes) -> None:
        """Feed a chunk of evidence data into both hash functions."""
        self._md5.update(data)
        self._sha256.update(data)

    @property
    def md5_hex(self) -> str:
        return self._md5.hexdigest()

    @property
    def sha256_hex(self) -> str:
        return self._sha256.hexdigest()
