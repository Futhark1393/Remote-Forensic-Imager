# Author: Kemal Sebzeci
# Description: DDSecure-style bad sector error map — offset list of unreadable sectors.
# Features: Tracks I/O errors with byte-level offset + length, exports to
#           text log (ddrescue-compatible format), JSON, and summary statistics.

import json
import os
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List, Optional


@dataclass
class BadSectorEntry:
    """A single unreadable region on the source device."""
    offset: int          # byte offset from start of device
    length: int          # number of bytes in the unreadable region
    error: str           # OS-level error description
    timestamp: float     # time.time() when the error occurred
    retry_count: int = 0 # number of retry attempts before giving up

    @property
    def end_offset(self) -> int:
        return self.offset + self.length

    @property
    def offset_hex(self) -> str:
        return f"0x{self.offset:016X}"

    @property
    def end_offset_hex(self) -> str:
        return f"0x{self.end_offset:016X}"

    @property
    def sector_512(self) -> int:
        """Sector number assuming 512-byte sectors."""
        return self.offset // 512

    @property
    def sector_count_512(self) -> int:
        """Number of 512-byte sectors in this bad region."""
        return (self.length + 511) // 512


@dataclass
class BadSectorMap:
    """
    DDSecure-style bad sector error map.

    Accumulates I/O errors during acquisition and exports them in
    forensic-grade formats (text log, JSON, ddrescue-compatible mapfile).
    """
    source: str = ""
    output: str = ""
    chunk_size: int = 4 * 1024 * 1024
    _entries: List[BadSectorEntry] = field(default_factory=list)
    _start_time: float = field(default_factory=time.time)

    # ── Recording ────────────────────────────────────────────────

    def record(self, offset: int, length: int, error: str, retry_count: int = 0) -> None:
        """Record an unreadable sector region."""
        self._entries.append(BadSectorEntry(
            offset=offset,
            length=length,
            error=str(error),
            timestamp=time.time(),
            retry_count=retry_count,
        ))

    @property
    def entries(self) -> List[BadSectorEntry]:
        return list(self._entries)

    @property
    def count(self) -> int:
        return len(self._entries)

    @property
    def total_bad_bytes(self) -> int:
        return sum(e.length for e in self._entries)

    @property
    def total_bad_sectors_512(self) -> int:
        """Total number of affected 512-byte sectors."""
        return sum(e.sector_count_512 for e in self._entries)

    def has_errors(self) -> bool:
        return len(self._entries) > 0

    # ── Merge adjacent entries ───────────────────────────────────

    def coalesce(self) -> "BadSectorMap":
        """Merge adjacent/overlapping bad regions into contiguous ranges."""
        if not self._entries:
            return self
        sorted_entries = sorted(self._entries, key=lambda e: e.offset)
        merged: List[BadSectorEntry] = [sorted_entries[0]]
        for entry in sorted_entries[1:]:
            last = merged[-1]
            if entry.offset <= last.end_offset:
                # Overlapping or adjacent — extend
                new_end = max(last.end_offset, entry.end_offset)
                merged[-1] = BadSectorEntry(
                    offset=last.offset,
                    length=new_end - last.offset,
                    error=last.error,
                    timestamp=last.timestamp,
                    retry_count=max(last.retry_count, entry.retry_count),
                )
            else:
                merged.append(entry)
        self._entries = merged
        return self

    # ── Export: JSON ─────────────────────────────────────────────

    def export_json(self, filepath: str) -> str:
        """Export error map as JSON (machine-readable)."""
        data = {
            "format": "ForenXtract Bad Sector Error Map",
            "version": "1.0",
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "source": self.source,
            "output": self.output,
            "chunk_size": self.chunk_size,
            "summary": {
                "bad_region_count": self.count,
                "total_bad_bytes": self.total_bad_bytes,
                "total_bad_sectors_512": self.total_bad_sectors_512,
            },
            "sectors": [
                {
                    "offset": e.offset,
                    "offset_hex": e.offset_hex,
                    "length": e.length,
                    "end_offset": e.end_offset,
                    "end_offset_hex": e.end_offset_hex,
                    "sector_512": e.sector_512,
                    "sector_count_512": e.sector_count_512,
                    "error": e.error,
                    "retry_count": e.retry_count,
                    "timestamp": e.timestamp,
                }
                for e in self._entries
            ],
        }
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return filepath

    # ── Export: DDSecure / ddrescue-style text log ───────────────

    def export_log(self, filepath: str) -> str:
        """
        Export error map as a human-readable text log (DDSecure-style).

        Format:
            OFFSET (hex)          OFFSET (dec)          LENGTH        SECTORS(512)  STATUS
            0x0000000004000000    67108864              4194304       8192          BAD
        """
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("# ForenXtract — Bad Sector Error Map (DDSecure-style)\n")
            f.write(f"# Generated : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
            f.write(f"# Source    : {self.source}\n")
            f.write(f"# Output    : {self.output}\n")
            f.write(f"# Chunk Size: {self.chunk_size} bytes\n")
            f.write("#\n")
            f.write(f"# Total bad regions  : {self.count}\n")
            f.write(f"# Total bad bytes    : {self.total_bad_bytes:,}\n")
            f.write(f"# Total bad sectors  : {self.total_bad_sectors_512} (512-byte)\n")
            f.write("#\n")

            if not self._entries:
                f.write("# No bad sectors detected.\n")
            else:
                # Header
                f.write(f"{'OFFSET (hex)':<22}{'OFFSET (dec)':<20}{'END OFFSET (hex)':<22}"
                        f"{'LENGTH':<14}{'SECTORS(512)':<14}{'RETRIES':<10}{'ERROR'}\n")
                f.write("-" * 130 + "\n")

                for e in self._entries:
                    f.write(
                        f"{e.offset_hex:<22}{e.offset:<20}{e.end_offset_hex:<22}"
                        f"{e.length:<14}{e.sector_count_512:<14}{e.retry_count:<10}{e.error}\n"
                    )

                f.write("-" * 130 + "\n")
                f.write(f"# END — {self.count} bad region(s), "
                        f"{self.total_bad_bytes:,} bytes, "
                        f"{self.total_bad_sectors_512} sector(s)\n")

        return filepath

    # ── Export: ddrescue mapfile format ──────────────────────────

    def export_ddrescue_map(self, filepath: str, device_size: int = 0) -> str:
        """
        Export in GNU ddrescue mapfile format for interoperability.

        See: https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html#Mapfile-structure

        Status characters:
            ?  non-tried
            +  rescued (successfully read)
            -  bad sector (failed)
            *  non-trimmed
            /  non-scraped
        """
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)

        # Build a list of (offset, length, status) covering the whole device
        regions = []
        sorted_entries = sorted(self._entries, key=lambda e: e.offset)
        current_pos = 0

        for e in sorted_entries:
            if e.offset > current_pos:
                # Good region before this bad one
                regions.append((current_pos, e.offset - current_pos, "+"))
            regions.append((e.offset, e.length, "-"))
            current_pos = e.end_offset

        # Trailing good region
        if device_size > 0 and current_pos < device_size:
            regions.append((current_pos, device_size - current_pos, "+"))
        elif not sorted_entries and device_size > 0:
            regions.append((0, device_size, "+"))

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("# ForenXtract ddrescue-compatible mapfile\n")
            f.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}\n")
            # Status line (current_pos  current_status  current_pass)
            f.write(f"0x{current_pos:016X}     +\n")
            for offset, length, status in regions:
                f.write(f"0x{offset:016X}  0x{length:016X}  {status}\n")

        return filepath

    # ── Summary string ──────────────────────────────────────────

    def summary(self) -> str:
        """One-line summary suitable for CLI/log output."""
        if not self._entries:
            return "No bad sectors detected."
        return (
            f"{self.count} bad region(s) — "
            f"{self.total_bad_bytes:,} bytes "
            f"({self.total_bad_sectors_512} sector(s) @ 512B) unreadable, "
            f"zero-padded in output image."
        )

    # ── Convenience: export all formats at once ─────────────────

    def export_all(self, base_path: str, device_size: int = 0) -> dict:
        """
        Export error map in all formats.

        Args:
            base_path: Base filename without extension (e.g., '/evidence/img.raw')
            device_size: Total device size in bytes (for ddrescue map)

        Returns dict with paths: {json_path, log_path, ddrescue_map_path}
        """
        json_path = base_path + ".bad_sectors.json"
        log_path = base_path + ".bad_sectors.log"
        ddrescue_path = base_path + ".bad_sectors.mapfile"

        self.export_json(json_path)
        self.export_log(log_path)
        self.export_ddrescue_map(ddrescue_path, device_size=device_size)

        return {
            "json_path": json_path,
            "log_path": log_path,
            "ddrescue_map_path": ddrescue_path,
        }
