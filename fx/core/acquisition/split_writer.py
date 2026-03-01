# Author: Kemal Sebzeci
# Description: Split evidence writer — segments large images into fixed-size parts.
# Features: FAT32-compatible splitting (2G/4G), configurable segment size,
#           FTK Imager-style numbered segments (.001, .002, …).

import os
from typing import Optional


def parse_split_size(value: str) -> int:
    """Parse a human-readable size string into bytes.

    Supported suffixes (case-insensitive):
        B   → bytes   (literal)
        K   → KiB (× 1024)
        M   → MiB (× 1024²)
        G   → GiB (× 1024³)
        T   → TiB (× 1024⁴)
        KB  → 1000
        MB  → 1000²
        GB  → 1000³

    No suffix → bytes.

    Examples:
        "2G"    → 2_147_483_648
        "4G"    → 4_294_967_296
        "650M"  → 681_574_400
        "4700M" → 4_928_307_200

    Raises ValueError on invalid input.
    """
    if not value:
        raise ValueError("Empty split size")

    value = value.strip()

    # Binary suffixes (IEC): K/M/G/T or KiB/MiB/GiB/TiB
    _BINARY = {"B": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
    # SI suffixes: KB/MB/GB/TB
    _SI = {"KB": 1000, "MB": 1000**2, "GB": 1000**3, "TB": 1000**4}

    upper = value.upper()

    # Try SI suffixes first (longer match)
    for suffix, multiplier in _SI.items():
        if upper.endswith(suffix):
            num_str = value[: -len(suffix)].strip()
            return int(float(num_str) * multiplier)

    # Try IEC suffixes (K/M/G/T plus optional "IB")
    for suffix_short, multiplier in _BINARY.items():
        full = suffix_short + "IB"
        if upper.endswith(full):
            num_str = value[: -len(full)].strip()
            return int(float(num_str) * multiplier)
        if upper.endswith(suffix_short) and suffix_short != "B":
            num_str = value[: -len(suffix_short)].strip()
            return int(float(num_str) * multiplier)

    # Plain number (bytes)
    if upper.endswith("B"):
        num_str = value[:-1].strip()
    else:
        num_str = value

    return int(float(num_str))


def format_split_size(size_bytes: int) -> str:
    """Format byte size into a human-readable string."""
    if size_bytes >= 1024**3 and size_bytes % (1024**3) == 0:
        return f"{size_bytes // (1024**3)}G"
    if size_bytes >= 1024**2 and size_bytes % (1024**2) == 0:
        return f"{size_bytes // (1024**2)}M"
    if size_bytes >= 1024 and size_bytes % 1024 == 0:
        return f"{size_bytes // 1024}K"
    return f"{size_bytes}B"


def _segment_path(base_path: str, segment_number: int) -> str:
    """Generate segment filename: evidence.raw.001, evidence.raw.002, …

    For E01 format, pyewf handles its own segmentation (.E01, .E02, …).
    This function is for RAW, LZ4, and AFF4.
    """
    return f"{base_path}.{segment_number:03d}"


class SplitWriter:
    """
    Wraps any evidence writer and splits output into fixed-size segments.

    Segment naming: ``<output_file>.001``, ``<output_file>.002``, …

    Usage:
        writer = SplitWriter(
            filepath="evidence.raw",
            segment_size=2 * 1024**3,   # 2 GiB
            writer_factory=lambda path: RawWriter(path),
        )
        writer.write(chunk)
        writer.close()

    The writer_factory callable is called for each new segment.
    Each segment is an independent, valid file of the underlying format.
    """

    def __init__(
        self,
        filepath: str,
        segment_size: int,
        writer_factory,
    ):
        if segment_size <= 0:
            raise ValueError(f"segment_size must be positive, got {segment_size}")

        self._base_path = filepath
        self._segment_size = segment_size
        self._writer_factory = writer_factory

        self._current_segment = 1
        self._current_bytes = 0
        self._current_writer = None
        self._total_segments = 0
        self._segment_paths: list[str] = []
        self._closed = False

        # Open first segment
        self._rotate()

    def _rotate(self) -> None:
        """Close current segment (if any) and open the next one."""
        if self._current_writer is not None:
            self._current_writer.close()

        seg_path = _segment_path(self._base_path, self._current_segment)
        self._current_writer = self._writer_factory(seg_path)
        self._segment_paths.append(seg_path)
        self._current_bytes = 0
        self._total_segments = self._current_segment
        self._current_segment += 1

    def write(self, chunk: bytes) -> None:
        """Write data, splitting across segments as needed."""
        if self._closed:
            raise IOError("SplitWriter is closed.")
        if not chunk:
            return

        offset = 0
        remaining = len(chunk)

        while remaining > 0:
            space_left = self._segment_size - self._current_bytes

            if remaining <= space_left:
                # Fits in current segment
                self._current_writer.write(chunk[offset:])
                self._current_bytes += remaining
                remaining = 0
            else:
                # Fill current segment, then rotate
                self._current_writer.write(chunk[offset: offset + space_left])
                self._current_bytes += space_left
                offset += space_left
                remaining -= space_left
                self._rotate()

    def close(self) -> None:
        """Close the current (last) segment."""
        if self._closed:
            return
        self._closed = True
        if self._current_writer is not None:
            self._current_writer.close()

    @property
    def segment_count(self) -> int:
        return self._total_segments

    @property
    def segment_paths(self) -> list[str]:
        return list(self._segment_paths)

    @property
    def segment_size(self) -> int:
        return self._segment_size
