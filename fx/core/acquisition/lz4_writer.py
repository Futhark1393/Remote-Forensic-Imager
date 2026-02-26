# Author: Futhark1393
# Description: LZ4-compressed evidence writer.
# Provides on-the-fly LZ4 compression of raw disk images with frame format.
# Requires: lz4 (pip install lz4>=4.0.0) — optional but recommended.

LZ4_AVAILABLE = False
_LZ4_IMPORT_ERROR = ""

try:
    import lz4.frame
    LZ4_AVAILABLE = True
except ImportError as _e:
    _LZ4_IMPORT_ERROR = str(_e)


class LZ4Writer:
    """Wraps a binary file with LZ4 frame compression."""

    def __init__(self, filepath: str):
        """
        Initialize LZ4Writer with frame compression.
        
        Args:
            filepath: Output file path (typically .raw.lz4)
            
        Raises:
            ImportError: If lz4 is not installed.
        """
        if not LZ4_AVAILABLE:
            raise ImportError(
                "LZ4 format selected but lz4 is not installed.\n"
                "Install with: pip install lz4>=4.0.0\n"
                f"Details: {_LZ4_IMPORT_ERROR}"
            )
        
        self._fh = open(filepath, "wb")
        # Create a frame context for streaming compression.
        # begin() must be called before compress() to initialize context.
        self._context = lz4.frame.LZ4FrameCompressor(compression_level=3)
        # Write frame header
        frame_header = self._context.begin()
        self._fh.write(frame_header)

    def write(self, chunk: bytes) -> None:
        """Compress and write a chunk of data."""
        if chunk:
            compressed = self._context.compress(chunk)
            self._fh.write(compressed)

    def close(self) -> None:
        """Flush remaining data and close the file."""
        # Flush any remaining buffered data
        final = self._context.flush()
        self._fh.write(final)
        self._fh.close()
