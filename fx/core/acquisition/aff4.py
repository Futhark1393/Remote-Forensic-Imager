# Author: Futhark1393
# Description: AFF4 evidence container writer.
# AFF4 (Advanced Forensic Format 4) is an open standard for forensic evidence containers.
# Requires: pyaff4 (pip install pyaff4) — optional dependency.
# If pyaff4 is not installed, AFF4Writer raises ImportError with instructions.

AFF4_AVAILABLE = False
_AFF4_IMPORT_ERROR = ""

try:
    from pyaff4 import data_store, lexicon, aff4_map  # type: ignore
    from pyaff4 import zip as aff4_zip                 # type: ignore
    AFF4_AVAILABLE = True
except ImportError as _e:
    _AFF4_IMPORT_ERROR = str(_e)


class AFF4NotAvailableError(Exception):
    """Raised when pyaff4 is not installed."""
    pass


class AFF4Writer:
    """
    AFF4 evidence container writer.

    Interface mirrors RawWriter / EwfWriter so AcquisitionEngine
    can swap writers without any other changes.

    Raises AFF4NotAvailableError on construction if pyaff4 not installed.
    """

    def __init__(self, output_path: str):
        if not AFF4_AVAILABLE:
            raise AFF4NotAvailableError(
                f"pyaff4 is not installed — AFF4 format unavailable.\n"
                f"Install with: pip install pyaff4\n"
                f"Original error: {_AFF4_IMPORT_ERROR}"
            )

        # output_path should end in .aff4 (caller responsibility)
        self._output_path = output_path
        self._resolver = data_store.MemoryDataStore()
        self._volume = None
        self._stream = None
        self._bytes_written = 0
        self._closed = False

        # Open the AFF4 zip volume and create a map stream inside it
        try:
            self._volume = aff4_zip.ZipFile.NewZipFile(self._resolver, self._output_path)
            image_urn = self._volume.urn.Append("image")
            self._stream = aff4_map.AFF4Map.NewAFF4Map(
                self._resolver, image_urn, self._volume.urn
            )
        except Exception as e:
            raise AFF4NotAvailableError(f"Failed to initialise AFF4 container: {e}")

    def write(self, chunk: bytes) -> None:
        """Write a chunk of data to the AFF4 stream."""
        if self._closed:
            raise IOError("AFF4Writer is closed.")
        if not chunk:
            return
        self._stream.Write(chunk)
        self._bytes_written += len(chunk)

    def close(self) -> None:
        """Flush and close the AFF4 container."""
        if self._closed:
            return
        try:
            if self._stream is not None:
                self._resolver.Close(self._stream.urn)
            if self._volume is not None:
                self._resolver.Close(self._volume.urn)
        except Exception:
            pass
        self._closed = True

    @property
    def bytes_written(self) -> int:
        return self._bytes_written
