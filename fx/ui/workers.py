# Author: Kemal Sebzeci
# Description: Thin Qt worker wrappers. No business logic.
# The acquisition engines do all the real work; this just bridges
# their callbacks to pyqtSignal for the GUI.

from PyQt6.QtCore import QThread, pyqtSignal

from fx.core.acquisition.base import AcquisitionEngine, AcquisitionError
from fx.core.acquisition.dead import DeadAcquisitionEngine, DeadAcquisitionError


class AcquisitionWorker(QThread):
    """
    QThread wrapper around AcquisitionEngine (live / remote).

    Bridges the engine's on_progress callback to Qt signals.
    Contains zero acquisition logic.
    """

    progress_signal = pyqtSignal(dict)
    finished_signal = pyqtSignal(dict)
    error_signal = pyqtSignal(str)

    def __init__(
        self,
        ip: str,
        user: str,
        key_path: str,
        disk: str,
        output_file: str,
        format_type: str,
        case_no: str,
        examiner: str,
        throttle_limit: float = 0.0,
        safe_mode: bool = True,
        run_triage: bool = False,
        triage_network: bool = True,
        triage_processes: bool = True,
        triage_memory: bool = False,
        triage_hash_exes: bool = True,
        output_dir: str = "",
        verify_hash: bool = False,
        write_blocker: bool = False,
        description: str = "",
        notes: str = "",
        split_size: int = 0,
    ):
        super().__init__()
        self._engine = AcquisitionEngine(
            ip=ip,
            user=user,
            key_path=key_path,
            disk=disk,
            output_file=output_file,
            format_type=format_type,
            case_no=case_no,
            examiner=examiner,
            throttle_limit=throttle_limit,
            safe_mode=safe_mode,
            run_triage=run_triage,
            triage_network=triage_network,
            triage_processes=triage_processes,
            triage_memory=triage_memory,
            triage_hash_exes=triage_hash_exes,
            output_dir=output_dir,
            verify_hash=verify_hash,
            write_blocker=write_blocker,
            on_progress=self._on_progress,
            description=description,
            notes=notes,
            split_size=split_size,
        )

    def _on_progress(self, data: dict) -> None:
        self.progress_signal.emit(data)

    def stop(self) -> None:
        self._engine.stop()

    def run(self) -> None:
        try:
            result = self._engine.run()
            self.finished_signal.emit(result)
        except AcquisitionError as e:
            self.error_signal.emit(str(e))
        except Exception as e:
            self.error_signal.emit(f"Unexpected error: {e}")


class DeadAcquisitionWorker(QThread):
    """
    QThread wrapper around DeadAcquisitionEngine (dead / local).

    Bridges the engine's on_progress callback to Qt signals.
    Contains zero acquisition logic.
    """

    progress_signal = pyqtSignal(dict)
    finished_signal = pyqtSignal(dict)
    error_signal = pyqtSignal(str)

    def __init__(
        self,
        source_path: str,
        output_file: str,
        format_type: str,
        case_no: str,
        examiner: str,
        throttle_limit: float = 0.0,
        safe_mode: bool = True,
        verify_hash: bool = False,
        write_blocker: bool = False,
        description: str = "",
        notes: str = "",
        split_size: int = 0,
    ):
        super().__init__()
        self._engine = DeadAcquisitionEngine(
            source_path=source_path,
            output_file=output_file,
            format_type=format_type,
            case_no=case_no,
            examiner=examiner,
            throttle_limit=throttle_limit,
            safe_mode=safe_mode,
            verify_hash=verify_hash,
            write_blocker=write_blocker,
            on_progress=self._on_progress,
            description=description,
            notes=notes,
            split_size=split_size,
        )

    def _on_progress(self, data: dict) -> None:
        self.progress_signal.emit(data)

    def stop(self) -> None:
        self._engine.stop()

    def run(self) -> None:
        try:
            result = self._engine.run()
            self.finished_signal.emit(result)
        except DeadAcquisitionError as e:
            self.error_signal.emit(str(e))
        except Exception as e:
            self.error_signal.emit(f"Unexpected error: {e}")
