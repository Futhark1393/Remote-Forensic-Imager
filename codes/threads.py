# Author: Futhark1393
# Description: QThread integration for the Paramiko streaming engine with E01.

from PyQt6.QtCore import QThread, pyqtSignal
from codes.engine import ForensicAcquisitionEngine

class AcquisitionWorker(QThread):
    # Define signals to communicate with the main GUI thread
    progress_signal = pyqtSignal(dict)
    finished_signal = pyqtSignal(dict)
    error_signal = pyqtSignal(str)

    def __init__(self, host, username, key_path, target_device, output_file, format_type, case_no, examiner):
        super().__init__()
        # Initialize the core acquisition engine with metadata
        self.engine = ForensicAcquisitionEngine(
            host, username, key_path, target_device, output_file, format_type, case_no, examiner
        )

    def run(self):
        try:
            # 1. Establish SSH connection via Paramiko
            self.engine.connect()

            # 2. Iterate over the yield generator for real-time chunk data
            for state in self.engine.acquire_and_hash():
                if state.get("status") == "error":
                    self.error_signal.emit(state.get("message"))
                    break

                elif state.get("status") == "completed":
                    self.finished_signal.emit(state)
                    break

                else:
                    # Emit current progress statistics to GUI
                    self.progress_signal.emit(state)

        except Exception as e:
            self.error_signal.emit(f"Critical Engine Error: {str(e)}")

        finally:
            self.engine.disconnect()
