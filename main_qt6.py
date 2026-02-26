# Author: Futhark1393
# Entry Point for ForenXtract (FX)
# Enforces dependency check and Case Wizard before launching main UI.

import sys
from PyQt6.QtWidgets import QApplication, QMessageBox, QDialog
from qt_material import apply_stylesheet

from fx.deps.dependency_checker import run_dependency_check
from fx.ui.gui import ForensicApp, CaseWizard


def main():
    # 1. Dependency check before UI boot
    py_missing, native_missing = run_dependency_check()

    if py_missing or native_missing:
        error_msg = "Missing Dependencies Detected:\n\n"

        if py_missing:
            error_msg += "Python Packages:\n"
            for pkg in py_missing:
                error_msg += f" - {pkg}\n"

        if native_missing:
            error_msg += "\nSystem Libraries:\n"
            for lib in native_missing:
                error_msg += f" - {lib}\n"

        app = QApplication(sys.argv)
        QMessageBox.critical(
            None,
            "Dependency Error",
            error_msg + "\n\nPlease install required components before running.",
        )
        sys.exit(1)

    # 2. Launch application
    app = QApplication(sys.argv)
    apply_stylesheet(app, theme="dark_teal.xml")

    # 3. Case Wizard (mandatory)
    wizard = CaseWizard()
    if wizard.exec() != QDialog.DialogCode.Accepted:
        sys.exit(0)

    # 4. Launch main window with enforced case context
    window = ForensicApp(
        wizard.case_no,
        wizard.examiner,
        wizard.evidence_dir,
    )
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
