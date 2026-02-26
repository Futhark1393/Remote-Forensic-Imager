# Author: Futhark1393
# Description: Runtime dependency checker.

import importlib
import subprocess

PYTHON_DEPENDENCIES = [
    "paramiko",
    "fpdf",
    "qt_material",
]

NATIVE_LIBS = [
    "libewf"
]


def run_dependency_check():
    py_missing = []
    native_missing = []

    # Check Python packages
    for module in PYTHON_DEPENDENCIES:
        try:
            importlib.import_module(module)
        except ImportError:
            py_missing.append(module)

    # Check native libraries
    try:
        result = subprocess.run(
            ["ldconfig", "-p"],
            capture_output=True,
            text=True
        )
        for lib in NATIVE_LIBS:
            if lib not in result.stdout:
                native_missing.append(lib)
    except Exception:
        native_missing.append("ldconfig unavailable")

    return py_missing, native_missing
