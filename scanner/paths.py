"""Resolve the application base directory for both source runs and frozen
(PyInstaller) builds.

When frozen as a onefile exe, PyInstaller unpacks bundled code to a temp dir
(`sys._MEIPASS`) that is deleted on exit — no good for config/signatures the
user edits. So for a frozen app we anchor on the *exe's own folder* (the
install dir under Program Files), where the installer places an editable
config.yaml and a signatures folder. From source we use the project root.
"""

from __future__ import annotations

import os
import sys


def app_base_dir() -> str:
    if getattr(sys, "frozen", False):
        # Directory containing the installed .exe.
        return os.path.dirname(os.path.abspath(sys.executable))
    # scanner/paths.py -> project root is one level up from this package.
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
