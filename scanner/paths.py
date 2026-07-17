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
from typing import Optional


def app_base_dir() -> str:
    if getattr(sys, "frozen", False):
        # Directory containing the installed .exe.
        return os.path.dirname(os.path.abspath(sys.executable))
    # scanner/paths.py -> project root is one level up from this package.
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def resolve_under_base(base_dir: str, path: Optional[str]) -> Optional[str]:
    """Resolve a possibly-relative configured path against the app base dir.

    One implementation so a writer and a reader of the same config key can
    never disagree about where it points (e.g. `usbscan feeds` writing to one
    directory while the engine reads another, silently disabling the check).
    """
    if not path:
        return path
    return path if os.path.isabs(path) else os.path.join(base_dir, path)


def norm_for_match(path: str) -> str:
    """Canonical form for comparing paths: absolute, case-folded (Windows),
    forward slashes, no trailing slash. THE one normalizer for containment/
    equality checks (exclusions, target dedupe) — do not grow local copies.
    Distinct from engine._norm, which deliberately does NOT absolutize
    (it must match ClamAV's echoed paths verbatim)."""
    n = os.path.normcase(os.path.abspath(path)).replace("\\", "/")
    return n.rstrip("/") or "/"


def is_under(child_norm: str, parent_norm: str) -> bool:
    """True if child == parent or child is inside parent's subtree. Both args
    must already be norm_for_match()-style. The '+ "/"' guard keeps /x/VMs
    from swallowing /x/VMsOther (string prefix != path parent)."""
    return child_norm == parent_norm or child_norm.startswith(parent_norm + "/")
