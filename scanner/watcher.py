"""Removable-media watcher.

Detects newly inserted USB drives and fires a callback so they can be scanned
automatically. Primary strategy is drive-letter polling via the Win32 API
(reliable on every Windows version, no WMI/admin needed). Falls back to mount
point polling on Linux/macOS so the tool is testable off Windows.
"""

from __future__ import annotations

import ctypes
import os
import sys
import time
from typing import Callable, List, Set

DRIVE_REMOVABLE = 2
DRIVE_FIXED = 3


def _windows_removable_drives(include_fixed: bool = False) -> List[str]:
    """Return list of removable (and optionally fixed) drive roots like 'E:\\'."""
    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    bitmask = kernel32.GetLogicalDrives()
    roots: List[str] = []
    for i in range(26):
        if not (bitmask >> i) & 1:
            continue
        root = f"{chr(ord('A') + i)}:\\"
        dtype = kernel32.GetDriveTypeW(ctypes.c_wchar_p(root))
        if dtype == DRIVE_REMOVABLE or (include_fixed and dtype == DRIVE_FIXED):
            roots.append(root)
    return roots


def _posix_mounts() -> List[str]:
    """Removable-ish mount points on macOS (/Volumes) and Linux (/media,/mnt,/run/media)."""
    roots: List[str] = []
    candidates = ["/Volumes"]
    user = os.environ.get("USER", "")
    candidates += ["/media", "/mnt", f"/media/{user}", f"/run/media/{user}"]
    for base in candidates:
        if os.path.isdir(base):
            for name in os.listdir(base):
                p = os.path.join(base, name)
                if os.path.ismount(p) or os.path.isdir(p):
                    roots.append(p)
    return roots


def list_removable(include_fixed: bool = False) -> List[str]:
    if sys.platform == "win32":
        return _windows_removable_drives(include_fixed)
    return _posix_mounts()


class DriveWatcher:
    """Polls for drive arrival and invokes `on_insert(root)` for each new drive."""

    def __init__(self, on_insert: Callable[[str], None], poll_interval: float = 3.0):
        self.on_insert = on_insert
        self.poll_interval = poll_interval
        self._seen: Set[str] = set(list_removable())

    def run_forever(self) -> None:
        while True:
            try:
                self._tick()
            except Exception as exc:  # keep the watcher alive no matter what
                sys.stderr.write(f"[watcher] error: {exc}\n")
            time.sleep(self.poll_interval)

    def _tick(self) -> None:
        current = set(list_removable())
        new = current - self._seen
        for root in sorted(new):
            # brief settle so the OS finishes mounting before we walk it
            time.sleep(0.5)
            if os.path.isdir(root):
                self.on_insert(root)
        self._seen = current
