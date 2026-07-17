"""Removable-media watcher.

Detects newly inserted USB drives and fires a callback so they can be scanned
automatically. Drive enumeration itself lives in `scanner.drives` — this module
only handles the polling/arrival logic on top of it.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Callable, Set

from .drives import list_removable

__all__ = ["DriveWatcher", "list_removable"]

# Not sys.stderr: it is None under pythonw / a PyInstaller windowed build, so
# writing to it inside the keep-alive handler would kill the watcher loop.
log = logging.getLogger("usbscanner")


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
                log.error("[watcher] error: %s", exc)
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
