"""Scan cache: remember files already scanned clean so re-scans of the same
drive skip them. Keyed by absolute path; invalidated when size or mtime changes.

This is the single biggest speed win on slow laptops re-scanning the same USB
stick or a company hard disk that barely changes between scans.
"""

from __future__ import annotations

import json
import os
import threading
from typing import Dict, Tuple


class ScanCache:
    def __init__(self, path: str, enabled: bool = True):
        self.enabled = enabled
        self.path = path
        self._lock = threading.Lock()
        # key -> [size, mtime_ns]
        self._clean: Dict[str, Tuple[int, int]] = {}
        if enabled:
            self._load()

    def _load(self) -> None:
        if not os.path.isfile(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            self._clean = {k: (v[0], v[1]) for k, v in raw.items()}
        except (OSError, ValueError, KeyError, IndexError):
            self._clean = {}  # corrupt cache -> start fresh, never crash a scan

    def is_clean(self, path: str, size: int, mtime_ns: int) -> bool:
        if not self.enabled:
            return False
        rec = self._clean.get(path)
        return rec is not None and rec[0] == size and rec[1] == mtime_ns

    def mark_clean(self, path: str, size: int, mtime_ns: int) -> None:
        if not self.enabled:
            return
        with self._lock:
            self._clean[path] = (size, mtime_ns)

    def forget(self, path: str) -> None:
        with self._lock:
            self._clean.pop(path, None)

    def save(self) -> None:
        if not self.enabled:
            return
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        tmp = self.path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump({k: [v[0], v[1]] for k, v in self._clean.items()}, fh)
            os.replace(tmp, self.path)
        except OSError:
            pass  # cache is best-effort; a failed write must not fail the scan
