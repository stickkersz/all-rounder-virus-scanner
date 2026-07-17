"""Scan cache: remember files already scanned clean so re-scans of the same
drive skip them. Keyed by absolute path; invalidated when size or mtime changes.

This is the single biggest speed win on slow laptops re-scanning the same USB
stick or a company hard disk that barely changes between scans.
"""

from __future__ import annotations

import json
import os
import tempfile
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
        """Atomically persist the cache.

        The real-time monitor and a manual scan share one engine (and one
        cache) across threads, so the dict is SNAPSHOTTED under the lock and
        serialized outside it: iterating it directly would raise
        "dictionary changed size during iteration" the moment the other thread
        marked a file clean — killing a scan or, worse, dropping a batch's
        detections after its files were already quarantined.

        The temp file is per-writer (mkstemp) because two threads sharing one
        fixed ".tmp" name interleave their JSON and corrupt the cache.
        """
        if not self.enabled:
            return
        with self._lock:
            snapshot = {k: [v[0], v[1]] for k, v in self._clean.items()}
        d = os.path.dirname(self.path) or "."
        os.makedirs(d, exist_ok=True)
        tmp = None
        try:
            fd, tmp = tempfile.mkstemp(dir=d, prefix=".scan_cache.", suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(snapshot, fh)
            os.replace(tmp, self.path)
        except OSError:
            # cache is best-effort; a failed write must not fail the scan
            if tmp and os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except OSError:
                    pass
