"""Behavioral detection over the real-time filesystem event stream.

Some malware classes cannot be caught by looking at one file: ransomware and
worms are defined by a *pattern of activity across many files in a short time*.
This analyzer is fed the same create/modify/move/delete events the real-time
monitor already receives and raises a detection when a burst matches a known
malicious shape:

* **Ransomware** — a rapid burst of modify+rename activity across many distinct
  files in a few seconds (the encrypt-then-rename loop), scored higher when the
  new names carry ransomware extensions. Hashing is weak against ransomware
  (variants mutate fast); the behavior is the durable signal.
* **Worm** — a burst of file *writes spread across many distinct directories /
  drive roots* at once (mass self-copy / propagation).
* **Canary trip** — any change to a bait file the scanner planted (see
  scanner/canary.py) is an immediate, high-confidence ransomware signal: nothing
  legitimate rewrites those files.

DESIGN: `record()` does NO disk I/O — it runs on watchdog's event thread, which
must stay fast, so it only counts events in a sliding time window. Everything is
tunable (window, thresholds, sensitivity) because behavioral signals are less
precise than hashing. Per-category cooldown prevents one ongoing attack from
emitting hundreds of alerts.

FALSE-POSITIVE stance: a legitimate mass operation (extracting a big archive,
a bulk photo import, a compiler writing thousands of objects) CAN trip the worm/
ransomware burst heuristics. That is why: (a) these are SUSPICIOUS by default
unless a canary trips or ransom extensions dominate (then INFECTED), (b)
thresholds default conservative, and (c) sensitivity is exposed. The analyzer
flags for review + logs; it does not by itself delete a user's files.
"""

from __future__ import annotations

import os
import threading
from collections import deque
from typing import Deque, Dict, List, Optional, Tuple

from .detectors import Category, Sensitivity, make_detection
from .heuristics import RANSOM_EXTENSIONS
from .models import Detection, Severity
from .paths import norm_for_match

# Event actions fed to the analyzer.
CREATED = "created"
MODIFIED = "modified"
MOVED = "moved"
DELETED = "deleted"

# Threshold presets per sensitivity: (ransomware distinct files, worm distinct
# directories, worm distinct files). Higher sensitivity trips on smaller bursts.
_PRESETS = {
    Sensitivity.LOW:    {"ransom_files": 40, "worm_dirs": 8,  "worm_files": 40},
    Sensitivity.MEDIUM: {"ransom_files": 20, "worm_dirs": 5,  "worm_files": 20},
    Sensitivity.HIGH:   {"ransom_files": 10, "worm_dirs": 3,  "worm_files": 10},
}


class BehaviorAnalyzer:
    def __init__(self, cfg: Optional[dict] = None, canaries=(),
                 clock=None):
        cfg = cfg or {}
        self.enabled = cfg.get("enabled", True)
        self.sensitivity = Sensitivity.parse(cfg.get("sensitivity"),
                                             Sensitivity.MEDIUM)
        preset = _PRESETS[self.sensitivity]
        # Explicit config overrides the preset (an admin who knows their fleet).
        self.window = float(cfg.get("window_seconds", 8.0))
        self.cooldown = float(cfg.get("cooldown_seconds", 30.0))
        self.ransom_files = int(cfg.get("ransomware_file_threshold",
                                        preset["ransom_files"]))
        self.worm_dirs = int(cfg.get("worm_dir_threshold", preset["worm_dirs"]))
        self.worm_files = int(cfg.get("worm_file_threshold", preset["worm_files"]))
        import time as _time
        self.clock = clock or _time.monotonic
        self.canaries = {norm_for_match(p) for p in canaries}
        self._events: Deque[Tuple[float, str, str, str]] = deque()  # when,npath,action,ext
        self._lock = threading.Lock()
        self._last_fire: Dict[str, float] = {}

    def add_canaries(self, paths) -> None:
        with self._lock:
            self.canaries |= {norm_for_match(p) for p in paths}

    def _cooling_down(self, category: str, now: float) -> bool:
        last = self._last_fire.get(category)
        return last is not None and (now - last) < self.cooldown

    def record(self, path: str, action: str,
               when: Optional[float] = None) -> List[Detection]:
        """Register one filesystem event; return any detections it triggers.

        No file I/O here — safe to call from the watchdog event thread."""
        if not self.enabled:
            return []
        now = self.clock() if when is None else when
        npath = norm_for_match(path)
        ext = os.path.splitext(npath)[1]

        with self._lock:
            # Canary: any change to a planted bait file is an instant, high-
            # confidence ransomware signal (still cooldown-gated to avoid spam).
            if npath in self.canaries and action in (MODIFIED, MOVED, DELETED):
                if not self._cooling_down("canary", now):
                    self._last_fire["canary"] = now
                    return [make_detection(
                        path, Category.RANSOMWARE,
                        "canary bait file was modified/deleted — ransomware "
                        "encryption behavior in progress",
                        "behavior", severity=Severity.INFECTED)]
                return []

            self._events.append((now, npath, action, ext))
            cutoff = now - self.window
            while self._events and self._events[0][0] < cutoff:
                self._events.popleft()

            out: List[Detection] = []
            out += self._check_ransomware(path, now)
            out += self._check_worm(path, now)
            return out

    def _check_ransomware(self, trigger_path: str, now: float) -> List[Detection]:
        if self._cooling_down("ransomware", now):
            return []
        # Distinct files touched by a modify/rename in the window.
        touched = {ev[1] for ev in self._events if ev[2] in (MODIFIED, MOVED)}
        if len(touched) < self.ransom_files:
            return []
        ransom_named = sum(1 for ev in self._events
                           if ev[2] in (MODIFIED, MOVED)
                           and ev[3] in RANSOM_EXTENSIONS)
        self._last_fire["ransomware"] = now
        # Ransom-extension dominance upgrades the verdict from SUSPICIOUS burst
        # to a confirmed encryption pattern.
        if ransom_named >= max(3, self.ransom_files // 4):
            sev, note = Severity.INFECTED, (
                f"{ransom_named} files renamed to ransomware extensions")
        else:
            sev, note = Severity.SUSPICIOUS, "no ransom extensions yet"
        return [make_detection(
            trigger_path, Category.RANSOMWARE,
            f"rapid modify/rename of {len(touched)} files in "
            f"{self.window:.0f}s ({note}) — possible ransomware",
            "behavior", severity=sev)]

    def _check_worm(self, trigger_path: str, now: float) -> List[Detection]:
        if self._cooling_down("worm", now):
            return []
        writes = [ev for ev in self._events if ev[2] in (CREATED, MODIFIED)]
        files = {ev[1] for ev in writes}
        dirs = {os.path.dirname(ev[1]) for ev in writes}
        if len(dirs) < self.worm_dirs or len(files) < self.worm_files:
            return []
        self._last_fire["worm"] = now
        return [make_detection(
            trigger_path, Category.WORM,
            f"burst of {len(files)} file writes across {len(dirs)} directories "
            f"in {self.window:.0f}s — possible worm propagation / mass-copy",
            "behavior", severity=Severity.SUSPICIOUS)]
