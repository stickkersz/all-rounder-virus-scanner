"""Canary (bait) files for ransomware early-warning.

Plants harmless files in watched folders whose ONLY purpose is to be modified by
ransomware. Nothing legitimate rewrites them, so a change to a canary (seen by
the real-time monitor and routed to BehaviorAnalyzer) is a high-confidence
"encryption in progress" signal — caught before the burst heuristic would, and
with far fewer false positives.

The filename is chosen to sort to the TOP of a directory listing (leading '!'),
because many ransomware families encrypt files in alphabetical order — so the
canary tends to be hit first, buying the earliest possible warning. Content is
plain text explaining what the file is, so a curious employee who finds it isn't
alarmed and doesn't delete it (a manual delete would trip a canary alert, which
is acceptable — better a false alert than a missed one).

The files are best-effort: a folder we can't write to is simply skipped, never a
hard error. `cleanup()` removes what we planted on shutdown.
"""

from __future__ import annotations

import os
from typing import Iterable, List, Optional

_DEFAULT_FILENAME = "!!!__ransomware_canary__DO_NOT_DELETE.txt"

_CANARY_BODY = (
    "This file was placed by the All-Round Virus Scanner as a ransomware\r\n"
    "early-warning tripwire. It is harmless. Please DO NOT delete, move, or\r\n"
    "edit it: if it changes, the scanner treats that as a sign that ransomware\r\n"
    "may be encrypting files and raises an alert.\r\n"
)


class CanaryManager:
    def __init__(self, cfg: Optional[dict] = None):
        cfg = cfg or {}
        self.enabled = cfg.get("enabled", True)
        self.filename = cfg.get("filename", _DEFAULT_FILENAME)
        self.deployed: List[str] = []

    def deploy(self, directories: Iterable[str]) -> List[str]:
        """Write a canary into each existing directory. Returns the paths
        planted (also stored on self.deployed for cleanup)."""
        if not self.enabled:
            return []
        planted: List[str] = []
        for d in directories:
            if not d or not os.path.isdir(d):
                continue
            path = os.path.join(d, self.filename)
            try:
                # Refresh content each start so a stale mtime can't look
                # "changed" to the monitor on the very first event.
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(_CANARY_BODY)
                planted.append(path)
            except OSError:
                continue          # unwritable folder — skip, never fail
        self.deployed = planted
        return planted

    def cleanup(self) -> None:
        for path in self.deployed:
            try:
                if os.path.isfile(path):
                    os.remove(path)
            except OSError:
                pass
        self.deployed = []
