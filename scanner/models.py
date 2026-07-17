"""Shared data types."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Severity(str, Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"   # heuristic hit, not confirmed malware
    INFECTED = "infected"       # signature / hash / YARA confirmed
    ERROR = "error"


@dataclass
class ProgressEvent:
    """Structured scan progress for UIs: which phase, current file, and counts
    so a front-end can draw a real percentage bar without guessing."""
    phase: str            # "indexing" | "clamav" | "scanning" | "done"
    message: str = ""     # current file path or a status line
    current: int = 0      # files processed so far (scanning phase)
    total: int = 0        # total candidate files (0 until known)


@dataclass
class Detection:
    path: str
    severity: Severity
    threat: str                 # signature name / rule / reason
    source: str                 # "clamav" | "hash" | "yara" | "heuristic" | ...
    sha256: Optional[str] = None
    quarantined_to: Optional[str] = None
    # Malware category this signal points at (virus/worm/trojan/ransomware/...).
    # Optional + defaulted so every existing Detection call site keeps working;
    # drives category-aware severity and the coverage report. See
    # scanner/detectors for the taxonomy.
    category: Optional[str] = None
    # Optional numeric weight of this single signal (behavioral detectors
    # accumulate these). None for plain pass/fail signals.
    score: Optional[float] = None

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "severity": self.severity.value,
            "threat": self.threat,
            "source": self.source,
            "sha256": self.sha256,
            "quarantined_to": self.quarantined_to,
            "category": self.category,
            "score": self.score,
        }


@dataclass
class ScanResult:
    target: str
    started: str
    finished: str = ""
    files_scanned: int = 0
    files_skipped: int = 0
    detections: List[Detection] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def infected(self) -> List[Detection]:
        return [d for d in self.detections if d.severity == Severity.INFECTED]

    @property
    def suspicious(self) -> List[Detection]:
        return [d for d in self.detections if d.severity == Severity.SUSPICIOUS]

    @property
    def clean(self) -> bool:
        return not self.infected and not self.suspicious

    def merge(self, other: "ScanResult") -> None:
        """Accumulate another result into this one (multi-root scans).

        Lives here so every accumulated field is defined in ONE place: a
        caller merging field-by-field silently drops any field added later.
        """
        self.files_scanned += other.files_scanned
        self.files_skipped += other.files_skipped
        self.detections.extend(other.detections)
        self.errors.extend(other.errors)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "started": self.started,
            "finished": self.finished,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "detections": [d.to_dict() for d in self.detections],
            "errors": self.errors,
        }
