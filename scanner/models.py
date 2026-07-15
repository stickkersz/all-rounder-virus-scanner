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
class Detection:
    path: str
    severity: Severity
    threat: str                 # signature name / rule / reason
    source: str                 # "clamav" | "hash" | "yara" | "heuristic"
    sha256: Optional[str] = None
    quarantined_to: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "severity": self.severity.value,
            "threat": self.threat,
            "source": self.source,
            "sha256": self.sha256,
            "quarantined_to": self.quarantined_to,
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
