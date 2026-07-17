"""Category-aware detection: one tunable rule-set per malware class.

The core engine (scanner/engine.py) stays flat and unchanged in shape. This
package adds the *category* layer the spec asks for: each malware class gets its
own named detector so its false-positive tuning is isolated from the others, and
so an operator can toggle/tune classes independently.

Two kinds of detector live here:

* **Static** detectors (this package) run per file, over bytes/metadata the
  engine already read once. They need no process/network context, so they work
  on-demand and in real time. Examples: trojan name-impersonation, PE overlay
  (file-infector), PUP/adware bundler naming.
* **Behavioral** detectors live in scanner/behavior.py because they are stateful
  across a *stream* of filesystem events (ransomware mass-rewrite, worm
  multi-path burst, canary trip) — they only make sense with the real-time
  monitor feeding them, not on a single file.

Honesty about limits is a hard requirement (see docs/DETECTION_COVERAGE.md):
rootkits and fileless/LOTL malware genuinely cannot be fully detected from
user-mode Python. Those detectors implement only the feasible sliver and say so;
they never claim coverage the architecture can't deliver.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, List, Optional

from ..models import Detection, Severity


class Category(str, Enum):
    """Malware classes. Value is the stable string stored on Detection.category
    and shown in the coverage report."""
    VIRUS = "virus"           # file infectors
    WORM = "worm"             # self-propagating
    TROJAN = "trojan"         # disguised
    RANSOMWARE = "ransomware"  # encrypt-for-extortion
    ROOTKIT = "rootkit"       # stealth (PARTIAL — see coverage doc)
    SPYWARE = "spyware"       # keyloggers/infostealers (PARTIAL)
    ADWARE = "adware"         # PUP/bundleware (low severity)
    FILELESS = "fileless"     # LOTL/script (PARTIAL — later phase)
    WEB = "web"               # download-origin / URL reputation
    GENERIC = "generic"       # uncategorized signature/hash hit


class Sensitivity(str, Enum):
    """Per-detector sensitivity. Behavioral/heuristic signals are inherently
    less precise than hash matching, so every such detector exposes this knob;
    higher = catches more, more false positives."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @classmethod
    def parse(cls, value, default: "Sensitivity" = None) -> "Sensitivity":
        default = default or cls.MEDIUM
        if isinstance(value, cls):
            return value
        try:
            return cls(str(value).lower())
        except ValueError:
            return default


# Category-aware severity policy. A single ransomware/trojan behavioral signal
# weighs FAR more than a single adware signal: adware is a nuisance (report,
# don't aggressively quarantine), ransomware is an emergency. This maps a
# category to the severity a confirmed signal in that category carries, and to a
# default weight for score accumulation.
#
# FP stance per category is documented at each detector; the weights here encode
# the "one weak adware hint must not equal one ransomware behavior" rule.
_SEVERITY: dict = {
    Category.VIRUS:      (Severity.INFECTED, 8.0),
    Category.WORM:       (Severity.SUSPICIOUS, 6.0),
    Category.TROJAN:     (Severity.SUSPICIOUS, 6.0),
    Category.RANSOMWARE: (Severity.INFECTED, 10.0),
    Category.ROOTKIT:    (Severity.SUSPICIOUS, 5.0),
    Category.SPYWARE:    (Severity.SUSPICIOUS, 5.0),
    Category.ADWARE:     (Severity.SUSPICIOUS, 2.0),
    Category.FILELESS:   (Severity.SUSPICIOUS, 5.0),
    Category.WEB:        (Severity.SUSPICIOUS, 4.0),
    Category.GENERIC:    (Severity.INFECTED, 8.0),
}


def default_severity(category: Category) -> Severity:
    return _SEVERITY.get(category, (Severity.SUSPICIOUS, 1.0))[0]


def default_weight(category: Category) -> float:
    return _SEVERITY.get(category, (Severity.SUSPICIOUS, 1.0))[1]


def make_detection(path: str, category: Category, threat: str, source: str,
                   severity: Optional[Severity] = None,
                   sha256: Optional[str] = None,
                   score: Optional[float] = None) -> Detection:
    """Build a Detection with the category's default severity/weight unless the
    caller overrides — so a detector states WHAT it found and the policy decides
    HOW severe by default, in one place."""
    return Detection(
        path=path,
        severity=severity or default_severity(category),
        threat=threat,
        source=source,
        sha256=sha256,
        category=category.value,
        score=score if score is not None else default_weight(category),
    )


@dataclass
class FileContext:
    """Everything a static detector needs about one file, computed ONCE by the
    heuristic engine so detectors never re-read the disk.

    `head` is up to the entropy sample size; `buf` is the whole file when it fit
    the in-memory cap, else None (large file streamed). `is_signed` is a lazy,
    memoized callback (Authenticode is a PowerShell spawn — only pay it if a
    detector actually asks)."""
    path: str
    name: str
    lower: str
    ext: str
    size: int
    head: Optional[bytes]
    buf: Optional[bytes]
    digest: Optional[str]
    is_signed: Callable[[], bool]


class StaticDetector:
    """Base class for a per-file category detector.

    Subclasses set `category`, a config `key`, and implement `check(ctx)`.
    Enable state + sensitivity come from the detector's slice of config
    (`heuristics.detectors.<key>`), so each class is toggled/tuned on its own.
    """
    category: Category = Category.GENERIC
    key: str = "generic"
    default_enabled: bool = True
    default_sensitivity: Sensitivity = Sensitivity.MEDIUM

    def __init__(self, cfg: Optional[dict] = None):
        cfg = cfg or {}
        self.enabled = cfg.get("enabled", self.default_enabled)
        self.sensitivity = Sensitivity.parse(cfg.get("sensitivity"),
                                             self.default_sensitivity)

    def check(self, ctx: FileContext) -> List[Detection]:
        raise NotImplementedError


# Registry key -> the config sub-key controlling every static detector. Each
# detector reads `heuristics.detectors.<key>` for {enabled, sensitivity}, so a
# category is toggled/tuned without touching the others.
def build_static_detectors(cfg: Optional[dict] = None) -> List[StaticDetector]:
    """Instantiate every static (per-file) category detector from config.

    Imports are local so this package's __init__ has no import-time dependency
    on its own submodules (they import back from here)."""
    from .infector import InfectorDetector
    from .pup import PupDetector
    from .rootkit import RootkitDriverDetector
    from .script import FilelessScriptDetector
    from .trojan import TrojanDetector

    per = (cfg or {}).get("detectors", {}) if cfg else {}
    classes = [TrojanDetector, InfectorDetector, PupDetector,
               FilelessScriptDetector, RootkitDriverDetector]
    return [c(per.get(c.key, {})) for c in classes]
