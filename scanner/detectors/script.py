"""Fileless / living-off-the-land detector — STATIC sliver only.

SCOPE HONESTY: true fileless/LOTL malware runs in memory via
PowerShell/WMI/script hosts with no malicious file on disk, and catching it
needs process-tree and command-line monitoring (parent/child relationships,
AMSI, ETW) that a user-mode file scanner does not have. See
docs/DETECTION_COVERAGE.md — full fileless detection is OUT OF SCOPE / later
phase. What IS feasible here: flag script FILES on disk that carry the textbook
LOTL launcher patterns (encoded PowerShell, download-and-execute one-liners),
because those frequently get dropped as .ps1/.bat/.hta droppers.

FP stance: admins legitimately use `Invoke-WebRequest`, base64, and `iex`. So a
single weak token is not enough — a detection needs either one HIGH-confidence
pattern (an encoded-command switch, or download+execute in one line) or, at
higher sensitivity, several softer tokens together. Category FILELESS →
SUSPICIOUS (report, don't quarantine).
"""

from __future__ import annotations

import re
from typing import List

from . import Category, FileContext, Sensitivity, StaticDetector, make_detection

_SCRIPT_EXTS = (".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js",
                ".jse", ".hta", ".wsf")

# High-confidence: on their own these are strong LOTL launcher tells.
_STRONG = (
    re.compile(r"-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/]{40,}={0,2}", re.I),  # -enc <b64>
    re.compile(r"frombase64string", re.I),
    re.compile(r"(downloadstring|downloadfile)\s*\(", re.I),
    re.compile(r"iex\s*\(\s*(new-object|iwr|invoke-webrequest)", re.I),
    re.compile(r"-nop\w*\s+-w\w*\s+hidden", re.I),        # -nop -w hidden
)
# Softer tokens — only accumulate at MEDIUM/HIGH.
_SOFT = (
    re.compile(r"invoke-expression", re.I),
    re.compile(r"invoke-webrequest|iwr\b", re.I),
    re.compile(r"new-object\s+net\.webclient", re.I),
    re.compile(r"bypass\b", re.I),
    re.compile(r"hidden\b", re.I),
    re.compile(r"start-process", re.I),
)

# How many soft tokens constitute a hit, per sensitivity.
_SOFT_THRESHOLD = {Sensitivity.LOW: 99, Sensitivity.MEDIUM: 3, Sensitivity.HIGH: 2}


class FilelessScriptDetector(StaticDetector):
    category = Category.FILELESS
    key = "fileless_script"
    default_enabled = True
    default_sensitivity = Sensitivity.MEDIUM

    def check(self, ctx: FileContext) -> List[Detection]:
        if not self.enabled or ctx.ext not in _SCRIPT_EXTS:
            return []
        raw = ctx.buf if ctx.buf is not None else ctx.head
        if not raw:
            return []
        try:
            text = raw.decode("utf-8", "ignore")
        except Exception:
            return []

        for pat in _STRONG:
            if pat.search(text):
                return [make_detection(
                    ctx.path, Category.FILELESS,
                    "script contains a living-off-the-land launcher pattern "
                    f"({pat.pattern.split(chr(92))[0][:24]}...)",
                    "fileless", sha256=ctx.digest)]

        threshold = _SOFT_THRESHOLD[self.sensitivity]
        hits = sum(1 for pat in _SOFT if pat.search(text))
        if hits >= threshold:
            return [make_detection(
                ctx.path, Category.FILELESS,
                f"script combines {hits} suspicious LOTL indicators "
                "(download/execute/hidden)",
                "fileless", sha256=ctx.digest)]
        return []
