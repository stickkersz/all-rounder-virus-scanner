"""Trojan detector: binaries disguised as legitimate Windows system processes.

Two signals, gated by sensitivity:

* **Impersonation by location** — a file with the EXACT name of a Windows system
  binary (svchost.exe, lsass.exe, ...) living OUTSIDE a real system directory,
  and not validly signed. The genuine binary only ever lives in System32 /
  SysWOW64 / WinSxS; a copy in Downloads or a temp dir claiming that name is the
  classic trojan disguise. (LOW sensitivity and up.)
* **Typosquatted name** — a look-alike of a system name (svch0st.exe, scvhost.exe,
  lsas.exe): leetspeak substitution or edit-distance 1. (MEDIUM sensitivity and
  up — noisier, so off at LOW.)

False-positive stance: the location signal is low-FP (a legit signed copy is
exempted, and portable apps rarely name themselves `svchost.exe`). The typosquat
signal is higher-FP (an unrelated tool could be one edit away from a system
name), so it is SUSPICIOUS only and disabled at LOW sensitivity. Category is
TROJAN → SUSPICIOUS by policy, i.e. reported, not auto-quarantined.
"""

from __future__ import annotations

import os
from typing import List

from ..models import Detection, Severity
from . import Category, FileContext, Sensitivity, StaticDetector, make_detection

# Windows binaries most often impersonated. Stored as lowercase stems (no .exe).
SYSTEM_PROCESS_STEMS = frozenset({
    "svchost", "lsass", "csrss", "services", "winlogon", "smss", "wininit",
    "explorer", "spoolsv", "taskhostw", "conhost", "dwm", "rundll32",
    "ctfmon", "dllhost", "sihost", "runtimebroker",
})

# Real homes of these binaries (normcased fragments). A same-named file NOT
# under one of these is impersonating by location.
_SYSTEM_DIR_FRAGMENTS = (
    os.path.normcase(r"\windows\system32"),
    os.path.normcase(r"\windows\syswow64"),
    os.path.normcase(r"\windows\winsxs"),
)

# Leetspeak / homoglyph folding so svch0st -> svchost, win1ogon -> winlogon.
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a",
                       "5": "s", "7": "t", "$": "s", "|": "l"})


def _within_edit_distance_1(a: str, b: str) -> bool:
    """True if a and b differ by at most one insertion/deletion/substitution.
    Cheap early-outs keep this off the hot path for obviously different names."""
    if a == b:
        return True
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:                                   # one substitution
        return sum(1 for x, y in zip(a, b) if x != y) == 1
    # one indel: the shorter must be the longer with one char removed
    if la > lb:
        a, b, la, lb = b, a, lb, la
    i = j = 0
    edited = False
    while i < la and j < lb:
        if a[i] != b[j]:
            if edited:
                return False
            edited = True
            j += 1
        else:
            i += 1
            j += 1
    return True


def _looks_like(folded: str, real: str) -> bool:
    """Typosquat test (Damerau distance <= 1): a leetspeak-folded name that
    equals or is one edit — including one adjacent transposition (scvhost vs
    svchost) — away from a real system name."""
    if _within_edit_distance_1(folded, real):
        return True
    if len(folded) == len(real):
        diffs = [i for i in range(len(folded)) if folded[i] != real[i]]
        if (len(diffs) == 2 and diffs[1] == diffs[0] + 1
                and folded[diffs[0]] == real[diffs[1]]
                and folded[diffs[1]] == real[diffs[0]]):
            return True                            # adjacent swap
    return False


class TrojanDetector(StaticDetector):
    category = Category.TROJAN
    key = "trojan"
    default_enabled = True
    default_sensitivity = Sensitivity.MEDIUM

    def check(self, ctx: FileContext) -> List[Detection]:
        if not self.enabled or ctx.ext not in (".exe", ".scr", ".com"):
            return []
        stem = os.path.splitext(ctx.lower)[0]
        npath = os.path.normcase(os.path.abspath(ctx.path))

        # Signal 1: exact system name in the wrong place, unsigned.
        if stem in SYSTEM_PROCESS_STEMS:
            in_system_dir = any(frag in npath for frag in _SYSTEM_DIR_FRAGMENTS)
            if not in_system_dir and not ctx.is_signed():
                return [make_detection(
                    ctx.path, Category.TROJAN,
                    f"system process name '{ctx.name}' outside a system "
                    f"directory and unsigned (impersonation)",
                    "trojan", sha256=ctx.digest)]
            return []

        # Signal 2 (MEDIUM+): typosquat of a system name.
        if self.sensitivity == Sensitivity.LOW:
            return []
        folded = stem.translate(_LEET)
        for real in SYSTEM_PROCESS_STEMS:
            if _looks_like(folded, real):
                return [make_detection(
                    ctx.path, Category.TROJAN,
                    f"executable name '{ctx.name}' mimics system process "
                    f"'{real}.exe' (possible trojan disguise)",
                    "trojan", severity=Severity.SUSPICIOUS, sha256=ctx.digest)]
        return []
