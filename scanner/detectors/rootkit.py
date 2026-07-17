"""Rootkit detector — feasible sliver only, with an explicit limitation.

SCOPE HONESTY (repeated at the top on purpose): a real rootkit hides in the
kernel or hooks the OS below the level any user-mode Python process can observe.
This project CANNOT detect an active rootkit's stealth — doing so needs a signed
kernel driver / EDR-class tooling, which is out of scope. See
docs/DETECTION_COVERAGE.md.

What is feasible AT REST, from files on disk: flag a kernel driver (`.sys`) that
sits OUTSIDE the legitimate driver store and is not validly signed. Windows will
not load an unsigned kernel driver on a normal 64-bit install, so an unsigned
`.sys` dropped in a temp/user/download folder is either a failed rootkit install,
a test-signing artifact, or a bring-your-own-vulnerable-driver payload — all
worth flagging for a human to look at.

FP stance: driver-development boxes and some legacy hardware ship unsigned
drivers; hence SUSPICIOUS (never auto-quarantine), category ROOTKIT. The
cross-view directory-listing / hidden-process discrepancy technique is
deliberately NOT implemented here — it needs a running-system view and produces
noise without kernel corroboration; it is documented as out of scope.
"""

from __future__ import annotations

import os
from typing import List

from . import Category, FileContext, StaticDetector, make_detection

# Legitimate homes for kernel drivers (normcased fragments).
_DRIVER_STORE_FRAGMENTS = (
    os.path.normcase(r"\windows\system32\drivers"),
    os.path.normcase(r"\windows\system32\driverstore"),
    os.path.normcase(r"\windows\winsxs"),
    os.path.normcase(r"\windows\system32\driverdata"),
)


class RootkitDriverDetector(StaticDetector):
    category = Category.ROOTKIT
    key = "rootkit_driver"
    default_enabled = True
    # No sensitivity levels: this is a single binary condition (unsigned .sys in
    # the wrong place). Kept simple on purpose.

    def check(self, ctx: FileContext) -> List[Detection]:
        if not self.enabled or ctx.ext != ".sys":
            return []
        npath = os.path.normcase(os.path.abspath(ctx.path))
        if any(frag in npath for frag in _DRIVER_STORE_FRAGMENTS):
            return []
        if ctx.is_signed():
            return []
        return [make_detection(
            ctx.path, Category.ROOTKIT,
            "unsigned kernel driver (.sys) outside the driver store — "
            "possible rootkit / vulnerable-driver payload (at-rest signal only; "
            "active rootkit stealth is out of this tool's scope)",
            "rootkit", sha256=ctx.digest)]
