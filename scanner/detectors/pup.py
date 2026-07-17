"""Adware / PUP (potentially unwanted program) detector — name-based.

Deliberately LOW severity: PUPs are a nuisance (toolbars, "PC optimizers",
bundled installers), not an emergency. Category ADWARE weighs 2.0 vs ransomware's
10.0, and maps to SUSPICIOUS — so a hit is reported, never auto-quarantined at
the aggressiveness of a trojan/ransomware. This supplements ClamAV's own PUA
detection (`--detect-pua`, already enabled), it does not replace it.

Signal: a risky installer/executable whose name carries a well-known adware/
bundleware brand or pattern token. FP stance: a bare `setup.exe` is NOT flagged —
that would hit every legitimate installer. A token from the adware list must be
present. Sensitivity HIGH additionally flags generic "bundle/offer" installer
naming, which is noisier.
"""

from __future__ import annotations

from typing import List

from . import Category, FileContext, Sensitivity, StaticDetector, make_detection

# Brand/pattern tokens strongly associated with adware, browser hijackers and
# "system optimizer" PUPs. Lowercased substring match on the filename.
_ADWARE_TOKENS = (
    "toolbar", "webcompanion", "mysearch", "searchprotect", "search-protect",
    "conduit", "babylon", "delta-search", "wajam", "shopperpro", "coupon",
    "pcoptimizer", "pc-optimizer", "pcspeedup", "speedupmypc", "driverupdater",
    "driver-updater", "driverbooster", "registrycleaner", "reimage",
    "onesystemcare", "advancedsystemcare", "wintweak", "systemhealer",
    "adaware", "opencandy", "installcore", "amonetize", "downloadmanager",
)

# Softer "bundler" hints — only at HIGH sensitivity.
_BUNDLER_HINTS = ("_setup_bundle", "offer_install", "sponsored", "adware")


class PupDetector(StaticDetector):
    category = Category.ADWARE
    key = "pup"
    default_enabled = True
    default_sensitivity = Sensitivity.MEDIUM

    def check(self, ctx: FileContext) -> List[Detection]:
        if not self.enabled or ctx.ext not in (".exe", ".msi", ".scr"):
            return []
        for tok in _ADWARE_TOKENS:
            if tok in ctx.lower:
                return [make_detection(
                    ctx.path, Category.ADWARE,
                    f"installer name matches known adware/PUP pattern '{tok}'",
                    "pup", sha256=ctx.digest)]
        if self.sensitivity == Sensitivity.HIGH:
            for tok in _BUNDLER_HINTS:
                if tok in ctx.lower:
                    return [make_detection(
                        ctx.path, Category.ADWARE,
                        f"installer name suggests bundled adware '{tok}'",
                        "pup", sha256=ctx.digest)]
        return []
