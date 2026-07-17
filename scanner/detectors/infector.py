"""File-infector / virus detector: appended code (PE overlay) heuristic.

A classic file infector appends its payload after the last section of a host PE,
or a companion/binder tacks a second executable onto the end. Statically we can
spot the *shape*: bytes beyond the end of the last mapped section (the "overlay")
that are large and high-entropy, in a binary that is not validly signed.

FALSE-POSITIVE WARNING (why this is conservative by default): legitimate software
routinely carries a big overlay — installers embed their payload there, and
Authenticode signatures themselves live in the overlay. So this signal alone is
weak. It fires only when ALL of: overlay is a meaningful fraction of the file AND
above an absolute floor AND high-entropy AND the file is unsigned. Even then it
is SUSPICIOUS (category VIRUS is INFECTED by policy, so we downgrade here
explicitly) — a hint to look closer, not a conviction. Sensitivity tunes the
overlay-fraction threshold. Hash/YARA remain the authoritative infector signals;
this only adds shape-based coverage for variants with no signature yet.
"""

from __future__ import annotations

import struct
from typing import List, Optional

from ..models import Severity
from . import Category, FileContext, Sensitivity, StaticDetector, make_detection

# Overlay must be at least this many bytes to bother (below this it's padding /
# a cert, not an appended executable payload).
_MIN_OVERLAY_BYTES = 64 * 1024
_HIGH_ENTROPY = 7.0

# Overlay-as-fraction-of-file threshold per sensitivity. Higher sensitivity =
# smaller overlay fraction triggers = more FPs.
_FRACTION = {
    Sensitivity.LOW: 0.60,
    Sensitivity.MEDIUM: 0.40,
    Sensitivity.HIGH: 0.20,
}


def end_of_last_section(data: bytes) -> Optional[int]:
    """File offset where the last PE section's raw data ends, or None if `data`
    is not a parseable PE header. Pure-stdlib, bounds-checked — never raises on
    a truncated/garbage file (returns None instead)."""
    try:
        if len(data) < 0x40 or data[:2] != b"MZ":
            return None
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return None
        coff = e_lfanew + 4
        num_sections = struct.unpack_from("<H", data, coff + 2)[0]
        opt_size = struct.unpack_from("<H", data, coff + 16)[0]
        sect_table = coff + 20 + opt_size
        if num_sections == 0 or num_sections > 96:      # PE cap is 96 sections
            return None
        end = 0
        for i in range(num_sections):
            off = sect_table + i * 40
            if off + 40 > len(data):
                return None
            raw_size = struct.unpack_from("<I", data, off + 16)[0]
            raw_ptr = struct.unpack_from("<I", data, off + 20)[0]
            if raw_ptr:                                  # 0 = uninitialized data
                end = max(end, raw_ptr + raw_size)
        return end or None
    except struct.error:
        return None


class InfectorDetector(StaticDetector):
    category = Category.VIRUS
    key = "infector"
    default_enabled = True
    default_sensitivity = Sensitivity.LOW      # conservative: overlays are common

    def check(self, ctx: FileContext) -> List[Detection]:
        if not self.enabled or ctx.size < _MIN_OVERLAY_BYTES:
            return []
        header = ctx.buf or ctx.head
        if not header or header[:2] != b"MZ":
            return []
        sect_end = end_of_last_section(header)
        if not sect_end or sect_end >= ctx.size:
            return []
        overlay = ctx.size - sect_end
        frac = overlay / ctx.size
        if overlay < _MIN_OVERLAY_BYTES or frac < _FRACTION[self.sensitivity]:
            return []
        # Entropy of what we can see of the overlay region (from the buffered
        # bytes when available). No buffer -> assume worst case only if the
        # header sample already reaches into the overlay.
        sample = None
        if ctx.buf and len(ctx.buf) > sect_end:
            sample = ctx.buf[sect_end:sect_end + 65536]
        if sample is not None:
            from ..heuristics import shannon_entropy   # lazy: avoid import cycle
            if shannon_entropy(sample) < _HIGH_ENTROPY:
                return []
        if ctx.is_signed():          # a big overlay on signed software is normal
            return []
        return [make_detection(
            ctx.path, Category.VIRUS,
            f"large high-entropy appended data after PE sections "
            f"({overlay // 1024} KB overlay, {int(frac * 100)}% of file) — "
            f"possible file-infector/binder",
            "infector", severity=Severity.SUSPICIOUS, sha256=ctx.digest)]
