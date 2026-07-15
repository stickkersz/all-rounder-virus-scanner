"""Heuristic + hash + YARA detection layer.

Runs alongside ClamAV. Catches USB-specific tricks (autorun.inf, double
extensions, LNK droppers) and matches against a company hash blocklist and
optional YARA rules — useful for zero-days ClamAV has no signature for yet.
"""

from __future__ import annotations

import hashlib
import os
from typing import List, Optional, Set

from .models import Detection, Severity

try:
    import yara  # type: ignore
    _HAS_YARA = True
except Exception:  # pragma: no cover - optional dependency
    yara = None
    _HAS_YARA = False


def sha256_of(path: str, chunk: int = 1 << 20) -> Optional[str]:
    """Streamed SHA-256 so multi-GB files don't blow up memory."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for block in iter(lambda: fh.read(chunk), b""):
                h.update(block)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


class HeuristicEngine:
    def __init__(self, cfg: dict, base_dir: str):
        self.cfg = cfg
        self.base_dir = base_dir
        self.enabled = cfg.get("enabled", True)
        self.suspicious_ext: Set[str] = {
            e.lower() for e in cfg.get("suspicious_extensions", [])
        }
        self.flag_autorun = cfg.get("flag_autorun_inf", True)
        self.flag_double = cfg.get("flag_double_extension", True)
        # Fast-mode gating: only read+hash+YARA files that are either a risky
        # type or small. Skips the expensive content read on big media/data
        # files that are extremely unlikely to be executable malware.
        self.deep_scan_all = cfg.get("deep_scan_all", False)
        self.deep_scan_max_bytes = int(cfg.get("deep_scan_max_mb", 50)) * 1024 * 1024
        self._hashes: Set[str] = self._load_hashes(cfg.get("hash_blocklist"))
        self._yara_rules = self._load_yara(cfg.get("yara_rules_dir"))

    # ---- loading -------------------------------------------------------
    def _resolve(self, rel: Optional[str]) -> Optional[str]:
        if not rel:
            return None
        return rel if os.path.isabs(rel) else os.path.join(self.base_dir, rel)

    def _load_hashes(self, rel: Optional[str]) -> Set[str]:
        path = self._resolve(rel)
        hashes: Set[str] = set()
        if not path or not os.path.isfile(path):
            return hashes
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                token = line.split("#", 1)[0].strip().lower()
                if len(token) == 64 and all(c in "0123456789abcdef" for c in token):
                    hashes.add(token)
        return hashes

    def _load_yara(self, rel: Optional[str]):
        if not _HAS_YARA:
            return None
        path = self._resolve(rel)
        if not path or not os.path.isdir(path):
            return None
        filepaths = {}
        for name in os.listdir(path):
            if name.lower().endswith((".yar", ".yara")):
                filepaths[name] = os.path.join(path, name)
        if not filepaths:
            return None
        try:
            return yara.compile(filepaths=filepaths)
        except yara.Error:
            return None

    def _needs_deep_scan(self, ext: str, size: int) -> bool:
        """Whether to read file bytes for hash/YARA. Risky types always; other
        files only if small enough (fast mode) or if deep_scan_all is set."""
        if self.deep_scan_all:
            return True
        if ext in self.suspicious_ext:
            return True
        return size <= self.deep_scan_max_bytes

    # ---- scanning ------------------------------------------------------
    def scan_file(self, path: str, size: int = 0) -> List[Detection]:
        if not self.enabled:
            return []
        out: List[Detection] = []
        name = os.path.basename(path)
        lower = name.lower()
        ext = os.path.splitext(lower)[1]

        # autorun.inf on removable media = classic worm autostart vector
        if self.flag_autorun and lower == "autorun.inf":
            out.append(Detection(path, Severity.SUSPICIOUS,
                                 "autorun.inf present (USB autostart vector)",
                                 "heuristic"))

        # double extension e.g. invoice.pdf.exe
        if self.flag_double and ext in self.suspicious_ext:
            stem = os.path.splitext(lower)[0]
            inner_ext = os.path.splitext(stem)[1]
            benign = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg",
                      ".png", ".txt", ".zip", ".rar"}
            if inner_ext in benign:
                out.append(Detection(path, Severity.SUSPICIOUS,
                                     f"double extension '{inner_ext}{ext}'",
                                     "heuristic"))

        # hash blocklist + YARA need the bytes — the expensive part. Skip on big
        # non-risky files so slow disks aren't hammered reading movies/backups.
        if not ((self._hashes or self._yara_rules)
                and self._needs_deep_scan(ext, size)):
            return out

        # compute hash once, shared by blocklist match + YARA metadata
        digest = sha256_of(path) if self._hashes else None

        if digest and digest in self._hashes:
            out.append(Detection(path, Severity.INFECTED,
                                 "matched company hash blocklist",
                                 "hash", sha256=digest))

        if self._yara_rules is not None:
            try:
                matches = self._yara_rules.match(path)
                for m in matches:
                    out.append(Detection(path, Severity.INFECTED,
                                         f"YARA:{m.rule}", "yara", sha256=digest))
            except Exception:
                pass

        return out
