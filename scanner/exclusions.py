"""Config-driven scan exclusions.

Full-disk scanning makes exclusions load-bearing: a Full scan that walks every
Steam library, node_modules tree and VM disk image takes hours and finds
nothing. Excluded directories are pruned during the walk (never descended into),
so the cost of a skipped tree is one comparison, not a traversal.

Pattern forms, matched case-insensitively on Windows:

  C:\\Windows\\WinSxS     absolute path  -> that directory and everything under it
  \\Windows\\WinSxS       driveless      -> same, on EVERY drive letter
  *.iso                   wildcard       -> matches full path or bare filename
  node_modules            bare name      -> any file/dir with that name, any depth

Only `*` and `?` are wildcard characters; `[` is a literal (legal in Windows
filenames like "D:\\VMs [old]"). Note `*` also spans separators, so `*/cache/*`
matches at any depth.

SECURITY: an exclusion is a hole in coverage — an excluded path is not scanned
by any layer. Exclude directories you control, never user-writable drop targets
(Downloads, Temp, %AppData%). Nothing is excluded by default.
"""

from __future__ import annotations

import fnmatch
import os
from typing import Iterable, List, Tuple

from .paths import is_under, norm_for_match

# Wildcards that make a pattern a glob. Deliberately NOT '[': fnmatch treats it
# as a character class, but it is a legal Windows filename character — a literal
# path like "D:\VMs [old]" must stay a prefix rule or it silently stops
# matching.
_MAGIC = ("*", "?")

# How a pattern is interpreted.
_PREFIX = "prefix"   # absolute literal -> the path and its whole subtree
_GLOB = "glob"       # wildcard -> full path or bare filename
_NAME = "name"       # bare literal -> basename at any depth


def _norm_pattern(pattern: str) -> str:
    """Pattern-side normalization. Unlike norm_for_match this must NOT
    absolutize — a bare name like 'node_modules' would become CWD-relative."""
    return os.path.normcase(pattern.strip()).replace("\\", "/").rstrip("/")


def _classify(pat: str) -> str:
    if any(m in pat for m in _MAGIC):
        return _GLOB
    # "/..." (driveless) and "c:/..." are both subtree prefixes; ":" catches
    # the drive form after normcase.
    if pat.startswith("/") or ":" in pat[:2]:
        return _PREFIX
    return _NAME


def _matches(kind: str, pat: str, path: str, base: str) -> bool:
    if kind == _PREFIX:
        if is_under(path, pat):
            return True
        # Driveless pattern ("/windows/winsxs") means "on any drive": compare
        # against the path with its drive letter stripped, else the pattern
        # can never match on Windows (paths normalize to "c:/...") while
        # silently working on the POSIX dev boxes — a deployment-only no-op.
        if pat.startswith("/") and len(path) > 2 and path[1] == ":":
            return is_under(path[2:], pat)
        return False
    if kind == _NAME:
        return base == pat
    return fnmatch.fnmatchcase(path, pat) or fnmatch.fnmatchcase(base, pat)


class ExclusionMatcher:
    """Decides whether a path is excluded from scanning.

    Empty pattern list => matches nothing (`excludes()` is always False), which
    is the default: users opt into exclusions, they are never implicit.
    """

    def __init__(self, patterns: Iterable[str] | None = None):
        self.rules: List[Tuple[str, str]] = []
        for raw in patterns or []:
            pat = _norm_pattern(str(raw))
            if pat:
                self.rules.append((_classify(pat), pat))

    @property
    def active(self) -> bool:
        return bool(self.rules)

    def excludes(self, path: str) -> bool:
        """True if `path` (file or directory) is excluded."""
        if not self.rules:
            return False
        p = norm_for_match(path)
        base = p.rsplit("/", 1)[-1]
        return any(_matches(k, pat, p, base) for k, pat in self.rules)

    def for_explicit_root(self, root: str) -> "ExclusionMatcher":
        """A copy adjusted for a root the USER explicitly asked to scan.

        If the user runs `scan D:\\VMs` while a rule covers `D:\\VMs`, honoring
        it would walk nothing and report "0 files, CLEAN" — a false all-clear,
        the worst outcome for a scanner. So rules that blanket the requested
        subtree (prefix rules covering the root, and globs matching the root's
        full path) are dropped for this walk.

        NAME rules are always kept: a name rule matching the root's own
        basename (scanning `...\\node_modules` with rule `node_modules`) never
        excludes the root's children by itself, but deeper same-name dirs must
        still prune — dropping it would silently deep-scan every nested
        node_modules tree.
        """
        p = norm_for_match(root)
        base = p.rsplit("/", 1)[-1]
        kept = ExclusionMatcher()
        kept.rules = [
            (k, pat) for k, pat in self.rules
            if k == _NAME or not _matches(k, pat, p, base)
        ]
        return kept
