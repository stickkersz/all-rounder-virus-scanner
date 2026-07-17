"""Web protection: threat-intel feeds + download-origin checking.

Downloads-folder scanning itself is the realtime monitor (scanner/realtime.py)
watching Downloads; this module adds the web-specific intelligence on top:

1. **Feed sync** (`usbscan feeds`): download URL blocklists from URLhaus
   (abuse.ch — free for any use, no API key) into a local feeds directory.
   Everything works offline after a sync; no lookup leaves the machine.
2. **Download-origin check**: Windows tags every downloaded file with a
   Zone.Identifier alternate data stream (Mark of the Web) recording the
   source URL. If that URL is in the URLhaus feed, the file came from a known
   malware-distribution URL — flagged even when the payload itself is new
   enough to have no signature.
3. **Google Safe Browsing** (optional, off by default): checks origin URLs via
   the Lookup API. Requires an API key the admin registers themselves, and
   sends the URLs to Google — a privacy tradeoff the config documents.

False-positive stance: an origin-URL match flags SUSPICIOUS, never INFECTED —
the URL being malicious is strong evidence but the file content is unproven
(renamed/re-served files), so origin alone must not auto-quarantine.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import urllib.request
from typing import Dict, Iterable, List, Optional, Set

from .models import Detection, Severity
from .paths import resolve_under_base

# Cap feed downloads so a misconfigured URL can't fill the disk.
_MAX_FEED_BYTES = 100 * 1024 * 1024
_UA = "AllRoundVirusScanner-feeds/1.0"


# ---- Mark of the Web (Zone.Identifier ADS) --------------------------------
def parse_zone_identifier(text: str) -> Dict[str, str]:
    """Parse the INI-ish Zone.Identifier stream. Documented keys: ZoneId
    (3 = Internet), ReferrerUrl, HostUrl (the actual download URL)."""
    out: Dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip()
    return out


def read_motw(path: str) -> Optional[Dict[str, str]]:
    """Read a file's Mark of the Web. None when absent or off-Windows.

    The ADS is opened via the documented `file:Zone.Identifier` syntax; a
    file that was never downloaded has no stream and the open just fails.
    """
    if sys.platform != "win32":
        return None
    try:
        with open(path + ":Zone.Identifier", "r", encoding="utf-8",
                  errors="ignore") as fh:
            return parse_zone_identifier(fh.read(4096))
    except OSError:
        return None


def _norm_url(url: str) -> str:
    return url.strip().rstrip("/").lower()


# ---- URL reputation (offline, feed-backed) ---------------------------------
def feed_signature(feeds_dir: Optional[str], suffix: str) -> tuple:
    """(name, mtime, size) for each matching feed file — cheap change check.

    The daily sync task rewrites these files while `usbscan monitor` and the
    GUI run for weeks. Without a change check they'd keep using the snapshot
    taken at logon, so "updated daily" intel would really be "as of last
    reboot".
    """
    if not feeds_dir or not os.path.isdir(feeds_dir):
        return ()
    out = []
    try:
        for name in sorted(os.listdir(feeds_dir)):
            if not name.endswith(suffix):
                continue
            try:
                st = os.stat(os.path.join(feeds_dir, name))
            except OSError:
                continue
            out.append((name, st.st_mtime_ns, st.st_size))
    except OSError:
        return ()
    return tuple(out)


class UrlReputation:
    """Exact-URL matching against synced feed files (*.urls.txt).

    Deliberately exact-URL only, not host-level: a compromised site serves
    malicious and legitimate files from the same host, so host-level matching
    would flag every download from a big hacked CDN — too FP-prone to default.
    """

    def __init__(self, urls: Iterable[str] = ()):
        self.urls: Set[str] = {_norm_url(u) for u in urls if u.strip()}

    @classmethod
    def load(cls, feeds_dir: Optional[str]) -> "UrlReputation":
        urls: List[str] = []
        if feeds_dir and os.path.isdir(feeds_dir):
            for name in os.listdir(feeds_dir):
                if not name.endswith(".urls.txt"):
                    continue
                try:
                    with open(os.path.join(feeds_dir, name), "r",
                              encoding="utf-8", errors="ignore") as fh:
                        for line in fh:
                            line = line.strip()
                            if line and not line.startswith("#"):
                                urls.append(line)
                except OSError:
                    continue
        return cls(urls)

    def check(self, url: Optional[str]) -> Optional[str]:
        if url and _norm_url(url) in self.urls:
            return "download origin is a known malware-distribution URL (URLhaus)"
        return None

    def __len__(self) -> int:
        return len(self.urls)


# ---- Google Safe Browsing (optional, needs admin-registered key) -----------
class SafeBrowsingClient:
    """Minimal Lookup API v4 client. Disabled without an API key.

    Fail-open by design: a network error disables the client for the rest of
    the session instead of stalling every file scan on a dead endpoint. It
    adds detections, never suppresses any — so failing open cannot hide a
    hit from the offline layers.
    """

    ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    # Bound the cache: `monitor` runs for weeks, so an unbounded dict keyed by
    # every URL ever seen is a slow leak. Verdicts also go stale — a URL that
    # was clean last month may be flagged now — so dropping them is correct,
    # not just smaller.
    CACHE_MAX = 4096
    CACHE_TTL_SECONDS = 6 * 3600

    def __init__(self, api_key: str = "", timeout: float = 3.0,
                 clock=time.monotonic):
        self.api_key = (api_key or "").strip()
        self.timeout = timeout
        self.clock = clock
        self._cache: Dict[str, tuple] = {}      # url -> (verdict, stamp)
        self._broken = False

    @property
    def enabled(self) -> bool:
        return bool(self.api_key) and not self._broken

    def check(self, url: Optional[str]) -> Optional[str]:
        if not url or not self.enabled:
            return None
        key = _norm_url(url)
        hit = self._cache.get(key)
        if hit is not None:
            verdict, stamp = hit
            if self.clock() - stamp < self.CACHE_TTL_SECONDS:
                return verdict
            del self._cache[key]                # stale -> re-check
        body = json.dumps({
            "client": {"clientId": "all-round-virus-scanner",
                       "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING",
                                "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{self.ENDPOINT}?key={self.api_key}", data=body,
            headers={"Content-Type": "application/json", "User-Agent": _UA})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read(1 << 20).decode("utf-8"))
        except Exception:
            self._broken = True     # don't stall every subsequent file
            return None
        threat = None
        for m in payload.get("matches", []):
            threat = m.get("threatType", "MALWARE")
            break
        verdict = (f"download origin flagged by Google Safe Browsing "
                   f"({threat})") if threat else None
        if len(self._cache) >= self.CACHE_MAX:
            self._cache.clear()
        self._cache[key] = (verdict, self.clock())
        return verdict


# ---- the per-file check the engine calls -----------------------------------
class WebProtection:
    def __init__(self, cfg: dict, base_dir: str):
        self.cfg = cfg or {}
        self.enabled = self.cfg.get("check_download_origin", True)
        self.feeds_dir = resolve_under_base(base_dir, self.cfg.get("feeds_dir"))
        self.rep = UrlReputation()
        self._sig = None            # feed-file signature the set was built from
        self.sb = SafeBrowsingClient(self.cfg.get("safe_browsing_api_key", ""))
        if self.enabled:
            self.reload_if_changed()

    def reload_if_changed(self) -> bool:
        """Re-read the URL feeds when the sync task has rewritten them.

        Called once per scan batch — a handful of stats, not a re-parse — so a
        monitor started at logon still picks up today's intel.
        """
        if not self.enabled:
            return False
        sig = feed_signature(self.feeds_dir, ".urls.txt")
        if sig == self._sig:
            return False
        self._sig = sig
        self.rep = UrlReputation.load(self.feeds_dir)
        return True

    @property
    def active(self) -> bool:
        """Anything to do at scan time? Needs the toggle AND at least one
        source of verdicts (a synced feed or a Safe Browsing key)."""
        return self.enabled and (len(self.rep) > 0 or self.sb.enabled)

    def check_file(self, path: str) -> List[Detection]:
        """Origin check for one file. Cheap: one ADS open; no file-content
        read. Caller gates on risky extensions so a full-disk scan doesn't
        pay an extra open() per media file."""
        motw = read_motw(path)
        if not motw:
            return []
        url = motw.get("HostUrl") or motw.get("ReferrerUrl")
        if not url:
            return []
        reason = self.rep.check(url) or self.sb.check(url)
        if reason:
            return [Detection(path, Severity.SUSPICIOUS,
                              f"{reason} [{url}]", "web")]
        return []


# ---- feed sync (usbscan feeds) ---------------------------------------------
def sync_feeds(cfg: dict, base_dir: str) -> List[str]:
    """Download configured threat-intel feeds. Returns human-readable status
    lines. Atomic per feed: a failed download leaves the previous file intact.
    """
    feeds = cfg.get("feeds") or []
    feeds_dir = resolve_under_base(base_dir, cfg.get("feeds_dir"))
    if not feeds:
        return ["No feeds configured (web.feeds in config.yaml)."]
    os.makedirs(feeds_dir, exist_ok=True)

    lines: List[str] = []
    for feed in feeds:
        name = feed.get("name", "feed")
        url = feed.get("url", "")
        ftype = feed.get("type", "urls")
        if ftype not in ("urls", "sha256"):
            lines.append(f"[skip] {name}: unknown type {ftype!r}")
            continue
        dest = os.path.join(feeds_dir, f"{name}.{ftype}.txt")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": _UA})
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = resp.read(_MAX_FEED_BYTES + 1)
            if len(data) > _MAX_FEED_BYTES:
                lines.append(f"[fail] {name}: response exceeds "
                             f"{_MAX_FEED_BYTES // (1024*1024)} MB cap")
                continue
            fd, tmp = tempfile.mkstemp(dir=feeds_dir, prefix=f".{name}.")
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            os.replace(tmp, dest)
            n = sum(1 for ln in data.splitlines()
                    if ln.strip() and not ln.startswith(b"#"))
            lines.append(f"[ok]   {name}: {n} entries -> {dest}")
        except Exception as exc:
            lines.append(f"[fail] {name}: {exc}")
    return lines
