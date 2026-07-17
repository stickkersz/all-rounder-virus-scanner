"""Web protection: MOTW parsing, URL reputation, feed sync, Safe Browsing.

All network access is mocked (spec §7); only EICAR-class/safe fixtures. The
"malicious" URLs here are RFC 2606 reserved example domains — never real.
"""

import io
import os
import urllib.request

import pytest

from scanner import web
from scanner.engine import ScanEngine
from scanner.models import Severity
from scanner.web import (SafeBrowsingClient, UrlReputation,
                         parse_zone_identifier, sync_feeds)

BAD_URL = "http://malware.example.com/payload.exe"


# ---- Zone.Identifier parsing ----------------------------------------------
def test_parse_zone_identifier_full():
    text = ("[ZoneTransfer]\r\nZoneId=3\r\n"
            "ReferrerUrl=http://example.com/page\r\n"
            f"HostUrl={BAD_URL}\r\n")
    z = parse_zone_identifier(text)
    assert z["ZoneId"] == "3"
    assert z["HostUrl"] == BAD_URL
    assert z["ReferrerUrl"] == "http://example.com/page"


def test_parse_zone_identifier_minimal():
    z = parse_zone_identifier("[ZoneTransfer]\nZoneId=3\n")
    assert z["ZoneId"] == "3" and "HostUrl" not in z


def test_read_motw_none_off_windows(tmp_path):
    p = tmp_path / "f.exe"
    p.write_bytes(b"MZ")
    if os.name != "nt":
        assert web.read_motw(str(p)) is None


# ---- URL reputation ---------------------------------------------------------
def test_reputation_exact_match():
    rep = UrlReputation([BAD_URL])
    assert rep.check(BAD_URL)
    assert rep.check(BAD_URL + "/") is not None      # trailing slash normalized
    assert rep.check("http://clean.example.com/x") is None
    assert rep.check(None) is None


def test_reputation_no_host_level_matching():
    """Same host, different path: NOT flagged — host-level matching would
    flag every download from any compromised CDN (FP tradeoff, module doc)."""
    rep = UrlReputation([BAD_URL])
    assert rep.check("http://malware.example.com/other.exe") is None


def test_reputation_loads_feed_files(tmp_path):
    (tmp_path / "urlhaus.urls.txt").write_text(
        f"# comment\n{BAD_URL}\n\nhttp://two.example.com/a\n")
    (tmp_path / "notafeed.txt").write_text("http://ignored.example.com/x\n")
    rep = UrlReputation.load(str(tmp_path))
    assert len(rep) == 2
    assert rep.check(BAD_URL)
    assert rep.check("http://ignored.example.com/x") is None


def test_reputation_missing_dir_is_empty():
    rep = UrlReputation.load("/nonexistent-feeds-dir")
    assert len(rep) == 0 and rep.check(BAD_URL) is None


# ---- feed sync --------------------------------------------------------------
class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _web_cfg(tmp_path):
    return {"feeds_dir": str(tmp_path / "feeds"),
            "feeds": [{"name": "urlhaus",
                       "url": "https://urlhaus.abuse.ch/downloads/text_online/",
                       "type": "urls"}]}


def test_sync_feeds_writes_file(tmp_path, monkeypatch):
    monkeypatch.setattr(urllib.request, "urlopen",
                        lambda req, timeout=0: FakeResponse(
                            f"# header\n{BAD_URL}\n".encode()))
    lines = sync_feeds(_web_cfg(tmp_path), str(tmp_path))
    assert lines and lines[0].startswith("[ok]")
    dest = tmp_path / "feeds" / "urlhaus.urls.txt"
    assert BAD_URL in dest.read_text()
    assert "1 entries" in lines[0]                  # comment line not counted


def test_sync_feeds_failure_keeps_old_file(tmp_path, monkeypatch):
    feeds = tmp_path / "feeds"
    feeds.mkdir()
    old = feeds / "urlhaus.urls.txt"
    old.write_text("http://old.example.com/keep\n")

    def boom(req, timeout=0):
        raise OSError("network down")
    monkeypatch.setattr(urllib.request, "urlopen", boom)
    lines = sync_feeds(_web_cfg(tmp_path), str(tmp_path))
    assert lines[0].startswith("[fail]")
    assert old.read_text() == "http://old.example.com/keep\n"   # untouched


def test_sync_feeds_rejects_unknown_type(tmp_path):
    cfg = {"feeds_dir": str(tmp_path / "f"),
           "feeds": [{"name": "x", "url": "http://e", "type": "exe"}]}
    lines = sync_feeds(cfg, str(tmp_path))
    assert lines[0].startswith("[skip]")


def test_sync_feeds_none_configured(tmp_path):
    lines = sync_feeds({"feeds": [], "feeds_dir": str(tmp_path)}, str(tmp_path))
    assert "No feeds configured" in lines[0]


# ---- Safe Browsing client ---------------------------------------------------
def test_safe_browsing_disabled_without_key():
    sb = SafeBrowsingClient("")
    assert not sb.enabled
    assert sb.check(BAD_URL) is None


def test_safe_browsing_match(monkeypatch):
    sb = SafeBrowsingClient("test-key")
    monkeypatch.setattr(urllib.request, "urlopen",
                        lambda req, timeout=0: FakeResponse(
                            b'{"matches": [{"threatType": "MALWARE"}]}'))
    verdict = sb.check(BAD_URL)
    assert verdict and "Safe Browsing" in verdict and "MALWARE" in verdict


def test_safe_browsing_clean(monkeypatch):
    sb = SafeBrowsingClient("test-key")
    monkeypatch.setattr(urllib.request, "urlopen",
                        lambda req, timeout=0: FakeResponse(b"{}"))
    assert sb.check(BAD_URL) is None


def test_safe_browsing_fails_open_and_stops_calling(monkeypatch):
    sb = SafeBrowsingClient("test-key")
    calls = []

    def boom(req, timeout=0):
        calls.append(1)
        raise OSError("timeout")
    monkeypatch.setattr(urllib.request, "urlopen", boom)
    assert sb.check(BAD_URL) is None
    assert sb.check("http://other.example.com/b.exe") is None
    assert len(calls) == 1                 # broken -> no further network calls
    assert not sb.enabled


# ---- engine integration ------------------------------------------------------
def _engine_with_feed(config, tmp_path, feed_urls):
    feeds = tmp_path / "feeds"
    feeds.mkdir(exist_ok=True)
    (feeds / "urlhaus.urls.txt").write_text("\n".join(feed_urls) + "\n")
    config.data["web"] = {"check_download_origin": True,
                          "feeds_dir": str(feeds)}
    return ScanEngine(config, base_dir=str(tmp_path))


def test_scan_flags_download_from_bad_origin(config, fake_usb, tmp_path,
                                             monkeypatch):
    eng = _engine_with_feed(config, tmp_path, [BAD_URL])
    monkeypatch.setattr(web, "read_motw",
                        lambda p: {"ZoneId": "3", "HostUrl": BAD_URL}
                        if p.endswith("invoice.pdf.exe") else None)
    res = eng.scan(str(fake_usb["dir"]), quarantine=False)
    hits = [d for d in res.detections if d.source == "web"]
    assert len(hits) == 1
    assert hits[0].severity == Severity.SUSPICIOUS   # origin alone: never INFECTED
    assert hits[0].path.endswith("invoice.pdf.exe")
    assert BAD_URL in hits[0].threat


def test_clean_origin_not_flagged(config, fake_usb, tmp_path, monkeypatch):
    eng = _engine_with_feed(config, tmp_path, [BAD_URL])
    monkeypatch.setattr(web, "read_motw",
                        lambda p: {"HostUrl": "http://clean.example.com/f"})
    res = eng.scan(str(fake_usb["dir"]), quarantine=False)
    assert not [d for d in res.detections if d.source == "web"]


def test_web_inactive_without_feed_or_key(config, tmp_path):
    config.data["web"] = {"check_download_origin": True,
                          "feeds_dir": str(tmp_path / "empty")}
    eng = ScanEngine(config, base_dir=str(tmp_path))
    assert not eng.web.active                       # nothing to check against


def test_feed_sha256_merges_into_hash_layer(config, fake_usb, tmp_path):
    feeds = tmp_path / "feeds"
    feeds.mkdir()
    (feeds / "urlhaus.sha256.txt").write_text(f"{fake_usb['mal_sha256']}\n")
    # point the company blocklist away so the FEED hash must do the catching
    empty_bl = tmp_path / "empty_blocklist.txt"
    empty_bl.write_text("# empty\n")
    config.data["heuristics"]["hash_blocklist"] = str(empty_bl)
    config.data["web"] = {"check_download_origin": True,
                          "feeds_dir": str(feeds)}
    eng = ScanEngine(config, base_dir=str(tmp_path))
    res = eng.scan(str(fake_usb["dir"]), quarantine=False)
    hash_hits = [d for d in res.infected if d.source == "hash"]
    assert any(d.path.endswith("mal.bin") for d in hash_hits)