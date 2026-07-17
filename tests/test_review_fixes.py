"""Regression tests for the phase-3/4/5 code-review findings.

Each test names the failure it prevents; see docs/LESSONS.md for the rules.
"""

import json
import os
import threading
import time

import pytest

from scanner import profiles, reporter, web
from scanner.cache import ScanCache
from scanner.config import Config
from scanner.engine import ScanEngine
from scanner.models import Detection, ScanResult, Severity
from scanner.realtime import RealtimeMonitor
from scanner.web import SafeBrowsingClient, WebProtection


# ---- cache thread-safety (finding 1: dropped detections / aborted scans) --
def test_cache_save_snapshots_under_the_lock(tmp_path):
    """save() must take the lock to snapshot the dict.

    Tested via the contract rather than by racing threads: with a live-dict
    comprehension the serialization usually finishes inside one GIL switch
    interval, so a naive race test passes against the BROKEN code and guards
    nothing. Holding the lock here proves save() waits for it — on the old
    unlocked save() this returns immediately and the test fails.
    """
    c = ScanCache(str(tmp_path / "cache.json"))
    for i in range(100):
        c.mark_clean(f"/f{i}", 1, 1)
    finished = threading.Event()

    c._lock.acquire()
    t = threading.Thread(target=lambda: (c.save(), finished.set()), daemon=True)
    t.start()
    try:
        assert not finished.wait(0.3), \
            "save() serialized without holding the lock — it can race mark_clean"
    finally:
        c._lock.release()
    assert finished.wait(5), "save() never completed after the lock was freed"
    assert json.loads((tmp_path / "cache.json").read_text())


def test_cache_survives_mutation_during_serialization(tmp_path, monkeypatch):
    """The other thread inserting mid-write must not corrupt or raise: the
    snapshot is already detached from the live dict by then."""
    import scanner.cache as cache_mod
    c = ScanCache(str(tmp_path / "cache.json"))
    for i in range(50):
        c.mark_clean(f"/f{i}", 1, 1)
    real_dump = cache_mod.json.dump

    def dump_then_mutate(obj, fh):
        c._clean["/inserted-mid-write"] = (9, 9)   # simulate the other thread
        return real_dump(obj, fh)

    monkeypatch.setattr(cache_mod.json, "dump", dump_then_mutate)
    c.save()                                        # must not raise
    data = json.loads((tmp_path / "cache.json").read_text())
    assert len(data) == 50 and "/f0" in data


def test_cache_save_is_atomic_and_valid_json(tmp_path):
    p = tmp_path / "cache.json"
    c = ScanCache(str(p))
    c.mark_clean("/a", 2, 3)
    c.save()
    assert json.loads(p.read_text()) == {"/a": [2, 3]}
    assert not list(tmp_path.glob("*.tmp"))       # temp file cleaned up


def test_cache_concurrent_saves_dont_share_tmp_path(tmp_path):
    """Two threads saving at once must not write the same .tmp file."""
    c = ScanCache(str(tmp_path / "cache.json"))
    for i in range(200):
        c.mark_clean(f"/f{i}", 1, 1)
    errs = []

    def saver():
        try:
            for _ in range(20):
                c.save()
        except Exception as exc:
            errs.append(exc)

    ts = [threading.Thread(target=saver) for _ in range(4)]
    [t.start() for t in ts]
    [t.join(timeout=5) for t in ts]
    assert not errs
    assert json.loads((tmp_path / "cache.json").read_text())   # not corrupt


# ---- realtime: no stderr, drains on stop, batches don't save cache -------
def _cfg(tmp_path, **realtime):
    rt = {"enabled": False, "paths": [str(tmp_path / "watch")],
          "settle_seconds": 0.0, "quarantine": True}
    rt.update(realtime)
    return Config(data={
        "scanner": {"prefer_daemon": False},
        "heuristics": {"enabled": True},
        "quarantine": {"path": str(tmp_path / "q")},
        "logging": {"path": str(tmp_path / "logs")},
        "reporting": {"path": str(tmp_path / "rep")},
        "web": {"feeds_dir": str(tmp_path / "feeds")},
        "realtime": rt,
    })


class StubEngine:
    def __init__(self):
        self.batches = []
        self.save_flags = []

        class _Cache:
            saves = 0

            def save(self_inner):
                self_inner.saves += 1
        self.cache = _Cache()

    def scan_files(self, paths, quarantine=True, save_cache=True):
        self.batches.append(sorted(paths))
        self.save_flags.append(save_cache)
        return ScanResult(target="stub", started="s", finished="f",
                          files_scanned=len(paths))


def test_worker_survives_error_when_stderr_is_none(monkeypatch, tmp_path):
    """Under pythonw / a windowed PyInstaller build sys.stderr is None. The
    keep-alive handler must not touch it, or it raises AttributeError, the
    worker thread dies, and protection stops while the UI still shows it on.
    """
    import sys as _sys
    import scanner.realtime as rt_mod
    monkeypatch.setattr(_sys, "stderr", None)

    class Boom(StubEngine):
        def scan_files(self, *a, **k):
            raise RuntimeError("boom")

    (tmp_path / "watch").mkdir()
    m = RealtimeMonitor.from_config(Boom(), _cfg(tmp_path), lambda r: None)
    m.queue.settle = 0.0
    m.poll_interval = 0.01
    logged = []
    monkeypatch.setattr(rt_mod.log, "error", lambda *a, **k: logged.append(a))

    t = threading.Thread(target=m._run, daemon=True)
    t.start()
    try:
        deadline = time.time() + 3
        while time.time() < deadline and not logged:
            m._touch(str(tmp_path / "watch" / "x.exe"))
            time.sleep(0.02)
    finally:
        m._stop.set()
        t.join(timeout=2)
    assert logged, "error was not logged (handler likely died on stderr=None)"
    assert not t.is_alive()


def test_watcher_error_handler_survives_stderr_none(monkeypatch):
    """Same defect existed in the USB-insert watcher's keep-alive handler."""
    import sys as _sys
    from scanner import watcher as w
    monkeypatch.setattr(_sys, "stderr", None)
    logged = []
    monkeypatch.setattr(w.log, "error", lambda *a, **k: logged.append(a))
    monkeypatch.setattr(w, "list_removable", lambda *a, **k: ["A"])
    dw = w.DriveWatcher(lambda r: None, poll_interval=0)

    def boom():
        raise RuntimeError("boom")
    monkeypatch.setattr(dw, "_tick", boom)
    monkeypatch.setattr(w.time, "sleep", lambda s: (_ for _ in ()).throw(
        KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt):
        dw.run_forever()
    assert logged


def test_drain_tells_engine_not_to_save_cache(tmp_path):
    eng = StubEngine()
    (tmp_path / "watch").mkdir()
    m = RealtimeMonitor.from_config(eng, _cfg(tmp_path), lambda r: None)
    m.queue.settle = 0.0
    m._touch(str(tmp_path / "watch" / "a.exe"))
    m.drain()
    assert eng.save_flags == [False]      # per-batch full rewrite avoided
    assert m._cache_dirty


def test_stop_drains_and_flushes(tmp_path):
    """GUI called only stop(); CLI called stop()+drain(). A file that settled
    mid-shutdown must be scanned either way."""
    eng = StubEngine()
    (tmp_path / "watch").mkdir()
    m = RealtimeMonitor.from_config(eng, _cfg(tmp_path), lambda r: None)
    m.queue.settle = 0.0
    m._touch(str(tmp_path / "watch" / "late.exe"))
    m.stop()
    assert eng.batches == [[str(tmp_path / "watch" / "late.exe")]]
    assert eng.cache.saves == 1           # flushed exactly once


# ---- realtime: from_config derives roots + ignore list -------------------
def test_from_config_ignores_our_own_output_dirs(tmp_path):
    (tmp_path / "watch").mkdir()
    cfg = _cfg(tmp_path)
    m = RealtimeMonitor.from_config(StubEngine(), cfg, lambda r: None)
    for own in ("q", "logs", "rep", "feeds"):
        assert m._is_ignored(str(tmp_path / own / "x.bin")), own


def test_from_config_honors_quarantine_override(tmp_path):
    (tmp_path / "watch").mkdir()
    cfg = _cfg(tmp_path, quarantine=True)
    m = RealtimeMonitor.from_config(StubEngine(), cfg, lambda r: None,
                                    quarantine=False)
    assert m.quarantine is False          # report-only wins over config


def test_clamd_warning_when_daemon_missing(tmp_path):
    (tmp_path / "watch").mkdir()
    eng = StubEngine()

    class Clam:
        available = True
        clamdscan = None
    eng.clam = Clam()
    m = RealtimeMonitor.from_config(eng, _cfg(tmp_path), lambda r: None)
    assert "clamd" in m.clamd_warning()


# ---- SYSTEM service watches every user, not systemprofile ----------------
def test_monitor_roots_use_all_users_when_running_as_system(monkeypatch):
    monkeypatch.setattr(profiles, "running_as_service_account", lambda: True)
    monkeypatch.setattr(profiles, "all_users_quick_locations",
                        lambda: ["C:/Users/alice/Downloads",
                                 "C:/Users/bob/Downloads"])
    monkeypatch.setattr(profiles, "quick_locations",
                        lambda: ["C:/Windows/System32/config/systemprofile"])
    roots = profiles.monitor_default_roots()
    assert any("alice" in r for r in roots) and any("bob" in r for r in roots)
    assert not any("systemprofile" in r for r in roots)


def test_monitor_roots_use_own_profile_when_running_as_user(monkeypatch):
    monkeypatch.setattr(profiles, "running_as_service_account", lambda: False)
    monkeypatch.setattr(profiles, "quick_locations", lambda: ["/home/me/Downloads"])
    assert profiles.monitor_default_roots() == ["/home/me/Downloads"]


def test_all_users_skips_template_profiles(monkeypatch, tmp_path):
    """Template/service profiles hold no downloads; real users must survive."""
    users = tmp_path / "Users"
    for name in ("alice", "Default", "All Users"):
        (users / name / "Downloads").mkdir(parents=True)
    found = profiles.all_users_quick_locations(users_root=str(users))
    assert any(os.path.join("alice", "Downloads") in p for p in found)
    assert not any("Default" in p for p in found)
    assert not any("All Users" in p for p in found)


# ---- CLI: explicit + profile targets de-duped ----------------------------
def test_scan_many_accepts_per_target_explicit(config, fake_usb, tmp_path):
    eng = ScanEngine(config, base_dir=str(tmp_path))
    res = eng.scan_many([(str(fake_usb["dir"]), True)], quarantine=False)
    assert len(res.infected) >= 1


def test_scan_many_mixed_pairs_respect_explicitness(config, fake_usb, tmp_path):
    """A machine-chosen root honors an exclusion; an explicit one overrides."""
    config.data["scanner"]["exclusions"] = [str(fake_usb["dir"])]
    eng = ScanEngine(config, base_dir=str(tmp_path))
    excluded = eng.scan_many([(str(fake_usb["dir"]), False)], quarantine=False)
    assert excluded.files_scanned == 0
    named = eng.scan_many([(str(fake_usb["dir"]), True)], quarantine=False)
    assert named.files_scanned > 0


def test_scanresult_merge_accumulates_every_field():
    a = ScanResult(target="a", started="s", files_scanned=1, files_skipped=2)
    a.detections = [Detection("/x", Severity.INFECTED, "t", "hash")]
    a.errors = ["e1"]
    b = ScanResult(target="b", started="s", files_scanned=3, files_skipped=4)
    b.detections = [Detection("/y", Severity.SUSPICIOUS, "t", "heuristic")]
    b.errors = ["e2"]
    a.merge(b)
    assert a.files_scanned == 4 and a.files_skipped == 6
    assert len(a.detections) == 2 and a.errors == ["e1", "e2"]


# ---- feeds reload in long-running processes ------------------------------
def test_web_reloads_when_feed_file_changes(tmp_path):
    feeds = tmp_path / "feeds"
    feeds.mkdir()
    f = feeds / "urlhaus.urls.txt"
    f.write_text("http://old.example.com/a\n")
    wp = WebProtection({"check_download_origin": True, "feeds_dir": str(feeds)},
                       str(tmp_path))
    assert wp.rep.check("http://old.example.com/a")
    assert not wp.rep.check("http://new.example.com/b")
    time.sleep(0.01)
    f.write_text("http://new.example.com/b\n")
    assert wp.reload_if_changed()
    assert wp.rep.check("http://new.example.com/b")
    assert not wp.rep.check("http://old.example.com/a")


def test_web_reload_is_noop_when_unchanged(tmp_path):
    feeds = tmp_path / "feeds"
    feeds.mkdir()
    (feeds / "u.urls.txt").write_text("http://x.example.com/a\n")
    wp = WebProtection({"check_download_origin": True, "feeds_dir": str(feeds)},
                       str(tmp_path))
    assert wp.reload_if_changed() is False


def test_engine_picks_up_new_sha256_feed(config, fake_usb, tmp_path):
    """A long-running process must see a hash feed the sync task wrote after
    the engine was constructed."""
    feeds = tmp_path / "feeds"
    feeds.mkdir()
    empty_bl = tmp_path / "empty.txt"
    empty_bl.write_text("# none\n")
    config.data["heuristics"]["hash_blocklist"] = str(empty_bl)
    # use_cache off: this asserts the FEED reload, not cache behavior (a file
    # already cached clean is not re-hashed — see LESSONS.md).
    config.data["scanner"]["use_cache"] = False
    config.data["web"] = {"check_download_origin": True, "feeds_dir": str(feeds)}
    eng = ScanEngine(config, base_dir=str(tmp_path))
    first = eng.scan(str(fake_usb["dir"]), quarantine=False)
    assert not any(d.source == "hash" for d in first.infected)   # not yet known
    # feed appears AFTER the engine was constructed (daily sync task)
    (feeds / "new.sha256.txt").write_text(f"{fake_usb['mal_sha256']}\n")
    eng._refresh_feeds()
    res = eng.scan(str(fake_usb["dir"]), quarantine=False)
    assert any(d.source == "hash" and d.path.endswith("mal.bin")
               for d in res.infected)


# ---- Safe Browsing cache bounded + TTL -----------------------------------
def test_safe_browsing_cache_is_bounded(monkeypatch):
    import urllib.request
    import io

    class R(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *a): return False

    sb = SafeBrowsingClient("k")
    sb.CACHE_MAX = 4
    monkeypatch.setattr(urllib.request, "urlopen", lambda r, timeout=0: R(b"{}"))
    for i in range(12):
        sb.check(f"http://e{i}.example.com/x")
    assert len(sb._cache) <= sb.CACHE_MAX


def test_safe_browsing_cache_expires(monkeypatch):
    import urllib.request
    import io

    class R(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *a): return False

    now = {"t": 0.0}
    sb = SafeBrowsingClient("k", clock=lambda: now["t"])
    calls = []

    def fake(req, timeout=0):
        calls.append(1)
        return R(b"{}")
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    sb.check("http://e.example.com/x")
    sb.check("http://e.example.com/x")
    assert len(calls) == 1                       # cached
    now["t"] = sb.CACHE_TTL_SECONDS + 1
    sb.check("http://e.example.com/x")
    assert len(calls) == 2                       # stale -> re-checked


# ---- report filenames never overwrite ------------------------------------
def test_reports_in_same_second_do_not_overwrite(tmp_path):
    cfg = {"path": str(tmp_path / "rep")}
    r = ScanResult(target="1 changed file(s)", started="s", finished="f")
    r.detections = [Detection("/x.exe", Severity.INFECTED, "T", "hash")]
    p1 = reporter.write_report(cfg, r)
    p2 = reporter.write_report(cfg, r)
    assert p1 != p2
    assert os.path.isfile(p1) and os.path.isfile(p2)


# ---- config degrades to defaults for a missing section -------------------
def test_config_missing_section_falls_back_to_defaults():
    c = Config(data={"scanner": {"workers": 1}})
    assert c["realtime"]["enabled"] is False     # no KeyError
    assert c["web"]["check_download_origin"] is True
    assert c["scanner"]["workers"] == 1
