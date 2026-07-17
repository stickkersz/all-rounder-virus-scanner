"""Real-time monitoring: debounce, feedback-loop guard, engine reuse.

Watchdog wiring is exercised in one live end-to-end test (skipped when
watchdog isn't installed); everything else drives the components directly so
tests are deterministic — no sleeps against real filesystem-event timing.
"""

import os

import pytest

from scanner.engine import ScanEngine
from scanner.realtime import (DebounceQueue, RealtimeMonitor, _EventHandler,
                              _HAS_WATCHDOG)


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


# ---- DebounceQueue -------------------------------------------------------
def test_debounce_holds_until_settled():
    clock = FakeClock()
    q = DebounceQueue(settle_seconds=2.0, clock=clock)
    q.touch("/f")
    clock.t = 1.0
    assert q.pop_settled() == []          # still hot
    clock.t = 2.0
    assert q.pop_settled() == ["/f"]      # quiet for 2s -> released
    assert q.pop_settled() == []          # released once, not twice


def test_debounce_rewrite_pushes_release_back():
    """A growing download keeps firing events; each one restarts the timer."""
    clock = FakeClock()
    q = DebounceQueue(settle_seconds=2.0, clock=clock)
    q.touch("/dl")
    clock.t = 1.9
    q.touch("/dl")                        # still being written
    clock.t = 3.0
    assert q.pop_settled() == []          # only 1.1s since last write
    clock.t = 3.9
    assert q.pop_settled() == ["/dl"]


def test_debounce_batches_multiple_files():
    clock = FakeClock()
    q = DebounceQueue(settle_seconds=1.0, clock=clock)
    q.touch("/a")
    q.touch("/b")
    clock.t = 1.0
    assert sorted(q.pop_settled()) == ["/a", "/b"]


# ---- event handler -------------------------------------------------------
class _Ev:
    def __init__(self, src, dest=None, is_dir=False):
        self.src_path = src
        self.dest_path = dest
        self.is_directory = is_dir


def test_handler_uses_move_destination():
    """Downloads land as x.part then rename — the DEST needs scanning."""
    seen = []
    h = _EventHandler(seen.append)
    h.on_moved(_Ev("/dl/x.part", dest="/dl/x.exe"))
    assert seen == ["/dl/x.exe"]


def test_handler_ignores_directory_events():
    seen = []
    h = _EventHandler(seen.append)
    h.on_created(_Ev("/newdir", is_dir=True))
    h.on_modified(_Ev("/newdir", is_dir=True))
    assert seen == []


# ---- monitor logic (no watchdog needed) -----------------------------------
class StubEngine:
    def __init__(self):
        self.batches = []

    def scan_files(self, paths, quarantine=True, **kw):
        self.batches.append(sorted(paths))
        from scanner.models import ScanResult
        return ScanResult(target="stub", started="s", finished="f",
                          files_scanned=len(paths))


def _monitor(engine, tmp_path, **kw):
    results = []
    m = RealtimeMonitor(engine, [str(tmp_path)], results.append, **kw)
    return m, results


def test_drain_scans_settled_batch(tmp_path):
    eng = StubEngine()
    m, results = _monitor(eng, tmp_path)
    m.queue = DebounceQueue(settle_seconds=0.0)
    m._touch(str(tmp_path / "new.exe"))
    m.drain()
    assert eng.batches == [[str(tmp_path / "new.exe")]]
    assert len(results) == 1


def test_quarantine_dir_events_ignored(tmp_path):
    """Feedback-loop guard: our own quarantine/log writes never re-scan."""
    eng = StubEngine()
    q_dir = tmp_path / "q"
    m, _results = _monitor(eng, tmp_path, ignore_paths=[str(q_dir)])
    m.queue = DebounceQueue(settle_seconds=0.0)
    m._touch(str(q_dir / "quarantined.bin"))
    m._touch(str(tmp_path / "real.exe"))
    m.drain()
    assert eng.batches == [[str(tmp_path / "real.exe")]]


def test_drain_without_events_scans_nothing(tmp_path):
    eng = StubEngine()
    m, results = _monitor(eng, tmp_path)
    m.drain()
    assert eng.batches == [] and results == []


def test_start_requires_existing_roots(tmp_path):
    m = RealtimeMonitor(StubEngine(), [str(tmp_path / "ghost")], lambda r: None)
    with pytest.raises(RuntimeError):
        m.start()


# ---- engine.scan_files (the shared pipeline) ------------------------------
def test_scan_files_detects_blocklisted(config, fake_usb, tmp_path):
    eng = ScanEngine(config, base_dir=str(tmp_path))
    res = eng.scan_files([str(fake_usb["dir"] / "mal.bin")], quarantine=False)
    assert len(res.infected) == 1
    assert res.infected[0].source == "hash"


def test_scan_files_honors_exclusions(config, fake_usb, tmp_path):
    config.data["scanner"]["exclusions"] = ["*.bin"]
    eng = ScanEngine(config, base_dir=str(tmp_path))
    res = eng.scan_files([str(fake_usb["dir"] / "mal.bin")], quarantine=False)
    assert res.files_scanned == 0 and res.files_skipped == 1
    assert res.clean


def test_scan_files_skips_vanished_file(config, tmp_path):
    eng = ScanEngine(config, base_dir=str(tmp_path))
    res = eng.scan_files([str(tmp_path / "gone.tmp")], quarantine=False)
    assert res.clean and res.files_scanned == 0


def test_scan_files_uses_cache(config, fake_usb, tmp_path):
    eng = ScanEngine(config, base_dir=str(tmp_path))
    target = str(fake_usb["dir"] / "notes.txt")
    r1 = eng.scan_files([target], quarantine=False)
    assert r1.files_scanned == 1
    r2 = eng.scan_files([target], quarantine=False)
    assert r2.files_scanned == 0 and r2.files_skipped == 1   # cached clean


# ---- live end-to-end (real watchdog) --------------------------------------
@pytest.mark.skipif(not _HAS_WATCHDOG, reason="watchdog not installed")
def test_live_monitor_catches_dropped_file(config, signatures, tmp_path):
    """Full loop: drop a blocklisted file into a watched dir, monitor scans
    and quarantines it through the real engine."""
    import time
    watched = tmp_path / "watched"
    watched.mkdir()
    eng = ScanEngine(config, base_dir=str(tmp_path))
    results = []
    m = RealtimeMonitor(eng, [str(watched)], results.append,
                        settle_seconds=0.2, quarantine=True,
                        poll_interval=0.05)
    m.start()
    try:
        (watched / "dropped.bin").write_bytes(b"known-bad-payload-bytes")
        deadline = time.time() + 10
        while time.time() < deadline and not any(r.infected for r in results):
            time.sleep(0.1)
    finally:
        m.stop()
    infected = [d for r in results for d in r.infected]
    assert infected, "monitor never flagged the dropped file"
    assert not (watched / "dropped.bin").exists()      # quarantined away
    assert infected[0].quarantined_to