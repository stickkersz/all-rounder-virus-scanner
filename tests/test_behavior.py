"""Behavioral detector tests. Synthetic events only — no real ransomware, no
encryption. We drive BehaviorAnalyzer.record() with a controlled clock (the
`when=` argument), which is exactly how a filesystem-event stream would feed it,
so a test can simulate a mass-rewrite burst without touching real files."""

import os

from scanner.behavior import (BehaviorAnalyzer, CREATED, DELETED, MODIFIED,
                              MOVED)
from scanner.detectors import Category


def _analyzer(**over):
    cfg = {"enabled": True, "sensitivity": "high", "window_seconds": 100,
           "cooldown_seconds": 100}
    cfg.update(over)
    return BehaviorAnalyzer(cfg)


# ---- ransomware -----------------------------------------------------------
def test_ransomware_burst_fires():
    a = _analyzer()                       # high -> threshold 10 distinct files
    hits = []
    for i in range(11):
        hits += a.record(f"/data/doc_{i}.txt", MODIFIED, when=float(i))
    assert any(h.category == Category.RANSOMWARE.value for h in hits)


def test_ransomware_with_ransom_extensions_is_infected():
    a = _analyzer()
    hits = []
    for i in range(12):
        hits += a.record(f"/data/doc_{i}.locked", MOVED, when=float(i))
    ransom = [h for h in hits if h.category == Category.RANSOMWARE.value]
    assert ransom and ransom[-1].severity.value == "infected"


def test_small_activity_does_not_fire():
    a = _analyzer()
    hits = []
    for i in range(4):                    # well below threshold
        hits += a.record(f"/data/doc_{i}.txt", MODIFIED, when=float(i))
    assert hits == []


def test_events_outside_window_are_pruned():
    a = _analyzer(window_seconds=5)
    hits = []
    # Ten files, but each 2s apart -> only the last few sit inside a 5s window.
    for i in range(10):
        hits += a.record(f"/data/doc_{i}.txt", MODIFIED, when=float(i * 2))
    assert hits == []


def test_cooldown_suppresses_repeat_alerts():
    a = _analyzer(cooldown_seconds=1000)
    first, second = [], []
    for i in range(11):
        first += a.record(f"/a/f{i}.txt", MODIFIED, when=float(i))
    for i in range(11, 30):
        second += a.record(f"/a/f{i}.txt", MODIFIED, when=float(i))
    assert first and not any(
        h.category == Category.RANSOMWARE.value for h in second)


# ---- canary ---------------------------------------------------------------
def test_canary_trip_is_immediate_infected():
    bait = "/watch/!!!__ransomware_canary__DO_NOT_DELETE.txt"
    a = _analyzer(sensitivity="low", canaries=[])
    a.add_canaries([bait])
    hits = a.record(bait, MODIFIED, when=1.0)
    assert len(hits) == 1
    assert hits[0].category == Category.RANSOMWARE.value
    assert hits[0].severity.value == "infected"


def test_canary_delete_also_trips():
    a = BehaviorAnalyzer({"sensitivity": "high"}, canaries=["/w/bait.txt"])
    assert a.record("/w/bait.txt", DELETED, when=1.0)


# ---- worm -----------------------------------------------------------------
def test_worm_multipath_burst_fires():
    a = _analyzer()                       # high -> 3 dirs / 10 files
    hits = []
    dirs = ["/mnt/a", "/mnt/b", "/mnt/c", "/mnt/d"]
    n = 0
    for d in dirs:
        for i in range(4):
            hits += a.record(f"{d}/copy_{i}.exe", CREATED, when=float(n))
            n += 1
    assert any(h.category == Category.WORM.value for h in hits)


def test_worm_single_directory_does_not_fire():
    a = _analyzer()
    hits = []
    for i in range(20):                   # many files, ONE directory
        hits += a.record(f"/mnt/only/copy_{i}.exe", CREATED, when=float(i))
    assert not any(h.category == Category.WORM.value for h in hits)


def test_disabled_analyzer_is_silent():
    a = BehaviorAnalyzer({"enabled": False})
    hits = []
    for i in range(50):
        hits += a.record(f"/x/f{i}.txt", MODIFIED, when=float(i))
    assert hits == []


# ---- monitor integration (drive hooks directly; no watchdog timing) -------
def test_monitor_delivers_behavior_hits(tmp_path):
    from scanner.realtime import RealtimeMonitor
    got = []
    an = BehaviorAnalyzer({"sensitivity": "high", "window_seconds": 100})
    m = RealtimeMonitor(engine=object(), roots=[str(tmp_path)],
                        on_result=got.append, analyzer=an)
    for i in range(12):
        m._behavior_event(f"/data/f{i}.txt", MODIFIED)
    m._drain_behavior()
    assert len(got) == 1
    assert got[0].detections[0].category == Category.RANSOMWARE.value
    # drained -> a second drain delivers nothing.
    m._drain_behavior()
    assert len(got) == 1


def test_monitor_skips_behavior_events_under_ignored_paths(tmp_path):
    from scanner.realtime import RealtimeMonitor
    got = []
    an = BehaviorAnalyzer({"sensitivity": "high", "window_seconds": 100})
    quar = str(tmp_path / "quarantine")
    m = RealtimeMonitor(engine=object(), roots=[str(tmp_path)],
                        on_result=got.append, analyzer=an,
                        ignore_paths=[quar])
    # Our own quarantine writes must never look like a ransomware burst.
    for i in range(30):
        m._behavior_event(os.path.join(quar, f"x{i}.quarantine"), MODIFIED)
    m._drain_behavior()
    assert got == []


def test_canary_manager_deploy_and_cleanup(tmp_path):
    from scanner.canary import CanaryManager
    cm = CanaryManager()
    planted = cm.deploy([str(tmp_path)])
    assert len(planted) == 1 and os.path.isfile(planted[0])
    cm.cleanup()
    assert not os.path.isfile(planted[0])
