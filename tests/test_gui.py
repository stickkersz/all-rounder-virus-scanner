"""GUI event-loop behavior (headless). Skips where Tk has no display."""

import gc

import pytest

from scanner.models import Detection, ProgressEvent, ScanResult, Severity


@pytest.fixture
def app(monkeypatch, config):
    """A live ScannerGUI, torn down on the MAIN thread.

    destroy() only tears down the Tcl widgets; the Python Tk object is
    finalized by the garbage collector, and this suite runs plenty of worker
    threads that can happen to trigger that collection. Finalizing Tk off the
    main thread aborts the interpreter with "Tcl_AsyncDelete: async handler
    deleted by the wrong thread", so the collection is forced here instead.
    """
    import gui
    # Force the GUI to use the temp-dir config (never touch C:\ProgramData).
    monkeypatch.setattr(gui.Config, "load", staticmethod(lambda p: config))
    try:
        a = gui.ScannerGUI()
    except Exception as exc:                     # no display in CI
        pytest.skip(f"Tk unavailable: {exc}")
    yield a
    if a._scan_thread:
        a._scan_thread.join(timeout=5)
    if a._monitor:
        a._monitor.stop()
    try:
        a.destroy()
    except Exception:
        pass                                     # already destroyed by the test
    del a
    gc.collect()


def test_progress_events_are_coalesced(monkeypatch, app):
    """The whole point of the anti-lag fix: many queued progress events collapse
    into ONE render per drain (the last one wins)."""
    renders = []
    monkeypatch.setattr(app, "_render_progress", lambda ev: renders.append(ev))
    for i in range(500):
        app._events.put(("progress", ProgressEvent("scanning", f"f{i}", i, 500)))
    app._drain_events()
    assert len(renders) == 1                 # 500 events -> 1 redraw
    assert renders[0].current == 499         # latest event kept


def test_render_progress_switches_bar_modes(app):
    app._render_progress(ProgressEvent("indexing", "Indexing"))
    assert app._bar_mode == "indeterminate"
    app._render_progress(ProgressEvent("scanning", "f", 5, 10))
    assert app._bar_mode == "determinate"
    assert "50%" in app.count_var.get()


def test_truncate_middle():
    import gui
    assert gui._truncate_middle("short") == "short"
    out = gui._truncate_middle("x" * 200, width=40)
    assert len(out) <= 40 and "..." in out


def test_rt_event_inserts_detections(app):
    """Real-time results flow through the same table/log path as manual scans."""
    r = ScanResult(target="rt", started="s", finished="f", files_scanned=1)
    r.detections = [Detection("/x/mal.exe", Severity.INFECTED,
                              "Test.Sig", "hash")]
    app._events.put(("rt", r))
    app._drain_events()
    rows = app.tree.get_children()
    assert len(rows) == 1
    assert app.tree.item(rows[0])["values"][3] == "/x/mal.exe"


def test_profile_buttons_exist_and_lock_together(app):
    """Every scan-launching button must lock during a scan, or a second
    concurrent scan can be started."""
    assert app.quick_btn and app.full_btn
    app._launch(lambda q: None)
    assert str(app.quick_btn["state"]) == "disabled"
    assert str(app.full_btn["state"]) == "disabled"
    assert str(app.scan_btn["state"]) == "disabled"


def test_close_stops_monitor(app):
    stopped = []

    class FakeMon:
        quarantine = True

        def stop(self):
            stopped.append(1)

    app._monitor = FakeMon()
    app._on_close()
    assert stopped == [1]
    assert app._monitor is None       # cleared, so teardown won't stop it twice


def test_realtime_honors_report_only(app):
    """'Report only (don't move files)' is the one visible move-nothing
    control; a real-time hit must honor it too."""
    app.report_only.set(True)
    assert app._realtime_quarantine() is False
    app.report_only.set(False)
    assert app._realtime_quarantine() is True

    # toggling the checkbox mid-session updates a running monitor
    class FakeMon:
        quarantine = True

        def stop(self):
            pass

    app._monitor = FakeMon()
    app.report_only.set(True)
    app._sync_report_only()
    assert app._monitor.quarantine is False


def test_monitor_checkbox_defaults_from_config(monkeypatch, config):
    """realtime.enabled must not be a knob that does nothing."""
    import gui
    config.data["realtime"] = {"enabled": False, "paths": [], "quarantine": True}
    monkeypatch.setattr(gui.Config, "load", staticmethod(lambda p: config))
    try:
        a = gui.ScannerGUI()
    except Exception as exc:
        pytest.skip(f"Tk unavailable: {exc}")
    try:
        assert a.monitor_var.get() is False
    finally:
        a.destroy()
        del a
        gc.collect()
