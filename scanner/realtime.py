"""Real-time file monitoring: scan files as they land.

Watches filesystem events (via `watchdog`) on configured roots, debounces them
(a big download fires hundreds of modify events — we wait until the file goes
quiet), then scans settled files in batches through the SAME ScanEngine
pipeline as manual scans. No second detection path exists.

`watchdog` is optional at import time (like yara): the module loads without it
so the rest of the scanner works, and `RealtimeMonitor.start()` explains what
to install.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Callable, Dict, Iterable, List, Optional

from . import behavior
from .behavior import BehaviorAnalyzer
from .canary import CanaryManager
from .models import ScanResult
from .paths import is_under, norm_for_match
from .profiles import monitor_default_roots

# Never write to sys.stderr from the worker: under pythonw / a PyInstaller
# windowed build sys.stderr is None, so the "keep it alive" handler would
# itself raise AttributeError and kill the thread — protection would stop
# silently while the UI still showed it as on.
log = logging.getLogger("usbscanner")

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
    _HAS_WATCHDOG = True
except Exception:  # pragma: no cover - optional dependency
    FileSystemEventHandler = object  # type: ignore[assignment,misc]
    Observer = None
    _HAS_WATCHDOG = False


class DebounceQueue:
    """Collects touched paths and releases them once they've gone quiet.

    Thread-safe. `touch()` is called from watchdog's event thread for every
    create/modify/move; `pop_settled()` from the worker thread returns paths
    that saw no event for `settle_seconds` — i.e. the write finished. Rapid
    re-writes just push the release time back, so one growing download is
    scanned once, not hundreds of times.
    """

    def __init__(self, settle_seconds: float = 2.0, clock=time.monotonic):
        self.settle = settle_seconds
        self.clock = clock
        self._last_event: Dict[str, float] = {}
        self._lock = threading.Lock()

    def touch(self, path: str) -> None:
        with self._lock:
            self._last_event[path] = self.clock()

    def pop_settled(self) -> List[str]:
        now = self.clock()
        with self._lock:
            ready = [p for p, t in self._last_event.items()
                     if now - t >= self.settle]
            for p in ready:
                del self._last_event[p]
        return ready

    def __len__(self) -> int:
        with self._lock:
            return len(self._last_event)


class _EventHandler(FileSystemEventHandler):
    """Feeds file events to two consumers: `on_touch` queues files for scanning
    (create/modify, and a move's destination — the file that now exists);
    `on_event` feeds the behavioral analyzer with action-typed events, including
    deletes and rename destinations it needs to spot ransomware/worm bursts."""

    def __init__(self, on_touch: Callable[[str], None],
                 on_event: Optional[Callable[[str, str], None]] = None):
        self.on_touch = on_touch
        self.on_event = on_event or (lambda p, a: None)

    def on_created(self, event):
        if not event.is_directory:
            self.on_touch(event.src_path)
            self.on_event(event.src_path, behavior.CREATED)

    def on_modified(self, event):
        if not event.is_directory:
            self.on_touch(event.src_path)
            self.on_event(event.src_path, behavior.MODIFIED)

    def on_moved(self, event):
        # A download often lands as name.part/name.crdownload then renames:
        # the DESTINATION is the file that now exists and needs scanning. The
        # destination name also carries any ransomware extension (.locked etc.).
        if not event.is_directory:
            self.on_touch(event.dest_path)
            self.on_event(event.dest_path, behavior.MOVED)

    def on_deleted(self, event):
        # No file to scan, but ransomware deletes/originals feed the behavior
        # burst + canary-trip detection.
        if not event.is_directory:
            self.on_event(event.src_path, behavior.DELETED)


class RealtimeMonitor:
    """Watch roots, debounce events, scan settled files via the engine.

    `ignore_paths` must include the quarantine, log and report directories:
    quarantining a hit WRITES files, which would fire events, which would
    scan the quarantine, which would... — the classic feedback loop.
    """

    # Flush the (whole-file) cache at most this often. scan_files itself is
    # told not to save per batch: after a Full scan the cache holds an entry
    # per file on the disk, and re-serializing that blob on every settled
    # download would peg the disk of an always-on monitor.
    CACHE_FLUSH_SECONDS = 60.0

    def __init__(self, engine, roots: Iterable[str],
                 on_result: Callable[[object], None],
                 settle_seconds: float = 2.0,
                 quarantine: bool = True,
                 ignore_paths: Iterable[str] = (),
                 poll_interval: float = 0.5,
                 analyzer: Optional[BehaviorAnalyzer] = None,
                 canary: Optional[CanaryManager] = None):
        self.engine = engine
        self.roots = [r for r in roots if os.path.isdir(r)]
        self.on_result = on_result
        self.quarantine = quarantine
        self.poll_interval = poll_interval
        self.queue = DebounceQueue(settle_seconds)
        self._ignore = [norm_for_match(p) for p in ignore_paths if p]
        self._observer = None
        self._worker: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._cache_dirty = False
        self._last_flush = time.monotonic()
        # Behavioral (ransomware/worm/canary) analysis over the event stream.
        # Optional: when absent the monitor is exactly the file-scanning monitor
        # it was before. Behavior hits are collected on the event thread and
        # delivered from the worker so watchdog's callback stays fast.
        self.analyzer = analyzer
        self.canary = canary
        self._behavior_hits: List = []
        self._behavior_lock = threading.Lock()

    @classmethod
    def from_config(cls, engine, cfg, on_result: Callable[[object], None],
                    quarantine: Optional[bool] = None) -> "RealtimeMonitor":
        """Build a monitor from config — the ONLY supported way to construct
        one for production use.

        Every caller (CLI, GUI) previously hand-assembled the watch roots and
        the ignore list. That duplication is how a caller ends up watching our
        own output: quarantining a hit writes files, which fire events, which
        scan the quarantine, forever. Deriving both here means a new output
        directory can never be forgotten by one caller only.
        """
        rt = cfg["realtime"]
        roots = [p for p in (rt.get("paths") or monitor_default_roots())
                 if os.path.isdir(p)]
        # Our own writes must never be watched. The scan cache lives in the
        # logging dir, and the feeds dir is rewritten by the daily sync task.
        ignore = [cfg["quarantine"].get("path", ""),
                  cfg["logging"].get("path", ""),
                  cfg["reporting"].get("path", ""),
                  (cfg.data.get("web", {}) or {}).get("feeds_dir", "")]
        if quarantine is None:
            quarantine = rt.get("quarantine", True)
        # Behavioral analysis + canary files are opt-out sub-features of the
        # monitor. Built here so CLI and GUI share one configuration path.
        behavior_cfg = rt.get("behavior", {}) or {}
        canary_cfg = rt.get("canary", {}) or {}
        analyzer = (BehaviorAnalyzer(behavior_cfg)
                    if behavior_cfg.get("enabled", True) else None)
        canary = (CanaryManager(canary_cfg)
                  if canary_cfg.get("enabled", True) else None)
        return cls(engine, roots, on_result,
                   settle_seconds=rt.get("settle_seconds", 2.0),
                   quarantine=quarantine, ignore_paths=ignore,
                   analyzer=analyzer, canary=canary)

    def clamd_warning(self) -> Optional[str]:
        """Warn when ClamAV would cold-start per batch.

        Without the resident daemon, every settled batch spawns clamscan,
        which reloads the whole signature database (tens of seconds, ~1 GB) —
        an always-on monitor then never stops thrashing.
        """
        clam = getattr(self.engine, "clam", None)
        if clam is not None and clam.available and not clam.clamdscan:
            return ("clamd (the resident ClamAV daemon) was not found. "
                    "Real-time scanning will start clamscan per batch, "
                    "reloading the signature database every time — slow and "
                    "CPU-heavy. Install/enable clamd for real-time use.")
        return None

    # ---- lifecycle -------------------------------------------------------
    def start(self) -> None:
        if not _HAS_WATCHDOG:
            raise RuntimeError(
                "Real-time monitoring needs the 'watchdog' package "
                "(pip install watchdog).")
        if not self.roots:
            raise RuntimeError("No existing directories to monitor.")
        # Plant canaries BEFORE the observer starts so writing them doesn't
        # register as a change event on our own bait.
        if self.canary and self.analyzer:
            planted = self.canary.deploy(self.roots)
            self.analyzer.add_canaries(planted)
        handler = _EventHandler(self._touch, self._behavior_event)
        self._observer = Observer()
        for root in self.roots:
            self._observer.schedule(handler, root, recursive=True)
        self._observer.start()
        self._stop.clear()
        self._worker = threading.Thread(target=self._run, daemon=True,
                                        name="realtime-scan-worker")
        self._worker.start()

    def stop(self) -> None:
        """Stop watching, then flush what settled mid-shutdown.

        The final drain is done HERE rather than left to each caller: a file
        that finished downloading a second before the user unticked the box
        must be scanned regardless of whether the CLI or the GUI is stopping
        us. The cache is flushed once here since batches don't save it.
        """
        self._stop.set()
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5)
            self._observer = None
        if self._worker:
            self._worker.join(timeout=5)
            self._worker = None
        try:
            self.drain()
            self._drain_behavior()
        except Exception as exc:
            log.error("[realtime] final drain failed: %s", exc)
        if self.canary:
            self.canary.cleanup()
        self._flush_cache()

    # ---- internals ---------------------------------------------------------
    def _touch(self, path: str) -> None:
        if self._is_ignored(path):
            return
        self.queue.touch(path)

    def _is_ignored(self, path: str) -> bool:
        p = norm_for_match(path)
        return any(is_under(p, ig) for ig in self._ignore)

    def _behavior_event(self, path: str, action: str) -> None:
        """Feed one action-typed event to the analyzer (event thread). Does no
        I/O; any resulting detections are buffered for the worker to deliver."""
        if not self.analyzer or self._is_ignored(path):
            return
        try:
            hits = self.analyzer.record(path, action)
        except Exception as exc:
            log.error("[realtime] behavior analysis failed: %s", exc)
            return
        if hits:
            with self._behavior_lock:
                self._behavior_hits.extend(hits)

    def _drain_behavior(self) -> None:
        """Deliver buffered behavioral detections as one report/alert. Runs on
        the worker thread so watchdog's callback never blocks on logging."""
        with self._behavior_lock:
            if not self._behavior_hits:
                return
            hits = self._behavior_hits
            self._behavior_hits = []
        result = ScanResult(target="real-time behavior", started="")
        result.detections.extend(hits)
        self.on_result(result)

    def _run(self) -> None:
        while not self._stop.wait(self.poll_interval):
            try:
                self.drain()
                self._drain_behavior()
                self._maybe_flush_cache()
            except Exception as exc:  # keep the monitor alive no matter what
                log.error("[realtime] error: %s", exc)

    def _maybe_flush_cache(self) -> None:
        now = time.monotonic()
        if self._cache_dirty and now - self._last_flush >= self.CACHE_FLUSH_SECONDS:
            self._flush_cache()

    def _flush_cache(self) -> None:
        if not self._cache_dirty:
            return
        self._cache_dirty = False
        self._last_flush = time.monotonic()
        try:
            self.engine.cache.save()
        except Exception as exc:
            log.error("[realtime] cache flush failed: %s", exc)

    def drain(self) -> None:
        """Scan whatever has settled. Public so tests (and the final flush in
        stop()) can drive it without threads."""
        settled = self.queue.pop_settled()
        if not settled:
            return
        result = self.engine.scan_files(settled, quarantine=self.quarantine,
                                        save_cache=False)
        self._cache_dirty = True
        if result.files_scanned or result.detections:
            self.on_result(result)
