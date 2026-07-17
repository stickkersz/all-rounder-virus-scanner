"""Scan engine: orchestrates ClamAV + the heuristic layer, then quarantines hits.

ClamAV does the heavy signature lifting (multi-million malware DB, archive
unpacking). The heuristic layer adds USB-specific detections and a company
hash/YARA blocklist. Results are merged and infected files are quarantined.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Callable, List, Optional

from .cache import ScanCache
from .exclusions import ExclusionMatcher
from .heuristics import HeuristicEngine, sha256_of
from .models import Detection, ProgressEvent, ScanResult, Severity
from .perf import resolve_workers, set_background_priority, system_memory
from .quarantine import Quarantine
from .web import WebProtection, feed_signature


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _norm(path: str) -> str:
    """Normalize a path for reliable matching between ClamAV's echoed paths and
    our own list (case-fold + separators on Windows, no-op on POSIX)."""
    return os.path.normcase(os.path.normpath(path))


class ClamAV:
    """Thin wrapper over clamscan/clamdscan. Degrades gracefully if absent."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.prefer_daemon = cfg.get("prefer_daemon", True)
        self.clamscan = self._resolve(cfg.get("clamscan_path"), "clamscan")
        self.clamdscan = self._resolve(cfg.get("clamdscan_path"), "clamdscan")
        self.max_mb = cfg.get("max_file_size_mb", 200)
        self.scan_archives = cfg.get("scan_archives", True)
        # clamdscan --multiscan uses all daemon threads in parallel — big win on
        # multi-core machines. Ignored by plain clamscan.
        self.multiscan = cfg.get("multiscan", True)
        # PUA = Potentially Unwanted Applications (adware, bundleware, PUPs).
        # Part of the "1.56B samples" are PUPs; ClamAV flags them only when asked.
        self.detect_pua = cfg.get("detect_pua", True)
        # ClamAV's own heuristics (broken-PE, packed, macro, phishing structure).
        self.heuristic_alerts = cfg.get("heuristic_alerts", True)
        # Optional explicit virus-DB directory. Needed for a bundled/portable
        # ClamAV so clamscan finds main.cvd/daily.cvd next to the exe. Passed
        # only when the directory actually exists (ignored on dev/mac).
        db = cfg.get("database_path")
        self.database_path = db if db and os.path.isdir(db) else None

    @staticmethod
    def _resolve(configured: Optional[str], name: str) -> Optional[str]:
        # Prefer the configured absolute path; fall back to PATH lookup so the
        # same config works on Linux/macOS test boxes and Windows prod.
        if configured and os.path.isfile(configured):
            return configured
        return shutil.which(name)

    @property
    def available(self) -> bool:
        return bool(self.clamscan or self.clamdscan)

    def _binary(self) -> Optional[tuple[str, bool]]:
        if self.prefer_daemon and self.clamdscan:
            return self.clamdscan, True
        if self.clamscan:
            return self.clamscan, False
        if self.clamdscan:
            return self.clamdscan, True
        return None

    def scan_filelist(self, list_path: str) -> tuple[List[Detection], List[str]]:
        """Scan exactly the files named in `list_path` (one path per line).

        Feeding ClamAV a precomputed list avoids a second full tree walk (the
        Python side already walked it) and lets the cache exclude unchanged
        files from the signature scan too.

        Prefers the resident daemon (fast: signature DB stays in RAM). If the
        daemon isn't running, transparently falls back to one-shot clamscan so a
        stopped clamd service never blocks scanning.
        """
        chosen = self._binary()
        if not chosen:
            return [], ["ClamAV binary not found; signature scan skipped."]
        binary, is_daemon = chosen

        dets, errs = self._run(binary, is_daemon, list_path)
        if is_daemon and errs and self.clamscan:
            # Daemon likely down (couldn't connect). Retry with plain clamscan.
            return self._run(self.clamscan, False, list_path)
        return dets, errs

    def _run(self, binary: str, is_daemon: bool,
             list_path: str) -> tuple[List[Detection], List[str]]:
        cmd = [binary, "--no-summary", "--infected", f"--file-list={list_path}"]
        # Detect adware / potentially-unwanted programs (works for clamscan and
        # clamdscan). Directly covers the "adware / PUP" threat category.
        if self.detect_pua:
            cmd.append("--detect-pua=yes")
        if not is_daemon:
            cmd += [f"--max-filesize={self.max_mb}M",
                    f"--max-scansize={self.max_mb}M"]
            cmd.append("--scan-archive=yes" if self.scan_archives
                       else "--scan-archive=no")
            # Turn on ClamAV's own heuristics (packed/broken PE, macros, etc.)
            # for better zero-day / novel-variant coverage.
            if self.heuristic_alerts:
                cmd += ["--heuristic-alerts=yes", "--alert-broken=yes"]
            # Point a portable/bundled clamscan at its bundled signature DB.
            if self.database_path:
                cmd.append(f"--database={self.database_path}")
        if is_daemon:
            # --fdpass lets clamd (running as another user) read the files.
            cmd.append("--fdpass")
            if self.multiscan:
                cmd.append("--multiscan")

        detections: List[Detection] = []
        errors: List[str] = []
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=3600)
        except FileNotFoundError:
            return [], [f"ClamAV binary missing: {binary}"]
        except subprocess.TimeoutExpired:
            return [], ["ClamAV scan timed out (>1h)."]

        # Exit codes: 0=clean, 1=virus found, 2=error.
        for line in proc.stdout.splitlines():
            if line.endswith(" FOUND"):
                # format: "<path>: <SignatureName> FOUND"
                try:
                    path, rest = line.rsplit(": ", 1)
                    sig = rest[: -len(" FOUND")].strip()
                except ValueError:
                    continue
                detections.append(Detection(path, Severity.INFECTED, sig,
                                            "clamav"))
        if proc.returncode == 2 and proc.stderr:
            errors.append(proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else "ClamAV error")
        return detections, errors


def _auto_workers(configured, in_memory_cap: int) -> int:
    """Resolve worker count. 'auto' -> scale to cores but stay modest so slow
    single-disk laptops don't thrash on seeks, and clamp so the worst-case
    per-worker file buffers still fit in a fraction of available RAM (a 2 GB
    laptop with 4 logical cores must not fan out to 4 * 64 MB buffers)."""
    _total, avail = system_memory()
    return resolve_workers(configured, in_memory_cap, avail_mem=avail)


class ScanEngine:
    def __init__(self, config, base_dir: str):
        self.config = config
        self.base_dir = base_dir
        self.clam = ClamAV(config["scanner"])
        self.heur = HeuristicEngine(config["heuristics"], base_dir)
        self.quar = Quarantine(config["quarantine"])
        # Sizing depends on the heuristic layer's per-file buffer cap (shrunk on
        # low-RAM boxes), so workers are resolved AFTER the heuristic engine.
        self.workers = _auto_workers(config["scanner"].get("workers", "auto"),
                                     self.heur.in_memory_cap)
        # Yield CPU so a Full scan doesn't freeze a weak laptop. Process-wide and
        # one notch down (below-normal), so an interactive GUI stays responsive.
        if config["scanner"].get("background_priority", True):
            set_background_priority()
        self.max_bytes = config["scanner"].get("max_file_size_mb", 200) * 1024 * 1024
        self.exclusions = ExclusionMatcher(config["scanner"].get("exclusions"))
        self.web = WebProtection(config.data.get("web", {}), base_dir)
        self._hash_feed_sig = None
        self._refresh_feeds()
        cache_path = os.path.join(config["logging"].get("path", "."), "scan_cache.json")
        self.cache = ScanCache(cache_path,
                               enabled=config["scanner"].get("use_cache", True))

    def scan(self, target: str,
             progress: Optional[Callable[[ProgressEvent], None]] = None,
             quarantine: bool = True, explicit: bool = True,
             save_cache: bool = True) -> ScanResult:
        """Scan one root.

        `explicit=True` means a human named this exact path (CLI path arg,
        custom profile, GUI pick): exclusion rules blanketing the root are
        suppressed so the scan can't silently report a false "0 files, CLEAN".
        Machine-generated roots (drive-insert watcher, quick/full profile
        resolution) pass explicit=False and honor exclusions fully.
        """
        result = ScanResult(target=target, started=_now())

        def emit(phase, message="", current=0, total=0):
            if progress:
                progress(ProgressEvent(phase, message, current, total))

        if not os.path.exists(target):
            result.errors.append(f"Target does not exist: {target}")
            result.finished = _now()
            return result

        if not explicit and self.exclusions.excludes(target):
            # Machine-generated target (watcher / profile) that the admin
            # excluded: honor it, but say so — never a silent no-op.
            result.errors.append(
                f"Target excluded by config (scanner.exclusions): {target}")
            emit("done", f"Excluded by config: {target}")
            result.finished = _now()
            return result

        # 1. Single tree walk. Collect (path, size, mtime_ns); apply size cap;
        #    skip files already scanned clean (unchanged) via the cache.
        emit("indexing", f"Indexing {target}")
        # (path, size, mtime_ns) -- mtime kept so caching reuses it (no re-stat).
        files: List[tuple[str, int, int]] = []
        cached_clean = 0
        for path, size, mtime in self._walk(target, result, explicit):
            if self.cache.is_clean(path, size, mtime):
                cached_clean += 1
                continue
            files.append((path, size, mtime))
        result.files_skipped += cached_clean
        self._scan_candidates(files, result, progress, quarantine, save_cache)
        return result

    def scan_files(self, paths: List[str],
                   progress: Optional[Callable[[ProgressEvent], None]] = None,
                   quarantine: bool = True,
                   save_cache: bool = True) -> ScanResult:
        """Scan an explicit list of files (no tree walk) through the same
        pipeline as a full scan — used by the real-time monitor's batches.

        Files are machine-selected (filesystem events), so exclusions apply
        fully, mirroring scan(explicit=False).
        """
        result = ScanResult(target=f"{len(paths)} changed file(s)",
                            started=_now())
        files: List[tuple[str, int, int]] = []
        for p in paths:
            if self.exclusions.excludes(p):
                result.files_skipped += 1
                continue
            try:
                st = os.stat(p)
            except OSError:
                continue          # deleted/renamed before we got to it
            # S_ISREG on the stat we already hold — os.path.isfile would be a
            # second syscall per file, on every batch, forever.
            if not stat.S_ISREG(st.st_mode) or st.st_size > self.max_bytes:
                result.files_skipped += 1
                continue
            if self.cache.is_clean(p, st.st_size, st.st_mtime_ns):
                result.files_skipped += 1
                continue
            files.append((p, st.st_size, st.st_mtime_ns))
        self._scan_candidates(files, result, progress, quarantine, save_cache)
        return result

    def _scan_candidates(self, files: List[tuple], result: ScanResult,
                         progress, quarantine: bool, save_cache: bool) -> None:
        """Steps 2-5 of the pipeline (ClamAV, heuristics, quarantine, cache)
        over pre-collected (path, size, mtime_ns) candidates. Shared by full
        scans and real-time batches so there is exactly one detection path."""
        def emit(phase, message="", current=0, total=0):
            if progress:
                progress(ProgressEvent(phase, message, current, total))

        result.files_scanned = len(files)
        total = len(files)

        if not files:
            emit("done", "Nothing new to scan (all cached clean)")
            result.finished = _now()
            return

        # 2. ClamAV signature scan over just the candidate files (file-list).
        list_path = None
        scan_complete = True
        try:
            list_path = self._write_file_list(files)
            emit("clamav", f"ClamAV signature scan ({total} files)", 0, total)
            clam_hits, clam_errs = self.clam.scan_filelist(list_path)
            result.detections.extend(clam_hits)
            # Only treat ClamAV problems as scan errors when ClamAV is present
            # but errored (a partial/failed signature pass). ClamAV simply
            # being absent is a supported mode -- the heuristic/hash/YARA layer
            # is authoritative there, the CLI already warns at startup, and
            # result.errors now drives a nonzero exit code -- so caching stays
            # enabled and the absence note stays out of `errors`.
            if self.clam.available and clam_errs:
                result.errors.extend(clam_errs)
                scan_complete = False
        finally:
            if list_path:
                try:
                    os.remove(list_path)
                except OSError:
                    pass

        # 3. Heuristic/hash/YARA layer, parallel across candidate files.
        #    Progress is throttled to ~30 events/sec so a huge drive can't flood
        #    the UI's event queue (the old per-file firehose caused the lag).
        if self.heur.enabled:
            done_n = 0
            last_emit = 0.0
            with ThreadPoolExecutor(max_workers=self.workers) as pool:
                futures = {pool.submit(self.heur.scan_file, p, s): p
                           for p, s, _mt in files}
                for fut in as_completed(futures):
                    p = futures[fut]
                    done_n += 1
                    now = time.monotonic()
                    if progress and (now - last_emit >= 0.03 or done_n == total):
                        last_emit = now
                        emit("scanning", p, done_n, total)
                    try:
                        result.detections.extend(fut.result())
                    except Exception as exc:  # never let one file kill the scan
                        result.errors.append(f"{p}: {exc}")

        # 3b. Download-origin check (Mark of the Web vs threat-intel feeds).
        #     Risky extensions only: it costs one extra open() per file, which
        #     a million-file media/backup walk must not pay. Runs in the same
        #     worker pool as the heuristics: with Safe Browsing enabled each
        #     uncached URL is a blocking HTTPS round-trip, and doing those one
        #     at a time added minutes to a scan whose other phases are
        #     parallel.
        if self.web.active:
            self._refresh_feeds()
            risky = [p for p, _s, _mt in files
                     if os.path.splitext(p)[1].lower() in self.heur.suspicious_ext]
            if risky:
                with ThreadPoolExecutor(max_workers=self.workers) as pool:
                    futures = {pool.submit(self.web.check_file, p): p
                               for p in risky}
                    for fut in as_completed(futures):
                        try:
                            result.detections.extend(fut.result())
                        except Exception as exc:
                            result.errors.append(f"{futures[fut]}: {exc}")

        # 4. Quarantine confirmed infections. Dedup by path first so a file hit
        #    by two layers isn't "quarantined" twice (2nd attempt would find it
        #    already moved and record a misleading quarantined_to=None).
        if quarantine:
            done: dict[str, Optional[str]] = {}
            for det in result.infected:
                key = _norm(det.path)
                if key not in done:
                    if not det.sha256:
                        det.sha256 = sha256_of(det.path)
                    done[key] = self.quar.store(det.path, det.threat, det.sha256)
                det.quarantined_to = done[key]

        # 5. Cache files that came back clean so next scan skips them. Match
        #    detections by normalized path (ClamAV may echo a path in different
        #    case/slash form than we listed), and never cache when the signature
        #    scan was incomplete -- both would let malware be skipped later.
        flagged = {_norm(d.path) for d in result.detections}
        if scan_complete:
            for path, size, mtime in files:
                if _norm(path) not in flagged:
                    # reuse size/mtime from the walk -- no extra os.stat per file
                    self.cache.mark_clean(path, size, mtime)
            if save_cache:
                self.cache.save()

        result.finished = _now()
        return result

    def _refresh_feeds(self) -> None:
        """Pick up feed files the daily sync task rewrote.

        Long-lived processes (`usbscan monitor` as a logon task, an open GUI)
        would otherwise keep the intel snapshot taken when they started, so
        "synced daily" would really mean "as of last reboot". Cheap: a few
        stats, and a re-read only when something actually changed.
        """
        self.web.reload_if_changed()
        # Feed-synced hash blocklists (usbscan feeds, type: sha256) join the
        # same hash layer as the company blocklist — one detection path.
        sig = feed_signature(self.web.feeds_dir, ".sha256.txt")
        if sig == self._hash_feed_sig:
            return
        self._hash_feed_sig = sig
        for name, _mtime, _size in sig:
            self.heur.add_hash_blocklist(os.path.join(self.web.feeds_dir, name))

    def scan_many(self, targets: List,
                  progress: Optional[Callable[[ProgressEvent], None]] = None,
                  quarantine: bool = True,
                  explicit: bool = True) -> ScanResult:
        """Scan several roots (a scan profile) and merge them into one result.

        `targets` is a list of paths, or of (path, explicit) pairs when the
        roots don't share one origin — e.g. `scan --profile quick D:\\x` mixes
        a machine-chosen set with a path the user named. Explicitness is a
        property of each target, so it is resolved here rather than by callers
        running two scans and merging by hand (which double-scanned any path
        appearing in both lists).

        A Full scan spanning three drives gives the user one verdict and one
        report, not three. Each root is still walked independently so one
        unreadable drive can't abort the rest.

        The cache is saved once at the end, not per root: cache.save() rewrites
        the ENTIRE cache file, and after scanning C:\\ that is a huge JSON blob
        we'd otherwise re-serialize for every remaining drive.
        """
        pairs = [t if isinstance(t, tuple) else (t, explicit) for t in targets]
        merged = ScanResult(
            target=", ".join(p for p, _e in pairs) or "(no targets)",
            started=_now())
        for path, is_explicit in pairs:
            r = self.scan(path, progress=progress, quarantine=quarantine,
                          explicit=is_explicit, save_cache=False)
            merged.merge(r)
        if pairs:
            self.cache.save()
        merged.finished = _now()
        return merged

    def _walk(self, target: str, result: ScanResult, explicit: bool = True):
        """Yield (path, size, mtime_ns) for every file under target, honoring
        the size cap and configured exclusions. Uses os.scandir (faster than
        os.walk on big trees).

        Excluded directories are pruned rather than filtered, so a skipped tree
        costs one comparison instead of a full traversal.

        For an explicit (user-named) root, rules blanketing the root are
        dropped for this walk (see ExclusionMatcher.for_explicit_root) so the
        scan can't report a false "0 files, CLEAN"; deeper exclusions still
        apply. Machine-generated roots keep the full rule set.
        """
        excl = (self.exclusions.for_explicit_root(target) if explicit
                else self.exclusions)
        excluding = excl.active   # hoisted: skip ~1M no-op calls on big walks
        if os.path.isfile(target):
            try:
                st = os.stat(target)
                if st.st_size <= self.max_bytes:
                    yield target, st.st_size, st.st_mtime_ns
                else:
                    result.files_skipped += 1
            except OSError:
                result.files_skipped += 1
            return
        stack = [target]
        while stack:
            d = stack.pop()
            try:
                with os.scandir(d) as it:
                    for entry in it:
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                if excluding and excl.excludes(entry.path):
                                    result.files_skipped += 1
                                    continue
                                stack.append(entry.path)
                                continue
                            if not entry.is_file(follow_symlinks=False):
                                continue
                            if excluding and excl.excludes(entry.path):
                                result.files_skipped += 1
                                continue
                            st = entry.stat(follow_symlinks=False)
                            if st.st_size > self.max_bytes:
                                result.files_skipped += 1
                                continue
                            yield entry.path, st.st_size, st.st_mtime_ns
                        except OSError:
                            result.files_skipped += 1
            except OSError:
                continue

    @staticmethod
    def _write_file_list(files: List[tuple]) -> str:
        # UTF-8 is correct for ClamAV 1.x (the version we bundle) on every
        # platform. ASCII paths work with any build; any file ClamAV can't
        # reopen is still fully covered by the hash/YARA layer, which uses
        # Python's native path handling.
        fd, path = tempfile.mkstemp(prefix="usbscan_list_", suffix=".txt")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            for p, *_rest in files:
                fh.write(p + "\n")
        return path
