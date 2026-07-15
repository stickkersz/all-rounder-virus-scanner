"""Scan engine: orchestrates ClamAV + the heuristic layer, then quarantines hits.

ClamAV does the heavy signature lifting (multi-million malware DB, archive
unpacking). The heuristic layer adds USB-specific detections and a company
hash/YARA blocklist. Results are merged and infected files are quarantined.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Callable, List, Optional

from .cache import ScanCache
from .heuristics import HeuristicEngine, sha256_of
from .models import Detection, ScanResult, Severity
from .quarantine import Quarantine


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


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
        """
        chosen = self._binary()
        if not chosen:
            return [], ["ClamAV binary not found; signature scan skipped."]
        binary, is_daemon = chosen

        cmd = [binary, "--no-summary", "--infected", f"--file-list={list_path}"]
        if not is_daemon:
            cmd += [f"--max-filesize={self.max_mb}M",
                    f"--max-scansize={self.max_mb}M"]
            cmd.append("--scan-archive=yes" if self.scan_archives
                       else "--scan-archive=no")
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


def _auto_workers(configured) -> int:
    """Resolve worker count. 'auto' -> scale to cores but stay modest so slow
    single-disk laptops don't thrash on seeks."""
    if isinstance(configured, int) and configured > 0:
        return configured
    cpu = os.cpu_count() or 2
    return max(2, min(8, cpu))


class ScanEngine:
    def __init__(self, config, base_dir: str):
        self.config = config
        self.base_dir = base_dir
        self.clam = ClamAV(config["scanner"])
        self.heur = HeuristicEngine(config["heuristics"], base_dir)
        self.quar = Quarantine(config["quarantine"])
        self.workers = _auto_workers(config["scanner"].get("workers", "auto"))
        self.max_bytes = config["scanner"].get("max_file_size_mb", 200) * 1024 * 1024
        cache_path = os.path.join(config["logging"].get("path", "."), "scan_cache.json")
        self.cache = ScanCache(cache_path,
                               enabled=config["scanner"].get("use_cache", True))

    def scan(self, target: str,
             progress: Optional[Callable[[str], None]] = None,
             quarantine: bool = True) -> ScanResult:
        result = ScanResult(target=target, started=_now())
        if not os.path.exists(target):
            result.errors.append(f"Target does not exist: {target}")
            result.finished = _now()
            return result

        # 1. Single tree walk. Collect (path, size, mtime_ns); apply size cap;
        #    skip files already scanned clean (unchanged) via the cache.
        if progress:
            progress(f"indexing {target}")
        files: List[tuple[str, int]] = []   # (path, size) for the heuristic pass
        cached_clean = 0
        for path, size, mtime in self._walk(target, result):
            if self.cache.is_clean(path, size, mtime):
                cached_clean += 1
                continue
            files.append((path, size))
        result.files_scanned = len(files)
        result.files_skipped += cached_clean

        if not files:
            if progress:
                progress("nothing new to scan (all cached clean)")
            result.finished = _now()
            return result

        # 2. ClamAV signature scan over just the candidate files (file-list).
        list_path = None
        try:
            list_path = self._write_file_list(files)
            if progress:
                progress(f"ClamAV signature scan: {len(files)} file(s)")
            clam_hits, clam_errs = self.clam.scan_filelist(list_path)
            result.detections.extend(clam_hits)
            result.errors.extend(clam_errs)
        finally:
            if list_path:
                try:
                    os.remove(list_path)
                except OSError:
                    pass

        # 3. Heuristic/hash/YARA layer, parallel across candidate files.
        if self.heur.enabled:
            with ThreadPoolExecutor(max_workers=self.workers) as pool:
                futures = {pool.submit(self.heur.scan_file, p, s): p
                           for p, s in files}
                for fut in as_completed(futures):
                    p = futures[fut]
                    if progress:
                        progress(f"heuristic: {p}")
                    try:
                        result.detections.extend(fut.result())
                    except Exception as exc:  # never let one file kill the scan
                        result.errors.append(f"{p}: {exc}")

        # 4. Quarantine confirmed infections (fill sha256 if missing).
        if quarantine:
            for det in result.infected:
                if not det.sha256:
                    det.sha256 = sha256_of(det.path)
                q = self.quar.store(det.path, det.threat, det.sha256)
                det.quarantined_to = q

        # 5. Cache the files that came back clean so next scan skips them.
        flagged = {d.path for d in result.detections}
        for path, size in files:
            if path not in flagged:
                try:
                    st = os.stat(path)
                    self.cache.mark_clean(path, st.st_size, st.st_mtime_ns)
                except OSError:
                    pass
        self.cache.save()

        result.finished = _now()
        return result

    def _walk(self, target: str, result: ScanResult):
        """Yield (path, size, mtime_ns) for every file under target, honoring
        the size cap. Uses os.scandir (faster than os.walk on big trees)."""
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
                                stack.append(entry.path)
                                continue
                            if not entry.is_file(follow_symlinks=False):
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
    def _write_file_list(files: List[tuple[str, int]]) -> str:
        fd, path = tempfile.mkstemp(prefix="usbscan_list_", suffix=".txt")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            for p, _size in files:
                fh.write(p + "\n")
        return path
