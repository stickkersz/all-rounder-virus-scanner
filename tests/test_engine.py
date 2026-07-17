"""ScanEngine end-to-end (heuristic/hash/YARA layers; ClamAV absent in CI)."""

import os

from scanner.engine import ScanEngine, _auto_workers
from scanner.models import Severity


def _engine(config, tmp_path):
    return ScanEngine(config, base_dir=str(tmp_path))


def test_auto_workers():
    cap = 64 * 1024 * 1024
    assert _auto_workers(4, cap) == 4               # explicit override wins
    assert 1 <= _auto_workers("auto", cap) <= 8     # auto: RAM-clamped 1..8
    assert 1 <= _auto_workers(0, cap) <= 8          # invalid -> auto


def test_scan_detects_threats(config, fake_usb, tmp_path):
    eng = _engine(config, tmp_path)
    res = eng.scan(str(fake_usb["dir"]), quarantine=False)
    assert not res.clean
    assert len(res.infected) >= 2          # hash + yara at least
    assert len(res.suspicious) >= 1        # autorun / double-ext
    threats = {d.source for d in res.detections}
    assert "hash" in threats and "yara" in threats and "heuristic" in threats


def test_report_only_leaves_files(config, fake_usb, tmp_path):
    eng = _engine(config, tmp_path)
    eng.scan(str(fake_usb["dir"]), quarantine=False)
    assert (fake_usb["dir"] / "mal.bin").exists()      # untouched


def test_quarantine_removes_infected(config, fake_usb, tmp_path):
    eng = _engine(config, tmp_path)
    res = eng.scan(str(fake_usb["dir"]), quarantine=True)
    assert not (fake_usb["dir"] / "mal.bin").exists()  # moved to quarantine
    assert (fake_usb["dir"] / "notes.txt").exists()    # clean file kept
    assert all(d.quarantined_to for d in res.infected)


def test_cache_skips_unchanged_on_rescan(config, fake_usb, tmp_path):
    eng = _engine(config, tmp_path)
    eng.scan(str(fake_usb["dir"]), quarantine=False)
    res2 = eng.scan(str(fake_usb["dir"]), quarantine=False)
    # clean files (notes.txt) cached -> skipped on 2nd pass
    assert res2.files_skipped >= 1


def test_nonexistent_target(config, tmp_path):
    eng = _engine(config, tmp_path)
    res = eng.scan(str(tmp_path / "ghost"))
    assert res.errors and res.clean


def test_size_cap_skips_large(config, fake_usb, tmp_path):
    config.data["scanner"]["max_file_size_mb"] = 0     # everything too big
    eng = _engine(config, tmp_path)
    res = eng.scan(str(fake_usb["dir"]), quarantine=False)
    assert res.files_scanned == 0
    assert res.files_skipped >= 4


def test_scan_single_file(config, fake_usb, tmp_path):
    eng = _engine(config, tmp_path)
    res = eng.scan(str(fake_usb["dir"] / "dl.ps1"), quarantine=False)
    assert res.files_scanned == 1
    assert any(d.source == "yara" for d in res.detections)


def test_double_flagged_file_quarantined_once(config, fake_usb, tmp_path, monkeypatch):
    """A file hit by two layers must show one consistent quarantine location,
    not a second 'quarantined_to=None' from a duplicate move attempt."""
    from scanner.models import Detection, Severity
    eng = _engine(config, tmp_path)
    mal = str(fake_usb["dir"] / "mal.bin")
    # force a ClamAV hit on the SAME file the hash layer also flags
    monkeypatch.setattr(eng.clam, "clamscan", "/bin/true")  # make .available True
    monkeypatch.setattr(eng.clam, "scan_filelist",
                        lambda lp: ([Detection(mal, Severity.INFECTED,
                                               "Test.Sig", "clamav")], []))
    result = eng.scan(str(fake_usb["dir"]), quarantine=True)
    dups = [d for d in result.infected if d.path == mal]
    assert len(dups) >= 2                         # hash + clamav, same file
    assert all(d.quarantined_to for d in dups)    # both show the same location


def test_no_cache_when_clamav_errors(config, fake_usb, tmp_path, monkeypatch):
    """If ClamAV is present but the signature pass errors, nothing is cached
    (so a missed infection can't be skipped on the next scan)."""
    eng = _engine(config, tmp_path)
    monkeypatch.setattr(eng.clam, "clamscan", "/bin/true")  # make .available True
    monkeypatch.setattr(eng.clam, "scan_filelist",
                        lambda lp: ([], ["clamd connection failed"]))
    eng.scan(str(fake_usb["dir"]), quarantine=False)
    # clean file NOT cached -> rescan still processes it
    res2 = eng.scan(str(fake_usb["dir"]), quarantine=False)
    assert res2.files_skipped == 0


def test_clamd_down_falls_back_to_clamscan(config, tmp_path, monkeypatch):
    """If the daemon errors (clamd not running), scan_filelist retries with
    one-shot clamscan instead of failing the whole signature pass."""
    from scanner.engine import ClamAV
    clam = ClamAV(config["scanner"])
    clam.clamdscan = "/bin/clamdscan"     # pretend both exist
    clam.clamscan = "/bin/clamscan"
    clam.prefer_daemon = True
    calls = []

    def fake_run(binary, is_daemon, lp):
        calls.append(is_daemon)
        if is_daemon:
            return [], ["Could not connect to clamd"]     # daemon down
        return [], []                                      # clamscan clean
    monkeypatch.setattr(clam, "_run", fake_run)
    dets, errs = clam.scan_filelist("list.txt")
    assert calls == [True, False]         # tried daemon, then fell back
    assert errs == []                     # clamscan succeeded


def test_cache_path_normalized_match(config, fake_usb, tmp_path, monkeypatch):
    """A ClamAV hit echoed with different case/slashes still marks the file
    infected (not cached clean) thanks to normalized matching."""
    from scanner.models import Detection, Severity
    eng = _engine(config, tmp_path)
    target = fake_usb["dir"] / "notes.txt"
    weird = str(target).upper() if os.name == "nt" else str(target)
    monkeypatch.setattr(eng.clam, "clamscan", "/bin/true")  # make .available True
    monkeypatch.setattr(eng.clam, "scan_filelist",
                        lambda lp: ([Detection(weird, Severity.INFECTED,
                                               "Test.Sig", "clamav")], []))
    res = eng.scan(str(fake_usb["dir"]), quarantine=False)
    from scanner.engine import _norm
    flagged = {_norm(d.path) for d in res.detections}
    assert _norm(str(target)) in flagged


# ---- exclusions ---------------------------------------------------------
def _cfg_with_exclusions(config, patterns):
    config.data["scanner"]["exclusions"] = patterns
    return config


def test_no_exclusions_by_default(config, fake_usb, tmp_path):
    """Nothing is excluded unless the user opts in — coverage is the default."""
    eng = _engine(config, tmp_path)
    assert not eng.exclusions.active
    res = eng.scan(str(fake_usb["dir"]), quarantine=False)
    assert len(res.infected) >= 2


def test_excluded_dir_is_not_scanned(config, fake_usb, tmp_path):
    """A directory exclusion hides the malware inside it (the coverage hole the
    config warns about) — proves pruning actually takes effect."""
    vms = fake_usb["dir"] / "VMs"
    vms.mkdir()
    (vms / "mal.bin").write_bytes(b"known-bad-payload-bytes")   # blocklisted hash
    eng = _engine(_cfg_with_exclusions(config, [str(vms)]), tmp_path)
    res = eng.scan(str(fake_usb["dir"]), quarantine=False)
    hit_paths = {os.path.normcase(d.path) for d in res.detections}
    assert os.path.normcase(str(vms / "mal.bin")) not in hit_paths
    # the identical payload OUTSIDE the excluded dir is still caught
    assert os.path.normcase(str(fake_usb["dir"] / "mal.bin")) in hit_paths


def test_excluded_file_glob_is_not_scanned(config, fake_usb, tmp_path):
    (fake_usb["dir"] / "disk.iso").write_bytes(b"known-bad-payload-bytes")
    eng = _engine(_cfg_with_exclusions(config, ["*.iso"]), tmp_path)
    res = eng.scan(str(fake_usb["dir"]), quarantine=False)
    assert not any(d.path.endswith(".iso") for d in res.detections)


def test_target_root_scanned_even_if_excluded(config, fake_usb, tmp_path):
    """Explicitly asking to scan a path beats an exclusion matching it —
    otherwise the scan silently does nothing."""
    eng = _engine(_cfg_with_exclusions(config, [str(fake_usb["dir"])]), tmp_path)
    res = eng.scan(str(fake_usb["dir"]), quarantine=False)
    assert len(res.infected) >= 1


def test_excluded_dir_counts_as_skipped(config, fake_usb, tmp_path):
    sub = fake_usb["dir"] / "cache"
    sub.mkdir()
    (sub / "a.txt").write_text("x")
    eng = _engine(_cfg_with_exclusions(config, ["cache"]), tmp_path)
    res = eng.scan(str(fake_usb["dir"]), quarantine=False)
    assert res.files_skipped >= 1


# ---- scan_many (scan profiles) ------------------------------------------
def test_scan_many_merges_results(config, fake_usb, tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    (other / "mal2.bin").write_bytes(b"known-bad-payload-bytes")
    eng = _engine(config, tmp_path)
    res = eng.scan_many([str(fake_usb["dir"]), str(other)], quarantine=False)
    paths = {os.path.basename(d.path) for d in res.detections}
    assert "mal.bin" in paths and "mal2.bin" in paths
    assert res.files_scanned >= 2
    assert res.finished and str(other) in res.target


def test_scan_many_one_bad_root_does_not_abort_rest(config, fake_usb, tmp_path):
    eng = _engine(config, tmp_path)
    res = eng.scan_many([str(tmp_path / "does-not-exist"), str(fake_usb["dir"])],
                        quarantine=False)
    assert any("does not exist" in e.lower() for e in res.errors)
    assert len(res.infected) >= 1          # the good root still scanned


def test_scan_many_empty_targets(config, tmp_path):
    eng = _engine(config, tmp_path)
    res = eng.scan_many([], quarantine=False)
    assert res.clean and res.files_scanned == 0


# ---- explicit vs machine-generated roots (review findings) ---------------
def test_non_explicit_scan_honors_root_exclusion(config, fake_usb, tmp_path):
    """Watcher/profile-derived root that the admin excluded: honored, and
    recorded in errors (visible partial coverage), never silently walked."""
    eng = _engine(_cfg_with_exclusions(config, [str(fake_usb["dir"])]), tmp_path)
    res = eng.scan(str(fake_usb["dir"]), quarantine=False, explicit=False)
    assert res.files_scanned == 0
    assert any("excluded by config" in e.lower() for e in res.errors)


def test_explicit_scan_overrides_root_exclusion(config, fake_usb, tmp_path):
    eng = _engine(_cfg_with_exclusions(config, [str(fake_usb["dir"])]), tmp_path)
    res = eng.scan(str(fake_usb["dir"]), quarantine=False, explicit=True)
    assert len(res.infected) >= 1


def test_explicit_root_name_rule_keeps_nested_pruning(config, tmp_path):
    """scan .../node_modules explicitly: nested node_modules still pruned."""
    root = tmp_path / "proj" / "node_modules"
    nested = root / "pkg" / "node_modules"
    nested.mkdir(parents=True)
    (root / "mal.bin").write_bytes(b"known-bad-payload-bytes")
    (nested / "mal.bin").write_bytes(b"known-bad-payload-bytes")
    eng = _engine(_cfg_with_exclusions(config, ["node_modules"]), tmp_path)
    res = eng.scan(str(root), quarantine=False)
    paths = {os.path.normcase(d.path) for d in res.detections}
    assert os.path.normcase(str(root / "mal.bin")) in paths
    assert os.path.normcase(str(nested / "mal.bin")) not in paths


def test_clamav_absence_is_not_a_scan_error(config, fake_usb, tmp_path):
    """No ClamAV installed is a supported mode; it must not push the exit
    code to 'completed with errors'."""
    eng = _engine(config, tmp_path)
    eng.clam.clamscan = None
    eng.clam.clamdscan = None
    res = eng.scan(str(fake_usb["dir"]), quarantine=False)
    assert not any("clamav" in e.lower() for e in res.errors)


def test_scan_many_saves_cache_once(config, fake_usb, tmp_path, monkeypatch):
    other = tmp_path / "o"
    other.mkdir()
    (other / "a.txt").write_text("x")
    eng = _engine(config, tmp_path)
    calls = []
    monkeypatch.setattr(eng.cache, "save", lambda: calls.append(1))
    eng.scan_many([str(fake_usb["dir"]), str(other)], quarantine=False)
    assert len(calls) == 1
