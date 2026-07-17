"""CLI smoke tests via subprocess — verifies commands + exit codes."""

import os
import subprocess
import sys

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run(args, **kw):
    return subprocess.run([sys.executable, os.path.join(ROOT, "cli.py"), *args],
                          capture_output=True, text=True, cwd=ROOT, **kw)


def _write_cfg(tmp_path, signatures):
    cfg = {
        "scanner": {"prefer_daemon": False},
        "heuristics": {"enabled": True,
                       "hash_blocklist": str(signatures / "hash_blocklist.txt"),
                       "yara_rules_dir": str(signatures / "yara")},
        "quarantine": {"path": str(tmp_path / "q")},
        "logging": {"path": str(tmp_path / "logs")},
        "reporting": {"path": str(tmp_path / "rep")},
    }
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump(cfg))
    return str(p)


def test_version():
    r = _run(["version"])
    assert r.returncode == 0 and "All-Round Virus Scanner" in r.stdout


def test_drives_runs():
    r = _run(["drives"])
    assert r.returncode == 0


def test_drives_all_runs():
    r = _run(["drives", "--all"])
    assert r.returncode == 0


def test_scan_without_path_or_profile_errors():
    r = _run(["scan"])
    assert r.returncode == 2
    assert "--profile" in r.stderr


def test_scan_custom_profile_scans_given_path(tmp_path, signatures, fake_usb):
    cfg = _write_cfg(tmp_path, signatures)
    r = _run(["-c", cfg, "scan", "--profile", "custom", str(fake_usb["dir"]),
              "--no-quarantine"])
    assert r.returncode == 1                       # threats found
    assert "THREATS FOUND" in r.stdout


def test_scan_custom_profile_without_path_errors(tmp_path, signatures):
    cfg = _write_cfg(tmp_path, signatures)
    r = _run(["-c", cfg, "scan", "--profile", "custom"])
    assert r.returncode == 2
    assert "custom profile requires" in r.stderr


def test_scan_bare_path_still_works(tmp_path, signatures, fake_usb):
    """The original `scan <path>` flow must keep working (spec §8)."""
    cfg = _write_cfg(tmp_path, signatures)
    r = _run(["-c", cfg, "scan", str(fake_usb["dir"]), "--no-quarantine"])
    assert r.returncode == 1 and "THREATS FOUND" in r.stdout


def test_scan_rejects_unknown_profile(tmp_path, signatures):
    cfg = _write_cfg(tmp_path, signatures)
    r = _run(["-c", cfg, "scan", "--profile", "turbo"])
    assert r.returncode != 0                       # argparse rejects the choice


def test_scan_clean_exit_zero(tmp_path, signatures):
    cfg = _write_cfg(tmp_path, signatures)
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "hello.txt").write_text("hi")
    r = _run(["-c", cfg, "scan", str(clean), "--no-quarantine"])
    assert r.returncode == 0
    assert "CLEAN" in r.stdout


def test_scan_infected_exit_one(tmp_path, signatures, fake_usb):
    cfg = _write_cfg(tmp_path, signatures)
    r = _run(["-c", cfg, "scan", str(fake_usb["dir"]), "--no-quarantine"])
    assert r.returncode == 1                       # threats -> exit 1
    assert "THREATS FOUND" in r.stdout


def test_bad_command_errors():
    r = _run(["nonsense"])
    assert r.returncode != 0


def test_quarantine_purge_empty(tmp_path, signatures):
    cfg = _write_cfg(tmp_path, signatures)
    r = _run(["-c", cfg, "quarantine", "--purge", "--yes"])
    assert r.returncode == 0
    assert "empty" in r.stdout.lower()


def test_quarantine_scan_then_purge(tmp_path, signatures, fake_usb):
    cfg = _write_cfg(tmp_path, signatures)
    # scan WITH quarantine (default) so infected files land in quarantine
    _run(["-c", cfg, "scan", str(fake_usb["dir"])])
    listed = _run(["-c", cfg, "quarantine"])
    assert "ID" in listed.stdout                    # something quarantined
    purged = _run(["-c", cfg, "quarantine", "--purge", "--yes"])
    assert "Permanently deleted" in purged.stdout
    after = _run(["-c", cfg, "quarantine"])
    assert "empty" in after.stdout.lower()          # gone forever


def test_quarantine_delete_unknown_id(tmp_path, signatures):
    cfg = _write_cfg(tmp_path, signatures)
    r = _run(["-c", cfg, "quarantine", "--delete", "does-not-exist"])
    assert r.returncode == 1
    assert "failed" in r.stdout.lower()


def test_scan_profile_plus_path_scans_both(tmp_path, signatures, fake_usb):
    """--profile quick E:\\ must scan E:\\ too — silently dropping a path the
    user typed is a false all-clear (review finding)."""
    cfg = _write_cfg(tmp_path, signatures)
    empty = tmp_path / "emptyquick"
    empty.mkdir()
    r = _run(["-c", cfg, "scan", "--profile", "custom", str(empty),
              "--no-quarantine"])
    assert r.returncode == 0                       # sanity: empty dir is clean
    r = _run(["-c", cfg, "scan", str(fake_usb["dir"]), "--no-quarantine"])
    assert r.returncode == 1                       # explicit path is scanned


def test_scan_exit_3_when_target_unreadable(tmp_path, signatures):
    """A scan that couldn't cover its target must not exit 0 (review finding:
    GPO scripts treated partial scans as clean)."""
    cfg = _write_cfg(tmp_path, signatures)
    r = _run(["-c", cfg, "scan", str(tmp_path / "does-not-exist"),
              "--no-quarantine"])
    assert r.returncode == 3
    assert "THREATS" not in r.stdout or "CLEAN" not in r.stdout


def test_drives_bare_output_is_script_parseable():
    """Plain `drives` prints bare roots (v1 stdout contract for GPO scripts);
    kind labels only appear in --all/--fixed/--network modes."""
    r = _run(["drives"])
    assert r.returncode == 0
    for line in r.stdout.splitlines():
        if line and not line.startswith("No matching"):
            assert "[" not in line
