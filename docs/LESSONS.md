# Lessons from failures

Appended by the `failure-coach` agent (and humans). One entry per root cause;
extend an entry rather than duplicating its rule. Newest at the bottom.

## 2026-07-15 — Excluded scan root reported a false "0 files, CLEAN"
- **Failure mode:** `usbscan scan D:\VMs` while `D:\VMs` was in `exclusions`
  walked zero files and printed CLEAN — a false all-clear.
- **Root cause:** exclusion matching applied to the walk root itself, not just
  to entries discovered under it; explicit user intent lost to config.
- **Rule:** an explicit user request must never become a silent clean verdict;
  when coverage shrinks, it must show in `files_skipped`, never in silence.
- **Guarded by:** tests/test_engine.py::test_target_root_scanned_even_if_excluded,
  tests/test_targets.py::test_without_matching_keeps_unrelated_rules.

## 2026-07-15 — macOS boot volume enumerated twice
- **Failure mode:** Full scan would walk the system disk twice (`/` and
  `/Volumes/Macintosh HD` are the same device).
- **Root cause:** POSIX enumerator treated every `/Volumes/*` entry as a
  distinct removable drive without checking the device id.
- **Rule:** drive enumeration must dedupe by identity (st_dev), not by path
  string — mounts are aliases, paths are not identities.
- **Guarded by:** tests/test_targets.py::test_posix_boot_volume_not_listed_twice.

## 2026-07-15 — Review of phases 1-2 caught four false-all-clear bugs
- **Failure mode:** (a) `scan --profile quick E:\` silently never scanned E:\;
  (b) exclusions were overridden even for watcher/profile-chosen roots;
  (c) GUI pre-selected C:\ when no USB was attached; (d) a scan that failed to
  read a whole drive still exited 0 "clean".
- **Root cause:** each feature reasoned about "the target" without asking *who
  chose it* — a human-named target and a machine-generated one need opposite
  defaults (override exclusions vs honor them; scan vs never pre-select).
- **Rule:** every scan entry point must carry explicit user intent
  (`explicit=` in `ScanEngine.scan`), and anything reducing coverage must be
  visible in the result (errors → exit 3, skips → files_skipped).
- **Guarded by:** tests/test_cli.py::test_scan_exit_3_when_target_unreadable,
  tests/test_engine.py::test_non_explicit_scan_honors_root_exclusion,
  tests/test_engine.py::test_explicit_root_name_rule_keeps_nested_pruning.

## 2026-07-15 — Exclusion patterns silently no-opped on the deployment OS
- **Failure mode:** `\Windows\WinSxS` (driveless) matched on macOS dev boxes
  but never on drive-lettered Windows paths; `D:\VMs [old]` was misread as a
  glob because `[` was treated as a wildcard.
- **Root cause:** pattern semantics tested only on the dev platform; Windows
  is the deployment target but has no CI coverage.
- **Rule:** path-matching logic must be tested against Windows-shaped inputs
  ("c:/..." strings) directly, not only through platform-dependent os.path.
- **Guarded by:** tests/test_targets.py::test_driveless_pattern_matching_is_platform_independent,
  tests/test_targets.py::test_bracket_is_literal_not_glob.
