#!/usr/bin/env python3
"""All-Round Virus Scanner - command-line entry point.

Commands:
  scan <path>       Scan a drive/folder/file now.
  scan --profile    Scan a preset target set (quick/full/custom).
  watch             Auto-scan every removable drive as it is inserted.
  monitor           Real-time: scan files the moment they land (watchdog).
  drives            List currently attached drives.
  quarantine        List or restore quarantined files.
  update            Update ClamAV signatures via freshclam.
  feeds             Sync threat-intel feeds (URLhaus) for origin checks.
  version           Print version.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import threading

from scanner import __version__
from scanner.config import Config
from scanner.drives import FIXED, NETWORK, REMOVABLE, list_drives
from scanner.engine import ScanEngine
from scanner.paths import app_base_dir, norm_for_match
from scanner.profiles import PROFILES, dedupe_roots, resolve_targets
from scanner.realtime import RealtimeMonitor
from scanner.reporter import log_result, setup_logging, write_report
from scanner.watcher import DriveWatcher, list_removable

BASE_DIR = app_base_dir()


def _load(args) -> tuple[Config, ScanEngine, object]:
    cfg = Config.load(args.config)
    logger = setup_logging(cfg["logging"])
    engine = ScanEngine(cfg, BASE_DIR)
    if not engine.clam.available:
        logger.warning("ClamAV not found - running heuristic/hash/YARA layer only. "
                       "Install ClamAV for full signature coverage.")
    return cfg, engine, logger


def _print_summary(result, report_path: str) -> None:
    verdict = "CLEAN" if result.clean else "THREATS FOUND"
    print("-" * 60)
    print(f"Target   : {result.target}")
    print(f"Scanned  : {result.files_scanned} files "
          f"({result.files_skipped} skipped)")
    print(f"Infected : {len(result.infected)}   "
          f"Suspicious: {len(result.suspicious)}")
    print(f"Verdict  : {verdict}")
    for d in result.infected:
        moved = f"  -> quarantined: {d.quarantined_to}" if d.quarantined_to else ""
        cat = f" <{d.category}>" if d.category else ""
        print(f"  [INFECTED]{cat}   {d.threat}  {d.path}{moved}")
    for d in result.suspicious:
        cat = f" <{d.category}>" if d.category else ""
        print(f"  [SUSPICIOUS]{cat} {d.threat}  {d.path}")
    print(f"Report   : {report_path}")
    print("-" * 60)


def _fmt_progress(ev) -> str:
    if ev.phase == "scanning" and ev.total:
        return f"  [{ev.current}/{ev.total}] {ev.message}"
    return f"  {ev.message}"


def _scan_targets(cfg, args) -> list:
    """Resolve what to scan, as (path, explicit) pairs.

    Positional paths given ALONGSIDE --profile quick/full are scanned in
    addition to the profile — silently discarding a path the user typed would
    be a false all-clear on exactly what they asked about. Explicit paths
    override exclusions blanketing them; profile roots honor exclusions fully.

    Explicit paths are listed first so de-duplication keeps them (and their
    explicitness) when a path appears in both sets — otherwise
    `scan --profile quick ~/Downloads` would walk Downloads twice and report
    every detection in it twice.
    """
    net = cfg["scanner"].get("scan_network_drives", False)
    if not args.profile:
        explicit, profile = dedupe_roots(args.path), []
    elif args.profile == "custom":
        explicit = resolve_targets("custom", custom=args.path,
                                   include_network=net)
        profile = []
    else:
        explicit = dedupe_roots(args.path)
        profile = resolve_targets(args.profile, include_network=net)
    explicit_norms = {norm_for_match(p) for p in explicit}
    return [(p, norm_for_match(p) in explicit_norms)
            for p in dedupe_roots(explicit + profile)]


def cmd_scan(args) -> int:
    cfg, engine, logger = _load(args)
    try:
        targets = _scan_targets(cfg, args)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not targets:
        print("error: give a path to scan, or --profile quick|full|custom",
              file=sys.stderr)
        return 2

    print(f"Scanning {len(targets)} target(s): "
          f"{', '.join(p for p, _e in targets)}")
    progress = (lambda ev: print(_fmt_progress(ev))) if args.verbose else None
    result = engine.scan_many(targets, progress=progress,
                              quarantine=not args.no_quarantine)

    log_result(logger, result)
    report = write_report(cfg["reporting"], result)
    _print_summary(result, report)
    # 0 = clean; 1 = threats; 3 = completed with errors (partial coverage —
    # e.g. an unreadable drive). A scan that couldn't cover everything must
    # not report the same exit code as a genuine clean scan.
    if result.infected:
        return 1
    return 3 if result.errors else 0


def cmd_watch(args) -> int:
    cfg, engine, logger = _load(args)
    poll = cfg["watcher"].get("poll_interval", 3)
    quarantine = not args.no_quarantine

    def on_insert(root: str) -> None:
        logger.info("Removable drive inserted: %s - auto-scanning", root)
        print(f"\n[+] Drive inserted: {root} - scanning...")
        # Machine-initiated scan: exclusions apply fully (explicit=False), so
        # an admin CAN exclude a known-huge drive from auto-scan.
        result = engine.scan(root, quarantine=quarantine, explicit=False)
        log_result(logger, result)
        report = write_report(cfg["reporting"], result)
        _print_summary(result, report)
        if result.infected:
            print(f"\n  !!! {len(result.infected)} THREAT(S) on {root} - quarantined.")

    print(f"All-Round Virus Scanner watcher running (poll {poll}s). Ctrl+C to stop.")
    print(f"Currently attached removable drives: {list_removable() or 'none'}")
    watcher = DriveWatcher(on_insert, poll_interval=poll)
    try:
        watcher.run_forever()
    except KeyboardInterrupt:
        print("\nWatcher stopped.")
    return 0


def cmd_monitor(args) -> int:
    cfg, engine, logger = _load(args)

    def on_result(result) -> None:
        log_result(logger, result)
        if result.detections:
            write_report(cfg["reporting"], result)
            for d in result.infected:
                moved = (f" -> quarantined: {d.quarantined_to}"
                         if d.quarantined_to else "")
                print(f"  !!! [INFECTED]   {d.threat}  {d.path}{moved}")
            for d in result.suspicious:
                print(f"  !   [SUSPICIOUS] {d.threat}  {d.path}")

    # from_config derives watch roots AND the ignore list (our own quarantine/
    # log/report/feeds dirs) so this command can't forget one and end up
    # scanning its own output in a loop.
    quarantine = False if args.no_quarantine else None
    monitor = RealtimeMonitor.from_config(engine, cfg, on_result,
                                          quarantine=quarantine)
    warning = monitor.clamd_warning()
    if warning:
        logger.warning(warning)
    try:
        monitor.start()
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print("Real-time monitor running. Watching:")
    for r in monitor.roots:
        print(f"  {r}")
    print("Ctrl+C to stop.")
    try:
        threading.Event().wait()      # sleep until interrupted
    except KeyboardInterrupt:
        print("\nStopping monitor...")
        monitor.stop()                # stop() drains + flushes the cache
    return 0


def cmd_drives(args) -> int:
    kinds = [REMOVABLE]
    if args.all or args.fixed:
        kinds.append(FIXED)
    if args.all or args.network:
        kinds.append(NETWORK)
    drives = list_drives(tuple(kinds))
    if not drives:
        print("No matching drives detected.")
    for d in drives:
        # Bare roots by default in EVERY mode: `drives` and `drives --all` are
        # documented as script-usable, and GPO scripts feed these lines
        # straight back into `scan`. Labels are opt-in via --kinds.
        print(d if args.kinds else d.root)
    return 0


def cmd_quarantine(args) -> int:
    cfg = Config.load(args.config)
    from scanner.quarantine import Quarantine
    q = Quarantine(cfg["quarantine"])
    if args.restore:
        dest = q.restore(args.restore, to=args.to)
        print(f"Restored to: {dest}" if dest else "Restore failed (unknown id?).")
        return 0 if dest else 1
    if args.delete:
        ok = q.delete(args.delete)
        print("Deleted permanently." if ok else "Delete failed (unknown id?).")
        return 0 if ok else 1
    if args.purge:
        pending = len(q.list_entries())
        if pending == 0:
            print("Quarantine already empty.")
            return 0
        if not args.yes:
            reply = input(f"Permanently delete all {pending} quarantined file(s)? "
                          "This cannot be undone [y/N]: ").strip().lower()
            if reply not in ("y", "yes"):
                print("Aborted.")
                return 1
        n = q.delete_all()
        print(f"Permanently deleted {n} file(s).")
        return 0
    entries = q.list_entries()
    if not entries:
        print("Quarantine empty.")
        return 0
    print(f"{'ID':34}  {'THREAT':30}  ORIGINAL")
    for e in entries:
        print(f"{e['id']:34}  {e.get('threat','')[:30]:30}  {e.get('original','')}")
    return 0


def cmd_feeds(args) -> int:
    from scanner.web import sync_feeds
    cfg = Config.load(args.config)
    print("Syncing threat-intel feeds...")
    lines = sync_feeds(cfg.data.get("web", {}), BASE_DIR)
    for line in lines:
        print(f"  {line}")
    failed = sum(1 for l in lines if l.startswith("[fail]"))
    return 1 if failed else 0


def cmd_update(args) -> int:
    fresh = shutil.which("freshclam") or r"C:\Program Files\ClamAV\freshclam.exe"
    if not (os.path.isfile(fresh) or shutil.which("freshclam")):
        print("freshclam not found. Install ClamAV first.")
        return 1
    print("Updating ClamAV signatures...")
    cmd = [fresh]
    # freshclam needs a config file; a winget/portable ClamAV may ship only a
    # .sample. Point it at a real freshclam.conf if we can find one next to the
    # binary so the update doesn't fail with "Can't parse the config file".
    clam_dir = os.path.dirname(fresh) if os.path.isabs(fresh) else \
        r"C:\Program Files\ClamAV"
    conf = os.path.join(clam_dir, "freshclam.conf")
    if os.path.isfile(conf):
        cmd.append(f"--config-file={conf}")
    return subprocess.call(cmd)


def cmd_version(args) -> int:
    print(f"All-Round Virus Scanner {__version__}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="usbscan",
        description="Company all-round malware scanner: removable media, fixed "
                    "disks, and opt-in network drives.")
    p.add_argument("-c", "--config", default=os.path.join(BASE_DIR, "config.yaml"),
                   help="Path to config.yaml")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="Scan a drive/folder/file, or a profile")
    s.add_argument("path", nargs="*",
                   help="Drive root (E:\\), folder, or file. Combined with "
                        "--profile quick/full, these are scanned IN ADDITION "
                        "to the profile's targets.")
    s.add_argument("--profile", choices=PROFILES,
                   help="quick: common malware drop/persistence locations. "
                        "full: every fixed + removable drive. "
                        "custom: exactly the paths given.")
    s.add_argument("-v", "--verbose", action="store_true")
    s.add_argument("--no-quarantine", action="store_true",
                   help="Detect and report only; never move files")
    s.set_defaults(func=cmd_scan)

    w = sub.add_parser("watch", help="Auto-scan removable drives on insert")
    w.add_argument("--no-quarantine", action="store_true")
    w.set_defaults(func=cmd_watch)

    m = sub.add_parser("monitor",
                       help="Real-time: scan files the moment they land "
                            "(watchdog)")
    m.add_argument("--no-quarantine", action="store_true",
                   help="Report/log only; never move files")
    m.set_defaults(func=cmd_monitor)

    d = sub.add_parser("drives", help="List attached drives")
    d.add_argument("--all", action="store_true",
                   help="Include fixed and network drives")
    d.add_argument("--fixed", action="store_true", help="Include fixed disks")
    d.add_argument("--network", action="store_true",
                   help="Include mapped network drives")
    d.add_argument("--kinds", action="store_true",
                   help="Label each drive with its kind (not script-parseable)")
    d.set_defaults(func=cmd_drives)

    q = sub.add_parser("quarantine",
                       help="List, restore, or permanently delete quarantined files")
    q.add_argument("--restore", metavar="ID", help="Restore a quarantined file by id")
    q.add_argument("--to", help="Restore destination path (default: original)")
    q.add_argument("--delete", metavar="ID",
                   help="Permanently delete one quarantined file (irreversible)")
    q.add_argument("--purge", action="store_true",
                   help="Permanently delete ALL quarantined files (irreversible)")
    q.add_argument("--yes", action="store_true",
                   help="Skip the confirmation prompt for --purge")
    q.set_defaults(func=cmd_quarantine)

    u = sub.add_parser("update", help="Update ClamAV signatures (freshclam)")
    u.set_defaults(func=cmd_update)

    f = sub.add_parser("feeds",
                       help="Sync threat-intel feeds (URLhaus) for the "
                            "download-origin check")
    f.set_defaults(func=cmd_feeds)

    v = sub.add_parser("version")
    v.set_defaults(func=cmd_version)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
