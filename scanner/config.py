"""Configuration loading with sane defaults so the tool runs even without a config file."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List

import yaml

DEFAULTS = {
    "scanner": {
        "clamscan_path": r"C:\Program Files\ClamAV\clamscan.exe",
        "clamdscan_path": r"C:\Program Files\ClamAV\clamdscan.exe",
        "database_path": r"C:\Program Files\ClamAV\database",
        "prefer_daemon": True,
        "max_file_size_mb": 200,
        "scan_archives": True,
        # "auto" scales worker threads to CPU cores, then clamps by available
        # RAM so a weak laptop can't fan out into an out-of-memory Full scan.
        # Set a positive integer to override (the admin knows the machine).
        "workers": "auto",
        # Run scans at below-normal process priority so a Full scan keeps a
        # low-end PC usable instead of pinning every core. Set false on a
        # dedicated scanning box where throughput matters more than the UI.
        "background_priority": True,
        "use_cache": True,
        "multiscan": True,
        "detect_pua": True,
        "heuristic_alerts": True,
        # Paths never scanned. Empty by default: an exclusion is a coverage
        # hole, so the user opts in. See scanner/exclusions.py for pattern forms.
        "exclusions": [],
        # Include mapped network drives in a Full scan. Off by default: walking
        # a share is slow and scans another machine's files.
        "scan_network_drives": False,
    },
    "heuristics": {
        "enabled": True,
        "flag_autorun_inf": True,
        "flag_ransomware": True,
        "flag_packed_exe": True,
        "suspicious_extensions": [
            ".exe", ".scr", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
            ".ps1", ".lnk", ".pif", ".com", ".hta", ".jar",
        ],
        "flag_double_extension": True,
        "hash_blocklist": "signatures/hash_blocklist.txt",
        "hash_allowlist": "signatures/allowlist_sha256.txt",
        "yara_rules_dir": "signatures/yara",
        "deep_scan_all": False,
        "deep_scan_max_mb": 50,
        "trust_signed": True,
        "trusted_paths": [
            r"C:\Windows",
            r"C:\Program Files",
            r"C:\Program Files (x86)",
        ],
        # Category-aware static detectors. Each runs per file and is toggled /
        # tuned on its own so false-positive work on one class never disturbs
        # another. sensitivity: low | medium | high (higher = more catches,
        # more false positives). See scanner/detectors and
        # docs/DETECTION_COVERAGE.md for each detector's FP tradeoff.
        "detectors": {
            # Disguised system binaries (svch0st.exe, unsigned svchost outside
            # System32). Low FP at medium.
            "trojan": {"enabled": True, "sensitivity": "medium"},
            # File-infector shape: large high-entropy appended PE overlay in an
            # unsigned binary. Conservative (overlays are common) -> low.
            "infector": {"enabled": True, "sensitivity": "low"},
            # Adware/PUP installer naming. Low severity (reported, not moved).
            "pup": {"enabled": True, "sensitivity": "medium"},
            # Fileless/LOTL launcher patterns in script files (STATIC sliver
            # only; true fileless needs process monitoring — out of scope).
            "fileless_script": {"enabled": True, "sensitivity": "medium"},
            # Unsigned kernel driver outside the driver store (rootkit AT-REST
            # signal only; active rootkit stealth is out of scope).
            "rootkit_driver": {"enabled": True},
        },
    },
    "quarantine": {
        "path": r"C:\ProgramData\USBVirusScanner\Quarantine",
        "neutralize": True,
    },
    "logging": {
        "path": r"C:\ProgramData\USBVirusScanner\Logs",
        "level": "INFO",
        "jsonl": True,
    },
    "reporting": {"path": r"C:\ProgramData\USBVirusScanner\Reports"},
    "watcher": {
        "auto_scan_on_insert": True,
        "poll_interval": 3,
    },
    "web": {
        # Check the download origin (Mark of the Web URL) of risky files
        # against synced threat-intel feeds. Windows-only signal; no-op
        # elsewhere. Flags SUSPICIOUS only — origin alone never quarantines.
        "check_download_origin": True,
        # Where synced feeds live. ProgramData (not Program Files) because
        # the sync task must be able to write here.
        "feeds_dir": r"C:\ProgramData\USBVirusScanner\Feeds",
        # Threat-intel sources for `usbscan feeds`. URLhaus (abuse.ch) is
        # free for any use including commercial, no API key. type: "urls"
        # (one URL per line) or "sha256" (hash blocklist, merged into the
        # hash layer).
        "feeds": [
            {"name": "urlhaus",
             "url": "https://urlhaus.abuse.ch/downloads/text_online/",
             "type": "urls"},
        ],
        # Google Safe Browsing Lookup API (optional). Register your own key
        # at console.cloud.google.com. Empty = disabled. PRIVACY: when set,
        # download-origin URLs are sent to Google for lookup.
        "safe_browsing_api_key": "",
    },
    "realtime": {
        # Real-time monitoring is opt-in (spec: keep new protection modules
        # toggleable; some deployments only want on-demand scanning).
        "enabled": False,
        # Directories to watch. Empty list = the Quick profile locations
        # (Downloads, Desktop, Temp, AppData, Startup) — where files land.
        "paths": [],
        # A file is scanned once it has gone this long without a new write
        # event, so one growing download is scanned once, not per chunk.
        "settle_seconds": 2.0,
        # Quarantine real-time hits (false = report/log only).
        "quarantine": True,
        # Behavioral detection over the live event stream (ransomware mass-
        # rewrite, worm multi-path burst). Alerts/logs — never auto-deletes a
        # user's files, since a legit bulk operation can trip the burst
        # heuristic. Thresholds are tunable; sensitivity low|medium|high.
        "behavior": {
            "enabled": True,
            "sensitivity": "medium",
            "window_seconds": 8.0,      # burst detection window
            "cooldown_seconds": 30.0,   # min gap between repeat alerts
            # Distinct files modified/renamed in the window to flag ransomware
            # (omit to use the sensitivity preset).
            # "ransomware_file_threshold": 20,
        },
        # Ransomware canary/bait files: plant a tripwire in each watched folder;
        # any change to it is a high-confidence ransomware signal. Harmless
        # text files, cleaned up on stop.
        "canary": {"enabled": True},
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


@dataclass
class Config:
    data: dict = field(default_factory=lambda: DEFAULTS.copy())

    @classmethod
    def load(cls, path: str | None) -> "Config":
        merged = DEFAULTS
        if path and os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as fh:
                user = yaml.safe_load(fh) or {}
            merged = _deep_merge(DEFAULTS, user)
        return cls(data=merged)

    def __getitem__(self, key: str):
        # Fall back to DEFAULTS for a whole missing section: a config built
        # without going through load() (or hand-written before a new section
        # existed) must degrade to defaults, not KeyError-crash the GUI at
        # startup.
        if key in self.data:
            return self.data[key]
        return DEFAULTS[key]

    def get(self, section: str, key: str, default=None):
        return self[section].get(key, default) if section in self.data or \
            section in DEFAULTS else default
