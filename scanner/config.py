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
        "prefer_daemon": True,
        "max_file_size_mb": 200,
        "scan_archives": True,
        "workers": "auto",
        "use_cache": True,
        "multiscan": True,
    },
    "heuristics": {
        "enabled": True,
        "flag_autorun_inf": True,
        "suspicious_extensions": [
            ".exe", ".scr", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
            ".ps1", ".lnk", ".pif", ".com", ".hta", ".jar",
        ],
        "flag_double_extension": True,
        "hash_blocklist": "signatures/hash_blocklist.txt",
        "yara_rules_dir": "signatures/yara",
        "deep_scan_all": False,
        "deep_scan_max_mb": 50,
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
        return self.data[key]

    def get(self, section: str, key: str, default=None):
        return self.data.get(section, {}).get(key, default)
