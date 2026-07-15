"""Logging + human and machine-readable scan reports."""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from logging.handlers import RotatingFileHandler

from .models import ScanResult


def setup_logging(cfg: dict) -> logging.Logger:
    log_dir = cfg.get("path", "logs")
    os.makedirs(log_dir, exist_ok=True)
    logger = logging.getLogger("usbscanner")
    logger.setLevel(getattr(logging, cfg.get("level", "INFO").upper(), logging.INFO))
    logger.handlers.clear()

    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    fh = RotatingFileHandler(os.path.join(log_dir, "scanner.log"),
                             maxBytes=5 * 1024 * 1024, backupCount=5,
                             encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    logger.addHandler(ch)
    logger._jsonl = cfg.get("jsonl", True)  # type: ignore[attr-defined]
    logger._log_dir = log_dir  # type: ignore[attr-defined]
    return logger


def log_result(logger: logging.Logger, result: ScanResult) -> None:
    n_inf, n_susp = len(result.infected), len(result.suspicious)
    logger.info("Scan %s: %d files, %d infected, %d suspicious, %d skipped",
                result.target, result.files_scanned, n_inf, n_susp,
                result.files_skipped)
    for d in result.detections:
        lvl = logging.WARNING if d.severity.value == "infected" else logging.INFO
        logger.log(lvl, "%s [%s] %s (%s)%s", d.severity.value.upper(), d.source,
                   d.path, d.threat,
                   f" -> {d.quarantined_to}" if d.quarantined_to else "")

    if getattr(logger, "_jsonl", False):
        jpath = os.path.join(getattr(logger, "_log_dir", "logs"), "events.jsonl")
        with open(jpath, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(result.to_dict()) + "\n")


def write_report(cfg: dict, result: ScanResult) -> str:
    out_dir = cfg.get("path", "reports")
    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = "".join(c if c.isalnum() else "_" for c in result.target)[-40:]
    path = os.path.join(out_dir, f"scan_{stamp}_{safe_target}.txt")

    lines = [
        "=" * 64,
        " USB VIRUS SCANNER — SCAN REPORT",
        "=" * 64,
        f" Target        : {result.target}",
        f" Started       : {result.started}",
        f" Finished      : {result.finished}",
        f" Files scanned : {result.files_scanned}",
        f" Files skipped : {result.files_skipped}",
        f" Infected      : {len(result.infected)}",
        f" Suspicious    : {len(result.suspicious)}",
        f" Verdict       : {'CLEAN' if result.clean else 'THREATS FOUND'}",
        "=" * 64,
        "",
    ]
    if result.detections:
        lines.append("DETECTIONS")
        lines.append("-" * 64)
        for d in result.detections:
            lines.append(f"[{d.severity.value.upper():10}] {d.threat}  ({d.source})")
            lines.append(f"    file : {d.path}")
            if d.sha256:
                lines.append(f"    sha256: {d.sha256}")
            if d.quarantined_to:
                lines.append(f"    moved: {d.quarantined_to}")
            lines.append("")
    if result.errors:
        lines.append("ERRORS")
        lines.append("-" * 64)
        lines.extend(f"  {e}" for e in result.errors)

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return path
