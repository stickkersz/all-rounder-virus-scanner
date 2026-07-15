"""Quarantine manager: move infected files off the removable drive, neutralize
them so they can't be double-clicked into execution, and keep a restore index.
"""

from __future__ import annotations

import json
import os
import shutil
import time
import uuid
from typing import Optional

# Fixed byte used to XOR-obfuscate quarantined payloads. This is NOT encryption;
# its only job is to make the on-disk copy non-executable / non-openable by
# accident. Reversible on restore.
_NEUTRALIZE_KEY = 0x5A


def _xor_file(src: str, dst: str, key: int = _NEUTRALIZE_KEY) -> None:
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        for block in iter(lambda: fin.read(1 << 20), b""):
            fout.write(bytes(b ^ key for b in block))


class Quarantine:
    def __init__(self, cfg: dict):
        self.dir = cfg.get("path", "quarantine")
        self.neutralize = cfg.get("neutralize", True)
        os.makedirs(self.dir, exist_ok=True)
        self.index_path = os.path.join(self.dir, "index.jsonl")

    def store(self, path: str, threat: str, sha256: Optional[str] = None) -> Optional[str]:
        """Move `path` into quarantine. Returns the quarantine file path, or None."""
        if not os.path.isfile(path):
            return None
        qid = uuid.uuid4().hex
        dest = os.path.join(self.dir, f"{qid}.quarantine")
        try:
            if self.neutralize:
                _xor_file(path, dest)
                os.remove(path)
            else:
                shutil.move(path, dest)
        except (OSError, PermissionError) as exc:
            self._append_index({
                "id": qid, "original": path, "threat": threat,
                "sha256": sha256, "ts": time.time(), "error": str(exc),
                "status": "failed",
            })
            return None

        self._append_index({
            "id": qid, "original": path, "quarantine": dest, "threat": threat,
            "sha256": sha256, "neutralized": self.neutralize, "ts": time.time(),
            "status": "quarantined",
        })
        return dest

    def restore(self, qid: str, to: Optional[str] = None) -> Optional[str]:
        """Restore a quarantined file by id. Returns the restored path."""
        entry = self._find(qid)
        if not entry or entry.get("status") != "quarantined":
            return None
        src = entry["quarantine"]
        dest = to or entry["original"]
        os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
        if entry.get("neutralized"):
            _xor_file(src, dest)  # XOR is symmetric — same op reverses it
        else:
            shutil.copy2(src, dest)
        os.remove(src)
        self._append_index({"id": qid, "status": "restored", "restored_to": dest,
                            "ts": time.time()})
        return dest

    # ---- index helpers -------------------------------------------------
    def _append_index(self, record: dict) -> None:
        with open(self.index_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")

    def _find(self, qid: str) -> Optional[dict]:
        if not os.path.isfile(self.index_path):
            return None
        found = None
        with open(self.index_path, "r", encoding="utf-8") as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("id") == qid:
                    found = rec  # last record for this id wins
        return found

    def list_entries(self) -> list[dict]:
        """Current quarantined items (dedup by id, latest status)."""
        if not os.path.isfile(self.index_path):
            return []
        latest: dict[str, dict] = {}
        with open(self.index_path, "r", encoding="utf-8") as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if "id" in rec:
                    latest[rec["id"]] = {**latest.get(rec["id"], {}), **rec}
        return [r for r in latest.values() if r.get("status") == "quarantined"]
