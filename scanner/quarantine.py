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


# XOR-with-a-fixed-key is a pure byte substitution, so a precomputed 256-entry
# translation table lets bytes.translate() do the whole block in C. The old
# per-byte generator (`bytes(b ^ key for b in block)`) ran a Python-level loop
# over every byte — painfully slow quarantining a large file on a weak CPU.
def _xor_table(key: int) -> bytes:
    return bytes(b ^ key for b in range(256))


_XOR_TABLE = _xor_table(_NEUTRALIZE_KEY)


def _xor_file(src: str, dst: str, key: int = _NEUTRALIZE_KEY) -> None:
    table = _XOR_TABLE if key == _NEUTRALIZE_KEY else _xor_table(key)
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        for block in iter(lambda: fin.read(1 << 20), b""):
            fout.write(block.translate(table))


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
        # The original location may be gone (e.g. the USB was unplugged), so a
        # restore can fail on makedirs/copy. Fail softly -> callers get None and
        # show a friendly message instead of an unhandled exception.
        try:
            os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
            if entry.get("neutralized"):
                _xor_file(src, dest)  # XOR is symmetric — same op reverses it
            else:
                shutil.copy2(src, dest)
            os.remove(src)
        except (OSError, PermissionError):
            return None
        self._append_index({"id": qid, "status": "restored", "restored_to": dest,
                            "ts": time.time()})
        return dest

    def delete(self, qid: str) -> bool:
        """Permanently delete a quarantined file. IRREVERSIBLE. Returns True on
        success (or if the file was already gone but the entry existed)."""
        entry = self._find(qid)
        if not entry or entry.get("status") != "quarantined":
            return False
        try:
            src = entry.get("quarantine")
            if src and os.path.isfile(src):
                os.remove(src)
        except (OSError, PermissionError):
            return False
        self._append_index({"id": qid, "status": "deleted", "ts": time.time()})
        return True

    def delete_all(self) -> int:
        """Permanently delete every quarantined file. IRREVERSIBLE. Returns the
        number of items deleted."""
        n = 0
        for entry in self.list_entries():
            if self.delete(entry["id"]):
                n += 1
        return n

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
