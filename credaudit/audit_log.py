"""Append-only, hash-chained audit log.

Every action a module takes gets written here, so the engagement has a
tamper-evident record to include in the final report / client sign-off.
Each entry embeds the hash of the previous entry, so verify_chain() can
detect if any line was edited or removed after the fact.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any


class AuditLog:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._prev_hash = self._last_hash()

    def _last_hash(self) -> str:
        if not self.path.exists():
            return "0" * 64
        last_line = None
        with self.path.open("r") as f:
            for line in f:
                if line.strip():
                    last_line = line
        if not last_line:
            return "0" * 64
        return json.loads(last_line)["entry_hash"]

    def record(self, module: str, action: str, detail: dict[str, Any]) -> None:
        entry = {
            "ts": time.time(),
            "module": module,
            "action": action,
            "detail": detail,
            "prev_hash": self._prev_hash,
        }
        entry_bytes = json.dumps(entry, sort_keys=True).encode()
        entry_hash = hashlib.sha256(entry_bytes).hexdigest()
        entry["entry_hash"] = entry_hash
        with self.path.open("a") as f:
            f.write(json.dumps(entry) + "\n")
        self._prev_hash = entry_hash

    def verify_chain(self) -> bool:
        """Confirm no log entry has been altered or removed after the fact."""
        prev = "0" * 64
        if not self.path.exists():
            return True
        with self.path.open("r") as f:
            for line in f:
                if not line.strip():
                    continue
                entry = json.loads(line)
                stored_hash = entry.pop("entry_hash")
                if entry["prev_hash"] != prev:
                    return False
                recomputed = hashlib.sha256(
                    json.dumps(entry, sort_keys=True).encode()
                ).hexdigest()
                if recomputed != stored_hash:
                    return False
                prev = stored_hash
        return True
