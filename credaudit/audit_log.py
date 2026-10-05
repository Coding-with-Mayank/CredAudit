"""Append-only, hash-chained audit log.

Every action a module takes gets written here, so the engagement has a
tamper-evident record to include in the final report / client sign-off.
Each entry embeds the hash of the previous entry, so verify_chain() can
detect if any line was edited or removed after the fact.

Limitation, stated plainly (do not oversell this as "tamper-proof"):
the hash chain detects edits, reordering, and deletions *within* the
remaining entries -- but if someone truncates the file (deletes lines
from the end and stops), the remaining chain is still internally
consistent and verify_chain() alone will not notice anything is
missing. That is exactly why `finalize()` below writes a separate
manifest recording the expected final hash and entry count -- compare
a log against its manifest with `verify_manifest()` to catch
truncation, which the chain alone cannot.
"""
from __future__ import annotations

import getpass
import hashlib
import json
import os
import socket
import time
from pathlib import Path
from typing import Any


def _default_actor() -> str:
    try:
        user = getpass.getuser()
    except Exception:
        user = "unknown"
    try:
        host = socket.gethostname()
    except Exception:
        host = "unknown"
    return f"{user}@{host}:pid{os.getpid()}"


class AuditLog:
    def __init__(self, path, engagement_id: str = "", actor: str = None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.engagement_id = engagement_id
        self.actor = actor or _default_actor()
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

    def entry_count(self) -> int:
        if not self.path.exists():
            return 0
        with self.path.open("r") as f:
            return sum(1 for line in f if line.strip())

    def record(
        self,
        module: str,
        action: str,
        detail: dict[str, Any],
        target: str = None,
        result: str = None,
    ) -> None:
        """Append one tamper-evident entry.

        `target`/`result` are optional, explicitly-named fields (rather
        than just more keys inside `detail`) because the schema this
        project's own requirements ask for treats them as first-class:
        timestamp, engagement id, module, action, target, result/status,
        actor, previous/current hash. Never pass a raw secret/credential
        value in `detail` -- this module does not redact anything for
        you; callers are responsible for only logging non-sensitive
        detail (every module in this project already follows that rule).
        """
        entry = {
            "ts": time.time(),
            "engagement_id": self.engagement_id,
            "module": module,
            "action": action,
            "target": target,
            "result": result,
            "detail": detail,
            "actor": self.actor,
            "prev_hash": self._prev_hash,
        }
        entry_bytes = json.dumps(entry, sort_keys=True, default=str).encode()
        entry_hash = hashlib.sha256(entry_bytes).hexdigest()
        entry["entry_hash"] = entry_hash
        with self.path.open("a") as f:
            f.write(json.dumps(entry, default=str) + "\n")
        self._prev_hash = entry_hash

    def verify_chain(self) -> bool:
        """Confirm no log entry has been altered, removed, or reordered
        *within* the entries present in the file. See the module
        docstring for why this alone cannot detect truncation from the
        end of the file -- use verify_manifest() for that."""
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
                    json.dumps(entry, sort_keys=True, default=str).encode()
                ).hexdigest()
                if recomputed != stored_hash:
                    return False
                prev = stored_hash
        return True

    def finalize(self, private_key_pem: bytes = None) -> dict:
        """Write a manifest (`<log>_manifest.json`) recording the final
        entry count and hash at the end of an engagement, optionally
        signed with an Ed25519 private key. This is what lets
        verify_manifest() detect truncation -- deleting entries from the
        end of the log changes both the entry count and the final hash,
        so a truncated log will not match its manifest even though its
        own internal chain still verifies.
        """
        manifest = {
            "engagement_id": self.engagement_id,
            "entry_count": self.entry_count(),
            "last_hash": self._prev_hash,
            "generated_at": time.time(),
        }
        if private_key_pem:
            from .core import authorization

            payload = json.dumps(manifest, sort_keys=True, default=str).encode()
            manifest["signature"] = authorization.sign_bytes(payload, private_key_pem)
        manifest_path = self._manifest_path()
        manifest_path.write_text(json.dumps(manifest, indent=2))
        return manifest

    def _manifest_path(self) -> Path:
        return self.path.with_name(self.path.stem + "_manifest.json")


def verify_manifest(log_path, manifest_path=None, trusted_public_key: bytes = None) -> dict:
    """Verify a log against its signed manifest. Returns a dict:
        {"chain_valid": bool, "manifest_found": bool,
         "count_matches": bool, "hash_matches": bool,
         "signature_valid": bool | None, "ok": bool}

    `ok` is True only when the chain verifies AND (no manifest was
    requested to be checked, or the manifest's count/hash match the log
    exactly, AND -- if the manifest carries a signature and
    trusted_public_key is supplied -- that signature verifies). Pass
    trusted_public_key explicitly (not read from the manifest itself)
    for the same reason `Scope`'s signature verification requires an
    external key for real assurance: a self-declared key inside the
    thing being verified proves internal consistency, not legitimacy.
    """
    log_path = Path(log_path)
    log = AuditLog(log_path)
    chain_valid = log.verify_chain()

    manifest_path = Path(manifest_path) if manifest_path else log._manifest_path()
    if not manifest_path.exists():
        return {
            "chain_valid": chain_valid, "manifest_found": False,
            "count_matches": None, "hash_matches": None,
            "signature_valid": None, "ok": chain_valid,
        }

    manifest = json.loads(manifest_path.read_text())
    count_matches = manifest.get("entry_count") == log.entry_count()
    hash_matches = manifest.get("last_hash") == log._prev_hash

    signature_valid = None
    if "signature" in manifest and trusted_public_key:
        from .core import authorization

        unsigned = {k: v for k, v in manifest.items() if k != "signature"}
        payload = json.dumps(unsigned, sort_keys=True, default=str).encode()
        signature_valid = authorization.verify_bytes(payload, manifest["signature"], trusted_public_key)

    ok = chain_valid and count_matches and hash_matches and (signature_valid is not False)
    return {
        "chain_valid": chain_valid, "manifest_found": True,
        "count_matches": count_matches, "hash_matches": hash_matches,
        "signature_valid": signature_valid, "ok": ok,
    }
