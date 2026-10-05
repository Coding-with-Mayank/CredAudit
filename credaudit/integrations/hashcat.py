"""Hashcat (or John the Ripper) integration.

`modules/offline.py` already owns invoking hashcat itself (scope check,
subprocess, timeout). This module's job is turning its output -- the
original hash export plus hashcat's `--outfile` (`hash:plaintext` per
line) -- into `analyzers.credentials.CredentialRecord` objects that the
credential analyzer can score, joining in real account names when the
hash export (or a separate mapping file) carries them.

Many real hash export formats do include a username alongside the hash
(e.g. many NTDS-derived exports, `/etc/shadow`-style dumps); some don't
(a bare list of hashes has no username at all). This module handles
both, honestly: when no username can be resolved for a cracked hash, the
resulting CredentialRecord gets a synthetic `hash:<prefix>` label rather
than a fabricated account name -- password-strength/reuse/breach
analysis still works across such records (reuse is still detected via
matching hashes), but privileged-account inference and any
account-specific remediation obviously cannot resolve a real name for
it.
"""
from __future__ import annotations

from pathlib import Path

from ..analyzers.credentials import CredentialRecord


def _parse_cracked_file(cracked_file) -> dict:
    """hashcat --outfile default shape: `hash:plaintext` per line."""
    cracked = {}
    for line in Path(cracked_file).read_text(errors="ignore").splitlines():
        line = line.rstrip("\n")
        if not line or ":" not in line:
            continue
        h, _, plain = line.partition(":")
        cracked[h.strip()] = plain
    return cracked


def _resolve_accounts_from_hash_file(hash_file, known_hashes: set) -> dict:
    """Best-effort: if the original hash export is `account:...:hash`
    shaped (colon-separated, with the hash as the last field -- true for
    many AD/NTDS-derived and shadow-file-derived exports), recover the
    account name for each cracked hash. Silently finds nothing if the
    format doesn't carry usernames -- that's a property of the export,
    not something this function can fix."""
    resolved = {}
    for line in Path(hash_file).read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        parts = line.split(":")
        if len(parts) < 2:
            continue
        candidate_account, candidate_hash = parts[0], parts[-1]
        if candidate_hash in known_hashes and candidate_account:
            resolved[candidate_hash] = candidate_account
    return resolved


def _load_account_map(account_map_file) -> dict:
    """Optional explicit `hash,account` or `hash:account` mapping file,
    for export formats where usernames live in a wholly separate file."""
    mapping = {}
    for line in Path(account_map_file).read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        sep = "," if "," in line else ":"
        h, _, account = line.partition(sep)
        if h.strip():
            mapping[h.strip()] = account.strip()
    return mapping


def load_cracked_credentials(
    hash_file,
    cracked_file,
    account_map_file=None,
    source: str = "offline_crack (hashcat)",
) -> list:
    """Return list[CredentialRecord] for every hash hashcat cracked.

    hash_file: the original hash export handed to hashcat.
    cracked_file: hashcat's --outfile (`hash:plaintext` per line).
    account_map_file: optional `hash,account` (or `hash:account`)
        mapping, for formats where usernames live in a separate export.
    """
    cracked = _parse_cracked_file(cracked_file)
    if not cracked:
        return []

    account_for_hash = _resolve_accounts_from_hash_file(hash_file, set(cracked))
    if account_map_file:
        account_for_hash.update(_load_account_map(account_map_file))

    records = []
    for h, plain in cracked.items():
        account = account_for_hash.get(h) or f"hash:{h[:12]}"
        records.append(CredentialRecord(account=account, password=plain, source=source))
    return records
