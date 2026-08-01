"""Offline hash auditing module.

For hashes you already legitimately possess -- e.g. an authorized export
of your own Active Directory NTDS database, or a client-provided dump
under contract. Wraps hashcat; does not reimplement cracking, and does
not help obtain hashes you don't already have.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from ..audit_log import AuditLog
from ..scope import Scope


class OfflineAuditError(Exception):
    pass


@dataclass
class OfflineAuditResult:
    out_file: Path
    total_hashes: int
    cracked_count: int

    @property
    def weak_ratio(self) -> float:
        return (self.cracked_count / self.total_hashes) if self.total_hashes else 0.0


def _count_lines(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open("r", errors="ignore") as f:
        return sum(1 for line in f if line.strip())


def run_offline_audit(
    scope: Scope,
    hash_file: Path,
    wordlist: Path,
    hash_mode: str,
    audit_log: AuditLog,
    out_dir: Path,
    hashcat_bin: str = "hashcat",
) -> OfflineAuditResult:
    scope.check_module("offline")

    if shutil.which(hashcat_bin) is None:
        raise OfflineAuditError(
            f"'{hashcat_bin}' not found on PATH. Install it separately: "
            f"https://hashcat.net/hashcat/"
        )

    hash_file = Path(hash_file)
    if not hash_file.exists():
        raise OfflineAuditError(f"Hash file not found: {hash_file}")

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "cracked.txt"

    audit_log.record(
        module="offline",
        action="crack_start",
        detail={"hash_file": str(hash_file), "hash_mode": hash_mode},
    )

    cmd = [
        hashcat_bin,
        "-m", hash_mode,
        "-a", "0",  # dictionary attack
        str(hash_file),
        str(wordlist),
        "--outfile", str(out_file),
        "--potfile-disable",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=7200)

    audit_result = OfflineAuditResult(
        out_file=out_file,
        total_hashes=_count_lines(hash_file),
        cracked_count=_count_lines(out_file),
    )

    audit_log.record(
        module="offline",
        action="crack_end",
        detail={
            "returncode": result.returncode,
            "total_hashes": audit_result.total_hashes,
            "cracked_count": audit_result.cracked_count,
        },
    )
    return audit_result
