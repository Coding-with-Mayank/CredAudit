"""Online credential testing module.

This module does NOT implement its own protocol-speaking or guessing
logic. It orchestrates calls to whichever engine you choose -- hydra,
medusa, or ncrack, all mature and already the industry standard -- using
their own documented CLI flags. Reinventing that engine adds risk without
adding value.

What this module adds on top, and does not let you configure away:
  * every target is re-checked against the scope file immediately before
    it is touched, and the online module requires interactive confirmation
    unless the scope file was pre-approved for automation
  * passwords are sprayed one at a time across the account list with a
    mandatory delay between passes, instead of hammering one account with
    a full wordlist -- this is the pattern used specifically because it
    avoids tripping account lockout policies
  * every pass is written to the audit log before and after it runs

Backend flags are based on each tool's own public documentation. Tool
versions drift -- if a command fails, check `<backend> --help` on your
installed version before assuming this wrapper is wrong.
"""
from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from ..audit_log import AuditLog
from ..scope import Scope

SUPPORTED_BACKENDS = {"hydra", "medusa", "ncrack"}

INSTALL_HINTS = {
    "hydra": "https://github.com/vanhauser-thc/thc-hydra",
    "medusa": "https://github.com/jmk-foofus/medusa",
    "ncrack": "https://github.com/nmap/ncrack",
}


class OnlineTestError(Exception):
    pass


@dataclass
class SprayConfig:
    protocol: str  # service name, e.g. "ssh", "rdp", "ftp" -- meaning is backend-specific
    usernames: list
    passwords: list
    seconds_between_passwords: int = 300  # tune to the target's real lockout policy
    tasks: int = 1  # parallel connections; keep low for spraying, this isn't about speed
    backend: str = "hydra"  # "hydra", "medusa", or "ncrack"


@dataclass
class OnlineTestSummary:
    log_path: Path
    accounts_tested: int
    valid_pairs_found: int


def summarize_log(log_path: Path, accounts_tested: int, backend: str = "hydra") -> OnlineTestSummary:
    """Best-effort count of valid pairs from the engine's own log, without
    ever surfacing the actual credentials into report data. The raw log
    file still has them, locally, exactly as the tool normally behaves --
    this just keeps the polished report from repeating live secrets.

    Output formats differ slightly by tool and version; this looks for
    each engine's typical "found a valid pair" line shape. For anything
    authoritative, read the raw log file directly.
    """
    log_path = Path(log_path)
    count = 0
    if log_path.exists():
        with log_path.open("r", errors="ignore") as f:
            for line in f:
                lower = line.lower()
                if backend == "hydra" and "login:" in lower and "password:" in lower:
                    count += 1
                elif backend == "medusa" and "success" in lower and ("password" in lower or "pass" in lower):
                    count += 1
                elif backend == "ncrack" and ("discovered credentials" in lower or "login:" in lower):
                    count += 1
    return OnlineTestSummary(
        log_path=log_path, accounts_tested=accounts_tested, valid_pairs_found=count
    )


def _build_command(backend, user_file, pass_file, target, protocol, tasks, out_log):
    if backend == "hydra":
        return [
            "hydra",
            "-L", str(user_file),
            "-P", str(pass_file),
            "-t", str(tasks),
            "-o", str(out_log),
            "-f",  # stop once a valid pair is found on this host
            target,
            protocol,
        ]
    if backend == "medusa":
        return [
            "medusa",
            "-h", target,
            "-U", str(user_file),
            "-P", str(pass_file),
            "-M", protocol,
            "-t", str(tasks),
            "-O", str(out_log),
            "-f",  # stop this host's audit after first valid pair found
        ]
    if backend == "ncrack":
        return [
            "ncrack",
            "-U", str(user_file),
            "-P", str(pass_file),
            "-T", str(tasks),
            "-oN", str(out_log),
            f"{protocol}://{target}",
        ]
    raise OnlineTestError(f"Unsupported backend '{backend}'. Choose from: {sorted(SUPPORTED_BACKENDS)}")


def run_spray(
    scope: Scope,
    target: str,
    cfg: SprayConfig,
    audit_log: AuditLog,
    out_dir: Path,
) -> Path:
    scope.check_module("online")
    scope.check_target(target)
    scope.require_interactive_confirmation("online")

    if cfg.backend not in SUPPORTED_BACKENDS:
        raise OnlineTestError(f"Unsupported backend '{cfg.backend}'. Choose from: {sorted(SUPPORTED_BACKENDS)}")

    if shutil.which(cfg.backend) is None:
        raise OnlineTestError(
            f"'{cfg.backend}' not found on PATH. Install it separately: "
            f"{INSTALL_HINTS[cfg.backend]}"
        )

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    combined_log = out_dir / f"online_{cfg.backend}_{target.replace('/', '_')}.log"

    user_file = out_dir / "users.tmp"
    user_file.write_text("\n".join(cfg.usernames))

    try:
        for i, password in enumerate(cfg.passwords):
            audit_log.record(
                module="online",
                action="spray_pass_start",
                detail={
                    "target": target, "protocol": cfg.protocol,
                    "backend": cfg.backend, "pass_index": i,
                },
            )

            pass_file = out_dir / f"pass_{i}.tmp"
            pass_file.write_text(password)

            cmd = _build_command(
                cfg.backend, user_file, pass_file, target, cfg.protocol, cfg.tasks, combined_log
            )
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)

            audit_log.record(
                module="online",
                action="spray_pass_end",
                detail={
                    "target": target, "backend": cfg.backend,
                    "pass_index": i, "returncode": result.returncode,
                },
            )
            pass_file.unlink(missing_ok=True)

            if i < len(cfg.passwords) - 1:
                time.sleep(cfg.seconds_between_passwords)
    finally:
        user_file.unlink(missing_ok=True)

    return combined_log
