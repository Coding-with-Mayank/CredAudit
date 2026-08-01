"""Defensive password-hygiene check against the Have I Been Pwned
Pwned Passwords API, using the k-anonymity model: only the first five
characters of the SHA-1 hash ever leave this machine, so no password
(cracked or otherwise) is ever transmitted in reversible form.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

import requests

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"


@dataclass
class BreachResult:
    password_masked: str
    times_seen: int

    @property
    def is_breached(self) -> bool:
        return self.times_seen > 0


def check_password(password: str, timeout: float = 5.0) -> BreachResult:
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    resp = requests.get(HIBP_RANGE_URL.format(prefix=prefix), timeout=timeout)
    resp.raise_for_status()

    times_seen = 0
    for line in resp.text.splitlines():
        candidate_suffix, count = line.split(":")
        if candidate_suffix == suffix:
            times_seen = int(count)
            break

    masked = (password[0] + "*" * (len(password) - 1)) if password else ""
    return BreachResult(password_masked=masked, times_seen=times_seen)


def check_many(passwords: list) -> list:
    return [check_password(p) for p in passwords]
