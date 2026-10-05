"""Entropy/crack-time password estimation via zxcvbn.

`credentials.classify_strength()` stays exactly as it was: a small,
fully-documented, auditable fixed rule (length + character-class
counting). That's not a limitation to quietly paper over -- a fixed
rule is predictable and easy to explain in a report ("Medium because
length >= 10 and 3+ character classes"), which matters when a finding
ends up in front of a client. What a fixed rule *can't* do is tell you
that "Tr0ub4dor&3"-style substitution patterns or "qwertyuiop"-style
keyboard walks are weak despite checking every character-class box, or
give a defensible crack-time estimate instead of a three-bucket label.

This module is the graduated, zxcvbn-backed alternative, offered
side-by-side rather than as a silent replacement: `analyze_credentials()`
takes it as an opt-in (`use_entropy_scoring=True`) precisely so nothing
that currently depends on the fixed rule's exact Weak/Medium/Strong
output or exact risk scores changes unless a caller asks for the richer
model.
"""
from __future__ import annotations

from dataclasses import dataclass, field

try:
    from zxcvbn import zxcvbn as _zxcvbn

    ZXCVBN_AVAILABLE = True
except ImportError:  # pragma: no cover -- exercised by the "unavailable" test via monkeypatch
    ZXCVBN_AVAILABLE = False


@dataclass
class PasswordStrengthEstimate:
    zxcvbn_score: int  # 0 (trivially guessed) .. 4 (very strong)
    entropy_bits: float  # log2(guesses) -- NOT Shannon entropy of the charset; see note below
    guesses: float
    crack_time_display: dict = field(default_factory=dict)  # scenario name -> human string, e.g. "3 hours"
    warning: str = ""
    suggestions: list = field(default_factory=list)
    weakness_score: float = 0.0  # 0.0-1.0, monotonically derived from zxcvbn_score for risk-engine use

    @property
    def offline_fast_hashing_crack_time(self) -> str:
        return self.crack_time_display.get("offline_fast_hashing_1e10_per_second", "unknown")


# zxcvbn's score is already a defensible 0-4 ordinal (it's the same
# scale zxcvbn's own authors calibrate guess counts against), so the
# risk-engine weight is just a direct, monotonic mapping rather than a
# second independent judgment call layered on top of theirs.
_SCORE_TO_WEAKNESS = {0: 1.0, 1: 0.85, 2: 0.6, 3: 0.3, 4: 0.1}


def estimate_strength(password: str, user_inputs: list = None) -> PasswordStrengthEstimate:
    """Returns None if zxcvbn isn't installed (it's a core dependency as
    of pyproject.toml, so this should only matter for an unusual/stripped
    install) -- callers must handle that and fall back to
    `classify_strength()` alone, never raise."""
    if not ZXCVBN_AVAILABLE:
        return None

    result = _zxcvbn(password, user_inputs=user_inputs or [])
    score = int(result.get("score", 0))
    guesses = float(result.get("guesses", 1))
    # entropy_bits here is log2(guesses), the standard way zxcvbn's own
    # guess count is converted into a bit count -- NOT the textbook
    # Shannon entropy of the character set (which badly overestimates
    # real-world password strength by assuming uniform random selection
    # from the full charset; that's precisely the gap a fixed
    # length+charset rule and naive "entropy" calculators both fall into,
    # and why this module leans on zxcvbn's pattern-based guess model
    # instead of recomputing entropy from charset size itself).
    import math

    entropy_bits = math.log2(guesses) if guesses > 0 else 0.0

    feedback = result.get("feedback", {}) or {}
    crack_times = result.get("crack_times_display", {}) or {}

    return PasswordStrengthEstimate(
        zxcvbn_score=score,
        entropy_bits=round(entropy_bits, 1),
        guesses=guesses,
        crack_time_display=dict(crack_times),
        warning=feedback.get("warning", "") or "",
        suggestions=list(feedback.get("suggestions", []) or []),
        weakness_score=_SCORE_TO_WEAKNESS.get(score, 0.5),
    )
