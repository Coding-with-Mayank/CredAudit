"""Custom candidate-password generator for a specific authorized target.

Generic wordlists (SecLists etc.) catch generic weak passwords. This
module catches the other common failure mode: passwords derived from the
target's own public information -- company name, product names, year
founded, and so on. It applies the same mutation rules tools like CUPP
use (capitalization, common suffixes, basic leetspeak) to a small set of
seed words you supply.

This is straightforward string mutation, not a novel technique -- the
same logic is in half a dozen public GitHub repos. What matters is you
only feed it seed words relevant to a target you're authorized to test.
"""
from __future__ import annotations

SUFFIXES = ["", "1", "12", "123", "!", "1!", "01", "007"]
YEARS = ["2023", "2024", "2025", "2026"]
LEET_MAP = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5"})


def _case_variants(word: str) -> list:
    return list({word, word.lower(), word.upper(), word.capitalize()})


def generate_candidates(
    seed_words: list,
    include_years: bool = True,
    include_leet: bool = True,
    max_candidates: int = 5000,
) -> list:
    """Build a de-duplicated candidate list from seed words.

    seed_words: things you already legitimately know about the target --
    company name, product names, street/city, founding year, etc. Keep
    this list scoped to public information about a target you're
    authorized to test; garbage in, garbage out either way.
    """
    candidates = set()

    for seed in seed_words:
        seed = seed.strip()
        if not seed:
            continue

        for cased in _case_variants(seed):
            for suffix in SUFFIXES:
                candidates.add(f"{cased}{suffix}")

            if include_years:
                for year in YEARS:
                    candidates.add(f"{cased}{year}")
                    candidates.add(f"{cased}@{year}")

            if include_leet:
                leeted = cased.translate(LEET_MAP)
                if leeted != cased:
                    for suffix in SUFFIXES:
                        candidates.add(f"{leeted}{suffix}")

    ranked = sorted(candidates, key=len)
    return ranked[:max_candidates]


def write_candidates(seed_words: list, out_path, **kwargs) -> int:
    """Generate candidates and write them to a file, one per line.
    Returns the number of candidates written."""
    from pathlib import Path

    candidates = generate_candidates(seed_words, **kwargs)
    Path(out_path).write_text("\n".join(candidates) + "\n")
    return len(candidates)
