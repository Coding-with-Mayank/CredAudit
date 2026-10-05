"""Finding correlation engine.

Individual findings are useful; a *chain* of related findings on the
same asset is often the actual story. "This host is internet-facing AND
has a weak, breached credential on a privileged account" is a
materially different risk than any one of those facts alone -- this
module is what turns co-occurring evidence into that combined picture,
instead of leaving a report as a flat list of independent findings.

How it works: evidence is grouped by asset, then by category. A small,
explicit table of category-set patterns (`CHAIN_PATTERNS`) says which
combinations are worth calling out as a chain. This is deliberately a
fixed, readable table rather than a scoring heuristic -- every chain
this engine produces is one you can point to in the table and explain.

Confidence/status discipline: this engine never upgrades a finding's
status past what its underlying evidence already supports.
Co-occurrence on the same asset is a *prioritization signal*, not proof
of a single attacker having actually walked that path -- a correlated
chain is "confirmed" only when every finding feeding it is itself
already "confirmed" (e.g. the online module actually validated a
login). Otherwise, at best, "potential_relationship".
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Order findings are presented in within a chain -- outside-in, roughly
# matching how an attacker would traverse it (find the exposed surface,
# find something on it, then present the credential/secret they'd have
# in hand).
CATEGORY_CHAIN_ORDER = [
    "Network/Service Exposure",
    "Secret Exposure",
    "Credential Exposure",
]

# category-set -> human-readable label for the chain. Only combinations
# listed here are ever surfaced as a CorrelatedFinding; anything else
# stays as independent findings. When more than one pattern matches the
# same asset, the pattern covering the most categories wins (so a
# 3-category match is preferred over the 2-category subsets it also
# satisfies).
CHAIN_PATTERNS = {
    frozenset({"Network/Service Exposure", "Credential Exposure"}):
        "Internet-facing service paired with a weak/exposed credential",
    frozenset({"Network/Service Exposure", "Secret Exposure"}):
        "Internet-facing service paired with an exposed secret",
    frozenset({"Credential Exposure", "Secret Exposure"}):
        "Exposed secret alongside a weak/exposed credential on the same asset",
    frozenset({"Network/Service Exposure", "Secret Exposure", "Credential Exposure"}):
        "Internet-facing service, exposed secret, and weak/exposed credential together",
}


@dataclass
class CorrelatedFinding:
    correlation_id: str
    asset: str
    related_finding_ids: list
    categories: list
    combined_risk_score: int
    confidence: float
    status: str
    explanation: str
    remediation: str


def _combined_confidence(items: list) -> float:
    """Geometric mean of the individual confidences: the chain is only
    as credible as its links, but a long chain of moderately-confident
    findings shouldn't collapse toward zero just from multiplying many
    numbers less than 1 together."""
    if not items:
        return 0.0
    product = 1.0
    for e in items:
        product *= max(e.confidence, 0.05)
    n = len(items)
    return round(product ** (1.0 / n), 2)


def _combined_status(items: list) -> str:
    statuses = {e.status for e in items}
    if statuses == {"confirmed"}:
        return "confirmed"
    if "confirmed" in statuses or "potential_relationship" in statuses:
        return "potential_relationship"
    if "suspected" in statuses:
        return "suspected"
    return "potential_relationship"


def _combined_risk_score(items: list) -> int:
    """Base score is the single highest-risk finding in the chain
    (a chain is never *less* risky than its worst link). A small,
    capped bonus reflects that co-occurring findings compound risk (a
    weak credential matters more when it's also internet-facing) --
    capped so volume of links alone can never manufacture a Critical
    score out of several low-risk findings."""
    base = max(e.risk_score for e in items)
    bonus = min(6 * (len(items) - 1), 15)
    return min(100, base + bonus)


def _dedupe_remediation(items: list) -> str:
    seen = []
    for e in items:
        if e.remediation and e.remediation not in seen:
            seen.append(e.remediation)
    return " ".join(seen) or "Review each related finding and remediate the highest-severity item first."


def correlate(evidence_list: list, min_chain_length: int = 2) -> list:
    """Group `evidence_list` by asset and emit a CorrelatedFinding for
    every asset whose set of present categories matches (covers) an
    entry in CHAIN_PATTERNS. Returns list[CorrelatedFinding], one per
    matching asset, in no particular order."""
    by_asset: dict = {}
    for e in evidence_list:
        by_asset.setdefault(e.asset, []).append(e)

    correlations = []
    counter = 0
    for asset, items in by_asset.items():
        by_category: dict = {}
        for e in items:
            by_category.setdefault(e.category, []).append(e)

        present_categories = frozenset(by_category)
        matched_label = None
        matched_categories = None
        for pattern_categories, label in CHAIN_PATTERNS.items():
            if pattern_categories <= present_categories and len(pattern_categories) >= min_chain_length:
                if matched_categories is None or len(pattern_categories) > len(matched_categories):
                    matched_label, matched_categories = label, pattern_categories

        if matched_label is None:
            continue

        chain_items = [e for cat in matched_categories for e in by_category[cat]]
        counter += 1
        chain_str = " \u2192 ".join(
            cat for cat in CATEGORY_CHAIN_ORDER if cat in matched_categories
        )
        correlations.append(
            CorrelatedFinding(
                correlation_id=f"CHAIN-{counter:03d}",
                asset=asset,
                related_finding_ids=[e.finding_id for e in chain_items],
                categories=sorted(matched_categories),
                combined_risk_score=_combined_risk_score(chain_items),
                confidence=_combined_confidence(chain_items),
                status=_combined_status(chain_items),
                explanation=f"{matched_label} on '{asset}': {chain_str}.",
                remediation=_dedupe_remediation(chain_items),
            )
        )
    return correlations
