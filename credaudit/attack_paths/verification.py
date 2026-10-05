"""Per-link corroboration status for an attack path.

What this module is NOT, stated up front because it's the single most
important thing to be clear about: this is not an exploitation engine,
and it will never become one. It does not attempt to use a finding to
gain access, does not chain exploits, and does not take any action
against a target. "Verification" here means exactly one thing: checking
whether each finding that makes up a path was *directly observed* (an
`Evidence.status` of "confirmed" -- set only by something that actually
validated a fact, like `integrations.hydra`'s live credential test
succeeding, or `validators`' live secret-validation) versus merely
*inferred* from co-occurring evidence.

Why not go further and actually test each link automatically: because
doing that for a credential or a network exposure means taking a live
action against a target system, and this platform already has
exactly-scoped, exactly-logged, human-confirmed ways to do that
(`modules.online` for credentials, `integrations.nuclei`/manual
verification for service exposure, `validators` for secrets). Silently
re-implementing a lightweight version of those checks here, without
their scope gate and without their confirmation prompt, would be a
regression dressed up as a feature -- it would quietly do, on every
path in every report, exactly the kind of live testing the rest of this
platform deliberately slows down and gates. See
docs/attack_path_verification.md for the full rationale, and
`GEMINI.md`/`CLAUDE.md` for the project-wide rule this follows.

What this module adds that `CorrelatedFinding.status` alone doesn't:
`_combined_status()` in `core.correlation` already tells you whether a
*whole* chain is fully confirmed, a mix, or all-hypothesis -- but not
*which specific link* broke it, or what a human would concretely need
to do about that one link. That's the gap this closes: an honest,
actionable "here's exactly what's still unproven, and the exact
authorized step that would prove it" -- the thing a human reviewing an
attack path actually needs, instead of a single aggregate status.
"""
from __future__ import annotations

from dataclasses import dataclass, field

FULLY_CORROBORATED = "fully_corroborated"
PARTIALLY_CORROBORATED = "partially_corroborated"
HYPOTHESIS_ONLY = "hypothesis_only"

VALID_VERIFICATION_STATUSES = (FULLY_CORROBORATED, PARTIALLY_CORROBORATED, HYPOTHESIS_ONLY)

# For each finding category, the specific *authorized, human-confirmed*
# action this platform already supports that would turn this one link
# from a hypothesis into a directly-observed fact. Deliberately points
# at existing scope-gated/confirmation-gated modules, not at a new
# auto-verification shortcut.
MANUAL_VERIFICATION_STEPS = {
    "Network/Service Exposure": (
        "Confirm the service/version directly against this exact asset -- an authorized nuclei run, "
        "or a manual banner-grab/version check -- rather than relying on inferred exposure."
    ),
    "Secret Exposure": (
        "Run `credaudit analyze-secrets --validate-secrets` (or `run --validate-secrets`) to make a "
        "read-only check of this exact secret against its own issuing provider."
    ),
    "Credential Exposure": (
        "Run an authorized `credaudit run --modules online` test against this exact asset (requires "
        "scope authorization and interactive confirmation) to directly confirm the credential grants access."
    ),
}
_DEFAULT_MANUAL_STEP = "Manually confirm this specific finding under the engagement's authorized scope."


@dataclass
class LinkVerification:
    finding_id: str
    category: str
    corroborated: bool  # True iff the underlying Evidence.status == "confirmed"
    next_step: str = ""  # populated only when corroborated is False


@dataclass
class PathVerification:
    status: str  # one of VALID_VERIFICATION_STATUSES
    links: list = field(default_factory=list)  # list[LinkVerification]

    @property
    def corroborated_count(self) -> int:
        return sum(1 for link in self.links if link.corroborated)

    @property
    def summary(self) -> str:
        total = len(self.links)
        if total == 0:
            return "No findings to verify."
        if self.status == FULLY_CORROBORATED:
            return f"Fully corroborated: all {total} finding(s) in this chain were directly observed, not inferred."
        if self.status == HYPOTHESIS_ONLY:
            return (
                f"Hypothesis only: none of the {total} finding(s) in this chain have been directly confirmed. "
                "This path describes co-occurrence of evidence, not a demonstrated attacker path."
            )
        return (
            f"Partially corroborated: {self.corroborated_count}/{total} finding(s) directly confirmed; "
            f"{total - self.corroborated_count} remain unconfirmed hypotheses (see per-link detail)."
        )

    @property
    def outstanding_steps(self) -> list:
        """The de-duplicated list of manual next-steps for every
        uncorroborated link, in path order -- what a human would
        actually go do to fully close this path's remaining gaps."""
        steps = []
        for link in self.links:
            if not link.corroborated and link.next_step not in steps:
                steps.append(link.next_step)
        return steps


def verify_path(path, evidence_by_id: dict) -> PathVerification:
    """Build a PathVerification for one AttackPath. `evidence_by_id`
    should map finding_id -> Evidence (the same mapping
    `attack_paths.graph.build_attack_paths` already builds internally)."""
    links = []
    for finding_id in path.supporting_findings:
        evidence = evidence_by_id.get(finding_id)
        if evidence is None:
            continue
        corroborated = evidence.status == "confirmed"
        next_step = "" if corroborated else MANUAL_VERIFICATION_STEPS.get(evidence.category, _DEFAULT_MANUAL_STEP)
        links.append(
            LinkVerification(
                finding_id=finding_id, category=evidence.category, corroborated=corroborated, next_step=next_step,
            )
        )

    if not links:
        status = HYPOTHESIS_ONLY
    elif all(link.corroborated for link in links):
        status = FULLY_CORROBORATED
    elif any(link.corroborated for link in links):
        status = PARTIALLY_CORROBORATED
    else:
        status = HYPOTHESIS_ONLY

    return PathVerification(status=status, links=links)


def verify_paths(paths: list, evidence_list: list) -> dict:
    """Convenience batch form: {path_id: PathVerification} for every
    path in `paths`. Does not mutate `paths` -- see
    `core.pipeline.run_pipeline`, which attaches the result to each
    AttackPath's `.verification` field."""
    evidence_by_id = {e.finding_id: e for e in evidence_list}
    return {path.path_id: verify_path(path, evidence_by_id) for path in paths}
