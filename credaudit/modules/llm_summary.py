"""Optional executive-summary generator, using your own Anthropic API
key.

This turns findings you've already collected into readable prose for a
report. It does not decide to take a new action, run a new module, run
recon again, or test anything -- it only summarizes structured data you
pass in. Treat its output as a first draft to review and edit, never as
a finished analysis, and never as something that triggers further tool
runs on its own.
"""
from __future__ import annotations

import json
import os


class LLMSummaryError(Exception):
    pass


def _collect_facts(
    scope, recon_findings=None, risk_assessments=None,
    offline_result=None, online_summary=None, breach_results=None,
) -> dict:
    online_list = online_summary if isinstance(online_summary, list) else (
        [online_summary] if online_summary else []
    )
    return {
        "engagement_id": scope.engagement_id,
        "client_name": scope.client_name,
        "targets": scope.targets,
        "recon_finding_count": len(recon_findings) if recon_findings is not None else None,
        "risk_assessments": [
            {
                "target": r.target, "service": r.service,
                "risk_level": r.risk_level, "reasoning": r.reasoning,
            }
            for r in (risk_assessments or [])
        ],
        "offline_audit": (
            {"total_hashes": offline_result.total_hashes, "cracked": offline_result.cracked_count}
            if offline_result else None
        ),
        "online_testing": [
            {"accounts_tested": s.accounts_tested, "valid_pairs_found": s.valid_pairs_found}
            for s in online_list
        ],
        "breach_check": (
            {
                "breached": sum(1 for r in breach_results if r.is_breached),
                "total": len(breach_results),
            }
            if breach_results else None
        ),
    }


_SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

_FALLBACK_NOTICE = (
    "[This is a deterministic, template-based summary \u2014 no AI model was used. For an "
    "AI-polished narrative version, install the 'llm' extra (`pip install credaudit[llm]`) "
    "and set ANTHROPIC_API_KEY, then re-run with --summary.]"
)


def generate_fallback_summary(
    scope,
    recon_findings=None,
    risk_assessments=None,
    offline_result=None,
    online_summary=None,
    breach_results=None,
) -> str:
    """Dependency-free, network-free, deterministic executive summary
    built from the exact same facts `generate_executive_summary` would
    send to the model -- template-based prose instead of a generated
    narrative. This exists so `--summary` always produces *something*
    useful: the AI-polished version is an enhancement on top of this,
    not a prerequisite for having an executive summary at all.
    """
    facts = _collect_facts(
        scope, recon_findings, risk_assessments, offline_result, online_summary, breach_results
    )
    lines = [
        f"Executive summary for engagement {facts['engagement_id']} ({facts['client_name']}), "
        f"covering {len(facts['targets'])} authorized target(s)."
    ]

    if facts["recon_finding_count"] is not None:
        lines.append(f"Reconnaissance identified {facts['recon_finding_count']} finding(s) across the authorized scope.")

    if facts["risk_assessments"]:
        counts: dict = {}
        for r in facts["risk_assessments"]:
            counts[r["risk_level"]] = counts.get(r["risk_level"], 0) + 1
        ordered = sorted(counts.items(), key=lambda kv: _SEVERITY_ORDER.get(kv[0], 99))
        breakdown = ", ".join(f"{count} {level}" for level, count in ordered)
        lines.append(f"Service-level risk assessment covered {len(facts['risk_assessments'])} service(s): {breakdown}.")

    if facts["offline_audit"]:
        total = facts["offline_audit"]["total_hashes"]
        cracked = facts["offline_audit"]["cracked"]
        pct = (cracked / total * 100) if total else 0
        lines.append(f"Offline password-hash analysis cracked {cracked} of {total} hash(es) ({pct:.0f}%).")

    if facts["online_testing"]:
        total_tested = sum(s["accounts_tested"] for s in facts["online_testing"])
        total_valid = sum(s["valid_pairs_found"] for s in facts["online_testing"])
        lines.append(
            f"Authorized online credential testing checked {total_tested} account(s) and directly "
            f"confirmed {total_valid} valid credential pair(s)."
        )

    if facts["breach_check"]:
        lines.append(
            f"Breach-database checking found {facts['breach_check']['breached']} of "
            f"{facts['breach_check']['total']} password(s) previously exposed in known breaches."
        )

    if len(lines) == 1:
        lines.append("No findings were supplied to summarize.")

    lines.append(_FALLBACK_NOTICE)
    return " ".join(lines)


def generate_executive_summary(
    scope,
    recon_findings=None,
    risk_assessments=None,
    offline_result=None,
    online_summary=None,
    breach_results=None,
    api_key: str = None,
    model: str = "claude-sonnet-4-6",
    allow_fallback: bool = False,
) -> str:
    """Calls the Anthropic Messages API with a JSON summary of findings
    you've already collected, and asks for a short factual executive
    summary. Requires ANTHROPIC_API_KEY in the environment, or an
    explicit api_key -- this is your key, your account, your call about
    what leaves your machine.

    By default (`allow_fallback=False`, unchanged from prior behavior),
    raises LLMSummaryError if the package isn't installed or no key is
    available, rather than silently doing nothing -- existing callers
    that handle that error keep working exactly as before. Pass
    `allow_fallback=True` (the CLI's `run --summary` does this) to get
    `generate_fallback_summary()`'s deterministic output instead of an
    exception in those two cases.
    """
    try:
        import anthropic
    except ImportError as e:
        if allow_fallback:
            return generate_fallback_summary(
                scope, recon_findings, risk_assessments, offline_result, online_summary, breach_results,
            )
        raise LLMSummaryError(
            "The 'anthropic' package isn't installed. Run: pip install credaudit[llm] (or: pip install anthropic)"
        ) from e

    key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        if allow_fallback:
            return generate_fallback_summary(
                scope, recon_findings, risk_assessments, offline_result, online_summary, breach_results,
            )
        raise LLMSummaryError(
            "No API key found. Set ANTHROPIC_API_KEY or pass api_key explicitly."
        )

    facts = _collect_facts(
        scope, recon_findings, risk_assessments, offline_result, online_summary, breach_results
    )

    client = anthropic.Anthropic(api_key=key)
    response = client.messages.create(
        model=model,
        max_tokens=500,
        messages=[{
            "role": "user",
            "content": (
                "Write a concise, factual executive summary (3-5 sentences) of this "
                "credential security audit, for a non-technical stakeholder, based "
                "only on the structured findings below. Do not invent any detail not "
                "present in the data. Do not recommend specific next actions beyond "
                "general remediation priorities -- this is a summary, not a plan.\n\n"
                + json.dumps(facts, indent=2)
            ),
        }],
    )
    return "".join(block.text for block in response.content if block.type == "text").strip()
