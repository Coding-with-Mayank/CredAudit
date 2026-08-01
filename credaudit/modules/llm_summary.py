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


def generate_executive_summary(
    scope,
    recon_findings=None,
    risk_assessments=None,
    offline_result=None,
    online_summary=None,
    breach_results=None,
    api_key: str = None,
    model: str = "claude-sonnet-4-6",
) -> str:
    """Calls the Anthropic Messages API with a JSON summary of findings
    you've already collected, and asks for a short factual executive
    summary. Requires ANTHROPIC_API_KEY in the environment, or an
    explicit api_key -- this is your key, your account, your call about
    what leaves your machine. Raises LLMSummaryError if the package
    isn't installed or no key is available, rather than silently doing
    nothing."""
    try:
        import anthropic
    except ImportError as e:
        raise LLMSummaryError(
            "The 'anthropic' package isn't installed. Run: pip install anthropic"
        ) from e

    key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not key:
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
