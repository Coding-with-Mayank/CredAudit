"""Attack-path analysis, built directly on correlated evidence.

Every path here is derived from a `core.correlation.CorrelatedFinding`
-- it starts at an "Internet" node, passes through the target asset,
then through each finding in that chain in a fixed, documented order
(network/service exposure, then secret exposure, then credential
exposure), and stops. Nothing here invents an intermediate node that
isn't backed by a specific finding_id, and nothing here tests, exploits,
or confirms anything: a path's `status` and `confidence` come directly
from the correlation it was built from, and its `path_risk` is that
correlation's combined risk score.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Fixed presentation order for findings within one path -- matches
# core.correlation.CATEGORY_CHAIN_ORDER, restated here because this is
# specifically about *path* traversal order, not just chain labeling.
_CATEGORY_RANK = {
    "Network/Service Exposure": 0,
    "Secret Exposure": 1,
    "Credential Exposure": 2,
}


@dataclass
class PathNode:
    id: str
    label: str
    kind: str  # "internet" | "asset" | "finding"
    finding_id: str = None


@dataclass
class PathEdge:
    source: str
    target: str
    label: str = ""


@dataclass
class AttackPath:
    path_id: str
    nodes: list
    edges: list
    path_risk: int
    confidence: float
    status: str
    supporting_findings: list
    recommended_mitigations: list
    narrative: str
    verification: object = None  # attack_paths.verification.PathVerification, set by core.pipeline.run_pipeline


def build_attack_paths(evidence_list: list, correlations: list) -> list:
    """Build one AttackPath per CorrelatedFinding in `correlations`.
    `evidence_list` supplies the full Evidence objects referenced by
    each correlation's `related_finding_ids`."""
    evidence_by_id = {e.finding_id: e for e in evidence_list}
    paths = []

    for i, corr in enumerate(correlations, start=1):
        nodes = [PathNode(id="internet", label="Internet", kind="internet")]
        edges = []
        prev_id = "internet"

        asset_node_id = f"asset:{corr.asset}"
        nodes.append(PathNode(id=asset_node_id, label=corr.asset, kind="asset"))
        edges.append(PathEdge(prev_id, asset_node_id, "targets"))
        prev_id = asset_node_id

        ordered = sorted(
            (evidence_by_id[fid] for fid in corr.related_finding_ids if fid in evidence_by_id),
            key=lambda e: _CATEGORY_RANK.get(e.category, 99),
        )
        for e in ordered:
            node_id = f"finding:{e.finding_id}"
            nodes.append(PathNode(id=node_id, label=f"{e.category}: {e.severity}", kind="finding", finding_id=e.finding_id))
            edges.append(PathEdge(prev_id, node_id, "leads to"))
            prev_id = node_id

        paths.append(
            AttackPath(
                path_id=f"PATH-{i:03d}",
                nodes=nodes,
                edges=edges,
                path_risk=corr.combined_risk_score,
                confidence=corr.confidence,
                status=corr.status,
                supporting_findings=list(corr.related_finding_ids),
                recommended_mitigations=[corr.remediation] if corr.remediation else [],
                narrative=corr.explanation,
            )
        )
    return paths
