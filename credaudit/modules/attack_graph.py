"""Attack graph: connects real evidence (risk assessments, JS-intel
secrets) into a hypothetical escalation path for the report.

This module never tests, verifies, or exploits anything it maps. Every
node is either something actually observed (verified=True) or a clearly
labeled hypothetical next stage (verified=False) -- and every path
through the graph terminates at a "needs manual verification" node, not
at an assumed compromise. Building this graph is analysis; acting on any
edge in it is a separate, deliberate, human decision that this module
does not make and cannot trigger.
"""
from __future__ import annotations

from dataclasses import dataclass, field

STAGE_ORDER = ["exposure", "credential_leak", "potential_access", "needs_verification"]

STAGE_LABELS = {
    "exposure": "Public exposure",
    "credential_leak": "Credential leak",
    "potential_access": "Potential access (unverified)",
    "needs_verification": "Needs manual verification",
}

# Which secret kinds plausibly lead to which "potential access" category.
# This is a taxonomy for labeling, not a claim that access was achieved.
SECRET_ACCESS_HINTS = {
    "aws_access_key": "Potential AWS access",
    "google_api_key": "Potential Google Cloud/API access",
    "slack_token": "Potential Slack workspace access",
    "private_key_header": "Potential SSH/TLS impersonation",
}


@dataclass
class GraphNode:
    id: str
    label: str
    stage: str
    verified: bool


@dataclass
class GraphEdge:
    source: str
    target: str
    label: str = ""


@dataclass
class AttackGraph:
    nodes: list = field(default_factory=list)
    edges: list = field(default_factory=list)

    def add_node(self, node: GraphNode) -> None:
        self.nodes.append(node)

    def add_edge(self, edge: GraphEdge) -> None:
        self.edges.append(edge)


def build_attack_graph(risk_assessments=None, js_intel_results=None) -> AttackGraph:
    graph = AttackGraph()
    counter = 0

    def new_id() -> str:
        nonlocal counter
        counter += 1
        return f"n{counter}"

    exposure_nodes = []  # (id, target) for high/critical risk findings
    for assessment in (risk_assessments or []):
        if assessment.risk_level in ("Critical", "High"):
            nid = new_id()
            graph.add_node(GraphNode(
                nid, f"{assessment.service.upper()} on {assessment.target} ({assessment.risk_level})",
                "exposure", True,
            ))
            exposure_nodes.append((nid, assessment.target))

    for result in (js_intel_results or []):
        for secret in result.secrets:
            secret_id = new_id()
            graph.add_node(GraphNode(
                secret_id, f"{secret.kind} in {result.source or 'JS content'}",
                "credential_leak", True,
            ))

            # best-effort correlation: only link an exposure to a secret
            # when the exposure's target string actually appears in the
            # secret's source -- no fabricated relationships
            for exp_id, exp_target in exposure_nodes:
                if exp_target and exp_target in (result.source or ""):
                    graph.add_edge(GraphEdge(exp_id, secret_id, "may have exposed"))

            access_label = SECRET_ACCESS_HINTS.get(secret.kind)
            if access_label:
                access_id = new_id()
                graph.add_node(GraphNode(access_id, access_label, "potential_access", False))
                graph.add_edge(GraphEdge(secret_id, access_id, "if valid"))

                verify_id = new_id()
                graph.add_node(GraphNode(
                    verify_id, "Manual verification required", "needs_verification", False,
                ))
                graph.add_edge(GraphEdge(access_id, verify_id, "requires explicit authorization"))
            else:
                verify_id = new_id()
                graph.add_node(GraphNode(
                    verify_id, "Manual verification required", "needs_verification", False,
                ))
                graph.add_edge(GraphEdge(secret_id, verify_id, "requires explicit authorization"))

    return graph
