"""JavaScript intelligence: static analysis of JS content you already
retrieved during authorized recon.

This module never fetches anything itself and never tests whether
anything it finds actually works against a live system -- it reads text
you already have and flags patterns in it. What you do with a found
secret (rotate it, report it to the client, confirm it's actually live)
is a judgment call for you, not something this module decides or acts
on.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

ENDPOINT_PATTERNS = [
    re.compile(r'''fetch\(\s*["'`]([^"'`]+)["'`]'''),
    re.compile(r'''axios\.\w+\(\s*["'`]([^"'`]+)["'`]'''),
    re.compile(r'''\.(?:get|post|put|delete|patch)\(\s*["'`](/[^"'`]+)["'`]'''),
    re.compile(r'''["'`](/api/[a-zA-Z0-9_\-/{}.]+)["'`]'''),
    re.compile(r'''["'`](/graphql[a-zA-Z0-9_\-/]*)["'`]'''),
]

# Patterns with no capture group match the whole secret; patterns with
# one capture group extract just the value out of a key: "value" pair.
SECRET_PATTERNS = {
    "aws_access_key": re.compile(r'AKIA[0-9A-Z]{16}'),
    "google_api_key": re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
    "slack_token": re.compile(r'xox[baprs]-[0-9A-Za-z-]{10,48}'),
    "private_key_header": re.compile(r'-----BEGIN (?:RSA |EC |)PRIVATE KEY-----'),
    "jwt": re.compile(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
    "generic_api_key": re.compile(
        r'''(?:api[_-]?key|apikey)["']?\s*[:=]\s*["']([A-Za-z0-9_\-]{16,64})["']''', re.IGNORECASE
    ),
    "generic_secret": re.compile(
        r'''(?:secret|client[_-]?secret)["']?\s*[:=]\s*["']([A-Za-z0-9_\-.]{16,64})["']''', re.IGNORECASE
    ),
}

GRAPHQL_HINTS = re.compile(r'\b(query|mutation|subscription)\s*\{|graphql', re.IGNORECASE)

INTEREST_KEYWORDS = {
    "admin": 3, "internal": 3, "debug": 3, "backup": 3,
    "staging": 2, "test": 2, "account": 2, "config": 2, "auth": 2, "token": 2, "upload": 2, "export": 2,
    "v1": 1, "v2": 1, "api": 1, "user": 1,
}


@dataclass
class SecretFinding:
    kind: str
    value: str
    masked: str


@dataclass
class JSIntelResult:
    source: str = ""
    endpoints: list = field(default_factory=list)  # list of (path, interest_score), sorted descending
    secrets: list = field(default_factory=list)     # list of SecretFinding
    has_graphql: bool = False


def _mask(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"


def _score_endpoint(path: str) -> int:
    lower = path.lower()
    return sum(weight for keyword, weight in INTEREST_KEYWORDS.items() if keyword in lower)


def analyze_js(content: str, source: str = "") -> JSIntelResult:
    endpoints_seen = {}
    for pattern in ENDPOINT_PATTERNS:
        for match in pattern.finditer(content):
            path = match.group(1)
            if len(path) < 2:
                continue
            endpoints_seen[path] = _score_endpoint(path)
    endpoints = sorted(endpoints_seen.items(), key=lambda kv: -kv[1])

    secrets = []
    seen_values = set()
    for kind, pattern in SECRET_PATTERNS.items():
        for match in pattern.finditer(content):
            value = match.group(1) if match.groups() else match.group(0)
            if value in seen_values:
                continue
            seen_values.add(value)
            secrets.append(SecretFinding(kind=kind, value=value, masked=_mask(value)))

    return JSIntelResult(
        source=source,
        endpoints=endpoints,
        secrets=secrets,
        has_graphql=bool(GRAPHQL_HINTS.search(content)),
    )


def analyze_js_file(path, source: str = "") -> JSIntelResult:
    from pathlib import Path
    content = Path(path).read_text(errors="ignore")
    return analyze_js(content, source=source or str(path))


def to_dict(result: JSIntelResult) -> dict:
    return {
        "source": result.source,
        "endpoints": [[path, score] for path, score in result.endpoints],
        "secrets": [
            {"kind": s.kind, "value": s.value, "masked": s.masked} for s in result.secrets
        ],
        "has_graphql": result.has_graphql,
    }


def from_dict(data: dict) -> JSIntelResult:
    return JSIntelResult(
        source=data.get("source", ""),
        endpoints=[(path, score) for path, score in data.get("endpoints", [])],
        secrets=[
            SecretFinding(kind=s["kind"], value=s["value"], masked=s["masked"])
            for s in data.get("secrets", [])
        ],
        has_graphql=data.get("has_graphql", False),
    )
