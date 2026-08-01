# Credential audit report

- **Engagement:** ACME-2026-Q3-001
- **Client:** Acme Corp
- **Authorized by:** Jane Doe, CISO — signed SOW #4521, 2026-07-20
- **Window:** 2026-08-01 to 2026-08-14
- **Scope file checksum (sha256):** `8f1a2c9e4b7d0f3a6c5e8b1d4f7a0c3e6b9d2f5a8c1e4b7d0f3a6c9e2b5d8f1a`
- **Generated:** 2026-08-01T12:08:05.778692Z

## Executive summary

*AI-generated draft — review before including in a client deliverable.*

This engagement identified 7 recon findings across 4 in-scope targets, including one critical exposure and a high-risk outdated SSH configuration with password authentication enabled. An AWS access key was found embedded in client-side JavaScript on acme.example and has not been verified as active -- this requires immediate manual follow-up. Offline hash auditing found 11 of 142 tested credentials (8%) to be weak, and 11 of 142 tested passwords have appeared in known public breaches. Online credential testing against the SSH service found 2 valid credential pairs out of 48 accounts tested.

## Targets in scope

- 203.0.113.10
- 203.0.113.0/28
- vpn.acme-test-range.example
- acme.example

## Risk assessment

- **Critical** — http on acme.example: Secrets or sensitive files exposed; Web misconfigurations often expose source code, secrets, or internal details. (indicators: secrets_exposed)
- **High** — ssh on 203.0.113.10: Outdated software version detected; Password authentication enabled; SSH is a common brute-force and credential-stuffing target. (indicators: old_version, password_auth_enabled)

## Recon findings

7 findings recorded (4 needing attention, 3 informational).

## JavaScript intelligence

- `https://acme.example/static/main.js`: 2 endpoint(s), 1 secret pattern(s)
  - aws_access_key: `AKIA************MNOP`

## Attack graph (hypothetical, unverified past credential leak)

- HTTP on acme.example (Critical) → aws_access_key in https://acme.example/static/main.js (may have exposed)
- aws_access_key in https://acme.example/static/main.js → Potential AWS access *(unverified)* (if valid)
- Potential AWS access → Manual verification required *(unverified)* (requires explicit authorization)

## Online credential testing

- `examples/sample-report/online_hydra_203.0.113.10.log` — 48 accounts tested, 2 valid pair(s) found

## Offline hash audit

- 11 / 142 hashes cracked (8%)
- Cracked-password log: `examples/sample-report/offline/cracked.txt`
- Raw plaintext is intentionally not embedded in this report; reference the log file directly and handle it per your engagement's data-handling rules.

## Password hygiene (breach-corpus check)

- 11 / 142 tested passwords have appeared in known public breaches.

## Audit trail

See `audit_log.jsonl` in this engagement's output directory for the full hash-chained action log. Verify it with `python -m credaudit.cli verify --log audit_log.jsonl`.
