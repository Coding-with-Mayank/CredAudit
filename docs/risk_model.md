# Risk model

Every risk score CredAudit produces comes from one function:
`credaudit.core.risk.score(factor_values, confidence)`. It's a weighted
sum of nine named factors, each normalized to `0.0`-`1.0`, multiplied by
a confidence discount, and clipped to `0`-`100`. There's no
per-finding special-casing and no hidden fudge factor: a credential
finding, a secret finding, and a service-exposure finding are all
scored by the exact same function, just fed different factor values by
the three convenience wrappers (`score_credential_finding`,
`score_secret_finding`, `score_service_finding`) in
`credaudit/core/risk.py`.

## The factors and why they're weighted the way they are

| Factor | Weight | What it captures |
|---|---|---|
| `asset_exposure` | 0.20 | Internet-facing vs. internal-only. The single biggest lever on "how likely is this to actually be reached" — the same technical weakness is a different risk on a public host than behind a VPN. |
| `privilege_level` | 0.18 | Blast radius if abused. A weak password on a disposable test account and the same password on a domain admin account are not the same event. |
| `exploitability` | 0.15 | How directly usable the finding is *today*, without further chaining. A default credential is immediately exploitable; a theoretical weak-cipher exposure less so. |
| `credential_weakness` | 0.12 | Intrinsic weakness of the credential itself (length/complexity/common password). |
| `breach_exposure` | 0.10 | Whether the exact credential/secret is already known to be public. |
| `vulnerability_severity` | 0.10 | Underlying CVE/misconfiguration severity (recon findings only). |
| `password_reuse` | 0.08 | Reuse multiplies blast radius — one leak compromises every account sharing it. |
| `service_criticality` | 0.05 | Business/asset importance. Deliberately the smallest weight: it's usually a judgment call supplied by whoever runs the engagement, not something CredAudit observes directly, so it nudges the score rather than dominating it. |
| `secret_type_sensitivity` | 0.02 | Tie-breaker between e.g. a cloud admin key and a low-scope token when everything else is equal. |

Weights sum to exactly `1.0` (enforced by an assertion at import time:
if someone edits `FACTOR_WEIGHTS` and gets the arithmetic wrong, the
package fails to import instead of silently producing scores that
don't mean what the documentation claims they mean).

## Severity bands

| Score | Severity |
|---|---|
| 80-100 | Critical |
| 60-79 | High |
| 40-59 | Medium |
| 20-39 | Low |
| 0-19 | Info |

## Worked example

The project brief's own example — an admin account with a weak,
reused, breached password on an internet-facing, privileged service —
scores out like this:

| Factor | Value | Weight | Contribution |
|---|---|---|---|
| asset_exposure | 1.0 | 0.20 | 20.0 |
| privilege_level | 1.0 | 0.18 | 18.0 |
| exploitability | 1.0 | 0.15 | 15.0 |
| credential_weakness | 1.0 | 0.12 | 12.0 |
| breach_exposure | 1.0 | 0.10 | 10.0 |
| password_reuse | 1.0 | 0.08 | 8.0 |
| service_criticality | 0.5 (default) | 0.05 | 2.5 |

Total: 85.5 → rounds to **85** → **Critical**, confidence 1.0 (every
factor here is a directly observed fact rather than an inference).

## What this model intentionally does *not* do

- It doesn't produce a score for a factor you didn't supply — a
  missing factor is `0.0` ("not observed"), never guessed at.
- It rejects an unrecognized factor name immediately
  (`RiskEngineError`) instead of silently ignoring a typo.
- It caps `secret_type_sensitivity`-only findings (e.g. a bare API key
  of unclear scope) well below what a directly-exploitable credential
  or private key can reach, on purpose — see
  `core.risk.score_secret_finding`'s docstring for the reasoning.

## Tuning this for your own risk appetite

These weights are a judgment call, not a physical law. If your
engagement calls for a different risk appetite — say you care more
about privilege than exposure because you're assessing an internal
red-team exercise rather than an external pentest — edit
`FACTOR_WEIGHTS` in `credaudit/core/risk.py` (keeping the sum at
`1.0`) and update the Weight column of this document to match. Every
score, report, and dashboard in the project reads from that one table,
so there's exactly one place to change.

## Limitations

- This is a prioritization tool, not a guarantee of real-world
  exploitability. A score of 85 means "treat this with urgency
  relative to CredAudit's other findings," not "this has been proven
  exploitable."
- `service_criticality` almost always comes from a default (`0.5`)
  unless whoever is running the engagement supplies a real value —
  treat scores involving it as provisional until that's filled in with
  actual business context.
- The model has no awareness of compensating controls (e.g. a weak
  internal password sitting behind otherwise solid network segmentation)
  unless that context is reflected in the factor values fed to it.
