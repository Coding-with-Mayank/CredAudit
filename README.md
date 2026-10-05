# CredAudit

A Python **security assessment and intelligence platform** built for
authorized engagements. It gathers credential, vulnerability, and
secret-exposure evidence — both from its own analyzers and from
external tools — groups related findings into chains an attacker could
actually follow, computes an explainable risk score, maps out possible
attack paths, and produces an auditable report and dashboard. All of it
sits behind a scope file that nothing in the project can be made to
bypass.

```
Scope/Authorization → Evidence Collection → Credential & Secret Analysis
  → Finding Correlation → Risk Engine → Attack-Path Analysis
  → Auditable Report / Dashboard
```

**It still doesn't reimplement brute-force or hash-cracking engines.**
Hydra, Medusa, ncrack, Hashcat, John the Ripper, and nuclei/scan4all
remain exactly what they always were: mature, widely-used tools that
handle that job better than a homegrown reimplementation would. What's
different is the architecture wrapped around them — those tools now act
as explicit **evidence sources** feeding a platform that does its own
analysis, scoring, and correlation, rather than a thin wrapper whose
only contribution is "runs the binary for you." See
[Why this exists](#why-this-exists) for more on that distinction.

## Why this exists

Most credential-testing tooling stops at "here are N findings." Raw
cracking speed was solved a long time ago; what's missing is scope
discipline, explainable risk, and turning a stack of disconnected
findings into the story they're actually telling. CredAudit rests on
three ideas:

1. **Nothing runs until the scope gate allows it**, and that gate can
   now carry a cryptographic signature instead of relying on a
   free-text claim alone — see [Authorization model](#authorization-model).
2. **Findings are evidence, not conclusions.** Every finding, whether
   it comes from a native analyzer or an external tool, lands in one
   unified, explainable schema with a documented risk score rather than
   a bare High/Medium/Low label. See [Evidence model](#evidence-model)
   and [Risk model](#risk-model).
3. **Correlated findings are the real risk.** An internet-facing SSH
   port, a weak password, and a breach-exposed credential are three
   unrelated facts on their own and one coherent story together. See
   [Finding correlation](#finding-correlation) and
   [Attack-path analysis](#attack-path-analysis).

## Architecture

```
credaudit/
├── scope.py, audit_log.py        # scope/authorization gate + tamper-evident audit log
│                                  # (canonical location; also aliased as core/scope.py, core/audit.py)
├── core/
│   ├── evidence.py                # unified finding schema every module speaks
│   ├── risk.py                    # explainable multi-factor risk engine
│   ├── correlation.py             # groups related evidence into risk chains
│   ├── authorization.py           # Ed25519 signing/verification
│   └── pipeline.py                # wires analyzers + integrations + correlation + attack paths
├── analyzers/
│   ├── credentials.py             # native credential intelligence (weak/reuse/breach/default/privileged)
│   ├── secrets.py                 # native secret detection (regex/shape-based, 10+ types)
│   └── vulnerabilities.py         # bridges the recon rule engine into the evidence model
├── integrations/
│   ├── hydra.py                   # confirmed-access evidence from live credential testing
│   ├── hashcat.py                 # joins cracked hashes back to accounts for the credential analyzer
│   └── nuclei.py                  # turns recon findings into evidence via analyzers.vulnerabilities
├── attack_paths/graph.py          # evidence-driven attack-path builder
├── dashboard/builder.py           # self-contained HTML dashboard
├── reporting/ (alias for report.py)
├── modules/                       # the original tool-wrapping modules (recon, online, offline,
│                                  # risk_engine, breach_check, js_intel, attack_graph, ...) — unchanged
│                                  # entry points; still own scope-checked subprocess invocation
└── cli.py                         # entrypoint wiring all of the above
```

Everything under `modules/` is the project's original orchestration
layer, already working, and its way of invoking external tools hasn't
changed — scope checks, subprocess handling, audit logging, and
lockout-safe pacing all still live there, in the same functions as
before. The new layer sits on top: `core/`, `analyzers/`,
`integrations/`, `attack_paths/`, and `dashboard/` take that
orchestration's raw output and turn it into unified, explainable,
correlated evidence.

## Install

Python 3.11+, packaged as an ordinary pip project (`pyproject.toml` —
`pip install .` and a bare `pytest` both just work, no `PYTHONPATH`
tricks required):

```bash
pip install .            # core CLI only
pip install .[llm]       # + AI-polished executive summaries (run --summary)
pip install .[api]       # + persistent findings REST API, DB, RBAC (credaudit serve)
pip install .[all]       # everything above
pip install -e .[dev]    # editable install + test deps, for working on CredAudit itself
```

`pyyaml`, `requests`, `cryptography` (Ed25519 signature verification),
and `zxcvbn` (password entropy estimation) are core dependencies rather
than optional extras, since scope-file/audit-log signing and sane
password scoring are part of the base workflow. `anthropic` (for
`--summary`) and `fastapi`/`sqlmodel`/`pyjwt`/`bcrypt` (for
`credaudit serve`) are kept as extras precisely because most scans need
neither.

This project orchestrates external binaries for live testing and
cracking, but handles its own analysis, correlation, risk, and
reporting — install whatever external tools you actually need
separately; none of them are pip dependencies (see
`docs/external_tools.md` for the reasoning):

- Recon: [nuclei](https://github.com/projectdiscovery/nuclei) (default) or
  [scan4all](https://github.com/GhostTroops/scan4all) (set `scanner_bin`)
- Online testing: [hydra](https://github.com/vanhauser-thc/thc-hydra),
  [medusa](https://github.com/jmk-foofus/medusa), or
  [ncrack](https://github.com/nmap/ncrack) — pick one with `--backend`
- Offline hash audit: [hashcat](https://hashcat.net/hashcat/) or John the Ripper

Run `credaudit doctor` at any point to see which optional Python
extras and external tools are currently available, along with install
hints for anything missing — or use the bundled `Dockerfile`, which
ships CredAudit plus all three external tools preinstalled on a Kali
base image (`docker build -t credaudit .`).

## Quickstart

1. Copy `scope/example-engagement.yaml`, fill in your real engagement
   details, and get it signed off through your org's process. To add
   real cryptographic assurance instead of leaning on the free-text
   `authorized_by` field alone (recommended):

```bash
python -m credaudit.cli keygen --out-prefix engagement-owner
python -m credaudit.cli sign-scope --scope scope/my-engagement.yaml \
  --private-key engagement-owner_private.pem
```

   See [Authorization model](#authorization-model) for exactly what
   this does and doesn't prove.

2. Run recon against everything in scope:

```bash
python -m credaudit.cli run --scope scope/my-engagement.yaml \
  --trusted-key engagement-owner_public.pem \
  --modules recon --out ./out
```

3. Run an offline hash audit. Cracked passwords now feed native
   credential intelligence automatically (weak/reuse/breach/
   default-credential detection) instead of just reporting a crack
   count — pass `--account-map` if your hash export doesn't carry
   usernames, and `--check-breach` to also check each cracked password
   against HIBP's Pwned Passwords API:

```bash
python -m credaudit.cli run --scope scope/my-engagement.yaml --modules offline \
  --hash-file hashes.txt --wordlist wordlists/passwords-standard.txt \
  --hash-mode ntlm --account-map hash_to_user.csv --check-breach --out ./out
```

4. Run online credential spraying — the safety model hasn't changed
   (scope check, interactive confirmation, lockout-safe pacing), and it
   now emits a **confirmed** (not merely detected) evidence finding
   whenever a live valid pair actually turns up:

```bash
python -m credaudit.cli run --scope scope/my-engagement.yaml --modules online \
  --target-group production --protocol rdp \
  --userlist users.txt --passwordlist wordlists/passwords-standard.txt \
  --backend hydra --out ./out
```

5. Run native secret detection over anything you've already retrieved
   (recon output, downloaded configs, a repo you're authorized to
   access) — this doesn't depend on any external tool:

```bash
python -m credaudit.cli run --scope scope/my-engagement.yaml --modules "" \
  --secret-scan ./retrieved-configs --out ./out
```

   (Steps 2-5 all write into the same `out/<engagement_id>/` directory
   and accumulate in the same report — run them in any combination, any
   order.)

6. Verify the audit trail (the hash chain *and*, if present, its
   signed manifest, which catches truncation that the chain alone
   can't):

```bash
python -m credaudit.cli verify --log out/<engagement_id>/audit_log.jsonl \
  --trusted-key engagement-owner_public.pem
```

7. Every run produces, in `out/<engagement_id>/`:
   - `report.md` / `report.html` — executive summary, every section
     below, redacted evidence, scope/authorization status, tool
     sources, and limitations
   - `dashboard.html` — a self-contained at-a-glance summary (stat
     tiles, risk distribution, correlated findings, attack paths,
     recent audit events)
   - `evidence.jsonl` — every finding in the unified schema, for your
     own tooling
   - `audit_log.jsonl` + `audit_log_manifest.json` — the tamper-evident
     trail and its final checkpoint

## Evidence model

Every analyzer, correlation step, and tool integration speaks one
schema (`credaudit/core/evidence.py`):

```json
{
  "finding_id": "CA-0001",
  "engagement_id": "ENG-001",
  "asset": "dc01.acme.example",
  "category": "Credential Exposure",
  "severity": "Critical",
  "risk_score": 85,
  "confidence": 0.92,
  "source": "credential_analysis",
  "evidence": "Account 'admin': Weak password (length 5); common=True; default_credential=True; ...",
  "related_findings": [],
  "remediation": "Change this default credential immediately. ...",
  "status": "detected"
}
```

`status` takes one of four values, and nothing downstream is allowed to
promote a finding past what its own evidence actually supports:

- `detected` — a pattern/indicator was observed
- `suspected` — multiple weak signals point the same way, nothing confirmed
- `potential_relationship` — part of a correlated chain that's still circumstantial
- `confirmed` — directly observed fact (e.g. the online module actually
  validated a login live)

## Risk model

Every score is the weighted sum of nine named, documented factors
(asset exposure, privilege level, exploitability, credential weakness,
breach exposure, vulnerability severity, password reuse, service
criticality, secret-type sensitivity), each normalized to `0.0`-`1.0`
and multiplied by a confidence discount. Every `RiskResult` carries its
own factor breakdown and plain-language explanation; nothing comes out
as a bare number. Full weight table, rationale, and a worked example
live in **[`docs/risk_model.md`](docs/risk_model.md)**.

```python
from credaudit.core import risk

result = risk.score_credential_finding(
    weak=True, reused=True, breached=True, privileged=True, internet_facing=True,
)
# result.score == 85, result.severity == "Critical"
# result.factors -> [RiskFactorContribution(name="asset_exposure", contribution=20.0, ...), ...]
# result.explanation -> "Asset is internet-facing... (+20 pts); ..."
```

## Credential intelligence

`credaudit/analyzers/credentials.py` goes well beyond "call Hashcat and
report a count." Given an account/password list — from a hash crack
joined back to real usernames via `integrations/hashcat.py`, or
supplied directly — it detects weak/common passwords, password reuse
across accounts, default credentials, privileged accounts sitting on
weak credentials, and, opt-in via `--check-breach`, breach exposure
through HIBP's k-anonymity API. **Plaintext is only ever held in memory
for the duration of a single analysis call** — every output object
carries a SHA-256 hash prefix, never the password itself.

Password strength defaults to a fixed, documented rule (length plus
character-class count). Pass `use_entropy_scoring=True` to
`analyze_credentials()` for a graduated, zxcvbn-based estimate instead
— entropy bits, crack-time-by-scenario, and pattern-aware scoring that
catches things the fixed rule misses, like keyboard walks. This is
additive and opt-in: the fixed rule's output stays exactly the same
unless you ask for the richer model.

```bash
credaudit analyze-credentials --creds-file accounts.txt \
  --check-breach --out out/creds.json
```

## Secret detection

`credaudit/analyzers/secrets.py` scans authorized files/directories for
AWS/GCP/Azure keys, Stripe/SendGrid keys, database connection strings,
private keys, JWTs, GitHub/Slack tokens, bearer tokens, and generic API
keys/secrets — pattern-based, the same general approach truffleHog and
gitleaks use. Output is always redacted (`AKIA************MNOP`); full
values never show up in a report or in the CLI's normal output.

Pattern matching alone can't distinguish a rotated key sitting in old
git history from a live one in production. `--validate-secrets`
(opt-in) closes that gap for secret types with a known issuer: one
read-only "who am I" API call per secret (GitHub/Slack/Stripe/
SendGrid/Google/AWS), the same technique TruffleHog and gitleaks label
"verified." A confirmed-active secret gets promoted to
`status="confirmed"`; a confirmed-inactive one has its severity capped
low but isn't thrown away — the exposure still happened. JWT expiry is
always checked locally with no network call, regardless of the flag.
Full details, including what's deliberately left out of
auto-validation (private keys, connection strings) and why, are in
**[`docs/secret_validation.md`](docs/secret_validation.md)**.

```bash
credaudit analyze-secrets --path ./retrieved-configs --validate-secrets --out out/secrets.json
```

## Finding correlation

`credaudit/core/correlation.py` groups evidence by asset and checks it
against a fixed, readable table of risk-chain patterns (e.g.
"internet-facing service + weak/exposed credential on the same host").
Every chain it produces traces back to specific `finding_id`s — nothing
gets inferred beyond what the underlying evidence already shows, and a
chain is only marked `confirmed` once every finding feeding it has
itself been independently confirmed.

## Attack-path analysis

`credaudit/attack_paths/graph.py` builds directly on correlated
findings: `Internet → asset → finding → finding → ...`, in a fixed
category order. Every node traces back to a specific finding; nothing
here tests, exploits, or confirms anything beyond what correlation
already established. (The project's original `modules/attack_graph.py`
— a narrower model built from recon risk assessments plus JS-intel
secrets — hasn't changed and still handles that specific path; this is
a complementary, broader model.)

`credaudit/attack_paths/verification.py` adds per-link detail on top of
that: for each finding in a path, whether it was directly observed
(`status="confirmed"`) or is still a hypothesis, and — for every
unconfirmed link — the exact, already-governed action that would
confirm it (e.g. "run `--validate-secrets`" or "run an authorized
`--modules online` test"). This is explicitly **not** an automated
exploitation/exploit-chaining feature, and it's not going to become
one — see
**[`docs/attack_path_verification.md`](docs/attack_path_verification.md)**
for why that line is deliberate rather than a gap waiting to be closed.

## Persistent findings backend (optional)

`credaudit/api/` (`pip install .[api]`) layers a REST API on top of
everything above: SQLite/Postgres-backed storage, JWT auth, and
role-based access control (admin/analyst/viewer), so findings persist
across scans and multiple analysts can track remediation over time —
`open` / `remediated` / `false_positive` / `accepted_risk`, a workflow
status kept separate from the scan's own confidence status.

```bash
export CREDAUDIT_JWT_SECRET=$(python -c 'import secrets; print(secrets.token_hex(32))')
credaudit create-user --username you --role admin   # first admin, CLI-only on purpose
credaudit serve                                       # http://127.0.0.1:8000/docs
credaudit import-findings --evidence out/.../evidence.jsonl --engagement-id ENG-1
```

Entirely additive: every CLI workflow still works exactly as before,
writing `evidence.jsonl` the same way, with zero dependency on this
module or a running database unless you opt in.

## Authorization model

Scope enforcement — target allowlists, CIDR ranges, wildcard
subdomains, module allowlists, per-protocol permissions, engagement
date windows — is unchanged in spirit and broader in reach than the
original project. New: scope files can now be **cryptographically
signed** (Ed25519) instead of relying solely on a free-text
`authorized_by` field, with `require_signature: true` to fail closed if
unsigned. The full model, the two trust levels, and exactly what each
does and doesn't prove live in
**[`docs/authorization.md`](docs/authorization.md)**.

```bash
python -m credaudit.cli keygen --out-prefix owner
python -m credaudit.cli sign-scope --scope scope/acme.yaml --private-key owner_private.pem
python -m credaudit.cli run --scope scope/acme.yaml --trusted-key owner_public.pem ...
```

## Audit model

The hash-chained audit log works the same way it always did — every
entry embeds the previous entry's hash, so `verify_chain()` catches any
edit, deletion, or reordering **within the entries present**. New:
every entry now also carries `engagement_id` and an `actor`
(user@host:pid), and `AuditLog.finalize()` writes a signed manifest
(final entry count plus hash, optionally Ed25519-signed) specifically
so that **truncation** from the end of the log — something an
internally-consistent hash chain alone can't catch — gets caught by
comparing the log against its manifest:

```bash
python -m credaudit.cli verify --log out/<engagement_id>/audit_log.jsonl \
  --manifest out/<engagement_id>/audit_log_manifest.json \
  --trusted-key owner_public.pem
```

`credaudit verify` reports chain validity, manifest match, and
signature validity as three separate checks, and fails (non-zero exit)
if any one of them doesn't hold.

## Reporting and dashboard

`report.md` / `report.html` now include, alongside the original
per-module sections: credential findings, secret exposure, correlated
findings, attack paths, a full evidence table, risk distribution, scope
and authorization status, tool/evidence sources, and a limitations
section — redacted throughout and readable by technical and
non-technical audiences alike. `dashboard.html` is a single
self-contained file (no external assets, no JS framework) built for a
fast at-a-glance summary: stat tiles, risk distribution, correlated
findings, attack paths, and recent audit events.

## Interpretation that predates this round of changes

These existed before and haven't changed:

**Legacy risk engine** (`modules/risk_engine.py`) — scores a recon
finding against a rule table (old versions, weak crypto, default creds,
anonymous access, exposed secrets, and so on). Still runs automatically
with `--modules recon`, and its output now also flows into the unified
evidence model via `analyzers/vulnerabilities.py`.

```python
from credaudit.modules.risk_engine import assess_service

assess_service("203.0.113.10", "ssh", ["old_version", "password_auth_enabled"])
# -> RiskAssessment(risk_level="High", reasoning="Outdated software version detected; ...")
```

**Decision engine** — `recon.suggest_online_targets_with_risk()` sorts
suggested `--target`/`--protocol` pairs by risk. Still just a
suggestion list; nothing calls the online module on its own.

**JavaScript intelligence** — `analyze-js` extracts endpoints, keys,
JWTs, and GraphQL hints from JS you've already retrieved. Detection
only; it never fetches anything itself. Full unmasked output is
available for your own triage, while reports always show masked
versions. Results now also feed the secret-detection/correlation
pipeline via `--js-intel` on `run`.

```bash
python -m credaudit.cli analyze-js --file main.js \
  --source https://acme.example/main.js --out out/js-intel/main.json
```

**Executive summary (optional)** — `--summary` asks an LLM (using your
own `ANTHROPIC_API_KEY`) to draft prose from findings already
collected. It never triggers another module, and its output is always
labeled a draft.

## Wordlists

`wordlists/fetch_wordlists.sh` pulls real, verified files from
[SecLists](https://github.com/danielmiessler/SecLists):

```bash
./wordlists/fetch_wordlists.sh standard    # 10k passwords, good default
./wordlists/fetch_wordlists.sh thorough    # 100k passwords
./wordlists/fetch_wordlists.sh deep        # 1,000,000 passwords (~8.7 MB)
./wordlists/fetch_wordlists.sh usernames   # common username shortlist
```

For target-specific weak passwords (company name variants, product
names, years, leetspeak), generate a custom list from public
information about your authorized target:

```bash
python -m credaudit.cli generate-wordlist \
  --seed AcmeCorp --seed AcmeWidget --seed Acme2019 \
  --out wordlists/acme-custom.txt
```

## Richer scope files

Beyond the required fields, a scope file can also define:

- **`target_groups`** — named subsets of `targets`. Every member is
  checked against the top-level `targets` list at load time, so a group
  can organize scope but can never extend it.
- **`protocol_limits`** — per-protocol pacing
  (`seconds_between_passwords`, `tasks`). Falls back to 300s / 1 task
  for anything not listed.
- **`allowed_protocols`** *(new)* — per-module protocol allowlist, e.g.
  `allowed_protocols: {online: [ssh, rdp]}`. A module with no entry
  here gets no additional restriction — this tightens things on an
  opt-in basis rather than introducing a new default that would break
  existing scope files.
- **`require_signature`** *(new)* — fail closed if the scope file isn't
  cryptographically signed. See [Authorization model](#authorization-model).
- **`emergency_contact`** — who to notify if something looks wrong
  mid-engagement.

Targets also now support wildcard subdomains (`*.acme-test.example`)
alongside exact hosts/IPs and CIDR ranges. See
`scope/example-engagement.yaml` for a fully worked example.

## Automating the offline audit

`.github/workflows/scheduled-offline-audit.yml` runs the offline
module weekly across every scope file in `scope/*.yaml`. It's safe to
automate — it only re-tests a hash export you already control against a
wordlist, and never sends live traffic. Online spraying is deliberately
**not** included in CI; the interactive confirmation it requires is a
safeguard, not a rough edge to script around. See the workflow file's
header comments for the per-engagement secrets setup.

`.github/workflows/tests.yml` runs the test suite on every push and PR.

## Testing

```bash
pytest tests/ -v
```

All tests are deterministic, mocked, and run against local fixtures —
none of them attack real external targets or need network access
(live secret-validation's provider calls are mocked via
`unittest.mock.patch` on `requests.get`/`requests.post`, the same
approach used for the existing HIBP breach-check tests). Coverage
includes: scope validation (including wildcard domains and protocol
permissions), signature generation/verification/tamper-detection, risk
calculation (including the brief's own worked example), credential
analysis (including plaintext-never-stored checks and opt-in entropy
scoring), secret detection (every pattern type, redaction, severity
consistency, opt-in live validation), evidence-schema validation,
finding correlation, attack-path generation and per-link verification,
audit-log integrity and truncation detection, redaction, the persistent
findings API (auth/RBAC/import-idempotency/workflow updates — skipped,
not failed, when the `[api]` extra isn't installed), and the full
pipeline end-to-end.

`pip install .` (no extras) followed by `pytest tests/ -v` is a
meaningful check in its own right: it's what confirms the base package
installs and tests cleanly with nothing optional present, which is
exactly the gap that used to make a bare `pytest` fail (see
`.github/workflows/tests.yml`, which runs both this and a from-scratch
`pip install .` as a dedicated regression check).

## Docs

- [`docs/risk_model.md`](docs/risk_model.md) — full factor table,
  worked example, tuning guidance
- [`docs/authorization.md`](docs/authorization.md) — the two
  signature-trust levels and exactly what each does and doesn't prove
- [`docs/kerberoasting.md`](docs/kerberoasting.md) — using the offline
  module's Kerberoasting/ASREPRoast presets during an authorized AD
  engagement
- [`docs/secret_validation.md`](docs/secret_validation.md) — what
  `--validate-secrets` checks, how, and what it deliberately doesn't
- [`docs/attack_path_verification.md`](docs/attack_path_verification.md)
  — per-link attack-path corroboration, and why it stops short of
  automated exploitation
- [`docs/external_tools.md`](docs/external_tools.md) — why
  Hydra/Hashcat/nuclei aren't pip dependencies, and three ways to get them

## Scope file

See `scope/example-engagement.yaml`. Required fields: `engagement_id`,
`client_name`, `authorized_by`, `start_date`, `end_date`, `targets`,
`allowed_modules`. The gate refuses to run outside the date window,
against any target not listed, or for any module not explicitly
allowed — and for the online module it additionally requires typing the
engagement ID to confirm, unless `confirm_online_testing: true` is
pre-set (e.g. for CI).

## Important notes on legality and scope

- **Authorization, not code, is what makes credential testing legal.**
  Cryptographic signing (above) proves a scope file's content hasn't
  changed since a specific key signed it — it does not, and cannot,
  verify that the underlying authorization is real. Get it in writing,
  through your org's actual process, before running anything against a
  live target.
- **Bug bounty programs frequently restrict automated brute-forcing
  even on in-scope assets.** Check the program's policy specifically
  for credential-stuffing/brute-force/rate-limit language before
  running the online module.
- **Offline auditing only applies to hashes you already legitimately
  possess.** It doesn't help you obtain hashes you don't have.
- The spray pattern in `modules/online.py` tests one password across
  all accounts with a delay before moving to the next, specifically to
  avoid lockouts — tune `seconds_between_passwords` to the target's
  actual lockout policy.

## Limitations

Stated here, in the generated report, and in the relevant module
docstrings — not just once:

- Scope enforcement happens in CredAudit's own Python code before every
  external-tool invocation; it cannot guarantee that a third-party
  binary (hydra, hashcat, nuclei, ...) will never itself act outside
  the intended boundary due to a bug or flag misuse.
- Signature verification with an externally-supplied trusted key is
  real assurance; with a key embedded in the scope file itself, it only
  proves internal self-consistency. Neither proves the signer was
  organizationally authorized to approve the engagement.
- The audit log's hash chain detects tampering *within* the entries
  present; detecting truncation requires its signed manifest
  (`credaudit verify`).
- Correlated findings and attack paths describe co-occurrence of
  evidence on the same asset, not a confirmed attacker path, unless
  every underlying finding was itself directly observed. Per-link
  verification detail is available (`docs/attack_path_verification.md`)
  but this platform does not and will not automatically exploit a
  finding to prove a path — that still requires a human to take the
  indicated, already-scoped action.
- Secret detection is pattern-based and misses secrets that don't match
  a known pattern shape. Opt-in live validation (`--validate-secrets`,
  `docs/secret_validation.md`) can confirm whether a secret with a known
  issuer is currently active via one read-only call to that issuer's own
  API; private keys and connection strings are deliberately excluded
  (validating those live would mean testing a target, not an issuer).
- Password-strength classification defaults to a fixed, documented rule;
  an opt-in zxcvbn-based entropy/crack-time estimate is available for a
  more graduated assessment. The built-in common-password list is a
  small hygiene sample, not a cracking dictionary.
- Breach-exposure checking is opt-in and needs network access; when not
  run, breach exposure is recorded as "not checked," never "clean."
- Risk scores are an explainable, documented weighted model (see
  `docs/risk_model.md`), not a guarantee of real-world exploitability.
- The optional persistent backend (`credaudit.api`) adds remediation
  workflow tracking on top of findings; it doesn't re-score or
  re-verify them on import, and every CLI workflow still works with
  zero dependency on it.

## License

MIT — see `LICENSE`.
