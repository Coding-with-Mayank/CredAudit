# CredAudit

**CredAudit is a Python security-auditing tool for authorized security assessments.**

It helps security teams find credential problems, exposed secrets, and vulnerabilities. It also connects related findings, explains risk scores, maps possible attack paths, and creates reports.

> **Use CredAudit only on systems and data you have permission to test.** A tool's scope settings do not replace written authorization or the target's rules.

## What can it do?

- **Check scope:** Limit an engagement to approved targets, modules, and dates.
- **Review credentials:** Find weak, reused, default, or breach-exposed passwords in credential data you are authorized to audit.
- **Find exposed secrets:** Look for API keys, tokens, private keys, database connection strings, and other recognizable secret patterns in files you are allowed to inspect.
- **Use security tools:** Collect findings from tools such as Nuclei, Hydra, and Hashcat. These external tools must be installed separately.
- **Explain risk:** Give findings a risk score with a breakdown of the factors that affected it.
- **Connect findings:** Group related findings and show possible attack paths. A possible path is not proof that an attack would succeed.
- **Create reports:** Generate Markdown and HTML reports, a dashboard, structured evidence, and an audit log.
- **Protect the audit trail:** Verify log integrity and optionally use cryptographic signatures for scope files and audit manifests.

## How it works

```text
Check authorization and scope
             ↓
Collect or load security findings
             ↓
Analyze credentials, secrets, and vulnerabilities
             ↓
Connect related findings and calculate risk
             ↓
Build possible attack paths
             ↓
Generate reports, dashboard, and audit log
```

## Requirements

- Python 3.11 or newer.
- External tools for the functions you plan to use. For example, reconnaissance uses Nuclei by default.
- Written authorization and a correctly configured scope file before testing live targets.

## Installation

Run these commands from the repository's main directory.

### Install the core project

```bash
python -m pip install .
```

### Optional features

```bash
# AI-polished executive summaries
python -m pip install ".[llm]"

# Persistent findings API, database support, and role-based access
python -m pip install ".[api]"

# All optional features
python -m pip install ".[all]"

# Development dependencies and test tools
python -m pip install -e ".[dev]"
```

The `--summary` option also has a built-in template-based summary when the AI package or API key is unavailable.

### Check your setup

```bash
credaudit doctor
```

This checks optional Python packages and the external security tools CredAudit knows how to use. Install missing external tools separately; see [`docs/external_tools.md`](docs/external_tools.md).

## Quick start: authorized reconnaissance

### 1. Create a scope file

Copy the example:

```bash
cp scope/example-engagement.yaml scope/my-engagement.yaml
```

Edit `scope/my-engagement.yaml` before running anything. Set the real engagement ID, client, authorization details, start/end dates, approved targets, and allowed modules. The example values are placeholders, and its sample dates may be in the past.

The scope file is the list of what this engagement is allowed to test. CredAudit checks target, module, and date restrictions before it runs an allowed module.

### 2. (Recommended) Sign the scope file

Generate a key pair:

```bash
python -m credaudit.cli keygen --out-prefix keys/engagement-owner
```

Sign your reviewed scope file:

```bash
python -m credaudit.cli sign-scope \
  --scope scope/my-engagement.yaml \
  --private-key keys/engagement-owner_private.pem
```

Keep the private key secret and out of Git. For stronger verification, keep the public key outside the scope file and pass it to CredAudit with `--trusted-key`.

A signature proves that the signed file has not changed since it was signed. It does **not** prove that the signer was authorized to approve the engagement. See [`docs/authorization.md`](docs/authorization.md).

### 3. Run reconnaissance

```bash
python -m credaudit.cli run \
  --scope scope/my-engagement.yaml \
  --trusted-key keys/engagement-owner_public.pem \
  --modules recon \
  --out ./out
```

Reconnaissance uses Nuclei by default, so install it first. This command writes results under `out/<engagement_id>/`.

### 4. Review the results

Look in `out/<engagement_id>/` for files such as:

- `report.md` — the readable security report.
- `report.html` — an HTML version of the report.
- `dashboard.html` — a quick visual summary.
- `evidence.jsonl` — structured findings that other tools can process.
- `audit_log.jsonl` — a record of audit events.
- `audit_log_manifest.json` — a final checkpoint used to help detect log truncation.

The exact findings depend on the modules and data used in the engagement.

## Other useful commands

### Scan files for exposed secrets

Use this for files or directories you are authorized to inspect:

```bash
credaudit analyze-secrets \
  --path ./retrieved-configs \
  --out ./out/secrets.json
```

To optionally check supported detected secrets with their issuing providers, add `--validate-secrets`. This sends a read-only identity request to the secret's own provider. JWT expiration is checked locally.

```bash
credaudit analyze-secrets \
  --path ./retrieved-configs \
  --validate-secrets \
  --out ./out/secrets.json
```

Secret detection uses patterns, so it may miss secrets that do not match a recognized pattern. Normal output masks detected secret values.

### Analyze credential data

Create a text file with one `account:password` pair per line, using only credential data you are authorized to audit. Then run:

```bash
credaudit analyze-credentials \
  --creds-file accounts.txt \
  --out ./out/credentials.jsonl
```

To check passwords against the Have I Been Pwned Pwned Passwords service, add `--check-breach`. This requires network access. If the check is not run, CredAudit records breach exposure as not checked rather than assuming the credentials are clean.

CredAudit's credential analysis avoids putting plaintext passwords in its normal findings output. Protect the input file as sensitive data and remove it when it is no longer needed.

### Analyze a JavaScript file you already have

```bash
credaudit analyze-js \
  --file main.js \
  --source https://example.com/main.js \
  --out ./out/js-intel.json
```

This command analyzes a local JavaScript file; it does not download the file for you.

### Verify an audit log

```bash
credaudit verify \
  --log out/<engagement_id>/audit_log.jsonl \
  --manifest out/<engagement_id>/audit_log_manifest.json \
  --trusted-key keys/engagement-owner_public.pem
```

Replace `<engagement_id>` with the directory name for your engagement. The verification command checks the log chain and manifest and checks the signature when a trusted key is supplied and the manifest is signed.

### See available hash presets

```bash
credaudit hash-types
```

## Online and offline credential testing

CredAudit can orchestrate external tools for offline password-hash auditing and online credential testing. These actions are more sensitive than passive analysis.

- Only audit password hashes you legitimately possess.
- Before online credential testing, verify that your written authorization and the target's rules explicitly allow it.
- Many bug bounty programs prohibit brute-force or credential-spraying tests, even on in-scope assets.
- Online testing checks the engagement scope and requires an interactive confirmation by default. Do not bypass these safeguards.

Read [`docs/external_tools.md`](docs/external_tools.md) for external tool details and [`docs/kerberoasting.md`](docs/kerberoasting.md) for the supported offline Active Directory hash-auditing workflow.

## How findings are rated

CredAudit uses a documented risk model. It considers factors such as asset exposure, privileges, credential weakness, breach exposure, vulnerability severity, password reuse, service importance, and secret sensitivity. The score is an estimate to help prioritize work, not a guarantee that an issue can be exploited.

Findings use statuses to distinguish observations from assumptions:

- `detected` — a pattern or indicator was found.
- `suspected` — several signals suggest a problem, but it is not confirmed.
- `potential_relationship` — the finding may be related to other findings.
- `confirmed` — the specific fact has been directly observed or verified.

Correlated findings and attack paths must not be treated as proven attack chains unless the supporting evidence confirms each step. See [`docs/risk_model.md`](docs/risk_model.md) and [`docs/attack_path_verification.md`](docs/attack_path_verification.md).

## Optional persistent findings API

The API stores findings in a database so a team can review them across scans and track remediation. It supports roles for administrators, analysts, and viewers.

Install and configure the optional API packages:

```bash
python -m pip install ".[api]"
export CREDAUDIT_JWT_SECRET=$(python -c 'import secrets; print(secrets.token_hex(32))')
credaudit create-user --username you --role admin
credaudit serve
```

The local API documentation is available at `http://127.0.0.1:8000/docs`. Keep the API and its secrets protected; configure network exposure and database access deliberately before using it outside your own machine.

## Testing

Install the development dependencies and run the test suite:

```bash
python -m pip install -e ".[dev]"
pytest tests/ -v
```

The tests are designed to use local fixtures and mocked external calls rather than attack real external systems.

## Project structure

```text
credaudit/
├── analyzers/      # Credential, secret, and vulnerability analysis
├── api/            # Optional persistent findings API
├── attack_paths/   # Builds possible paths from findings
├── core/           # Evidence, risk, correlation, authorization, pipeline
├── dashboard/      # HTML dashboard generation
├── integrations/   # Adapts output from external tools
├── modules/        # Recon, online/offline workflows, and other features
├── validators/     # Checks supported secret types
├── audit_log.py    # Audit trail and integrity checks
├── report.py       # Markdown and HTML reports
├── scope.py        # Engagement scope enforcement
└── cli.py          # Command-line interface
```

## Documentation

- [`docs/authorization.md`](docs/authorization.md) — scope signatures and authorization checks.
- [`docs/risk_model.md`](docs/risk_model.md) — risk factors and scoring.
- [`docs/secret_validation.md`](docs/secret_validation.md) — secret validation behavior and limits.
- [`docs/attack_path_verification.md`](docs/attack_path_verification.md) — how to interpret possible attack paths.
- [`docs/external_tools.md`](docs/external_tools.md) — installing and using external tools.
- [`docs/kerberoasting.md`](docs/kerberoasting.md) — authorized offline Active Directory auditing.

## Responsible use

CredAudit is intended for defensive security work and authorized assessments. Get written permission, define the approved targets and methods, and follow the relevant engagement or bug bounty policy. Stop testing if it risks disrupting a service or locking accounts.

## License

MIT License. See [`LICENSE`](LICENSE).
