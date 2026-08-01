# credaudit

A scope-gated orchestration framework for authorized credential security
assessments — password spraying, offline hash audits, and recon — built
for professional pentest engagements and bug bounty work.

**This project does not reimplement brute-force or hash-cracking engines.**
Those problems are already solved extremely well by mature, widely-used
tools (Hydra, Medusa, Hashcat, John the Ripper, nuclei). `credaudit` wraps
them. What it adds is the part that's usually missing from a pentester's
toolbox: a hard gate that stops any module from touching anything outside
a signed scope, lockout-safe pacing for live credential testing, and a
single tamper-evident report you can hand to a client or an auditor.

## Why this exists

Raw cracking speed is a solved problem. Scope discipline generally isn't —
most brute-force tooling will happily run against whatever target you type
in, with no memory of what you were actually authorized to touch. This
framework inverts that: **nothing runs until the scope gate says it's
allowed**, and every action is logged to a hash-chained audit trail before
it executes.

## Architecture

```
scope/engagement.yaml  →  Scope & authorization gate  →  recon (nuclei/scan4all)
                                                        →  online testing (hydra/medusa/ncrack, spray-paced)
                                                        →  offline audit (hashcat/john, your own hashes)
                                                        →  unified report + audit_log.jsonl
```

## Install

Python 3.11+. This project only orchestrates external binaries — install
whichever of these you need separately, they are not bundled:

- Recon: [nuclei](https://github.com/projectdiscovery/nuclei) (default) or
  [scan4all](https://github.com/GhostTroops/scan4all) (set `scanner_bin`)
- Online testing: [hydra](https://github.com/vanhauser-thc/thc-hydra),
  [medusa](https://github.com/jmk-foofus/medusa), or
  [ncrack](https://github.com/nmap/ncrack) — pick one with `--backend`
- Offline hash audit: [hashcat](https://hashcat.net/hashcat/) or John the Ripper

```bash
pip install -r requirements.txt
```

## Quickstart

1. Copy `scope/example-engagement.yaml`, fill in your real engagement
   details, and get it signed off (`authorized_by`) per your org's process.
2. Run recon against everything in scope — this also prints suggested
   `--target`/`--protocol` pairs for step 4, pulled from what it finds:

```bash
python -m credaudit.cli run --scope scope/my-engagement.yaml --modules recon --out ./out
```

3. Run an offline hash audit directly from the CLI (safe to automate — see
   "Automating the offline audit" below). Use a preset name instead of
   looking up hashcat mode numbers — run `python -m credaudit.cli hash-types`
   to see all of them (NTLM, bcrypt, sha512crypt, Kerberoasting, etc, every
   number checked against hashcat's own reference table):

```bash
python -m credaudit.cli run --scope scope/my-engagement.yaml --modules offline \
  --hash-file hashes.txt --wordlist wordlists/passwords-standard.txt \
  --hash-mode ntlm --out ./out
```

4. Run online credential spraying directly from the CLI — no hand-written
   Python needed. Choose your engine with `--backend` (`hydra`, `medusa`,
   or `ncrack`, whichever you have installed), and target either a single
   host or a named group from the scope file's `target_groups`:

```bash
python -m credaudit.cli run --scope scope/my-engagement.yaml --modules online \
  --target-group production --protocol rdp \
  --userlist users.txt --passwordlist wordlists/passwords-standard.txt \
  --backend hydra --out ./out
```

   Pacing (`--spray-delay`, `--tasks`) defaults to whatever the scope file's
   `protocol_limits` says for that protocol, so RDP can be paced more
   conservatively than SSH without you remembering to pass different flags
   each time — set `--spray-delay`/`--tasks` explicitly to override.

   This still runs the full scope gate every time — target check, module
   check, and an interactive "type the engagement id" confirmation unless
   `confirm_online_testing: true` is set in the scope file. Automated
   command, unchanged safety checks; those are different things.

5. Verify a report's audit trail hasn't been altered:

```bash
python -m credaudit.cli verify --log out/<engagement_id>/audit_log.jsonl
```

6. Every run produces `out/<engagement_id>/report.md`,
   `out/<engagement_id>/report.html` (the client/auditor-facing version,
   with proportion charts for each module's results — see `examples/` for
   a sample), and `out/<engagement_id>/audit_log.jsonl`.

## Interpretation, not just pass-through

Recon used to just report "N findings." It now interprets them:

**Risk engine** — every recon finding gets scored against a rule table
(old software versions, weak crypto, default creds, anonymous access,
exposed secrets, etc.), producing a risk level and *why*, not just a raw
count. You can also feed it facts you observed yourself:

```python
from credaudit.modules.risk_engine import assess_service

assess_service("203.0.113.10", "ssh", ["old_version", "password_auth_enabled"])
# -> RiskAssessment(risk_level="High",
#      reasoning="Outdated software version detected; Password authentication
#                  enabled; SSH is a common brute-force and credential-stuffing target.")
```

Running `--modules recon` now prints this table and folds it into both
reports automatically.

**Decision engine** — `recon.suggest_online_targets_with_risk()` sorts
suggested `--target`/`--protocol` pairs by risk instead of just listing
them in discovery order, so the highest-priority one is first. It's still
a suggestion list, exactly like before — nothing here calls the online
module for you.

**JavaScript intelligence** — `analyze-js` extracts endpoints, API keys,
AWS keys, JWTs, and GraphQL hints from JS you already retrieved during
authorized recon:

```bash
python -m credaudit.cli analyze-js --file main.js \
  --source https://acme.example/main.js --out out/js-intel/main.json
```

This is detection only. It never fetches anything itself and never tests
whether a found key actually works — the JSON output has full unmasked
values for your own triage (same pattern as `cracked.txt`); the report
only ever shows masked versions. Fold saved results into a report with
`run --js-intel out/js-intel/main.json` (repeatable).

**Attack graph** — when a report has both risk assessments and JS-intel
secrets, it builds a graph connecting real evidence into a hypothetical
escalation path — e.g. an exposed service linked to a leaked AWS key
linked to "potential access." Every path terminates at **"Manual
verification required"** — this module never tests, verifies, or
confirms anything past a credential leak. See `examples/` for what this
looks like rendered.

**Executive summary (optional)** — `--summary` asks an LLM to turn
already-collected findings into a short prose summary, using *your own*
`ANTHROPIC_API_KEY` (`pip install anthropic` first). It only summarizes
data you already have; it never triggers another module run, and its
output is always labeled as a draft to review, never inserted as final
text.

## Wordlists

`wordlists/fetch_wordlists.sh` pulls real, verified files from
[SecLists](https://github.com/danielmiessler/SecLists) — maintained under
OWASP, this is what working pentesters actually use, not a hand-rolled
list:

```bash
./wordlists/fetch_wordlists.sh standard    # 10k passwords, good default
./wordlists/fetch_wordlists.sh thorough    # 100k passwords
./wordlists/fetch_wordlists.sh deep        # 1,000,000 passwords (~8.7 MB)
./wordlists/fetch_wordlists.sh usernames   # common username shortlist
```

Files aren't bundled in the repo (some tiers are tens of megabytes) — the
script fetches only what you ask for, on demand.

For target-specific weak passwords (company name variants, product names,
year, common suffixes/leetspeak — the same mutation rules tools like CUPP
use), generate a custom list from public information about your
authorized target — either from the CLI:

```bash
python -m credaudit.cli generate-wordlist \
  --seed AcmeCorp --seed AcmeWidget --seed Acme2019 \
  --out wordlists/acme-custom.txt
```

or from Python:

```python
from credaudit.modules.wordlist_gen import write_candidates

write_candidates(
    seed_words=["AcmeCorp", "AcmeWidget", "Acme2019"],  # things you already
    out_path="wordlists/acme-custom.txt",                # know about the target
)
```

Combine both: run the generic SecLists tier first, then the custom list,
so common weak passwords and target-specific ones both get covered.

## Richer scope files

Beyond the required fields, a scope file can define:

- **`target_groups`** — named subsets of `targets` (e.g. `production`,
  `staging`) so `--target-group production` replaces typing hosts by hand.
  Every member is validated against the top-level `targets` list at load
  time — a group can organize scope, it can never extend it. Try to sneak
  an out-of-scope host into a group and the engagement refuses to start.
- **`protocol_limits`** — per-protocol pacing (`seconds_between_passwords`,
  `tasks`), since RDP and SSH lockout policies are rarely the same. Falls
  back to 300s / 1 task for anything not listed.
- **`emergency_contact`** — who to notify if something on the target side
  looks wrong mid-engagement.

See `scope/example-engagement.yaml` for a fully worked example of all of
these together.

## Automating the offline audit

`.github/workflows/scheduled-offline-audit.yml` runs the offline module on
a weekly schedule — across **every** scope file in `scope/*.yaml`, not
just one. A `discover` job scans the directory and builds a matrix
automatically; add a third engagement's scope file and the workflow
picks it up with zero edits. This is safe to automate because it never
sends live traffic anywhere — it only re-tests a hash export you already
control against a wordlist. Online spraying is deliberately **not**
included in CI: it sends live authentication attempts at a real target,
and the interactive confirmation `credaudit` requires for that is a
safeguard, not a rough edge to script around.

Each engagement gets its own hash-dump secret without any engagement
being able to see another's: create a GitHub **Environment** per
engagement (Settings → Environments) named after its `engagement_id`
(lowercased, underscores → hyphens — e.g. `ACME-PROD` becomes
`acme-prod`), and add that environment's own `AD_HASH_DUMP_URL` secret.
The workflow's matrix job selects `environment: ${{ matrix.environment }}`
per engagement, so `secrets.AD_HASH_DUMP_URL` resolves to the right value
for each one automatically. Until an environment's secret is set, that
engagement's job runs, finds nothing to fetch, and exits cleanly — it
won't fail the workflow. See the comments at the top of the workflow file
for the full checklist, including guidance for dumps too large for a URL
secret. Only the report and audit log are ever uploaded as artifacts —
never the cracked-password file itself.

`.github/workflows/tests.yml` runs the test suite on every push and PR.

## Docs

- [`docs/kerberoasting.md`](docs/kerberoasting.md) — using the offline
  module's Kerberoasting/ASREPRoast presets during an authorized AD
  engagement, and where credaudit's involvement starts and stops.

## Scope file

See `scope/example-engagement.yaml`. Required fields: `engagement_id`,
`client_name`, `authorized_by`, `start_date`, `end_date`, `targets`,
`allowed_modules`. The gate refuses to run outside the date window, against
any target not listed, or for any module not explicitly allowed — and for
the online module it additionally requires typing the engagement ID to
confirm, unless `confirm_online_testing: true` is pre-set (e.g. for CI).

## Important notes on legality and scope

- **Authorization, not code, is what makes credential testing legal.**
  This tool enforces a scope file; it cannot verify that the scope file
  itself is accurate. That's on you — get it in writing before you run
  anything against a live target.
- **Bug bounty programs frequently restrict automated brute-forcing even
  on in-scope assets.** Check the program's policy page specifically for
  language about credential stuffing, brute force, or rate limits before
  running the online module — being "in scope" for recon or a specific
  endpoint does not automatically mean brute-forcing logins is permitted.
- **Offline auditing only applies to hashes you already legitimately
  possess** (e.g. your own AD export, or a client-provided dump under
  contract). It doesn't help you obtain hashes you don't have.
- The spray pattern in `modules/online.py` tests one password across all
  accounts with a delay before moving to the next, specifically to avoid
  triggering account lockouts — tune `seconds_between_passwords` to the
  target's actual lockout policy, which you should know before testing.

## License

MIT — see `LICENSE`.
