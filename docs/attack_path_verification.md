# Attack-path verification

`core/correlation.py` has always been explicit that a "chain" is
co-occurring evidence, not a demonstrated path:
`_combined_status()` gives a whole chain `"confirmed"` only if every
finding feeding it was itself directly observed; otherwise it's a mix
status, and the README has always called that a hypothesis, not proof.

## What this adds, and what it doesn't

`attack_paths/verification.py` adds one thing: **per-link** detail on
top of that existing aggregate status, plus a concrete, actionable next
step for each link that isn't yet confirmed.

It does **not** add automated exploitation, exploit chaining, or any
new way to "prove" a finding beyond what this platform already proves
elsewhere. That's a deliberate line, not an oversight:

- Automated exploit-chaining/exploitation code is out of scope for this
  project, full stop, regardless of engagement authorization — writing
  code that uses a finding to gain access is a fundamentally different
  thing to build than code that detects, scores, and reports findings.
- Even setting that line aside: actually testing a credential or a
  network exposure means taking a live action against a target system.
  This project already has exactly-scoped, exactly-logged,
  human-confirmed ways to do that — `modules/online.py` for
  credentials (mandatory interactive confirmation, see `GEMINI.md`),
  live secret validation for secrets (`docs/secret_validation.md`,
  itself scoped to calling an issuer's own API, never a target), and
  manual/nuclei-based checks for service exposure. A silent
  "auto-verify this attack path" feature would either duplicate those
  safeguards badly or bypass them entirely. Neither is acceptable.

## What a `PathVerification` actually tells you

For each finding that makes up a path:

- **Corroborated** (`Evidence.status == "confirmed"`): directly
  observed — a live credential test that succeeded
  (`integrations/hydra.py`), or a live-validated secret
  (`validators/`). Nothing further to do for that link.
- **Not corroborated**: everything else. The result includes exactly
  which authorized, already-existing mechanism in this project would
  turn it into a directly-observed fact:

  | Finding category | What would confirm it |
  |---|---|
  | Secret Exposure | `credaudit analyze-secrets --validate-secrets` (or `run --validate-secrets`) |
  | Credential Exposure | `credaudit run --modules online` against this exact asset (requires scope + interactive confirmation) |
  | Network/Service Exposure | A direct, authorized nuclei run or manual banner/version check against this exact asset |

A path's overall status is one of `fully_corroborated`,
`partially_corroborated`, or `hypothesis_only` — derived purely from
how many of its links are corroborated, with no inference of its own.

```python
from credaudit.attack_paths import verification as pv

result = pv.verify_path(path, evidence_by_id)
print(result.summary)
# "Partially corroborated: 1/2 finding(s) directly confirmed;
#  1 remain unconfirmed hypotheses (see per-link detail)."
for step in result.outstanding_steps:
    print("To confirm:", step)
```

This is wired into `core/pipeline.run_pipeline()` automatically —
every `AttackPath.verification` gets populated, and `report.py` renders
the summary and outstanding steps under each path in both the Markdown
and HTML reports.

## Why this is still useful despite not auto-exploiting anything

The honest answer to "can you prove this chain is exploitable" used to
be a single aggregate status with no actionable detail. Now it's: here's
exactly which link is unproven, and here's the specific, already-governed
action that would prove it, under the same authorization and
confirmation discipline the rest of this project already requires.
That's the gap worth closing — turning "we can't automatically verify
everything" into "here's precisely what's left and how to close it,"
rather than pretending the gap doesn't exist or quietly automating
around the safeguards that make closing it responsible in the first
place.
