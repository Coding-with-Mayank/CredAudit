# Secret live-validation

`credaudit/analyzers/secrets.py` has always been pattern-based: a
string that matches `sk_live_...` or a 40-character base64-ish blob
next to `aws_secret_access_key` gets flagged. That's necessarily
noisy — a matched pattern tells you "this looks like a secret," not
"this secret still works." A rotated key sitting in old git history and
a key that's live in production today match the exact same regex.

## The gap this closes

`credaudit/validators/` adds exactly one capability: for secret types
with a known issuing provider, make a single, read-only,
non-destructive API call using the secret exactly as a legitimate
client would, and record whether the provider accepted it. This is the
same technique mainstream secret scanners (TruffleHog, gitleaks) call
"verified" detection — not a novel idea, just one this project didn't
have yet.

## What gets checked, and how

| Secret type | Check | Mechanism |
|---|---|---|
| `github_token` | `GET /user` | Bearer auth |
| `slack_token` | `auth.test` | Bearer auth |
| `stripe_api_key` | `GET /v1/balance` | Basic auth (key as username) |
| `sendgrid_api_key` | `GET /v3/scopes` | Bearer auth |
| `gcp_api_key` | Geocoding API lookup | query param (heuristic -- see below) |
| `aws_access_key` + `aws_secret_key` | `sts:GetCallerIdentity` | AWS SigV4 (hand-rolled signer, see `validators/aws_sigv4.py`) |
| `jwt` | Local `exp` claim check | **No network call** -- decodes the token's own payload |

Every provider check returns one of three states, not two:
`verified_active`, `verified_inactive`, or `unknown`. A timeout, a
non-standard HTTP status, or a response this module doesn't
specifically recognize becomes `unknown` — it's never silently
treated as either "safe" or "confirmed dangerous." Collapsing "we
don't know" into either bucket would be worse than not checking at
all.

The GCP check is explicitly heuristic: unlike the others, a Google API
key has no universal account-level identity endpoint, since it's
scoped to whichever specific APIs are enabled on its project. The
Geocoding API serves as a free-tier proxy, and the result flags when
that proxy can't distinguish "invalid key" from "valid key, just not
enabled for this particular API."

## What this deliberately does NOT check, and why

`private_key` and `database_connection_string` have no validator here,
on purpose. Checking either one for real would mean opening a live
session against whatever host the key/connection string points at —
that's testing a *target*, not querying an issuer's own account-level
API, and it's a materially different, more sensitive action than
calling GitHub's `/user` endpoint. This platform already has a module
for exactly that: `modules/online.py`, which has its own scope check,
target allowlist, rate limiting, and, critically, a mandatory
interactive confirmation before it runs. Adding a silent "quick check"
to the secret scanner would quietly route around that safeguard for
precisely the cases it exists to cover.

`generic_api_key`, `generic_secret`, and `bearer_token` also have no
validator: there's no fixed provider to call, by definition.

## How to use it

```bash
# One-off secret scan with live validation
credaudit analyze-secrets --path ./retrieved-configs --validate-secrets \
  --engagement-id ENG-1 --out out/secrets.json

# As part of a full engagement run
credaudit run --scope engagement.yaml --secret-scan ./retrieved-configs \
  --validate-secrets --validate-secrets-max 50 --out ./out
```

Off by default in both commands. Turning it on does two things a
person running a scan should know about before opting in:

1. It makes real outbound network requests — to the secret's own
   issuing provider only, never anywhere else, and the request is
   exactly the one a legitimate client makes to authenticate.
2. It sends the discovered secret value itself in that request, which
   is inherent to "check if this credential authenticates" — there's
   no way to check without presenting it.

`--validate-secrets-max` (default 25) caps how many distinct secrets
get checked over the network in one run, for two reasons: it avoids
turning a large scan into hundreds of outbound requests (politeness to
the providers), and it bounds how much of a corpus of discovered
secrets gets sent anywhere at all, even to their own issuers, without
the person running the scan explicitly raising that number.

## What a validated result changes

- `verified_active` -> the finding's `status` becomes `"confirmed"`
  (the same status `integrations/hydra.py` produces when it directly
  observes a working credential pair — a directly-observed fact, not a
  pattern match), confidence is raised to 1.0, and severity is
  recomputed at that confidence.
- `verified_inactive` -> severity is capped low. The finding is **not**
  removed: the exposure itself is still a real, observed fact worth a
  hygiene note (confirm the rotation process actually covered every
  place this leaked to), even though the immediate risk is now minimal.
- `unknown` -> no change to severity or status. The attempt and its
  inconclusive result are recorded in the finding's `extra` field for
  transparency — a validation attempt that didn't resolve either way is
  different from a validation that was never attempted, and the output
  reflects which one happened.

See `credaudit/validators/base.py` and `credaudit/validators/providers.py`
for the implementation, and `tests/test_live_validation.py` for the
full behavioral test suite (all mocked — the test suite makes no real
network calls, the same discipline as every other test in this project).
