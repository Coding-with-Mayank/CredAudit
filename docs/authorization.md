# Authorization model

CredAudit has always refused to run outside an authorized scope: every
module checks the target, the module name, and the engagement date
window before doing anything (`credaudit/scope.py`). This document
covers the part that's new — cryptographic signing — and is upfront
about exactly what it does and doesn't prove.

## The gap this closes

A scope file has always had an `authorized_by` field, e.g.
`authorized_by: "Jane Doe, CISO — signed SOW #4521"`. That's a
free-text string, and software can't verify it — anyone with write
access to the scope file can type anything there. The enforced checks
(targets, module list, date window) don't depend on that string being
true, but nothing previously stopped someone from editing
`authorized_by`, or the targets list itself, without the edit being
detectable.

## What signing adds

An engagement owner (a CISO, engagement lead, whoever your process
designates) holds an Ed25519 private key. The scope file carries a
`signature` field: a signature over the file's own content. Anyone
running CredAudit can verify that signature before the engagement is
allowed to proceed.

```bash
# One-time: generate a keypair for whoever approves engagements
python -m credaudit.cli keygen --out-prefix engagement-owner
# -> engagement-owner_private.pem (keep secret), engagement-owner_public.pem (safe to share)

# Sign a scope file after it's been reviewed/approved
python -m credaudit.cli sign-scope --scope scope/acme.yaml \
  --private-key engagement-owner_private.pem

# Run with the public key supplied separately -- NOT read from the scope file
python -m credaudit.cli run --scope scope/acme.yaml \
  --trusted-key engagement-owner_public.pem --modules recon --out ./out
```

Add `require_signature: true` to a scope file and CredAudit refuses to
run it at all without a valid signature — fail closed, not a warning.

## Two trust levels — this is the part not to gloss over

**`external_trusted_key`** (pass `--trusted-key` / `trusted_public_key`):
the verifier's public key comes from somewhere the scope file's own
author can't edit — a key file in your own controlled repo, a CI
secret, wherever your org already keeps trusted key material. This is
the mode that proves something real: the scope file's content hasn't
changed since a *specific, externally-known* private key signed it.

**`embedded_key_self_signed`** (`sign-scope --public-key ...`, no
`--trusted-key` at run time): the public key is embedded in the scope
file itself. Verifying against it only proves the file hasn't changed
since it was signed with *some* Ed25519 key — it does **not** prove
that key belongs to a legitimate approver, since an attacker who can
edit the scope file can just as easily replace the embedded key and
re-sign with a key of their own. This mode exists for convenience and
testing, not for real assurance. `Scope.verification_trust_level`
reports which mode was actually used, and every report includes it, so
it's never silently glossed over in a client-facing deliverable.

## What this still does not prove — stated plainly

Even in `external_trusted_key` mode, signature verification proves the
scope file's *content* hasn't changed since a holder of the trusted
private key signed it. It does **not** prove that signer was actually
authorized, by your organization's real process, to approve this
specific engagement. That's a governance question — who's allowed to
hold that private key, and under what process they use it — and no
software can answer it from inside a YAML file, signed or not. Signing
closes the "anyone can type free text" gap; it doesn't replace your
approval process.

## Scope enforcement's own limitation

Separately from signing: scope checks happen in CredAudit's own Python
code, before every external-tool invocation. This guarantees
CredAudit's own code won't act outside scope. It can't guarantee that
an external binary it invokes (hydra, hashcat, nuclei, ...) will never,
through some bug or flag misuse, touch something outside that boundary.
Checking every target against scope before every subprocess call is
the strongest control CredAudit can offer from outside a compiled
third-party tool — not an absolute guarantee about that tool's own
behavior.

## Audit-log signing is the same pattern, applied to the audit trail

`AuditLog.finalize(private_key_pem=...)` signs a final manifest (entry
count + last hash) the same way, so that *truncating* the audit log —
not just editing an entry — is detectable. See the audit-model section
of the README and `credaudit verify` for the mechanics. The same
external-vs-embedded-key distinction applies there too.
