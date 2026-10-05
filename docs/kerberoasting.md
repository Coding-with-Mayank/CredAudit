# Kerberoasting & ASREPRoast with credaudit

This is a two-stage workflow, and credaudit is deliberately involved in
only the second stage. It's worth being explicit about where the line
sits.

## What these are

**Kerberoasting**: any authenticated domain user can request a Kerberos
service ticket (TGS) for any account with a registered SPN. Part of
that ticket is encrypted with a hash derived from the service account's
password. Once you have the ticket, cracking it is a purely offline
problem — no further contact with the domain controller needed. Weak
service-account passwords are the usual finding here, and service
accounts are disproportionately likely to carry old, never-rotated,
weak passwords precisely because nobody logs in with them by hand.

**ASREPRoast**: accounts with Kerberos pre-authentication disabled
return an AS-REP that's crackable the same way, and you don't even
need valid credentials to request it — just the username.

## Stage 1: getting the hash (not this tool)

Extracting the ticket data happens against the live domain, under
whatever your engagement's rules of engagement already say about AD
enumeration. This is standard, already-public AD pentest tooling your
engagement has presumably already approved, most commonly:

- **Impacket's `GetUserSPNs.py`** for Kerberoasting
- **Impacket's `GetNPUsers.py`** for ASREPRoast
- **Rubeus** if you're operating from a Windows host

That step is intentionally outside credaudit's scope: it's live-target
enumeration, not credential brute-forcing, and it's already well
documented by Impacket's own project. Both tools write output directly
in hashcat's expected format.

## Stage 2: auditing the hash (this tool)

From the moment you have the hash file, you're testing password
strength against data you already extracted under your existing
authorization — no further live traffic. This is exactly what the
offline module is for:

```bash
# Classic Kerberoasting (RC4, etype 23)
python -m credaudit.cli run --scope scope/my-engagement.yaml --modules offline \
  --hash-file kerberoast_hashes.txt \
  --wordlist wordlists/passwords-standard.txt \
  --hash-mode kerberoast \
  --out ./out

# AES-enabled SPNs -- use the matching etype instead
python -m credaudit.cli run --scope scope/my-engagement.yaml --modules offline \
  --hash-file kerberoast_hashes.txt \
  --wordlist wordlists/passwords-standard.txt \
  --hash-mode kerberoast-aes256 \
  --out ./out

# ASREPRoast
python -m credaudit.cli run --scope scope/my-engagement.yaml --modules offline \
  --hash-file asrep_hashes.txt \
  --wordlist wordlists/passwords-standard.txt \
  --hash-mode asreproast \
  --out ./out
```

Run `python -m credaudit.cli hash-types` any time to see the exact
verified hashcat mode number behind each preset.

## Reading the results

The report shows a cracked/total ratio and a proportion chart, never
the plaintext itself. But the raw percentage understates what actually
matters here: a single cracked account with high privilege (domain
admin, anything with DCSync rights, a service account that's secretly a
member of a privileged group) is a far bigger finding than the same
percentage spread across low-privilege accounts. Cross-reference
cracked accounts — from the raw `cracked.txt`, handled per your
engagement's data-handling policy — against what each account can
actually do before writing up severity. credaudit reports the numbers;
the privilege analysis is on you.

## Scope, specifically for this technique

An SPN scan or AS-REP sweep touches every account in the domain by
nature, not just a subset. Before running the extraction step, make
sure your scope file's `targets` and `allowed_modules` actually reflect
"the domain" (or the specific OUs in scope) rather than a narrower host
list left over from other testing. The offline module will happily
audit whatever hash file you hand it, but the authorization for *how
you got that file* is a decision made before credaudit ever runs.
