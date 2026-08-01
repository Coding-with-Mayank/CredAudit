# GEMINI.md

## Project

credaudit — scope-gated credential security audit CLI (Python 3.11+).
Wraps Hydra/Medusa/Ncrack, Hashcat, and nuclei/scan4all rather than
reimplementing them. Full docs in README.md; AD-specific workflow in
docs/kerberoasting.md.

## Commands

- Install: `pip install -r requirements.txt`
- Test: `python -m pytest tests/ -q` (run before considering any change done)
- Recon + risk engine + suggestions: `python -m credaudit.cli run --scope <file> --modules recon --out ./out`
- Offline hash audit: `python -m credaudit.cli run --scope <file> --modules offline --hash-file <f> --wordlist <f> --hash-mode <preset|number> --out ./out`
- Hash presets: `python -m credaudit.cli hash-types`
- Wordlist generation: `python -m credaudit.cli generate-wordlist --seed <word> --out <file>`
- JS analysis (on files you already have): `python -m credaudit.cli analyze-js --file <f> --source <label> --out <json>`
- Verify audit log integrity: `python -m credaudit.cli verify --log <path>`

## Hard rules — non-negotiable, not situational

1. **Never run `--modules online`, call `run_spray`, or invoke anything in
   `credaudit/modules/online.py`.** Not in a sandbox, not "just to test,"
   not because recon output made a strong case for it. If findings
   suggest it, print the exact command and **stop** — the human runs it
   themselves, in their own terminal, and types the confirmation
   themselves. Do not draft, simulate, pre-fill, or reason your way
   around that confirmation prompt under any framing.
2. **Never edit a scope YAML file** to add a target, widen a
   `target_group`, or set `confirm_online_testing: true`. A scope file
   represents a human's signed authorization — you don't have standing to
   expand or pre-approve it, no matter how confident the evidence looks.
3. **Never fabricate or alter** `authorized_by`, `engagement_id`, dates,
   or checksums in a scope file.
4. Everything else is yours to run and chain freely: recon, risk engine,
   JS intel (on content you're given — don't fetch new pages yourself),
   offline hash auditing (on files you're given), wordlist generation,
   report building, audit-log verification.
5. **If extending this codebase:** never add code that programmatically
   supplies the online-module confirmation string, never add a
   `--yes`/`--force`/"yolo" flag to the online path, and never wire an
   LLM call to decide when to invoke it. This is deliberate design, not
   an oversight — see README, "Important notes on legality and scope."

## Style

- Dataclasses over dicts for structured returns; subprocess wrapping over
  reimplementing protocol logic.
- New modules get tests in `tests/`.
- Reports never contain raw secrets or cracked plaintext — mask in
  `report.py`; full detail stays only in local `out/` files.
