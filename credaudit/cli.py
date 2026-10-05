"""Command-line entrypoint.

    python -m credaudit.cli run --scope scope/my-engagement.yaml --modules recon --out ./out

    python -m credaudit.cli run --scope scope/my-engagement.yaml --modules offline \
        --hash-file hashes.txt --wordlist wordlist.txt --hash-mode ntlm \
        --account-map hash_to_user.csv --check-breach --out ./out

    python -m credaudit.cli run --scope scope/my-engagement.yaml --modules online \
        --target-group production --protocol rdp --userlist users.txt \
        --passwordlist wordlists/passwords-standard.txt --out ./out

    python -m credaudit.cli run --scope scope/my-engagement.yaml --modules recon \
        --secret-scan ./retrieved-configs --credential-file manual-creds.txt \
        --js-intel out/js-intel/main.json --summary --out ./out

    python -m credaudit.cli analyze-js --file main.js --source https://acme.example/main.js \
        --out out/js-intel/main.json
    python -m credaudit.cli analyze-credentials --creds-file accounts.txt --check-breach --out out/creds.json
    python -m credaudit.cli analyze-secrets --path ./retrieved-configs --out out/secrets.json

    python -m credaudit.cli hash-types
    python -m credaudit.cli generate-wordlist --seed AcmeCorp --out wordlists/acme-custom.txt
    python -m credaudit.cli verify --log out/<engagement_id>/audit_log.jsonl

    python -m credaudit.cli keygen --out-prefix engagement-owner
    python -m credaudit.cli sign-scope --scope scope/my-engagement.yaml \
        --private-key engagement-owner_private.pem --public-key engagement-owner_public.pem
    python -m credaudit.cli run --scope scope/my-engagement.yaml \
        --trusted-key engagement-owner_public.pem --modules recon --out ./out

The online module is driven from this CLI now -- but every safety check
is identical to before: scope.check_module, scope.check_target,
scope.check_protocol, and scope.require_interactive_confirmation all
still run inside run_spray itself, not in this file, so there is no code
path that skips them. "Automated" here means "not hand-written Python
each time," not "unattended" -- those are different things, on purpose.

The risk engine, credential/secret analyzers, correlation engine,
attack-path builder, JS intelligence, and old attack graph are all pure
interpretation of evidence already collected: they read data, they don't
generate new live traffic, and they never decide to run another module
on your behalf. --summary (if you have ANTHROPIC_API_KEY set) asks an
LLM to turn already-collected findings into draft prose -- it does not
feed back into any further action either.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .analyzers import credentials as credential_analyzer
from .audit_log import AuditLog, verify_manifest
from .core import evidence as ev
from .core import pipeline as pipeline_mod
from .core.authorization import AuthorizationError
from .dashboard import build_dashboard
from .integrations import hashcat as hashcat_integration
from .modules import breach_check, js_intel, recon, risk_engine
from .modules.hash_presets import format_preset_table, resolve_hash_mode
from .modules.llm_summary import LLMSummaryError, generate_executive_summary
from .modules.offline import OfflineAuditError, run_offline_audit
from .modules.online import OnlineTestError, SprayConfig, run_spray, summarize_log
from .modules.recon import ReconError
from .modules.wordlist_gen import write_candidates
from .report import build_html_report, build_report
from .scope import Scope, ScopeViolation


def main() -> None:
    parser = argparse.ArgumentParser(prog="credaudit")
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="Run an engagement per its scope file")
    run_p.add_argument("--scope", required=True, help="Path to scope YAML file")
    run_p.add_argument("--modules", default="recon", help="Comma-separated: recon, online, offline")
    run_p.add_argument("--out", default="./out", help="Output directory")
    run_p.add_argument("--trusted-key", help="Path to an Ed25519 public key (PEM) to verify a "
                        "signed scope file against -- required for real signature assurance "
                        "rather than the weaker embedded-key mode. See docs/authorization.md.")

    run_p.add_argument("--hash-file", help="[offline] path to hash export")
    run_p.add_argument("--wordlist", help="[offline] path to password wordlist")
    run_p.add_argument("--hash-mode", help="[offline] preset name (see `hash-types`) or raw hashcat -m number")
    run_p.add_argument("--account-map", help="[offline] optional hash,account (or hash:account) mapping "
                        "file, for hash exports whose format doesn't carry usernames")

    run_p.add_argument("--target", help="[online] single target host/IP")
    run_p.add_argument("--target-group", help="[online] named group from scope's target_groups, instead of --target")
    run_p.add_argument("--protocol", help="[online] service, e.g. ssh, ftp, rdp")
    run_p.add_argument("--userlist", help="[online] path to username list, one per line")
    run_p.add_argument("--passwordlist", help="[online] path to password list, one per line")
    run_p.add_argument("--backend", default="hydra", choices=["hydra", "medusa", "ncrack"],
                        help="[online] which engine to drive (default: hydra)")
    run_p.add_argument("--tasks", type=int, default=None,
                        help="[online] parallel connections (default: scope's protocol_limits, else 1)")
    run_p.add_argument("--spray-delay", type=int, default=None,
                        help="[online] seconds between password passes "
                             "(default: scope's protocol_limits, else 300)")

    run_p.add_argument("--credential-file", help="Optional account:password list (one per line; e.g. "
                        "client-supplied test credentials) to run through native credential intelligence, "
                        "in addition to anything cracked by --modules offline")
    run_p.add_argument("--check-breach", action="store_true",
                        help="Check analyzed credentials against the HIBP Pwned Passwords API "
                             "(k-anonymity model; requires network access)")
    run_p.add_argument("--secret-scan", action="append", default=[],
                        help="File or directory of already-retrieved, authorized content to run "
                             "native secret detection over (repeatable)")
    run_p.add_argument("--validate-secrets", action="store_true",
                        help="For each detected secret with a known issuing provider (GitHub, Slack, "
                             "Stripe, SendGrid, Google, AWS), make ONE read-only 'who am I' call to that "
                             "provider's own API to check if it's still active (same technique TruffleHog/"
                             "gitleaks call 'verified'). Requires network access; sends the discovered secret "
                             "value to its own issuing provider only, never anywhere else. JWT expiry is "
                             "always checked locally regardless of this flag (no network call). "
                             "See docs/secret_validation.md.")
    run_p.add_argument("--validate-secrets-max", type=int, default=25,
                        help="Cap on how many distinct secrets --validate-secrets will check over the "
                             "network in one run (default: 25)")
    run_p.add_argument("--internal-only", action="store_true",
                        help="Score findings as NOT internet-facing (default assumes internet-facing, "
                             "the more conservative assumption for an external engagement)")
    run_p.add_argument("--sign-audit-key", help="Path to an Ed25519 private key to sign the final "
                        "audit-log manifest/checkpoint (optional -- an unsigned manifest is still "
                        "written and still detects truncation, just without a signer identity attached)")
    run_p.add_argument("--no-dashboard", action="store_true", help="Skip generating dashboard.html")

    run_p.add_argument("--js-intel", action="append", default=[],
                        help="Path to a JSON file from `analyze-js` (repeatable) to fold "
                             "into the report, attack graph, and secret/correlation pipeline")
    run_p.add_argument("--summary", action="store_true",
                        help="Generate a draft executive summary. Uses your ANTHROPIC_API_KEY for an "
                             "AI-polished narrative when the 'llm' extra and a key are both available "
                             "(pip install credaudit[llm]); otherwise falls back to a deterministic, "
                             "template-based summary of the same findings, so --summary always produces "
                             "something rather than requiring that setup.")

    verify_p = sub.add_parser("verify", help="Verify an audit log's hash chain (and, if present, its signed manifest)")
    verify_p.add_argument("--log", required=True, help="Path to audit_log.jsonl")
    verify_p.add_argument("--manifest", help="Path to the manifest (defaults to <log>_manifest.json if present)")
    verify_p.add_argument("--trusted-key", help="Public key (PEM) to verify the manifest's signature, if it has one")

    sub.add_parser("hash-types", help="List hash-mode presets for --hash-mode")

    wl_p = sub.add_parser("generate-wordlist", help="Build a target-specific candidate wordlist")
    wl_p.add_argument("--seed", action="append", required=True,
                       help="Seed word (repeatable), e.g. --seed AcmeCorp --seed AcmeWidget")
    wl_p.add_argument("--out", required=True, help="Output path for the generated wordlist")
    wl_p.add_argument("--max", type=int, default=5000, help="Max candidates to generate")
    wl_p.add_argument("--no-years", action="store_true", help="Skip year-suffix variants")
    wl_p.add_argument("--no-leet", action="store_true", help="Skip leetspeak variants")

    js_p = sub.add_parser("analyze-js", help="Extract endpoints/secrets/JWTs from JS you already retrieved")
    js_p.add_argument("--file", required=True, help="Path to a local JS file (content you already have)")
    js_p.add_argument("--source", default="", help="Label for where this JS came from, e.g. a URL")
    js_p.add_argument("--out", required=True, help="Output path for the JSON result")

    cred_p = sub.add_parser("analyze-credentials",
                             help="Native credential intelligence over an account/password list you already have")
    cred_p.add_argument("--creds-file", required=True,
                         help="account:password per line. Never logged or stored elsewhere by this tool; "
                              "plaintext is held only transiently to compute a hash/strength/reuse check.")
    cred_p.add_argument("--engagement-id", default="standalone", help="Engagement id to tag findings with")
    cred_p.add_argument("--asset", default="credential-analysis", help="Asset label for these findings")
    cred_p.add_argument("--check-breach", action="store_true",
                         help="Check each password against the HIBP Pwned Passwords API (requires network)")
    cred_p.add_argument("--internal-only", action="store_true", help="Score as NOT internet-facing")
    cred_p.add_argument("--out", required=True, help="Output path for JSON(L) evidence")

    sec_p = sub.add_parser("analyze-secrets", help="Native secret detection over authorized files/directories")
    sec_p.add_argument("--path", required=True, help="File or directory to scan")
    sec_p.add_argument("--engagement-id", default="standalone", help="Engagement id to tag findings with")
    sec_p.add_argument("--out", required=True, help="Output path for JSON(L) evidence")
    sec_p.add_argument("--validate-secrets", action="store_true",
                        help="Make one read-only 'who am I' call per secret to its own issuing provider "
                             "(GitHub/Slack/Stripe/SendGrid/Google/AWS) to check liveness. See docs/secret_validation.md.")
    sec_p.add_argument("--validate-secrets-max", type=int, default=25,
                        help="Cap on distinct secrets checked over the network (default: 25)")

    keygen_p = sub.add_parser("keygen", help="Generate an Ed25519 keypair for signing scope files / audit manifests")
    keygen_p.add_argument("--out-prefix", required=True,
                           help="Writes <prefix>_private.pem (keep secret) and <prefix>_public.pem (safe to share)")

    sign_p = sub.add_parser("sign-scope", help="Sign a scope YAML file with an Ed25519 private key")
    sign_p.add_argument("--scope", required=True, help="Scope YAML file to sign (edited in place)")
    sign_p.add_argument("--private-key", required=True, help="Path to the Ed25519 private key (PEM)")
    sign_p.add_argument("--public-key",
                         help="Optional: also embed this public key in the scope file itself. Convenient "
                              "for a self-contained file, but weaker -- see docs/authorization.md. For real "
                              "assurance, keep the public key out of the file and pass it at run time via "
                              "`run --trusted-key` instead.")

    serve_p = sub.add_parser("serve", help="Run the persistent findings REST API (requires: pip install credaudit[api])")
    serve_p.add_argument("--host", default="127.0.0.1")
    serve_p.add_argument("--port", type=int, default=8000)
    serve_p.add_argument("--db-url", default=None, help="Overrides CREDAUDIT_DATABASE_URL for this process")
    serve_p.add_argument("--reload", action="store_true", help="Auto-reload on code changes (development only)")

    user_p = sub.add_parser("create-user",
                             help="Create/update a user in the findings database (requires: pip install credaudit[api])")
    user_p.add_argument("--username", required=True)
    user_p.add_argument("--password", help="If omitted, prompted interactively (not echoed, not logged)")
    user_p.add_argument("--role", choices=["admin", "analyst", "viewer"], default="viewer")
    user_p.add_argument("--db-url", default=None)

    import_p = sub.add_parser("import-findings",
                               help="Import an evidence.jsonl into the findings database (requires: pip install credaudit[api])")
    import_p.add_argument("--evidence", required=True, help="Path to an evidence.jsonl produced by `run` or `analyze-*`")
    import_p.add_argument("--engagement-id", required=True)
    import_p.add_argument("--client-name", default="")
    import_p.add_argument("--db-url", default=None)

    sub.add_parser("doctor", help="Check which optional Python extras and external security tools are available")

    args = parser.parse_args()
    if args.command == "run":
        _run(args)
    elif args.command == "verify":
        _verify(args)
    elif args.command == "hash-types":
        print(format_preset_table())
    elif args.command == "generate-wordlist":
        _generate_wordlist(args)
    elif args.command == "analyze-js":
        _analyze_js(args)
    elif args.command == "analyze-credentials":
        _analyze_credentials(args)
    elif args.command == "analyze-secrets":
        _analyze_secrets(args)
    elif args.command == "keygen":
        _keygen(args)
    elif args.command == "sign-scope":
        _sign_scope(args)
    elif args.command == "serve":
        _serve(args)
    elif args.command == "create-user":
        _create_user(args)
    elif args.command == "import-findings":
        _import_findings(args)
    elif args.command == "doctor":
        _doctor()


def _analyze_js(args: argparse.Namespace) -> None:
    result = js_intel.analyze_js_file(args.file, source=args.source)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(js_intel.to_dict(result), indent=2))

    print(f"{len(result.endpoints)} endpoint(s), {len(result.secrets)} secret pattern(s) found"
          + (", GraphQL detected" if result.has_graphql else ""))
    for path, score in result.endpoints[:10]:
        print(f"  endpoint (score {score}): {path}")
    for s in result.secrets:
        print(f"  secret ({s.kind}): {s.masked}")
    print(f"Full result (unmasked) written to {out_path}")


def _load_manual_credentials(path, source_label: str = None) -> list:
    records = []
    for line in Path(path).read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        account, _, password = line.partition(":")
        records.append(
            credential_analyzer.CredentialRecord(account=account, password=password, source=source_label or str(path))
        )
    return records


def _make_breach_checker():
    def _check(password: str) -> bool:
        return breach_check.check_password(password).is_breached
    return _check


def _analyze_credentials(args: argparse.Namespace) -> None:
    records = _load_manual_credentials(args.creds_file)
    if not records:
        print(f"[ERROR] No 'account:password' records found in {args.creds_file}")
        raise SystemExit(1)

    breach_checker = _make_breach_checker() if args.check_breach else None
    findings = credential_analyzer.analyze_credentials(
        records, breach_checker=breach_checker, internet_facing=not args.internal_only,
    )
    ev.reset_finding_id_counter()
    evidence_list = credential_analyzer.findings_to_evidence(findings, args.engagement_id, asset=args.asset)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    ev.write_evidence_jsonl(evidence_list, out_path)

    print(f"Analyzed {len(records)} credential(s):")
    for f in sorted(findings, key=lambda x: x.risk.score, reverse=True):
        flags = []
        if f.default_credential:
            flags.append("default")
        if f.reused_with:
            flags.append(f"reused x{len(f.reused_with)}")
        if f.breach_exposure:
            flags.append("breached")
        if f.privileged:
            flags.append("privileged")
        print(f"  [{f.risk.severity:>8}] {f.account}: {f.strength}"
              f"{' (' + ', '.join(flags) + ')' if flags else ''} \u2014 risk {f.risk.score}")
    print(f"Evidence written to {out_path}")


def _analyze_secrets(args: argparse.Namespace) -> None:
    from .analyzers import secrets as secrets_analyzer

    target_path = Path(args.path)
    findings = secrets_analyzer.scan_directory(target_path) if target_path.is_dir() else secrets_analyzer.scan_file(target_path)

    live_results = None
    if args.validate_secrets and findings:
        from . import validators

        print(f"[VALIDATE-SECRETS] Checking up to {args.validate_secrets_max} secret(s) against their own "
              f"issuing providers (read-only identity calls only) ...")
        live_results = validators.validate_findings(findings, max_checks=args.validate_secrets_max)
        counts = validators.summarize(live_results)
        print(f"[VALIDATE-SECRETS] {counts.get('verified_active', 0)} active, "
              f"{counts.get('verified_inactive', 0)} inactive, {counts.get('unknown', 0)} inconclusive")

    ev.reset_finding_id_counter()
    evidence_list = secrets_analyzer.to_evidence(
        findings, args.engagement_id, asset=str(target_path), live_results=live_results,
    )

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    ev.write_evidence_jsonl(evidence_list, out_path)

    print(f"Found {len(findings)} potential secret(s) in {target_path}.")
    for e in evidence_list:
        print(f"  [{e.severity:>8}] {e.evidence}")
    print(f"Evidence written to {out_path}")


def _keygen(args: argparse.Namespace) -> None:
    from .core import authorization

    try:
        private_pem, public_pem = authorization.generate_keypair()
    except AuthorizationError as e:
        print(f"[ERROR] {e}")
        raise SystemExit(1)

    priv_path = Path(f"{args.out_prefix}_private.pem")
    pub_path = Path(f"{args.out_prefix}_public.pem")
    priv_path.parent.mkdir(parents=True, exist_ok=True)
    priv_path.write_bytes(private_pem)
    pub_path.write_bytes(public_pem)
    try:
        priv_path.chmod(0o600)
    except OSError:
        pass
    print(f"Wrote {priv_path} (keep this secret -- do not commit it) and {pub_path} (safe to share/commit).")


def _sign_scope(args: argparse.Namespace) -> None:
    import yaml

    from .core import authorization

    scope_path = Path(args.scope)
    data = yaml.safe_load(scope_path.read_text())
    data.pop("signature", None)

    if args.public_key:
        data["signer_public_key"] = Path(args.public_key).read_text()

    private_pem = Path(args.private_key).read_bytes()
    try:
        signature = authorization.sign_scope_data(data, private_pem)
    except AuthorizationError as e:
        print(f"[ERROR] {e}")
        raise SystemExit(1)

    data["signature"] = signature
    scope_path.write_text(yaml.safe_dump(data, sort_keys=False, default_flow_style=False))
    print(f"Signed {scope_path}.")
    if args.public_key:
        print("A public key was embedded in the file itself (self-contained but weaker trust mode --")
        print("see docs/authorization.md). For real assurance, verify at run time with a copy of the")
        print("public key kept OUTSIDE this file: `run --trusted-key <path-to-public-key.pem>`.")
    else:
        print("No public key was embedded. Verify at run time with:")
        print(f"  python -m credaudit.cli run --scope {scope_path} --trusted-key <path-to-public-key.pem> ...")


def _generate_wordlist(args: argparse.Namespace) -> None:
    count = write_candidates(
        args.seed, args.out,
        include_years=not args.no_years,
        include_leet=not args.no_leet,
        max_candidates=args.max,
    )
    print(f"Wrote {count} candidates to {args.out}")


def _verify(args: argparse.Namespace) -> None:
    trusted_key = Path(args.trusted_key).read_bytes() if args.trusted_key else None
    result = verify_manifest(args.log, manifest_path=args.manifest, trusted_public_key=trusted_key)

    print(f"Hash chain intact: {result['chain_valid']}")
    if result["manifest_found"]:
        print(f"Manifest found \u2014 entry count matches: {result['count_matches']}, "
              f"final hash matches: {result['hash_matches']}")
        if result["signature_valid"] is not None:
            print(f"Manifest signature valid: {result['signature_valid']}")
        elif trusted_key is None:
            print("(Manifest has no signature check performed \u2014 pass --trusted-key to verify one, if present.)")
    else:
        print("No manifest found alongside this log \u2014 in-chain tampering was checked, "
              "but truncation from the end of the log cannot be ruled out without one.")

    if result["ok"]:
        print(f"OK: {args.log} \u2014 no tampering or truncation detected.")
    else:
        print(f"FAILED: {args.log} \u2014 treat this log as untrusted.")
        raise SystemExit(1)


def _read_audit_entries(path) -> list:
    path = Path(path)
    entries = []
    if path.exists():
        for line in path.read_text().splitlines():
            if line.strip():
                entries.append(json.loads(line))
    return entries


def _run(args: argparse.Namespace) -> None:
    trusted_key = Path(args.trusted_key).read_bytes() if args.trusted_key else None
    try:
        scope = Scope.load(args.scope, trusted_public_key=trusted_key)
    except ScopeViolation as e:
        print(f"[SCOPE VIOLATION] {e}")
        raise SystemExit(1)

    if scope.cryptographically_verified:
        print(f"[AUTHZ] Scope signature verified (trust level: {scope.verification_trust_level}).")
    else:
        print("[AUTHZ] Scope file is not cryptographically signed \u2014 relying on the enforced "
              "targets/module/date checks and free-text authorized_by only. See docs/authorization.md.")

    out_dir = Path(args.out) / scope.engagement_id
    audit_log_path = out_dir / "audit_log.jsonl"
    audit_log = AuditLog(audit_log_path, engagement_id=scope.engagement_id)
    audit_log.record("cli", "engagement_start", {
        "scope_sha256": scope.source_sha256,
        "cryptographically_verified": scope.cryptographically_verified,
        "verification_trust_level": scope.verification_trust_level,
    })

    modules = [m.strip() for m in args.modules.split(",") if m.strip()]
    recon_findings = None
    offline_result = None
    online_summaries = []
    risk_assessments = []
    credential_records = list(_load_manual_credentials(args.credential_file)) if args.credential_file else []

    js_intel_results = []
    for path in args.js_intel:
        try:
            js_intel_results.append(js_intel.from_dict(json.loads(Path(path).read_text())))
        except (OSError, json.JSONDecodeError) as e:
            print(f"[WARN] Couldn't load --js-intel {path}: {e}")

    try:
        if "recon" in modules:
            recon_findings = recon.run_recon(scope, out_dir / "recon")
            risk_assessments = risk_engine.assess_all(recon_findings)

            if risk_assessments:
                print(f"Risk engine rated {len(risk_assessments)} finding(s):")
                for a in sorted(risk_assessments, key=lambda x: risk_engine.RISK_ORDER.index(x.risk_level), reverse=True):
                    print(f"  [{a.risk_level:>8}] {a.service} on {a.target}: {a.reasoning}")

            suggestions = recon.suggest_online_targets_with_risk(recon_findings)
            if suggestions:
                print(f"\nSuggested next steps for --modules online (highest risk first):")
                for s in suggestions:
                    print(f"  --target {s['target']} --protocol {s['protocol']}  "
                          f"[{s['risk_level']}] {s['reasoning']}")

        if "offline" in modules:
            if not (args.hash_file and args.wordlist and args.hash_mode):
                print("[OFFLINE ERROR] --hash-file, --wordlist, and --hash-mode are all required.")
                raise SystemExit(1)
            try:
                resolved_mode = resolve_hash_mode(args.hash_mode)
            except ValueError as e:
                print(f"[OFFLINE ERROR] {e}")
                raise SystemExit(1)
            offline_result = run_offline_audit(
                scope=scope,
                hash_file=Path(args.hash_file),
                wordlist=Path(args.wordlist),
                hash_mode=resolved_mode,
                audit_log=audit_log,
                out_dir=out_dir / "offline",
            )
            if offline_result.cracked_count > 0:
                try:
                    cracked_records = hashcat_integration.load_cracked_credentials(
                        hash_file=args.hash_file,
                        cracked_file=offline_result.out_file,
                        account_map_file=args.account_map,
                    )
                    credential_records.extend(cracked_records)
                except OSError as e:
                    print(f"[WARN] Couldn't join cracked passwords to accounts for credential "
                          f"intelligence: {e}")

        if "online" in modules:
            if not (args.protocol and args.userlist and args.passwordlist):
                print("[ONLINE ERROR] --protocol, --userlist, and --passwordlist are all required.")
                raise SystemExit(1)
            if not (args.target or args.target_group):
                print("[ONLINE ERROR] Provide either --target or --target-group.")
                raise SystemExit(1)

            targets = [args.target] if args.target else scope.resolve_group(args.target_group)
            limits = scope.get_protocol_limits(args.protocol)
            tasks = args.tasks if args.tasks is not None else limits["tasks"]
            delay = args.spray_delay if args.spray_delay is not None else limits["seconds_between_passwords"]

            usernames = [u for u in Path(args.userlist).read_text().splitlines() if u.strip()]
            passwords = [p for p in Path(args.passwordlist).read_text().splitlines() if p.strip()]

            for target in targets:
                cfg = SprayConfig(
                    protocol=args.protocol, usernames=usernames, passwords=passwords,
                    seconds_between_passwords=delay, tasks=tasks, backend=args.backend,
                )
                # scope + target + protocol + interactive-confirmation checks all
                # happen inside run_spray itself -- see modules/online.py
                log_path = run_spray(scope, target, cfg, audit_log, out_dir / "online")
                online_summaries.append(
                    summarize_log(
                        log_path, accounts_tested=len(usernames), backend=args.backend,
                        target=target, protocol=args.protocol,
                    )
                )

    except ScopeViolation as e:
        audit_log.record("cli", "scope_violation", {"error": str(e)})
        print(f"[SCOPE VIOLATION] {e}")
        raise SystemExit(1)
    except ReconError as e:
        audit_log.record("cli", "module_error", {"module": "recon", "error": str(e)})
        print(f"[RECON ERROR] {e}")
        raise SystemExit(1)
    except OfflineAuditError as e:
        audit_log.record("cli", "module_error", {"module": "offline", "error": str(e)})
        print(f"[OFFLINE ERROR] {e}")
        raise SystemExit(1)
    except OnlineTestError as e:
        audit_log.record("cli", "module_error", {"module": "online", "error": str(e)})
        print(f"[ONLINE ERROR] {e}")
        raise SystemExit(1)

    executive_summary = None
    if args.summary:
        try:
            executive_summary = generate_executive_summary(
                scope, recon_findings=recon_findings, risk_assessments=risk_assessments,
                offline_result=offline_result, online_summary=online_summaries or None,
                allow_fallback=True,
            )
            audit_log.record("cli", "executive_summary_generated", {
                "ai_generated": "no AI model was used" not in executive_summary,
            })
        except LLMSummaryError as e:  # pragma: no cover -- allow_fallback=True means this shouldn't normally raise
            print(f"[SUMMARY SKIPPED] {e}")

    if args.validate_secrets:
        print(f"[VALIDATE-SECRETS] Will make up to {args.validate_secrets_max} read-only API calls to "
              f"secrets' own issuing providers (GitHub/Slack/Stripe/SendGrid/Google/AWS) to check liveness.")
        audit_log.record("cli", "secret_validation_requested", {"max_checks": args.validate_secrets_max})

    breach_checker = _make_breach_checker() if args.check_breach else None
    pipeline_result = pipeline_mod.run_pipeline(
        scope,
        recon_findings=recon_findings,
        risk_assessments=risk_assessments or None,
        offline_result=offline_result,
        credential_records=credential_records or None,
        breach_checker=breach_checker,
        secret_scan_paths=args.secret_scan or None,
        js_intel_results=js_intel_results or None,
        online_summaries=online_summaries or None,
        internet_facing_default=not args.internal_only,
        validate_secrets=args.validate_secrets,
        live_validation_max_checks=args.validate_secrets_max,
    )

    if pipeline_result.live_validation_summary is not None:
        counts = pipeline_result.live_validation_summary
        print(f"[VALIDATE-SECRETS] checked {sum(counts.values())}: "
              f"{counts.get('verified_active', 0)} active, "
              f"{counts.get('verified_inactive', 0)} inactive, "
              f"{counts.get('unknown', 0)} inconclusive")
        audit_log.record("cli", "secret_validation_completed", counts)

    if pipeline_result.evidence:
        ev.write_evidence_jsonl(pipeline_result.evidence, out_dir / "evidence.jsonl")
        print(f"\nUnified evidence: {len(pipeline_result.evidence)} finding(s) across "
              f"{len({e.asset for e in pipeline_result.evidence})} asset(s).")
    if pipeline_result.correlations:
        print(f"Correlation engine identified {len(pipeline_result.correlations)} related-finding chain(s):")
        for c in pipeline_result.correlations:
            print(f"  [{c.status}] {c.explanation} (risk {c.combined_risk_score}, confidence {c.confidence:.0%})")

    audit_log.record("cli", "engagement_end", {})

    sign_key = Path(args.sign_audit_key).read_bytes() if args.sign_audit_key else None
    manifest = audit_log.finalize(private_key_pem=sign_key)

    md_path = build_report(
        scope, out_dir, recon_findings=recon_findings,
        offline_result=offline_result, online_summary=online_summaries or None,
        risk_assessments=risk_assessments or None, js_intel_results=js_intel_results or None,
        executive_summary=executive_summary,
        evidence_list=pipeline_result.evidence or None,
        correlations=pipeline_result.correlations,
        attack_paths=pipeline_result.attack_paths,
        credential_findings=pipeline_result.credential_findings or None,
        secret_findings=pipeline_result.secret_findings or None,
    )
    html_path = build_html_report(
        scope, out_dir, audit_log_path, recon_findings=recon_findings,
        offline_result=offline_result, online_summary=online_summaries or None,
        risk_assessments=risk_assessments or None, js_intel_results=js_intel_results or None,
        executive_summary=executive_summary,
        evidence_list=pipeline_result.evidence or None,
        correlations=pipeline_result.correlations,
        attack_paths=pipeline_result.attack_paths,
        credential_findings=pipeline_result.credential_findings or None,
        secret_findings=pipeline_result.secret_findings or None,
    )

    print(f"\nDone. Report written to {md_path} and {html_path}")

    if not args.no_dashboard:
        audit_entries = _read_audit_entries(audit_log_path)
        assets_tested = len({e.asset for e in pipeline_result.evidence}) if pipeline_result.evidence else 0
        dashboard_path = build_dashboard(
            scope, out_dir, evidence_list=pipeline_result.evidence,
            correlations=pipeline_result.correlations, attack_paths=pipeline_result.attack_paths,
            audit_entries=audit_entries, assets_tested=assets_tested,
        )
        print(f"Dashboard written to {dashboard_path}")

    signed_note = "signed" if "signature" in manifest else "unsigned -- pass --sign-audit-key to sign it"
    print(f"Audit manifest written to {audit_log._manifest_path()} ({signed_note})")


def _require_api_extra() -> None:
    try:
        import fastapi  # noqa: F401
        import sqlmodel  # noqa: F401
    except ImportError:
        print("This command needs the persistent-backend extra: pip install credaudit[api]")
        raise SystemExit(1)


def _serve(args: argparse.Namespace) -> None:
    _require_api_extra()
    import os

    if args.db_url:
        os.environ["CREDAUDIT_DATABASE_URL"] = args.db_url
    if not os.environ.get("CREDAUDIT_JWT_SECRET"):
        print("CREDAUDIT_JWT_SECRET is not set. Generate one and export it first, e.g.:")
        print("  export CREDAUDIT_JWT_SECRET=$(python -c 'import secrets; print(secrets.token_hex(32))')")
        raise SystemExit(1)

    import uvicorn

    from .api.app import create_app

    print(f"Starting CredAudit findings API on http://{args.host}:{args.port} "
          f"(interactive docs at /docs). First run? Create an admin with "
          f"`credaudit create-user --username <you> --role admin` before logging in.")
    uvicorn.run(create_app(), host=args.host, port=args.port, reload=args.reload)


def _create_user(args: argparse.Namespace) -> None:
    _require_api_extra()
    import getpass

    from sqlmodel import Session, select

    from .api.db import Role, User, get_engine, init_db
    from .api.security import hash_password

    engine = get_engine(args.db_url)
    init_db(engine)

    password = args.password or getpass.getpass(f"Password for '{args.username}' (not echoed): ")
    if not password:
        print("A non-empty password is required.")
        raise SystemExit(1)

    with Session(engine) as session:
        existing = session.exec(select(User).where(User.username == args.username)).first()
        if existing:
            existing.hashed_password = hash_password(password)
            existing.role = Role(args.role)
            existing.disabled = False
            session.add(existing)
            session.commit()
            print(f"Updated existing user '{args.username}' (role={args.role}).")
        else:
            user = User(username=args.username, hashed_password=hash_password(password), role=Role(args.role))
            session.add(user)
            session.commit()
            print(f"Created user '{args.username}' (role={args.role}).")


def _import_findings(args: argparse.Namespace) -> None:
    _require_api_extra()
    from sqlmodel import Session

    from .api import ingest
    from .api.db import get_engine, init_db

    engine = get_engine(args.db_url)
    init_db(engine)

    with Session(engine) as session:
        result = ingest.import_evidence_jsonl(session, args.engagement_id, args.evidence, args.client_name)
    print(
        f"Imported {result['imported']} new finding(s) into engagement '{args.engagement_id}'; "
        f"{result['skipped_existing']} already present and left untouched (their workflow status, "
        f"if any, was not overwritten)."
    )


_DOCTOR_EXTERNAL_TOOLS = {
    "hydra": ("online credential testing", "integrations.hydra"),
    "medusa": ("online credential testing (hydra alternative)", "integrations.hydra"),
    "ncrack": ("online credential testing (hydra alternative)", "integrations.hydra"),
    "hashcat": ("offline hash cracking", "modules.offline"),
    "john": ("offline hash cracking (hashcat alternative)", "modules.offline"),
    "nuclei": ("template-based vulnerability scanning", "integrations.nuclei"),
}
_DOCTOR_VERSION_FLAGS = {
    "hydra": "-h", "medusa": "-h", "ncrack": "-V",
    "hashcat": "--version", "john": "", "nuclei": "-version",
}


def _tool_version_line(tool: str, path: str) -> str:
    import subprocess

    try:
        flag = _DOCTOR_VERSION_FLAGS.get(tool, "--version")
        cmd = [path] + ([flag] if flag else [])
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        text = (result.stdout or result.stderr or "").strip()
        return text.splitlines()[0][:70] if text else ""
    except Exception:
        return ""


def _doctor() -> None:
    import shutil

    print("CredAudit environment check")
    print("=" * 40)
    print("\nCore package: OK (pyyaml, requests, cryptography, zxcvbn)")

    print("\nOptional Python extras:")
    for module_name, extra, purpose in [
        ("anthropic", "llm", "AI-polished executive summaries (`run --summary`)"),
        ("fastapi", "api", "persistent findings REST API (`credaudit serve`)"),
        ("sqlmodel", "api", "persistent findings REST API (`credaudit serve`)"),
        ("jwt", "api", "persistent findings REST API (JWT auth)"),
        ("bcrypt", "api", "persistent findings REST API (password hashing)"),
    ]:
        try:
            __import__(module_name)
            line = "available"
        except ImportError:
            line = f"MISSING -- pip install credaudit[{extra}]"
        print(f"  {module_name:<12} {line:<38} ({purpose})")

    print("\nExternal security tools (never bundled into this package -- see docs/external_tools.md):")
    any_missing = False
    for tool, (purpose, module) in _DOCTOR_EXTERNAL_TOOLS.items():
        path = shutil.which(tool)
        if path:
            version = _tool_version_line(tool, path)
            suffix = f" ({version})" if version else ""
            print(f"  {tool:<8} found at {path}{suffix}")
        else:
            any_missing = True
            print(f"  {tool:<8} NOT FOUND -- needed by {module} for: {purpose}")

    if any_missing:
        print(
            "\nInstall missing tools via your OS package manager (e.g. `apt install hydra hashcat nuclei` on "
            "Debian/Kali, `brew install hydra hashcat nuclei` on macOS), or build/run the bundled Dockerfile "
            "(`docker build -t credaudit .`), which ships all of them preinstalled on a Kali Linux base image. "
            "See docs/external_tools.md for exact per-OS commands and why these aren't vendored into the "
            "Python package itself."
        )
    else:
        print("\nAll checked external tools were found on PATH.")


if __name__ == "__main__":
    main()
