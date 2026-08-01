"""Command-line entrypoint.

    python -m credaudit.cli run --scope scope/my-engagement.yaml --modules recon --out ./out

    python -m credaudit.cli run --scope scope/my-engagement.yaml --modules offline \
        --hash-file hashes.txt --wordlist wordlist.txt --hash-mode ntlm --out ./out

    python -m credaudit.cli run --scope scope/my-engagement.yaml --modules online \
        --target-group production --protocol rdp --userlist users.txt \
        --passwordlist wordlists/passwords-standard.txt --out ./out

    python -m credaudit.cli analyze-js --file main.js --source https://acme.example/main.js \
        --out out/js-intel/main.json

    python -m credaudit.cli run --scope scope/my-engagement.yaml --modules recon \
        --js-intel out/js-intel/main.json --summary --out ./out

    python -m credaudit.cli hash-types
    python -m credaudit.cli generate-wordlist --seed AcmeCorp --out wordlists/acme-custom.txt
    python -m credaudit.cli verify --log out/<engagement_id>/audit_log.jsonl

The online module is driven from this CLI now -- but every safety check
is identical to before: scope.check_module, scope.check_target, and
scope.require_interactive_confirmation all still run inside run_spray
itself, not in this file, so there is no code path that skips them.
"Automated" here means "not hand-written Python each time," not
"unattended" -- those are different things, on purpose.

The risk engine, JS intelligence, and attack graph are all pure
interpretation of evidence already collected: they read data, they don't
generate new live traffic and they never decide to run another module on
your behalf. --summary (if you have ANTHROPIC_API_KEY set) asks an LLM to
turn already-collected findings into draft prose -- it does not feed
back into any further action either.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .audit_log import AuditLog
from .modules import js_intel, recon, risk_engine
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

    run_p.add_argument("--hash-file", help="[offline] path to hash export")
    run_p.add_argument("--wordlist", help="[offline] path to password wordlist")
    run_p.add_argument("--hash-mode", help="[offline] preset name (see `hash-types`) or raw hashcat -m number")

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

    run_p.add_argument("--js-intel", action="append", default=[],
                        help="Path to a JSON file from `analyze-js` (repeatable) to fold "
                             "into the report and attack graph")
    run_p.add_argument("--summary", action="store_true",
                        help="Generate a draft executive summary via your ANTHROPIC_API_KEY "
                             "(best-effort: skipped with a warning if unavailable)")

    verify_p = sub.add_parser("verify", help="Verify an audit log's hash chain is intact")
    verify_p.add_argument("--log", required=True, help="Path to audit_log.jsonl")

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


def _generate_wordlist(args: argparse.Namespace) -> None:
    count = write_candidates(
        args.seed, args.out,
        include_years=not args.no_years,
        include_leet=not args.no_leet,
        max_candidates=args.max,
    )
    print(f"Wrote {count} candidates to {args.out}")


def _verify(args: argparse.Namespace) -> None:
    log = AuditLog(args.log)
    if log.verify_chain():
        print(f"OK: {args.log} \u2014 chain intact, no entries altered or removed.")
    else:
        print(f"FAILED: {args.log} \u2014 chain is broken. Treat this log as untrusted.")
        raise SystemExit(1)


def _run(args: argparse.Namespace) -> None:
    try:
        scope = Scope.load(args.scope)
    except ScopeViolation as e:
        print(f"[SCOPE VIOLATION] {e}")
        raise SystemExit(1)

    out_dir = Path(args.out) / scope.engagement_id
    audit_log_path = out_dir / "audit_log.jsonl"
    audit_log = AuditLog(audit_log_path)
    audit_log.record("cli", "engagement_start", {"scope_sha256": scope.source_sha256})

    modules = [m.strip() for m in args.modules.split(",") if m.strip()]
    recon_findings = None
    offline_result = None
    online_summaries = []
    risk_assessments = []

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
                # scope + target + interactive-confirmation checks all happen
                # inside run_spray itself -- see modules/online.py
                log_path = run_spray(scope, target, cfg, audit_log, out_dir / "online")
                online_summaries.append(
                    summarize_log(log_path, accounts_tested=len(usernames), backend=args.backend)
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
            )
            audit_log.record("cli", "executive_summary_generated", {})
        except LLMSummaryError as e:
            print(f"[SUMMARY SKIPPED] {e}")

    audit_log.record("cli", "engagement_end", {})

    md_path = build_report(
        scope, out_dir, recon_findings=recon_findings,
        offline_result=offline_result, online_summary=online_summaries or None,
        risk_assessments=risk_assessments or None, js_intel_results=js_intel_results or None,
        executive_summary=executive_summary,
    )
    html_path = build_html_report(
        scope, out_dir, audit_log_path, recon_findings=recon_findings,
        offline_result=offline_result, online_summary=online_summaries or None,
        risk_assessments=risk_assessments or None, js_intel_results=js_intel_results or None,
        executive_summary=executive_summary,
    )
    print(f"Done. Report written to {md_path} and {html_path}")


if __name__ == "__main__":
    main()
