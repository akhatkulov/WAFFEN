"""WAFFEN command-line interface.

WAFFEN is a WAF evaluation / bypass-research tool for targets you own or are
authorized to test. It searches for evasion *paths* (mutation chains + request
transforms) against a WAF so its coverage gaps can be found and fixed.

Subcommands:
  bypass       search for evasion chains against a target (or a mock WAF)
  eval         score WAF coverage + false-positive rate over a corpus
  dataset      build a labelled attack+benign training set
  analyze      analyze a collected dataset/log JSONL offline (no network)
  smuggle      experimental timing-based HTTP request-smuggling probes
  fingerprint  identify the WAF in front of a target
  kb-update    check/apply a KB update from a configured source
  mutators     list the built-in mutation library
  transforms   list the request-level transforms
  version      print version
"""
from __future__ import annotations

import argparse
import sys

from . import __version__
from . import ui
from .core.mock import make_mock_sender
from .core.oracle import Target
from .core import transforms as T
from .mutate import REGISTRY
from .kb import seeds as kb_seeds
from .report import results as report
from .engine import run_bypass
from .eval.coverage import run_eval
from .eval import corpus as eval_corpus
from .report import rules as rule_report


def _auth_kwargs(args):
    """Session/auth Target kwargs shared by every subcommand (--header/--cookie)."""
    return {"extra_headers": tuple(getattr(args, "header", None) or ()),
            "cookie": getattr(args, "cookie", "")}


def _gather_seeds(args):
    seeds = []
    use_corpus = getattr(args, "corpus", False)
    grammar_type = getattr(args, "grammar", "")

    if grammar_type:
        from .grammar import GRAMMARS
        grammar = GRAMMARS.get(grammar_type)
        if grammar:
            cls_name = {"sqli": "SQL Injection", "sql": "SQL Injection",
                        "xss": "XSS Injection", "ssti": "SSTI"}.get(grammar_type, grammar_type)
            for p in grammar.generate_n(50, max_depth=10, seed=42):
                seeds.append((cls_name, p))
            return seeds

    if args.payload:
        seeds.append((args.attack_class or "", args.payload))
    elif args.attack_class:
        for p in kb_seeds.seeds_for(args.attack_class, include_corpus=use_corpus):
            seeds.append((args.attack_class, p))
    if args.all_classes:
        for c in kb_seeds.classes():
            for p in kb_seeds.seeds_for(c, include_corpus=use_corpus):
                seeds.append((c, p))
    return seeds


def cmd_adaptive(args) -> int:
    if not args.target:
        print("[err] --target is required", file=sys.stderr)
        return 2
    from .search.adaptive import AdaptiveSearch, AdaptiveConfig
    target = Target(base_url=args.target, path=args.path, param=args.param, inject=args.inject,
                    method=args.method, timeout=args.timeout, tls_verify=args.tls_verify,
                    block_signature=args.block_signature, **_auth_kwargs(args))

    cfg = AdaptiveConfig(
        total_budget=args.budget, search_strategy=args.search_strategy,
        deepen_strategy=args.deepen_strategy, do_verify=args.verify,
        transport=args.transport, concurrency=args.concurrency,
    )

    bn = ui.banner(__version__)
    if bn:
        print(bn)
    print(ui.info("adaptive pipeline for ") + ui.bold(args.target))
    print(ui.gray(f"  budget={cfg.total_budget}  search={cfg.search_strategy}  deepen={cfg.deepen_strategy}"))
    print(ui.gray(f"  stages: learn → score-probe → gap-scan → search → deepen"))
    print(ui.rule())

    classes = [c.strip() for c in args.classes.split(",") if c.strip()] or ["sqli"]

    def ev(kind, **kw):
        if kind == "adaptive_start":
            print(ui.info("starting 5-stage adaptive pipeline"))
        elif kind.startswith("learn_"):
            print(f"  {ui.green('+')} learn: {kind} {kw}")
        elif kind.startswith("score_"):
            print(f"  {ui.green('+')} score: {kw}")
        elif kind.startswith("gaps_"):
            print(f"  {ui.green('+')} gaps: {kw}")
        elif kind == "searched":
            f_count = kw.get("findings", 0)
            v_count = kw.get("verified", 0)
            print(f"  {ui.green('+')} search: {f_count} findings ({v_count} verified)")
        elif kind == "deepened":
            f_count = kw.get("findings", 0)
            v_count = kw.get("verified", 0)
            print(f"  {ui.green('+')} deepen: {f_count} findings ({v_count} verified)")
        elif kind == "adaptive_done":
            print(ui.rule())
            print(f"  {ui.info('budget:   ')} {kw.get('budget_used', 0)} requests")
            print(f"  {ui.info('findings: ')} {kw.get('findings', 0)}")
            print(f"  {ui.info('verified: ')} {ui.bold(str(kw.get('verified', 0)))}")

    search = AdaptiveSearch(target, cfg, on_event=ev)
    result = search.run(classes)

    if result.verified_findings > 0:
        print(f"\n  {ui.green(ui.bold('BYPASS TOPILDI!'))}")
        for f in result.all_findings():
            if getattr(f, "verified", False):
                chain = getattr(f, "chain", [])
                print(f"    {ui.green('V')} {f.payload[:55]}  chain={chain}")
    elif result.total_findings > 0:
        print(f"\n  {ui.yellow('Through payloadlar bor — verify qilinmagan')}")
    else:
        print(f"\n  {ui.gray('Bypass topilmadi — WAF kuchli')}")

    if args.out:
        import json as _json
        from pathlib import Path as _P
        _P(args.out).write_text(_json.dumps(result.as_dict(), indent=2))
        print(ui.ok(f"adaptive report written to {args.out}"))
    return 0


def cmd_minimize(args) -> int:
    if not args.target:
        print("[err] --target is required", file=sys.stderr)
        return 2
    if not args.payload and not args.findings:
        print("[err] --payload or --findings required", file=sys.stderr)
        return 2

    from .search.minimize import PayloadMinimizer, _replay_chain
    from .core.oracle import Oracle as _O

    target = Target(base_url=args.target, path=args.path, param=args.param,
                    inject=args.inject, method=args.method,
                    timeout=args.timeout, tls_verify=args.tls_verify,
                    block_signature=args.block_signature, **_auth_kwargs(args))
    oracle = _O(target, transport=args.transport)
    minimizer = PayloadMinimizer(oracle)

    bn = ui.banner(__version__)
    if bn:
        print(bn)

    findings_to_minimize = []
    if args.payload:
        chain = [c.strip() for c in args.chain.split(",") if c.strip()] if args.chain else []
        findings_to_minimize.append({
            "payload": args.payload, "seed": args.seed or args.payload,
            "chain": chain,
        })
    elif args.findings:
        import json as _json
        from pathlib import Path as _P
        for line in _P(args.findings).read_text().strip().splitlines():
            if not line.strip():
                continue
            rec = _json.loads(line)
            findings_to_minimize.append({
                "payload": rec.get("payload", ""),
                "seed": rec.get("seed", ""),
                "chain": rec.get("chain", []),
            })

    print(ui.info("minimize ") + ui.bold(args.target)
          + ui.gray(f"   {len(findings_to_minimize)} finding(s)"))
    print(ui.rule())

    for i, f in enumerate(findings_to_minimize):
        chain = f["chain"]
        seed = f["seed"]
        payload = f["payload"]

        print(f"\n  {ui.bold(f'Finding {i+1}/{len(findings_to_minimize)}')}")
        print(f"  {ui.gray('Seed:    ')} {seed[:60]}")
        print(f"  {ui.gray('Chain:   ')} {' → '.join(chain) if chain else '(none)'}")
        print(f"  {ui.gray('Payload: ')} {payload[:60]}")

        result = minimizer.minimize(seed, chain, do_trim=not args.no_trim)

        chain_changed = result.minimized_chain != result.original_chain
        if chain_changed:
            print(f"  {ui.green('Minimized chain:')} {' → '.join(result.minimized_chain)}"
                  f" ({len(result.original_chain)} → {len(result.minimized_chain)} steps)")
        else:
            print(f"  {ui.gray('Chain:   already minimal')}")

        print(f"  {ui.gray('Payload: ')} {result.minimized_payload[:60]}")

        if result.trimmed_payload and result.trimmed_payload != result.minimized_payload:
            print(f"  {ui.green('Trimmed: ')} {result.trimmed_payload[:60]}"
                  f" ({len(result.minimized_payload)} → {len(result.trimmed_payload)} chars)")

        print(f"  {ui.gray(f'{result.requests_used} requests used')}")

    print(ui.rule())
    return 0


def cmd_diff(args) -> int:
    # Multi-WAF mode: --targets "Name1=URL1,Name2=URL2,..."
    if getattr(args, "targets", ""):
        return _cmd_diff_multi(args)

    # Legacy two-target mode: --waf + --origin
    if not args.waf:
        print("[err] --waf is required (or use --targets for multi-WAF)", file=sys.stderr)
        return 2
    if not args.origin:
        print("[err] --origin is required", file=sys.stderr)
        return 2

    from .recon.diff import DifferentialTester, write_diff_jsonl
    from .kb.seeds import resolve_class

    waf_path = args.waf_path or args.path
    origin_path = args.origin_path or args.path
    waf_target = Target(base_url=args.waf, path=waf_path, param=args.param,
                        inject=args.inject, method=args.method, timeout=args.timeout,
                        tls_verify=args.tls_verify, block_signature=args.block_signature,
                        **_auth_kwargs(args))
    origin_target = Target(base_url=args.origin, path=origin_path, param=args.param,
                           inject=args.inject, method=args.method, timeout=args.timeout,
                           tls_verify=args.tls_verify, block_signature=args.block_signature,
                           **_auth_kwargs(args))

    bn = ui.banner(__version__)
    if bn:
        print(bn)
    print(ui.info("differential  ") + ui.bold(args.waf) + ui.gray("  vs  ") + ui.bold(args.origin))
    print(ui.gray(f"  param={args.param} inject={args.inject} method={args.method}"))
    print(ui.rule())

    tester = DifferentialTester(waf_target, origin_target)

    if args.findings:
        print(ui.info(f"re-testing findings from {args.findings}"))
        report = tester.run_findings(args.findings)
    else:
        classes = [resolve_class(c.strip()) for c in (args.attack_class or "sqli").split(",")]
        print(ui.info(f"testing seeds for: {', '.join(classes)}"))
        report = tester.run_seeds(classes)

    # summary
    print()
    cats = [
        ("WAF_ONLY", report.waf_only, ui.red),
        ("BOTH_BLOCK", report.both_block, ui.gray),
        ("BOTH_PASS", report.both_pass, ui.green),
        ("APP_ONLY", report.app_only, ui.yellow),
        ("DESYNC", report.desync, ui.yellow),
    ]
    for name, probes, color in cats:
        cnt = str(len(probes))
        label = color(f"{name:12s}")
        suffix = ""
        if name == "BOTH_PASS" and probes:
            suffix = ui.bold("  ← potential bypass!")
        elif name == "DESYNC" and probes:
            suffix = ui.gray("  ← investigate")
        print(f"  {label} {cnt:>3}  payloads{suffix}")

    # detail for interesting categories
    for tag, probes in [("BOTH_PASS", report.both_pass), ("DESYNC", report.desync)]:
        if probes:
            print(f"\n  {ui.bold(tag)} details:")
            for p in probes[:20]:
                cls_tag = ui.gray(f"[{p.attack_class}]") if p.attack_class else ""
                print(f"    {p.payload[:50]:50s}  WAF={p.waf_code}  Origin={p.origin_code}  {cls_tag}")

    print(ui.rule())
    print(ui.gray(f"  {len(report.probes)} probes total"))

    if args.out:
        write_diff_jsonl(report, args.out)
        print(ui.ok(f"diff report written to {args.out}"))
    return 0


def _cmd_diff_multi(args) -> int:
    """Multi-WAF differential: compare 2+ WAFs against each other."""
    from .recon.diff import MultiWAFDifferential, write_multi_diff_jsonl
    from .kb.seeds import resolve_class

    # Parse --targets "Name1=URL1,Name2=URL2"
    targets_dict = {}
    for pair in args.targets.split(","):
        pair = pair.strip()
        if "=" not in pair:
            print(f"[err] invalid target format: {pair!r} — expected Name=URL", file=sys.stderr)
            return 2
        name, url = pair.split("=", 1)
        name, url = name.strip(), url.strip()
        targets_dict[name] = Target(
            base_url=url, path=args.path, param=args.param,
            inject=args.inject, method=args.method, timeout=args.timeout,
            tls_verify=args.tls_verify, block_signature=args.block_signature,
            **_auth_kwargs(args),
        )

    if len(targets_dict) < 2:
        print("[err] --targets requires at least 2 WAFs", file=sys.stderr)
        return 2

    bn = ui.banner(__version__)
    if bn:
        print(bn)
    names = list(targets_dict.keys())
    print(ui.info("multi-WAF differential  ") + ui.bold(" vs ".join(names)))
    print(ui.gray(f"  param={args.param} inject={args.inject} method={args.method}"))
    print(ui.rule())

    tester = MultiWAFDifferential(targets_dict)

    use_corpus = getattr(args, "corpus", False)
    classes = [resolve_class(c.strip()) for c in (args.attack_class or "sqli").split(",")]

    if use_corpus:
        print(ui.info(f"testing corpus for: {', '.join(classes)}"))
        report = tester.run_corpus(classes[0])
    else:
        print(ui.info(f"testing seeds for: {', '.join(classes)}"))
        report = tester.run_seeds(classes)

    # summary
    print()
    for label, count, color in [
        ("ALL BLOCK", report.all_blocked, ui.gray),
        ("ALL PASS", report.all_passed, ui.green),
        ("SPLIT", report.split, ui.red),
    ]:
        suffix = ""
        if label == "SPLIT" and count:
            suffix = ui.bold("  ← WAFs disagree — gold mine")
        elif label == "ALL PASS" and count:
            suffix = ui.gray("  ← none blocked (benign or all vulnerable)")
        print(f"  {color(f'{label:12s}')} {count:>4}  payloads{suffix}")

    # per-WAF miss breakdown
    if report.split:
        print(f"\n  {ui.bold('Split details')} (per-WAF misses):")
        misses = report.per_waf_misses()
        for name in names:
            others = [n for n in names if n != name]
            cnt = len(misses[name])
            if cnt:
                print(f"    {ui.red(name)} misses ({'+'.join(others)} block): "
                      f"{ui.bold(str(cnt))} payloads")
            else:
                print(f"    {ui.green(name)}: no unique misses")

        # show first few split payloads
        splits = report.split_details[:20]
        if splits:
            print(f"\n  {ui.bold('Sample split payloads')}:")
            for p in splits:
                blocked = ",".join(p.blocked_by)
                missed = ",".join(p.missed_by)
                cls_tag = ui.gray(f"[{p.attack_class}]") if p.attack_class else ""
                print(f"    {p.payload[:40]:40s}  "
                      f"blocked={blocked}  missed={ui.bold(missed)}  {cls_tag}")

    print(ui.rule())
    print(ui.gray(f"  {report.total_probes} probes × {len(names)} WAFs = "
                  f"{report.total_probes * len(names)} requests"))

    if args.out:
        write_multi_diff_jsonl(report, args.out)
        print(ui.ok(f"multi-WAF diff report written to {args.out}"))
    return 0


def cmd_daemon(args) -> int:
    if not args.target:
        print("[err] --target is required", file=sys.stderr)
        return 2

    from .daemon import WAFFENDaemon, DaemonConfig

    cfg = DaemonConfig(
        target_url=args.target,
        path=args.path,
        param=args.param,
        inject=args.inject,
        method=args.method,
        interval_hours=args.interval,
        attack_classes=[c.strip() for c in args.attack_class.split(",")
                        ] if args.attack_class else ["sqli"],
        max_requests_per_cycle=args.max_requests,
        profile_path=args.profile or "",
        webhook_url=args.webhook or "",
        block_signature=args.block_signature,
        timeout=args.timeout,
        tls_verify=args.tls_verify,
        transport=args.transport,
        extra_headers=tuple(args.header or []),
        cookie=args.cookie or "",
    )

    daemon = WAFFENDaemon(cfg)
    try:
        daemon.run(max_cycles=args.cycles)
    except KeyboardInterrupt:
        print("\n  [!] Daemon stopped by user")
    return 0


def cmd_watch(args) -> int:
    if not args.findings:
        print("[err] --findings is required", file=sys.stderr)
        return 2
    if not args.target:
        print("[err] --target is required", file=sys.stderr)
        return 2

    from .watch import load_findings, WatchRunner, write_watch_jsonl

    findings = load_findings(args.findings)
    if not findings:
        print(ui.warn("no findings loaded — is the JSONL empty?"))
        return 0

    target = Target(base_url=args.target, path=args.path, param=args.param,
                    inject=args.inject, method=args.method,
                    timeout=args.timeout, tls_verify=args.tls_verify,
                    block_signature=args.block_signature, **_auth_kwargs(args))

    bn = ui.banner(__version__)
    if bn:
        print(bn)
    print(ui.info("watch ") + ui.bold(args.target)
          + ui.gray(f"   {len(findings)} finding(s) from {args.findings}"))
    rounds_label = "infinite" if args.rounds == 0 and not args.once else str(1 if args.once else args.rounds)
    print(ui.gray(f"  interval={args.interval}s  rounds={rounds_label}"))
    print(ui.rule())

    runner = WatchRunner(target, transport=args.transport)

    def printer(report, diff, max_rounds):
        rounds_str = f"/{max_rounds}" if max_rounds else ""
        print(f"\n  {ui.bold(f'Round {report.round_num}{rounds_str}')} ({report.timestamp})")
        for e in report.entries:
            if e.current_verdict == "ALIVE":
                icon = ui.green("●")
                tag = ui.green("ALIVE  ")
            elif e.current_verdict == "BLOCKED":
                icon = ui.red("✗")
                tag = ui.red("BLOCKED")
            else:
                icon = ui.yellow("?")
                tag = ui.yellow("ERROR  ")

            delta = ""
            for nb in diff.newly_blocked:
                if nb.payload == e.payload and nb.transform == e.transform:
                    delta = ui.red(" ← was ALIVE")
                    break
            for na in diff.newly_alive:
                if na.payload == e.payload and na.transform == e.transform:
                    delta = ui.green(" ← was BLOCKED")
                    break

            cls = ui.gray(f"{e.attack_class:5}")
            payload_short = e.payload[:45]
            xform = ui.gray(f"(transform: {e.transform})")
            print(f"  {icon} {tag} {cls} {payload_short:47} {xform}{delta}")

        nb_count = len(diff.newly_blocked)
        na_count = len(diff.newly_alive)
        delta_parts = []
        if nb_count:
            delta_parts.append(ui.red(f"{nb_count} newly blocked"))
        if na_count:
            delta_parts.append(ui.green(f"{na_count} newly alive"))
        delta_str = f" ({', '.join(delta_parts)} since last)" if delta_parts else ""
        print(f"\n  Summary: {ui.green(str(report.alive))} alive / "
              f"{ui.red(str(report.blocked))} blocked / "
              f"{report.errored} errors{delta_str}")

    if args.once:
        reports = [runner.retest(findings, round_num=1)]
        diff = runner.diff_report(None, reports[0])
        printer(reports[0], diff, 1)
    else:
        reports = runner.run_loop(findings, interval=args.interval,
                                 max_rounds=args.rounds, printer=printer)

    if args.out and reports:
        write_watch_jsonl(reports, args.out)
        print(f"\n{ui.ok(f'watch report written to {args.out}')}")

    return 0


def cmd_profile(args) -> int:
    from .core.profile import TargetProfile
    try:
        p = TargetProfile.load(args.file)
    except FileNotFoundError:
        print(f"[err] profile not found: {args.file}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"[err] failed to load profile: {exc}", file=sys.stderr)
        return 1
    bn = ui.banner(__version__)
    if bn:
        print(bn)
    if args.json:
        import json
        print(json.dumps(p._to_dict(), indent=2, ensure_ascii=False, default=str))
    else:
        print(ui.info("Target profile: ") + ui.bold(args.file))
        print(ui.rule())
        print(p.summary())
    return 0


def cmd_auto(args) -> int:
    from .auto import run_auto, AutoConfig
    cfg = AutoConfig(
        url=args.url,
        path=args.path,
        param=args.param,
        yes=args.yes,
        out=args.out,
        timeout=args.timeout,
        transport=args.transport,
        tls_verify=args.tls_verify,
        cookie=args.cookie or "",
        headers=tuple(args.header or []),
        reconstruct=args.reconstruct,
        corpus=getattr(args, "corpus", False),
    )
    if getattr(args, "profile", ""):
        cfg.profile_path = args.profile
    return run_auto(cfg)


def cmd_bypass(args) -> int:
    seeds = _gather_seeds(args)
    if not seeds:
        print("[err] give --payload, --class <name>, or --all-classes", file=sys.stderr)
        return 2
    if not args.mock and not args.target:
        print("[err] --target is required (or --mock for offline engine testing)", file=sys.stderr)
        return 2

    target = Target(
        base_url=args.target or "mock://local",
        path=args.path, param=args.param, method=args.method,
        inject=args.inject, block_signature=args.block_signature, timeout=args.timeout, tls_verify=args.tls_verify,
        **_auth_kwargs(args),
    )
    sender = make_mock_sender(block_signature=args.block_signature) if args.mock else None
    transform_names = set(args.transforms.split(",")) if args.transforms else None

    def ev(kind, **kw):
        if args.verbose:
            print(f"    . {kind}: {kw}")

    b = ui.banner(__version__)
    if b:
        print(b)
    tgt = "MOCK" if args.mock else target.base_url
    print(ui.info("target    ") + ui.bold(tgt))
    print(ui.info("strategy  ") + ui.cyan(args.strategy)
          + ui.gray(f"   inject {target.inject} {target.method} {target.path} param={target.param!r}"))
    flags = []
    if args.calibrate: flags.append(ui.green("calibrate"))
    if args.learn: flags.append(ui.magenta("learn"))
    if args.verify and not args.mock: flags.append(ui.green("verify"))
    print(ui.info("plan      ") + ui.gray(
        f"seeds={len(seeds)}  transforms={sorted(transform_names) if transform_names else 'ALL'}  "
        f"budget={args.max_requests}/run")
        + (("  " + " ".join(flags)) if flags else ""))
    print(ui.rule())

    n_transforms = len(sorted(transform_names)) if transform_names else len(T.TRANSFORMS)
    total_max = len(seeds) * n_transforms * args.max_requests
    est_min = total_max * 1.5 / 60
    print(ui.gray(f"  estimate: {len(seeds)} seeds × {n_transforms} transforms × "
                  f"{args.max_requests} budget = {total_max} max requests (~{est_min:.0f} min)"))

    if getattr(args, "dry_run", False):
        print(ui.info("\n  --dry-run: exiting without sending requests"))
        return 0

    if args.canary:
        print(ui.gray(f"  (canary: re-probing a known-benign value every {args.canary_every} sends; "
                      "only active at --concurrency 1 — see --help)"))

    _scorer = None
    if getattr(args, "fitness", "default") == "gradient":
        from .search.gradient import GradientScorer
        _scorer = GradientScorer()
        print(ui.info("fitness   ") + ui.cyan("gradient") + ui.gray(" (10-feature calibratable scorer)"))

    runs = run_bypass(
        target, seeds,
        strategy=args.strategy, transform_names=transform_names, all_mutators=args.all_mutators,
        width=args.width, depth=args.depth,
        pop_size=args.pop_size, generations=args.generations, branch=args.branch,
        iterations=args.iterations, rollout_depth=args.rollout_depth, delay=args.delay,
        max_requests=args.max_requests, stop_on_first=args.stop_on_first,
        do_calibrate=args.calibrate, do_learn=args.learn, concurrency=args.concurrency,
        canary_payload=args.canary or None, canary_every=args.canary_every,
        do_verify=args.verify and not args.mock, sender=sender,
        transport=args.transport, on_event=ev, scorer=_scorer,
        cross_axis=getattr(args, "cross_axis", False),
        cross_axis_budget=getattr(args, "cross_axis_budget", 200),
        exploit_guided=getattr(args, "exploit_guided", False),
        save_policy=getattr(args, "save_policy", ""),
        load_policy=getattr(args, "load_policy", ""),
    )
    report.print_engine_summary(runs)
    if args.out:
        report.write_engine_jsonl(runs, args.out)
        print(f"\n[*] findings written to {args.out}")

    if args.rules or args.rules_out:
        # one rule per DISTINCT (class, payload): the same bypass is routinely
        # rediscovered under several transforms/runs, and nine copies of one rule
        # is noise for whoever has to act on it. Dedupe, keeping first occurrence.
        seen: set = set()
        suggestions = []
        for run in runs:
            for f in run.result.findings:
                if not f.verified:
                    continue
                key = (run.attack_class, f.payload)
                if key in seen:
                    continue
                seen.add(key)
                suggestions.append(rule_report.recommend_from_finding(f, endpoint=args.path))
        if suggestions:
            if args.rules:
                print("\n" + ui.rule("SUGGESTED WAF RULES"))
                print(rule_report.render_text(suggestions))
            if args.rules_out:
                from pathlib import Path as _P
                _P(args.rules_out).write_text(rule_report.render_markdown(suggestions))
                print(ui.ok(f"rule recommendations written to {args.rules_out}"))
        else:
            print("\n" + ui.gray("(no verified-exploitable findings — nothing to recommend a rule for)"))

    if args.nuclei:
        from .report import nuclei as nuclei_report
        # verified findings only, deduped like the rule suggestions above
        seen_n: set = set()
        pairs = []
        for run in runs:
            for f in run.result.findings:
                if not f.verified:
                    continue
                key = (run.attack_class, f.payload)
                if key in seen_n:
                    continue
                seen_n.add(key)
                if not getattr(f, "attack_class", ""):
                    f.attack_class = run.attack_class
                pairs.append((run.result.seed, f))
        if pairs:
            paths = nuclei_report.write_nuclei(pairs, target, args.nuclei)
            print(ui.ok(f"{len(paths)} Nuclei audit template(s) written to {args.nuclei}/"))
        else:
            print("\n" + ui.gray("(no verified-exploitable findings — no Nuclei templates emitted)"))

    if getattr(args, "sarif", ""):
        from .report import sarif as sarif_report
        all_findings = []
        for run in runs:
            for f in run.result.findings:
                if not getattr(f, "attack_class", ""):
                    f.attack_class = run.attack_class
                all_findings.append(f)
        sarif_report.write_sarif(all_findings, args.target or "mock://local", args.sarif)
        print(ui.ok(f"SARIF report written to {args.sarif}"))

    if getattr(args, "defend", ""):
        from .report import defend as defend_report
        d_findings = []
        d_seen: set = set()
        for run in runs:
            for f in run.result.findings:
                if not f.verified:
                    continue
                key = (run.attack_class, f.payload)
                if key in d_seen:
                    continue
                d_seen.add(key)
                if not getattr(f, "attack_class", ""):
                    f.attack_class = run.attack_class
                d_findings.append(f)
        if d_findings:
            engine = args.defend.strip().lower()
            if engine == "all":
                out_dir = args.defend_out or "waffen-rules"
                paths = defend_report.write_all_engines(
                    defend_report.generate_rules(d_findings), out_dir)
                print(ui.ok(f"defense rules written to {out_dir}/ ({len(paths)} files)"))
            else:
                rules = defend_report.generate_rules(d_findings, engine)
                rendered = defend_report.render_rules(rules, engine)
                if args.defend_out:
                    defend_report.write_rules(rules, args.defend_out, engine)
                    print(ui.ok(f"{len(rules)} {engine} defense rule(s) written to {args.defend_out}"))
                else:
                    print("\n" + ui.rule(f"DEFENSE RULES ({engine.upper()})"))
                    print(rendered)
        else:
            print("\n" + ui.gray("(no verified-exploitable findings — no defense rules generated)"))

    if getattr(args, "html_report", ""):
        from .report.professional import generate_html_report, write_html_report, ReportConfig
        all_f = []
        for run in runs:
            for f in run.result.findings:
                rec = f.as_dict()
                rec["request_transform"] = run.transform
                v = run.verifications.get(f.payload)
                if v is not None:
                    rec["verified_exploitable"] = getattr(v, "exploitable", None)
                    rec["verify_confidence"] = getattr(v, "confidence", None)
                    rec["verify_reason"] = getattr(v, "reason", None)
                all_f.append(rec)
        cfg = ReportConfig(target=args.target or "mock://local")
        html_str = generate_html_report(all_f, cfg)
        write_html_report(html_str, args.html_report)
        print(ui.ok(f"HTML report written to {args.html_report}"))

    if getattr(args, "csv", ""):
        from .report.csv_export import write_findings_csv
        csv_f = []
        for run in runs:
            for f in run.result.findings:
                rec = f.as_dict()
                rec["attack_class"] = run.attack_class
                rec["transform"] = run.transform
                v = run.verifications.get(f.payload)
                if v is not None:
                    rec["verified"] = getattr(v, "exploitable", False)
                csv_f.append(rec)
        write_findings_csv(csv_f, args.csv)
        print(ui.ok(f"CSV findings written to {args.csv}"))

    if getattr(args, "webhook", ""):
        verified_count = sum(
            1 for run in runs for f in run.result.findings
            if run.verifications.get(f.payload) and getattr(run.verifications[f.payload], "exploitable", False)
        )
        if verified_count:
            import urllib.request as _ureq
            import json as _json
            tgt = args.target or "mock"
            msg = f":gun: *WAFFEN* found *{verified_count}* verified bypass(es) on `{tgt}`"
            try:
                _ureq.urlopen(_ureq.Request(
                    args.webhook,
                    data=_json.dumps({"text": msg}).encode(),
                    headers={"Content-Type": "application/json"},
                ), timeout=10)
                print(ui.ok("Webhook notification sent"))
            except Exception as exc:
                print(f"  [warn] webhook failed: {exc}", file=sys.stderr)

    return 0


def cmd_benchmark(args) -> int:
    if args.list_profiles:
        from .eval.profiles import list_profiles
        print(ui.info("Pre-built WAF profiles:"))
        for p in list_profiles():
            print(f"  {ui.bold(p.key):18s} {p.name:25s} {ui.gray(p.note)}")
        return 0

    if args.compare:
        from .eval.benchmark import load_benchmark_json, compare
        a = load_benchmark_json(args.compare[0])
        b = load_benchmark_json(args.compare[1])
        bn = ui.banner(__version__)
        if bn:
            print(bn)
        print(ui.info("WAF Benchmark Comparison"))
        print(ui.gray(f"  A: {a.waf_name} ({a.target_url})"))
        print(ui.gray(f"  B: {b.waf_name} ({b.target_url})"))
        print(ui.rule())
        print(compare(a, b))
        return 0

    if args.profile:
        from .eval.profiles import get_profile
        prof = get_profile(args.profile)
        if not prof:
            print(f"[err] unknown profile '{args.profile}' — use --list-profiles", file=sys.stderr)
            return 2
        args.target = args.target or prof.default_url
        args.path = prof.path
        args.param = prof.param
        if prof.block_signature:
            args.block_signature = prof.block_signature
        args.waf_name = args.waf_name or prof.name

    if not args.target:
        print("[err] --target is required (or --profile)", file=sys.stderr)
        return 2

    from .eval.benchmark import WAFBenchmark, write_benchmark_json, write_html_report
    target = Target(base_url=args.target, path=args.path, param=args.param,
                    inject=args.inject, method=args.method, timeout=args.timeout,
                    tls_verify=args.tls_verify, block_signature=args.block_signature,
                    **_auth_kwargs(args))

    classes = [c.strip() for c in args.classes.split(",") if c.strip()] or None
    bmark = WAFBenchmark(target, corpus_classes=classes,
                         transport=args.transport, waf_name=args.waf_name)

    bn = ui.banner(__version__)
    if bn:
        print(bn)
    print(ui.info("WAF Benchmark: ") + ui.bold(args.target))
    if classes:
        print(ui.gray(f"  classes: {', '.join(classes)}"))
    print(ui.gray(f"  benign FP test: {'yes' if not args.no_benign else 'no'}"))
    print(ui.rule())

    def on_progress(cls_name, cs):
        icon = ui.green("●") if cs.detection_rate >= 0.9 else (
            ui.yellow("●") if cs.detection_rate >= 0.7 else ui.red("●"))
        print(f"  {icon} {cls_name:22s} {cs.detection_rate:6.1%} "
              f"({cs.passed} bypass / {cs.payloads_tested} tested)")

    score = bmark.run(include_benign=not args.no_benign, on_progress=on_progress)

    print(ui.rule())
    gc = {"A+": "green", "A": "green", "A-": "green",
          "B+": "yellow", "B": "yellow", "B-": "yellow"}.get(score.overall_grade, "red")
    grade_fn = getattr(ui, gc, ui.bold)
    print(f"  Grade: {grade_fn(ui.bold(score.overall_grade))}")
    print(f"  Detection: {score.detection_rate:.1%}  |  "
          f"FP: {score.false_positive_rate:.1%}  |  "
          f"Bypasses: {score.bypass_count}  |  "
          f"Avg: {score.avg_response_ms:.0f}ms  |  "
          f"{score.duration_s:.1f}s")

    if score.top_bypasses:
        print(ui.info("\n  Top bypasses:"))
        for i, (cls, payload) in enumerate(score.top_bypasses[:5], 1):
            print(f"    {i}. {cls}: {ui.bold(payload[:55])}")

    if args.out:
        write_benchmark_json(score, args.out)
        print(ui.ok(f"\n  Benchmark JSON: {args.out}"))
    if args.html:
        write_html_report(score, args.html)
        print(ui.ok(f"  Benchmark HTML: {args.html}"))

    return 0


def cmd_eval(args) -> int:
    if not args.mock and not args.target:
        print("[err] --target is required (or --mock)", file=sys.stderr)
        return 2
    # gather attack cases
    cases = []
    if args.corpus:
        from pathlib import Path as _P
        if not _P(args.corpus).exists():
            print(f"[err] corpus dir not found: {args.corpus}", file=sys.stderr)
            return 2
        by_cls = eval_corpus.harvest(args.corpus, max_per_class=args.max_per_class)
        for cls, payloads in by_cls.items():
            cases += [(cls, p) for p in payloads]
    else:
        classes = kb_seeds.classes() if args.all_classes else ([args.attack_class] if args.attack_class else [])
        if not classes:
            print("[err] give --class, --all-classes, or --corpus DIR", file=sys.stderr)
            return 2
        for c in classes:
            cases += [(c, p) for p in kb_seeds.seeds_for(c)]
    if not cases:
        print("[err] no attack cases gathered", file=sys.stderr)
        return 2

    benign = None
    if args.benign:
        from pathlib import Path as _P
        bf = _P(args.benign)
        if not bf.exists():
            print(f"[err] benign file not found: {args.benign}", file=sys.stderr)
            return 2
        benign = [l for l in bf.read_text(errors="replace").splitlines()
                  if l.strip() and not l.lstrip().startswith("#")]

    target = Target(base_url=args.target or "mock://local", path=args.path, param=args.param,
                    method=args.method, inject=args.inject, block_signature=args.block_signature,
                    timeout=args.timeout, tls_verify=args.tls_verify, **_auth_kwargs(args))
    sender = make_mock_sender(block_signature=args.block_signature) if args.mock else None

    calibration = None
    if args.calibrate:
        try:
            from .verify.calibrate import calibrate
            from .core.oracle import Oracle as _O
            from .kb.inject_map import resolve_base as _rb
            calibration = calibrate(_O(_rb(target), sender=sender, transport=args.transport))
            print(f"[*] calibrated: waf_detected={getattr(calibration,'waf_detected',None)} "
                  f"confidence={getattr(calibration,'confidence',None)}")
        except Exception as e:
            print(f"[warn] calibration failed: {e}", file=sys.stderr)

    b = ui.banner(__version__)
    if b:
        print(b)
    print(ui.info("target  ") + ui.bold("MOCK" if args.mock else target.base_url))
    print(ui.info("corpus  ") + ui.gray(
        f"cases={len(cases)}  benign={len(benign) if benign else 0}  "
        f"inject={target.inject} {target.path}  concurrency={args.concurrency}"))
    print(ui.rule())

    if args.concurrency > 1 and not args.mock:
        print(ui.warn(f"concurrency={args.concurrency}: real-time ban detection is off (the canary "
                      "runs only at --concurrency 1). Benign is measured first so FP stays valid, but "
                      "a ban during the attack phase could inflate coverage — use --concurrency 1 for an "
                      "unattended full-corpus run."))
    res = run_eval(target, cases, benign=benign, calibration=calibration, sender=sender,
                   concurrency=args.concurrency, delay=args.delay, transport=args.transport)

    o = res.overall
    print("\n" + ui.rule("COVERAGE") + ui.gray("   █ blocked = WAF caught it · ░ gap = reached origin"))
    for cls in sorted(res.per_class, key=lambda c: res.per_class[c].coverage):
        s = res.per_class[cls]
        print(f"  {ui.bar(s.coverage)} {s.coverage:5.1f}%  "
              + ui.gray(f"B={s.blocked:5d} T={s.through:5d} U={s.unresolved:4d} D={s.down:4d}  ")
              + ui.bold(cls))
    print("  " + ui.gray("─" * 54))
    print(f"  {ui.bar(o.coverage)} {ui.bold(f'{o.coverage:5.1f}%')}  "
          + ui.gray(f"B={o.blocked} T={o.through} U={o.unresolved} D={o.down}  ") + ui.bold("OVERALL"))
    if res.benign_total:
        line = f"false positives: {res.benign_blocked}/{res.benign_total} = {res.fp_rate:.1f}% (benign wrongly blocked)"
        print("\n" + (ui.ok(line) if res.fp_rate == 0 else ui.warn(line)))
    if args.out:
        import json as _json
        from pathlib import Path as _P
        _P(args.out).write_text(_json.dumps(res.as_dict(), indent=2))
        # also dump the coverage-gap payloads for review
        gaps = _P(args.out).with_suffix(".through.txt")
        with gaps.open("w") as f:
            for cls, samples in res.through_samples.items():
                for p in samples:
                    f.write(f"[{cls}] {p}\n")
        print(f"\n[*] wrote {args.out} and {gaps}")
    if args.html:
        from .report.html import write_eval_html
        write_eval_html(res, args.html, meta={
            "cases": len(cases), "inject": target.inject,
            "calibrated": "yes" if calibration else "no"})
        print("\n" + ui.ok(f"HTML report: {args.html}"))

    if args.rules or args.rules_out:
        suggestions = rule_report.recommend_from_eval(res, endpoint=args.path)
        if suggestions:
            if args.rules:
                print("\n" + ui.rule("SUGGESTED WAF RULES"))
                print(rule_report.render_text(suggestions))
            if args.rules_out:
                from pathlib import Path as _P
                _P(args.rules_out).write_text(rule_report.render_markdown(suggestions))
                print(ui.ok(f"rule recommendations written to {args.rules_out}"))
        else:
            print("\n" + ui.gray("(no coverage gaps — nothing to recommend a rule for)"))

    if args.find_cutoff and not args.mock:
        from .core.oracle import Oracle as _O
        from .core.transforms import find_inspection_cutoff
        print("\n" + ui.rule("BODY-INSPECTION CUTOFF") +
              ui.gray(f"  binary search, up to {args.cutoff_probes} probes"))
        cutoff_oracle = _O(target, sender=sender, calibration=calibration, transport=args.transport)
        cutoff = find_inspection_cutoff(cutoff_oracle, param="padding", probes=args.cutoff_probes)
        if cutoff is None:
            print(ui.gray("  no cutoff found within the probe budget (or the signature never got through)"))
        else:
            print(ui.ok(f"  measured cutoff: ~{cutoff} bytes") +
                  ui.gray(f"  ({cutoff_oracle.requests} requests)"))
    return 0


def cmd_dataset(args) -> int:
    from pathlib import Path as _P
    from .eval.dataset import build_dataset, stratified_split, write_jsonl, write_csv, class_balance
    if not args.mock and not args.target:
        print("[err] --target is required (or --mock)", file=sys.stderr)
        return 2
    # attack cases
    cases = []
    if args.corpus:
        if not _P(args.corpus).exists():
            print(f"[err] corpus dir not found: {args.corpus}", file=sys.stderr); return 2
        for cls, payloads in eval_corpus.harvest(args.corpus, max_per_class=args.max_per_class).items():
            cases += [(cls, p) for p in payloads]
    else:
        classes = kb_seeds.classes() if args.all_classes else ([args.attack_class] if args.attack_class else [])
        for c in classes:
            cases += [(c, p) for p in kb_seeds.seeds_for(c)]
    if not cases:
        print("[err] give --class, --all-classes, or --corpus DIR", file=sys.stderr); return 2
    benign = None
    if args.benign:
        bf = _P(args.benign)
        if not bf.exists():
            print(f"[err] benign file not found: {args.benign}", file=sys.stderr); return 2
        benign = [l for l in bf.read_text(errors="replace").splitlines()
                  if l.strip() and not l.lstrip().startswith("#")]

    target = Target(base_url=args.target or "mock://local", path=args.path, param=args.param,
                    method=args.method, inject=args.inject, block_signature=args.block_signature,
                    timeout=args.timeout, tls_verify=args.tls_verify, **_auth_kwargs(args))
    sender = make_mock_sender(block_signature=args.block_signature) if args.mock else None
    calibration = None
    if args.calibrate:
        try:
            from .verify.calibrate import calibrate
            from .core.oracle import Oracle as _O
            from .kb.inject_map import resolve_base as _rb
            calibration = calibrate(_O(_rb(target), sender=sender, transport=args.transport))
        except Exception as e:
            print(f"[warn] calibration failed: {e}", file=sys.stderr)

    b = ui.banner(__version__)
    if b: print(b)
    print(ui.info("dataset  ") + ui.gray(f"attack={len(cases)} benign={len(benign) if benign else 0} "
                                          f"target={'MOCK' if args.mock else target.base_url}"))
    if not benign:
        print(ui.warn("no --benign given: dataset has only malicious samples. A WAF trained on one "
                      "class can't learn a boundary — add a benign set (from an UN-banned source)."))
    print(ui.rule())

    if args.concurrency > 1 and not args.canary and not args.mock:
        print(ui.warn(f"concurrency={args.concurrency} with no --canary: ban detection is off. "
                      "Pass --canary <benign> (post-batch check at concurrency>1) or use --concurrency 1."))
    out = build_dataset(target, cases, benign=benign, calibration=calibration, sender=sender,
                        concurrency=args.concurrency, delay=args.delay, transport=args.transport,
                        canary_payload=args.canary or None, canary_every=args.canary_every)
    records, stats = out["records"], out["stats"]
    bal = class_balance(records)
    print(ui.info("records  ") + ui.bold(str(stats["kept"]))
          + ui.gray(f"  (malicious={stats['malicious']} benign={stats['benign']} "
                    f"dropped_down={stats['dropped_down']} dup={stats['dup']})"))
    ratio = bal.get("ratio_malicious_to_benign")
    if ratio is not None and ratio > 5:
        print(ui.warn(f"class imbalance {ratio:.1f}:1 — consider more benign or downsampling attacks"))

    base = args.out or "dataset"
    if args.split > 0:
        train, val = stratified_split(records, args.split)
        write_jsonl(train, f"{base}_train.jsonl"); write_jsonl(val, f"{base}_val.jsonl")
        write_csv(train, f"{base}_train.csv"); write_csv(val, f"{base}_val.csv")
        print("\n" + ui.ok(f"wrote {base}_train.(jsonl|csv) n={len(train)} · {base}_val.(jsonl|csv) n={len(val)}"))
    else:
        write_jsonl(records, f"{base}.jsonl"); write_csv(records, f"{base}.csv")
        print("\n" + ui.ok(f"wrote {base}.jsonl and {base}.csv  (n={len(records)})"))
    return 0


def cmd_calibrate(args) -> int:
    if not args.target:
        print("[err] --target is required", file=sys.stderr)
        return 2
    target = Target(base_url=args.target, path=args.path, param=args.param, inject=args.inject,
                    method=args.method, timeout=args.timeout, tls_verify=args.tls_verify,
                    block_signature=args.block_signature, **_auth_kwargs(args))

    from .core.oracle import Oracle as _O
    oracle = _O(target, transport=args.transport)

    bn = ui.banner(__version__)
    if bn:
        print(bn)

    if args.cluster:
        print(ui.info("response clustering for ") + ui.bold(args.target))
        print(ui.gray("  sending mixed probes to discover WAF response taxonomy..."))
        print(ui.rule())

        from .verify.cluster import ResponseClusterer
        clusterer = ResponseClusterer(oracle)
        profile = clusterer.run()

        print(ui.info(f"cluster analysis ({profile.total_probes} probes, k={profile.k}, "
                      f"silhouette={profile.silhouette:.2f}):\n"))
        for c in sorted(profile.clusters, key=lambda x: x.avg_status):
            color = {"PASS": ui.green, "BLOCK": ui.red, "CHALLENGE": ui.yellow,
                     "RATELIMIT": ui.yellow, "UNKNOWN": ui.gray}.get(c.label, ui.gray)
            print(f"  {color(f'{c.label:12s}')} (k={c.cluster_id}): "
                  f"status={c.avg_status:.0f}, ~{c.avg_size:.0f} bytes, "
                  f"{c.avg_time*1000:.0f}ms  [{c.size} samples]")
            if c.example_payloads:
                for ex in c.example_payloads[:2]:
                    print(f"    {ui.gray(ex[:50])}")

        if args.out:
            import json as _json
            from pathlib import Path as _P
            _P(args.out).write_text(_json.dumps(profile.as_dict(), indent=2, ensure_ascii=False))
            print(f"\n{ui.ok(f'cluster report written to {args.out}')}")
    else:
        print(ui.info("calibrating ") + ui.bold(args.target))
        print(ui.rule())

        from .verify.calibrate import calibrate
        cal = calibrate(oracle)
        if cal.waf_detected:
            print(f"  {ui.green('+')} WAF detected, confidence={cal.confidence:.0%}")
            print(f"  {ui.info('block codes:   ')} {sorted(cal.block_codes)}")
            print(f"  {ui.info('pass codes:    ')} {sorted(cal.pass_codes)}")
            print(f"  {ui.info('block size:    ')} {cal.block_size_band}")
            print(f"  {ui.info('block marker:  ')} {cal.block_marker[:60] or '(none)'}")
            print(f"  {ui.info('timing:        ')} {'reliable' if cal.timing_reliable else 'unreliable'}")
        else:
            print(f"  {ui.yellow('?')} no WAF detected (benign and attack responses indistinguishable)")
    return 0


def cmd_fingerprint(args) -> int:
    if not args.target:
        print("[err] --target is required", file=sys.stderr)
        return 2
    try:
        from .recon.fingerprint import fingerprint
    except Exception as e:
        print(f"[err] fingerprint module unavailable: {e}", file=sys.stderr)
        return 1
    target = Target(base_url=args.target, path=args.path, timeout=args.timeout, tls_verify=args.tls_verify,
                    block_signature=args.block_signature, **_auth_kwargs(args))
    guesses = fingerprint(target)
    bn = ui.banner(__version__)
    if bn:
        print(bn)
    if not guesses:
        print(ui.warn(f"no WAF signature matched for {args.target} (no WAF, or an unknown one)"))
        return 0
    print(ui.info("WAF fingerprint for ") + ui.bold(args.target))
    for i, g in enumerate(guesses):
        name = getattr(g, "name", "?")
        conf = getattr(g, "confidence", 0.0)
        padded = f"{name:30}"
        label = ui.bold(ui.cyan(padded)) if i == 0 else padded
        print(f"  {ui.bar(conf*100, width=12)} {conf:.2f}  {label} " + ui.gray(getattr(g, "evidence", "")))

    try:
        from .recon.fingerprint import recommend_plan
        plan = recommend_plan(guesses)
        print("\n" + ui.rule("SUGGESTED TEST PLAN") + ui.gray("  heuristic — not a guarantee"))
        print(ui.info("body limit      ") + ui.bold(f"~{plan['body_limit']} bytes"))
        if plan["suggested_mutators"]:
            print(ui.info("worth trying    ") + ui.gray(", ".join(plan["suggested_mutators"])))
        print(ui.gray("  " + plan["note"]))
    except Exception as exc:
        print(f"  [warn] test plan generation failed: {exc}", file=sys.stderr)
    return 0


def cmd_sequence(args) -> int:
    from .kb.sequences import all_sequences, get_sequence
    from .core.sequence import SequenceRunner

    if args.list_seqs:
        bn = ui.banner(__version__)
        if bn:
            print(bn)
        print(ui.info("built-in attack sequences"))
        print(ui.rule())
        for s in all_sequences():
            print(f"  {ui.bold(s.name):30s}  {s.description}")
            print(f"  {ui.gray(f'  {len(s.steps)} steps')}")
        return 0

    if not args.target:
        print("[err] --target is required", file=sys.stderr)
        return 2

    target = Target(base_url=args.target, path=args.path, timeout=args.timeout,
                    tls_verify=args.tls_verify,
                    block_signature=args.block_signature, **_auth_kwargs(args))

    bn = ui.banner(__version__)
    if bn:
        print(bn)

    seqs = []
    if args.run:
        s = get_sequence(args.run)
        if not s:
            print(f"[err] unknown sequence: {args.run}", file=sys.stderr)
            print(f"  available: {', '.join(s.name for s in all_sequences())}")
            return 2
        seqs = [s]
    elif args.run_all:
        seqs = all_sequences()
    else:
        print("[err] give --run <name>, --all, or --list", file=sys.stderr)
        return 2

    runner = SequenceRunner(target)
    payload = args.payload

    print(ui.info("sequence run for ") + ui.bold(args.target))
    print(ui.gray(f"  payload={payload!r}  sequences={len(seqs)}"))
    print(ui.rule())

    all_results = []
    for seq in seqs:
        result = runner.run(seq, payload)
        all_results.append(result)
        marker = ui.green("● THRU") if result.through else ui.red("✗ BLOCK")
        print(f"  {marker}  {ui.bold(seq.name):30s}  "
              f"{result.final_code}  {result.requests} req")
        for step in result.steps:
            tag = "→" if step.index < len(seq.steps) - 1 else "★"
            extr = ""
            if step.extracted:
                extr = ui.gray(f"  extracted: {list(step.extracted.keys())}")
            print(f"    {tag} step {step.index}: {step.code}{extr}")

    print(ui.rule())
    throughs = sum(1 for r in all_results if r.through)
    total = len(all_results)
    print(f"  {throughs}/{total} sequences passed WAF")

    if args.out:
        import json as _json
        from pathlib import Path as _P
        data = []
        for r in all_results:
            data.append({
                "sequence": r.sequence_name, "payload": r.payload,
                "verdict": r.verdict, "final_code": r.final_code,
                "requests": r.requests,
                "steps": [{"index": s.index, "code": s.code,
                           "extracted": s.extracted} for s in r.steps],
            })
        _P(args.out).write_text(_json.dumps(data, indent=2, ensure_ascii=False))
        print(ui.ok(f"sequence results written to {args.out}"))

    return 0


def cmd_fuzz(args) -> int:
    if not args.target:
        print("[err] --target is required", file=sys.stderr)
        return 2
    if not args.wordlist and not args.builtin and not args.corpus:
        print("[err] give --wordlist FILE, --builtin NAME, or --corpus CLASS", file=sys.stderr)
        return 2
    from .fuzz.engine import AsyncFuzzer, FuzzReport
    from .fuzz import wordlists

    target = Target(base_url=args.target, path=args.path, param=args.param,
                    inject=args.inject, method=args.method,
                    timeout=args.timeout, tls_verify=args.tls_verify,
                    block_signature=args.block_signature, **_auth_kwargs(args))

    if args.wordlist:
        with open(args.wordlist) as f:
            words = [line.strip() for line in f if line.strip()]
    elif args.builtin:
        gen = wordlists.BUILTINS.get(args.builtin)
        if not gen:
            print(f"[err] unknown builtin: {args.builtin}", file=sys.stderr)
            return 2
        words = gen()
    else:
        from .kb.corpus import corpus_for
        words = corpus_for(args.corpus)
        if not words:
            print(f"[err] no corpus for class: {args.corpus}", file=sys.stderr)
            return 2

    filter_codes = {int(c) for c in args.mc.split(",") if c.strip()} if args.mc else None
    hide_codes = {int(c) for c in args.fc.split(",") if c.strip()} if args.fc else None
    filter_size = args.ms if args.ms >= 0 else None
    hide_size = args.fs if args.fs >= 0 else None
    match_regex = args.mr or None

    bn = ui.banner(__version__)
    if bn:
        print(bn)
    print(ui.info("fuzz ") + ui.bold(args.target + args.path)
          + ui.gray(f"  param={args.param} inject={args.inject} threads={args.concurrency}"))
    print(ui.gray(f"  {len(words)} payloads"))
    print(ui.rule())

    counters = {"done": 0, "blocked": 0}
    lock = __import__("threading").Lock()

    def on_result(res):
        tag = ui.red(f"  {res.code}") if res.code >= 500 else ui.green(f"  {res.code}")
        print(f"{tag}  {res.size:>6}B  {res.time_ms:>6.0f}ms  {res.payload[:60]}")

    fuzzer = AsyncFuzzer(target, concurrency=args.concurrency,
                         timeout=args.timeout,
                         block_signature=args.block_signature)

    try:
        report = fuzzer.fuzz_wordlist(
            words, on_result=on_result,
            filter_codes=filter_codes, hide_codes=hide_codes,
            filter_size=filter_size, hide_size=hide_size,
            match_regex=match_regex,
        )
    except KeyboardInterrupt:
        fuzzer.stop()
        print(ui.warn("\n  Interrupted"))
        return 1

    print(ui.rule())
    parts = []
    if report.blocked:
        parts.append(ui.red(f"blocked={report.blocked}"))
    if report.passed:
        parts.append(ui.green(f"passed={report.passed}"))
    if report.errors:
        parts.append(ui.yellow(f"errors={report.errors}"))
    print(f"  [{report.total}/{len(words)}]  {' '.join(parts)}  |  "
          + ui.bold(f"{report.rps:.0f} req/s") + f"  |  {report.elapsed:.1f}s")

    if args.out:
        import json as _json
        from pathlib import Path as _P
        _P(args.out).write_text(_json.dumps(report.as_dict(), indent=2, ensure_ascii=False))
        print(ui.ok(f"results written to {args.out}"))

    return 0


def cmd_graphql(args) -> int:
    if not args.target:
        print("[err] --target is required", file=sys.stderr)
        return 2
    target = Target(base_url=args.target, path=args.path, timeout=args.timeout,
                    tls_verify=args.tls_verify, block_signature=args.block_signature,
                    **_auth_kwargs(args))
    bn = ui.banner(__version__)
    if bn:
        print(bn)
    print(ui.info("graphql for ") + ui.bold(args.target))
    print(ui.rule())

    if args.introspect:
        from .graphql.introspect import introspect, probe_introspection_bypass
        print(ui.info("introspection probe"))
        result = introspect(target)
        if result.success:
            print(f"  {ui.green('+')} schema exposed ({len(result.types)} types)")
            for t in result.types[:15]:
                print(f"      {t}")
            if len(result.types) > 15:
                print(f"      ... ({len(result.types)} total)")
        else:
            print(f"  {ui.yellow('?')} direct introspection blocked — trying bypasses")
            bypasses = probe_introspection_bypass(target)
            for bp in bypasses:
                icon = ui.green("+") if bp.success else ui.gray("-")
                print(f"  {icon} {bp.bypass_used}: {'EXPOSED' if bp.success else 'blocked'}")
        return 0

    payload = args.payload or "' OR 1=1--"
    from .graphql import attacks
    techniques = []
    if args.batch or args.all_techniques:
        print(ui.info("batch bypass"))
        r = attacks.batch_bypass(target, payload)
        techniques.append(r)
        icon = ui.red("BLOCKED") if r.waf_blocked else ui.green("PASSED")
        print(f"  {icon} batch: {r.code}")

    if args.alias_flood or args.all_techniques:
        n = args.alias_count
        print(ui.info(f"alias flood (n={n})"))
        r = attacks.alias_flood(target, payload, n=n)
        techniques.append(r)
        icon = ui.red("BLOCKED") if r.waf_blocked else ui.green("PASSED")
        print(f"  {icon} alias_flood: {r.code}")

    if args.directive or args.all_techniques:
        print(ui.info("directive injection"))
        r = attacks.directive_injection(target, payload)
        techniques.append(r)
        icon = ui.red("BLOCKED") if r.waf_blocked else ui.green("PASSED")
        print(f"  {icon} directive: {r.code}")

    if args.persisted or args.all_techniques:
        print(ui.info("persisted query"))
        r = attacks.persisted_query_bypass(target, payload)
        techniques.append(r)
        icon = ui.red("BLOCKED") if r.waf_blocked else ui.green("PASSED")
        print(f"  {icon} persisted: {r.code}")

    if args.field_leak or args.all_techniques:
        print(ui.info("field suggestion leak"))
        r = attacks.field_suggestion_leak(target)
        techniques.append(r)
        icon = ui.green("+") if "Did you mean" in r.body else ui.gray("-")
        print(f"  {icon} field_leak: {r.code}")

    if not techniques:
        print(ui.gray("  specify --introspect, --batch, --alias-flood, --directive, --persisted, --field-leak, or --all"))
        return 2

    print(ui.rule())
    passed = sum(1 for t in techniques if not t.waf_blocked)
    print(f"  {passed}/{len(techniques)} techniques passed WAF")
    return 0


def cmd_ws(args) -> int:
    if not args.target:
        print("[err] --target is required", file=sys.stderr)
        return 2
    target = Target(base_url=args.target, path=args.path or "/", timeout=args.timeout,
                    tls_verify=args.tls_verify, block_signature=args.block_signature,
                    extra_headers=tuple(args.header or ()))
    bn = ui.banner(__version__)
    if bn:
        print(bn)
    print(ui.info("websocket for ") + ui.bold(args.target))
    print(ui.rule())

    payload = args.payload or "' OR 1=1--"
    ws_path = args.ws_path
    from .ws import attacks as ws_attacks

    results = []
    if args.text or args.all_techniques:
        print(ui.info("text frame injection"))
        r = ws_attacks.ws_inject(target, payload, ws_path=ws_path)
        results.append(r)
        if not r.connected:
            print(f"  {ui.red('!')} connection failed")
        else:
            icon = ui.red("BLOCKED") if r.waf_blocked else ui.green("ALIVE")
            print(f"  {icon} text inject: conn_alive={r.connection_alive}")

    if args.binary or args.all_techniques:
        print(ui.info("binary frame injection"))
        r = ws_attacks.ws_binary_inject(target, payload, ws_path=ws_path)
        results.append(r)
        if r.connected:
            icon = ui.red("BLOCKED") if r.waf_blocked else ui.green("ALIVE")
            print(f"  {icon} binary inject: conn_alive={r.connection_alive}")
        else:
            print(f"  {ui.red('!')} connection failed")

    if args.fragment or args.all_techniques:
        print(ui.info("fragmented frame injection"))
        r = ws_attacks.ws_fragment_inject(target, payload, ws_path=ws_path)
        results.append(r)
        if r.connected:
            icon = ui.red("BLOCKED") if r.waf_blocked else ui.green("ALIVE")
            print(f"  {icon} fragment inject: conn_alive={r.connection_alive}")
        else:
            print(f"  {ui.red('!')} connection failed")

    if args.upgrade or args.all_techniques:
        print(ui.info("upgrade URL injection"))
        r = ws_attacks.ws_upgrade_inject(target, payload)
        results.append(r)
        icon = ui.red("BLOCKED") if r.waf_blocked else ui.green("PASSED")
        print(f"  {icon} upgrade inject: connected={r.connected}")

    if not results:
        print(ui.gray("  specify --text, --binary, --fragment, --upgrade, or --all"))
        return 2

    print(ui.rule())
    passed = sum(1 for r in results if not r.waf_blocked)
    print(f"  {passed}/{len(results)} techniques passed WAF")
    return 0


def cmd_rulemap(args) -> int:
    if not args.target:
        print("[err] --target is required", file=sys.stderr)
        return 2
    from .recon.rulemap import RuleMapper, write_rulemap_json
    target = Target(base_url=args.target, path=args.path, param=args.param,
                    inject=args.inject, method=args.method, timeout=args.timeout,
                    tls_verify=args.tls_verify, block_signature=args.block_signature,
                    **_auth_kwargs(args))
    bn = ui.banner(__version__)
    if bn:
        print(bn)
    print(ui.info("WAF rule map for ") + ui.bold(args.target))
    print(ui.gray("  reverse-engineering WAF rule set via black-box probing"))
    print(ui.rule())

    mapper = RuleMapper(target, sender=None)
    report = mapper.map_rules()

    print(f"  {ui.info('WAF type:        ')} {ui.bold(report.waf_type)}")
    if report.estimated_paranoia_level:
        print(f"  {ui.info('Paranoia level:  ')} {ui.bold(f'PL{report.estimated_paranoia_level}')}")
    print(f"  {ui.info('Rules active:    ')} {len(report.rules_active)}/{report.total_probes}")
    print(f"  {ui.info('Gaps (inactive): ')} {ui.bold(str(len(report.gaps)))}")

    print(f"\n  {ui.info('Category breakdown:')}")
    for cat in sorted(report.categories):
        info = report.categories[cat]
        pct = info["active"] / info["total"] * 100 if info["total"] else 0
        pl_parts = []
        for pl in sorted(info.get("by_pl", {})):
            pldata = info["by_pl"][pl]
            pl_pct = pldata["active"] / pldata["total"] * 100 if pldata["total"] else 0
            pl_parts.append(f"PL{pl}:{pl_pct:.0f}%")
        pl_str = " — " + " ".join(pl_parts) if pl_parts else ""
        bar_color = ui.green if pct > 80 else (ui.yellow if pct > 50 else ui.red)
        print(f"    {cat:12s} {info['active']:3d}/{info['total']:3d} "
              f"({bar_color(f'{pct:.0f}%')}){pl_str}")

    if report.gaps:
        print(f"\n  {ui.red(f'GAPS ({len(report.gaps)} inactive rules):')}")
        for g in report.gaps[:20]:
            print(f"    {ui.red('!')} {g.rule_id} (PL{g.paranoia_level}) "
                  f"{g.description} {ui.gray('→')} {ui.bold(g.trigger_payload[:50])}")

    print(ui.rule())

    if args.out:
        write_rulemap_json(report, args.out)
        print(ui.ok(f"rule map written to {args.out}"))
    return 0


def cmd_sidechannel(args) -> int:
    if not args.target:
        print("[err] --target is required", file=sys.stderr)
        return 2
    from .recon.sidechannel import SideChannelOracle
    target = Target(base_url=args.target, path=args.path, param=args.param,
                    inject=args.inject, method=args.method, timeout=args.timeout,
                    tls_verify=args.tls_verify, block_signature=args.block_signature,
                    **_auth_kwargs(args))
    bn = ui.banner(__version__)
    if bn:
        print(bn)
    print(ui.info("side-channel analysis for ") + ui.bold(args.target))
    print(ui.gray("  timing-based WAF internal scoring extraction"))
    print(ui.rule())

    payloads = None
    if getattr(args, "payloads", ""):
        with open(args.payloads) as f:
            payloads = [line.strip() for line in f if line.strip()]

    oracle = SideChannelOracle(target, samples_per_probe=args.samples,
                               transport=args.transport)
    report = oracle.run(payloads=payloads)

    print(f"  {ui.info('Baseline (benign):  ')} {report.baseline_ms:.1f}ms")
    print(f"  {ui.info('Ceiling (blocked):  ')} {report.blocked_ms:.1f}ms")
    print(f"  {ui.info('Processing window:  ')} {report.timing_range_ms:.1f}ms")

    if report.rule_clusters:
        print(f"\n  {ui.info('Rule clusters')} ({len(report.rule_clusters)} detected):")
        for c in report.rule_clusters:
            label_color = ui.green if c.label == "no_processing" else ui.gray
            print(f"    {label_color(f'{c.label:20s}')} {c.median_ms:7.1f}ms  "
                  f"{c.count:3d} payloads")

    if report.gap_payloads:
        print(f"\n  {ui.green(f'Gap payloads ({len(report.gap_payloads)})')} "
              + ui.gray("— WAF barely processed these:"))
        for p in report.gap_payloads[:10]:
            print(f"    {ui.bold(p[:60])}")

    print(ui.rule())
    print(ui.gray(f"  {report.estimated_rule_groups} estimated rule groups, "
                  f"{report.total_requests} requests used"))

    if args.out:
        import json as _json
        from pathlib import Path as _P
        _P(args.out).write_text(
            _json.dumps(report.as_dict(), indent=2, ensure_ascii=False))
        print(ui.ok(f"side-channel report written to {args.out}"))
    return 0


def cmd_origin(args) -> int:
    if not args.domain:
        print("[err] --domain is required", file=sys.stderr)
        return 2
    from .recon.origin import OriginDiscovery
    bn = ui.banner(__version__)
    if bn:
        print(bn)
    print(ui.info("origin IP discovery for ") + ui.bold(args.domain))
    print(ui.gray("  probes subdomains, MX records, SPF, response headers"))
    print(ui.rule())

    disc = OriginDiscovery(args.domain)
    if args.verify:
        report = disc.discover_and_verify()
    else:
        report = disc.discover()

    if report.main_ips:
        print(ui.gray(f"  main domain IPs: {', '.join(report.main_ips)}"))

    if not report.candidates:
        print(ui.gray("\n  no origin IP candidates found"))
    else:
        for c in report.candidates:
            conf_color = {"high": ui.green, "medium": ui.yellow, "low": ui.gray}
            label = conf_color.get(c.confidence, ui.gray)(f"{c.confidence.upper():8s}")
            print(f"  {label} {c.ip:20s} {c.source:10s} {ui.gray(c.evidence)}")

    if args.verify and report.verified:
        print(ui.rule())
        print(ui.green(f"  {len(report.verified)} verified origin IP(s):"))
        for c in report.verified:
            print(f"  {ui.green('✓')} {c.ip:20s} responds with Host: {args.domain}")
    if args.verify and report.unverified:
        for c in report.unverified:
            print(f"  {ui.gray('✗')} {c.ip:20s} no response")

    print(ui.rule())
    print(ui.gray(f"  {len(report.candidates)} candidate(s), {len(report.verified)} verified"))

    if args.out:
        import json as _json
        from pathlib import Path as _P
        _P(args.out).write_text(_json.dumps(report.as_dict(), indent=2, ensure_ascii=False))
        print(ui.ok(f"origin report written to {args.out}"))
    return 0


def cmd_discover(args) -> int:
    if not args.target:
        print("[err] --target is required", file=sys.stderr)
        return 2
    from .recon.discover import InjectionDiscovery
    target = Target(base_url=args.target, path=args.path, timeout=args.timeout, tls_verify=args.tls_verify,
                    block_signature=args.block_signature, **_auth_kwargs(args))
    bn = ui.banner(__version__)
    if bn:
        print(bn)
    print(ui.info("injection-point discovery for ") + ui.bold(target.url()))
    print(ui.gray("  probes query params, JSON keys, headers, cookies, path segments"))
    print(ui.rule())

    disc = InjectionDiscovery(target)
    report = disc.discover()

    for p in report.points:
        if p.waf_active:
            icon = ui.green("✓")
            detail = ui.bold(f"WAF active ({p.baseline_code}→{p.blocked_code})")
        else:
            icon = ui.gray("-")
            detail = ui.gray(f"no WAF ({p.baseline_code}→{p.blocked_code})")
        print(f"  {icon} {p.location:8s} {p.param:20s} {detail}")

    print(ui.rule())
    active = report.active_points
    if active:
        best = active[0]
        print(ui.green(f"  {len(active)} WAF-inspected injection point(s) found"))
        print(ui.info(f"  best: ") + ui.bold(f"{best.location} {best.param}"))
    else:
        print(ui.gray("  no WAF-inspected injection points found"))
    print(ui.gray(f"  {report.requests_used} requests used"))

    if args.out:
        import json as _json
        from pathlib import Path as _P
        _P(args.out).write_text(_json.dumps(report.as_dict(), indent=2, ensure_ascii=False))
        print(ui.ok(f"discovery report written to {args.out}"))
    return 0


def cmd_score_probe(args) -> int:
    if not args.target:
        print("[err] --target is required", file=sys.stderr)
        return 2
    from .recon.score_probe import ScoreProber
    from .core.oracle import Oracle as _O
    target = Target(base_url=args.target, path=args.path, param=args.param, inject=args.inject,
                    method=args.method, timeout=args.timeout, tls_verify=args.tls_verify,
                    block_signature=args.block_signature, **_auth_kwargs(args))
    oracle = _O(target, transport=args.transport)

    if args.calibrate:
        try:
            from .verify.calibrate import calibrate
            cal = calibrate(oracle)
            oracle.calibration = cal
            print(f"[*] calibrated: waf_detected={cal.waf_detected} confidence={cal.confidence:.2f}")
        except Exception as e:
            print(f"[warn] calibration failed: {e}", file=sys.stderr)

    bn = ui.banner(__version__)
    if bn:
        print(bn)
    print(ui.info("score-probe for ") + ui.bold(args.target)
          + ui.gray(f"   class={args.attack_class} inject={target.inject} param={target.param!r}"))
    print(ui.gray("  maps WAF detection thresholds: keyword → block/allow + progressive strip"))
    print(ui.rule())

    prober = ScoreProber(oracle)
    result = prober.run(args.attack_class)

    # keyword map
    detected = [k for k in result.keyword_map if k.detected]
    invisible = [k for k in result.keyword_map if not k.detected]
    print(ui.info("keyword detection map ") + ui.gray(f"({len(result.keyword_map)} tokens tested)"))
    if detected:
        print(ui.red(f"  detected ({len(detected)}): ") + ui.gray(", ".join(k.token for k in detected[:30])))
    if invisible:
        print(ui.green(f"  invisible ({len(invisible)}): ") + ui.bold(", ".join(k.token for k in invisible[:30])))

    # strip chain
    print("\n" + ui.info("progressive strip chain"))
    for i, s in enumerate(result.strip_chain):
        marker = ui.red("█ BLOCK") if s.verdict == "BLOCKED" else ui.green("░ THRU ")
        arrow = " ← flip" if i == result.flip_index else ""
        print(f"  {marker}  {s.code}  {s.payload[:60]}{ui.bold(arrow)}")
    if result.flip_index >= 0:
        print(ui.info(f"\n  threshold flip at index {result.flip_index}"))
    else:
        print(ui.warn("\n  no flip found — all blocked or all passed"))

    # boundary payloads
    if result.boundary_payloads:
        print("\n" + ui.info(f"boundary payloads ({len(result.boundary_payloads)} at the detection edge)"))
        for b in result.boundary_payloads[:15]:
            print(f"  {ui.green('░ THRU')}  {b.payload[:55]}  " + ui.gray(b.note[:40]))

    print(ui.rule())
    print(ui.gray(f"  {result.requests_used} requests used"))

    if args.out:
        import json as _json
        from pathlib import Path as _P
        _P(args.out).write_text(_json.dumps(result.as_dict(), indent=2, ensure_ascii=False))
        print(ui.ok(f"score-probe report written to {args.out}"))
    return 0


def cmd_libinjection_scan(args) -> int:
    if not args.target:
        print("[err] --target is required", file=sys.stderr)
        return 2
    from .recon.libinjection_gaps import LibinjectionGapHunter
    from .core.oracle import Oracle as _O
    target = Target(base_url=args.target, path=args.path, param=args.param, inject=args.inject,
                    method=args.method, timeout=args.timeout, tls_verify=args.tls_verify,
                    block_signature=args.block_signature, **_auth_kwargs(args))
    oracle = _O(target, transport=args.transport)
    engines = [e.strip() for e in args.engines.split(",") if e.strip()] or None

    bn = ui.banner(__version__)
    if bn:
        print(bn)
    print(ui.info("libinjection-scan for ") + ui.bold(args.target)
          + ui.gray(f"   engines={engines or 'all'}"))
    print(ui.gray("  probes database-specific SQL tokens for WAF blind spots"))
    print(ui.rule())

    hunter = LibinjectionGapHunter(target, sender=lambda p: oracle.send(p), engines=engines)
    reports = hunter.scan_all()

    total_gaps = 0
    for r in reports:
        icon = ui.green("●") if r.through > 0 else ui.gray("○")
        print(f"  {icon} {ui.bold(r.engine):20s}  "
              f"total={r.total}  blocked={r.blocked}  "
              + (ui.green(f"gaps={r.through}") if r.through else ui.gray(f"gaps=0"))
              + (f"  down={r.down}" if r.down else ""))
        total_gaps += r.through
        for g in r.gaps:
            print(f"      {ui.green('GAP')} {g.token.name:20s}  ({g.token.kind})  "
                  + ui.gray(f"template={g.template} payload={g.payload[:40]}"))
        if r.seeds:
            print(ui.info(f"    exploit seeds ({len(r.seeds)}):"))
            for s in r.seeds[:10]:
                print(f"      {ui.bold(s[:60])}")

    print(ui.rule())
    if total_gaps:
        print(ui.green(f"  {total_gaps} token gaps found — seeds ready for search engine"))
    else:
        print(ui.gray("  no gaps found — WAF covers all tested dialect tokens"))

    if args.out:
        import json as _json
        from pathlib import Path as _P
        data = []
        for r in reports:
            data.append({
                "engine": r.engine, "total": r.total,
                "blocked": r.blocked, "through": r.through, "down": r.down,
                "gaps": [{"token": g.token.name, "kind": g.token.kind,
                          "template": g.template, "payload": g.payload,
                          "code": g.code} for g in r.gaps],
                "seeds": r.seeds,
            })
        _P(args.out).write_text(_json.dumps(data, indent=2, ensure_ascii=False))
        print(ui.ok(f"libinjection-scan report written to {args.out}"))
    return 0


def cmd_cve_probe(args) -> int:
    if not args.target:
        print("[err] --target is required", file=sys.stderr)
        return 2
    from .recon.cve_probe import probe_cve_primitives
    target = Target(base_url=args.target, path=args.path, param=args.param, inject=args.inject,
                    method=args.method, timeout=args.timeout, tls_verify=args.tls_verify,
                    block_signature=args.block_signature, **_auth_kwargs(args))
    bn = ui.banner(__version__)
    if bn:
        print(bn)
    print(ui.info("2026 WAF-engine CVE probe for ") + ui.bold(args.target)
          + ui.gray(f"   inject {target.inject} {target.path} param={target.param!r}"))
    print(ui.gray("  canary-token differentials; safe against an authorized target"))
    print(ui.rule())
    colour = {"PRESENT": ui.red, "ABSENT": ui.green, "INCONCLUSIVE": ui.gray}
    probes = probe_cve_primitives(target)
    for p in probes:
        tag = colour.get(p.verdict, ui.gray)(f"{p.verdict:13}")
        print(f"  {tag} {ui.bold(p.cve)}  {ui.gray(p.name)}")
        print(ui.gray(f"       {p.detail}"))
    present = [p for p in probes if p.verdict == "PRESENT"]
    print(ui.rule())
    if present:
        print(ui.warn(f"{len(present)} primitive(s) look exploitable: ") + ", ".join(p.cve for p in present))
        print(ui.gray("  confirm with: bypass --verify using the matching mutators/transforms"))
    else:
        print(ui.ok("no 2026 engine primitive looks exploitable on this endpoint"))
    return 0


def cmd_smuggle(args) -> int:
    if not args.target:
        print("[err] --target is required", file=sys.stderr)
        return 2
    from .core.smuggle import detect
    bn = ui.banner(__version__)
    if bn:
        print(bn)
    print(ui.info("smuggle probe ") + ui.bold(args.target) + ui.gray(f"  path={args.path} timeout={args.timeout}s"))
    print(ui.gray("  (experimental timing-based desync detection · authorized targets only)"))
    print(ui.rule())
    findings = detect(args.target, args.path, timeout=args.timeout, tls_verify=args.tls_verify, stall_factor=args.stall_factor)
    any_hit = False
    for f in findings:
        mark = ui.red("● STALL") if f.suspected else ui.gray("○ ok   ")
        any_hit = any_hit or f.suspected
        print(f"  {mark}  {ui.bold(f.name):22} " + ui.gray(f.detail))
    print(ui.rule())
    if any_hit:
        print(ui.warn("possible request-smuggling desync — investigate manually (timing is noisy)"))
    else:
        print(ui.ok("no desync signal (no stall vs baseline)"))
    return 0


def cmd_defend(args) -> int:
    from .report import defend as defend_report
    import json as _json
    from types import SimpleNamespace

    findings = []
    with open(args.findings) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                d = _json.loads(line)
            except _json.JSONDecodeError:
                continue
            # Reconstruct a Finding-like object from JSONL
            findings.append(SimpleNamespace(
                payload=d.get("payload", d.get("bypass_payload", "")),
                chain=d.get("chain", []),
                attack_class=d.get("attack_class", ""),
                verified=d.get("verified_exploitable", d.get("verified", None)),
                confidence=d.get("verify_confidence", d.get("confidence", None)),
                code=d.get("http_code", d.get("code", "")),
            ))

    if not findings:
        print(ui.warn("no findings loaded from " + args.findings))
        return 1

    bn = ui.banner(__version__)
    if bn:
        print(bn)
    print(ui.info("defend — ") + ui.bold(f"{len(findings)} finding(s)") +
          ui.gray(f"  engine={args.engine}  source={args.findings}"))
    print(ui.rule())

    engine = args.engine.strip().lower()

    if engine == "all":
        out_dir = args.out or "waffen-rules"
        rules = defend_report.generate_rules(findings)
        paths = defend_report.write_all_engines(rules, out_dir)
        for p in paths:
            print(f"  {ui.green('+')} {p}")
        print(ui.ok(f"{len(rules)} rule(s) × {len(paths)} engines written to {out_dir}/"))
    else:
        rules = defend_report.generate_rules(findings, engine)
        rendered = defend_report.render_rules(rules, engine)
        if args.out:
            defend_report.write_rules(rules, args.out, engine)
            print(ui.ok(f"{len(rules)} {engine} rule(s) written to {args.out}"))
        else:
            print(rendered)

    return 0


def cmd_report(args) -> int:
    from .report.professional import (
        generate_html_report, generate_summary_card,
        write_html_report, load_findings_jsonl, ReportConfig,
    )
    findings = load_findings_jsonl(args.findings)
    if not findings:
        print(ui.warn("no findings loaded from " + args.findings))
        return 1

    cfg = ReportConfig(
        title=args.title,
        author=args.author,
        target=args.target,
        classification=args.classification,
    )

    bn = ui.banner(__version__)
    if bn:
        print(bn)

    if args.summary_only:
        html_str = generate_summary_card(findings, cfg)
        print(ui.info("report — ") + ui.bold("summary card") +
              ui.gray(f"  {len(findings)} finding(s)"))
    else:
        html_str = generate_html_report(findings, cfg)
        print(ui.info("report — ") + ui.bold("full report") +
              ui.gray(f"  {len(findings)} finding(s)"))

    write_html_report(html_str, args.html)
    print(ui.ok(f"HTML report written to {args.html}"))
    print(ui.gray("  Open in browser and print to PDF (Ctrl+P)"))

    if getattr(args, "csv", ""):
        from .report.csv_export import write_findings_csv
        write_findings_csv(findings, args.csv)
        print(ui.ok(f"CSV findings written to {args.csv}"))

    return 0


def cmd_analyze(args) -> int:
    from pathlib import Path as _P
    from .report import analyze as az
    if not _P(args.log).exists():
        print(f"[err] log file not found: {args.log}", file=sys.stderr)
        return 2
    bn = ui.banner(__version__)
    if bn:
        print(bn)
    records = az.load_log(args.log)
    if not records:
        print(ui.warn(f"no usable records in {args.log}"))
        return 0
    result = az.analyze(records)
    ban = az.ban_heuristic(records)
    print(ui.info("analyzed ") + ui.bold(f"{len(records)} records") + ui.gray(f"  from {args.log}"))
    print(ui.rule())

    o = result.overall
    print(ui.rule("COVERAGE") + ui.gray("   █ blocked = WAF caught it · ░ gap = reached origin"))
    for cls in sorted(result.per_class, key=lambda c: result.per_class[c].coverage):
        s = result.per_class[cls]
        print(f"  {ui.bar(s.coverage)} {s.coverage:5.1f}%  "
              + ui.gray(f"B={s.blocked:5d} T={s.through:5d} U={s.unresolved:4d} D={s.down:4d}  ")
              + ui.bold(cls))
    print("  " + ui.gray("─" * 54))
    print(f"  {ui.bar(o.coverage)} {ui.bold(f'{o.coverage:5.1f}%')}  "
          + ui.gray(f"B={o.blocked} T={o.through} U={o.unresolved} D={o.down}  ") + ui.bold("OVERALL"))
    if result.benign_total:
        fp = f"false positives: {result.benign_blocked}/{result.benign_total} = {result.fp_rate:.1f}%"
        print("\n" + (ui.ok(fp) if result.fp_rate <= 1 else ui.warn(fp)))
    # ban-contamination heuristic
    if getattr(ban, "suspected", False):
        print("\n" + ui.warn("BAN CONTAMINATION SUSPECTED: " + getattr(ban, "reason", "")))
    else:
        print("\n" + ui.ok("no ban-contamination signal — " + getattr(ban, "reason", "looks clean")))

    if args.html:
        az.to_html(result, args.html, meta={"source": args.log, "records": len(records)})
        print("\n" + ui.ok(f"HTML report: {args.html}"))
    if args.balanced_out:
        from .eval.dataset import balance_records, stratified_split, write_jsonl, write_csv, class_balance
        balanced = balance_records(records, max_ratio=args.balance)
        bal = class_balance(balanced)
        print("\n" + ui.info("balanced ") + ui.bold(f"{len(balanced)} rows")
              + ui.gray(f"  (malicious={bal.get('malicious',0)} benign={bal.get('benign',0)}, "
                        f"max_ratio={args.balance})"))
        base = args.balanced_out
        if args.split > 0:
            train, val = stratified_split(balanced, args.split)
            write_jsonl(train, f"{base}_train.jsonl"); write_jsonl(val, f"{base}_val.jsonl")
            write_csv(train, f"{base}_train.csv"); write_csv(val, f"{base}_val.csv")
            print(ui.ok(f"wrote {base}_train.(jsonl|csv) n={len(train)} · {base}_val.(jsonl|csv) n={len(val)}"))
        else:
            write_jsonl(balanced, f"{base}.jsonl"); write_csv(balanced, f"{base}.csv")
            print(ui.ok(f"wrote {base}.jsonl and {base}.csv (n={len(balanced)})"))
    if args.rules or args.rules_out:
        suggestions = rule_report.recommend_from_eval(result)
        if suggestions:
            if args.rules:
                print("\n" + ui.rule("SUGGESTED WAF RULES"))
                print(rule_report.render_text(suggestions))
            if args.rules_out:
                from pathlib import Path as _P2
                _P2(args.rules_out).write_text(rule_report.render_markdown(suggestions))
                print(ui.ok(f"rule recommendations written to {args.rules_out}"))
    return 0


def cmd_kb_update(args) -> int:
    from .kb.update import KBSource, check_and_update_all, default_sources, load_local_version

    bn = ui.banner(__version__)
    if bn:
        print(bn)

    sources = default_sources()
    if args.name and args.kind:
        local_v = load_local_version(args.dest, args.name)
        sources = [KBSource(name=args.name, kind=args.kind, repo=args.repo,
                            manifest_url=args.manifest_url, local_version=local_v)]
    elif sources:
        pass  # (currently always empty — default_sources() ships with none configured yet)
    else:
        print(ui.warn("no KB source configured — there is no public WAFFEN community-KB yet."))
        print(ui.gray("  pass --name NAME --kind github_release --repo owner/name"))
        print(ui.gray("  or   --name NAME --kind manifest --manifest-url URL"))
        print(ui.gray("  to check/apply one source now."))
        return 0

    print(ui.info("checking ") + ui.bold(f"{len(sources)} source(s)") + ui.gray(f"  dest={args.dest}"))
    results = check_and_update_all(sources, args.dest)
    any_err = False
    for r in results:
        if r.error:
            any_err = True
            print(ui.bad(f"{r.source_name}: {r.error}"))
        elif r.applied:
            print(ui.ok(f"{r.source_name}: updated to {r.new_version} -> {r.dest_path}"))
        else:
            print(ui.gray(f"  {r.source_name}: already up to date"))
    return 1 if any_err else 0


def cmd_mutators(args) -> int:
    ms = REGISTRY.all()
    if args.attack_class:
        ms = REGISTRY.select(attack_class=args.attack_class)
    head = f"{len(ms)} mutators" + (f" valid for {args.attack_class!r}" if args.attack_class else "")
    print(ui.bold(ui.cyan(head)))
    for m in sorted(ms, key=lambda x: (x.category, x.name)):
        cls = "any" if "*" in m.classes else ",".join(sorted(c for c in m.classes if c != "*"))
        tag = ui.magenta(f"{m.category:10}") if m.category == "encoder" else ui.yellow(f"{m.category:10}")
        print(f"  [{tag}] " + ui.bold(f"{m.name:28}") + " " + m.desc + ui.gray(f"  ({cls})"))
    return 0


def cmd_transforms(args) -> int:
    print(ui.bold(ui.cyan(f"{len(T.TRANSFORMS)} request-level transforms")))
    for tr in T.TRANSFORMS:
        print("  " + ui.bold(f"{tr.name:24}") + " " + ui.gray(tr.desc))
    return 0


def cmd_corpus(args) -> int:
    from .kb.corpus import corpus_all, corpus_stats, corpus_total, corpus_for
    if args.attack_class:
        cls = kb_seeds.resolve_class(args.attack_class)
        payloads = corpus_for(cls)
        print(ui.bold(f"{cls}: {len(payloads)} payloads"))
        if not args.count_only:
            for p in payloads:
                print(f"  {p}")
    else:
        stats = corpus_stats()
        total = corpus_total()
        print(ui.bold(ui.cyan(f"WAFFEN Payload Corpus — {total} payloads")))
        print(ui.rule())
        for cls, count in sorted(stats.items(), key=lambda x: -x[1]):
            bar = ui.bar(count / max(stats.values()) * 100, width=20)
            print(f"  {bar} {count:>5}  {cls}")
        print(ui.rule())
        print(ui.gray(f"  Total: {total} payloads across {len(stats)} classes"))
        print(ui.gray("  Use: waffen bypass --corpus --class sqli --target URL"))
    return 0


def cmd_oob(args) -> int:
    from .oob.server import OOBServer
    from .oob.payloads import oob_payloads_for

    bn = ui.banner(__version__)
    if bn:
        print(bn)

    if args.generate:
        srv = OOBServer(external_host=args.external or "localhost", listen_port=args.port)
        cb = srv.generate(context=args.context)
        print(ui.info("generated callback:"))
        print(f"  id:  {ui.bold(cb.id)}")
        print(f"  url: {ui.bold(cb.url)}")
        if args.context:
            print(f"  ctx: {args.context}")
        return 0

    if args.payloads:
        host = args.external or "localhost"
        url = f"http://{host}:{args.port}/cb/TOKEN"
        for cls in (args.payloads_class or "SSRF,XXE Injection,XSS Injection,Command Injection,SSTI").split(","):
            cls = cls.strip()
            pls = oob_payloads_for(cls, url)
            if pls:
                print(ui.info(f"{cls} ({len(pls)} payloads):"))
                for p in pls:
                    print(f"  {p[:100]}")
                print()
        return 0

    srv = OOBServer(listen_host=args.listen, listen_port=args.port,
                    external_host=args.external)
    print(ui.info("OOB callback server"))
    print(f"  listen:   {ui.bold(f'{srv.host}:{srv.port}')}")
    print(f"  external: {ui.bold(f'{srv.external}:{srv.port}')}")
    print(ui.gray("  Ctrl-C to stop\n"))

    srv.start()
    try:
        while True:
            import time as _t
            _t.sleep(1)
            received = srv.check_any()
            if received:
                for cb in received:
                    if not hasattr(cb, "_printed"):
                        print(f"  {ui.green('CALLBACK')} {cb.id}  "
                              f"from={cb.source_ip}  method={cb.request_method}  "
                              f"ctx={cb.payload_context}")
                        cb._printed = True  # type: ignore[attr-defined]
    except KeyboardInterrupt:
        print(f"\n{ui.gray('  stopping...')}")
    finally:
        s = srv.summary()
        print(f"  {ui.info('summary:')} {s['received']} received / {s['total']} total")
        if args.out:
            srv.write_jsonl(args.out)
            print(ui.ok(f"callbacks written to {args.out}"))
        srv.stop()
    return 0


def cmd_plugin(args) -> int:
    from .plugins import (
        PLUGIN_DIR, discover_plugins, load_plugin, unload_plugin,
        is_disabled, disable_plugin, enable_plugin, create_plugin,
    )
    action = args.plugin_action

    if action == "list":
        from .plugins.loader import _find_plugin_entries
        entries = _find_plugin_entries(PLUGIN_DIR)
        if not entries:
            print(ui.gray(f"  No plugins found in {PLUGIN_DIR}"))
            print(ui.gray(f"  Create one: waffen plugin create <name>"))
            return 0
        print(ui.info(f"Installed plugins ({PLUGIN_DIR}):"))
        print(ui.rule())
        for entry in entries:
            name = entry.stem if entry.is_file() else entry.name
            disabled = is_disabled(entry if entry.is_dir() else PLUGIN_DIR / name)
            plugins = discover_plugins() if not disabled else []
            matched = [p for p in plugins if p.name == name or entry.name == name]
            if disabled:
                print(f"  {ui.gray('○')} {ui.gray(name):30s}  (disabled)")
            elif matched:
                p = matched[0]
                print(f"  {ui.green('●')} {ui.bold(p.name):30s}  v{p.version}  by {p.author}")
                print(f"      {ui.gray(p.description)}")
                parts = []
                if p.mutator_count:
                    parts.append(f"mutators: {p.mutator_count}")
                if p.transform_count:
                    parts.append(f"transforms: {p.transform_count}")
                if p.seed_count:
                    parts.append(f"seeds: {p.seed_count}")
                if parts:
                    print(f"      {ui.gray('  '.join(parts))}")
            else:
                print(f"  {ui.yellow('?')} {name:30s}  (failed to load)")
        return 0

    elif action == "create":
        name = args.name
        if not name:
            print("[err] plugin name required", file=sys.stderr)
            return 2
        try:
            path = create_plugin(name, author=args.author, desc=args.desc)
            print(ui.ok(f"Plugin created: {path}"))
            print(ui.gray(f"  Edit {path / '__init__.py'} to add your mutators/transforms"))
        except FileExistsError as e:
            print(f"[err] {e}", file=sys.stderr)
            return 1
        return 0

    elif action == "info":
        name = args.name
        if not name:
            print("[err] plugin name required", file=sys.stderr)
            return 2
        info = load_plugin(name)
        if info is None:
            print(f"[err] plugin not found or disabled: {name}", file=sys.stderr)
            return 1
        print(ui.info(f"Plugin: {info.name}"))
        print(f"  Version:     {info.version}")
        print(f"  Author:      {info.author}")
        print(f"  Description: {info.description}")
        print(f"  Path:        {info.path}")
        print(f"  Type:        {info.type}")
        print(f"  Mutators:    {info.mutator_count}")
        print(f"  Transforms:  {info.transform_count}")
        print(f"  Seeds:       {info.seed_count}")
        return 0

    elif action == "disable":
        name = args.name
        if not name:
            print("[err] plugin name required", file=sys.stderr)
            return 2
        if disable_plugin(name):
            print(ui.ok(f"Plugin disabled: {name}"))
        else:
            print(f"[err] plugin not found: {name}", file=sys.stderr)
            return 1
        return 0

    elif action == "enable":
        name = args.name
        if not name:
            print("[err] plugin name required", file=sys.stderr)
            return 2
        if enable_plugin(name):
            print(ui.ok(f"Plugin enabled: {name}"))
        else:
            print(f"[err] plugin not found or not disabled: {name}", file=sys.stderr)
            return 1
        return 0

    print(f"[err] unknown plugin action: {action}", file=sys.stderr)
    return 2


def cmd_exploit(args) -> int:
    if not args.target:
        print("[err] --target is required", file=sys.stderr)
        return 2
    if not args.bypass_payload:
        print("[err] --bypass-payload is required", file=sys.stderr)
        return 2
    from .exploit.sqli import SQLiExploiter
    target = Target(base_url=args.target, path=args.path, param=args.param,
                    inject=args.inject, method=args.method,
                    timeout=args.timeout, tls_verify=args.tls_verify,
                    block_signature=args.block_signature, **_auth_kwargs(args))
    chain = [c.strip() for c in args.bypass_chain.split(",") if c.strip()] if args.bypass_chain else []

    bn = ui.banner(__version__)
    if bn:
        print(bn)
    print(ui.info("exploit for ") + ui.bold(args.target))
    print(ui.gray(f"  bypass: {args.bypass_payload[:50]}  chain: {chain or 'none'}"))
    print(ui.rule())

    exploiter = SQLiExploiter(target, args.bypass_payload, bypass_chain=chain,
                              transport=args.transport)

    if args.auto:
        print(ui.info("auto-exploit: detect → enumerate → extract"))
        result = exploiter.run_auto()
    else:
        dbms = exploiter.detect_dbms()
        print(f"  {ui.green('+')} DBMS: {ui.bold(dbms)}")
        technique = exploiter.detect_technique()
        print(f"  {ui.green('+')} Technique: {ui.bold(technique or 'none found')}")
        if not technique:
            print(ui.red("  no extraction technique found through WAF"))
            return 1

        if args.tables:
            tables = exploiter.enumerate_tables()
            print(f"\n  {ui.info('Tables:')} {', '.join(tables) if tables else 'none found'}")
            return 0

        if args.columns and args.table:
            cols = exploiter.enumerate_columns(args.table)
            print(f"\n  {ui.info(f'Columns in {args.table}:')} {', '.join(cols) if cols else 'none found'}")
            return 0

        if args.dump and args.table:
            cols = [c.strip() for c in args.dump_columns.split(",")] if args.dump_columns else None
            result = exploiter.extract(args.table, columns=cols, limit=args.limit)
        elif args.query:
            val = exploiter.extract_value(args.query)
            print(f"\n  {ui.info('Result:')} {val}")
            return 0
        else:
            print("[err] specify --tables, --columns, --dump, --query, or --auto", file=sys.stderr)
            return 2

    # Print results
    print(ui.rule())
    if result.error:
        print(ui.red(f"  error: {result.error}"))
    print(f"  {ui.info('DBMS:      ')} {result.dbms}")
    print(f"  {ui.info('Technique: ')} {result.technique}")
    print(f"  {ui.info('Table:     ')} {result.table}")
    print(f"  {ui.info('Columns:   ')} {', '.join(result.columns)}")
    print(f"  {ui.info('Rows:      ')} {len(result.data)}")
    print(f"  {ui.info('Requests:  ')} {result.requests_used}")
    print(f"  {ui.info('Duration:  ')} {result.duration:.1f}s")
    if result.data:
        print(f"\n  {ui.bold('Extracted data:')}")
        for i, row in enumerate(result.data[:20]):
            vals = "  |  ".join(f"{k}={v}" for k, v in row.items())
            print(f"    [{i}] {vals}")
    print(ui.rule())

    if args.out:
        import json as _json
        from pathlib import Path as _P
        data = {
            "dbms": result.dbms, "technique": result.technique,
            "table": result.table, "columns": result.columns,
            "rows": result.data, "requests": result.requests_used,
            "duration": result.duration, "error": result.error,
        }
        _P(args.out).write_text(_json.dumps(data, indent=2, ensure_ascii=False))
        print(ui.ok(f"extraction results written to {args.out}"))
    return 0 if result.data else 1


def cmd_grammar(args) -> int:
    from .grammar import GRAMMARS
    gtype = args.type
    grammar = GRAMMARS.get(gtype)
    if not grammar:
        print(f"[err] unknown grammar type: {gtype}", file=sys.stderr)
        return 2

    bn = ui.banner(__version__)
    if bn:
        print(bn)
    print(ui.info("grammar generator ") + ui.bold(gtype)
          + ui.gray(f"   depth={args.max_depth}"))
    print(ui.rule())

    if args.target_symbols:
        required = {s.strip() for s in args.target_symbols.split(",") if s.strip()}
        payloads = grammar.generate_targeted(
            required, max_depth=args.max_depth,
            attempts=args.generate * 5, seed=args.seed)
        payloads = payloads[:args.generate]
        print(ui.info(f"targeted generation (require: {required})"))
    elif args.coverage:
        payloads = grammar.coverage_generate(
            n=args.generate, max_depth=args.max_depth, seed=args.seed)
        covered = len(payloads)
        total_rules = sum(len(alts) for alts in grammar.rules.values())
        print(ui.info(f"coverage mode: {covered} payloads, {total_rules} rule alternatives"))
    else:
        payloads = grammar.generate_n(
            args.generate, max_depth=args.max_depth, seed=args.seed)
        print(ui.info(f"random generation: {len(payloads)} payloads"))

    for i, p in enumerate(payloads):
        print(f"  {ui.gray(f'{i+1:3d}')}  {p}")

    print(ui.rule())
    print(ui.gray(f"  {len(payloads)} payloads generated"))

    if args.out:
        from pathlib import Path
        Path(args.out).write_text("\n".join(payloads) + "\n")
        print(ui.ok(f"written to {args.out}"))

    return 0


def cmd_semantic(args) -> int:
    from .mutate.semantic import SemanticEngine, semantic_all
    bn = ui.banner(__version__)
    if bn:
        print(bn)
    print(ui.info("semantic equivalence engine")
          + ui.gray(f"   dbms={args.dbms}  count={args.count}"))
    print(ui.rule())

    engine = SemanticEngine(dbms=args.dbms, max_variants=args.count)

    if args.payload:
        payloads = engine.semantic_expand(args.payload)
        print(ui.info(f"expanding: ") + ui.bold(args.payload))
    elif args.mode == "tautology":
        payloads = engine.generate_tautology_injections()
        print(ui.info("tautology injections"))
    elif args.mode == "union":
        payloads = engine.generate_union_injections(columns=args.columns)
        print(ui.info(f"UNION injections (columns={args.columns})"))
    elif args.mode == "blind":
        payloads = engine.generate_blind_injections()
        print(ui.info("blind boolean injections"))
    elif args.mode == "time":
        payloads = engine.generate_time_injections()
        print(ui.info("time-based blind injections"))
    else:
        payloads = engine.generate_tautology_injections()
        print(ui.info("tautology injections (default)"))

    payloads = payloads[:args.count]
    for i, p in enumerate(payloads):
        print(f"  {ui.gray(f'{i+1:3d}')}  {p}")

    print(ui.rule())
    print(ui.gray(f"  {len(payloads)} semantically equivalent payloads"))

    if args.out:
        from pathlib import Path
        Path(args.out).write_text("\n".join(payloads) + "\n")
        print(ui.ok(f"written to {args.out}"))
    return 0


def cmd_synthesize(args) -> int:
    from .ai.synthesize import PayloadSynthesizer, SynthesisConfig, SynthesisContext

    config = SynthesisConfig(
        provider=args.provider,
        model=args.model,
        api_key=args.api_key,
        max_payloads=args.count,
        temperature=args.temperature,
    )

    # Build context from one of three sources
    ctx = None
    if args.profile:
        try:
            from .core.profile import TargetProfile
            profile = TargetProfile.load(args.profile)
            ctx = SynthesisContext.from_profile(profile)
            print(ui.info("context loaded from profile: ") + ui.bold(args.profile))
        except Exception as exc:
            print(f"[err] could not load profile: {exc}", file=sys.stderr)
            return 2
    elif args.detected or args.invisible or args.gaps:
        ctx = SynthesisContext.from_manual(
            detected=args.detected, invisible=args.invisible,
            gaps=args.gaps, db=args.db, waf=args.waf_name,
        )
    elif args.target:
        # Run score-probe live to build context
        try:
            from .recon.score_probe import ScoreProber
            from .core.oracle import Oracle
            target = Target(base_url=args.target, path=args.path, param=args.param,
                            inject="query", method="GET", timeout=args.timeout,
                            tls_verify=args.tls_verify,
                            block_signature=args.block_signature,
                            **_auth_kwargs(args))
            oracle = Oracle(target, transport=args.transport)
            print(ui.info("running score-probe to build WAF context..."))
            prober = ScoreProber(oracle)
            result = prober.run(args.attack_class)
            ctx = SynthesisContext.from_score_probe(result)
            print(ui.gray(f"  detected={len(ctx.detected_keywords)}  "
                          f"invisible={len(ctx.invisible_keywords)}  "
                          f"boundary={len(ctx.boundary_payloads)}"))
        except Exception as exc:
            print(f"[err] score-probe failed: {exc}", file=sys.stderr)
            return 1
    else:
        print("[err] provide --target, --profile, or --detected/--invisible/--gaps", file=sys.stderr)
        return 2

    if ctx is None or ctx.is_empty():
        print(ui.warn("empty context — synthesis may produce generic payloads"))
        ctx = ctx or SynthesisContext()

    bn = ui.banner(__version__)
    if bn:
        print(bn)
    print(ui.info("LLM payload synthesis ") + ui.bold(f"({config.provider}/{config.model})"))
    print(ui.gray(f"  class={args.attack_class}  count={config.max_payloads}  "
                  f"temp={config.temperature}"))
    print(ui.rule())

    synth = PayloadSynthesizer(config)
    try:
        payloads = synth.synthesize(ctx, args.attack_class)
    except ValueError as exc:
        print(ui.red(f"  {exc}"))
        print(ui.gray("\n  Offline alternative: waffen grammar --type sqli --generate 50"))
        print(ui.gray("  Or: waffen bypass --corpus --class sqli"))
        return 1
    except Exception as exc:
        print(ui.red(f"  API error: {exc}"))
        return 1

    print(ui.green(f"  {len(payloads)} payloads synthesized\n"))
    for i, p in enumerate(payloads[:30]):
        print(f"  {ui.gray(f'{i+1:3d}')}  {p}")
    if len(payloads) > 30:
        print(ui.gray(f"  ... and {len(payloads) - 30} more"))

    print(ui.rule())
    print(ui.gray("  Privacy: only keyword map + gap tokens were sent to API (no URLs/creds/bodies)"))

    if args.out:
        from pathlib import Path
        Path(args.out).write_text("\n".join(payloads) + "\n")
        print(ui.ok(f"payloads written to {args.out}"))
    return 0


def cmd_plan(args) -> int:
    from .plan import AttackPlanner, GOALS
    from .plan.planner import write_plan_json

    if args.list_goals:
        print(ui.info("Available attack goals:"))
        for name, goal in GOALS.items():
            print(f"  {ui.bold(name):25s} {goal.description}")
        return 0

    if not args.target and not args.goal:
        print("[err] --target and --goal are required (or --list-goals)", file=sys.stderr)
        return 2

    target = Target(base_url=args.target, path=args.path, param=args.param,
                    timeout=args.timeout, tls_verify=args.tls_verify,
                    block_signature=args.block_signature, **_auth_kwargs(args))

    bn = ui.banner(__version__)
    if bn:
        print(bn)
    print(ui.info("attack planner for ") + ui.bold(args.target))
    print(ui.rule())

    planner = AttackPlanner(target)

    if args.discover:
        from .core.oracle import Oracle
        oracle = Oracle(target, transport=args.transport)
        planner._oracle = oracle
        print(ui.gray("  probing endpoints for WAF protection..."))
        planner.discover()
    else:
        planner.build_graph()

    g = planner.graph
    print(f"  Attack graph: {len(g.nodes)} nodes, {len(g.edges)} edges")

    if args.goal:
        plan = planner.plan_attack(args.goal)
        print()
        print(plan.summary())
        if plan.bypasses_needed:
            print()
            print(ui.red(f"  ⚡ {len(plan.bypasses_needed)} WAF bypass(es) required:"))
            for e in plan.bypasses_needed:
                print(f"    - {e.method} {e.path} ({e.description})")

        if args.execute:
            print()
            print(ui.info("Executing plan (dry-run)..."))
            result = planner.execute_plan(plan)
            for sr in result.steps:
                icon = ui.green("✓") if sr.success else ui.red("✗")
                print(f"  {icon} {sr.edge.method} {sr.edge.path} → {sr.response_code}")
            if result.success:
                print(ui.green(f"\n  Plan executed successfully"))
            else:
                print(ui.red(f"\n  Plan failed at step {len(result.steps)}"))

        if args.out:
            write_plan_json(plan, args.out)
            print(ui.ok(f"plan written to {args.out}"))

    print(ui.rule())
    return 0


def cmd_dtree(args) -> int:
    if not args.target:
        print("[err] --target is required", file=sys.stderr)
        return 2
    from .recon.decision_tree import WAFDecisionTreeProber, write_dtree_json
    target = Target(base_url=args.target, path=args.path, param=args.param,
                    inject=args.inject, method=args.method,
                    timeout=args.timeout, tls_verify=args.tls_verify,
                    block_signature=args.block_signature, **_auth_kwargs(args))

    bn = ui.banner(__version__)
    if bn:
        print(bn)
    print(ui.info("WAF decision tree for ") + ui.bold(args.target))
    print(ui.gray("  fingerprints the WAF processing pipeline via strategic probing"))
    print(ui.rule())

    prober = WAFDecisionTreeProber(target)
    report = prober.run()

    print(ui.info("processing pipeline"))
    for step, active in report.pipeline.processing_order():
        mark = ui.green("✓") if active else ui.red("✗")
        print(f"  {mark} {step}")

    gaps = report.pipeline.gaps()
    if gaps:
        print("\n" + ui.info(f"gaps ({len(gaps)})"))
        for g in gaps:
            print(f"  {ui.yellow('!')} {g}")

    if report.recommended_mutations:
        print("\n" + ui.info(f"recommended mutations ({len(report.recommended_mutations)})"))
        for i, m in enumerate(report.recommended_mutations, 1):
            print(f"  {i}. {ui.bold(m)}")

    print(ui.rule())
    print(ui.gray(f"  {report.requests_used} requests used"))

    if args.out:
        write_dtree_json(report, args.out)
        print(ui.ok(f"decision tree written to {args.out}"))
    return 0


def cmd_synthesize_config(args) -> int:
    from .report.synthesize_config import (
        WAFConfigSynthesizer, write_config,
        load_findings_jsonl, load_rulemap_json,
    )

    synth = WAFConfigSynthesizer()

    if args.findings:
        findings = load_findings_jsonl(args.findings)
        synth.add_bypasses(findings)

    if args.rulemap:
        rulemap = load_rulemap_json(args.rulemap)
        synth.add_rulemap(rulemap)

    if args.benchmark:
        import json as _json
        with open(args.benchmark) as f:
            synth.add_benchmark(_json.loads(f.read()))

    if args.false_positives:
        with open(args.false_positives) as f:
            fps = [line.strip() for line in f if line.strip()]
        synth.add_false_positives(fps)

    bn = ui.banner(__version__)
    if bn:
        print(bn)
    print(ui.info("WAF Config Synthesis"))
    print(ui.gray(f"  engine={args.engine}  target_grade={args.target_grade}"))
    print(ui.rule())

    config = synth.synthesize(engine=args.engine, target_grade=args.target_grade)
    warnings = synth.validate(config)

    print(f"  {ui.info('Paranoia level:')} {config.paranoia_level}")
    print(f"  {ui.info('Custom rules:')} {len(config.custom_rules)}")
    print(f"  {ui.info('Rules to enable:')} {len(config.rules_enabled)}")
    print(f"  {ui.info('Exclusions:')} {len(config.exclusions)}")
    print(f"  {ui.info('Recommendations:')} {len(config.recommendations)}")

    for rec in config.recommendations:
        print(f"    {ui.green('+')} {rec}")
    for w in warnings:
        print(f"    {ui.yellow('!')} {w}")

    if args.out:
        files = write_config(synth, config, args.out)
        print(ui.rule())
        print(ui.ok(f"Configuration written to {args.out}/"))
        for f in files:
            print(f"    {f}")
    else:
        print(ui.rule())
        print(synth.render(config))

    return 0


def cmd_version(args) -> int:
    print(ui.banner(__version__, force=True))
    print(f"  waffen {__version__}")
    return 0


def _add_target_args(p):
    p.add_argument("--target", default="", help="base URL of a target you own/are authorized to test")
    p.add_argument("--path", default="/", help="request path on target")
    p.add_argument("--timeout", type=int, default=15)
    p.add_argument("--block-signature", default="",
                   help="WAF block page signature (auto-detected via --calibrate if empty)")
    p.add_argument("--tls-verify", action="store_true",
                   help="enforce TLS certificate verification (default: off — for self-signed test targets)")
    p.add_argument("--header", "-H", action="append", default=None, metavar="'Name: Value'",
                   help="extra request header, e.g. 'Authorization: Bearer ...' (repeatable). "
                        "Threads through every inject mode and transform — run a search behind auth")
    p.add_argument("--cookie", default="", metavar="'a=1; b=2'",
                   help="cookie string sent with every request (session auth)")
    p.add_argument("--transport", default="auto", choices=["auto", "curl", "pooled", "h2"],
                   help="request transport: 'auto' (default, pooled for plain requests, curl for "
                        "transforms), 'curl' (uniform subprocess), or 'pooled' (keep-alive "
                        "http.client — faster, falls back to curl for transform sends)")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="waffen",
                                description="WAF evaluation / bypass-research tool (authorized targets only)")
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("bypass", help="search for WAF evasion chains")
    _add_target_args(b)
    b.add_argument("--mock", action="store_true", help="use a built-in mock WAF (offline engine test)")
    b.add_argument("--payload", default="", help="single seed payload")
    b.add_argument("--class", dest="attack_class", default="", help="attack class (uses built-in KB seeds)")
    b.add_argument("--all-classes", action="store_true", help="run all built-in KB seeds")
    b.add_argument("--corpus", action="store_true",
                   help="use the full 3000+ payload corpus instead of minimal KB seeds")
    b.add_argument("--param", default="q", help="param/header/cookie name")
    b.add_argument("--method", default="GET")
    b.add_argument("--inject", default="query",
                   choices=["query", "path", "rawpath", "body", "json", "header", "cookie", "upload", "auto"])
    b.add_argument("--strategy", default="beam", choices=["beam", "genetic", "bestfirst", "mcts", "adaptive", "rl", "dna"],
                   help="search strategy (adaptive = multi-stage pipeline)")
    b.add_argument("--branch", type=int, default=4, help="bestfirst: mutators tried per expansion")
    b.add_argument("--iterations", type=int, default=200, help="mcts: tree-search iterations")
    b.add_argument("--rollout-depth", type=int, default=3, help="mcts: rollout depth")
    b.add_argument("--transforms", default="", help="request transforms to sweep (comma-sep; default all)")
    b.add_argument("--verify", action="store_true", help="semantically verify each bypass (live targets)")
    b.add_argument("--calibrate", action="store_true",
                   help="learn the WAF block/pass signature at runtime (replaces naive 403=block)")
    b.add_argument("--learn", action="store_true",
                   help="GOFA-lite: probe the WAF's normalization and aim mutations at its blind spots")
    b.add_argument("--width", type=int, default=6, help="beam width")
    b.add_argument("--depth", type=int, default=4, help="beam: max mutation-chain length")
    b.add_argument("--pop-size", type=int, default=20, help="genetic: population size")
    b.add_argument("--generations", type=int, default=8, help="genetic: generations")
    b.add_argument("--max-requests", type=int, default=400, help="request budget per run")
    b.add_argument("--delay", type=float, default=0.0, help="seconds between requests (throttle; avoids self-ban)")
    b.add_argument("--stop-on-first", action="store_true", help="stop a run at its first bypass")
    b.add_argument("--all-mutators", action="store_true", help="ignore per-class mutator filtering")
    b.add_argument("--concurrency", type=int, default=1,
                   help="batch-evaluate this many candidates per round via oracle.send_many "
                        "(beam/genetic/bestfirst speed up; mcts is sequential by nature, see docs)")
    b.add_argument("--canary", default="",
                   help="a known-BENIGN value to re-probe periodically; if it starts looking "
                        "blocked, the test source is likely banned, not the content risky. "
                        "Only checked at --concurrency 1 (sequential sends)")
    b.add_argument("--canary-every", type=int, default=25, help="re-probe the canary every N sends")
    b.add_argument("--fitness", default="default", choices=["default", "gradient"],
                   help="scoring function: 'default' (built-in heuristic) or 'gradient' (10-feature "
                        "calibratable scorer — recommended for scoring-engine WAFs)")
    b.add_argument("--verbose", action="store_true", help="print search events")
    b.add_argument("--out", default="", help="write findings JSONL here")
    b.add_argument("--rules", action="store_true",
                   help="print suggested WAF rules for verified-exploitable findings")
    b.add_argument("--rules-out", default="", help="write suggested WAF rules (Markdown) here")
    b.add_argument("--nuclei", default="", metavar="DIR",
                   help="write Nuclei v3 differential WAF-audit templates (one per verified bypass) to DIR")
    b.add_argument("--exploit-guided", action="store_true",
                   help="score THROUGH payloads by exploit signal (backend error, SQL error, reflection) — "
                        "beam search prefers real exploits over harmless evasions")
    b.add_argument("--cross-axis", action="store_true",
                   help="second pass: cross-compose top mutated payloads × top transforms")
    b.add_argument("--cross-axis-budget", type=int, default=200,
                   help="request budget for cross-axis second pass (default: 200)")
    b.add_argument("--profile", default="", metavar="FILE",
                   help="target profile JSON: save state after each transform, "
                        "resume with --resume to skip completed transforms")
    b.add_argument("--resume", action="store_true",
                   help="resume from --profile: skip already-completed transforms")
    b.add_argument("--sarif", default="", metavar="FILE",
                   help="write SARIF 2.1.0 report here (for GitHub Security tab)")
    b.add_argument("--defend", default="", metavar="ENGINE",
                   help="generate deployable WAF rules from verified bypasses "
                        "(modsecurity/naxsi/cloudflare/aws/all)")
    b.add_argument("--defend-out", default="", metavar="PATH",
                   help="file or directory for --defend output (default: stdout)")
    b.add_argument("--html-report", default="", metavar="FILE",
                   help="write a professional HTML pentest report here (open in browser, print to PDF)")
    b.add_argument("--dry-run", action="store_true",
                   help="show the search plan and time estimate, then exit without sending any requests")
    b.add_argument("--grammar", default="", metavar="TYPE",
                   help="use grammar-guided seed generation (sqli/xss/ssti) instead of KB seeds")
    b.add_argument("--save-policy", default="", metavar="FILE",
                   help="(RL strategy) save the learned Q-table policy to a JSON file after the run")
    b.add_argument("--load-policy", default="", metavar="FILE",
                   help="(RL strategy) load a previously learned policy to warm-start the agent")
    b.add_argument("--csv", default="", metavar="FILE",
                   help="write findings CSV here (for spreadsheet users)")
    b.add_argument("--webhook", default="", metavar="URL",
                   help="send Slack/Discord notification on verified bypass (JSON payload to URL)")
    b.set_defaults(func=cmd_bypass)

    ad = sub.add_parser("adaptive",
                        help="multi-stage adaptive pipeline: learn → score-probe → gap-scan → search → deepen")
    _add_target_args(ad)
    ad.add_argument("--param", default="q", help="parameter name")
    ad.add_argument("--inject", default="query", choices=["query", "body", "json"])
    ad.add_argument("--method", default="GET")
    ad.add_argument("--classes", default="sqli", help="comma-separated attack classes (default: sqli)")
    ad.add_argument("--budget", type=int, default=2000, help="total request budget across all stages")
    ad.add_argument("--search-strategy", default="beam", choices=["beam", "genetic", "bestfirst"],
                    help="primary search strategy for stage 4 (default: beam)")
    ad.add_argument("--deepen-strategy", default="mcts", choices=["mcts", "bestfirst", "beam"],
                    help="deepening strategy for stage 5 (default: mcts)")
    ad.add_argument("--verify", action="store_true", help="semantically verify findings")
    ad.add_argument("--concurrency", type=int, default=1)
    ad.add_argument("--out", default="", help="write adaptive report JSON here")
    ad.set_defaults(func=cmd_adaptive)

    a = sub.add_parser("auto",
                       help="guided wizard — answers a few questions, runs the full pipeline automatically")
    a.add_argument("--url", "--target", default="", dest="url",
                   help="target URL (skips the interactive prompt)")
    a.add_argument("--path", default="", help="request path")
    a.add_argument("--param", default="q", help="parameter name")
    a.add_argument("-y", "--yes", action="store_true",
                   help="non-interactive: accept all defaults (requires --url)")
    a.add_argument("--out", default="", help="write findings JSONL here")
    a.add_argument("--timeout", type=int, default=10)
    a.add_argument("--transport", default="auto", choices=["auto", "curl", "pooled", "h2"])
    a.add_argument("--tls-verify", action="store_true")
    a.add_argument("--block-signature", default="")
    a.add_argument("--header", "-H", action="append", default=None)
    a.add_argument("--cookie", default="")
    a.add_argument("--corpus", action="store_true",
                   help="use the full 3000+ payload corpus instead of KB seeds only")
    a.add_argument("--no-reconstruct", dest="reconstruct", action="store_false", default=True,
                   help="skip payload reconstruction from recon results")
    a.add_argument("--profile", default="", metavar="FILE",
                   help="target profile JSON: skip recon phases if profile has results")
    a.set_defaults(func=cmd_auto)

    w = sub.add_parser("watch",
                       help="re-test saved bypass findings and track what still works vs what got patched")
    _add_target_args(w)
    w.add_argument("--findings", required=True, help="JSONL from `waffen bypass --out` with saved findings")
    w.add_argument("--param", default="q", help="parameter name (default: q)")
    w.add_argument("--inject", default="query", choices=["query", "body", "json"],
                   help="where to inject (default: query)")
    w.add_argument("--method", default="GET", help="HTTP method (default: GET)")
    w.add_argument("--interval", type=int, default=3600, help="seconds between rounds (default: 3600)")
    w.add_argument("--rounds", type=int, default=0, help="max rounds (0 = infinite, default: 0)")
    w.add_argument("--once", action="store_true", help="run one check and exit")
    w.add_argument("--out", default="", help="write watch report JSONL here")
    w.set_defaults(func=cmd_watch)

    dm = sub.add_parser("daemon",
                        help="continuous autonomous assessment — monitor a WAF 24/7, detect changes, alert on new bypasses")
    _add_target_args(dm)
    dm.add_argument("--param", default="q", help="parameter name (default: q)")
    dm.add_argument("--inject", default="query", choices=["query", "body", "json"],
                    help="where to inject (default: query)")
    dm.add_argument("--method", default="GET", help="HTTP method (default: GET)")
    dm.add_argument("--class", dest="attack_class", default="sqli",
                    help="attack classes, comma-separated (default: sqli)")
    dm.add_argument("--interval", type=float, default=6.0,
                    help="hours between cycles (default: 6)")
    dm.add_argument("--max-requests", type=int, default=500,
                    help="request budget per cycle (default: 500)")
    dm.add_argument("--profile", default="",
                    help="JSON profile path for save/resume across restarts")
    dm.add_argument("--webhook", default="",
                    help="Slack/Discord/generic webhook URL for alerts")
    dm.add_argument("--cycles", type=int, default=0,
                    help="max cycles (0 = infinite, default: 0)")
    dm.set_defaults(func=cmd_daemon)

    mn = sub.add_parser("minimize",
                        help="shrink bypass findings to their minimal form (chain reduction + text trimming)")
    _add_target_args(mn)
    mn.add_argument("--payload", default="", help="single payload to minimize")
    mn.add_argument("--seed", default="", help="original seed before mutation (for chain replay)")
    mn.add_argument("--chain", default="", help="comma-separated mutator chain (e.g. base64,url_encode)")
    mn.add_argument("--findings", default="", help="JSONL from `waffen bypass --out` — minimize all")
    mn.add_argument("--param", default="q")
    mn.add_argument("--inject", default="query", choices=["query", "body", "json"])
    mn.add_argument("--method", default="GET")
    mn.add_argument("--no-trim", action="store_true", help="skip text trimming (chain reduction only)")
    mn.set_defaults(func=cmd_minimize)

    df = sub.add_parser("diff",
                        help="differential testing: compare WAF vs origin, or WAF vs WAF (multi-target)")
    df.add_argument("--waf", default="", help="WAF-fronted target URL (two-target mode)")
    df.add_argument("--origin", default="", help="bare origin target URL (two-target mode)")
    df.add_argument("--targets", default="",
                    help="multi-WAF mode: 'Name1=URL1,Name2=URL2,...' — compare 2+ WAFs")
    df.add_argument("--corpus", action="store_true",
                    help="use full payload corpus instead of KB seeds")
    df.add_argument("--path", default="/", help="shared request path (default: /)")
    df.add_argument("--waf-path", default="", help="override path for WAF target only")
    df.add_argument("--origin-path", default="", help="override path for origin target only")
    df.add_argument("--param", default="q", help="parameter name (default: q)")
    df.add_argument("--inject", default="query", choices=["query", "body", "json"],
                    help="where to inject (default: query)")
    df.add_argument("--method", default="GET", help="HTTP method (default: GET)")
    df.add_argument("--class", dest="attack_class", default="sqli",
                    help="attack class(es) for KB seeds, comma-separated (default: sqli)")
    df.add_argument("--findings", default="",
                    help="JSONL from `waffen bypass --out` to re-test differentially")
    df.add_argument("--timeout", type=int, default=15)
    df.add_argument("--tls-verify", action="store_true")
    df.add_argument("--block-signature", default="")
    df.add_argument("--header", "-H", action="append", default=None)
    df.add_argument("--cookie", default="")
    df.add_argument("--out", default="", help="write diff report JSONL here")
    df.set_defaults(func=cmd_diff)

    gql = sub.add_parser("graphql", help="GraphQL attack techniques: introspection, batching, alias flood")
    _add_target_args(gql)
    gql.add_argument("--payload", default="", help="injection payload")
    gql.add_argument("--introspect", action="store_true", help="probe for schema introspection")
    gql.add_argument("--batch", action="store_true", help="batching bypass (payload in 2nd query)")
    gql.add_argument("--alias-flood", action="store_true", help="alias flood (N copies in aliases)")
    gql.add_argument("--alias-count", "-n", type=int, default=50, help="alias count (default: 50)")
    gql.add_argument("--directive", action="store_true", help="directive injection (@include/@skip)")
    gql.add_argument("--persisted", action="store_true", help="persisted query hash bypass (APQ)")
    gql.add_argument("--field-leak", action="store_true", help="field suggestion leak")
    gql.add_argument("--all", dest="all_techniques", action="store_true", help="run all techniques")
    gql.set_defaults(func=cmd_graphql)

    wsp = sub.add_parser("ws", help="WebSocket attack techniques: frame injection, binary, fragmentation")
    _add_target_args(wsp)
    wsp.add_argument("--payload", default="", help="injection payload")
    wsp.add_argument("--ws-path", default="/socket.io/?EIO=4&transport=websocket",
                     help="WebSocket upgrade path (default: socket.io)")
    wsp.add_argument("--text", action="store_true", help="text frame injection")
    wsp.add_argument("--binary", action="store_true", help="binary frame injection")
    wsp.add_argument("--fragment", action="store_true", help="fragmented frame injection")
    wsp.add_argument("--upgrade", action="store_true", help="upgrade URL injection")
    wsp.add_argument("--all", dest="all_techniques", action="store_true", help="run all techniques")
    wsp.set_defaults(func=cmd_ws)

    sc = sub.add_parser("sidechannel",
                        help="timing-based side-channel analysis — extract WAF internal scoring and rule structure")
    _add_target_args(sc)
    sc.add_argument("--param", default="q", help="parameter to inject (default: q)")
    sc.add_argument("--inject", default="query", choices=["query", "body", "json"])
    sc.add_argument("--method", default="GET")
    sc.add_argument("--samples", type=int, default=5,
                    help="timing samples per payload (default: 5, more = more accurate)")
    sc.add_argument("--payloads", default="", help="file with custom payloads (one per line)")
    sc.add_argument("--out", default="", help="write side-channel report JSON here")
    sc.set_defaults(func=cmd_sidechannel)

    e = sub.add_parser("eval", help="score WAF coverage + false-positive rate over a corpus")
    _add_target_args(e)
    e.add_argument("--mock", action="store_true", help="use the built-in mock WAF")
    e.add_argument("--class", dest="attack_class", default="", help="attack class (KB seeds)")
    e.add_argument("--all-classes", action="store_true", help="all built-in KB seeds")
    e.add_argument("--corpus", default="", help="PayloadsAllTheThings-style dir to harvest payloads from")
    e.add_argument("--max-per-class", type=int, default=0, help="cap payloads per class (0 = all)")
    e.add_argument("--benign", default="", help="file of benign values for false-positive testing")
    e.add_argument("--param", default="q")
    e.add_argument("--method", default="GET")
    e.add_argument("--inject", default="query",
                   choices=["query", "path", "rawpath", "body", "json", "header", "cookie", "upload", "auto"])
    e.add_argument("--calibrate", action="store_true", help="learn block/pass signature first")
    e.add_argument("--concurrency", type=int, default=6)
    e.add_argument("--delay", type=float, default=0.0)
    e.add_argument("--out", default="", help="write coverage JSON (+ .through.txt gaps) here")
    e.add_argument("--html", default="", help="write a styled standalone HTML coverage report here")
    e.add_argument("--rules", action="store_true", help="print suggested WAF rules for coverage gaps")
    e.add_argument("--rules-out", default="", help="write suggested WAF rules (Markdown) here")
    e.add_argument("--find-cutoff", action="store_true",
                   help="binary-search the real body-inspection cutoff against the live target "
                        "(nowafpls-style; ignored with --mock)")
    e.add_argument("--cutoff-probes", type=int, default=12, help="max requests for --find-cutoff")
    e.set_defaults(func=cmd_eval)

    d = sub.add_parser("dataset", help="build a labelled attack+benign training set (for WAF training)")
    _add_target_args(d)
    d.add_argument("--mock", action="store_true", help="use the built-in mock WAF")
    d.add_argument("--class", dest="attack_class", default="", help="attack class (KB seeds)")
    d.add_argument("--all-classes", action="store_true", help="all built-in KB seeds")
    d.add_argument("--corpus", default="", help="PayloadsAllTheThings-style dir to harvest attacks from")
    d.add_argument("--max-per-class", type=int, default=0)
    d.add_argument("--benign", default="", help="file of benign values (label=benign); use an UN-banned source")
    d.add_argument("--param", default="q")
    d.add_argument("--method", default="GET")
    d.add_argument("--inject", default="query",
                   choices=["query", "path", "rawpath", "body", "json", "header", "cookie", "upload", "auto"])
    d.add_argument("--calibrate", action="store_true", help="learn block/pass signature first")
    d.add_argument("--concurrency", type=int, default=6)
    d.add_argument("--delay", type=float, default=0.0)
    d.add_argument("--canary", default="",
                   help="a known-BENIGN value to re-probe periodically (ban-onset detector); "
                        "only effective at --concurrency 1")
    d.add_argument("--canary-every", type=int, default=25)
    d.add_argument("--split", type=float, default=0.0, help="val fraction for a stratified train/val split")
    d.add_argument("--out", default="dataset", help="output prefix (writes <out>.jsonl/.csv)")
    d.set_defaults(func=cmd_dataset)

    fz = sub.add_parser("fuzz", help="high-speed wordlist-driven WAF testing (threaded keep-alive)")
    _add_target_args(fz)
    fz.add_argument("--param", default="q", help="parameter to fuzz (default: q)")
    fz.add_argument("--inject", default="query", choices=["query", "body", "json", "path"],
                    help="where to inject (default: query)")
    fz.add_argument("--method", default="GET", help="HTTP method (default: GET)")
    fz.add_argument("--wordlist", "-w", default="", help="path to a wordlist file (one payload per line)")
    fz.add_argument("--builtin", default="", choices=["sqli", "xss", "path", "param"],
                    help="use a built-in wordlist instead of --wordlist")
    fz.add_argument("--corpus", default="", help="use the full corpus for this attack class (e.g. sqli)")
    fz.add_argument("-c", "--concurrency", type=int, default=50, help="number of threads (default: 50)")
    fz.add_argument("-mc", default="", help="match HTTP status codes (comma-sep, e.g. 200,500)")
    fz.add_argument("-fc", default="", help="filter (hide) HTTP status codes (comma-sep, e.g. 403)")
    fz.add_argument("-ms", type=int, default=-1, help="match response size (bytes)")
    fz.add_argument("-fs", type=int, default=-1, help="filter (hide) response size (bytes)")
    fz.add_argument("-mr", default="", help="match regex in response body")
    fz.add_argument("--out", default="", help="write results JSONL here")
    fz.set_defaults(func=cmd_fuzz)

    bm = sub.add_parser("benchmark",
                        help="standardized WAF benchmark — detection rate, FP rate, letter grade (SSL Labs for WAFs)")
    _add_target_args(bm)
    bm.add_argument("--param", default="q", help="parameter to inject (default: q)")
    bm.add_argument("--inject", default="query", choices=["query", "body", "json"])
    bm.add_argument("--method", default="GET")
    bm.add_argument("--classes", default="",
                    help="comma-separated attack classes (default: all standard classes)")
    bm.add_argument("--no-benign", action="store_true",
                    help="skip false-positive testing with benign payloads")
    bm.add_argument("--waf-name", default="", help="WAF name for the report")
    bm.add_argument("--profile", default="",
                    help="pre-built profile: crs-pl1, crs-pl2, crs-pl3, crs-pl4, redeye")
    bm.add_argument("--compare", nargs=2, metavar="FILE",
                    help="compare two benchmark JSON files side-by-side")
    bm.add_argument("--html", default="", help="write HTML benchmark report here")
    bm.add_argument("--out", default="", help="write benchmark JSON here")
    bm.add_argument("--list-profiles", action="store_true",
                    help="list pre-built WAF profiles and exit")
    bm.set_defaults(func=cmd_benchmark)

    sm = sub.add_parser("smuggle", help="experimental: timing-based HTTP request-smuggling (desync) probes")
    _add_target_args(sm)
    sm.add_argument("--stall-factor", type=float, default=3.0,
                    help="flag a probe whose response is this-times slower than baseline")
    sm.set_defaults(func=cmd_smuggle)

    sp = sub.add_parser("score-probe",
                        help="map WAF scoring-engine detection thresholds and boundary payloads")
    _add_target_args(sp)
    sp.add_argument("--param", default="q", help="parameter to inject (default: q)")
    sp.add_argument("--inject", default="query", choices=["query", "body", "json"],
                    help="where to place the probe (default: query)")
    sp.add_argument("--method", default="GET", help="HTTP method (default: GET)")
    sp.add_argument("--class", dest="attack_class", default="sqli",
                    choices=["sqli", "xss", "ssti"],
                    help="attack class to probe (default: sqli)")
    sp.add_argument("--calibrate", action="store_true",
                    help="learn the WAF block/pass signature first")
    sp.add_argument("--out", default="", help="write JSON score-probe report here")
    sp.set_defaults(func=cmd_score_probe)

    lp = sub.add_parser("libinjection-scan",
                        help="probe WAF for database-specific token blind spots (libinjection gaps)")
    _add_target_args(lp)
    lp.add_argument("--param", default="q", help="parameter to inject (default: q)")
    lp.add_argument("--inject", default="query", choices=["query", "body", "json"],
                    help="where to place the probe (default: query)")
    lp.add_argument("--method", default="GET", help="HTTP method (default: GET)")
    lp.add_argument("--engines", default="", help="comma-separated DB engines (default: all)")
    lp.add_argument("--out", default="", help="write JSON gap report here")
    lp.set_defaults(func=cmd_libinjection_scan)

    cvp = sub.add_parser("cve-probe",
                         help="probe which 2026 WAF-engine CVE primitives look exploitable on a target")
    _add_target_args(cvp)
    cvp.add_argument("--param", default="q", help="parameter to inject (default: q)")
    cvp.add_argument("--inject", default="query", choices=["query", "body", "json"],
                     help="where to place the probe (default: query)")
    cvp.add_argument("--method", default="GET", help="HTTP method for query inject (default: GET)")
    cvp.set_defaults(func=cmd_cve_probe)

    cal = sub.add_parser("calibrate",
                         help="learn WAF block/pass signature, or --cluster to discover full response taxonomy")
    _add_target_args(cal)
    cal.add_argument("--param", default="q", help="parameter to inject (default: q)")
    cal.add_argument("--inject", default="query", choices=["query", "body", "json"])
    cal.add_argument("--method", default="GET")
    cal.add_argument("--cluster", action="store_true",
                     help="discover full response taxonomy via k-means clustering (PASS/BLOCK/CHALLENGE/RATELIMIT)")
    cal.add_argument("--out", default="", help="write calibration/cluster report JSON here")
    cal.set_defaults(func=cmd_calibrate)

    rm = sub.add_parser("rulemap",
                        help="reverse-engineer WAF rule set via black-box probing (CRS rule mapping)")
    _add_target_args(rm)
    rm.add_argument("--param", default="q", help="parameter to inject (default: q)")
    rm.add_argument("--inject", default="query", choices=["query", "body", "json"],
                    help="where to place the probe (default: query)")
    rm.add_argument("--method", default="GET", help="HTTP method (default: GET)")
    rm.add_argument("--out", default="", help="write rule map report JSON here")
    rm.set_defaults(func=cmd_rulemap)

    fp = sub.add_parser("fingerprint", help="identify the WAF in front of a target")
    _add_target_args(fp)
    fp.set_defaults(func=cmd_fingerprint)

    og = sub.add_parser("origin", help="discover origin server IP behind a WAF (DNS, MX, SPF, headers)")
    og.add_argument("--domain", "--target", required=True, dest="domain",
                    help="target domain (e.g. example.com)")
    og.add_argument("--verify", action="store_true",
                    help="verify each candidate by sending a request with Host header")
    og.add_argument("--out", default="", help="write origin report JSON here")
    og.set_defaults(func=cmd_origin)

    sq = sub.add_parser("sequence",
                        help="run multi-request attack sequences (split attacks across HTTP requests)")
    _add_target_args(sq)
    sq.add_argument("--list", dest="list_seqs", action="store_true",
                    help="list available built-in sequences")
    sq.add_argument("--run", default="", help="run a specific sequence by name")
    sq.add_argument("--all", dest="run_all", action="store_true",
                    help="run all built-in sequences")
    sq.add_argument("--payload", default="' OR 1=1--", help="payload to inject (default: ' OR 1=1--)")
    sq.add_argument("--out", default="", help="write results JSONL here")
    sq.set_defaults(func=cmd_sequence)

    disc = sub.add_parser("discover",
                          help="auto-discover WAF-inspected injection points on a target")
    _add_target_args(disc)
    disc.add_argument("--out", default="", help="write discovery report JSON here")
    disc.set_defaults(func=cmd_discover)

    df = sub.add_parser("defend",
                        help="generate deployable WAF rules from bypass findings (ModSecurity/NAXSI/Cloudflare/AWS)")
    df.add_argument("--findings", required=True, help="JSONL from `waffen bypass --out`")
    df.add_argument("--engine", default="modsecurity",
                    choices=["modsecurity", "naxsi", "cloudflare", "aws", "all"],
                    help="WAF engine format (default: modsecurity)")
    df.add_argument("--out", default="", help="output file (or directory for --engine all)")
    df.set_defaults(func=cmd_defend)

    rp = sub.add_parser("report",
                        help="generate professional HTML pentest report from findings")
    rp.add_argument("--findings", required=True, help="JSONL from `waffen bypass --out`")
    rp.add_argument("--html", required=True, metavar="FILE", help="output HTML report path")
    rp.add_argument("--title", default="WAF Bypass Assessment Report")
    rp.add_argument("--author", default="WAFFEN Automated Assessment")
    rp.add_argument("--target", default="")
    rp.add_argument("--classification", default="CONFIDENTIAL")
    rp.add_argument("--summary-only", action="store_true",
                    help="generate a 1-page summary card instead of full report")
    rp.add_argument("--csv", default="", metavar="FILE",
                    help="also write findings CSV here (for spreadsheet users)")
    rp.set_defaults(func=cmd_report)

    an = sub.add_parser("analyze", help="analyze a collected dataset/log JSONL offline (no network)")
    an.add_argument("log", help="path to a .jsonl log written by `waffen dataset`")
    an.add_argument("--html", default="", help="write a styled HTML coverage report here")
    an.add_argument("--rules", action="store_true", help="print suggested WAF rules for coverage gaps")
    an.add_argument("--rules-out", default="", help="write suggested WAF rules (Markdown) here")
    an.add_argument("--balanced-out", default="",
                    help="write a class-balanced training set derived from this log (prefix)")
    an.add_argument("--balance", type=float, default=1.0,
                    help="max malicious:benign ratio for --balanced-out (default 1.0)")
    an.add_argument("--split", type=float, default=0.0,
                    help="val fraction for a stratified train/val split of --balanced-out")
    an.set_defaults(func=cmd_analyze)

    kb = sub.add_parser("kb-update", help="check/apply a KB update from a configured source")
    kb.add_argument("--name", default="", help="source name (required with --kind)")
    kb.add_argument("--kind", default="", choices=["", "github_release", "manifest"],
                    help="where to check for an update")
    kb.add_argument("--repo", default="", help="owner/name, for --kind github_release")
    kb.add_argument("--manifest-url", default="", help="manifest JSON URL, for --kind manifest")
    kb.add_argument("--dest", default="./waffen_kb", help="local directory to store KB state in")
    kb.set_defaults(func=cmd_kb_update)

    pf = sub.add_parser("profile", help="show or manage a saved target profile")
    pf.add_argument("file", help="path to a profile .json file")
    pf.add_argument("--show", action="store_true", default=True,
                    help="print profile summary (default)")
    pf.add_argument("--json", action="store_true",
                    help="print the full profile as JSON")
    pf.set_defaults(func=cmd_profile)

    m = sub.add_parser("mutators", help="list the built-in mutation library")
    m.add_argument("--class", dest="attack_class", default="", help="only mutators valid for this class")
    m.set_defaults(func=cmd_mutators)

    tr = sub.add_parser("transforms", help="list the request-level transforms")
    tr.set_defaults(func=cmd_transforms)

    cp = sub.add_parser("corpus", help="show the built-in 3000+ payload corpus")
    cp.add_argument("--class", dest="attack_class", default="", help="show payloads for this class")
    cp.add_argument("--count", dest="count_only", action="store_true", help="show count only")
    cp.set_defaults(func=cmd_corpus)

    oob = sub.add_parser("oob", help="out-of-band callback server for blind vulnerability verification "
                         "(runs in FOREGROUND — use a separate terminal for bypass commands)")
    oob.add_argument("--listen", default="127.0.0.1", help="listen address (default: 127.0.0.1)")
    oob.add_argument("--port", type=int, default=8888, help="listen port (default: 8888)")
    oob.add_argument("--external", default="", help="external hostname/IP that the target can reach")
    oob.add_argument("--out", default="", help="write callbacks JSONL here on exit")
    oob.add_argument("--generate", action="store_true", help="generate one callback URL and exit")
    oob.add_argument("--context", default="", help="context label for --generate")
    oob.add_argument("--payloads", action="store_true", help="show OOB payloads for each class and exit")
    oob.add_argument("--payloads-class", default="", help="comma-separated classes for --payloads")
    oob.set_defaults(func=cmd_oob)

    pl = sub.add_parser("plugin", help="manage plugins (~/.waffen/plugins/)")
    pl.add_argument("plugin_action", choices=["list", "create", "info", "disable", "enable"],
                    help="action: list / create / info / disable / enable")
    pl.add_argument("name", nargs="?", default="", help="plugin name (for create/info/disable/enable)")
    pl.add_argument("--author", default="me", help="author name (for create)")
    pl.add_argument("--desc", default="", help="description (for create)")
    pl.set_defaults(func=cmd_plugin)

    ex = sub.add_parser("exploit",
                        help="exploit a confirmed SQLi bypass — extract data through the WAF")
    _add_target_args(ex)
    ex.add_argument("--param", default="q", help="parameter name (default: q)")
    ex.add_argument("--inject", default="query", choices=["query", "body", "json"],
                    help="where to inject (default: query)")
    ex.add_argument("--method", default="GET", help="HTTP method (default: GET)")
    ex.add_argument("--bypass-payload", default="", help="the WAF-bypassing payload (required)")
    ex.add_argument("--bypass-chain", default="",
                    help="comma-separated mutation chain that produced the bypass")
    ex.add_argument("--auto", action="store_true",
                    help="auto-exploit: detect DBMS + technique, enumerate, extract first table")
    ex.add_argument("--tables", action="store_true", help="enumerate database tables")
    ex.add_argument("--columns", action="store_true", help="enumerate columns (requires --table)")
    ex.add_argument("--dump", action="store_true", help="extract rows (requires --table)")
    ex.add_argument("--dump-columns", default="", help="specific columns to dump (comma-sep)")
    ex.add_argument("--table", default="", help="target table name")
    ex.add_argument("--query", default="", help="raw SQL query to extract a single value")
    ex.add_argument("--limit", type=int, default=10, help="max rows to extract (default: 10)")
    ex.add_argument("--out", default="", help="write extraction results JSON here")
    ex.set_defaults(func=cmd_exploit)

    gr = sub.add_parser("grammar",
                        help="generate syntactically valid payloads from context-free grammars")
    gr.add_argument("--type", default="sqli", choices=["sqli", "sql", "xss", "ssti"],
                    help="grammar type (default: sqli)")
    gr.add_argument("--generate", "-n", type=int, default=20,
                    help="number of payloads to generate (default: 20)")
    gr.add_argument("--coverage", action="store_true",
                    help="generate payloads covering all grammar rules")
    gr.add_argument("--target-symbols", default="",
                    help="comma-separated symbols that must appear in payloads")
    gr.add_argument("--max-depth", type=int, default=10,
                    help="max grammar expansion depth (default: 10)")
    gr.add_argument("--seed", type=int, default=None,
                    help="random seed for reproducibility")
    gr.add_argument("--out", default="", help="write payloads to file (one per line)")
    gr.set_defaults(func=cmd_grammar)

    se = sub.add_parser("semantic",
                        help="semantic preservation engine — generate SQL-equivalent payloads "
                             "that express the same logic in different syntax")
    se.add_argument("--payload", default="",
                    help="payload to expand into semantic equivalents")
    se.add_argument("--mode", default="tautology",
                    choices=["tautology", "union", "blind", "time"],
                    help="generation mode when no --payload given (default: tautology)")
    se.add_argument("--dbms", default="generic",
                    choices=["generic", "sqlite", "mysql", "postgresql", "mssql"],
                    help="target database engine (default: generic)")
    se.add_argument("--count", "-n", type=int, default=50,
                    help="max payloads to generate (default: 50)")
    se.add_argument("--columns", type=int, default=3,
                    help="column count for UNION mode (default: 3)")
    se.add_argument("--out", default="", help="write payloads to file (one per line)")
    se.set_defaults(func=cmd_semantic)

    sy = sub.add_parser("synthesize",
                        help="LLM-guided payload synthesis — generate context-aware bypass payloads "
                             "using Claude/GPT (requires API key)")
    _add_target_args(sy)
    sy.add_argument("--param", default="q", help="parameter name (default: q)")
    sy.add_argument("--class", dest="attack_class", default="sqli",
                    help="attack class: sqli, xss, ssti, ssrf, xxe, cmdi (default: sqli)")
    sy.add_argument("--profile", default="", help="load WAF context from a saved target profile")
    sy.add_argument("--provider", default="anthropic", choices=["anthropic", "openai"],
                    help="LLM provider (default: anthropic)")
    sy.add_argument("--model", default="claude-sonnet-4-20250514",
                    help="model name (default: claude-sonnet-4-20250514)")
    sy.add_argument("--api-key", default="", help="API key (or set ANTHROPIC_API_KEY / OPENAI_API_KEY env var)")
    sy.add_argument("--count", type=int, default=50, help="number of payloads to generate (default: 50)")
    sy.add_argument("--temperature", type=float, default=0.8, help="generation temperature (default: 0.8)")
    sy.add_argument("--detected", default="", help="comma-separated detected keywords (manual context)")
    sy.add_argument("--invisible", default="", help="comma-separated invisible keywords (manual context)")
    sy.add_argument("--gaps", default="", help="comma-separated gap tokens (manual context)")
    sy.add_argument("--db", default="", help="backend DB engine: sqlite, mysql, postgresql, mssql")
    sy.add_argument("--waf-name", default="", help="WAF name for context")
    sy.add_argument("--out", default="", help="write payloads to file (one per line)")
    sy.set_defaults(func=cmd_synthesize)

    pln = sub.add_parser("plan",
                         help="multi-step attack planner — model target as graph, find optimal attack chains")
    _add_target_args(pln)
    pln.add_argument("--param", default="q", help="primary parameter")
    pln.add_argument("--goal", default="",
                     help="attack goal: dump_database, admin_access, read_file, rce, xss_stored, account_takeover")
    pln.add_argument("--discover", action="store_true",
                     help="probe the live target to map WAF protection per endpoint")
    pln.add_argument("--execute", action="store_true",
                     help="execute the plan (dry-run without this flag)")
    pln.add_argument("--list-goals", action="store_true", help="list available attack goals")
    pln.add_argument("--out", default="", help="write plan JSON here")
    pln.set_defaults(func=cmd_plan)

    dt = sub.add_parser("dtree",
                        help="fingerprint the WAF processing pipeline — decode order, comment "
                             "stripping, case handling, libinjection, scoring engine")
    _add_target_args(dt)
    dt.add_argument("--param", default="q", help="parameter to inject (default: q)")
    dt.add_argument("--inject", default="query", choices=["query", "body", "json"],
                    help="where to inject (default: query)")
    dt.add_argument("--method", default="GET", help="HTTP method (default: GET)")
    dt.add_argument("--out", default="", help="write decision tree JSON here")
    dt.set_defaults(func=cmd_dtree)

    sc = sub.add_parser("synthesize-config",
                        help="generate optimal deployable WAF config from bypass findings + rulemap")
    sc.add_argument("--findings", default="", help="JSONL from `waffen bypass --out`")
    sc.add_argument("--rulemap", default="", help="JSON from `waffen rulemap --out`")
    sc.add_argument("--benchmark", default="", help="JSON from `waffen benchmark --out`")
    sc.add_argument("--false-positives", default="", help="file of known false-positive payloads (one per line)")
    sc.add_argument("--engine", default="modsecurity", choices=["modsecurity", "nginx"],
                    help="target WAF engine (default: modsecurity)")
    sc.add_argument("--target-grade", default="A", choices=["A+", "A", "B+", "B", "C", "D", "F"],
                    help="desired security grade (default: A)")
    sc.add_argument("--out", default="", help="output directory for config files")
    sc.set_defaults(func=cmd_synthesize_config)

    v = sub.add_parser("version", help="print version")
    v.set_defaults(func=cmd_version)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    from .mutate import load_plugins
    load_plugins()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
