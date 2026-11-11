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
    if args.payload:
        seeds.append((args.attack_class or "", args.payload))
    elif args.attack_class:
        for p in kb_seeds.seeds_for(args.attack_class):
            seeds.append((args.attack_class, p))
    if args.all_classes:
        for c in kb_seeds.classes():
            for p in kb_seeds.seeds_for(c):
                seeds.append((c, p))
    return seeds


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
    )
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

    if args.canary:
        print(ui.gray(f"  (canary: re-probing a known-benign value every {args.canary_every} sends; "
                      "only active at --concurrency 1 — see --help)"))

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
        transport=args.transport, on_event=ev,
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
    except Exception:
        pass  # plan is a bonus; never let it break a plain fingerprint run
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


def cmd_version(args) -> int:
    print(ui.banner(__version__, force=True))
    print(f"  waffen {__version__}")
    return 0


def _add_target_args(p):
    p.add_argument("--target", default="", help="base URL of a target you own/are authorized to test")
    p.add_argument("--path", default="/", help="request path on target")
    p.add_argument("--timeout", type=int, default=15)
    p.add_argument("--block-signature", default="Request blocked by RedEye")
    p.add_argument("--tls-verify", action="store_true",
                   help="enforce TLS certificate verification (default: off — for self-signed test targets)")
    p.add_argument("--header", "-H", action="append", default=None, metavar="'Name: Value'",
                   help="extra request header, e.g. 'Authorization: Bearer ...' (repeatable). "
                        "Threads through every inject mode and transform — run a search behind auth")
    p.add_argument("--cookie", default="", metavar="'a=1; b=2'",
                   help="cookie string sent with every request (session auth)")
    p.add_argument("--transport", default="curl", choices=["curl", "pooled"],
                   help="request transport: 'curl' (default, uniform, required for request "
                        "transforms) or 'pooled' (keep-alive http.client — faster on long runs; "
                        "falls back to curl for transform sends)")


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
    b.add_argument("--param", default="q", help="param/header/cookie name")
    b.add_argument("--method", default="GET")
    b.add_argument("--inject", default="query",
                   choices=["query", "path", "rawpath", "body", "json", "header", "cookie", "upload", "auto"])
    b.add_argument("--strategy", default="beam", choices=["beam", "genetic", "bestfirst", "mcts"],
                   help="search strategy")
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
    b.add_argument("--verbose", action="store_true", help="print search events")
    b.add_argument("--out", default="", help="write findings JSONL here")
    b.add_argument("--rules", action="store_true",
                   help="print suggested WAF rules for verified-exploitable findings")
    b.add_argument("--rules-out", default="", help="write suggested WAF rules (Markdown) here")
    b.add_argument("--nuclei", default="", metavar="DIR",
                   help="write Nuclei v3 differential WAF-audit templates (one per verified bypass) to DIR")
    b.set_defaults(func=cmd_bypass)

    a = sub.add_parser("auto",
                       help="guided wizard — answers a few questions, runs the full pipeline automatically")
    a.add_argument("--url", default="", help="target URL (skips the interactive prompt)")
    a.add_argument("--path", default="", help="request path")
    a.add_argument("--param", default="q", help="parameter name")
    a.add_argument("-y", "--yes", action="store_true",
                   help="non-interactive: accept all defaults (requires --url)")
    a.add_argument("--out", default="", help="write findings JSONL here")
    a.add_argument("--timeout", type=int, default=10)
    a.add_argument("--transport", default="curl", choices=["curl", "pooled"])
    a.add_argument("--tls-verify", action="store_true")
    a.add_argument("--block-signature", default="Request blocked by RedEye")
    a.add_argument("--header", "-H", action="append", default=None)
    a.add_argument("--cookie", default="")
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

    fp = sub.add_parser("fingerprint", help="identify the WAF in front of a target")
    _add_target_args(fp)
    fp.set_defaults(func=cmd_fingerprint)

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

    m = sub.add_parser("mutators", help="list the built-in mutation library")
    m.add_argument("--class", dest="attack_class", default="", help="only mutators valid for this class")
    m.set_defaults(func=cmd_mutators)

    tr = sub.add_parser("transforms", help="list the request-level transforms")
    tr.set_defaults(func=cmd_transforms)

    v = sub.add_parser("version", help="print version")
    v.set_defaults(func=cmd_version)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
