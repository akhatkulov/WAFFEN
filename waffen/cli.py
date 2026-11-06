"""WAFFEN command-line interface.

WAFFEN is a WAF evaluation / bypass-research tool for targets you own or are
authorized to test. It searches for evasion *paths* (mutation chains + request
transforms) against a WAF so its coverage gaps can be found and fixed.

Subcommands:
  bypass       search for evasion chains against a target (or a mock WAF)
  fingerprint  identify the WAF in front of a target
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

    runs = run_bypass(
        target, seeds,
        strategy=args.strategy, transform_names=transform_names, all_mutators=args.all_mutators,
        width=args.width, depth=args.depth,
        pop_size=args.pop_size, generations=args.generations, branch=args.branch,
        iterations=args.iterations, rollout_depth=args.rollout_depth, delay=args.delay,
        max_requests=args.max_requests, stop_on_first=args.stop_on_first,
        do_calibrate=args.calibrate, do_learn=args.learn,
        do_verify=args.verify and not args.mock, sender=sender, on_event=ev,
    )
    report.print_engine_summary(runs)
    if args.out:
        report.write_engine_jsonl(runs, args.out)
        print(f"\n[*] findings written to {args.out}")
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
                    timeout=args.timeout, tls_verify=args.tls_verify)
    sender = make_mock_sender(block_signature=args.block_signature) if args.mock else None

    calibration = None
    if args.calibrate:
        try:
            from .verify.calibrate import calibrate
            from .core.oracle import Oracle as _O
            calibration = calibrate(_O(target, sender=sender))
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

    res = run_eval(target, cases, benign=benign, calibration=calibration, sender=sender,
                   concurrency=args.concurrency, delay=args.delay)

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
                    timeout=args.timeout, tls_verify=args.tls_verify)
    sender = make_mock_sender(block_signature=args.block_signature) if args.mock else None
    calibration = None
    if args.calibrate:
        try:
            from .verify.calibrate import calibrate
            from .core.oracle import Oracle as _O
            calibration = calibrate(_O(target, sender=sender))
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

    out = build_dataset(target, cases, benign=benign, calibration=calibration, sender=sender,
                        concurrency=args.concurrency, delay=args.delay)
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
                    block_signature=args.block_signature)
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
                   choices=["query", "path", "rawpath", "body", "json", "header", "cookie"])
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
    b.add_argument("--verbose", action="store_true", help="print search events")
    b.add_argument("--out", default="", help="write findings JSONL here")
    b.set_defaults(func=cmd_bypass)

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
                   choices=["query", "path", "rawpath", "body", "json", "header", "cookie"])
    e.add_argument("--calibrate", action="store_true", help="learn block/pass signature first")
    e.add_argument("--concurrency", type=int, default=6)
    e.add_argument("--delay", type=float, default=0.0)
    e.add_argument("--out", default="", help="write coverage JSON (+ .through.txt gaps) here")
    e.add_argument("--html", default="", help="write a styled standalone HTML coverage report here")
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
                   choices=["query", "path", "rawpath", "body", "json", "header", "cookie"])
    d.add_argument("--calibrate", action="store_true", help="learn block/pass signature first")
    d.add_argument("--concurrency", type=int, default=6)
    d.add_argument("--delay", type=float, default=0.0)
    d.add_argument("--split", type=float, default=0.0, help="val fraction for a stratified train/val split")
    d.add_argument("--out", default="dataset", help="output prefix (writes <out>.jsonl/.csv)")
    d.set_defaults(func=cmd_dataset)

    sm = sub.add_parser("smuggle", help="experimental: timing-based HTTP request-smuggling (desync) probes")
    _add_target_args(sm)
    sm.add_argument("--stall-factor", type=float, default=3.0,
                    help="flag a probe whose response is this-times slower than baseline")
    sm.set_defaults(func=cmd_smuggle)

    fp = sub.add_parser("fingerprint", help="identify the WAF in front of a target")
    _add_target_args(fp)
    fp.set_defaults(func=cmd_fingerprint)

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
