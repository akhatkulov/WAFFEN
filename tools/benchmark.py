#!/usr/bin/env python3
"""Benchmark the search strategies head-to-head on the offline mock WAF.

Reports, per seed, how many requests each strategy spent and whether it found a
bypass (and the shortest chain). Lets us tune width/depth/branch/pop and prove
best-first/genetic reach a bypass with fewer requests than beam.

    python3 tools/benchmark.py
    python3 tools/benchmark.py --budget 300 --class "XSS Injection"
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from waffen.core.mock import make_mock_sender
from waffen.core.oracle import Oracle, Target
from waffen.mutate import REGISTRY
from waffen.kb import seeds as kb_seeds
from waffen.search.beam import beam_search
from waffen.search.genetic import genetic_search
from waffen.search.bestfirst import best_first_search
from waffen.search.mcts import mcts_search


def _fresh_oracle():
    return Oracle(Target(base_url="mock://bench"), sender=make_mock_sender())


def run(seed, cls, budget):
    ms = REGISTRY.select(attack_class=cls) or REGISTRY.all()
    # fair cross-strategy metric: requests to the FIRST bypass (stop_on_first)
    rows = []
    for name, fn in (
        ("beam", lambda o: beam_search(o, seed, ms, width=6, depth=4,
                                       max_requests=budget, attack_class=cls, stop_on_first=True)),
        ("genetic", lambda o: genetic_search(o, seed, ms, pop_size=20, generations=8,
                                             max_requests=budget, attack_class=cls, stop_on_first=True)),
        ("bestfirst", lambda o: best_first_search(o, seed, ms, branch=4,
                                                  max_requests=budget, attack_class=cls, stop_on_first=True)),
        ("mcts", lambda o: mcts_search(o, seed, ms, iterations=budget, rollout_depth=3,
                                       max_requests=budget, attack_class=cls, stop_on_first=True)),
    ):
        o = _fresh_oracle()
        res = fn(o)
        best_len = min((len(f.chain) for f in res.findings), default=None)
        rows.append((name, res.requests, len(res.findings), best_len))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--budget", type=int, default=400)
    ap.add_argument("--class", dest="cls", default="")
    args = ap.parse_args()

    classes = [args.cls] if args.cls else kb_seeds.classes()
    print(f"{'seed':44} {'strategy':10} {'reqs':>5} {'finds':>5} {'bestlen':>7}")
    print("-" * 78)
    agg = {}
    for cls in classes:
        for seed in kb_seeds.seeds_for(cls):
            for name, reqs, finds, blen in run(seed, cls, args.budget):
                print(f"{seed[:42]!r:44} {name:10} {reqs:5d} {finds:5d} "
                      f"{(blen if blen is not None else '-'):>7}")
                a = agg.setdefault(name, [0, 0, 0])
                a[0] += reqs; a[1] += finds; a[2] += (1 if finds else 0)
            print()
    print("=" * 78)
    print(f"{'STRATEGY':10} {'total_reqs':>11} {'total_finds':>12} {'seeds_solved':>13}")
    for name, (r, f, s) in agg.items():
        print(f"{name:10} {r:11d} {f:12d} {s:13d}")


if __name__ == "__main__":
    main()
