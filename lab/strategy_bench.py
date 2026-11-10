"""Benchmark the 4 search strategies head-to-head under an equal request budget,
against the CRS lab SQL class. Honest metric: distinct THROUGH (WAF-evading) payloads
found per fixed budget, plus requests actually spent and wall-clock."""
import time
from waffen.core.oracle import Target
from waffen.engine import run_bypass
from waffen.kb import seeds as kb

TARGET = Target(base_url="http://localhost:18080", path="/rest/products/search",
                param="q", inject="query", block_signature="nginx")
SEEDS = [("SQL Injection", p) for p in kb.seeds_for("SQL Injection")]
BUDGET = 150

print(f"target=CRS :18080  class=SQL  seeds={len(SEEDS)}  budget={BUDGET}/run  (calibrated)\n")
print(f"{'strategy':10} {'distinct bypasses':18} {'requests':9} {'time(s)':8} {'bypass/1k-req':12}")
print("-" * 62)
rows = []
for strat in ("beam", "genetic", "bestfirst", "mcts"):
    t0 = time.monotonic()
    runs = run_bypass(TARGET, SEEDS, strategy=strat, do_calibrate=True,
                      max_requests=BUDGET, transform_names={"identity"})
    dt = time.monotonic() - t0
    found = set()
    reqs = 0
    for r in runs:
        reqs += getattr(r.result, "requests", 0) or 0
        for f in r.result.findings:
            found.add(f.payload)
    eff = (len(found) / reqs * 1000) if reqs else 0.0
    rows.append((strat, len(found), reqs, dt, eff))
    print(f"{strat:10} {len(found):<18} {reqs:<9} {dt:<8.1f} {eff:<12.1f}")

print("\n" + "-" * 62)
best = max(rows, key=lambda r: (r[1], r[4]))
print(f"most distinct bypasses: {best[0]} ({best[1]})")
best_eff = max(rows, key=lambda r: r[4])
print(f"most efficient (bypass/1k-req): {best_eff[0]} ({best_eff[4]:.1f})")
