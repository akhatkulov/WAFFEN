"""Write bypass-search findings to JSONL and print a readable summary."""
from __future__ import annotations

import json
from pathlib import Path

from ..search.beam import SearchResult


def write_jsonl(results: list[SearchResult], path: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w") as f:
        for r in results:
            for find in r.findings:
                rec = find.as_dict()
                rec["seed"] = r.seed
                rec["requests"] = r.requests
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def write_engine_jsonl(runs, path: str) -> None:
    """Write findings from a full engine sweep (with transform + verification)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w") as f:
        for run in runs:
            for find in run.result.findings:
                rec = find.as_dict()
                rec["seed"] = run.result.seed
                rec["request_transform"] = run.transform
                rec["requests"] = run.result.requests
                v = run.verifications.get(find.payload)
                if v is not None:
                    rec["verified_exploitable"] = getattr(v, "exploitable", None)
                    rec["verify_confidence"] = getattr(v, "confidence", None)
                    rec["verify_reason"] = getattr(v, "reason", None)
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def print_engine_summary(runs) -> None:
    from .. import ui
    total_find = sum(len(r.result.findings) for r in runs)
    total_req = sum(r.result.requests for r in runs)
    confirmed = 0
    print("\n" + ui.rule("BYPASS SWEEP"))
    for run in runs:
        res = run.result
        head = (ui.gray(f"[{run.attack_class or '?'}]") + " via " + ui.cyan(f"{run.transform}")
                + ui.gray(f"  seed={res.seed[:40]!r}"))
        if not res.findings:
            print("  " + ui.gray("○ ") + head + ui.gray(f"  → no bypass ({res.requests} req)"))
            continue
        print("  " + ui.bold(ui.green("● ")) + head
              + "  → " + ui.bold(f"{len(res.findings)} bypass(es)") + ui.gray(f" ({res.requests} req)"))
        for find in res.findings:
            chain = ui.cyan(" → ".join(find.chain)) if find.chain else ui.gray("(raw)")
            vtag = ui.verified_tag(find.verified, find.confidence)
            if find.verified:
                confirmed += 1
            print(f"       {ui.verdict('THROUGH')} {find.code}  via  {chain}{vtag}")
            print("         " + ui.gray(find.payload[:160]))
    print("  " + ui.gray("─" * 54))
    tail = (", " + ui.red(f"{confirmed} verified exploitable")) if any(r.verifications for r in runs) else ""
    print("  " + ui.bold(f"{total_find} bypass(es)") + ui.gray(f" across {len(runs)} run(s), {total_req} requests total") + tail)


def print_summary(results: list[SearchResult]) -> None:
    total_find = sum(len(r.findings) for r in results)
    total_req = sum(r.requests for r in results)
    print("\n=== WAFFEN bypass-search summary ===")
    for r in results:
        tag = f"{len(r.findings)} bypass(es)" if r.findings else "no bypass"
        print(f"  [{r.attack_class or '?'}] seed={r.seed!r}  baseline={r.baseline_verdict}  "
              f"-> {tag}  ({r.requests} req)")
        for find in r.findings:
            chain = " -> ".join(find.chain) if find.chain else "(raw, already through)"
            print(f"       THROUGH {find.code}  via  {chain}")
            print(f"         {find.payload}")
    print(f"  ----------------------------------------------------")
    print(f"  {total_find} bypass(es) across {len(results)} seed(s), {total_req} requests total")
