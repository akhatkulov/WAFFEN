"""Offline analysis of a `dataset` JSONL log: coverage, FP rate, ban heuristic.

No network. Folds already-collected records into the same EvalResult that an
`eval` run produces, so report.html / report.rules consume it unchanged.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from ..eval.coverage import ClassScore, EvalResult
from .html import write_eval_html

MAX_THROUGH_SAMPLES = 50
BENIGN_BLOCK_THRESHOLD = 0.20
TAIL_FRACTION = 0.10
TAIL_MIN_RECORDS = 5        # tail must have at least this many records to be judged
TAIL_BLOCK_THRESHOLD = 0.95
HEAD_MAX_BLOCK = 0.90       # earlier records must be "mixed" (not already all-block)


def load_log(path) -> list[dict]:
    """Read a JSONL log; blank, malformed, or non-object lines are skipped."""
    records: list[dict] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if isinstance(obj, dict):
                records.append(obj)
    return records


def analyze(records) -> EvalResult:
    records = list(records)
    res = EvalResult()
    if records:
        res.target = str(records[0].get("url") or "")
    for r in records:
        verdict = r.get("verdict")
        if r.get("label") == "benign":
            res.benign_total += 1
            if verdict == "block":
                res.benign_blocked += 1
            continue
        if r.get("label") != "malicious":
            continue
        cls = str(r.get("attack_class") or "unknown")
        score = res.per_class.setdefault(cls, ClassScore())
        samples = res.through_samples.setdefault(cls, [])
        if verdict == "block":
            score.blocked += 1
        elif verdict == "pass":
            score.through += 1
            if len(samples) < MAX_THROUGH_SAMPLES:
                samples.append(r.get("text", ""))
        elif verdict == "unresolved":
            score.unresolved += 1
        elif verdict == "down":
            score.down += 1
    return res


@dataclass
class BanHeuristic:
    suspected: bool
    reason: str
    benign_block_rate: float
    tail_block_rate: float


def _block_rate(recs) -> float:
    return (sum(1 for r in recs if r.get("verdict") == "block") / len(recs)) if recs else 0.0


def ban_heuristic(records) -> BanHeuristic:
    """Best-effort ban-contamination check (heuristic, not proof)."""
    records = list(records)
    benign = [r for r in records if r.get("label") == "benign"]
    b_rate = _block_rate(benign)
    n_tail = max(1, int(len(records) * TAIL_FRACTION)) if records else 0
    tail = records[len(records) - n_tail:] if n_tail else []
    head = records[: len(records) - n_tail]
    t_rate = _block_rate(tail)
    h_rate = _block_rate(head)

    reasons = []
    if benign and b_rate > BENIGN_BLOCK_THRESHOLD:
        reasons.append(f"benign block rate is {b_rate:.0%} (> {BENIGN_BLOCK_THRESHOLD:.0%}); "
                       "benign traffic being blocked often means the source IP was banned")
    if (len(tail) >= TAIL_MIN_RECORDS and t_rate >= TAIL_BLOCK_THRESHOLD
            and head and h_rate < HEAD_MAX_BLOCK):
        reasons.append(f"last {len(tail)} records are {t_rate:.0%} blocked while earlier "
                       f"records were mixed ({h_rate:.0%} blocked); a ban may have kicked in mid-run")
    if reasons:
        return BanHeuristic(True, "; ".join(reasons) + " (heuristic, may be a false alarm)",
                            b_rate, t_rate)
    return BanHeuristic(False, "no ban contamination signs found (heuristic only, not a guarantee)",
                        b_rate, t_rate)


def summary_text(result: EvalResult, ban: BanHeuristic) -> str:
    o = result.overall
    lines = [
        f"Target: {result.target or '(unknown)'}",
        f"Overall coverage: {o.coverage:.1f}%  "
        f"(blocked={o.blocked} through={o.through} unresolved={o.unresolved} down={o.down})",
        f"False-positive rate: {result.fp_rate:.1f}%  "
        f"({result.benign_blocked}/{result.benign_total} benign blocked)",
        f"Ban contamination: {'SUSPECTED' if ban.suspected else 'not suspected'} - {ban.reason}",
        "",
    ]
    if result.per_class:
        w = max(len("Class"), *(len(c) for c in result.per_class))
        lines.append(f"{'Class'.ljust(w)}  {'Cov%':>6}  {'Block':>5}  {'Thru':>5}  {'Unres':>5}  {'Down':>5}")
        for name, s in sorted(result.per_class.items(), key=lambda kv: (kv[1].coverage, kv[0])):
            lines.append(f"{name.ljust(w)}  {s.coverage:6.1f}  {s.blocked:5d}  {s.through:5d}  "
                         f"{s.unresolved:5d}  {s.down:5d}")
    else:
        lines.append("No malicious records.")
    return "\n".join(lines)


def to_html(result: EvalResult, out_path, meta: dict | None = None) -> None:
    write_eval_html(result, str(out_path), meta)
