"""Training-set export — WAFFEN's original purpose.

Ports the standalone `make_dataset.py` concept into the tool: fire labelled
attack and benign traffic at a target, record the *exact* payload sent plus
the oracle's verdict, and emit a clean (text, label) dataset the RedEye team
can train their own WAF model on.

IMPORTANT: this only produces a valid dataset when measured against the
team's own infrastructure. In particular, benign traffic must be sent from a
source the target has NOT already banned/rate-limited/fingerprinted — a
banned-source skew would mislabel ordinary, legitimate requests as whatever
a block page returns, poisoning the "benign" class before training even
starts. Always sanity-check the benign block rate (see `class_balance` /
`EvalResult.fp_rate` in `coverage.py`) before shipping a dataset.

Record schema (one dict per sent payload):
    text        - the payload string (primary feature for the classifier)
    label       - "malicious" | "benign"
    attack_class- source attack class, or "benign" for benign rows
    verdict     - "block" | "pass" | "unresolved" | "down"
    http_code   - response status code (string, as returned by the oracle)
    method      - HTTP method used
    url         - target URL the payload was sent against
    inject      - injection point ("query", "body", "header", ...)
    resp_size   - response body size in bytes
"""
from __future__ import annotations

import csv
import json
import random
from collections import Counter

from ..core.oracle import Oracle, Target, MIN_CALIBRATION_CONFIDENCE

_VERDICT_MAP = {"BLOCKED": "block", "THROUGH": "pass", "DOWN": "down"}

FIELDS = ["text", "label", "attack_class", "verdict", "http_code",
          "method", "url", "inject", "resp_size"]


def _classify(resp, calibration) -> str:
    """Map a Response to block|pass|unresolved|down, preferring calibration."""
    if (calibration is not None and getattr(calibration, "waf_detected", False)
            and getattr(calibration, "confidence", 0.0) >= MIN_CALIBRATION_CONFIDENCE):
        try:
            return calibration.classify(resp)
        except Exception:
            pass
    return _VERDICT_MAP.get(resp.verdict, "pass")


def _make_record(payload: str, label: str, attack_class: str, resp, target: Target,
                  calibration) -> dict:
    return {
        "text": payload,
        "label": label,
        "attack_class": attack_class,
        "verdict": _classify(resp, calibration),
        "http_code": resp.code,
        "method": target.method,
        "url": target.url(),
        "inject": target.inject,
        "resp_size": resp.size,
    }


def build_dataset(target: Target, attack_cases, benign=None, *, calibration=None,
                   sender=None, concurrency: int = 6, delay: float = 0.0,
                   canary_payload: str | None = None, canary_every: int = 25,
                   transport: str = "curl", drop_down: bool = True, dedup: bool = True) -> dict:
    """Send attack + benign payloads at `target`, label them, return a dataset.

    `attack_cases` = iterable of (attack_class, payload) -> label "malicious".
    `benign`       = iterable of payload strings -> label "benign".

    Benign is measured FIRST, before the attack flood: a long attack run can get
    the test source rate-limited/banned, after which every subsequent request
    (benign included) looks blocked — logging those as "benign: blocked" would
    corrupt the one label a WAF-training dataset most needs to be reliable.

    `canary_payload`/`canary_every`: with `concurrency<=1`, pass a known-benign
    string to periodically re-verify the source hasn't been banned mid-run (a
    ban usually looks like a clean, fast block, not a timeout) — see
    `Oracle.send`. Has no effect at concurrency>1 (see `Oracle.send_many`).

    Returns {"records": [...], "stats": {total, kept, dropped_down, dup,
    malicious, benign}}.
    """
    import dataclasses as _dc
    from ..kb.inject_map import effective as _eff
    auto = getattr(target, "inject", None) == "auto"
    # the base oracle serves benign + the canary; "auto" isn't a concrete inject mode,
    # so resolve it to `query` for them (per-class auto routing applies to attacks only).
    base_target = _dc.replace(target, inject="query") if auto else target
    oracle = Oracle(base_target, sender=sender, canary_payload=canary_payload,
                    canary_every=canary_every, transport=transport)
    attack_cases = list(attack_cases)
    benign = list(benign) if benign else []

    records: list[dict] = []
    total = len(attack_cases) + len(benign)

    if benign:
        responses = oracle.send_many(benign, concurrency=concurrency, delay=delay)
        for payload, resp in zip(benign, responses):
            records.append(_make_record(payload, "benign", "benign", resp, base_target, calibration))

    if attack_cases:
        # group by class so --inject auto can route each class to its right point;
        # for a fixed inject this still works (one group per class, shared oracle).
        by_cls: dict[str, list[str]] = {}
        for cls, payload in attack_cases:
            by_cls.setdefault(cls, []).append(payload)
        for cls, payloads in by_cls.items():
            cls_target = _eff(target, cls) if auto else target
            cls_oracle = Oracle(cls_target, sender=sender, canary_payload=canary_payload,
                                canary_every=canary_every, transport=transport) if auto else oracle
            responses = cls_oracle.send_many(payloads, concurrency=concurrency, delay=delay)
            for payload, resp in zip(payloads, responses):
                records.append(_make_record(payload, "malicious", cls, resp, cls_target, calibration))

    dropped_down = 0
    if drop_down:
        kept = [r for r in records if r["verdict"] != "down"]
        dropped_down = len(records) - len(kept)
        records = kept

    dup = 0
    if dedup:
        seen = set()
        deduped = []
        for r in records:
            key = (r["text"], r["inject"])
            if key in seen:
                dup += 1
                continue
            seen.add(key)
            deduped.append(r)
        records = deduped

    malicious = sum(1 for r in records if r["label"] == "malicious")
    benign_n = sum(1 for r in records if r["label"] == "benign")

    stats = {
        "total": total,
        "kept": len(records),
        "dropped_down": dropped_down,
        "dup": dup,
        "malicious": malicious,
        "benign": benign_n,
    }
    return {"records": records, "stats": stats}


def stratified_split(records: list[dict], val_fraction: float = 0.2, seed: int = 42):
    """Split records into (train, val), preserving the label ratio in each.

    Splits within each label group independently so both labels are present
    in train and val (as long as each label has at least 2 records).
    """
    rng = random.Random(seed)
    by_label: dict[str, list[dict]] = {}
    for r in records:
        by_label.setdefault(r["label"], []).append(r)

    train, val = [], []
    for label, group in by_label.items():
        group = group[:]
        rng.shuffle(group)
        n_val = int(round(len(group) * val_fraction))
        # keep at least one sample in train when possible, and don't force a
        # val split for a single-item group.
        if len(group) > 1:
            n_val = min(n_val, len(group) - 1)
        else:
            n_val = 0
        val.extend(group[:n_val])
        train.extend(group[n_val:])

    rng.shuffle(train)
    rng.shuffle(val)
    return train, val


def write_jsonl(records: list[dict], path: str) -> None:
    """Write records as newline-delimited JSON (one object per line)."""
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=True) + "\n")


def write_csv(records: list[dict], path: str) -> None:
    """Write records as CSV with a stable column order (see FIELDS)."""
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS, extrasaction="ignore")
        writer.writeheader()
        for r in records:
            writer.writerow(r)


def class_balance(records: list[dict]) -> dict:
    """Return {label: count, ..., "ratio_malicious_to_benign": float|None}."""
    counts = Counter(r["label"] for r in records)
    result = dict(counts)
    malicious = counts.get("malicious", 0)
    benign = counts.get("benign", 0)
    result["ratio_malicious_to_benign"] = (malicious / benign) if benign else None
    return result


def balance_records(records: list[dict], *, max_ratio: float = 1.0, seed: int = 42) -> list[dict]:
    """Downsample the malicious rows so malicious:benign <= `max_ratio`.

    A raw full-corpus collection is wildly imbalanced (e.g. 27:1) and training on
    it teaches a model to just predict "malicious". This trims the malicious side
    down to `max_ratio` x the benign count, **stratified by attack_class** so the
    cut is proportional and no class is wiped out (each class present keeps at
    least one row while budget allows). Benign rows are always kept in full.
    Deterministic given `seed`. If there are already few enough malicious rows (or
    no benign rows to anchor the ratio), the input is returned unchanged.
    """
    import random
    benign = [r for r in records if r.get("label") == "benign"]
    malicious = [r for r in records if r.get("label") == "malicious"]
    other = [r for r in records if r.get("label") not in ("benign", "malicious")]
    if not benign:
        return list(records)  # nothing to anchor a ratio to
    target = int(len(benign) * max_ratio)
    if len(malicious) <= target:
        return list(records)  # already balanced enough

    rng = random.Random(seed)
    by_cls: dict[str, list] = {}
    for r in malicious:
        by_cls.setdefault(r.get("attack_class", "unknown"), []).append(r)

    # proportional per-class quota, floored at 1 per non-empty class, then trimmed
    # back to exactly `target` by shaving the largest buckets first.
    quota = {c: max(1, round(target * len(rows) / len(malicious))) for c, rows in by_cls.items()}
    quota = {c: min(q, len(by_cls[c])) for c, q in quota.items()}
    # reconcile the rounded total to exactly `target`
    while sum(quota.values()) > target:
        c = max(quota, key=lambda k: quota[k])
        if quota[c] <= 1:
            break
        quota[c] -= 1
    while sum(quota.values()) < target:
        c = max(by_cls, key=lambda k: len(by_cls[k]) - quota[k])
        if quota[c] >= len(by_cls[c]):
            break
        quota[c] += 1

    kept_mal = []
    for c, rows in by_cls.items():
        picks = rows[:]  # copy
        rng.shuffle(picks)
        kept_mal.extend(picks[:quota[c]])

    out = benign + kept_mal + other
    rng.shuffle(out)
    return out
