"""Tests for dataset.balance_records (class-stratified malicious downsampling)."""
import collections

from waffen.eval.dataset import balance_records, class_balance


def _mal(cls, i):
    return {"text": f"{cls}-{i}", "label": "malicious", "attack_class": cls}


def _ben(i):
    return {"text": f"benign-{i}", "label": "benign", "attack_class": "benign"}


def test_downsamples_to_ratio():
    recs = [_mal("XSS Injection", i) for i in range(100)] + [_ben(i) for i in range(10)]
    out = balance_records(recs, max_ratio=1.0)
    bal = class_balance(out)
    assert bal["benign"] == 10
    assert bal["malicious"] == 10          # 10 benign * 1.0
    assert bal["ratio_malicious_to_benign"] == 1.0


def test_ratio_2_to_1():
    recs = [_mal("XSS Injection", i) for i in range(100)] + [_ben(i) for i in range(10)]
    out = balance_records(recs, max_ratio=2.0)
    bal = class_balance(out)
    assert bal["malicious"] == 20 and bal["benign"] == 10


def test_stratified_keeps_small_classes():
    # a huge class + two tiny ones; balancing must not wipe the tiny classes out
    recs = ([_mal("Directory Traversal", i) for i in range(900)]
            + [_mal("CRLF Injection", i) for i in range(5)]
            + [_mal("NoSQL Injection", i) for i in range(5)]
            + [_ben(i) for i in range(50)])
    out = balance_records(recs, max_ratio=1.0)
    kept = collections.Counter(r["attack_class"] for r in out if r["label"] == "malicious")
    assert sum(kept.values()) == 50
    assert kept["CRLF Injection"] >= 1 and kept["NoSQL Injection"] >= 1   # survived


def test_noop_when_already_balanced():
    recs = [_mal("XSS Injection", i) for i in range(5)] + [_ben(i) for i in range(10)]
    out = balance_records(recs, max_ratio=1.0)
    assert len(out) == len(recs)           # 5 malicious <= 10 target -> unchanged


def test_noop_when_no_benign():
    recs = [_mal("XSS Injection", i) for i in range(100)]
    assert len(balance_records(recs)) == 100   # nothing to anchor the ratio


def test_deterministic():
    recs = [_mal("XSS Injection", i) for i in range(100)] + [_ben(i) for i in range(10)]
    a = [r["text"] for r in balance_records(recs, seed=7)]
    b = [r["text"] for r in balance_records(recs, seed=7)]
    assert a == b
