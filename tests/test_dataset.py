"""Tests for the training-set export (offline, against the mock WAF)."""
import csv
import json
import os
import tempfile

from waffen.core.mock import make_mock_sender
from waffen.core.oracle import Response, Target
from waffen.eval.dataset import (
    build_dataset,
    class_balance,
    stratified_split,
    write_csv,
    write_jsonl,
)

ATTACK_CASES = [
    ("XSS Injection", "<script>alert(1)</script>"),
    ("SQL Injection", "' OR 1=1-- -"),
    ("Path Traversal", "../../../../etc/passwd"),
]
BENIGN = ["banana juice", "hello world", "red shoes size 9", "contact support"]


def _target():
    return Target(base_url="mock://local")


def test_build_dataset_labels():
    ds = build_dataset(_target(), ATTACK_CASES, BENIGN, sender=make_mock_sender())
    records = ds["records"]
    labels = {r["text"]: r["label"] for r in records}
    for cls, payload in ATTACK_CASES:
        assert labels[payload] == "malicious"
    for payload in BENIGN:
        assert labels[payload] == "benign"
    assert ds["stats"]["malicious"] == len(ATTACK_CASES)
    assert ds["stats"]["benign"] == len(BENIGN)
    assert ds["stats"]["total"] == len(ATTACK_CASES) + len(BENIGN)


def test_build_dataset_verdicts_match_mock():
    ds = build_dataset(_target(), ATTACK_CASES, BENIGN, sender=make_mock_sender())
    by_text = {r["text"]: r for r in ds["records"]}
    for cls, payload in ATTACK_CASES:
        assert by_text[payload]["verdict"] == "block"
        assert by_text[payload]["attack_class"] == cls
    for payload in BENIGN:
        assert by_text[payload]["verdict"] == "pass"


def test_drop_down_removes_down_rows():
    base_sender = make_mock_sender()

    def flaky_sender(payload):
        if payload == "timeout-me":
            return Response("DOWN", "000", 0, 0.0, "")
        return base_sender(payload)

    cases = ATTACK_CASES + [("Flaky", "timeout-me")]
    ds = build_dataset(_target(), cases, BENIGN, sender=flaky_sender, drop_down=True)
    texts = [r["text"] for r in ds["records"]]
    assert "timeout-me" not in texts
    assert ds["stats"]["dropped_down"] == 1

    ds_keep = build_dataset(_target(), cases, BENIGN, sender=flaky_sender, drop_down=False)
    texts_keep = [r["text"] for r in ds_keep["records"]]
    assert "timeout-me" in texts_keep
    assert ds_keep["stats"]["dropped_down"] == 0


def test_dedup_removes_duplicates():
    dup_cases = ATTACK_CASES + [ATTACK_CASES[0]]  # duplicate first case
    ds_dedup = build_dataset(_target(), dup_cases, sender=make_mock_sender(), dedup=True)
    ds_nodedup = build_dataset(_target(), dup_cases, sender=make_mock_sender(), dedup=False)
    assert ds_dedup["stats"]["dup"] == 1
    assert len(ds_dedup["records"]) == len(ATTACK_CASES)
    assert len(ds_nodedup["records"]) == len(dup_cases)


def test_stratified_split_keeps_both_labels():
    more_benign = BENIGN + ["weather forecast", "quarterly report 2024", "another safe query"]
    ds = build_dataset(_target(), ATTACK_CASES, more_benign, sender=make_mock_sender())
    train, val = stratified_split(ds["records"], val_fraction=0.3, seed=42)
    train_labels = {r["label"] for r in train}
    val_labels = {r["label"] for r in val}
    assert "malicious" in train_labels and "benign" in train_labels
    assert "malicious" in val_labels and "benign" in val_labels
    assert len(train) + len(val) == len(ds["records"])


def test_write_jsonl_roundtrip():
    ds = build_dataset(_target(), ATTACK_CASES, BENIGN, sender=make_mock_sender())
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "out.jsonl")
        write_jsonl(ds["records"], path)
        with open(path, encoding="utf-8") as f:
            lines = [json.loads(line) for line in f if line.strip()]
        assert len(lines) == len(ds["records"])
        assert {r["text"] for r in lines} == {r["text"] for r in ds["records"]}


def test_write_csv_roundtrip_with_odd_payloads():
    odd_cases = ATTACK_CASES + [("CSV Injection", 'a,"b\nc",=cmd|calc!')]
    ds = build_dataset(_target(), odd_cases, BENIGN, sender=make_mock_sender())
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "out.csv")
        write_csv(ds["records"], path)
        with open(path, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == len(ds["records"])
        texts = {r["text"] for r in rows}
        assert 'a,"b\nc",=cmd|calc!' in texts


def test_class_balance():
    ds = build_dataset(_target(), ATTACK_CASES, BENIGN, sender=make_mock_sender())
    balance = class_balance(ds["records"])
    assert balance["malicious"] == len(ATTACK_CASES)
    assert balance["benign"] == len(BENIGN)
    assert balance["ratio_malicious_to_benign"] == len(ATTACK_CASES) / len(BENIGN)


def test_class_balance_no_benign():
    balance = class_balance([{"label": "malicious"}, {"label": "malicious"}])
    assert balance["malicious"] == 2
    assert balance.get("benign", 0) == 0
    assert balance["ratio_malicious_to_benign"] is None
