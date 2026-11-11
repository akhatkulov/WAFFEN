"""Tests for the WAF regression watch module."""
import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from waffen.watch import (
    SavedFinding,
    WatchEntry,
    WatchReport,
    WatchRunner,
    load_findings,
    write_watch_jsonl,
)
from waffen.core.oracle import Target, Response


# ---- fixtures ---------------------------------------------------------------

def _make_finding(payload="' OR 1=1--", transform="identity", cls="sqli"):
    return SavedFinding(
        payload=payload,
        attack_class=cls,
        chain=["mutator_a"],
        transform=transform,
        http_code="200",
    )


def _jsonl_line(payload="' OR 1=1--", transform="identity", cls="sqli"):
    return json.dumps({
        "payload": payload,
        "attack_class": cls,
        "chain": ["mutator_a"],
        "http_code": "200",
        "request_transform": transform,
        "seed": "' OR 1=1--",
        "requests": 42,
        "verified_exploitable": True,
        "verify_confidence": 0.95,
    })


def _target():
    return Target(base_url="https://example.com", path="/search", param="q")


def _mock_oracle_factory(verdicts):
    """Return a WatchRunner whose oracles return canned verdicts in sequence."""
    idx = [0]
    def fake_send(payload):
        v = verdicts[min(idx[0], len(verdicts) - 1)]
        idx[0] += 1
        return Response(verdict=v, code="200" if v == "THROUGH" else "403", size=100, time=0.1, body="")
    target = _target()
    runner = WatchRunner(target, sender=fake_send)
    return runner


# ---- load_findings ----------------------------------------------------------

class TestLoadFindings:
    def test_loads_from_jsonl(self, tmp_path):
        p = tmp_path / "results.jsonl"
        p.write_text(_jsonl_line() + "\n" + _jsonl_line("other", "hpp_duplicate", "xss") + "\n")
        findings = load_findings(str(p))
        assert len(findings) == 2
        assert findings[0].payload == "' OR 1=1--"
        assert findings[0].transform == "identity"
        assert findings[1].payload == "other"
        assert findings[1].transform == "hpp_duplicate"

    def test_deduplicates(self, tmp_path):
        p = tmp_path / "results.jsonl"
        p.write_text(_jsonl_line() + "\n" + _jsonl_line() + "\n")
        findings = load_findings(str(p))
        assert len(findings) == 1

    def test_skips_blank_lines(self, tmp_path):
        p = tmp_path / "results.jsonl"
        p.write_text("\n" + _jsonl_line() + "\n\n")
        findings = load_findings(str(p))
        assert len(findings) == 1

    def test_default_transform(self, tmp_path):
        p = tmp_path / "results.jsonl"
        rec = json.dumps({"payload": "test", "attack_class": "sqli", "chain": [], "http_code": "200"})
        p.write_text(rec + "\n")
        findings = load_findings(str(p))
        assert findings[0].transform == "identity"


# ---- WatchReport properties ------------------------------------------------

class TestWatchReport:
    def test_alive_blocked_errored_counts(self):
        entries = [
            WatchEntry("p1", "identity", "sqli", [], "THROUGH", "ALIVE", "200", "t"),
            WatchEntry("p2", "identity", "sqli", [], "THROUGH", "BLOCKED", "403", "t"),
            WatchEntry("p3", "identity", "sqli", [], "THROUGH", "ERROR", "000", "t"),
            WatchEntry("p4", "identity", "sqli", [], "THROUGH", "ALIVE", "200", "t"),
        ]
        r = WatchReport(target="https://x.com", round_num=1, timestamp="t", entries=entries)
        assert r.alive == 2
        assert r.blocked == 1
        assert r.errored == 1

    def test_as_dict(self):
        r = WatchReport(target="https://x.com", round_num=1, timestamp="t", entries=[])
        d = r.as_dict()
        assert d["target"] == "https://x.com"
        assert d["round"] == 1
        assert d["alive"] == 0


# ---- WatchRunner.retest ----------------------------------------------------

class TestRetest:
    def test_through_is_alive(self):
        runner = _mock_oracle_factory(["THROUGH"])
        findings = [_make_finding()]
        report = runner.retest(findings)
        assert len(report.entries) == 1
        assert report.entries[0].current_verdict == "ALIVE"
        assert report.alive == 1

    def test_blocked_is_blocked(self):
        runner = _mock_oracle_factory(["BLOCKED"])
        findings = [_make_finding()]
        report = runner.retest(findings)
        assert report.entries[0].current_verdict == "BLOCKED"
        assert report.blocked == 1

    def test_down_is_error(self):
        runner = _mock_oracle_factory(["DOWN"])
        findings = [_make_finding()]
        report = runner.retest(findings)
        assert report.entries[0].current_verdict == "ERROR"

    def test_multiple_findings(self):
        runner = _mock_oracle_factory(["THROUGH", "BLOCKED", "THROUGH"])
        findings = [_make_finding("p1"), _make_finding("p2"), _make_finding("p3")]
        report = runner.retest(findings)
        assert report.alive == 2
        assert report.blocked == 1

    def test_exception_is_error(self):
        def exploding_send(payload):
            raise ConnectionError("timeout")
        target = _target()
        runner = WatchRunner(target, sender=exploding_send)
        report = runner.retest([_make_finding()])
        assert report.entries[0].current_verdict == "ERROR"
        assert report.entries[0].response_code == "000"


# ---- WatchRunner.diff_report -----------------------------------------------

class TestDiffReport:
    def test_no_prev_all_unchanged(self):
        report = WatchReport("x", 1, "t", entries=[
            WatchEntry("p1", "identity", "sqli", [], "THROUGH", "ALIVE", "200", "t"),
        ])
        diff = WatchRunner.diff_report(None, report)
        assert diff.unchanged == 1
        assert len(diff.newly_blocked) == 0

    def test_detects_newly_blocked(self):
        prev = WatchReport("x", 1, "t", entries=[
            WatchEntry("p1", "identity", "sqli", [], "THROUGH", "ALIVE", "200", "t1"),
        ])
        curr = WatchReport("x", 2, "t", entries=[
            WatchEntry("p1", "identity", "sqli", [], "THROUGH", "BLOCKED", "403", "t2"),
        ])
        diff = WatchRunner.diff_report(prev, curr)
        assert len(diff.newly_blocked) == 1
        assert diff.newly_blocked[0].payload == "p1"

    def test_detects_newly_alive(self):
        prev = WatchReport("x", 1, "t", entries=[
            WatchEntry("p1", "identity", "sqli", [], "THROUGH", "BLOCKED", "403", "t1"),
        ])
        curr = WatchReport("x", 2, "t", entries=[
            WatchEntry("p1", "identity", "sqli", [], "THROUGH", "ALIVE", "200", "t2"),
        ])
        diff = WatchRunner.diff_report(prev, curr)
        assert len(diff.newly_alive) == 1

    def test_unchanged_stays_unchanged(self):
        prev = WatchReport("x", 1, "t", entries=[
            WatchEntry("p1", "identity", "sqli", [], "THROUGH", "ALIVE", "200", "t1"),
        ])
        curr = WatchReport("x", 2, "t", entries=[
            WatchEntry("p1", "identity", "sqli", [], "THROUGH", "ALIVE", "200", "t2"),
        ])
        diff = WatchRunner.diff_report(prev, curr)
        assert diff.unchanged == 1
        assert len(diff.newly_blocked) == 0
        assert len(diff.newly_alive) == 0

    def test_mixed_changes(self):
        prev = WatchReport("x", 1, "t", entries=[
            WatchEntry("p1", "identity", "sqli", [], "THROUGH", "ALIVE", "200", "t1"),
            WatchEntry("p2", "hpp", "xss", [], "THROUGH", "ALIVE", "200", "t1"),
            WatchEntry("p3", "identity", "sqli", [], "THROUGH", "BLOCKED", "403", "t1"),
        ])
        curr = WatchReport("x", 2, "t", entries=[
            WatchEntry("p1", "identity", "sqli", [], "THROUGH", "BLOCKED", "403", "t2"),
            WatchEntry("p2", "hpp", "xss", [], "THROUGH", "ALIVE", "200", "t2"),
            WatchEntry("p3", "identity", "sqli", [], "THROUGH", "ALIVE", "200", "t2"),
        ])
        diff = WatchRunner.diff_report(prev, curr)
        assert len(diff.newly_blocked) == 1
        assert diff.newly_blocked[0].payload == "p1"
        assert len(diff.newly_alive) == 1
        assert diff.newly_alive[0].payload == "p3"
        assert diff.unchanged == 1


# ---- write_watch_jsonl ------------------------------------------------------

class TestWriteWatchJsonl:
    def test_writes_reports(self, tmp_path):
        r = WatchReport("https://x.com", 1, "t", entries=[
            WatchEntry("p1", "identity", "sqli", [], "THROUGH", "ALIVE", "200", "t"),
        ])
        out = tmp_path / "watch.jsonl"
        write_watch_jsonl([r], str(out))
        lines = out.read_text().strip().splitlines()
        assert len(lines) == 1
        data = json.loads(lines[0])
        assert data["alive"] == 1
        assert data["target"] == "https://x.com"
        assert len(data["entries"]) == 1


# ---- CLI integration -------------------------------------------------------

class TestCliWatch:
    def test_parser_has_watch(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args(["watch", "--findings", "f.jsonl", "--target", "https://x.com", "--once"])
        assert args.findings == "f.jsonl"
        assert args.once is True
        assert hasattr(args, "func")

    def test_watch_help_flag(self):
        from waffen.cli import build_parser
        p = build_parser()
        # Just ensure the subparser is registered (parse_args with --help would exit)
        args = p.parse_args(["watch", "--findings", "f.jsonl", "--target", "https://x.com"])
        assert args.interval == 3600
        assert args.rounds == 0
