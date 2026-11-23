"""Tests for multi-WAF differential testing."""
import json
import tempfile
from unittest.mock import MagicMock

import pytest

from waffen.recon.diff import (
    MultiDiffProbe,
    MultiDiffReport,
    MultiWAFDifferential,
    _multi_diagnose,
    write_multi_diff_jsonl,
)
from waffen.core.oracle import Response, Target, BLOCKED, THROUGH, DOWN


# ---- _multi_diagnose -------------------------------------------------------

class TestMultiDiagnose:
    def test_all_blocked(self):
        d, blocked, missed = _multi_diagnose({"A": BLOCKED, "B": BLOCKED, "C": BLOCKED})
        assert d == "ALL_BLOCK"
        assert len(blocked) == 3
        assert missed == []

    def test_all_passed(self):
        d, blocked, missed = _multi_diagnose({"A": THROUGH, "B": THROUGH})
        assert d == "ALL_PASS"
        assert blocked == []
        assert len(missed) == 2

    def test_split_one_misses(self):
        d, blocked, missed = _multi_diagnose({"A": BLOCKED, "B": BLOCKED, "C": THROUGH})
        assert d == "SPLIT"
        assert set(blocked) == {"A", "B"}
        assert missed == ["C"]

    def test_split_one_blocks(self):
        d, blocked, missed = _multi_diagnose({"A": THROUGH, "B": BLOCKED, "C": THROUGH})
        assert d == "SPLIT"
        assert blocked == ["B"]
        assert set(missed) == {"A", "C"}

    def test_two_wafs_split(self):
        d, blocked, missed = _multi_diagnose({"A": BLOCKED, "B": THROUGH})
        assert d == "SPLIT"

    def test_down_counts_as_not_blocked(self):
        d, blocked, missed = _multi_diagnose({"A": BLOCKED, "B": DOWN})
        assert d == "SPLIT"
        assert blocked == ["A"]
        assert missed == ["B"]


# ---- MultiDiffProbe --------------------------------------------------------

class TestMultiDiffProbe:
    def test_as_dict(self):
        p = MultiDiffProbe(
            payload="' OR 1=1--", attack_class="sqli",
            results={"CRS": BLOCKED, "RedEye": THROUGH},
            codes={"CRS": "403", "RedEye": "200"},
            diagnosis="SPLIT",
            blocked_by=["CRS"], missed_by=["RedEye"],
        )
        d = p.as_dict()
        assert d["payload"] == "' OR 1=1--"
        assert d["diagnosis"] == "SPLIT"
        assert d["missed_by"] == ["RedEye"]

    def test_all_block_probe(self):
        p = MultiDiffProbe(
            payload="test", attack_class="",
            results={"A": BLOCKED, "B": BLOCKED}, codes={"A": "403", "B": "403"},
            diagnosis="ALL_BLOCK", blocked_by=["A", "B"], missed_by=[],
        )
        assert p.missed_by == []


# ---- MultiDiffReport -------------------------------------------------------

class TestMultiDiffReport:
    def _make_report(self):
        r = MultiDiffReport(waf_names=["CRS", "RedEye", "CF"])
        r.probes = [
            MultiDiffProbe("p1", "sqli", {"CRS": BLOCKED, "RedEye": BLOCKED, "CF": BLOCKED},
                           {"CRS": "403", "RedEye": "403", "CF": "403"},
                           "ALL_BLOCK", ["CRS", "RedEye", "CF"], []),
            MultiDiffProbe("p2", "sqli", {"CRS": BLOCKED, "RedEye": THROUGH, "CF": BLOCKED},
                           {"CRS": "403", "RedEye": "200", "CF": "403"},
                           "SPLIT", ["CRS", "CF"], ["RedEye"]),
            MultiDiffProbe("p3", "sqli", {"CRS": THROUGH, "RedEye": THROUGH, "CF": THROUGH},
                           {"CRS": "200", "RedEye": "200", "CF": "200"},
                           "ALL_PASS", [], ["CRS", "RedEye", "CF"]),
            MultiDiffProbe("p4", "xss", {"CRS": BLOCKED, "RedEye": THROUGH, "CF": THROUGH},
                           {"CRS": "403", "RedEye": "200", "CF": "200"},
                           "SPLIT", ["CRS"], ["RedEye", "CF"]),
        ]
        return r

    def test_counts(self):
        r = self._make_report()
        assert r.total_probes == 4
        assert r.all_blocked == 1
        assert r.all_passed == 1
        assert r.split == 2

    def test_split_details(self):
        r = self._make_report()
        splits = r.split_details
        assert len(splits) == 2
        assert all(s.diagnosis == "SPLIT" for s in splits)

    def test_per_waf_misses(self):
        r = self._make_report()
        misses = r.per_waf_misses()
        assert "p2" in misses["RedEye"]
        assert "p4" in misses["RedEye"]
        assert "p4" in misses["CF"]
        assert misses["CRS"] == []

    def test_as_dict(self):
        r = self._make_report()
        d = r.as_dict()
        assert d["total"] == 4
        assert d["split"] == 2
        assert d["per_waf_misses"]["CRS"] == 0
        assert d["per_waf_misses"]["RedEye"] == 2


# ---- MultiWAFDifferential with mock oracles --------------------------------

def _fake_sender(verdict_map):
    """Create a sender that returns canned verdicts per payload."""
    def send(payload):
        v = verdict_map.get(payload, THROUGH)
        code = "403" if v == BLOCKED else "200"
        return Response(verdict=v, code=code, size=100, time=0.1, body="")
    return send


class TestMultiWAFDifferential:
    def test_probe_all_block(self):
        targets = {
            "A": Target(base_url="http://a.test"),
            "B": Target(base_url="http://b.test"),
        }
        senders = {
            "A": _fake_sender({"evil": BLOCKED}),
            "B": _fake_sender({"evil": BLOCKED}),
        }
        tester = MultiWAFDifferential(targets, senders=senders)
        p = tester.probe("evil", "sqli")
        assert p.diagnosis == "ALL_BLOCK"

    def test_probe_split(self):
        targets = {
            "CRS": Target(base_url="http://crs.test"),
            "RedEye": Target(base_url="http://re.test"),
        }
        senders = {
            "CRS": _fake_sender({"evil": BLOCKED}),
            "RedEye": _fake_sender({"evil": THROUGH}),
        }
        tester = MultiWAFDifferential(targets, senders=senders)
        p = tester.probe("evil", "sqli")
        assert p.diagnosis == "SPLIT"
        assert "CRS" in p.blocked_by
        assert "RedEye" in p.missed_by

    def test_run_payloads(self):
        targets = {
            "A": Target(base_url="http://a.test"),
            "B": Target(base_url="http://b.test"),
            "C": Target(base_url="http://c.test"),
        }
        senders = {
            "A": _fake_sender({"p1": BLOCKED, "p2": BLOCKED, "p3": THROUGH}),
            "B": _fake_sender({"p1": BLOCKED, "p2": THROUGH, "p3": THROUGH}),
            "C": _fake_sender({"p1": BLOCKED, "p2": BLOCKED, "p3": BLOCKED}),
        }
        tester = MultiWAFDifferential(targets, senders=senders)
        report = tester.run_payloads([("sqli", "p1"), ("sqli", "p2"), ("sqli", "p3")])
        assert report.total_probes == 3
        assert report.all_blocked == 1   # p1
        assert report.split == 2         # p2 (B misses), p3 (A+B miss, C blocks)

    def test_three_way_split(self):
        targets = {
            "X": Target(base_url="http://x"),
            "Y": Target(base_url="http://y"),
            "Z": Target(base_url="http://z"),
        }
        senders = {
            "X": _fake_sender({"payload": BLOCKED}),
            "Y": _fake_sender({"payload": THROUGH}),
            "Z": _fake_sender({"payload": THROUGH}),
        }
        tester = MultiWAFDifferential(targets, senders=senders)
        r = tester.run_payloads([("sqli", "payload")])
        assert r.split == 1
        misses = r.per_waf_misses()
        assert len(misses["Y"]) == 1
        assert len(misses["Z"]) == 1
        assert misses["X"] == []

    def test_empty_payloads(self):
        targets = {"A": Target(base_url="http://a"), "B": Target(base_url="http://b")}
        senders = {"A": _fake_sender({}), "B": _fake_sender({})}
        tester = MultiWAFDifferential(targets, senders=senders)
        r = tester.run_payloads([])
        assert r.total_probes == 0
        assert r.split == 0


# ---- write_multi_diff_jsonl ------------------------------------------------

class TestWriteMultiDiffJsonl:
    def test_writes_summary_and_splits(self):
        r = MultiDiffReport(waf_names=["A", "B"])
        r.probes = [
            MultiDiffProbe("evil", "sqli", {"A": BLOCKED, "B": THROUGH},
                           {"A": "403", "B": "200"}, "SPLIT", ["A"], ["B"]),
            MultiDiffProbe("safe", "", {"A": THROUGH, "B": THROUGH},
                           {"A": "200", "B": "200"}, "ALL_PASS", [], ["A", "B"]),
        ]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            path = f.name
        write_multi_diff_jsonl(r, path)
        with open(path) as f:
            lines = [json.loads(l) for l in f if l.strip()]
        assert len(lines) == 2  # summary + 1 split (ALL_PASS not included)
        assert lines[0]["split"] == 1
        assert lines[1]["diagnosis"] == "SPLIT"


# ---- CLI integration -------------------------------------------------------

class TestCLI:
    def test_parser_has_targets(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args(["diff", "--targets", "A=http://a,B=http://b",
                             "--path", "/test", "--param", "q"])
        assert args.targets == "A=http://a,B=http://b"

    def test_parser_backward_compat(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args(["diff", "--waf", "http://waf", "--origin", "http://origin"])
        assert args.waf == "http://waf"
        assert args.origin == "http://origin"

    def test_parser_corpus_flag(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args(["diff", "--targets", "A=http://a,B=http://b", "--corpus"])
        assert args.corpus is True
