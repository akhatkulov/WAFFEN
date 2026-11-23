"""Tests for differential testing mode (waffen diff)."""
import json
import tempfile
from unittest.mock import MagicMock

import pytest

from waffen.recon.diff import (
    DiffProbe,
    DiffReport,
    DifferentialTester,
    _diagnose,
    write_diff_jsonl,
)
from waffen.core.oracle import Response, Target, BLOCKED, THROUGH, DOWN


# ---- _diagnose tests -------------------------------------------------------

def _resp(verdict, code="200"):
    return Response(verdict=verdict, code=code, size=100, time=0.1, body="")


class TestDiagnose:
    def test_waf_only(self):
        assert _diagnose(_resp(BLOCKED, "403"), _resp(THROUGH, "200")) == "WAF_ONLY"

    def test_app_only(self):
        assert _diagnose(_resp(THROUGH, "200"), _resp(BLOCKED, "403")) == "APP_ONLY"

    def test_both_block(self):
        assert _diagnose(_resp(BLOCKED, "403"), _resp(BLOCKED, "403")) == "BOTH_BLOCK"

    def test_both_pass(self):
        assert _diagnose(_resp(THROUGH, "200"), _resp(THROUGH, "200")) == "BOTH_PASS"

    def test_desync_down_waf(self):
        assert _diagnose(_resp(DOWN, "000"), _resp(THROUGH, "200")) == "DESYNC"

    def test_desync_down_origin(self):
        assert _diagnose(_resp(THROUGH, "200"), _resp(DOWN, "000")) == "DESYNC"

    def test_desync_origin_5xx(self):
        assert _diagnose(_resp(THROUGH, "200"), _resp(THROUGH, "500")) == "DESYNC"

    def test_both_pass_normal_codes(self):
        assert _diagnose(_resp(THROUGH, "200"), _resp(THROUGH, "404")) == "BOTH_PASS"


# ---- DiffProbe tests --------------------------------------------------------

class TestDiffProbe:
    def test_as_dict(self):
        p = DiffProbe(
            payload="' OR 1=1--", attack_class="sqli",
            waf_code="403", waf_verdict=BLOCKED,
            origin_code="200", origin_verdict=THROUGH,
            diagnosis="WAF_ONLY",
        )
        d = p.as_dict()
        assert d["payload"] == "' OR 1=1--"
        assert d["diagnosis"] == "WAF_ONLY"
        assert d["waf_code"] == "403"
        assert d["origin_code"] == "200"


# ---- DiffReport tests -------------------------------------------------------

class TestDiffReport:
    def _make_report(self):
        r = DiffReport(waf_target="https://waf.test", origin_target="https://origin.test")
        r.probes = [
            DiffProbe("p1", "sqli", "403", BLOCKED, "200", THROUGH, "WAF_ONLY"),
            DiffProbe("p2", "sqli", "403", BLOCKED, "403", BLOCKED, "BOTH_BLOCK"),
            DiffProbe("p3", "xss", "200", THROUGH, "200", THROUGH, "BOTH_PASS"),
            DiffProbe("p4", "sqli", "200", THROUGH, "403", BLOCKED, "APP_ONLY"),
            DiffProbe("p5", "sqli", "200", THROUGH, "500", THROUGH, "DESYNC"),
        ]
        return r

    def test_waf_only_filter(self):
        r = self._make_report()
        assert len(r.waf_only) == 1
        assert r.waf_only[0].payload == "p1"

    def test_both_block_filter(self):
        r = self._make_report()
        assert len(r.both_block) == 1

    def test_both_pass_filter(self):
        r = self._make_report()
        assert len(r.both_pass) == 1
        assert r.both_pass[0].payload == "p3"

    def test_app_only_filter(self):
        r = self._make_report()
        assert len(r.app_only) == 1

    def test_desync_filter(self):
        r = self._make_report()
        assert len(r.desync) == 1

    def test_as_dict(self):
        r = self._make_report()
        d = r.as_dict()
        assert d["total"] == 5
        assert d["waf_only"] == 1
        assert d["both_pass"] == 1
        assert len(d["probes"]) == 5


# ---- DifferentialTester tests -----------------------------------------------

def _make_tester(waf_responses, origin_responses):
    """Build a tester with canned responses for both oracles."""
    waf_target = Target(base_url="https://waf.test")
    origin_target = Target(base_url="https://origin.test")

    waf_idx = [0]
    origin_idx = [0]

    def waf_send(payload):
        r = waf_responses[min(waf_idx[0], len(waf_responses) - 1)]
        waf_idx[0] += 1
        return r

    def origin_send(payload):
        r = origin_responses[min(origin_idx[0], len(origin_responses) - 1)]
        origin_idx[0] += 1
        return r

    return DifferentialTester(waf_target, origin_target,
                              waf_sender=waf_send, origin_sender=origin_send)


class TestDifferentialTester:
    def test_probe_waf_only(self):
        t = _make_tester(
            [_resp(BLOCKED, "403")],
            [_resp(THROUGH, "200")],
        )
        p = t.probe("' OR 1=1--", "sqli")
        assert p.diagnosis == "WAF_ONLY"
        assert p.waf_verdict == BLOCKED
        assert p.origin_verdict == THROUGH

    def test_probe_both_pass(self):
        t = _make_tester(
            [_resp(THROUGH, "200")],
            [_resp(THROUGH, "200")],
        )
        p = t.probe("harmless", "sqli")
        assert p.diagnosis == "BOTH_PASS"

    def test_probe_both_block(self):
        t = _make_tester(
            [_resp(BLOCKED, "403")],
            [_resp(BLOCKED, "403")],
        )
        p = t.probe("' OR 1=1--", "sqli")
        assert p.diagnosis == "BOTH_BLOCK"

    def test_probe_app_only(self):
        t = _make_tester(
            [_resp(THROUGH, "200")],
            [_resp(BLOCKED, "403")],
        )
        p = t.probe("app-restricted", "sqli")
        assert p.diagnosis == "APP_ONLY"

    def test_probe_desync(self):
        t = _make_tester(
            [_resp(THROUGH, "200")],
            [_resp(DOWN, "000")],
        )
        p = t.probe("crash", "sqli")
        assert p.diagnosis == "DESYNC"

    def test_run_payloads(self):
        t = _make_tester(
            [_resp(BLOCKED, "403"), _resp(THROUGH, "200")],
            [_resp(THROUGH, "200"), _resp(THROUGH, "200")],
        )
        report = t.run_payloads([("sqli", "p1"), ("sqli", "p2")])
        assert len(report.probes) == 2
        assert report.probes[0].diagnosis == "WAF_ONLY"
        assert report.probes[1].diagnosis == "BOTH_PASS"

    def test_run_seeds(self):
        t = _make_tester(
            [_resp(BLOCKED, "403")] * 50,
            [_resp(THROUGH, "200")] * 50,
        )
        report = t.run_seeds(["SQL Injection"])
        assert len(report.probes) > 0
        assert all(p.diagnosis == "WAF_ONLY" for p in report.probes)

    def test_run_findings_from_jsonl(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write(json.dumps({"payload": "' OR 1=1--", "attack_class": "sqli"}) + "\n")
            f.write(json.dumps({"payload": "<script>", "attack_class": "xss"}) + "\n")
            path = f.name

        t = _make_tester(
            [_resp(BLOCKED, "403"), _resp(BLOCKED, "403")],
            [_resp(THROUGH, "200"), _resp(THROUGH, "200")],
        )
        report = t.run_findings(path)
        assert len(report.probes) == 2
        assert report.probes[0].payload == "' OR 1=1--"

    def test_run_findings_missing_file(self):
        t = _make_tester([], [])
        report = t.run_findings("/nonexistent/path.jsonl")
        assert len(report.probes) == 0

    def test_run_findings_empty_lines(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write("\n\n")
            f.write(json.dumps({"payload": "test", "attack_class": ""}) + "\n")
            f.write("\n")
            path = f.name

        t = _make_tester(
            [_resp(THROUGH, "200")],
            [_resp(THROUGH, "200")],
        )
        report = t.run_findings(path)
        assert len(report.probes) == 1

    def test_attack_class_preserved(self):
        t = _make_tester(
            [_resp(BLOCKED, "403")],
            [_resp(THROUGH, "200")],
        )
        p = t.probe("payload", attack_class="XSS Injection")
        assert p.attack_class == "XSS Injection"


# ---- write_diff_jsonl tests -------------------------------------------------

class TestWriteDiffJsonl:
    def test_writes_probes(self):
        report = DiffReport(waf_target="https://w.test", origin_target="https://o.test")
        report.probes = [
            DiffProbe("p1", "sqli", "403", BLOCKED, "200", THROUGH, "WAF_ONLY"),
            DiffProbe("p2", "xss", "200", THROUGH, "200", THROUGH, "BOTH_PASS"),
        ]
        with tempfile.NamedTemporaryFile(mode="r", suffix=".jsonl", delete=False) as f:
            path = f.name

        write_diff_jsonl(report, path)

        with open(path) as f:
            lines = [l.strip() for l in f if l.strip()]
        assert len(lines) == 2
        d1 = json.loads(lines[0])
        assert d1["diagnosis"] == "WAF_ONLY"
        d2 = json.loads(lines[1])
        assert d2["diagnosis"] == "BOTH_PASS"

    def test_creates_parent_dirs(self):
        import os
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "sub", "dir", "out.jsonl")
            report = DiffReport(waf_target="a", origin_target="b")
            write_diff_jsonl(report, path)
            assert os.path.exists(path)
