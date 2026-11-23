"""Tests for the WAF benchmark system."""
import json
import os
import tempfile
from unittest.mock import MagicMock

import pytest

from waffen.eval.benchmark import (
    BenchmarkScore,
    ClassScore,
    WAFBenchmark,
    grade,
    compare,
    generate_html_report,
    write_benchmark_json,
    load_benchmark_json,
    write_html_report,
    BENIGN_PAYLOADS,
)
from waffen.eval.profiles import WAF_PROFILES, list_profiles, get_profile


# ---- grading ---------------------------------------------------------------

class TestGrading:
    def test_a_plus(self):
        assert grade(0.995, 0.005) == "A+"

    def test_a(self):
        assert grade(0.96, 0.02) == "A"

    def test_a_minus(self):
        assert grade(0.92, 0.04) == "A-"

    def test_b_plus(self):
        assert grade(0.91, 0.08) == "B+"

    def test_b(self):
        assert grade(0.86, 0.12) == "B"

    def test_b_minus(self):
        assert grade(0.81, 0.18) == "B-"

    def test_c_plus(self):
        assert grade(0.76, 0.3) == "C+"

    def test_c(self):
        assert grade(0.71, 0.3) == "C"

    def test_d(self):
        assert grade(0.65, 0.3) == "D"

    def test_f(self):
        assert grade(0.50, 0.3) == "F"

    def test_perfect_detection_high_fp(self):
        assert grade(1.0, 0.20) == "B-"

    def test_zero_detection(self):
        assert grade(0.0, 0.0) == "F"


# ---- ClassScore ------------------------------------------------------------

class TestClassScore:
    def test_calc_detection_rate(self):
        cs = ClassScore("SQLi", payloads_tested=100, blocked=90, passed=10)
        cs._calc()
        assert cs.detection_rate == pytest.approx(0.9)

    def test_calc_zero_tested(self):
        cs = ClassScore("XSS", payloads_tested=0, blocked=0, passed=0)
        cs._calc()
        assert cs.detection_rate == 0.0

    def test_as_dict(self):
        cs = ClassScore("SSTI", payloads_tested=50, blocked=48, passed=2,
                        detection_rate=0.96, bypasses=["p1", "p2"])
        d = cs.as_dict()
        assert d["attack_class"] == "SSTI"
        assert d["detection_rate"] == 0.96
        assert len(d["bypasses"]) == 2


# ---- BenchmarkScore --------------------------------------------------------

class TestBenchmarkScore:
    def _make_score(self, **kw):
        defaults = {
            "waf_name": "TestWAF", "target_url": "https://test.com",
            "timestamp": "2026-01-01T00:00:00Z", "overall_grade": "B+",
            "detection_rate": 0.91, "false_positive_rate": 0.03,
            "bypass_count": 5, "total_payloads": 100,
            "avg_response_ms": 25.0,
        }
        defaults.update(kw)
        return BenchmarkScore(**defaults)

    def test_summary_contains_grade(self):
        s = self._make_score()
        assert "B+" in s.summary()

    def test_summary_contains_detection(self):
        s = self._make_score()
        assert "91" in s.summary()

    def test_as_dict_roundtrip(self):
        s = self._make_score()
        d = s.as_dict()
        assert d["waf_name"] == "TestWAF"
        assert d["overall_grade"] == "B+"
        assert d["detection_rate"] == 0.91

    def test_as_dict_has_all_fields(self):
        s = self._make_score()
        d = s.as_dict()
        for key in ["waf_name", "target_url", "timestamp", "overall_grade",
                     "detection_rate", "false_positive_rate", "bypass_count",
                     "total_payloads", "avg_response_ms", "per_class"]:
            assert key in d


# ---- WAFBenchmark with mock oracle ----------------------------------------

class _FakeResp:
    def __init__(self, verdict, code="403", time=0.02):
        self.verdict = verdict
        self.code = code
        self.time = time
        self.size = 100
        self.body = ""


class TestWAFBenchmark:
    def _make_benchmark(self, verdicts):
        """Create benchmark with a mock sender returning canned verdicts."""
        from waffen.core.oracle import Target
        target = Target(base_url="https://mock.test", path="/", param="q")
        idx = [0]
        def sender(payload):
            v = verdicts[idx[0] % len(verdicts)]
            idx[0] += 1
            return _FakeResp(v)
        return WAFBenchmark(target, corpus_classes=["sqli"],
                            sender=sender, waf_name="MockWAF")

    def test_all_blocked(self):
        bm = self._make_benchmark(["BLOCKED"])
        score = bm.run(include_benign=False)
        assert score.detection_rate == 1.0
        assert score.bypass_count == 0

    def test_all_through(self):
        bm = self._make_benchmark(["THROUGH"])
        score = bm.run(include_benign=False)
        assert score.detection_rate == 0.0
        assert score.bypass_count > 0

    def test_mixed(self):
        bm = self._make_benchmark(["BLOCKED", "BLOCKED", "THROUGH"])
        score = bm.run(include_benign=False)
        assert 0.0 < score.detection_rate < 1.0

    def test_grade_assigned(self):
        bm = self._make_benchmark(["BLOCKED"])
        score = bm.run(include_benign=False)
        assert score.overall_grade in ("A+", "A", "A-")

    def test_benign_fp(self):
        bm = self._make_benchmark(["BLOCKED"])
        score = bm.run(include_benign=True)
        assert score.benign_tested == len(BENIGN_PAYLOADS)
        assert score.false_positive_rate == 1.0

    def test_per_class_present(self):
        bm = self._make_benchmark(["BLOCKED"])
        score = bm.run(include_benign=False)
        assert "SQL Injection" in score.per_class

    def test_progress_callback(self):
        bm = self._make_benchmark(["BLOCKED"])
        calls = []
        bm.run(include_benign=False, on_progress=lambda c, s: calls.append(c))
        assert len(calls) >= 1


# ---- comparison -----------------------------------------------------------

class TestCompare:
    def test_compare_output(self):
        a = BenchmarkScore(waf_name="A", detection_rate=0.9, false_positive_rate=0.05,
                           bypass_count=10, avg_response_ms=20)
        b = BenchmarkScore(waf_name="B", detection_rate=0.95, false_positive_rate=0.02,
                           bypass_count=5, avg_response_ms=15)
        result = compare(a, b)
        assert "Detection Rate" in result
        assert "WAF A" in result

    def test_compare_per_class(self):
        a = BenchmarkScore()
        a.per_class["SQLi"] = ClassScore("SQLi", detection_rate=0.9)
        b = BenchmarkScore()
        b.per_class["SQLi"] = ClassScore("SQLi", detection_rate=0.95)
        result = compare(a, b)
        assert "SQLi" in result


# ---- HTML report -----------------------------------------------------------

class TestHTMLReport:
    def test_html_contains_grade(self):
        s = BenchmarkScore(waf_name="TestWAF", overall_grade="A",
                           detection_rate=0.95, false_positive_rate=0.02)
        html = generate_html_report(s)
        assert "TestWAF" in html
        assert ">A<" in html

    def test_html_per_class(self):
        s = BenchmarkScore(waf_name="X", overall_grade="B")
        s.per_class["SQLi"] = ClassScore("SQLi", payloads_tested=100,
                                          blocked=90, passed=10, detection_rate=0.9)
        html = generate_html_report(s)
        assert "SQLi" in html
        assert "90.0%" in html

    def test_html_bypasses(self):
        s = BenchmarkScore(waf_name="X", overall_grade="C",
                           top_bypasses=[("sqli", "' OR 1=1--")])
        html = generate_html_report(s)
        assert "OR 1=1" in html


# ---- JSON I/O -------------------------------------------------------------

class TestIO:
    def test_json_roundtrip(self):
        s = BenchmarkScore(waf_name="TestWAF", overall_grade="B+",
                           detection_rate=0.91, false_positive_rate=0.03,
                           bypass_count=5, total_payloads=100)
        s.per_class["SQLi"] = ClassScore("SQLi", payloads_tested=50,
                                          blocked=45, passed=5, detection_rate=0.9)
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            write_benchmark_json(s, path)
            loaded = load_benchmark_json(path)
            assert loaded.waf_name == "TestWAF"
            assert loaded.overall_grade == "B+"
            assert "SQLi" in loaded.per_class
            assert loaded.per_class["SQLi"].detection_rate == pytest.approx(0.9)
        finally:
            os.unlink(path)

    def test_html_write(self):
        s = BenchmarkScore(waf_name="X", overall_grade="A")
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        try:
            write_html_report(s, path)
            with open(path) as f:
                html = f.read()
            assert "<!DOCTYPE html>" in html
            assert "X" in html
        finally:
            os.unlink(path)


# ---- profiles --------------------------------------------------------------

class TestProfiles:
    def test_list_profiles(self):
        profiles = list_profiles()
        assert len(profiles) >= 4

    def test_get_crs_pl1(self):
        p = get_profile("crs-pl1")
        assert p is not None
        assert "CRS" in p.name

    def test_get_unknown(self):
        assert get_profile("nonexistent") is None

    def test_all_profiles_have_fields(self):
        for p in list_profiles():
            assert p.key
            assert p.name
            assert p.default_url
            assert p.path


# ---- CLI -------------------------------------------------------------------

class TestCLI:
    def test_benchmark_subparser(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args(["benchmark", "--target", "https://test.com",
                             "--classes", "sqli,xss", "--no-benign"])
        assert args.target == "https://test.com"
        assert args.classes == "sqli,xss"
        assert args.no_benign is True

    def test_list_profiles_flag(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args(["benchmark", "--list-profiles"])
        assert args.list_profiles is True

    def test_compare_flag(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args(["benchmark", "--compare", "a.json", "b.json"])
        assert args.compare == ["a.json", "b.json"]
