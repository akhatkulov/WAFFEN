"""Tests for waffen/eval/coverage.py — WAF coverage scoring."""
from unittest.mock import MagicMock

from waffen.eval.coverage import (
    ClassScore,
    EvalResult,
    class_group,
    _classify,
    API_CLASSES,
)


class TestClassGroup:
    def test_api_classes(self):
        for cls in ("NoSQL Injection", "SSRF", "XXE Injection", "GraphQL"):
            assert class_group(cls) == "api", f"{cls} should be api"

    def test_app_classes(self):
        for cls in ("SQL Injection", "XSS Injection", "SSTI", "Command Injection"):
            assert class_group(cls) == "app", f"{cls} should be app"

    def test_unknown_defaults_to_app(self):
        assert class_group("FooBarBaz") == "app"

    def test_empty_string(self):
        assert class_group("") == "app"


class TestClassScore:
    def test_zero_state(self):
        cs = ClassScore()
        assert cs.blocked == 0
        assert cs.through == 0
        assert cs.resolved == 0
        assert cs.coverage == 0.0

    def test_coverage_calculation(self):
        cs = ClassScore(blocked=90, through=10)
        assert cs.resolved == 100
        assert cs.coverage == 90.0

    def test_coverage_all_blocked(self):
        cs = ClassScore(blocked=50, through=0)
        assert cs.coverage == 100.0

    def test_coverage_all_through(self):
        cs = ClassScore(blocked=0, through=50)
        assert cs.coverage == 0.0

    def test_unresolved_not_in_coverage(self):
        cs = ClassScore(blocked=5, through=5, unresolved=90)
        assert cs.resolved == 10
        assert cs.coverage == 50.0


class TestEvalResult:
    def test_empty(self):
        r = EvalResult()
        o = r.overall
        assert o.blocked == 0
        assert o.coverage == 0.0
        assert r.fp_rate == 0.0

    def test_overall_aggregates(self):
        r = EvalResult(per_class={
            "SQL Injection": ClassScore(blocked=80, through=20),
            "XSS Injection": ClassScore(blocked=70, through=30),
        })
        o = r.overall
        assert o.blocked == 150
        assert o.through == 50
        assert o.coverage == 75.0

    def test_fp_rate(self):
        r = EvalResult(benign_total=100, benign_blocked=5)
        assert r.fp_rate == 5.0

    def test_fp_rate_no_benign(self):
        r = EvalResult(benign_total=0, benign_blocked=0)
        assert r.fp_rate == 0.0

    def test_api_vs_app_coverage(self):
        r = EvalResult(per_class={
            "SQL Injection": ClassScore(blocked=90, through=10),
            "SSRF": ClassScore(blocked=50, through=50),
        })
        assert r.app_coverage == 90.0
        assert r.api_coverage == 50.0

    def test_as_dict_structure(self):
        r = EvalResult(
            target="https://test.com",
            per_class={"SQL Injection": ClassScore(blocked=9, through=1)},
            benign_total=10, benign_blocked=1,
        )
        d = r.as_dict()
        assert d["target"] == "https://test.com"
        assert d["overall"]["coverage_pct"] == 90.0
        assert d["false_positive_pct"] == 10.0
        assert "per_class" in d
        assert "api_vs_app" in d

    def test_as_dict_empty(self):
        d = EvalResult().as_dict()
        assert d["overall"]["coverage_pct"] == 0.0


class TestClassify:
    def test_naive_blocked(self):
        resp = MagicMock(verdict="BLOCKED")
        assert _classify(resp, None) == "block"

    def test_naive_through(self):
        resp = MagicMock(verdict="THROUGH")
        assert _classify(resp, None) == "pass"

    def test_naive_down(self):
        resp = MagicMock(verdict="DOWN")
        assert _classify(resp, None) == "down"

    def test_naive_unknown_verdict(self):
        resp = MagicMock(verdict="WEIRD")
        assert _classify(resp, None) == "pass"

    def test_calibration_used(self):
        resp = MagicMock(verdict="BLOCKED")
        cal = MagicMock()
        cal.waf_detected = True
        cal.confidence = 0.9
        cal.classify = MagicMock(return_value="block")
        assert _classify(resp, cal) == "block"
        cal.classify.assert_called_once_with(resp)

    def test_calibration_low_confidence_ignored(self):
        resp = MagicMock(verdict="THROUGH")
        cal = MagicMock()
        cal.waf_detected = True
        cal.confidence = 0.1
        result = _classify(resp, cal)
        assert result == "pass"

    def test_calibration_error_fallback(self):
        resp = MagicMock(verdict="BLOCKED")
        cal = MagicMock()
        cal.waf_detected = True
        cal.confidence = 0.9
        cal.classify = MagicMock(side_effect=RuntimeError("boom"))
        assert _classify(resp, cal) == "block"
