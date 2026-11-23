"""Tests for the WAFFEN SDK — public Python library API."""
from unittest.mock import patch, MagicMock
from dataclasses import fields

import pytest

from waffen.sdk import (
    _build_target,
    BypassResult, BypassFinding, FingerprintResult, DiscoverResult,
    ExploitResult, FuzzResult, FuzzMatchResult, ScoreProbeResult,
    OriginResult,
    bypass, fingerprint, discover, exploit, fuzz,
    score_probe, origin, defend, report,
)


# ---- dataclass structure tests ------------------------------------------------

class TestBypassResult:
    def test_has_bypass_true(self):
        r = BypassResult(findings=[], verified_count=1)
        assert r.has_bypass()

    def test_has_bypass_false(self):
        r = BypassResult(findings=[], verified_count=0)
        assert not r.has_bypass()

    def test_default_empty(self):
        r = BypassResult()
        assert r.findings == []
        assert r.total_requests == 0
        assert r.strategy == ""


class TestBypassFinding:
    def test_fields(self):
        f = BypassFinding(payload="x", chain=["a"], code="200")
        assert f.payload == "x"
        assert f.verified is None


class TestFingerprintResult:
    def test_default(self):
        r = FingerprintResult()
        assert r.name == "Unknown"
        assert r.confidence == 0.0

    def test_custom(self):
        r = FingerprintResult(name="Cloudflare", confidence=0.95, evidence="cf-ray")
        assert r.name == "Cloudflare"


class TestDiscoverResult:
    def test_default(self):
        r = DiscoverResult()
        assert r.injection_points == []
        assert r.best_point is None


class TestExploitResult:
    def test_default(self):
        r = ExploitResult()
        assert not r.success
        assert r.tables == []
        assert r.error == ""


class TestFuzzResult:
    def test_default(self):
        r = FuzzResult()
        assert r.total == 0
        assert r.rps == 0.0


class TestScoreProbeResult:
    def test_default(self):
        r = ScoreProbeResult()
        assert r.detected_keywords == []
        assert r.flip_index == -1


class TestOriginResult:
    def test_default(self):
        r = OriginResult()
        assert r.candidates == []
        assert r.verified == []


# ---- _build_target tests ------------------------------------------------------

class TestBuildTarget:
    def test_minimal(self):
        t = _build_target("https://example.com")
        assert t.base_url == "https://example.com"
        assert t.path == "/"
        assert t.param == "q"

    def test_custom(self):
        t = _build_target("https://x.com", path="/s", param="query",
                          cookie="sid=abc", method="POST", inject="json")
        assert t.path == "/s"
        assert t.param == "query"
        assert t.cookie == "sid=abc"
        assert t.method == "POST"

    def test_ignores_unknown_kwargs(self):
        t = _build_target("https://x.com", unknown_key="value")
        assert t.base_url == "https://x.com"


# ---- fingerprint SDK test ------------------------------------------------------

class TestFingerprintSDK:
    def test_no_matches(self):
        with patch("waffen.recon.fingerprint.fingerprint", return_value=[]):
            result = fingerprint("https://x.com")
        assert result.name == "Unknown"

    def test_with_mock(self):
        guess = MagicMock(name="Cloudflare", confidence=0.95, evidence="cf-ray")
        guess.name = "Cloudflare"
        guess.confidence = 0.95
        guess.evidence = "cf-ray"
        with patch("waffen.recon.fingerprint.fingerprint", return_value=[guess]):
            result = fingerprint("https://x.com")
        assert result.name == "Cloudflare"
        assert result.confidence == 0.95
        assert len(result.all_matches) == 1

    def test_no_waf(self):
        with patch("waffen.recon.fingerprint.fingerprint", return_value=[]):
            result = fingerprint("https://x.com")
        assert result.name == "Unknown"
        assert result.confidence == 0.0


# ---- defend SDK test -----------------------------------------------------------

class TestDefendSDK:
    def test_generates_string(self):
        with patch("waffen.report.defend.generate_rules", return_value=[]):
            with patch("waffen.report.defend.render_rules", return_value="# no rules"):
                result = defend([], engine="modsecurity")
        assert isinstance(result, str)


# ---- report SDK test -----------------------------------------------------------

class TestReportSDK:
    def test_html_format(self):
        with patch("waffen.report.professional.generate_html_report",
                   return_value="<html>test</html>"):
            result = report([], format="html")
        assert "<html>" in result

    def test_csv_format(self):
        findings = [{"attack_class": "sqli", "payload": "' OR 1=1--",
                     "chain": ["base64"], "code": "200", "verified": True}]
        result = report(findings, format="csv")
        assert "attack_class" in result
        assert "sqli" in result

    def test_csv_empty(self):
        result = report([], format="csv")
        assert "attack_class" in result  # header still present

    def test_unknown_format_raises(self):
        with pytest.raises(ValueError, match="Unknown report format"):
            report([], format="pdf")

    def test_sarif_format(self):
        with patch("waffen.report.sarif.findings_to_sarif",
                   return_value={"runs": []}):
            result = report([], format="sarif")
        assert '"runs"' in result


# ---- lazy import test ----------------------------------------------------------

class TestLazyImport:
    def test_bypass_importable_from_waffen(self):
        import waffen
        assert hasattr(waffen, "bypass")
        assert callable(waffen.bypass)

    def test_fingerprint_importable(self):
        import waffen
        assert hasattr(waffen, "fingerprint")

    def test_result_classes_importable(self):
        import waffen
        assert hasattr(waffen, "BypassResult")
        assert hasattr(waffen, "FingerprintResult")

    def test_unknown_attr_raises(self):
        import waffen
        with pytest.raises(AttributeError):
            _ = waffen.nonexistent_thing
