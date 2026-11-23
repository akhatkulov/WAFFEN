"""Tests for the WAF decision tree fingerprinting module."""
from unittest.mock import MagicMock

import pytest

from waffen.recon.decision_tree import (
    WAFPipeline,
    WAFDecisionTreeProber,
    DecisionTreeReport,
    ProbeResult,
    write_dtree_json,
)


# ── WAFPipeline tests ──────────────────────────────────────────────────

class TestWAFPipeline:
    def test_defaults_all_false(self):
        p = WAFPipeline()
        assert not p.decodes_url
        assert not p.strips_comments
        assert not p.checks_libinjection

    def test_processing_order_returns_tuples(self):
        p = WAFPipeline(decodes_url=True, checks_keywords=True)
        order = p.processing_order()
        assert isinstance(order, list)
        assert ("URL decode", True) in order
        assert ("Keyword match", True) in order

    def test_gaps_when_nothing_processed(self):
        p = WAFPipeline()
        gaps = p.gaps()
        assert "comments not stripped" in gaps
        assert "no base64 decode" in gaps
        assert "no libinjection" in gaps

    def test_gaps_shrink_when_features_enabled(self):
        p = WAFPipeline(strips_comments=True, decodes_base64=True,
                       checks_libinjection=True, normalizes_case=True)
        gaps = p.gaps()
        assert "comments not stripped" not in gaps
        assert "no base64 decode" not in gaps
        assert "no libinjection" not in gaps
        assert "case-sensitive matching" not in gaps

    def test_as_dict_has_all_fields(self):
        p = WAFPipeline(decodes_url=True)
        d = p.as_dict()
        assert d["decodes_url"] is True
        assert "gaps" in d
        assert isinstance(d["gaps"], list)

    def test_keyword_before_decode_in_gaps(self):
        p = WAFPipeline(keyword_before_decode=True)
        assert "keywords checked before decode" in p.gaps()


# ── ProbeResult ────────────────────────────────────────────────────────

class TestProbeResult:
    def test_fields(self):
        pr = ProbeResult("test", "payload", "base", "BLOCKED", "interp")
        assert pr.name == "test"
        assert pr.verdict == "BLOCKED"


# ── Mock oracle helper ─────────────────────────────────────────────────

class _FakeResponse:
    def __init__(self, verdict):
        self.verdict = verdict
        self.code = "403" if verdict == "BLOCKED" else "200"
        self.size = 100
        self.time = 0.01
        self.body = ""


def _make_prober(responses_map: dict):
    """Build a prober whose oracle returns verdicts based on payload content."""
    target = MagicMock()
    target.base_url = "https://test.com"
    target.path = "/"
    target.param = "q"

    def fake_send(payload):
        for key, verdict in responses_map.items():
            if key in payload:
                return _FakeResponse(verdict)
        return _FakeResponse("THROUGH")

    prober = WAFDecisionTreeProber(target)
    prober._oracle = MagicMock()
    prober._oracle.send = fake_send
    return prober


# ── Prober tests ───────────────────────────────────────────────────────

class TestProbeBaseline:
    def test_baseline_blocked(self):
        prober = _make_prober({"OR 1=1": "BLOCKED"})
        prober._probe_baseline()
        assert prober.pipeline.checks_keywords is True

    def test_baseline_through(self):
        prober = _make_prober({})
        prober._probe_baseline()
        assert prober.pipeline.checks_keywords is False


class TestProbeURLDecode:
    def test_url_encoded_blocked(self):
        prober = _make_prober({"%27%20OR": "BLOCKED"})
        prober._probe_url_decoding()
        assert prober.pipeline.decodes_url is True

    def test_url_encoded_through(self):
        prober = _make_prober({})
        prober._probe_url_decoding()
        assert prober.pipeline.decodes_url is False


class TestProbeDoubleURL:
    def test_double_encoded_blocked(self):
        prober = _make_prober({"%2527": "BLOCKED"})
        prober._probe_double_url_decoding()
        assert prober.pipeline.decodes_double_url is True

    def test_double_encoded_through(self):
        prober = _make_prober({})
        prober._probe_double_url_decoding()
        assert prober.pipeline.decodes_double_url is False


class TestProbeComments:
    def test_comment_stripped(self):
        prober = _make_prober({"O/**/R": "BLOCKED"})
        prober._probe_comment_stripping()
        assert prober.pipeline.strips_comments is True

    def test_comment_not_stripped(self):
        prober = _make_prober({})
        prober._probe_comment_stripping()
        assert prober.pipeline.strips_comments is False


class TestProbeInlineComments:
    def test_inline_blocked(self):
        prober = _make_prober({"UN/*x*/ION": "BLOCKED"})
        prober._probe_inline_comments()
        assert prober.pipeline.strips_inline_comments is True


class TestProbeWhitespace:
    def test_tab_blocked(self):
        prober = _make_prober({"\tOR\t": "BLOCKED"})
        prober._probe_whitespace_normalization()
        assert prober.pipeline.normalizes_whitespace is True

    def test_tab_through(self):
        prober = _make_prober({})
        prober._probe_whitespace_normalization()
        assert prober.pipeline.normalizes_whitespace is False


class TestProbeCase:
    def test_mixed_case_blocked(self):
        prober = _make_prober({"oR": "BLOCKED"})
        prober._probe_case_normalization()
        assert prober.pipeline.normalizes_case is True

    def test_mixed_case_through(self):
        prober = _make_prober({})
        prober._probe_case_normalization()
        assert prober.pipeline.normalizes_case is False


class TestProbeLibinjection:
    def test_libinjection_detected(self):
        prober = _make_prober({"OR 1=1": "BLOCKED"})
        # ' GLOB '* does NOT match "OR 1=1" → THROUGH
        prober._probe_libinjection()
        assert prober.pipeline.checks_libinjection is True

    def test_no_libinjection(self):
        prober = _make_prober({"OR 1=1": "BLOCKED", "GLOB": "BLOCKED"})
        prober._probe_libinjection()
        assert prober.pipeline.checks_libinjection is False


class TestProbeScoringEngine:
    def test_scoring_detected(self):
        prober = _make_prober({"OR 1=1": "BLOCKED"})
        # SELECT alone → THROUGH, combo → BLOCKED
        prober._probe_scoring_engine()
        assert prober.pipeline.checks_scoring is True


class TestProbeProcessingOrder:
    def test_decode_before_keyword(self):
        prober = _make_prober({"%4fR": "BLOCKED"})
        prober.pipeline.decodes_url = True
        prober._probe_processing_order()
        assert prober.pipeline.decode_before_keyword is True
        assert prober.pipeline.keyword_before_decode is False

    def test_keyword_before_decode(self):
        prober = _make_prober({})
        prober.pipeline.decodes_url = True
        prober._probe_processing_order()
        assert prober.pipeline.keyword_before_decode is True


class TestProbeRegex:
    def test_regex_detected(self):
        prober = _make_prober({"UNION%0aSELECT": "BLOCKED"})
        prober._probe_regex()
        assert prober.pipeline.checks_regex is True


# ── Full pipeline ──────────────────────────────────────────────────────

class TestProbeAll:
    def test_full_pipeline_all_blocked(self):
        """WAF that blocks everything → all features detected."""
        prober = _make_prober({
            "OR 1=1": "BLOCKED", "%27%20OR": "BLOCKED", "%2527": "BLOCKED",
            "＇": "BLOCKED", "&#39;": "BLOCKED", "JyBPUi": "BLOCKED",
            "O/**/R": "BLOCKED", "UN/*x*/ION": "BLOCKED", "\tOR\t": "BLOCKED",
            "oR": "BLOCKED", "GLOB": "BLOCKED", "SELECT": "BLOCKED",
            "UNION%0aSELECT": "BLOCKED", "%4fR": "BLOCKED",
        })
        pipeline = prober.probe_all()
        assert pipeline.decodes_url is True
        assert pipeline.decodes_double_url is True
        assert pipeline.strips_comments is True
        assert pipeline.normalizes_whitespace is True
        assert pipeline.normalizes_case is True

    def test_full_pipeline_minimal_waf(self):
        """WAF that only blocks basic SQLi → most features missing."""
        prober = _make_prober({"OR 1=1": "BLOCKED"})
        pipeline = prober.probe_all()
        assert pipeline.checks_keywords is True
        assert pipeline.decodes_double_url is False
        assert pipeline.strips_comments is False
        assert pipeline.decodes_base64 is False


# ── Recommendations ────────────────────────────────────────────────────

class TestRecommendMutations:
    def test_all_gaps_recommend_all(self):
        prober = _make_prober({"OR 1=1": "BLOCKED"})
        prober.probe_all()
        recs = prober.recommend_mutations()
        assert "ast_comment_split" in recs
        assert "base64" in recs

    def test_no_gaps_recommend_nothing(self):
        prober = _make_prober({
            "OR 1=1": "BLOCKED", "%27%20OR": "BLOCKED", "%2527": "BLOCKED",
            "＇": "BLOCKED", "&#39;": "BLOCKED", "JyBPUi": "BLOCKED",
            "O/**/R": "BLOCKED", "UN/*x*/ION": "BLOCKED", "\tOR\t": "BLOCKED",
            "oR": "BLOCKED", "GLOB": "BLOCKED", "SELECT": "BLOCKED",
            "UNION%0aSELECT": "BLOCKED", "%4fR": "BLOCKED",
        })
        prober.probe_all()
        recs = prober.recommend_mutations()
        assert "ast_comment_split" not in recs
        assert "base64" not in recs

    def test_keyword_before_decode_recommends_url_encode(self):
        prober = _make_prober({"OR 1=1": "BLOCKED"})
        prober.pipeline.keyword_before_decode = True
        recs = prober.recommend_mutations()
        assert "url_encode" in recs


# ── DecisionTreeReport ─────────────────────────────────────────────────

class TestDecisionTreeReport:
    def test_run_returns_report(self):
        prober = _make_prober({"OR 1=1": "BLOCKED"})
        report = prober.run()
        assert isinstance(report, DecisionTreeReport)
        assert report.requests_used > 0
        assert len(report.probes) > 0
        assert isinstance(report.recommended_mutations, list)

    def test_report_as_dict(self):
        prober = _make_prober({"OR 1=1": "BLOCKED"})
        report = prober.run()
        d = report.as_dict()
        assert "pipeline" in d
        assert "probes" in d
        assert "recommended_mutations" in d
        assert "requests_used" in d

    def test_write_json(self, tmp_path):
        prober = _make_prober({"OR 1=1": "BLOCKED"})
        report = prober.run()
        path = str(tmp_path / "dtree.json")
        write_dtree_json(report, path)
        import json
        with open(path) as f:
            data = json.load(f)
        assert "pipeline" in data
        assert data["requests_used"] > 0
