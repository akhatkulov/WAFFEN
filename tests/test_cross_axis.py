"""Tests for the cross-axis composition engine."""
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from waffen.search.cross_axis import (
    CrossAxisComposer,
    CrossAxisConfig,
    CrossAxisFinding,
    CrossAxisResult,
)
from waffen.search.beam import Finding, SearchResult
from waffen.engine import BypassRun


# ---- helpers ---------------------------------------------------------------

def _finding(payload, chain=None, code="200", cls="sqli"):
    return Finding(payload=payload, chain=chain or [], code=code, attack_class=cls)


def _run(transform, cls, findings, seed="seed"):
    return BypassRun(
        transform=transform,
        attack_class=cls,
        result=SearchResult(seed=seed, attack_class=cls, findings=findings),
    )


def _mock_target():
    t = MagicMock()
    t.base_url = "https://test.com"
    t.path = "/"
    t.param = "q"
    t.inject = "query"
    t.method = "GET"
    t.timeout = 5
    t.tls_verify = False
    t.extra_headers = ()
    t.cookie = ""
    t.block_signature = ""
    t.user_agent = "test"
    return t


# ---- ranking tests ---------------------------------------------------------

class TestPayloadRanking:
    def test_throughs_ranked_first(self):
        runs = [
            _run("identity", "sqli", [_finding("through1"), _finding("through2")]),
        ]
        ranked = CrossAxisComposer._rank_payloads(runs, 5)
        assert len(ranked) == 2
        assert ranked[0][0] == "through1"

    def test_deduplicates(self):
        runs = [
            _run("identity", "sqli", [_finding("same")]),
            _run("hpp_duplicate", "sqli", [_finding("same")]),
        ]
        ranked = CrossAxisComposer._rank_payloads(runs, 5)
        assert len(ranked) == 1

    def test_respects_limit(self):
        findings = [_finding(f"p{i}") for i in range(20)]
        runs = [_run("identity", "sqli", findings)]
        ranked = CrossAxisComposer._rank_payloads(runs, 3)
        assert len(ranked) == 3

    def test_empty_runs(self):
        ranked = CrossAxisComposer._rank_payloads([], 5)
        assert ranked == []

    def test_carries_metadata(self):
        runs = [_run("chunked_body", "xss", [_finding("xss1", chain=["m1", "m2"])])]
        ranked = CrossAxisComposer._rank_payloads(runs, 5)
        payload, chain, cls, tr = ranked[0]
        assert payload == "xss1"
        assert chain == ["m1", "m2"]
        assert cls == "xss"
        assert tr == "chunked_body"


class TestTransformRanking:
    def test_ranks_by_through_count(self):
        runs = [
            _run("identity", "sqli", [_finding("a")]),
            _run("hpp_duplicate", "sqli", [_finding("b"), _finding("c")]),
            _run("chunked_body", "sqli", []),
        ]
        ranked = CrossAxisComposer._rank_transforms(runs, 3)
        assert ranked[0] == "hpp_duplicate"
        assert ranked[1] == "identity"

    def test_includes_untried_transforms(self):
        runs = [_run("identity", "sqli", [_finding("a")])]
        ranked = CrossAxisComposer._rank_transforms(runs, 20)
        assert len(ranked) > 1
        assert "identity" in ranked

    def test_empty_runs(self):
        ranked = CrossAxisComposer._rank_transforms([], 5)
        assert len(ranked) > 0  # still returns available transforms


class TestAlreadyTested:
    def test_collects_pairs(self):
        runs = [
            _run("identity", "sqli", [_finding("p1"), _finding("p2")]),
            _run("hpp_duplicate", "sqli", [_finding("p1")]),
        ]
        tested = CrossAxisComposer._already_tested(runs)
        assert ("p1", "identity") in tested
        assert ("p2", "identity") in tested
        assert ("p1", "hpp_duplicate") in tested
        assert ("p2", "hpp_duplicate") not in tested


# ---- composer integration --------------------------------------------------

class TestCompose:
    def test_skips_same_transform(self):
        runs = [_run("identity", "sqli", [_finding("p1")])]
        cfg = CrossAxisConfig(top_payloads=5, top_transforms=5, budget=100)
        composer = CrossAxisComposer(_mock_target(), config=cfg)

        # Mock Oracle to return THROUGH for everything
        with patch("waffen.search.cross_axis.Oracle") as MockOracle:
            mock_inst = MagicMock()
            mock_inst.send.return_value = SimpleNamespace(
                verdict="THROUGH", code="200", through=True, size=100, time=0.1, body=""
            )
            MockOracle.return_value = mock_inst

            result = composer.compose(runs)

        assert result.pairs_skipped >= 1  # identity × identity skipped

    def test_finds_cross_axis_bypass(self):
        runs = [_run("identity", "sqli", [_finding("mutated_payload")])]
        cfg = CrossAxisConfig(top_payloads=5, top_transforms=3, budget=100)
        composer = CrossAxisComposer(_mock_target(), config=cfg)

        with patch("waffen.search.cross_axis.Oracle") as MockOracle:
            mock_inst = MagicMock()
            mock_inst.send.return_value = SimpleNamespace(
                verdict="THROUGH", code="200", through=True, size=100, time=0.1, body=""
            )
            MockOracle.return_value = mock_inst

            result = composer.compose(runs)

        assert result.requests > 0
        assert len(result.findings) > 0
        f = result.findings[0]
        assert f.payload == "mutated_payload"
        assert f.source_transform == "identity"
        assert f.transform != "identity"

    def test_respects_budget(self):
        findings = [_finding(f"p{i}") for i in range(20)]
        runs = [_run("identity", "sqli", findings)]
        cfg = CrossAxisConfig(top_payloads=20, top_transforms=20, budget=5)
        composer = CrossAxisComposer(_mock_target(), config=cfg)

        with patch("waffen.search.cross_axis.Oracle") as MockOracle:
            mock_inst = MagicMock()
            mock_inst.send.return_value = SimpleNamespace(
                verdict="BLOCKED", code="403", through=False, size=100, time=0.1, body=""
            )
            MockOracle.return_value = mock_inst

            result = composer.compose(runs)

        assert result.requests <= 5

    def test_no_findings_when_all_blocked(self):
        runs = [_run("identity", "sqli", [_finding("p1")])]
        cfg = CrossAxisConfig(top_payloads=5, top_transforms=5, budget=100)
        composer = CrossAxisComposer(_mock_target(), config=cfg)

        with patch("waffen.search.cross_axis.Oracle") as MockOracle:
            mock_inst = MagicMock()
            mock_inst.send.return_value = SimpleNamespace(
                verdict="BLOCKED", code="403", through=False, size=100, time=0.1, body=""
            )
            MockOracle.return_value = mock_inst

            result = composer.compose(runs)

        assert len(result.findings) == 0

    def test_empty_first_pass(self):
        cfg = CrossAxisConfig()
        composer = CrossAxisComposer(_mock_target(), config=cfg)
        result = composer.compose([])
        assert result.requests == 0
        assert result.findings == []


class TestCrossAxisFinding:
    def test_as_dict(self):
        f = CrossAxisFinding(
            payload="test", chain=["m1"], transform="hpp_duplicate",
            code="200", attack_class="sqli", source_transform="identity",
        )
        d = f.as_dict()
        assert d["payload"] == "test"
        assert d["transform"] == "hpp_duplicate"
        assert d["source_transform"] == "identity"


class TestCrossAxisResult:
    def test_defaults(self):
        r = CrossAxisResult()
        assert r.findings == []
        assert r.requests == 0
        assert r.pairs_tested == 0
        assert r.pairs_skipped == 0
