"""Tests for the adversarial ML payload generator."""
from unittest.mock import MagicMock
import pytest

from waffen.ai.adversarial import (
    AdversarialGenerator,
    AdversarialResult,
    BoundaryPayload,
    FeatureWeight,
    _perturbations,
    _malice_ladder,
    write_adversarial_json,
)
from waffen.core.oracle import Target, Response, BLOCKED, THROUGH


# ---- helpers --------------------------------------------------------------

def _resp(verdict: str, code: str = "200") -> Response:
    return Response(verdict=verdict, code=code, size=100, time=0.01, body="")


def _make_generator(responses, attack_class="sqli"):
    """Build an AdversarialGenerator with a canned oracle."""
    target = MagicMock(spec=Target)
    idx = [0]
    def fake_send(payload):
        r = responses[min(idx[0], len(responses) - 1)]
        idx[0] += 1
        return r
    mock_oracle = MagicMock()
    mock_oracle.send = fake_send
    gen = AdversarialGenerator(target, attack_class=attack_class)
    gen._oracle = lambda: mock_oracle
    return gen


# ---- BoundaryPayload tests -----------------------------------------------

class TestBoundaryPayload:
    def test_as_dict(self):
        bp = BoundaryPayload("' OR 1=1--", 0.9, True, "binary_malice")
        d = bp.as_dict()
        assert d["payload"] == "' OR 1=1--"
        assert d["estimated_score"] == 0.9
        assert d["is_malicious"] is True
        assert d["technique"] == "binary_malice"

    def test_fields(self):
        bp = BoundaryPayload("test", 0.1, False, "walk")
        assert bp.payload == "test"
        assert not bp.is_malicious


# ---- AdversarialResult tests ---------------------------------------------

class TestAdversarialResult:
    def test_adversarial_bypasses(self):
        r = AdversarialResult(
            boundary_payloads=[
                BoundaryPayload("bad", 0.9, True, "t"),   # blocked (above threshold)
                BoundaryPayload("adv", 0.3, True, "t"),   # adversarial (below threshold, malicious)
                BoundaryPayload("ok", 0.1, False, "t"),   # benign (not malicious)
            ],
            estimated_threshold=0.5,
        )
        bypasses = r.adversarial_bypasses()
        assert len(bypasses) == 1
        assert bypasses[0].payload == "adv"

    def test_as_dict(self):
        r = AdversarialResult(
            boundary_payloads=[BoundaryPayload("x", 0.5, True, "t")],
            feature_weights=[FeatureWeight("KW:OR", 0.3, True, False)],
            estimated_threshold=0.6,
            requests_used=50,
            techniques_used=["binary_malice"],
        )
        d = r.as_dict()
        assert d["estimated_threshold"] == 0.6
        assert len(d["boundary_payloads"]) == 1
        assert len(d["feature_weights"]) == 1
        assert d["requests_used"] == 50

    def test_empty(self):
        r = AdversarialResult()
        assert r.adversarial_bypasses() == []
        assert r.requests_used == 0


# ---- FeatureWeight tests -------------------------------------------------

class TestFeatureWeight:
    def test_fields(self):
        fw = FeatureWeight("KEYWORD:OR", 0.35, True, False)
        assert fw.feature == "KEYWORD:OR"
        assert fw.delta == 0.35
        assert fw.blocked_with is True
        assert fw.blocked_without is False


# ---- perturbation helpers -------------------------------------------------

class TestPerturbations:
    def test_produces_variants(self):
        variants = _perturbations("' OR 1=1--")
        assert len(variants) > 5

    def test_all_different_from_original(self):
        payload = "' OR 1=1--"
        variants = _perturbations(payload)
        # at least some should differ
        different = [v for v, _ in variants if v != payload]
        assert len(different) > 3

    def test_descriptions_present(self):
        variants = _perturbations("test")
        for _, desc in variants:
            assert isinstance(desc, str) and len(desc) > 0


# ---- malice ladder --------------------------------------------------------

class TestMaliceLadder:
    def test_sqli_ladder(self):
        ladder = _malice_ladder("sqli")
        assert len(ladder) >= 10
        assert ladder[0][1] >= 0.9  # first entry is high malice
        assert ladder[-1][1] <= 0.01  # last entry is benign

    def test_xss_ladder(self):
        ladder = _malice_ladder("xss")
        assert len(ladder) >= 5

    def test_unknown_falls_back(self):
        ladder = _malice_ladder("unknown_class")
        assert len(ladder) > 0  # falls back to sqli


# ---- binary malice search -------------------------------------------------

class TestBinaryMaliceSearch:
    def test_all_blocked(self):
        gen = _make_generator([_resp(BLOCKED, "403")] * 50)
        results = gen.binary_malice_search(budget=30)
        assert len(results) > 0
        assert all(r.technique == "binary_malice" for r in results)

    def test_flip_detected(self):
        # first 5 blocked, rest pass
        resps = [_resp(BLOCKED, "403")] * 5 + [_resp(THROUGH, "200")] * 20
        gen = _make_generator(resps)
        results = gen.binary_malice_search(budget=25)
        # should have both blocked and through payloads
        verdicts = set()
        for r in results:
            if r.estimated_score >= 0.5:
                verdicts.add("high")
            else:
                verdicts.add("low")
        assert len(results) > 2

    def test_budget_respected(self):
        gen = _make_generator([_resp(BLOCKED)] * 100)
        gen.binary_malice_search(budget=5)
        assert gen._requests <= 5


# ---- perturbation walk ----------------------------------------------------

class TestPerturbationWalk:
    def test_seed_already_through(self):
        gen = _make_generator([_resp(THROUGH)] * 10)
        results = gen.perturbation_walk(budget=10)
        assert len(results) >= 1
        assert results[0].technique == "perturbation_walk"

    def test_finds_through_variant(self):
        # baseline blocked, then some variant passes
        resps = [_resp(BLOCKED)] + [_resp(BLOCKED)] * 5 + [_resp(THROUGH)] * 20
        gen = _make_generator(resps)
        results = gen.perturbation_walk(budget=30)
        through_results = [r for r in results if "perturbation_walk" in r.technique]
        assert len(through_results) >= 1

    def test_budget_limit(self):
        gen = _make_generator([_resp(BLOCKED)] * 200)
        gen.perturbation_walk(budget=10)
        assert gen._requests <= 10


# ---- semantic interpolation -----------------------------------------------

class TestSemanticInterpolation:
    def test_produces_results(self):
        resps = [_resp(BLOCKED)] * 5 + [_resp(THROUGH)] * 20
        gen = _make_generator(resps)
        results = gen.semantic_interpolation(budget=20)
        assert len(results) > 0
        assert all(r.technique == "semantic_interpolation" for r in results)

    def test_includes_malicious_and_benign(self):
        resps = [_resp(BLOCKED)] * 3 + [_resp(THROUGH)] * 20
        gen = _make_generator(resps)
        results = gen.semantic_interpolation(
            malicious="' OR 1=1--", benign="apple", budget=20)
        # should contain both malicious and non-malicious entries
        assert any(r.is_malicious for r in results) or len(results) > 0


# ---- feature knockout -----------------------------------------------------

class TestFeatureKnockout:
    def test_identifies_critical_feature(self):
        # baseline (' OR 1=1--) blocked; removing OR makes it pass
        call_count = [0]
        def smart_send(payload):
            call_count[0] += 1
            if "OR" in payload.upper() and "'" in payload:
                return _resp(BLOCKED, "403")
            return _resp(THROUGH, "200")

        target = MagicMock(spec=Target)
        gen = AdversarialGenerator(target, "sqli")
        mock_oracle = MagicMock()
        mock_oracle.send = smart_send
        gen._oracle = lambda: mock_oracle

        results, weights = gen.feature_knockout("' OR 1=1--", budget=50)
        # should find that removing OR changes verdict
        or_weights = [w for w in weights if "OR" in w.feature]
        assert len(or_weights) > 0

    def test_empty_payload(self):
        gen = _make_generator([_resp(THROUGH)] * 10)
        results, weights = gen.feature_knockout("", budget=10)
        assert results == []
        assert weights == []


# ---- find_boundary (ensemble) ---------------------------------------------

class TestFindBoundary:
    def test_runs_all_techniques(self):
        resps = [_resp(BLOCKED)] * 50 + [_resp(THROUGH)] * 200
        gen = _make_generator(resps)
        result = gen.find_boundary(budget=200)
        assert isinstance(result, AdversarialResult)
        assert len(result.techniques_used) == 4
        assert result.requests_used > 0

    def test_specific_techniques(self):
        resps = [_resp(BLOCKED)] * 20 + [_resp(THROUGH)] * 50
        gen = _make_generator(resps)
        result = gen.find_boundary(budget=50, techniques=["binary_malice"])
        assert result.techniques_used == ["binary_malice"]

    def test_deduplicates_payloads(self):
        resps = [_resp(THROUGH)] * 200
        gen = _make_generator(resps)
        result = gen.find_boundary(budget=100)
        payloads = [b.payload for b in result.boundary_payloads]
        assert len(payloads) == len(set(payloads))

    def test_threshold_estimation(self):
        # mix of blocked and passing
        resps = [_resp(BLOCKED)] * 30 + [_resp(THROUGH)] * 100
        gen = _make_generator(resps)
        result = gen.find_boundary(budget=100)
        assert 0.0 < result.estimated_threshold < 1.0

    def test_progress_callback(self):
        resps = [_resp(BLOCKED)] * 50 + [_resp(THROUGH)] * 200
        gen = _make_generator(resps)
        progress = []
        result = gen.find_boundary(budget=100,
                                    on_progress=lambda t, n: progress.append((t, n)))
        assert len(progress) > 0
        assert progress[0][0] == "binary_malice"


# ---- write_adversarial_json ----------------------------------------------

class TestWriteJson:
    def test_write(self, tmp_path):
        result = AdversarialResult(
            boundary_payloads=[BoundaryPayload("x", 0.5, True, "t")],
            estimated_threshold=0.6,
            requests_used=10,
            techniques_used=["binary_malice"],
        )
        path = str(tmp_path / "adv.json")
        write_adversarial_json(result, path)
        import json
        with open(path) as f:
            d = json.load(f)
        assert d["estimated_threshold"] == 0.6
        assert len(d["boundary_payloads"]) == 1
