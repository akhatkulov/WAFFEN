"""Tests for the calibratable gradient scorer."""
import math

import pytest

from waffen.core.oracle import Response, BLOCKED, THROUGH, DOWN
from waffen.search.gradient import (
    GradientScorer,
    extract_features,
    N_FEATURES,
    _sigmoid,
    _status_bucket,
    _has_error_detail,
    _body_similarity,
    patch_oracle_scorer,
)


# ---- helpers ---------------------------------------------------------------

def _resp(verdict="BLOCKED", code="403", size=500, time=0.05, body="blocked"):
    return Response(verdict=verdict, code=code, size=size, time=time, body=body)


def _baseline():
    return _resp(BLOCKED, "403", 500, 0.05, "Request blocked by RedEye WAF")


# ---- feature extraction ---------------------------------------------------

class TestExtractFeatures:
    def test_returns_correct_length(self):
        feats = extract_features(_resp(), _baseline())
        assert len(feats) == N_FEATURES

    def test_all_features_are_float(self):
        feats = extract_features(_resp(), _baseline())
        assert all(isinstance(f, float) for f in feats)

    def test_blocked_baseline_same_response(self):
        bl = _baseline()
        feats = extract_features(bl, bl)
        assert feats[0] == 0.0   # status_bucket: 403 = 0
        assert feats[3] == 0.0   # status_changed: no
        assert feats[4] == 0.0   # is_5xx: no

    def test_200_response_high_status_bucket(self):
        resp = _resp(THROUGH, "200", 1000, 0.1, "success data")
        feats = extract_features(resp, _baseline())
        assert feats[0] == 1.0

    def test_500_response_features(self):
        resp = _resp(BLOCKED, "500", 200, 0.3, '{"error":"Internal Server Error"}')
        feats = extract_features(resp, _baseline())
        assert feats[0] == 0.5   # status_bucket: 5xx
        assert feats[3] == 1.0   # status_changed: yes
        assert feats[4] == 1.0   # is_5xx: yes
        assert feats[7] == 1.0   # error_detail: yes

    def test_redirect_feature(self):
        resp = _resp(BLOCKED, "302", 0, 0.02, "")
        feats = extract_features(resp, _baseline())
        assert feats[8] == 1.0

    def test_size_delta_feature(self):
        resp = _resp(BLOCKED, "403", 1000, 0.05, "x" * 1000)
        feats = extract_features(resp, _baseline())
        assert feats[1] == 1.0  # capped at 1.0

    def test_time_delta_feature(self):
        resp = _resp(BLOCKED, "403", 500, 0.5, "blocked")
        feats = extract_features(resp, _baseline())  # baseline.time = 0.05
        assert feats[2] > 0.5  # significantly slower

    def test_body_similarity_block(self):
        bl = _baseline()
        same = _resp(BLOCKED, "403", 500, 0.05, bl.body)
        feats = extract_features(same, bl)
        assert feats[5] < 0.1  # identical to block → low dissimilarity

    def test_body_dissimilarity(self):
        resp = _resp(BLOCKED, "403", 200, 0.05, "completely different content here xyz")
        feats = extract_features(resp, _baseline())
        assert feats[5] > 0.5  # very different from block page

    def test_error_detail_detection(self):
        resp = _resp(BLOCKED, "500", 200, 0.1, '{"error":"Internal Server Error"}')
        feats = extract_features(resp, _baseline())
        assert feats[7] == 1.0

    def test_no_error_detail(self):
        feats = extract_features(_baseline(), _baseline())
        assert feats[7] == 0.0

    def test_pass_body_similarity(self):
        pass_body = "success response with data"
        resp = _resp(BLOCKED, "200", 100, 0.1, "success response with data")
        feats = extract_features(resp, _baseline(), pass_body=pass_body)
        assert feats[6] > 0.9  # very similar to pass page


# ---- status bucket ---------------------------------------------------------

class TestStatusBucket:
    def test_200(self):
        assert _status_bucket("200") == 1.0

    def test_403(self):
        assert _status_bucket("403") == 0.0

    def test_500(self):
        assert _status_bucket("500") == 0.5

    def test_302(self):
        assert _status_bucket("302") == 0.6

    def test_empty(self):
        assert _status_bucket("") == 0.0

    def test_000(self):
        assert _status_bucket("000") == 0.0


# ---- body similarity -------------------------------------------------------

class TestBodySimilarity:
    def test_identical(self):
        assert _body_similarity("hello world", "hello world") == 1.0

    def test_empty(self):
        assert _body_similarity("", "hello") == 0.0

    def test_completely_different(self):
        sim = _body_similarity("aaaa bbbb cccc", "xxxx yyyy zzzz")
        assert sim < 0.2

    def test_partial_overlap(self):
        sim = _body_similarity("the quick brown fox", "the quick red cat")
        assert 0.2 < sim < 0.8


# ---- error detail ----------------------------------------------------------

class TestErrorDetail:
    def test_detects_internal_server_error(self):
        assert _has_error_detail("Internal Server Error") == 1.0

    def test_detects_traceback(self):
        assert _has_error_detail("Traceback (most recent call last)") == 1.0

    def test_no_error(self):
        assert _has_error_detail("Request blocked by WAF") == 0.0

    def test_empty(self):
        assert _has_error_detail("") == 0.0


# ---- sigmoid ---------------------------------------------------------------

class TestSigmoid:
    def test_zero(self):
        assert _sigmoid(0.0) == pytest.approx(0.5)

    def test_large_positive(self):
        assert _sigmoid(100.0) == pytest.approx(1.0, abs=1e-6)

    def test_large_negative(self):
        assert _sigmoid(-100.0) == pytest.approx(0.0, abs=1e-6)

    def test_symmetry(self):
        assert _sigmoid(2.0) + _sigmoid(-2.0) == pytest.approx(1.0)


# ---- GradientScorer --------------------------------------------------------

class TestGradientScorer:
    def test_default_construction(self):
        gs = GradientScorer()
        assert len(gs.weights) == N_FEATURES
        assert not gs.calibrated

    def test_through_dominates(self):
        gs = GradientScorer()
        bl = _baseline()
        resp = _resp(THROUGH, "200", 1000, 0.1, "data")
        assert gs.score_response(resp, bl) > 1e8

    def test_down_penalized(self):
        gs = GradientScorer()
        bl = _baseline()
        resp = _resp(DOWN, "000", 0, 0.0, "")
        assert gs.score_response(resp, bl) == -1.0

    def test_blocked_but_perturbed_scores_higher(self):
        gs = GradientScorer()
        bl = _baseline()
        same = _resp(BLOCKED, "403", 500, 0.05, bl.body)
        diff = _resp(BLOCKED, "500", 200, 0.3, '{"error":"Internal Server Error"}')
        s_same = gs.score_response(same, bl)
        s_diff = gs.score_response(diff, bl)
        assert s_diff > s_same

    def test_chain_penalty(self):
        gs = GradientScorer()
        bl = _baseline()
        resp = _resp(BLOCKED, "500", 200, 0.1, "error")
        s0 = gs.score_response(resp, bl, chain_len=0)
        s3 = gs.score_response(resp, bl, chain_len=3)
        assert s0 > s3

    def test_raw_score_range(self):
        gs = GradientScorer()
        feats = [0.5] * N_FEATURES
        raw = gs.raw_score(feats)
        assert 0.0 < raw < 1.0

    def test_set_baselines(self):
        gs = GradientScorer()
        gs.set_baselines("block page", "pass page")
        assert gs.block_body == "block page"
        assert gs.pass_body == "pass page"

    def test_as_dict(self):
        gs = GradientScorer()
        d = gs.as_dict()
        assert d["n_features"] == N_FEATURES
        assert "weights" in d
        assert isinstance(d["weights"], dict)


# ---- calibration -----------------------------------------------------------

class TestCalibration:
    def _separable_data(self):
        """Block samples: low features. Pass samples: high features."""
        block = [[0.0, 0.0, 0.5, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0] for _ in range(20)]
        passed = [[1.0, 0.8, 0.7, 1.0, 0.0, 0.9, 0.8, 0.0, 0.0, 1.0] for _ in range(20)]
        return block, passed

    def test_calibration_converges(self):
        gs = GradientScorer()
        block, passed = self._separable_data()
        loss = gs.calibrate_weights(block, passed)
        assert loss < 0.5
        assert gs.calibrated

    def test_calibrated_separates_correctly(self):
        gs = GradientScorer()
        block, passed = self._separable_data()
        gs.calibrate_weights(block, passed)

        block_score = gs.raw_score(block[0])
        pass_score = gs.raw_score(passed[0])
        assert pass_score > block_score
        assert pass_score > 0.7
        assert block_score < 0.3

    def test_empty_samples_returns_inf(self):
        gs = GradientScorer()
        assert gs.calibrate_weights([], [[1.0] * N_FEATURES]) == float("inf")
        assert not gs.calibrated

    def test_calibration_modifies_weights(self):
        gs = GradientScorer()
        orig = list(gs.weights)
        block, passed = self._separable_data()
        gs.calibrate_weights(block, passed)
        assert gs.weights != orig

    def test_noisy_data_still_converges(self):
        import random
        random.seed(42)
        gs = GradientScorer()
        block = [[random.uniform(0.0, 0.4) for _ in range(N_FEATURES)] for _ in range(30)]
        passed = [[random.uniform(0.6, 1.0) for _ in range(N_FEATURES)] for _ in range(30)]
        loss = gs.calibrate_weights(block, passed, iterations=120)
        assert loss < 1.0


# ---- patch_oracle_scorer ---------------------------------------------------

class TestPatchOracle:
    def test_patched_oracle_uses_scorer(self):
        from unittest.mock import MagicMock
        oracle = MagicMock()
        oracle.score = MagicMock(return_value=0.0)

        scorer = GradientScorer()
        original = patch_oracle_scorer(oracle, scorer)

        bl = _baseline()
        resp = _resp(BLOCKED, "500", 200, 0.3, "error")
        result = oracle.score(resp, bl)
        assert result != 0.0  # should use GradientScorer, not the mock's 0.0
