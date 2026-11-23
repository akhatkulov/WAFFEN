"""Tests for the side-channel WAF oracle."""
import statistics
from unittest.mock import MagicMock, patch

import pytest

from waffen.recon.sidechannel import (
    SideChannelOracle,
    SideChannelReport,
    TimingProbe,
    RuleCluster,
    default_probes,
    _kmeans_1d,
    _silhouette_1d,
    _auto_cluster,
)
from waffen.core.oracle import Target, Response


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_target():
    return Target(base_url="https://test.local", path="/search", param="q")


def _mock_oracle_factory(timing_map: dict[str, float],
                         verdict_map: dict[str, str] | None = None):
    """Return a SideChannelOracle whose _send_timed returns controlled timing."""
    target = _make_target()
    oracle = SideChannelOracle(target, samples_per_probe=1)

    default_time = 20.0
    default_verdict = "BLOCKED"

    def fake_send_timed(payload):
        t = timing_map.get(payload, default_time)
        v = (verdict_map or {}).get(payload, default_verdict)
        resp = Response(verdict=v, code="403" if v == "BLOCKED" else "200",
                        size=100, time=t / 1000.0, body="")
        oracle._total_reqs += 1
        return resp, t

    oracle._send_timed = fake_send_timed
    return oracle


# ---------------------------------------------------------------------------
# TimingProbe
# ---------------------------------------------------------------------------

class TestTimingProbe:
    def test_as_dict(self):
        p = TimingProbe(payload="test", times=[10.0, 12.0], median_ms=11.0,
                        verdict="BLOCKED", code="403", estimated_score=0.75)
        d = p.as_dict()
        assert d["payload"] == "test"
        assert d["median_ms"] == 11.0
        assert d["estimated_score"] == 0.75
        assert d["samples"] == 2

    def test_defaults(self):
        p = TimingProbe(payload="x")
        assert p.times == []
        assert p.median_ms == 0.0
        assert p.estimated_score == 0.0


# ---------------------------------------------------------------------------
# RuleCluster
# ---------------------------------------------------------------------------

class TestRuleCluster:
    def test_as_dict(self):
        c = RuleCluster(cluster_id=0, label="light_inspection",
                        median_ms=15.3, count=5, payloads=["a", "b"])
        d = c.as_dict()
        assert d["label"] == "light_inspection"
        assert d["count"] == 5
        assert len(d["payloads"]) == 2

    def test_payload_cap(self):
        c = RuleCluster(0, "", 10.0, 20, payloads=[str(i) for i in range(20)])
        d = c.as_dict()
        assert len(d["payloads"]) == 10


# ---------------------------------------------------------------------------
# SideChannelReport
# ---------------------------------------------------------------------------

class TestSideChannelReport:
    def test_as_dict(self):
        r = SideChannelReport(baseline_ms=10.0, blocked_ms=50.0,
                              timing_range_ms=40.0, total_requests=100)
        d = r.as_dict()
        assert d["baseline_ms"] == 10.0
        assert d["total_requests"] == 100

    def test_empty_defaults(self):
        r = SideChannelReport()
        assert r.probes == []
        assert r.rule_clusters == []
        assert r.gap_payloads == []


# ---------------------------------------------------------------------------
# Default probes
# ---------------------------------------------------------------------------

class TestDefaultProbes:
    def test_has_categories(self):
        probes = default_probes()
        cats = {cat for cat, _ in probes}
        assert "benign" in cats
        assert "attack_high" in cats

    def test_non_empty(self):
        assert len(default_probes()) >= 20


# ---------------------------------------------------------------------------
# 1D k-means
# ---------------------------------------------------------------------------

class TestKmeans1D:
    def test_two_clusters(self):
        values = [1.0, 2.0, 3.0, 100.0, 101.0, 102.0]
        assign = _kmeans_1d(values, 2)
        low = {assign[0], assign[1], assign[2]}
        high = {assign[3], assign[4], assign[5]}
        assert len(low) == 1
        assert len(high) == 1
        assert low != high

    def test_single_value(self):
        assign = _kmeans_1d([5.0], 1)
        assert assign == [0]

    def test_k_exceeds_n(self):
        assign = _kmeans_1d([1.0, 2.0], 5)
        assert len(assign) == 2

    def test_three_clusters(self):
        values = [1.0, 1.1, 1.2, 50.0, 50.1, 50.2, 200.0, 200.1, 200.2]
        assign = _kmeans_1d(values, 3)
        assert len(set(assign)) == 3
        low = {assign[0], assign[1], assign[2]}
        mid = {assign[3], assign[4], assign[5]}
        high = {assign[6], assign[7], assign[8]}
        assert len(low) == 1 and len(mid) == 1 and len(high) == 1
        assert low != mid and mid != high and low != high


# ---------------------------------------------------------------------------
# Silhouette
# ---------------------------------------------------------------------------

class TestSilhouette:
    def test_perfect_separation(self):
        values = [0.0, 0.0, 0.0, 100.0, 100.0, 100.0]
        assign = [0, 0, 0, 1, 1, 1]
        s = _silhouette_1d(values, assign, 2)
        assert s > 0.9

    def test_poor_separation(self):
        values = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0]
        assign = [0, 1, 0, 1, 0, 1]
        s = _silhouette_1d(values, assign, 2)
        assert s < 0.5

    def test_single_cluster(self):
        s = _silhouette_1d([1, 2, 3], [0, 0, 0], 1)
        assert s == 0.0


# ---------------------------------------------------------------------------
# Auto cluster
# ---------------------------------------------------------------------------

class TestAutoCluster:
    def test_finds_two(self):
        values = [1, 2, 3, 100, 101, 102]
        assign, k = _auto_cluster(values, max_k=5)
        assert k == 2
        assert len(assign) == 6

    def test_minimum_points(self):
        values = [1, 2, 3]
        assign, k = _auto_cluster(values, max_k=3)
        assert k == 2
        assert len(assign) == 3


# ---------------------------------------------------------------------------
# SideChannelOracle — calibration
# ---------------------------------------------------------------------------

class TestCalibrateTiming:
    def test_returns_baseline_and_ceiling(self):
        timing = {}
        from waffen.recon.sidechannel import _BENIGN, _ATTACK_HIGH
        for p in _BENIGN[:5]:
            timing[p] = 10.0
        for p in _ATTACK_HIGH[:3]:
            timing[p] = 50.0
        oracle = _mock_oracle_factory(timing)
        baseline, ceiling = oracle.calibrate_timing()
        assert baseline == pytest.approx(10.0, abs=1.0)
        assert ceiling == pytest.approx(50.0, abs=1.0)

    def test_ceiling_equals_baseline_when_no_waf(self):
        timing = {}
        from waffen.recon.sidechannel import _BENIGN, _ATTACK_HIGH
        for p in _BENIGN[:5]:
            timing[p] = 15.0
        for p in _ATTACK_HIGH[:3]:
            timing[p] = 15.0
        oracle = _mock_oracle_factory(timing)
        baseline, ceiling = oracle.calibrate_timing()
        assert abs(ceiling - baseline) < 2.0


# ---------------------------------------------------------------------------
# Score estimation
# ---------------------------------------------------------------------------

class TestEstimateScore:
    def test_low_timing_low_score(self):
        oracle = _mock_oracle_factory({})
        p = TimingProbe(payload="test", median_ms=10.0)
        score = oracle.estimate_score(p, baseline=10.0, ceiling=50.0)
        assert score == pytest.approx(0.0, abs=0.05)

    def test_high_timing_high_score(self):
        oracle = _mock_oracle_factory({})
        p = TimingProbe(payload="test", median_ms=50.0)
        score = oracle.estimate_score(p, baseline=10.0, ceiling=50.0)
        assert score == pytest.approx(1.0, abs=0.05)

    def test_mid_timing_mid_score(self):
        oracle = _mock_oracle_factory({})
        p = TimingProbe(payload="test", median_ms=30.0)
        score = oracle.estimate_score(p, baseline=10.0, ceiling=50.0)
        assert 0.4 <= score <= 0.6

    def test_zero_range(self):
        oracle = _mock_oracle_factory({})
        p = TimingProbe(payload="test", median_ms=10.0)
        score = oracle.estimate_score(p, baseline=10.0, ceiling=10.0)
        assert score == 0.5

    def test_clamps_above_ceiling(self):
        oracle = _mock_oracle_factory({})
        p = TimingProbe(payload="test", median_ms=100.0)
        score = oracle.estimate_score(p, baseline=10.0, ceiling=50.0)
        assert score == 1.0

    def test_clamps_below_baseline(self):
        oracle = _mock_oracle_factory({})
        p = TimingProbe(payload="test", median_ms=5.0)
        score = oracle.estimate_score(p, baseline=10.0, ceiling=50.0)
        assert score == 0.0


# ---------------------------------------------------------------------------
# Probe timing
# ---------------------------------------------------------------------------

class TestProbeTiming:
    def test_collects_times(self):
        oracle = _mock_oracle_factory({"hello": 25.0})
        oracle.samples = 3
        p = oracle.probe_timing("hello")
        assert len(p.times) == 3
        assert p.median_ms == pytest.approx(25.0, abs=1.0)

    def test_records_verdict(self):
        oracle = _mock_oracle_factory(
            {"test": 10.0}, verdict_map={"test": "THROUGH"})
        p = oracle.probe_timing("test")
        assert p.verdict == "THROUGH"


# ---------------------------------------------------------------------------
# Rule cluster mapping
# ---------------------------------------------------------------------------

class TestMapRuleClusters:
    def test_separates_fast_and_slow(self):
        oracle = _mock_oracle_factory({})
        fast = [TimingProbe(f"f{i}", median_ms=10.0) for i in range(5)]
        slow = [TimingProbe(f"s{i}", median_ms=100.0) for i in range(5)]
        clusters = oracle.map_rule_clusters(fast + slow)
        assert len(clusters) >= 2
        medians = sorted(c.median_ms for c in clusters)
        assert medians[0] < 50 < medians[-1]

    def test_few_probes(self):
        oracle = _mock_oracle_factory({})
        probes = [TimingProbe("a", median_ms=10.0), TimingProbe("b", median_ms=20.0)]
        clusters = oracle.map_rule_clusters(probes)
        assert len(clusters) == 1
        assert clusters[0].count == 2


# ---------------------------------------------------------------------------
# Label clusters
# ---------------------------------------------------------------------------

class TestLabelClusters:
    def test_labels_by_position(self):
        oracle = _mock_oracle_factory({})
        clusters = [
            RuleCluster(0, "", 10.0, 5),
            RuleCluster(1, "", 25.0, 3),
            RuleCluster(2, "", 45.0, 2),
        ]
        labeled = oracle._label_clusters(clusters, baseline=10.0, ceiling=50.0)
        assert labeled[0].label == "no_processing"
        assert labeled[2].label in ("deep_inspection", "full_rule_chain")

    def test_zero_range_gives_unknown(self):
        oracle = _mock_oracle_factory({})
        clusters = [RuleCluster(0, "", 10.0, 5)]
        labeled = oracle._label_clusters(clusters, baseline=10.0, ceiling=10.0)
        assert labeled[0].label == "unknown"


# ---------------------------------------------------------------------------
# Timing boundary
# ---------------------------------------------------------------------------

class TestTimingBoundary:
    def test_produces_probes(self):
        timing = {}
        for i in range(20):
            timing["' OR 1=1--"[:i + 1]] = 10.0 + i * 2
        oracle = _mock_oracle_factory(timing)
        oracle.samples = 1
        probes = oracle.find_timing_boundary("' OR 1=1--", max_probes=5)
        assert len(probes) == 5
        assert probes[0].payload == "' OR 1=1--"


# ---------------------------------------------------------------------------
# Full run
# ---------------------------------------------------------------------------

class TestFullRun:
    def test_run_with_defaults(self):
        timing = {}
        from waffen.recon.sidechannel import _BENIGN, _ATTACK_HIGH
        for p in _BENIGN:
            timing[p] = 10.0
        for p in _ATTACK_HIGH:
            timing[p] = 50.0
        oracle = _mock_oracle_factory(timing)
        oracle.samples = 1
        report = oracle.run()
        assert report.baseline_ms == pytest.approx(10.0, abs=2.0)
        assert report.blocked_ms == pytest.approx(50.0, abs=2.0)
        assert len(report.probes) > 0
        assert report.total_requests > 0

    def test_run_with_custom_payloads(self):
        timing = {"a": 5.0, "b": 50.0, "c": 100.0}
        oracle = _mock_oracle_factory(timing)
        oracle.samples = 1
        report = oracle.run(payloads=["a", "b", "c"])
        assert len(report.probes) == 3

    def test_gap_payloads_found(self):
        timing = {}
        from waffen.recon.sidechannel import _BENIGN, _ATTACK_HIGH
        for p in _BENIGN:
            timing[p] = 10.0
        for p in _ATTACK_HIGH:
            timing[p] = 50.0
        from waffen.recon.sidechannel import _ATTACK_LOW
        for p in _ATTACK_LOW:
            timing[p] = 11.0
        oracle = _mock_oracle_factory(timing)
        oracle.samples = 1
        report = oracle.run()
        assert isinstance(report.gap_payloads, list)

    def test_report_as_dict(self):
        timing = {"x": 10.0, "y": 50.0, "z": 30.0}
        oracle = _mock_oracle_factory(timing)
        oracle.samples = 1
        report = oracle.run(payloads=["x", "y", "z"])
        d = report.as_dict()
        assert "baseline_ms" in d
        assert "probes" in d
        assert "rule_clusters" in d


# ---------------------------------------------------------------------------
# CLI parser
# ---------------------------------------------------------------------------

class TestCLI:
    def test_parser_has_sidechannel(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args(["sidechannel", "--target", "https://t.com"])
        assert hasattr(args, "func")

    def test_parser_accepts_payloads(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args(["sidechannel", "--target", "https://t.com",
                             "--samples", "3"])
        assert args.samples == 3
