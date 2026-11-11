"""Tests for response clustering calibration."""
import math
from unittest.mock import MagicMock

import pytest

from waffen.verify.cluster import (
    CalibrationProfile,
    ClusterInfo,
    ProbeSample,
    ResponseClusterer,
    _centroid,
    _euclidean,
    _extract_sample,
    _label_clusters,
    _normalize,
    kmeans,
    silhouette_score,
)


# ---- math primitives ------------------------------------------------------

class TestEuclidean:
    def test_same_point(self):
        assert _euclidean([1, 2, 3], [1, 2, 3]) == 0.0

    def test_known_distance(self):
        assert abs(_euclidean([0, 0], [3, 4]) - 5.0) < 1e-9

    def test_single_dim(self):
        assert abs(_euclidean([0], [7]) - 7.0) < 1e-9


class TestNormalize:
    def test_basic(self):
        pts = [[0, 10], [5, 20], [10, 30]]
        normed, mins, ranges = _normalize(pts)
        assert normed[0] == [0.0, 0.0]
        assert normed[2] == [1.0, 1.0]
        assert abs(normed[1][0] - 0.5) < 1e-9

    def test_constant_feature(self):
        pts = [[5, 1], [5, 2], [5, 3]]
        normed, _, ranges = _normalize(pts)
        # constant dimension → range=1.0 (fallback), all normalized to 0.0
        assert all(p[0] == 0.0 for p in normed)

    def test_empty(self):
        normed, mins, ranges = _normalize([])
        assert normed == []


class TestCentroid:
    def test_basic(self):
        c = _centroid([[0, 0], [4, 4]])
        assert c == [2.0, 2.0]

    def test_single(self):
        c = _centroid([[3, 7]])
        assert c == [3.0, 7.0]

    def test_empty(self):
        assert _centroid([]) == []


# ---- k-means ---------------------------------------------------------------

class TestKmeans:
    def test_two_clear_clusters(self):
        # Two well-separated groups
        points = [[0, 0], [1, 0], [0, 1], [1, 1],   # cluster A near origin
                  [10, 10], [11, 10], [10, 11], [11, 11]]  # cluster B
        assignments, centroids = kmeans(points, 2)
        # Points 0-3 should be in one cluster, 4-7 in another
        assert assignments[0] == assignments[1] == assignments[2] == assignments[3]
        assert assignments[4] == assignments[5] == assignments[6] == assignments[7]
        assert assignments[0] != assignments[4]

    def test_k_equals_n(self):
        points = [[1], [2], [3]]
        assignments, centroids = kmeans(points, 3)
        assert len(set(assignments)) == 3

    def test_k_greater_than_n(self):
        points = [[1], [2]]
        assignments, centroids = kmeans(points, 5)
        assert len(assignments) == 2

    def test_single_point(self):
        assignments, centroids = kmeans([[5, 5]], 1)
        assert assignments == [0]

    def test_empty(self):
        assignments, centroids = kmeans([], 2)
        assert assignments == []

    def test_three_clusters(self):
        points = ([[0, 0]] * 5 + [[50, 50]] * 5 + [[100, 0]] * 5)
        assignments, _ = kmeans(points, 3)
        # Each group of 5 should share a cluster
        assert len(set(assignments[:5])) == 1
        assert len(set(assignments[5:10])) == 1
        assert len(set(assignments[10:])) == 1
        assert len(set(assignments)) == 3


# ---- silhouette ------------------------------------------------------------

class TestSilhouette:
    def test_perfect_clusters(self):
        points = [[0, 0], [1, 0], [100, 100], [101, 100]]
        assignments = [0, 0, 1, 1]
        score = silhouette_score(points, assignments, 2)
        assert score > 0.9  # should be very high

    def test_single_cluster(self):
        assert silhouette_score([[1, 2]], [0], 1) == 0.0

    def test_bad_clustering(self):
        # Interleaved assignment is worse than grouped
        points = [[0], [1], [10], [11]]
        good = silhouette_score(points, [0, 0, 1, 1], 2)
        bad = silhouette_score(points, [0, 1, 0, 1], 2)
        assert good > bad


# ---- feature extraction ----------------------------------------------------

class TestExtractSample:
    def test_basic(self):
        resp = MagicMock()
        resp.code = "403"
        resp.size = 1500
        resp.body = "<html>Request blocked by RedEye WAF</html>"
        resp.time = 0.05
        sample = _extract_sample("' OR 1=1--", "attack_high", resp)
        assert sample.status_code == 403
        assert sample.response_size == 1500
        assert sample.label == "attack_high"
        assert sample.payload == "' OR 1=1--"
        assert len(sample.feature_vector()) == 7

    def test_json_content_type(self):
        resp = MagicMock()
        resp.code = "200"
        resp.size = 500
        resp.body = '{"status":"success","data":[]}'
        resp.time = 0.1
        sample = _extract_sample("test", "benign", resp)
        assert sample.content_type == "application/json"

    def test_missing_body(self):
        resp = MagicMock()
        resp.code = "200"
        resp.size = 0
        resp.body = ""
        resp.time = 0.01
        sample = _extract_sample("", "benign", resp)
        assert sample.response_size == 0


# ---- cluster labelling -----------------------------------------------------

class TestLabelClusters:
    def _make_sample(self, label, status=200, size=1000):
        return ProbeSample(
            payload="x", label=label, status_code=status,
            response_size=size, header_count=10, has_set_cookie=False,
            content_type="text/html", body_prefix_hash="a" * 32,
            response_time=0.05,
        )

    def test_benign_cluster_gets_pass(self):
        samples = [self._make_sample("benign") for _ in range(5)]
        assignments = [0] * 5
        centroids = [[200, 1000, 10, 0, 50, 500, 50]]
        infos = _label_clusters(samples, assignments, centroids, 1)
        assert infos[0].label == "PASS"

    def test_attack_cluster_gets_block(self):
        samples = [self._make_sample("attack_high", status=403, size=1800) for _ in range(5)]
        assignments = [0] * 5
        centroids = [[403, 1800, 8, 0, 50, 500, 30]]
        infos = _label_clusters(samples, assignments, centroids, 1)
        assert infos[0].label == "BLOCK"

    def test_two_clusters_labelled(self):
        samples = ([self._make_sample("benign", status=200, size=3000)] * 4 +
                   [self._make_sample("attack_high", status=403, size=1800)] * 4)
        assignments = [0] * 4 + [1] * 4
        centroids = [[200, 3000, 10, 0, 50, 500, 100], [403, 1800, 8, 0, 50, 500, 30]]
        infos = _label_clusters(samples, assignments, centroids, 2)
        labels = {i.label for i in infos}
        assert "PASS" in labels
        assert "BLOCK" in labels

    def test_ratelimit_on_429(self):
        samples = [self._make_sample("attack_mid", status=429, size=200) for _ in range(3)]
        assignments = [0] * 3
        centroids = [[429, 200, 5, 0, 50, 500, 50]]
        infos = _label_clusters(samples, assignments, centroids, 1)
        assert infos[0].label == "RATELIMIT"


# ---- CalibrationProfile ---------------------------------------------------

class TestCalibrationProfile:
    def test_get_cluster(self):
        c = ClusterInfo(label="BLOCK", cluster_id=0, centroid=[], size=5,
                        avg_status=403, avg_size=1800, avg_time=0.03)
        p = CalibrationProfile(clusters=[c], k=2, silhouette=0.8, total_probes=20)
        assert p.get_cluster("BLOCK") is c
        assert p.get_cluster("PASS") is None

    def test_as_dict(self):
        c = ClusterInfo(label="PASS", cluster_id=0, centroid=[1.0, 2.0], size=10,
                        avg_status=200, avg_size=3000, avg_time=0.1,
                        example_payloads=["hello"], probe_labels={"benign": 10})
        p = CalibrationProfile(clusters=[c], k=1, silhouette=0.9, total_probes=10)
        d = p.as_dict()
        assert d["k"] == 1
        assert d["clusters"][0]["label"] == "PASS"
        assert d["clusters"][0]["avg_status"] == 200


# ---- full clusterer (mock oracle) -----------------------------------------

class TestResponseClusterer:
    def _mock_oracle(self, responses):
        """Oracle that returns canned responses in order."""
        oracle = MagicMock()
        idx = [0]
        def fake_send(payload):
            r = MagicMock()
            resp = responses[min(idx[0], len(responses) - 1)]
            r.code = resp.get("code", "200")
            r.size = resp.get("size", 1000)
            r.body = resp.get("body", "")
            r.time = resp.get("time", 0.05)
            idx[0] += 1
            return r
        oracle.send = fake_send
        return oracle

    def test_run_produces_profile(self):
        # 7 benign → 200, 4 attack_high → 403, rest → mixed
        resps = []
        for label, _ in _PROBES_FOR_TEST:
            if label in ("benign", "noise"):
                resps.append({"code": "200", "size": 3000, "body": '{"data":[]}', "time": 0.1})
            elif label == "attack_high":
                resps.append({"code": "403", "size": 1500, "body": "blocked", "time": 0.02})
            else:
                resps.append({"code": "403", "size": 2500, "body": "blocked maybe", "time": 0.05})

        oracle = self._mock_oracle(resps)
        probes = _PROBES_FOR_TEST
        clusterer = ResponseClusterer(oracle, probes=probes)
        profile = clusterer.run()

        assert isinstance(profile, CalibrationProfile)
        assert profile.k >= 2
        assert profile.total_probes == len(probes)
        assert len(profile.clusters) >= 2

    def test_auto_k_selection(self):
        # Clear two-group separation
        resps = ([{"code": "200", "size": 5000, "body": "ok", "time": 0.2}] * 10 +
                 [{"code": "403", "size": 500, "body": "blocked", "time": 0.01}] * 10)
        probes = ([("benign", f"b{i}") for i in range(10)] +
                  [("attack_high", f"a{i}") for i in range(10)])
        oracle = self._mock_oracle(resps)
        clusterer = ResponseClusterer(oracle, probes=probes)
        profile = clusterer.run()
        assert profile.k == 2  # should find 2 clear clusters


# Test probe list matching the default
from waffen.verify.cluster import _PROBES
_PROBES_FOR_TEST = _PROBES
