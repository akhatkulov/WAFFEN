"""Response clustering for advanced WAF calibration.

Standard calibration (calibrate.py) splits responses into binary block/pass
via known-bad + known-good probes. A scoring-engine WAF (like RedEye) often
has 3+ response classes:

  PASS       — request reached the origin (200, normal body)
  BLOCK      — hard block (403, WAF error page)
  CHALLENGE  — soft block / CAPTCHA / JS challenge (403/200, large body)
  RATELIMIT  — rate/connection throttle (429, small body)
  UNKNOWN    — doesn't fit any known pattern

This module discovers the full response taxonomy by sending a diverse mix of
probes, extracting feature vectors from each response, and running k-means
clustering (stdlib-only implementation) to group similar responses.

Usage:
    from waffen.verify.cluster import ResponseClusterer
    clusterer = ResponseClusterer(oracle)
    profile = clusterer.run()
    # profile.clusters → list of labelled clusters with centroids and examples
"""
from __future__ import annotations

import hashlib
import math
import random
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Probe payloads — diverse mix to trigger different WAF response classes
# ---------------------------------------------------------------------------

_PROBES: list[tuple[str, str]] = [
    # benign
    ("benign", "fresh orange juice"),
    ("benign", "weather today"),
    ("benign", "quarterly sales report"),
    ("benign", "red shoes size 10"),
    ("benign", "chocolate cake recipe"),
    ("benign", ""),
    ("benign", "42"),
    # obvious attacks (should trigger hard block)
    ("attack_high", "' OR 1=1--"),
    ("attack_high", "<script>alert(1)</script>"),
    ("attack_high", "' UNION SELECT NULL,NULL--"),
    ("attack_high", "../../../../etc/passwd"),
    # medium severity (might trigger soft block / challenge)
    ("attack_mid", "' OR '"),
    ("attack_mid", "<img src=x>"),
    ("attack_mid", "SELECT"),
    ("attack_mid", "1=1"),
    # edge / suspicious but not clearly malicious
    ("edge", "admin' --"),
    ("edge", "{{7*7}}"),
    ("edge", "${7*7}"),
    # noise / special chars
    ("noise", "a" * 2000),
    ("noise", "%00%0d%0a"),
]


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

@dataclass
class ProbeSample:
    payload: str
    label: str              # benign | attack_high | attack_mid | edge | noise
    status_code: int
    response_size: int
    header_count: int
    has_set_cookie: bool
    content_type: str
    body_prefix_hash: str   # md5 of first 512 bytes
    response_time: float

    def feature_vector(self) -> list[float]:
        """Numeric features for clustering."""
        return [
            float(self.status_code),
            float(self.response_size),
            float(self.header_count),
            float(self.has_set_cookie),
            # hash content_type to a numeric bucket
            float(hash(self.content_type) % 100),
            # hash body prefix to a numeric bucket
            float(int(self.body_prefix_hash[:8], 16) % 1000),
            self.response_time * 1000,  # ms
        ]


def _extract_sample(payload: str, label: str, resp) -> ProbeSample:
    """Extract features from an OracleResponse / Response."""
    body = getattr(resp, "body", "") or ""
    code_str = getattr(resp, "code", "0")
    try:
        code = int(code_str)
    except (ValueError, TypeError):
        code = 0

    prefix = body[:512].encode("utf-8", errors="replace")
    prefix_hash = hashlib.md5(prefix).hexdigest()

    # header count: infer from body structure or use a default
    # The Oracle's Response doesn't carry headers directly, so we approximate
    # from known patterns: a larger body with more diverse content = more headers
    hdr_count = 10  # reasonable default
    has_cookie = "set-cookie" in body.lower()[:2000]
    ct = "text/html"
    if body.lstrip().startswith("{"):
        ct = "application/json"
    elif body.lstrip().startswith("<?xml"):
        ct = "application/xml"

    return ProbeSample(
        payload=payload,
        label=label,
        status_code=code,
        response_size=getattr(resp, "size", len(body)),
        header_count=hdr_count,
        has_set_cookie=has_cookie,
        content_type=ct,
        body_prefix_hash=prefix_hash,
        response_time=getattr(resp, "time", 0.0),
    )


# ---------------------------------------------------------------------------
# k-means (stdlib-only)
# ---------------------------------------------------------------------------

def _euclidean(a: list[float], b: list[float]) -> float:
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))


def _normalize(points: list[list[float]]) -> tuple[list[list[float]], list[float], list[float]]:
    """Min-max normalize each feature to [0, 1]."""
    if not points:
        return [], [], []
    dims = len(points[0])
    mins = [min(p[d] for p in points) for d in range(dims)]
    maxs = [max(p[d] for p in points) for d in range(dims)]
    ranges = [maxs[d] - mins[d] if maxs[d] != mins[d] else 1.0 for d in range(dims)]
    normed = [[(p[d] - mins[d]) / ranges[d] for d in range(dims)] for p in points]
    return normed, mins, ranges


def _centroid(points: list[list[float]]) -> list[float]:
    if not points:
        return []
    dims = len(points[0])
    return [sum(p[d] for p in points) / len(points) for d in range(dims)]


def kmeans(
    points: list[list[float]],
    k: int,
    max_iter: int = 50,
    seed: int = 42,
) -> tuple[list[int], list[list[float]]]:
    """Run k-means clustering. Returns (assignments, centroids)."""
    if not points or k <= 0:
        return [], []
    n = len(points)
    if k >= n:
        return list(range(n)), list(points)

    rng = random.Random(seed)
    # k-means++ init
    centroids = [list(points[rng.randint(0, n - 1)])]
    for _ in range(1, k):
        dists = [min(_euclidean(p, c) ** 2 for c in centroids) for p in points]
        total = sum(dists)
        if total == 0:
            centroids.append(list(points[rng.randint(0, n - 1)]))
            continue
        r = rng.random() * total
        cumul = 0.0
        for i, d in enumerate(dists):
            cumul += d
            if cumul >= r:
                centroids.append(list(points[i]))
                break
        else:
            centroids.append(list(points[-1]))

    assignments = [0] * n
    for _ in range(max_iter):
        # assign
        changed = False
        for i, p in enumerate(points):
            dists = [_euclidean(p, c) for c in centroids]
            best = min(range(k), key=lambda j: dists[j])
            if assignments[i] != best:
                changed = True
                assignments[i] = best
        if not changed:
            break
        # recompute centroids
        for j in range(k):
            members = [points[i] for i in range(n) if assignments[i] == j]
            if members:
                centroids[j] = _centroid(members)

    return assignments, centroids


def silhouette_score(
    points: list[list[float]],
    assignments: list[int],
    k: int,
) -> float:
    """Simplified silhouette score (mean across all points)."""
    n = len(points)
    if n <= 1 or k <= 1:
        return 0.0

    # group points by cluster
    groups: dict[int, list[int]] = {j: [] for j in range(k)}
    for i, a in enumerate(assignments):
        groups[a].append(i)

    scores = []
    for i in range(n):
        ci = assignments[i]
        # a = mean distance to own cluster
        own = groups[ci]
        if len(own) <= 1:
            scores.append(0.0)
            continue
        a = sum(_euclidean(points[i], points[j]) for j in own if j != i) / (len(own) - 1)

        # b = min mean distance to any other cluster
        b = float("inf")
        for cj in range(k):
            if cj == ci or not groups[cj]:
                continue
            mean_dist = sum(_euclidean(points[i], points[j]) for j in groups[cj]) / len(groups[cj])
            b = min(b, mean_dist)

        if b == float("inf"):
            scores.append(0.0)
        else:
            denom = max(a, b)
            scores.append((b - a) / denom if denom > 0 else 0.0)

    return sum(scores) / len(scores) if scores else 0.0


# ---------------------------------------------------------------------------
# Cluster labelling
# ---------------------------------------------------------------------------

@dataclass
class ClusterInfo:
    label: str                  # PASS | BLOCK | CHALLENGE | RATELIMIT | UNKNOWN
    cluster_id: int
    centroid: list[float]
    size: int
    avg_status: float
    avg_size: float
    avg_time: float
    example_payloads: list[str] = field(default_factory=list)
    probe_labels: dict[str, int] = field(default_factory=dict)  # label → count


@dataclass
class CalibrationProfile:
    """Full response taxonomy discovered by clustering."""
    clusters: list[ClusterInfo]
    k: int
    silhouette: float
    total_probes: int
    samples: list[ProbeSample] = field(default_factory=list)

    def get_cluster(self, label: str) -> Optional[ClusterInfo]:
        for c in self.clusters:
            if c.label == label:
                return c
        return None

    def as_dict(self) -> dict:
        return {
            "k": self.k,
            "silhouette": round(self.silhouette, 3),
            "total_probes": self.total_probes,
            "clusters": [
                {
                    "label": c.label,
                    "cluster_id": c.cluster_id,
                    "size": c.size,
                    "avg_status": round(c.avg_status),
                    "avg_size": round(c.avg_size),
                    "avg_time_ms": round(c.avg_time * 1000, 1),
                    "examples": c.example_payloads[:3],
                    "probe_labels": c.probe_labels,
                }
                for c in self.clusters
            ],
        }


def _label_clusters(
    samples: list[ProbeSample],
    assignments: list[int],
    centroids: list[list[float]],
    k: int,
) -> list[ClusterInfo]:
    """Heuristic labeling based on which probe types land in each cluster."""
    groups: dict[int, list[ProbeSample]] = {j: [] for j in range(k)}
    for i, s in enumerate(samples):
        groups[assignments[i]].append(s)

    infos = []
    for j in range(k):
        members = groups[j]
        if not members:
            continue
        probe_labels: dict[str, int] = {}
        for m in members:
            probe_labels[m.label] = probe_labels.get(m.label, 0) + 1

        avg_status = sum(m.status_code for m in members) / len(members)
        avg_size = sum(m.response_size for m in members) / len(members)
        avg_time = sum(m.response_time for m in members) / len(members)

        examples = [m.payload for m in members[:5] if m.payload]

        infos.append(ClusterInfo(
            label="UNKNOWN",
            cluster_id=j,
            centroid=centroids[j],
            size=len(members),
            avg_status=avg_status,
            avg_size=avg_size,
            avg_time=avg_time,
            example_payloads=examples,
            probe_labels=probe_labels,
        ))

    # Assign labels based on probe composition
    for info in infos:
        benign_count = info.probe_labels.get("benign", 0) + info.probe_labels.get("noise", 0)
        attack_high = info.probe_labels.get("attack_high", 0)
        attack_mid = info.probe_labels.get("attack_mid", 0)
        total = info.size

        if total == 0:
            continue

        benign_ratio = benign_count / total
        attack_ratio = (attack_high + attack_mid) / total

        # Heuristic rules
        if benign_ratio > 0.5:
            info.label = "PASS"
        elif attack_high > 0 and attack_ratio > 0.5:
            # Distinguish BLOCK vs CHALLENGE by response size
            # CHALLENGE pages (CAPTCHA/JS) tend to be significantly larger
            if info.avg_size > 3000 and info.avg_status < 403:
                info.label = "CHALLENGE"
            else:
                info.label = "BLOCK"
        elif info.avg_status >= 429:
            info.label = "RATELIMIT"
        elif attack_mid > 0 and benign_count == 0:
            info.label = "CHALLENGE"
        else:
            info.label = "UNKNOWN"

    # If no BLOCK was assigned but attacks are present, pick the most attack-heavy
    labels_assigned = {i.label for i in infos}
    if "BLOCK" not in labels_assigned:
        best = max(
            (i for i in infos if i.label not in ("PASS",)),
            key=lambda i: i.probe_labels.get("attack_high", 0),
            default=None,
        )
        if best and best.probe_labels.get("attack_high", 0) > 0:
            best.label = "BLOCK"

    return infos


# ---------------------------------------------------------------------------
# Main clusterer
# ---------------------------------------------------------------------------

class ResponseClusterer:
    """Discover the full WAF response taxonomy via k-means clustering."""

    def __init__(self, oracle, probes: list[tuple[str, str]] | None = None):
        self._oracle = oracle
        self._probes = probes or _PROBES

    def collect_samples(self) -> list[ProbeSample]:
        """Send probes and extract feature vectors."""
        samples = []
        for label, payload in self._probes:
            resp = self._oracle.send(payload)
            samples.append(_extract_sample(payload, label, resp))
        return samples

    def cluster(
        self,
        samples: list[ProbeSample],
        k: int | None = None,
    ) -> tuple[list[int], list[list[float]], int, float]:
        """Cluster samples. Auto-selects k if not given."""
        raw_points = [s.feature_vector() for s in samples]
        normed, _, _ = _normalize(raw_points)

        if k is not None:
            assignments, centroids = kmeans(normed, k)
            sil = silhouette_score(normed, assignments, k)
            return assignments, centroids, k, sil

        # Try k=2..5, pick best silhouette
        best_k, best_sil = 2, -1.0
        best_assign: list[int] = []
        best_cents: list[list[float]] = []

        for try_k in range(2, min(6, len(samples))):
            a, c = kmeans(normed, try_k)
            s = silhouette_score(normed, a, try_k)
            if s > best_sil:
                best_sil = s
                best_k = try_k
                best_assign = a
                best_cents = c

        return best_assign, best_cents, best_k, best_sil

    def run(self, k: int | None = None) -> CalibrationProfile:
        """Full pipeline: collect → cluster → label → profile."""
        samples = self.collect_samples()
        assignments, centroids, chosen_k, sil = self.cluster(samples, k)
        clusters = _label_clusters(samples, assignments, centroids, chosen_k)

        return CalibrationProfile(
            clusters=clusters,
            k=chosen_k,
            silhouette=sil,
            total_probes=len(samples),
            samples=samples,
        )
