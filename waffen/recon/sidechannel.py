"""Side-channel WAF oracle — extract internal scoring from timing and response metadata.

A WAF evaluates more rules against a suspicious payload than a benign one.
This shows in response time: a payload scoring 0.95 internally spends more
time in the rule engine than one scoring 0.10.  By measuring timing across
many payloads, we can:

  1. Approximate the WAF's internal confidence score per payload
  2. Cluster payloads by processing cost → map the WAF's rule groups
  3. Find "gap payloads" that the WAF barely processes (potential bypasses)
  4. Locate the timing boundary between block and pass

Non-destructive: uses the standard Oracle for transport.

Usage:
    oracle = SideChannelOracle(target, samples_per_probe=5)
    report = oracle.run(payloads)
    for c in report.rule_clusters:
        print(c["label"], c["count"], c["median_ms"])
"""
from __future__ import annotations

import math
import statistics
import time
from dataclasses import dataclass, field
from typing import Sequence, Callable, Optional

from ..core.oracle import Oracle, Target, Response, BLOCKED, THROUGH


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class TimingProbe:
    payload: str
    times: list[float] = field(default_factory=list)
    median_ms: float = 0.0
    verdict: str = ""
    code: str = ""
    estimated_score: float = 0.0

    def as_dict(self) -> dict:
        return {
            "payload": self.payload,
            "median_ms": round(self.median_ms, 2),
            "verdict": self.verdict,
            "code": self.code,
            "estimated_score": round(self.estimated_score, 3),
            "samples": len(self.times),
        }


@dataclass
class RuleCluster:
    cluster_id: int
    label: str
    median_ms: float
    count: int
    payloads: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "cluster_id": self.cluster_id,
            "label": self.label,
            "median_ms": round(self.median_ms, 2),
            "count": self.count,
            "payloads": self.payloads[:10],
        }


@dataclass
class SideChannelReport:
    baseline_ms: float = 0.0
    blocked_ms: float = 0.0
    timing_range_ms: float = 0.0
    probes: list[TimingProbe] = field(default_factory=list)
    rule_clusters: list[RuleCluster] = field(default_factory=list)
    gap_payloads: list[str] = field(default_factory=list)
    estimated_rule_groups: int = 0
    total_requests: int = 0

    def as_dict(self) -> dict:
        return {
            "baseline_ms": round(self.baseline_ms, 2),
            "blocked_ms": round(self.blocked_ms, 2),
            "timing_range_ms": round(self.timing_range_ms, 2),
            "total_requests": self.total_requests,
            "estimated_rule_groups": self.estimated_rule_groups,
            "gap_payloads": self.gap_payloads[:20],
            "probes": [p.as_dict() for p in self.probes],
            "rule_clusters": [c.as_dict() for c in self.rule_clusters],
        }


# ---------------------------------------------------------------------------
# Default probe payloads (diverse severity levels)
# ---------------------------------------------------------------------------

_BENIGN = [
    "fresh orange juice", "weather today", "quarterly sales report",
    "red shoes size 10", "chocolate cake recipe", "42", "hello world",
    "python tutorial", "best restaurants", "how to cook pasta",
]

_ATTACK_HIGH = [
    "' OR 1=1-- -", "' UNION SELECT 1,2,3--", "<script>alert(1)</script>",
    "../../../../etc/passwd", "' AND 1=1-- -",
]

_ATTACK_MEDIUM = [
    "' OR 'a'='a", "1 AND 1=1", "<img src=x>", "SELECT version()",
    "UNION ALL", "ORDER BY 100", "' HAVING 1=1--",
]

_ATTACK_LOW = [
    "' GLOB '*", "' COLLATE NOCASE", "typeof(1)", "' ISNULL",
    "sqlite_version()", "BENCHMARK(1,1)", "' RLIKE '.*",
]

_ATTACK_EXOTIC = [
    "' GLOB iif(1,'*','')--", "{{7*7}}", "${7*7}", "'; cat /etc/passwd",
    "' SOUNDS LIKE '", "WAITFOR DELAY '0:0:1'",
]


def default_probes() -> list[tuple[str, str]]:
    """Return (category, payload) tuples for diverse coverage."""
    out: list[tuple[str, str]] = []
    for p in _BENIGN:
        out.append(("benign", p))
    for p in _ATTACK_HIGH:
        out.append(("attack_high", p))
    for p in _ATTACK_MEDIUM:
        out.append(("attack_medium", p))
    for p in _ATTACK_LOW:
        out.append(("attack_low", p))
    for p in _ATTACK_EXOTIC:
        out.append(("attack_exotic", p))
    return out


# ---------------------------------------------------------------------------
# Clustering (reuse math from verify/cluster.py)
# ---------------------------------------------------------------------------

def _kmeans_1d(values: list[float], k: int, max_iter: int = 50,
               seed: int = 42) -> list[int]:
    """Simple 1-dimensional k-means for timing values."""
    import random as _rng
    r = _rng.Random(seed)
    n = len(values)
    if k >= n:
        return list(range(n))

    centroids = sorted(r.sample(values, k))
    assignments = [0] * n

    for _ in range(max_iter):
        changed = False
        for i, v in enumerate(values):
            best = min(range(k), key=lambda j: abs(v - centroids[j]))
            if assignments[i] != best:
                changed = True
                assignments[i] = best
        if not changed:
            break
        for j in range(k):
            members = [values[i] for i in range(n) if assignments[i] == j]
            if members:
                centroids[j] = statistics.mean(members)

    return assignments


def _silhouette_1d(values: list[float], assignments: list[int], k: int) -> float:
    """Silhouette score for 1D data."""
    n = len(values)
    if n <= k or k <= 1:
        return 0.0
    clusters: dict[int, list[float]] = {}
    for i, v in enumerate(values):
        clusters.setdefault(assignments[i], []).append(v)

    total = 0.0
    for i, v in enumerate(values):
        own = assignments[i]
        own_members = clusters[own]
        if len(own_members) <= 1:
            continue
        a = sum(abs(v - m) for m in own_members) / (len(own_members) - 1)
        b = float("inf")
        for j in range(k):
            if j == own or j not in clusters:
                continue
            d = sum(abs(v - m) for m in clusters[j]) / len(clusters[j])
            b = min(b, d)
        if b == float("inf"):
            continue
        s = (b - a) / max(a, b) if max(a, b) > 0 else 0.0
        total += s
    return total / n


def _auto_cluster(values: list[float], max_k: int = 6) -> tuple[list[int], int]:
    """Pick the best k by silhouette score."""
    best_k = 2
    best_score = -1.0
    best_assign: list[int] = []
    for k in range(2, min(max_k + 1, len(values))):
        assign = _kmeans_1d(values, k)
        score = _silhouette_1d(values, assign, k)
        if score > best_score:
            best_score = score
            best_k = k
            best_assign = assign
    return best_assign, best_k


# ---------------------------------------------------------------------------
# The oracle
# ---------------------------------------------------------------------------

class SideChannelOracle:
    """Extract WAF internal scoring from response timing side channels."""

    def __init__(self, target: Target, samples_per_probe: int = 5,
                 sender: Optional[Callable] = None,
                 transport: str = "auto"):
        self.target = target
        self.samples = max(1, samples_per_probe)
        self._oracle = Oracle(target, sender=sender, transport=transport)
        self._total_reqs = 0

    def _send_timed(self, payload: str) -> tuple[Response, float]:
        """Send a payload and measure wall-clock time with high precision."""
        t0 = time.perf_counter()
        resp = self._oracle.send(payload)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        self._total_reqs += 1
        resp_time = resp.time * 1000.0 if resp.time > 0 else elapsed_ms
        return resp, resp_time

    def probe_timing(self, payload: str) -> TimingProbe:
        """Send payload multiple times and collect timing statistics."""
        times: list[float] = []
        last_resp: Optional[Response] = None
        for _ in range(self.samples):
            resp, t = self._send_timed(payload)
            times.append(t)
            last_resp = resp

        if len(times) >= 3:
            times_sorted = sorted(times)
            times_trimmed = times_sorted[1:-1]
        else:
            times_trimmed = times

        med = statistics.median(times_trimmed) if times_trimmed else 0.0
        return TimingProbe(
            payload=payload,
            times=times,
            median_ms=med,
            verdict=last_resp.verdict if last_resp else "",
            code=last_resp.code if last_resp else "",
        )

    def calibrate_timing(self) -> tuple[float, float]:
        """Measure baseline (benign) and ceiling (blocked) median timing."""
        benign_times: list[float] = []
        for p in _BENIGN[:5]:
            probe = self.probe_timing(p)
            benign_times.append(probe.median_ms)
        baseline = statistics.median(benign_times) if benign_times else 0.0

        blocked_times: list[float] = []
        for p in _ATTACK_HIGH[:3]:
            probe = self.probe_timing(p)
            blocked_times.append(probe.median_ms)
        ceiling = statistics.median(blocked_times) if blocked_times else baseline

        return baseline, ceiling

    def estimate_score(self, probe: TimingProbe,
                       baseline: float, ceiling: float) -> float:
        """Map timing to estimated WAF score [0.0, 1.0]."""
        rng = ceiling - baseline
        if rng <= 0:
            return 0.5
        raw = (probe.median_ms - baseline) / rng
        return max(0.0, min(1.0, raw))

    def map_rule_clusters(self, probes: list[TimingProbe],
                          max_k: int = 6) -> list[RuleCluster]:
        """Group probes by timing similarity → WAF rule groups."""
        if len(probes) < 3:
            return [RuleCluster(0, "single_group",
                                statistics.median([p.median_ms for p in probes]) if probes else 0,
                                len(probes),
                                [p.payload for p in probes])]

        values = [p.median_ms for p in probes]
        assignments, k = _auto_cluster(values, max_k)

        clusters: dict[int, list[TimingProbe]] = {}
        for i, p in enumerate(probes):
            clusters.setdefault(assignments[i], []).append(p)

        result: list[RuleCluster] = []
        for cid in sorted(clusters.keys()):
            members = clusters[cid]
            med = statistics.median([p.median_ms for p in members])
            result.append(RuleCluster(
                cluster_id=cid,
                label="",
                median_ms=med,
                count=len(members),
                payloads=[p.payload for p in members],
            ))

        result.sort(key=lambda c: c.median_ms)
        return result

    def _label_clusters(self, clusters: list[RuleCluster],
                        baseline: float, ceiling: float) -> list[RuleCluster]:
        """Heuristic labeling based on timing position."""
        rng = ceiling - baseline
        for c in clusters:
            if rng <= 0:
                c.label = "unknown"
                continue
            pos = (c.median_ms - baseline) / rng
            if pos < 0.15:
                c.label = "no_processing"
            elif pos < 0.35:
                c.label = "light_inspection"
            elif pos < 0.65:
                c.label = "pattern_matching"
            elif pos < 0.85:
                c.label = "deep_inspection"
            else:
                c.label = "full_rule_chain"
        return clusters

    def find_timing_boundary(self, seed: str = "' OR 1=1--",
                             max_probes: int = 20) -> list[TimingProbe]:
        """Progressive strip of a payload, measuring timing at each step."""
        variants = [seed]
        current = seed
        for i in range(len(current) - 1, 0, -1):
            variants.append(current[:i])
            if len(variants) >= max_probes:
                break

        probes: list[TimingProbe] = []
        for v in variants:
            p = self.probe_timing(v)
            probes.append(p)
        return probes

    def run(self, payloads: Sequence[str] | None = None) -> SideChannelReport:
        """Full side-channel analysis: calibrate → probe → cluster → label."""
        self._total_reqs = 0
        report = SideChannelReport()

        baseline, ceiling = self.calibrate_timing()
        report.baseline_ms = baseline
        report.blocked_ms = ceiling
        report.timing_range_ms = ceiling - baseline

        if payloads is None:
            probe_list = default_probes()
            payload_list = [p for _, p in probe_list]
        else:
            payload_list = list(payloads)

        probes: list[TimingProbe] = []
        for payload in payload_list:
            p = self.probe_timing(payload)
            p.estimated_score = self.estimate_score(p, baseline, ceiling)
            probes.append(p)

        report.probes = probes

        if len(probes) >= 3:
            clusters = self.map_rule_clusters(probes)
            clusters = self._label_clusters(clusters, baseline, ceiling)
            report.rule_clusters = clusters
            report.estimated_rule_groups = sum(
                1 for c in clusters if c.label not in ("no_processing", "unknown")
            )
            for c in clusters:
                if c.label == "no_processing":
                    report.gap_payloads.extend(c.payloads)

        report.total_requests = self._total_reqs
        return report
