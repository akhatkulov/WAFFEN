"""Cross-axis composition — combine mutated payloads × structural transforms.

The normal engine sweep tests each (transform, seed) pair independently: for a
given transform, it searches over mutators; for a given seed, it tries each
transform.  The *composition* this misses is a mutated payload (from mutator
search) delivered inside a non-identity transform (structural framing trick).

This module runs as a focused **second pass** after the first-pass sweep:
1. Rank payloads from the first pass by fitness (throughs first, then score).
2. Rank transforms by how many throughs they produced.
3. For each (top-payload × top-transform) pair not already tried, send it.
4. Return new findings.

Budget-limited so it stays a cheap refinement, not a combinatorial explosion.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..core.oracle import Oracle, Target
from ..core import transforms as T


@dataclass
class CrossAxisConfig:
    top_payloads: int = 10
    top_transforms: int = 5
    budget: int = 200


@dataclass
class CrossAxisFinding:
    payload: str
    chain: list[str]
    transform: str
    code: str
    attack_class: str = ""
    source_transform: str = ""
    verified: Optional[bool] = None
    confidence: Optional[float] = None

    def as_dict(self) -> dict:
        return {
            "payload": self.payload,
            "chain": self.chain,
            "transform": self.transform,
            "source_transform": self.source_transform,
            "http_code": self.code,
            "attack_class": self.attack_class,
            "verified_exploitable": self.verified,
            "verify_confidence": self.confidence,
        }


@dataclass
class CrossAxisResult:
    findings: list[CrossAxisFinding] = field(default_factory=list)
    requests: int = 0
    pairs_tested: int = 0
    pairs_skipped: int = 0


class CrossAxisComposer:
    """Cross-compose top payloads from first-pass runs with top transforms."""

    def __init__(self, target: Target, *, config: CrossAxisConfig | None = None,
                 sender=None, transport: str = "curl"):
        self.target = target
        self.config = config or CrossAxisConfig()
        self._sender = sender
        self._transport = transport

    def compose(self, first_pass_runs) -> CrossAxisResult:
        """Run the cross-axis second pass.

        *first_pass_runs*: list of BypassRun from engine.run_bypass().
        """
        cfg = self.config
        result = CrossAxisResult()

        top_payloads = self._rank_payloads(first_pass_runs, cfg.top_payloads)
        top_transforms = self._rank_transforms(first_pass_runs, cfg.top_transforms)

        if not top_payloads or not top_transforms:
            return result

        already_tried = self._already_tested(first_pass_runs)

        pairs = []
        for payload, chain, cls, src_tr in top_payloads:
            for tr_name in top_transforms:
                if tr_name == src_tr:
                    result.pairs_skipped += 1
                    continue
                key = (payload, tr_name)
                if key in already_tried:
                    result.pairs_skipped += 1
                    continue
                pairs.append((payload, chain, cls, src_tr, tr_name))

        for payload, chain, cls, src_tr, tr_name in pairs:
            if result.requests >= cfg.budget:
                break

            tr = T.get(tr_name)
            rt = None if tr_name == "identity" else tr

            from ..kb.inject_map import effective as _effective_target
            eff = _effective_target(self.target, cls)
            oracle = Oracle(eff, sender=self._sender, request_transform=rt,
                            transport=self._transport)
            resp = oracle.send(payload)
            result.requests += 1
            result.pairs_tested += 1

            if resp.through:
                result.findings.append(CrossAxisFinding(
                    payload=payload,
                    chain=chain,
                    transform=tr_name,
                    code=resp.code,
                    attack_class=cls,
                    source_transform=src_tr,
                ))

        return result

    @staticmethod
    def _rank_payloads(runs, n: int) -> list[tuple[str, list, str, str]]:
        """Return top-N (payload, chain, class, transform) ranked by fitness.

        Throughs first (they already bypassed via *some* transform — maybe
        another transform carries them further), then highest-scoring blocked
        candidates (closest to the boundary).
        """
        seen: set[str] = set()
        throughs: list[tuple[str, list, str, str, float]] = []
        blocked: list[tuple[str, list, str, str, float]] = []

        for run in runs:
            tr_name = run.transform
            cls = run.attack_class
            for f in run.result.findings:
                if f.payload in seen:
                    continue
                seen.add(f.payload)
                throughs.append((f.payload, f.chain, cls, tr_name, 1.0))

        for run in runs:
            tr_name = run.transform
            cls = run.attack_class
            if not hasattr(run.result, "best_blocked"):
                continue
            for payload, score in run.result.best_blocked:
                if payload in seen:
                    continue
                seen.add(payload)
                blocked.append((payload, [], cls, tr_name, score))

        throughs.sort(key=lambda x: -x[4])
        blocked.sort(key=lambda x: -x[4])
        combined = throughs + blocked
        return [(p, c, cl, tr) for p, c, cl, tr, _ in combined[:n]]

    @staticmethod
    def _rank_transforms(runs, n: int) -> list[str]:
        """Return top-N transform names by through count."""
        counts: dict[str, int] = {}
        for run in runs:
            counts[run.transform] = counts.get(run.transform, 0) + len(run.result.findings)

        ranked = sorted(counts.keys(), key=lambda t: -counts[t])
        all_transforms = [t.name for t in T.TRANSFORMS]
        for t_name in all_transforms:
            if t_name not in ranked:
                ranked.append(t_name)
        return ranked[:n]

    @staticmethod
    def _already_tested(runs) -> set[tuple[str, str]]:
        """Build set of (payload, transform) pairs already tested in first pass."""
        tested: set[tuple[str, str]] = set()
        for run in runs:
            for f in run.result.findings:
                tested.add((f.payload, run.transform))
        return tested
