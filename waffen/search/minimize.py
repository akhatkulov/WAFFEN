"""Payload minimization — shorten mutation chains to their minimal bypass form.

When a bypass is found via a multi-step chain (e.g., base64 → url_encode →
comment_interleave), this module identifies the smallest subset that still
evades the WAF. A 4-step chain that works as 1-step reveals the actual WAF
gap and produces a more stable, reportable finding.

Two strategies:
  1. **Chain minimization** — remove mutation steps one at a time and re-test.
  2. **Payload text trimming** — binary search on the string itself to find
     the minimal substring that passes (useful for encoding-based throughs).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from itertools import combinations

from ..core.oracle import Oracle, THROUGH
from ..mutate import REGISTRY


@dataclass
class MinimizeResult:
    original_chain: list[str]
    original_payload: str
    minimized_chain: list[str]
    minimized_payload: str
    requests_used: int = 0
    trimmed_payload: str = ""
    trim_requests: int = 0

    def as_dict(self) -> dict:
        return {
            "original_chain": self.original_chain,
            "original_payload": self.original_payload,
            "minimized_chain": self.minimized_chain,
            "minimized_payload": self.minimized_payload,
            "requests_used": self.requests_used,
            "trimmed_payload": self.trimmed_payload,
            "trim_requests": self.trim_requests,
        }


def _replay_chain(seed: str, chain: list[str]) -> str:
    """Apply a sequence of mutator names to a seed, returning the final payload."""
    payload = seed
    for name in chain:
        try:
            m = REGISTRY.get(name)
            payload = m.apply(payload)
        except KeyError:
            pass
    return payload


class PayloadMinimizer:
    """Shrink bypass findings to their minimal form."""

    def __init__(self, oracle: Oracle):
        self.oracle = oracle
        self._requests = 0

    def _send(self, payload: str) -> bool:
        """Send and return True if the payload is THROUGH."""
        resp = self.oracle.send(payload)
        self._requests += 1
        return resp.verdict == THROUGH

    # ---- chain minimization ------------------------------------------------

    def minimize_chain(self, seed: str, chain: list[str]) -> MinimizeResult:
        """Find the shortest sub-chain of *chain* that still passes the WAF.

        Strategy:
          1. Try each single mutator alone on the seed.
          2. If none pass alone, try all pairs.
          3. If no pair passes, try removing one step at a time (n-1 subsets).
          4. Continue removing until no shorter chain passes.

        Returns the shortest chain found.
        """
        self._requests = 0
        original_payload = _replay_chain(seed, chain)

        if not chain:
            return MinimizeResult(
                original_chain=[], original_payload=original_payload,
                minimized_chain=[], minimized_payload=original_payload,
                requests_used=0,
            )

        # Phase 1: try single mutators
        for name in chain:
            payload = _replay_chain(seed, [name])
            if payload != seed and self._send(payload):
                return MinimizeResult(
                    original_chain=list(chain), original_payload=original_payload,
                    minimized_chain=[name], minimized_payload=payload,
                    requests_used=self._requests,
                )

        # Phase 2: try pairs (if chain >= 3)
        if len(chain) >= 3:
            for pair in combinations(chain, 2):
                ordered = [s for s in chain if s in pair]
                payload = _replay_chain(seed, ordered)
                if payload != seed and self._send(payload):
                    return MinimizeResult(
                        original_chain=list(chain), original_payload=original_payload,
                        minimized_chain=ordered, minimized_payload=payload,
                        requests_used=self._requests,
                    )

        # Phase 3: remove one step at a time (greedy)
        best_chain = list(chain)
        best_payload = original_payload
        improved = True
        while improved and len(best_chain) > 1:
            improved = False
            for i in range(len(best_chain)):
                shorter = best_chain[:i] + best_chain[i + 1:]
                payload = _replay_chain(seed, shorter)
                if payload != seed and self._send(payload):
                    best_chain = shorter
                    best_payload = payload
                    improved = True
                    break

        return MinimizeResult(
            original_chain=list(chain), original_payload=original_payload,
            minimized_chain=best_chain, minimized_payload=best_payload,
            requests_used=self._requests,
        )

    # ---- payload text trimming ---------------------------------------------

    def trim_payload(self, payload: str) -> MinimizeResult:
        """Binary search on the payload string to find the shortest prefix/suffix
        that still passes the WAF.

        Useful for encoding-based throughs (e.g., base64 string where any
        prefix still looks like random text to the WAF).
        """
        self._requests = 0
        if not payload:
            return MinimizeResult(
                original_chain=[], original_payload=payload,
                minimized_chain=[], minimized_payload=payload,
                trimmed_payload=payload, requests_used=0,
            )

        # Try progressively shorter prefixes via binary search
        lo, hi = 1, len(payload)
        best = payload
        while lo < hi:
            mid = (lo + hi) // 2
            candidate = payload[:mid]
            if self._send(candidate):
                best = candidate
                hi = mid
            else:
                lo = mid + 1

        # Also try suffix trimming on the best prefix
        if len(best) > 1:
            lo_s, hi_s = 0, len(best) - 1
            while lo_s < hi_s:
                mid = (lo_s + hi_s + 1) // 2
                candidate = best[mid:]
                if self._send(candidate):
                    best = candidate
                    lo_s = mid
                else:
                    hi_s = mid - 1

        return MinimizeResult(
            original_chain=[], original_payload=payload,
            minimized_chain=[], minimized_payload=payload,
            trimmed_payload=best, trim_requests=self._requests,
            requests_used=self._requests,
        )

    # ---- combined ----------------------------------------------------------

    def minimize(self, seed: str, chain: list[str],
                 do_trim: bool = True) -> MinimizeResult:
        """Full minimization: chain reduction + optional text trimming."""
        result = self.minimize_chain(seed, chain)

        if do_trim and result.minimized_payload:
            trim = self.trim_payload(result.minimized_payload)
            result.trimmed_payload = trim.trimmed_payload
            result.trim_requests = trim.trim_requests
            result.requests_used += trim.requests_used

        return result
