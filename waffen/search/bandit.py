"""A3 — online operator selection and search pruning.

Beam/genetic apply every mutator uniformly. That wastes budget: against a given
WAF only a handful of operators ever help, and which ones depends on context.
`UCB1` learns, online and with no training phase, which mutators are paying off
and biases selection toward them while still exploring — the same UCB rule that
sits inside MCTS, but usable as a drop-in on the existing strategies.

`BlockedMemory` prunes the search: it remembers payload signatures that got
blocked so near-identical dead-ends are not re-sent, and dedups exact payloads.
Both are stdlib-only and side-effect free beyond their own state.
"""
from __future__ import annotations

import hashlib
import math


class UCB1:
    """Upper-Confidence-Bound bandit over a fixed set of arms (mutator names)."""

    def __init__(self, arms, c: float = 1.4):
        self.arms = list(arms)
        self.c = c
        self.n = {a: 0 for a in self.arms}
        self.q = {a: 0.0 for a in self.arms}  # running mean reward
        self.t = 0

    def _ucb(self, a: str) -> float:
        if self.n[a] == 0:
            return float("inf")  # try every arm once first
        return self.q[a] + self.c * math.sqrt(math.log(max(self.t, 1)) / self.n[a])

    def rank(self) -> list[str]:
        """Arms ordered by current UCB value (best first)."""
        return sorted(self.arms, key=self._ucb, reverse=True)

    def select(self, k: int) -> list[str]:
        """Top-k arms to try next."""
        return self.rank()[:max(1, k)]

    def update(self, arm: str, reward: float) -> None:
        if arm not in self.n:
            self.n[arm] = 0
            self.q[arm] = 0.0
            self.arms.append(arm)
        self.t += 1
        self.n[arm] += 1
        # incremental mean
        self.q[arm] += (reward - self.q[arm]) / self.n[arm]

    def stats(self) -> dict:
        return {a: (self.n[a], round(self.q[a], 3)) for a in self.arms if self.n[a]}


def _sig(payload: str) -> str:
    """A coarse signature: a payload's shape, so near-duplicates collapse."""
    # fold runs of digits/hex to a class, cap length, hash
    import re
    norm = re.sub(r"[0-9a-fA-F]{2,}", "#", payload)[:120]
    return hashlib.sha1(norm.encode("utf-8", "replace")).hexdigest()[:16]


class BlockedMemory:
    """Remembers exact payloads seen and signatures that were blocked."""

    def __init__(self):
        self.seen: set[str] = set()
        self.blocked_sigs: set[str] = set()

    def is_dup(self, payload: str) -> bool:
        return payload in self.seen

    def add_seen(self, payload: str) -> None:
        self.seen.add(payload)

    def mark_blocked(self, payload: str) -> None:
        self.blocked_sigs.add(_sig(payload))

    def looks_dead(self, payload: str) -> bool:
        """True if this payload's signature already proved to be blocked."""
        return _sig(payload) in self.blocked_sigs


def reward_from_score(score: float, parent_score: float) -> float:
    """Normalize a raw gradient score into a [0,1]-ish bandit reward.

    A huge THROUGH score saturates to 1.0; otherwise reward improvement over the
    parent, squashed. Negative (DOWN / regression) gives ~0.
    """
    if score >= 1e8:
        return 1.0
    delta = score - parent_score
    # logistic squash of the improvement
    return 1.0 / (1.0 + math.exp(-delta))
