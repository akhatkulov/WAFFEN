"""Tests for live progress callbacks across all search strategies."""
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from waffen.search.beam import beam_search, SearchResult


class _FakeOracle:
    """Minimal Oracle stub that tracks requests and returns BLOCKED."""

    def __init__(self, through_on=None):
        self.requests = 0
        self._through_on = through_on or set()

    def send(self, payload):
        self.requests += 1
        is_through = payload in self._through_on
        return SimpleNamespace(
            code="200" if is_through else "403",
            verdict="THROUGH" if is_through else "BLOCKED",
            through=is_through,
            body="", headers={}, time=0.1, size=100,
        )

    def send_many(self, payloads, concurrency=1):
        return [self.send(p) for p in payloads]

    def score(self, resp, baseline):
        return 1.0 if resp.through else 0.1


class _FakeMutator:
    def __init__(self, name, suffix):
        self.name = name
        self._suffix = suffix
        self.classes = set()
        self.multi = False

    def apply(self, payload):
        return payload + self._suffix

    def apply_multi(self, payload, max_variants=5):
        return [self.apply(payload)]


def test_beam_progress_called():
    oracle = _FakeOracle()
    muts = [_FakeMutator("a", "_a"), _FakeMutator("b", "_b")]
    calls = []

    def on_progress(**kw):
        calls.append(kw)

    beam_search(oracle, "seed", muts, width=2, depth=3,
                max_requests=100, on_progress=on_progress)

    assert len(calls) >= 1, "on_progress should be called at least once"
    for c in calls:
        assert "depth" in c
        assert "max_depth" in c
        assert "requests" in c
        assert "budget" in c
        assert "throughs" in c
        assert "best_score" in c
        assert "frontier_size" in c


def test_beam_progress_depth_increments():
    oracle = _FakeOracle()
    muts = [_FakeMutator("a", "_a"), _FakeMutator("b", "_b")]
    calls = []

    beam_search(oracle, "seed", muts, width=2, depth=3,
                max_requests=200, on_progress=lambda **kw: calls.append(kw))

    depths = [c["depth"] for c in calls]
    assert depths == sorted(depths), "depths should increase monotonically"
    assert all(d <= 3 for d in depths)


def test_beam_progress_reports_through():
    oracle = _FakeOracle(through_on={"seed_a_b"})
    muts = [_FakeMutator("a", "_a"), _FakeMutator("b", "_b")]
    calls = []

    beam_search(oracle, "seed", muts, width=4, depth=3,
                max_requests=200, on_progress=lambda **kw: calls.append(kw))

    any_through = any(c["throughs"] > 0 for c in calls)
    assert any_through, "should report throughs found"


def test_genetic_progress_called():
    from waffen.search.genetic import genetic_search

    oracle = _FakeOracle()
    muts = [_FakeMutator("a", "_a"), _FakeMutator("b", "_b")]
    calls = []

    genetic_search(oracle, "seed", muts, pop_size=5, generations=3,
                   max_requests=100, on_progress=lambda **kw: calls.append(kw))

    assert len(calls) >= 1


def test_bestfirst_progress_called():
    from waffen.search.bestfirst import best_first_search

    oracle = _FakeOracle()
    muts = [_FakeMutator("a", "_a"), _FakeMutator("b", "_b")]
    calls = []

    best_first_search(oracle, "seed", muts, branch=2, max_requests=30,
                      on_progress=lambda **kw: calls.append(kw))

    assert len(calls) >= 1


def test_mcts_progress_called():
    from waffen.search.mcts import mcts_search

    oracle = _FakeOracle()
    muts = [_FakeMutator("a", "_a"), _FakeMutator("b", "_b")]
    calls = []

    mcts_search(oracle, "seed", muts, iterations=20, max_requests=50,
                on_progress=lambda **kw: calls.append(kw))

    assert len(calls) >= 1


def test_no_progress_callback_ok():
    """Search works fine without on_progress."""
    oracle = _FakeOracle()
    muts = [_FakeMutator("a", "_a")]
    result = beam_search(oracle, "seed", muts, width=2, depth=2,
                         max_requests=50)
    assert isinstance(result, SearchResult)


def test_progress_budget_field():
    oracle = _FakeOracle()
    muts = [_FakeMutator("a", "_a")]
    calls = []

    beam_search(oracle, "seed", muts, width=2, depth=2,
                max_requests=77, on_progress=lambda **kw: calls.append(kw))

    if calls:
        assert calls[0]["budget"] == 77
