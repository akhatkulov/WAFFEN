"""Concurrency support for genetic_search, mcts_search and best_first_search.

Mirrors tests/test_beam_concurrency.py's shape: concurrency=1 (the default) is
byte-identical to the pre-concurrency sequential path — that's covered by the
existing, UNMODIFIED tests/test_genetic.py, tests/test_mcts.py and
tests/test_bestfirst.py. These tests cover the concurrency>1 path: budget
respected, no payload ever sent twice (even under threaded `send_many`), and
bypasses still found — plus an honesty check for MCTS, which (see its
docstring) has no real concurrent seam and so is a documented no-op.
"""
import threading

from waffen.core.mock import make_mock_sender
from waffen.core.oracle import Oracle, Target
from waffen.mutate import REGISTRY
from waffen.search.bestfirst import best_first_search
from waffen.search.genetic import genetic_search
from waffen.search.mcts import mcts_search

XSS = "<script>alert(1)</script>"
SQLI = "' OR 1=1-- -"


def _dedup_sender():
    """Wraps the mock sender, failing loudly if the same payload is ever sent
    twice. Thread-safe: `oracle.send_many` dispatches workers from a
    ThreadPoolExecutor, so sends can race on `seen` without the lock."""
    inner = make_mock_sender()
    seen: set[str] = set()
    lock = threading.Lock()

    def sender(payload: str):
        with lock:
            assert payload not in seen, f"payload sent twice: {payload!r}"
            seen.add(payload)
        return inner(payload)

    return sender


def _oracle():
    return Oracle(Target(base_url="mock://x"), sender=_dedup_sender())


# --------------------------------------------------------------------- genetic
def test_genetic_concurrent_finds_bypass_no_dup_sends_within_budget():
    o = _oracle()
    ms = REGISTRY.select(attack_class="XSS Injection")
    res = genetic_search(o, XSS, ms, pop_size=20, generations=8,
                          max_requests=400, attack_class="XSS Injection",
                          concurrency=4)
    assert res.baseline_verdict == "BLOCKED"
    assert res.findings, "expected at least one evasion chain"
    assert o.requests <= 400 + 1  # +1 baseline, same slack as the sequential tests


def test_genetic_concurrency_1_and_4_both_succeed():
    r1 = genetic_search(_oracle(), XSS, REGISTRY.select(attack_class="XSS Injection"),
                         pop_size=20, generations=8, max_requests=400,
                         attack_class="XSS Injection", concurrency=1)
    r4 = genetic_search(_oracle(), XSS, REGISTRY.select(attack_class="XSS Injection"),
                         pop_size=20, generations=8, max_requests=400,
                         attack_class="XSS Injection", concurrency=4)
    assert r1.findings and r4.findings
    assert r1.requests <= 400 + 1 and r4.requests <= 400 + 1


def test_genetic_concurrent_respects_budget():
    o = _oracle()
    genetic_search(o, XSS, REGISTRY.all(), pop_size=20, generations=20,
                    max_requests=50, attack_class="XSS Injection", concurrency=4)
    assert o.requests <= 50 + 1


# ----------------------------------------------------------------------- mcts
def test_mcts_concurrent_accepted_finds_bypass_no_dup_sends():
    o = _oracle()
    ms = REGISTRY.select(attack_class="XSS Injection")
    res = mcts_search(o, XSS, ms, iterations=200, rollout_depth=3,
                       max_requests=400, attack_class="XSS Injection",
                       concurrency=4)
    assert res.baseline_verdict == "BLOCKED"
    assert res.findings, "expected an evasion chain"
    assert o.requests <= 400 + 1


def test_mcts_concurrency_1_and_4_both_succeed():
    r1 = mcts_search(_oracle(), XSS, REGISTRY.select(attack_class="XSS Injection"),
                      iterations=200, rollout_depth=3, max_requests=400,
                      attack_class="XSS Injection", concurrency=1)
    r4 = mcts_search(_oracle(), XSS, REGISTRY.select(attack_class="XSS Injection"),
                      iterations=200, rollout_depth=3, max_requests=400,
                      attack_class="XSS Injection", concurrency=4)
    assert r1.findings and r4.findings
    assert r1.requests <= 400 + 1 and r4.requests <= 400 + 1


def test_mcts_concurrency_is_honestly_a_no_op():
    """MCTS has no safe concurrent seam (see its docstring): selection is
    sequential across iterations by construction, expansion sends at most one
    brand-new payload per iteration, and the rollout is a single dependent
    chain (each step's payload depends on the previous step's result). This
    pins that honesty down concretely: for the same seed, concurrency=1 and
    concurrency=8 run the exact same sequence of oracle calls, so they use the
    exact same request count and find the exact same number of bypasses.
    Accepting the parameter is safe; it just does not do anything (yet)."""
    r1 = mcts_search(_oracle(), XSS, REGISTRY.select(attack_class="XSS Injection"),
                      iterations=150, rollout_depth=3, max_requests=300,
                      attack_class="XSS Injection", seed_rng=7, concurrency=1)
    r8 = mcts_search(_oracle(), XSS, REGISTRY.select(attack_class="XSS Injection"),
                      iterations=150, rollout_depth=3, max_requests=300,
                      attack_class="XSS Injection", seed_rng=7, concurrency=8)
    assert r1.requests == r8.requests
    assert len(r1.findings) == len(r8.findings)


# ------------------------------------------------------------------ bestfirst
def test_bestfirst_concurrent_finds_bypass_no_dup_sends_within_budget():
    o = _oracle()
    ms = REGISTRY.select(attack_class="XSS Injection")
    res = best_first_search(o, XSS, ms, branch=5, max_requests=400,
                             attack_class="XSS Injection", concurrency=4)
    assert res.baseline_verdict == "BLOCKED"
    assert res.findings, "expected an evasion chain"
    assert o.requests <= 400 + 1


def test_bestfirst_concurrency_1_and_4_both_succeed():
    r1 = best_first_search(_oracle(), XSS, REGISTRY.select(attack_class="XSS Injection"),
                            branch=5, max_requests=400,
                            attack_class="XSS Injection", concurrency=1)
    r4 = best_first_search(_oracle(), XSS, REGISTRY.select(attack_class="XSS Injection"),
                            branch=5, max_requests=400,
                            attack_class="XSS Injection", concurrency=4)
    assert r1.findings and r4.findings
    assert r1.requests <= 400 + 1 and r4.requests <= 400 + 1


def test_bestfirst_concurrent_respects_budget():
    o = _oracle()
    best_first_search(o, SQLI, REGISTRY.all(), branch=4, max_requests=60,
                       attack_class="SQL Injection", concurrency=4)
    assert o.requests <= 60 + 1
