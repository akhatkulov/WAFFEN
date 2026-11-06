"""Tests for A4 MCTS + CFG tree search (offline mock)."""
from waffen.core.mock import make_mock_sender
from waffen.core.oracle import Oracle, Target
from waffen.mutate import REGISTRY
from waffen.search.mcts import mcts_search


def _oracle(sender=None):
    return Oracle(Target(base_url="mock://x"), sender=sender or make_mock_sender())


def test_mcts_finds_xss_bypass():
    o = _oracle()
    ms = REGISTRY.select(attack_class="XSS Injection")
    res = mcts_search(o, "<script>alert(1)</script>", ms,
                      iterations=200, rollout_depth=3, max_requests=400,
                      attack_class="XSS Injection")
    assert res.baseline_verdict == "BLOCKED"
    assert res.findings, "expected an evasion chain"


def test_mcts_finds_sqli_bypass():
    o = _oracle()
    ms = REGISTRY.select(attack_class="SQL Injection")
    res = mcts_search(o, "' OR 1=1-- -", ms, iterations=200, rollout_depth=3,
                      max_requests=400, attack_class="SQL Injection")
    assert res.findings


def test_mcts_respects_budget_and_no_dup_sends():
    sent = []
    base = make_mock_sender()

    def counting(p):
        sent.append(p)
        return base(p)

    o = _oracle(sender=counting)
    ms = REGISTRY.all()
    mcts_search(o, "' OR 1=1-- -", ms, iterations=500, rollout_depth=4,
                max_requests=80, attack_class="SQL Injection")
    assert o.requests <= 80 + 1
    assert len(sent) == len(set(sent)), "MCTS must memoize — no payload sent twice"


def test_mcts_stop_on_first():
    o = _oracle()
    ms = REGISTRY.select(attack_class="XSS Injection")
    res = mcts_search(o, "<script>alert(1)</script>", ms, iterations=400,
                      rollout_depth=3, max_requests=400, attack_class="XSS Injection",
                      stop_on_first=True)
    assert len(res.findings) == 1


def test_mcts_deterministic():
    ms = REGISTRY.select(attack_class="XSS Injection")
    r1 = mcts_search(_oracle(), "<script>alert(1)</script>", ms, iterations=100,
                     max_requests=200, attack_class="XSS Injection", seed_rng=7)
    r2 = mcts_search(_oracle(), "<script>alert(1)</script>", ms, iterations=100,
                     max_requests=200, attack_class="XSS Injection", seed_rng=7)
    assert r1.requests == r2.requests
