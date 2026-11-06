"""Tests for A1 gradient scoring, A3 bandit, and A5 best-first search (offline mock)."""
from waffen.core.mock import make_mock_sender
from waffen.core.oracle import Oracle, Target, Response
from waffen.mutate import REGISTRY
from waffen.search.bestfirst import best_first_search
from waffen.search.bandit import UCB1, BlockedMemory, reward_from_score
from waffen.search.scoring import gradient_score


def _oracle():
    return Oracle(Target(base_url="mock://x"), sender=make_mock_sender())


# --- A3 bandit ---------------------------------------------------------------
def test_ucb_tries_each_arm_first():
    b = UCB1(["a", "b", "c"])
    first3 = {b.select(1)[0] for _ in range(3)}  # ties at inf; just ensure it returns
    b.update("a", 1.0)
    assert b.rank()[0] in ("b", "c")  # untried arms (inf) outrank the tried one


def test_ucb_prefers_rewarding_arm_after_exploration():
    b = UCB1(["good", "bad"])
    for _ in range(10):
        b.update("good", 1.0)
        b.update("bad", 0.0)
    assert b.rank()[0] == "good"


def test_blocked_memory_dedup_and_dead():
    m = BlockedMemory()
    m.add_seen("x")
    assert m.is_dup("x") and not m.is_dup("y")
    m.mark_blocked("abcdef1234")
    assert m.looks_dead("abcdef1234")


def test_reward_saturates_on_through():
    assert reward_from_score(1e9, 0.0) == 1.0


# --- A1 gradient -------------------------------------------------------------
def test_gradient_through_dominates():
    base = Response("BLOCKED", "403", 6000, 0.05, "blocked")
    thru = Response("THROUGH", "200", 1200, 0.3, "ok")
    blk = Response("BLOCKED", "403", 6010, 0.05, "blocked")
    assert gradient_score(thru, base, chain_len=3) > gradient_score(blk, base, chain_len=1)


def test_gradient_reflection_beats_plain_block():
    base = Response("BLOCKED", "403", 6000, 0.05, "Request blocked")
    reflected = Response("BLOCKED", "403", 6000, 0.05, "you searched for <script>alert(1)</script>")
    plain = Response("BLOCKED", "403", 6000, 0.05, "Request blocked")
    s_ref = gradient_score(reflected, base, seed_payload="<script>alert(1)</script>", chain_len=1)
    s_plain = gradient_score(plain, base, seed_payload="<script>alert(1)</script>", chain_len=1)
    assert s_ref > s_plain


def test_gradient_reached_backend_on_5xx():
    base = Response("BLOCKED", "403", 6000, 0.05, "b")
    err5 = Response("BLOCKED", "500", 6000, 0.05, "b")
    assert gradient_score(err5, base, chain_len=1) > gradient_score(base, base, chain_len=1)


# --- A5 best-first ------------------------------------------------------------
def test_bestfirst_finds_xss_bypass():
    o = _oracle()
    ms = REGISTRY.select(attack_class="XSS Injection")
    res = best_first_search(o, "<script>alert(1)</script>", ms,
                            branch=5, max_requests=400, attack_class="XSS Injection")
    assert res.baseline_verdict == "BLOCKED"
    assert res.findings, "expected an evasion chain"


def test_bestfirst_respects_budget_and_no_dup_sends():
    sent = []
    base_sender = make_mock_sender()

    def counting(p):
        sent.append(p)
        return base_sender(p)

    o = Oracle(Target(base_url="mock://x"), sender=counting)
    ms = REGISTRY.all()
    best_first_search(o, "' OR 1=1-- -", ms, branch=4, max_requests=60,
                      attack_class="SQL Injection")
    assert o.requests <= 60 + 1  # +1 baseline
    assert len(sent) == len(set(sent)), "best-first must not send the same payload twice"


def test_bestfirst_stop_on_first():
    o = _oracle()
    ms = REGISTRY.select(attack_class="XSS Injection")
    res = best_first_search(o, "<script>alert(1)</script>", ms,
                            branch=6, max_requests=400, attack_class="XSS Injection",
                            stop_on_first=True)
    assert len(res.findings) == 1
