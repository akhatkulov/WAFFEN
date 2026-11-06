"""Beam search concurrency: batched per-depth evaluation via oracle.send_many.

Opt-in only — concurrency=1 (the default) keeps the original sequential path
untouched (covered by tests/test_engine.py). These tests cover the
concurrency>1 path: budget respected, no payload sent twice, bypasses found.
"""
import threading

from waffen.core.mock import make_mock_sender
from waffen.core.oracle import Oracle, Target
from waffen.mutate import REGISTRY
from waffen.search.beam import beam_search


def _dedup_counting_sender():
    """Wraps the mock sender, failing loudly if the same payload is ever sent
    twice (thread-safe counting)."""
    inner = make_mock_sender()
    seen = set()
    lock = threading.Lock()

    def sender(payload):
        with lock:
            assert payload not in seen, f"payload sent twice: {payload!r}"
            seen.add(payload)
        return inner(payload)

    return sender


def _oracle():
    return Oracle(Target(base_url="mock://local"), sender=_dedup_counting_sender())


def test_beam_concurrent_finds_xss_bypass():
    o = _oracle()
    ms = REGISTRY.select(attack_class="XSS Injection")
    res = beam_search(o, "<script>alert(1)</script>", ms,
                       width=6, depth=4, max_requests=400,
                       attack_class="XSS Injection", concurrency=8)
    assert res.baseline_verdict == "BLOCKED"
    assert res.findings, "expected at least one evasion chain"


def test_beam_concurrent_respects_budget():
    o = _oracle()
    ms = REGISTRY.all()
    beam_search(o, "<script>alert(1)</script>", ms,
                width=6, depth=6, max_requests=50, attack_class="XSS Injection",
                stop_on_first=False, concurrency=8)
    assert o.requests <= 50 + 1  # +1 baseline


def test_beam_concurrent_and_sequential_both_find_bypasses():
    o_seq = _oracle()
    o_conc = _oracle()
    ms = REGISTRY.select(attack_class="XSS Injection")

    res_seq = beam_search(o_seq, "<script>alert(1)</script>", ms,
                           width=6, depth=4, max_requests=400,
                           attack_class="XSS Injection", concurrency=1)
    res_conc = beam_search(o_conc, "<script>alert(1)</script>", ms,
                            width=6, depth=4, max_requests=400,
                            attack_class="XSS Injection", concurrency=8)

    assert res_seq.findings
    assert res_conc.findings
    assert o_seq.requests <= 400 + 1
    assert o_conc.requests <= 400 + 1
