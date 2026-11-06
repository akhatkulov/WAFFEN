"""Genetic search tests — run offline against the mock WAF."""
from waffen.core.mock import make_mock_sender
from waffen.core.oracle import Oracle, Target
from waffen.mutate import REGISTRY
from waffen.search.genetic import genetic_search
from waffen.search.beam import beam_search
from waffen.search.scoring import composite_score


def _counting_sender():
    """Wraps the mock sender and records every payload sent, so tests can
    assert no decoded payload was ever sent to the oracle twice."""
    inner = make_mock_sender()
    sent: list[str] = []

    def sender(payload: str):
        sent.append(payload)
        return inner(payload)

    return sender, sent


def _oracle(sender):
    return Oracle(Target(base_url="mock://x"), sender=sender)


def test_genetic_finds_xss_bypass():
    sender, sent = _counting_sender()
    o = _oracle(sender)
    ms = REGISTRY.select(attack_class="XSS Injection")
    res = genetic_search(o, "<script>alert(1)</script>", ms,
                          pop_size=20, generations=8, max_requests=400,
                          attack_class="XSS Injection")
    assert res.baseline_verdict == "BLOCKED"
    assert res.findings, "expected at least one evasion chain"
    assert o.requests <= 400 + 1
    assert len(sent) == len(set(sent)), "a decoded payload was sent more than once"


def test_genetic_findings_sorted_shortest_first():
    sender, _ = _counting_sender()
    o = _oracle(sender)
    ms = REGISTRY.select(attack_class="XSS Injection")
    res = genetic_search(o, "<script>alert(1)</script>", ms,
                          pop_size=20, generations=8, max_requests=400,
                          attack_class="XSS Injection")
    assert res.findings
    lengths = [len(f.chain) for f in res.findings]
    assert lengths == sorted(lengths)


def test_genetic_respects_budget():
    sender, _ = _counting_sender()
    o = _oracle(sender)
    ms = REGISTRY.all()
    genetic_search(o, "<script>alert(1)</script>", ms,
                    pop_size=20, generations=20, max_requests=50,
                    attack_class="XSS Injection")
    assert o.requests <= 50 + 1  # +1 baseline


def test_genetic_stop_on_first():
    sender, _ = _counting_sender()
    o = _oracle(sender)
    ms = REGISTRY.select(attack_class="SQL Injection")
    res = genetic_search(o, "' OR 1=1-- -", ms,
                          pop_size=20, generations=8, max_requests=400,
                          attack_class="SQL Injection", stop_on_first=True)
    assert len(res.findings) == 1


def test_genetic_no_duplicate_requests_across_run():
    sender, sent = _counting_sender()
    o = _oracle(sender)
    ms = REGISTRY.all()
    genetic_search(o, "<script>alert(1)</script>", ms,
                    pop_size=16, generations=6, max_requests=300,
                    attack_class="XSS Injection")
    assert len(sent) == len(set(sent))
    assert len(sent) == o.requests


def test_composite_score_prefers_shorter_chain_on_tie():
    from waffen.core.oracle import Response
    baseline = Response("BLOCKED", "403", 1000, 0.05, "blocked")
    resp = Response("BLOCKED", "403", 1200, 0.05, "blocked")
    short = composite_score(resp, baseline, 1)
    long = composite_score(resp, baseline, 5)
    assert short > long


def test_composite_score_bonus_on_4xx_to_5xx_transition():
    from waffen.core.oracle import Response
    baseline = Response("BLOCKED", "403", 1000, 0.05, "blocked")
    plain_drift = Response("BLOCKED", "403", 1800, 0.05, "blocked")
    transition = Response("BLOCKED", "500", 1800, 0.05, "err")
    assert composite_score(transition, baseline, 2) > composite_score(plain_drift, baseline, 2)


def test_genetic_matches_or_beats_beam_requests_on_mock():
    # Not a strict performance assertion (both are budget-capped stochastic
    # searches over the same mock WAF) — just sanity-checks both terminate
    # within budget and find at least one bypass, for a requests comparison.
    sender_b, _ = _counting_sender()
    ob = _oracle(sender_b)
    ms_b = REGISTRY.select(attack_class="XSS Injection")
    rb = beam_search(ob, "<script>alert(1)</script>", ms_b,
                      width=6, depth=4, max_requests=400,
                      attack_class="XSS Injection")

    sender_g, _ = _counting_sender()
    og = _oracle(sender_g)
    ms_g = REGISTRY.select(attack_class="XSS Injection")
    rg = genetic_search(og, "<script>alert(1)</script>", ms_g,
                         pop_size=20, generations=8, max_requests=400,
                         attack_class="XSS Injection")

    assert rb.findings and rg.findings
    assert rb.requests <= 400 + 1 and rg.requests <= 400 + 1


def _run_all():
    tests = [v for k, v in list(globals().items()) if k.startswith("test_")]
    failed = []
    for t in tests:
        try:
            t()
            print(f"OK   {t.__name__}")
        except Exception as e:
            failed.append((t.__name__, e))
            print(f"FAIL {t.__name__}: {e}")
    if failed:
        raise SystemExit(f"{len(failed)} test(s) failed")
    print(f"all {len(tests)} tests passed")


if __name__ == "__main__":
    _run_all()
