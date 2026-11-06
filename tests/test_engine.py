"""Core engine tests — run offline against the mock WAF."""
from waffen.core.mock import make_mock_sender
from waffen.core.oracle import Oracle, Target
from waffen.mutate import REGISTRY
from waffen.search.beam import beam_search
from waffen.kb import seeds as kb_seeds


def _oracle():
    return Oracle(Target(base_url="mock://local"), sender=make_mock_sender())


def test_registry_nonempty():
    assert len(REGISTRY.all()) >= 15


def test_mock_blocks_raw_payload():
    o = _oracle()
    r = o.send("<script>alert(1)</script>")
    assert r.verdict == "BLOCKED" and r.code == "403"


def test_mock_allows_clean_payload():
    o = _oracle()
    r = o.send("banana juice")
    assert r.verdict == "THROUGH" and r.code == "200"


def test_beam_finds_xss_bypass():
    o = _oracle()
    ms = REGISTRY.select(attack_class="XSS Injection")
    res = beam_search(o, "<script>alert(1)</script>", ms,
                      width=6, depth=4, max_requests=400,
                      attack_class="XSS Injection")
    assert res.baseline_verdict == "BLOCKED"
    assert res.findings, "expected at least one evasion chain"


def test_beam_finds_sqli_bypass():
    o = _oracle()
    ms = REGISTRY.select(attack_class="SQL Injection")
    res = beam_search(o, "' OR 1=1-- -", ms,
                      width=6, depth=4, max_requests=400,
                      attack_class="SQL Injection")
    assert res.findings, "expected at least one evasion chain"


def test_budget_is_respected():
    o = _oracle()
    ms = REGISTRY.all()
    beam_search(o, "<script>alert(1)</script>", ms,
                width=6, depth=6, max_requests=50, attack_class="XSS Injection",
                stop_on_first=False)
    assert o.requests <= 50 + 1  # +1 baseline


def test_all_kb_classes_have_seeds():
    for c in kb_seeds.classes():
        assert kb_seeds.seeds_for(c), c
