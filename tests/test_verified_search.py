"""Verified-search: a THROUGH must be confirmed exploitable before stop_on_first fires.

Uses the offline mock plus a controllable fake verifier so we can prove the search
keeps hunting past semantically-dead bypasses (the behaviour the live run exposed)."""
from types import SimpleNamespace

from waffen.core.mock import make_mock_sender
from waffen.core.oracle import Oracle, Target
from waffen.mutate import REGISTRY
from waffen.search.beam import beam_search, Finding, finalize_finding
from waffen.search.bestfirst import best_first_search
from waffen.search.mcts import mcts_search
from waffen.search.genetic import genetic_search


def _oracle():
    return Oracle(Target(base_url="mock://x"), sender=make_mock_sender())


def vf_all_dead(_p):
    return SimpleNamespace(exploitable=False, confidence=0.3)


def vf_all_live(_p):
    return SimpleNamespace(exploitable=True, confidence=0.9)


XSS = "<script>alert(1)</script>"


def test_finalize_sets_fields_and_returns_real():
    f = Finding("p", ["m"], "200", "XSS Injection")
    real = finalize_finding(f, vf_all_live)
    assert real is True and f.verified is True and f.confidence == 0.9
    f2 = Finding("p", ["m"], "200", "XSS Injection")
    assert finalize_finding(f2, vf_all_dead) is False and f2.verified is False


def test_no_verifier_treats_through_as_success():
    f = Finding("p", [], "200", "XSS Injection")
    assert finalize_finding(f, None) is True and f.verified is None


def test_beam_stop_on_first_requires_verified():
    ms = REGISTRY.select(attack_class="XSS Injection")
    # dead verifier: stop_on_first never satisfied -> keeps finding more than one
    res_dead = beam_search(_oracle(), XSS, ms, width=6, depth=4, max_requests=400,
                           attack_class="XSS Injection", stop_on_first=True, verify_fn=vf_all_dead)
    assert res_dead.findings and all(f.verified is False for f in res_dead.findings)
    assert len(res_dead.findings) >= 2  # did NOT halt on the first dead bypass
    # live verifier: stops at the first confirmed one
    res_live = beam_search(_oracle(), XSS, ms, width=6, depth=4, max_requests=400,
                           attack_class="XSS Injection", stop_on_first=True, verify_fn=vf_all_live)
    assert len(res_live.findings) == 1 and res_live.findings[0].verified is True


def test_bestfirst_stop_on_first_requires_verified():
    ms = REGISTRY.select(attack_class="XSS Injection")
    res_dead = best_first_search(_oracle(), XSS, ms, branch=5, max_requests=300,
                                 attack_class="XSS Injection", stop_on_first=True, verify_fn=vf_all_dead)
    assert len(res_dead.findings) >= 2 and all(f.verified is False for f in res_dead.findings)
    res_live = best_first_search(_oracle(), XSS, ms, branch=5, max_requests=300,
                                 attack_class="XSS Injection", stop_on_first=True, verify_fn=vf_all_live)
    assert len(res_live.findings) == 1 and res_live.findings[0].verified is True


def test_mcts_and_genetic_accept_verify_fn():
    ms = REGISTRY.select(attack_class="XSS Injection")
    rm = mcts_search(_oracle(), XSS, ms, iterations=150, max_requests=300,
                     attack_class="XSS Injection", stop_on_first=True, verify_fn=vf_all_live)
    assert rm.findings and rm.findings[0].verified is True
    rg = genetic_search(_oracle(), XSS, ms, pop_size=20, generations=6, max_requests=300,
                        attack_class="XSS Injection", stop_on_first=True, verify_fn=vf_all_live)
    assert rg.findings and any(f.verified for f in rg.findings)


def test_finding_as_dict_has_verify_fields():
    f = Finding("p", ["m"], "200", "XSS Injection", verified=True, confidence=0.8)
    d = f.as_dict()
    assert d["verified_exploitable"] is True and d["verify_confidence"] == 0.8
