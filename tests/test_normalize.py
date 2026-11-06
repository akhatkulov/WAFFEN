"""Tests for the GOFA-lite normalization learner (offline mock)."""
from waffen.core.mock import make_mock_sender
from waffen.core.oracle import Oracle, Target, Response
from waffen.mutate import REGISTRY
from waffen.recon.normalize import learn_normalization, reorder_mutators


def _oracle(sender=None):
    return Oracle(Target(base_url="mock://x"), sender=sender or make_mock_sender())


def test_learns_mock_normalization_and_blind_spots():
    prof = learn_normalization(_oracle())
    assert prof.waf_detected and prof.trigger
    # the realistic mock url-decodes and case-folds before matching -> it SEES those
    assert prof.applies.get("url_decode") is True
    assert prof.applies.get("case_fold") is True
    # ...but it does NOT html-entity-decode or unicode-fold -> blind spots
    assert "html_entity_decode" in prof.blind_to
    assert "unicode_fold" in prof.blind_to
    # and it recommends the mutators that exploit those blind spots
    assert any(m.startswith("html_entity") for m in prof.recommended_mutators)
    assert "unicode_fullwidth" in prof.recommended_mutators


def test_reorder_puts_recommended_first():
    prof = learn_normalization(_oracle())
    ms = REGISTRY.select(attack_class="XSS Injection")
    reordered = reorder_mutators(ms, prof)
    rec = set(prof.recommended_mutators)
    present = [m.name for m in reordered if m.name in rec]
    # the first recommended-and-present mutator must appear before the first non-recommended one
    first_non_rec = next(i for i, m in enumerate(reordered) if m.name not in rec)
    first_rec = next((i for i, m in enumerate(reordered) if m.name in rec), None)
    if present:
        assert first_rec < first_non_rec


def test_no_waf_returns_undetected():
    # sender that lets everything through -> nothing blocked -> can't learn
    prof = learn_normalization(_oracle(sender=lambda p: Response("THROUGH", "200", 100, 0.1, "ok")))
    assert prof.waf_detected is False and not prof.blind_to


def test_requests_counted():
    o = _oracle()
    prof = learn_normalization(o)
    assert prof.requests == o.requests and prof.requests > 0
