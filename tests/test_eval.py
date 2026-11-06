"""Tests for the eval/coverage scorer (offline mock)."""
from waffen.core.mock import make_mock_sender
from waffen.core.oracle import Target
from waffen.eval.coverage import run_eval, ClassScore
from waffen.kb import seeds as kb_seeds


def _target():
    return Target(base_url="mock://x", path="/", param="q", inject="query")


def test_attack_corpus_mostly_blocked():
    cases = [(c, p) for c in kb_seeds.classes() for p in kb_seeds.seeds_for(c)]
    res = run_eval(_target(), cases, sender=make_mock_sender(), concurrency=4)
    o = res.overall
    assert o.blocked > 0
    # the mock blocks raw attack signatures, so overall coverage should be high
    assert o.coverage >= 60.0


def test_benign_low_false_positive():
    cases = [("XSS Injection", "<script>alert(1)</script>")]
    benign = ["banana juice", "apple smoothie", "order 12345", "how to reset password"]
    res = run_eval(_target(), cases, benign=benign, sender=make_mock_sender(), concurrency=2)
    assert res.benign_total == 4
    assert res.benign_blocked == 0        # clean benign strings must not be blocked
    assert res.fp_rate == 0.0


def test_classscore_math():
    s = ClassScore(blocked=8, through=2)
    assert s.resolved == 10 and s.coverage == 80.0
    assert ClassScore().coverage == 0.0  # no divide-by-zero


def test_through_samples_recorded():
    # a payload the mock lets through (no signature) should surface as a gap sample
    cases = [("SQL Injection", "harmless_text_no_sig")]
    res = run_eval(_target(), cases, sender=make_mock_sender())
    assert res.per_class["SQL Injection"].through == 1
    assert "harmless_text_no_sig" in res.through_samples["SQL Injection"]


def test_as_dict_shape():
    cases = [("XSS Injection", "<script>alert(1)</script>")]
    res = run_eval(_target(), cases, benign=["banana"], sender=make_mock_sender())
    d = res.as_dict()
    assert "overall" in d and "false_positive_pct" in d and "per_class" in d


def test_api_vs_app_split():
    from waffen.eval.coverage import EvalResult, class_group
    res = EvalResult(per_class={
        "NoSQL Injection": ClassScore(blocked=1, through=3),
        "SSRF": ClassScore(blocked=3, through=1),
        "SQL Injection": ClassScore(blocked=9, through=1),
        "Mystery Class": ClassScore(blocked=1, through=0),
    })
    assert class_group("Mystery Class") == "app"
    assert res.api_coverage == 50.0           # 4 blocked / 8 resolved
    assert abs(res.app_coverage - 100.0 * 10 / 11) < 1e-9
    d = res.as_dict()["api_vs_app"]
    assert d["api"] == {"coverage_pct": 50.0, "blocked": 4, "through": 4}
    assert d["app"] == {"coverage_pct": 90.9, "blocked": 10, "through": 1}


def test_api_vs_app_empty_group_is_zero():
    from waffen.eval.coverage import EvalResult
    res = EvalResult(per_class={"SQL Injection": ClassScore(blocked=1, through=1)})
    assert res.api_coverage == 0.0
    assert res.as_dict()["api_vs_app"]["api"] == {"coverage_pct": 0.0, "blocked": 0, "through": 0}
