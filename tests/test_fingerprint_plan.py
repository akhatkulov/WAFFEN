"""Tests for waffen.recon.fingerprint.recommend_plan() — vendor -> test-plan hints.

Run offline: recommend_plan() is pure data lookup over fingerprint()'s output,
no network/sender involved.
"""
from __future__ import annotations

from waffen.recon.fingerprint import (
    BODY_LIMITS,
    DEFAULT_BODY_LIMIT,
    WEAK_HINTS,
    WafGuess,
    recommend_plan,
)


def test_recommend_plan_top_guess_cloudflare_returns_body_limit_and_mutators():
    guesses = [WafGuess(name="Cloudflare", confidence=0.8, evidence="body~/cloudflare/")]
    plan = recommend_plan(guesses)

    assert plan["vendor"] == "Cloudflare"
    assert plan["confidence"] == 0.8
    assert plan["body_limit"] == BODY_LIMITS["Cloudflare"] == 131072
    assert plan["suggested_mutators"], "expected a non-empty suggested_mutators list"
    assert plan["suggested_mutators"] == WEAK_HINTS["Cloudflare"]
    assert isinstance(plan["note"], str) and plan["note"]


def test_recommend_plan_picks_highest_confidence_guess():
    # order in the list shouldn't matter — the HIGHEST-confidence guess wins
    guesses = [
        WafGuess(name="ModSecurity", confidence=0.2, evidence="x"),
        WafGuess(name="Sucuri", confidence=0.9, evidence="y"),
    ]
    plan = recommend_plan(guesses)

    assert plan["vendor"] == "Sucuri"
    assert plan["confidence"] == 0.9
    assert plan["body_limit"] == BODY_LIMITS["Sucuri"]


def test_recommend_plan_empty_guesses_returns_none_vendor_and_default_limit():
    plan = recommend_plan([])

    assert plan["vendor"] is None
    assert plan["confidence"] == 0.0
    assert plan["body_limit"] == DEFAULT_BODY_LIMIT
    assert plan["suggested_mutators"] == []
    note = plan["note"].lower()
    assert "heuristic" in note or "guarantee" in note


def test_recommend_plan_unrecognized_vendor_falls_back_sanely():
    guesses = [WafGuess(name="TotallyMadeUpWAF 9000", confidence=0.55, evidence="z")]
    plan = recommend_plan(guesses)

    assert plan["vendor"] == "TotallyMadeUpWAF 9000"  # fingerprint's guess is preserved
    assert plan["confidence"] == 0.55
    assert plan["body_limit"] == DEFAULT_BODY_LIMIT    # no BODY_LIMITS entry -> generic fallback
    assert plan["suggested_mutators"] == []            # no WEAK_HINTS entry -> empty, not an error
    assert isinstance(plan["note"], str) and plan["note"]


def test_recommend_plan_redeye_has_no_documented_body_limit():
    # RedEye is this project's own stand-in target: intentionally omitted from
    # BODY_LIMITS/WEAK_HINTS (not-yet-documented), same fallback as "unrecognized"
    guesses = [WafGuess(name="RedEye", confidence=0.95, evidence="body~/request blocked by redeye/")]
    plan = recommend_plan(guesses)

    assert plan["vendor"] == "RedEye"
    assert plan["body_limit"] == DEFAULT_BODY_LIMIT
    assert plan["suggested_mutators"] == []


def test_body_limits_are_positive_ints_and_redeye_is_omitted():
    assert isinstance(DEFAULT_BODY_LIMIT, int) and DEFAULT_BODY_LIMIT > 0
    for vendor, limit in BODY_LIMITS.items():
        assert isinstance(limit, int) and limit > 0, vendor
    assert "RedEye" not in BODY_LIMITS


def test_weak_hints_reference_real_mutators_or_transforms():
    # guards against WEAK_HINTS silently drifting from actually-registered names
    from waffen.core import transforms as T
    import waffen.mutate as M

    known_transform_names = set(T.BY_NAME)
    known_mutator_names = {m.name for m in M.REGISTRY.all()}
    for vendor, names in WEAK_HINTS.items():
        assert names, f"{vendor!r} has an empty WEAK_HINTS list"
        for name in names:
            assert name in known_transform_names or name in known_mutator_names, (
                f"WEAK_HINTS[{vendor!r}] references unknown mutator/transform {name!r}"
            )
