"""Tests for waffen/search/scoring.py — fitness scoring logic."""
from waffen.core.oracle import Response, BLOCKED, THROUGH, DOWN
from waffen.search.scoring import (
    composite_score,
    gradient_score,
    _is_5xx,
    _is_4xx,
    _attack_tokens,
    _reflection,
    CHAIN_PENALTY_PER_STEP,
    TRANSITION_BONUS,
    REACHED_BACKEND_BONUS,
    REFLECT_INTACT_BONUS,
    REFLECT_NEUTRALIZED_BONUS,
)


def _resp(verdict="BLOCKED", code="403", size=1800, time=0.1, body=""):
    return Response(verdict=verdict, code=code, size=size, time=time, body=body)


# ---- helpers ----

class TestHelpers:
    def test_is_5xx(self):
        assert _is_5xx("500")
        assert _is_5xx("503")
        assert not _is_5xx("403")
        assert not _is_5xx("200")
        assert not _is_5xx("50")
        assert not _is_5xx("")

    def test_is_4xx(self):
        assert _is_4xx("403")
        assert _is_4xx("404")
        assert not _is_4xx("200")
        assert not _is_4xx("500")


# ---- composite_score ----

class TestCompositeScore:
    def test_through_dominates(self):
        baseline = _resp()
        resp = _resp(verdict=THROUGH, code="200", size=3200)
        s = composite_score(resp, baseline, chain_len=1)
        assert s > 1e8

    def test_down_is_negative(self):
        baseline = _resp()
        resp = _resp(verdict=DOWN, code="000", size=0)
        assert composite_score(resp, baseline, chain_len=0) == -1.0

    def test_blocked_same_code_low_score(self):
        baseline = _resp(code="403", size=1800)
        resp = _resp(code="403", size=1800)
        s = composite_score(resp, baseline, chain_len=0)
        assert s == 0.0

    def test_code_drift_adds_score(self):
        baseline = _resp(code="403", size=1800)
        resp = _resp(code="500", size=1800)
        s = composite_score(resp, baseline, chain_len=0)
        assert s >= 3.0

    def test_4xx_to_5xx_transition_bonus(self):
        baseline = _resp(code="403", size=1800)
        resp = _resp(code="500", size=1800)
        s = composite_score(resp, baseline, chain_len=0)
        assert s >= 3.0 + TRANSITION_BONUS

    def test_size_delta(self):
        baseline = _resp(code="403", size=1000)
        resp = _resp(code="403", size=2000)
        s = composite_score(resp, baseline, chain_len=0)
        assert s > 0.0

    def test_chain_penalty(self):
        baseline = _resp()
        resp = _resp(verdict=THROUGH, code="200")
        s0 = composite_score(resp, baseline, chain_len=0)
        s3 = composite_score(resp, baseline, chain_len=3)
        assert s0 > s3
        assert abs((s0 - s3) - CHAIN_PENALTY_PER_STEP * 3) < 1e-6

    def test_through_always_beats_blocked(self):
        baseline = _resp(code="403", size=1800)
        blocked = _resp(code="500", size=5000)
        through = _resp(verdict=THROUGH, code="200", size=100)
        s_blocked = composite_score(blocked, baseline, chain_len=0)
        s_through = composite_score(through, baseline, chain_len=10)
        assert s_through > s_blocked

    def test_negative_chain_len_treated_as_zero(self):
        baseline = _resp()
        resp = _resp(verdict=THROUGH, code="200")
        s = composite_score(resp, baseline, chain_len=-5)
        assert s == composite_score(resp, baseline, chain_len=0)


# ---- attack_tokens ----

class TestAttackTokens:
    def test_extracts_keywords(self):
        tokens = _attack_tokens("' OR 1=1-- SELECT * FROM users")
        assert any("SELECT" in t for t in tokens)

    def test_empty_payload(self):
        assert _attack_tokens("") == []
        assert _attack_tokens(None) == []

    def test_deduplicates(self):
        tokens = _attack_tokens("SELECT select SELECT")
        lower = [t.lower() for t in tokens]
        assert len(lower) == len(set(lower))

    def test_caps_at_6(self):
        payload = " ".join(f"token{i}xx" for i in range(20))
        tokens = _attack_tokens(payload)
        assert len(tokens) <= 6


# ---- reflection ----

class TestReflection:
    def test_intact_with_dangerous_chars(self):
        body = "<p>SELECT * FROM users</p>"
        assert _reflection(body, ["SELECT"]) == "intact"

    def test_neutralized_entity_encoded(self):
        body = "result: &lt;script&gt;alert&lt;/script&gt;"
        assert _reflection(body, ["script"]) in ("intact", "neutralized")

    def test_none_when_absent(self):
        assert _reflection("hello world", ["UNION"]) == "none"

    def test_empty_body(self):
        assert _reflection("", ["UNION"]) == "none"

    def test_empty_tokens(self):
        assert _reflection("some body", []) == "none"


# ---- gradient_score ----

class TestGradientScore:
    def test_through_dominates(self):
        baseline = _resp()
        resp = _resp(verdict=THROUGH, code="200")
        s = gradient_score(resp, baseline, seed_payload="' OR 1=1--")
        assert s > 1e8

    def test_down_worst(self):
        baseline = _resp()
        resp = _resp(verdict=DOWN, code="000")
        assert gradient_score(resp, baseline) == -1.0

    def test_5xx_gets_reached_bonus(self):
        baseline = _resp(code="403", size=1800, time=0.05)
        resp_5xx = _resp(code="500", size=200, time=0.05)
        resp_4xx = _resp(code="404", size=200, time=0.05)
        s_5xx = gradient_score(resp_5xx, baseline)
        s_4xx = gradient_score(resp_4xx, baseline)
        assert s_5xx > s_4xx

    def test_slow_response_gets_reached_bonus(self):
        baseline = _resp(code="403", time=0.05)
        fast = _resp(code="403", time=0.05)
        slow = _resp(code="403", time=0.5)
        s_fast = gradient_score(fast, baseline)
        s_slow = gradient_score(slow, baseline)
        assert s_slow > s_fast

    def test_reflection_intact_beats_neutralized(self):
        baseline = _resp(code="403", size=1800)
        resp_intact = _resp(code="403", size=1800,
                            body="<p>SELECT * FROM users</p>")
        resp_neutral = _resp(code="403", size=1800,
                             body="result: &lt;SELECT&gt;")
        s_intact = gradient_score(resp_intact, baseline,
                                  seed_payload="SELECT * FROM users")
        s_neutral = gradient_score(resp_neutral, baseline,
                                   seed_payload="SELECT * FROM users")
        assert s_intact >= s_neutral

    def test_timing_threshold_override(self):
        baseline = _resp(code="403", time=0.05)
        resp = _resp(code="403", time=0.3)
        s_no_thresh = gradient_score(resp, baseline, timing_threshold=None)
        s_with_thresh = gradient_score(resp, baseline, timing_threshold=0.2)
        assert s_with_thresh >= s_no_thresh

    def test_chain_penalty_applied(self):
        baseline = _resp()
        resp = _resp(code="500")
        s0 = gradient_score(resp, baseline, chain_len=0)
        s5 = gradient_score(resp, baseline, chain_len=5)
        assert s0 > s5
