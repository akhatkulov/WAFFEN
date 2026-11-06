"""Tests for waffen.core.transforms: the graphql_body placeholder transform,
the junk_prefix_param_sized padding factory, and the live
find_inspection_cutoff binary search (nowafpls++)."""
from __future__ import annotations

import json
import urllib.parse

from waffen.core import transforms as T
from waffen.core.oracle import Target


def _t():
    return Target(base_url="https://x.example", path="/api", param="q")


# ---------------------------------------------------------------------------
# graphql_body
# ---------------------------------------------------------------------------
def test_graphql_body_is_valid_json_with_payload_in_variables_q():
    argv = T.get("graphql_body").build(_t(), "<script>alert(1)</script>")
    body = argv[-1]
    parsed = json.loads(body)  # must be valid JSON

    assert parsed["variables"]["q"] == "<script>alert(1)</script>"
    assert "query" in parsed and "Probe" in parsed["query"] and "$q" in parsed["query"]


def test_graphql_body_sets_json_content_type_and_posts():
    argv = T.get("graphql_body").build(_t(), "PAY")

    assert any(a == "Content-Type: application/json" for a in argv)
    assert "-X" in argv and "POST" in argv


def test_graphql_body_registered_as_placeholder_not_structural():
    assert "graphql_body" in T.BY_NAME
    assert "graphql_body" not in T.STRUCTURAL
    assert "graphql_body" in getattr(T, "PLACEHOLDER_EXTRA", {"graphql_body"})


# ---------------------------------------------------------------------------
# junk_prefix_param_sized
# ---------------------------------------------------------------------------
def test_junk_prefix_param_sized_differs_from_default_8000():
    t = _t()
    small = T.junk_prefix_param_sized(500).build(t, "PAY")
    default = T.get("junk_prefix_param").build(t, "PAY")  # hardcoded 8000B, unchanged

    small_q, default_q = small[-1], default[-1]
    assert small_q != default_q
    assert len(small_q) < len(default_q)
    assert "A" * 500 in small_q           # the 500B padding block is present ...
    assert "A" * 501 not in small_q       # ... and is not accidentally bigger


def test_junk_prefix_param_sized_not_auto_registered_in_transforms():
    before = [t.name for t in T.TRANSFORMS]
    factory_transform = T.junk_prefix_param_sized(42)

    assert [t.name for t in T.TRANSFORMS] == before  # TRANSFORMS untouched
    assert "junk_prefix_param_42" not in T.BY_NAME
    # but it's still a perfectly usable, standalone RequestTransform
    argv = factory_transform.build(_t(), "PAY")
    assert "A" * 42 in argv[-1]


# ---------------------------------------------------------------------------
# find_inspection_cutoff — fake oracle, no real Oracle/network needed.
# Simulates a WAF whose verdict flips BLOCKED -> THROUGH once the crafted
# payload string reaches `threshold` bytes (i.e. padding has pushed the
# signature past the inspection window).
# ---------------------------------------------------------------------------
class _FakeResponse:
    def __init__(self, verdict: str):
        self.verdict = verdict


class _FakeOracle:
    def __init__(self, threshold: int):
        self.threshold = threshold
        self.calls = 0

    def send(self, payload: str) -> _FakeResponse:
        self.calls += 1
        verdict = "THROUGH" if len(payload) >= self.threshold else "BLOCKED"
        return _FakeResponse(verdict)


def _crafted(pad_size: int, param: str = "padding",
             sig: str = "<script>alert(1)</script>") -> str:
    """Mirrors find_inspection_cutoff's documented payload construction, so
    tests can verify convergence without reaching into its internals."""
    return ("A" * pad_size) + "&" + urllib.parse.urlencode({param: sig})


def test_find_inspection_cutoff_converges_near_threshold_within_budget():
    threshold = 437
    oracle = _FakeOracle(threshold)

    result = T.find_inspection_cutoff(oracle, lo=0, hi=1000, probes=12)
    calls_used = oracle.calls

    assert result is not None
    assert calls_used <= 12  # strict probe cap

    # the returned size must actually flip the fake oracle to THROUGH ...
    assert len(_crafted(result)) >= threshold
    # ... and be (at worst, very close to) the minimal such size
    if result > 0:
        assert len(_crafted(result - 1)) < threshold + 5  # "near T", small slack
    assert abs(len(_crafted(result)) - threshold) <= 5


def test_find_inspection_cutoff_never_exceeds_probes_cap_with_tiny_budget():
    oracle = _FakeOracle(437)

    result = T.find_inspection_cutoff(oracle, lo=0, hi=1000, probes=3)

    assert oracle.calls <= 3
    assert oracle.calls >= 1
    if result is not None:
        assert len(_crafted(result)) >= 437  # whatever it returns must be a real flip


def test_find_inspection_cutoff_returns_none_when_it_never_flips_within_hi():
    oracle = _FakeOracle(threshold=10_000_000)  # far beyond hi — never flips

    result = T.find_inspection_cutoff(oracle, lo=0, hi=1000, probes=12)

    assert result is None
    assert oracle.calls <= 12


def test_find_inspection_cutoff_zero_probe_budget_sends_nothing():
    oracle = _FakeOracle(437)

    result = T.find_inspection_cutoff(oracle, lo=0, hi=1000, probes=0)

    assert result is None
    assert oracle.calls == 0
