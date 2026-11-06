"""Tests for waffen.report.rules — bypass/gap -> actionable WAF rule recommendations.

Deliberately never imports waffen.search.beam.Finding or waffen.eval.coverage.EvalResult:
rules.py is specified to be duck-typed against those shapes (read, not hard-imported), and
these tests exercise exactly that contract with SimpleNamespace stand-ins, so they keep
passing even while beam.py / coverage.py are being edited concurrently elsewhere."""
from types import SimpleNamespace

from waffen.report.rules import (
    RuleSuggestion,
    recommend_from_finding,
    recommend_from_eval,
    render_markdown,
    render_text,
)

_SEVERITY_LEVEL = {"low": 0, "medium": 1, "high": 2, "critical": 3}

_TOP_TIER = ("Upload Insecure Files", "Command Injection", "SQL Injection", "SSTI", "File Inclusion")
_MID_TIER = ("CRLF Injection", "XSS Injection", "Directory Traversal", "NoSQL Injection", "LDAP Injection")

# A class-specific substring every suggested_rule is expected to mention, grounded in that
# class's real evasion mechanics (not generic boilerplate).
_CLASS_KEYWORDS = {
    "XSS Injection": "javascript:",
    "SQL Injection": "UNION",
    "Command Injection": "$IFS",
    "Directory Traversal": "../",
    "File Inclusion": "php://",
    "SSTI": "{{",
    "NoSQL Injection": "$ne",
    "CRLF Injection": "%0d",
    "Upload Insecure Files": "Content-Disposition",
    "LDAP Injection": "LDAP",
}


def _finding(attack_class, payload="payload", chain=None, verified=None, confidence=None):
    return SimpleNamespace(attack_class=attack_class, payload=payload,
                           chain=list(chain or []), verified=verified, confidence=confidence)


def _score(blocked, through):
    resolved = blocked + through
    coverage = (100.0 * blocked / resolved) if resolved else 0.0
    return SimpleNamespace(blocked=blocked, through=through, coverage=coverage)


def _eval_result(through_samples, per_class=None):
    return SimpleNamespace(through_samples=dict(through_samples), per_class=dict(per_class or {}))


# --------------------------------------------------------------------------- #
# recommend_from_finding — per-class templates
# --------------------------------------------------------------------------- #

def test_each_class_has_a_distinct_class_appropriate_suggested_rule():
    rules_by_class = {}
    for cls, keyword in _CLASS_KEYWORDS.items():
        f = _finding(cls, payload=f"{cls}-probe", chain=["m1", "m2"], verified=True, confidence=0.9)
        sug = recommend_from_finding(f, endpoint="/app")
        assert isinstance(sug, RuleSuggestion)
        assert sug.attack_class == cls
        assert keyword in sug.suggested_rule, f"{cls} suggested_rule missing {keyword!r}"
        rules_by_class[cls] = sug.suggested_rule
    # no two classes share identical boilerplate text
    assert len(set(rules_by_class.values())) == len(rules_by_class)


def test_generic_fallback_mentions_unknown_class_and_differs_from_known_classes():
    sug = recommend_from_finding(_finding("Some New Exotic Class", payload="x"))
    assert "Some New Exotic Class" in sug.suggested_rule
    known_rules = {recommend_from_finding(_finding(c)).suggested_rule for c in _CLASS_KEYWORDS}
    assert sug.suggested_rule not in known_rules


# --------------------------------------------------------------------------- #
# recommend_from_finding — severity heuristic
# --------------------------------------------------------------------------- #

def test_top_tier_classes_verified_true_is_critical_else_high():
    for cls in _TOP_TIER:
        assert recommend_from_finding(_finding(cls, verified=True)).severity == "critical"
        assert recommend_from_finding(_finding(cls, verified=False)).severity == "high"
        assert recommend_from_finding(_finding(cls, verified=None)).severity == "high"


def test_mid_tier_classes_verified_true_is_high_else_medium():
    for cls in _MID_TIER:
        assert recommend_from_finding(_finding(cls, verified=True)).severity == "high"
        assert recommend_from_finding(_finding(cls, verified=False)).severity == "medium"
        assert recommend_from_finding(_finding(cls, verified=None)).severity == "medium"


def test_unknown_class_verified_true_is_medium_else_low():
    sug_true = recommend_from_finding(_finding("Mystery Class", verified=True))
    sug_false = recommend_from_finding(_finding("Mystery Class", verified=False))
    sug_none = recommend_from_finding(_finding("Mystery Class", verified=None))
    assert sug_true.severity == "medium"
    assert sug_false.severity == "low"
    assert sug_none.severity == "low"


def test_severity_verified_ranks_gte_unverified_for_every_class():
    for cls in list(_CLASS_KEYWORDS) + ["Some Unknown Class"]:
        s_true = _SEVERITY_LEVEL[recommend_from_finding(_finding(cls, verified=True)).severity]
        s_false = _SEVERITY_LEVEL[recommend_from_finding(_finding(cls, verified=False)).severity]
        s_none = _SEVERITY_LEVEL[recommend_from_finding(_finding(cls, verified=None)).severity]
        assert s_true >= s_false
        assert s_true >= s_none


def test_all_severities_are_in_the_allowed_set():
    allowed = {"low", "medium", "high", "critical"}
    for cls in list(_CLASS_KEYWORDS) + ["Unknown Thing"]:
        for verified in (True, False, None):
            assert recommend_from_finding(_finding(cls, verified=verified)).severity in allowed


# --------------------------------------------------------------------------- #
# recommend_from_finding — rationale / traceability / duck typing
# --------------------------------------------------------------------------- #

def test_rationale_mentions_truncated_payload_and_chain():
    long_payload = "A" * 200
    f = _finding("XSS Injection", payload=long_payload, chain=["url_encode", "case_swap"],
                verified=True, confidence=0.75)
    sug = recommend_from_finding(f, endpoint="/search")
    assert "url_encode" in sug.rationale and "case_swap" in sug.rationale
    assert long_payload not in sug.rationale           # truncated, not dumped whole
    assert "A" * 20 in sug.rationale                   # but a recognizable prefix survives
    assert "0.75" in sug.rationale


def test_duck_typed_simplenamespace_fake_finding_works():
    # Explicitly NOT importing waffen.search.beam.Finding: proves no hard coupling to its
    # exact dataclass shape, even if beam.py is being touched concurrently elsewhere.
    fake = SimpleNamespace(attack_class="SQL Injection", payload="' OR 1=1-- -",
                           chain=["comment_obfuscate"], verified=True, confidence=0.95)
    sug = recommend_from_finding(fake, endpoint="/login")
    assert sug.attack_class == "SQL Injection"
    assert sug.severity == "critical"
    assert "UNION" in sug.suggested_rule


def test_missing_optional_attrs_do_not_crash():
    fake = SimpleNamespace(attack_class="XSS Injection", payload="<script>", chain=[])
    sug = recommend_from_finding(fake)
    assert sug.severity in {"low", "medium", "high", "critical"}


# --------------------------------------------------------------------------- #
# recommend_from_eval
# --------------------------------------------------------------------------- #

def test_recommend_from_eval_one_suggestion_per_qualifying_class():
    ev = _eval_result(
        through_samples={
            "XSS Injection": ["<script>1</script>", "<svg onload=1>"],
            "SQL Injection": [],                       # no samples -> not a gap, excluded
            "Command Injection": ["; id"],
        },
        per_class={
            "XSS Injection": _score(blocked=8, through=2),
            "Command Injection": _score(blocked=9, through=1),
        },
    )
    sugs = recommend_from_eval(ev, endpoint="/api")
    classes = {s.attack_class for s in sugs}
    assert classes == {"XSS Injection", "Command Injection"}
    for s in sugs:
        assert isinstance(s, RuleSuggestion)
        assert s.severity in {"low", "medium", "high", "critical"}


def test_recommend_from_eval_respects_min_through():
    ev = _eval_result(through_samples={
        "XSS Injection": ["a"],
        "SQL Injection": ["a", "b"],
        "Command Injection": ["a", "b", "c", "d"],
    })
    sugs = recommend_from_eval(ev, min_through=3)
    assert {s.attack_class for s in sugs} == {"Command Injection"}

    sugs_all = recommend_from_eval(ev, min_through=1)
    assert {s.attack_class for s in sugs_all} == {"XSS Injection", "SQL Injection", "Command Injection"}


def test_recommend_from_eval_uses_through_samples_payloads_in_rationale():
    ev = _eval_result(through_samples={"CRLF Injection": ["foo%0d%0abar"]})
    sugs = recommend_from_eval(ev)
    assert len(sugs) == 1
    assert "foo%0d%0abar" in sugs[0].rationale
    assert "%0d" in sugs[0].suggested_rule


def test_recommend_from_eval_gap_only_severity_matches_unverified_finding_severity():
    ev = _eval_result(through_samples={"SQL Injection": ["' OR 1=1-- -"]})
    gap_sug = recommend_from_eval(ev)[0]
    unverified_finding_sug = recommend_from_finding(_finding("SQL Injection", verified=None))
    assert gap_sug.severity == unverified_finding_sug.severity == "high"


def test_recommend_from_eval_missing_per_class_entry_does_not_crash():
    ev = _eval_result(through_samples={"LDAP Injection": ["*)(uid=*"]}, per_class={})
    sugs = recommend_from_eval(ev)
    assert len(sugs) == 1 and sugs[0].attack_class == "LDAP Injection"


def test_recommend_from_eval_duck_typed_plain_object_no_eval_import_needed():
    # Only .through_samples / .per_class are touched — no waffen.eval.coverage import here.
    ev = SimpleNamespace(through_samples={"NoSQL Injection": ["{'$gt': ''}"]}, per_class={})
    sugs = recommend_from_eval(ev)
    assert sugs and sugs[0].attack_class == "NoSQL Injection"


def test_recommend_from_eval_empty_through_samples_returns_empty_list():
    assert recommend_from_eval(_eval_result(through_samples={})) == []


# --------------------------------------------------------------------------- #
# render_markdown / render_text
# --------------------------------------------------------------------------- #

def _sample_suggestions():
    return [
        recommend_from_finding(_finding("SQL Injection", chain=["tamper"], verified=True, confidence=0.9)),
        recommend_from_finding(_finding("XSS Injection", chain=["encode"], verified=False, confidence=0.2)),
        recommend_from_finding(_finding("Directory Traversal", chain=[], verified=None)),
    ]


def test_render_markdown_contains_all_titles_and_looks_like_markdown():
    sugs = _sample_suggestions()
    out = render_markdown(sugs)
    assert out.startswith("# ")                 # top-level heading
    for s in sugs:
        assert s.title in out
    assert "## CRITICAL" in out                 # severity section heading present
    assert "|" in out                           # the summary table
    # critical-tier item (SQL Injection, verified) must be listed before a medium-tier one
    assert out.index(sugs[0].title) < out.index(sugs[2].title)


def test_render_markdown_empty_list_does_not_crash():
    out = render_markdown([])
    assert out.startswith("# ")
    assert "No findings" in out


def test_render_text_has_no_markdown_heading_or_bold_clutter():
    sugs = _sample_suggestions()
    out = render_text(sugs)
    assert "#" not in out
    assert "**" not in out
    for s in sugs:
        assert s.title in out


def test_render_text_empty_list_does_not_crash():
    out = render_text([])
    assert "No findings" in out
    assert "#" not in out and "**" not in out
