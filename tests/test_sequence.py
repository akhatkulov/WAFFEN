"""Tests for multi-request attack sequences."""
from unittest.mock import MagicMock

import pytest

from waffen.core.sequence import (
    AttackSequence,
    RequestStep,
    SequenceResult,
    SequenceRunner,
    StepResult,
    _extract,
    _jsonpath,
    _sub,
    THROUGH,
    BLOCKED,
    DOWN,
    Response,
)
from waffen.core.oracle import Target
from waffen.kb.sequences import (
    SEQUENCES,
    BY_NAME,
    all_sequences,
    get_sequence,
    sequence_names,
)


# ---------------------------------------------------------------------------
# placeholder substitution
# ---------------------------------------------------------------------------

class TestSub:
    def test_simple(self):
        assert _sub("hello {name}", {"name": "world"}) == "hello world"

    def test_multiple(self):
        assert _sub("{a}+{b}", {"a": "1", "b": "2"}) == "1+2"

    def test_no_placeholder(self):
        assert _sub("plain text", {"a": "1"}) == "plain text"

    def test_empty_ctx(self):
        assert _sub("{x}", {}) == "{x}"

    def test_missing_key(self):
        assert _sub("{x}", {"y": "1"}) == "{x}"

    def test_payload_placeholder(self):
        assert _sub("{PAYLOAD}", {"PAYLOAD": "' OR 1=1--"}) == "' OR 1=1--"


# ---------------------------------------------------------------------------
# JSON path extraction
# ---------------------------------------------------------------------------

class TestJsonpath:
    def test_simple_key(self):
        assert _jsonpath('{"a": 1}', "a") == "1"

    def test_nested(self):
        assert _jsonpath('{"authentication": {"token": "abc123"}}',
                         "authentication.token") == "abc123"

    def test_missing_key(self):
        assert _jsonpath('{"a": 1}', "b") == ""

    def test_invalid_json(self):
        assert _jsonpath("not json", "a") == ""

    def test_array_index(self):
        assert _jsonpath('{"data": [10, 20, 30]}', "data.1") == "20"

    def test_deep_nest(self):
        assert _jsonpath('{"a": {"b": {"c": "deep"}}}', "a.b.c") == "deep"

    def test_null_value(self):
        assert _jsonpath('{"a": null}', "a") == ""


# ---------------------------------------------------------------------------
# extract from response
# ---------------------------------------------------------------------------

class TestExtract:
    def test_jsonpath(self):
        body = '{"authentication": {"token": "tok123"}}'
        assert _extract(body, {}, "$.authentication.token") == "tok123"

    def test_header(self):
        assert _extract("", {"Set-Cookie": "sid=abc"}, "Set-Cookie") == "sid=abc"

    def test_header_case_fallback(self):
        assert _extract("", {"set-cookie": "sid=abc"}, "Set-Cookie") == "sid=abc"

    def test_regex(self):
        body = 'token=abc123&other=1'
        assert _extract(body, {}, "/token=([a-z0-9]+)/") == "abc123"

    def test_regex_no_match(self):
        assert _extract("nothing here", {}, "/token=([a-z]+)/") == ""

    def test_unknown_pattern(self):
        assert _extract("body", {}, "something weird") == ""


# ---------------------------------------------------------------------------
# RequestStep
# ---------------------------------------------------------------------------

class TestRequestStep:
    def test_with_context(self):
        step = RequestStep(
            method="GET", path="/api/{version}/search",
            params={"q": "{PAYLOAD}"},
            headers={"Authorization": "Bearer {token}"},
        )
        resolved = step.with_context({"version": "v2", "PAYLOAD": "test", "token": "abc"})
        assert resolved.path == "/api/v2/search"
        assert resolved.params["q"] == "test"
        assert resolved.headers["Authorization"] == "Bearer abc"

    def test_with_context_no_placeholders(self):
        step = RequestStep(method="GET", path="/plain")
        resolved = step.with_context({"x": "1"})
        assert resolved.path == "/plain"

    def test_with_context_body(self):
        step = RequestStep(body='{"email": "{PAYLOAD}"}')
        resolved = step.with_context({"PAYLOAD": "test@test.com"})
        assert resolved.body == '{"email": "test@test.com"}'


# ---------------------------------------------------------------------------
# AttackSequence
# ---------------------------------------------------------------------------

class TestAttackSequence:
    def test_with_payload(self):
        seq = AttackSequence(
            name="test",
            steps=[
                RequestStep(params={"q": "{PAYLOAD}"}),
                RequestStep(body='{"x": "{PAYLOAD}"}'),
            ],
        )
        resolved = seq.with_payload("' OR 1=1--")
        assert resolved.steps[0].params["q"] == "' OR 1=1--"
        assert "' OR 1=1--" in resolved.steps[1].body

    def test_with_payload_preserves_name(self):
        seq = AttackSequence(name="orig", steps=[])
        assert seq.with_payload("x").name == "orig"

    def test_original_unchanged(self):
        seq = AttackSequence(
            name="test",
            steps=[RequestStep(params={"q": "{PAYLOAD}"})],
        )
        seq.with_payload("injected")
        assert seq.steps[0].params["q"] == "{PAYLOAD}"


# ---------------------------------------------------------------------------
# SequenceRunner with mock sender
# ---------------------------------------------------------------------------

def _mock_runner(responses):
    """Build a SequenceRunner with canned responses."""
    target = Target(base_url="https://test.example.com")
    idx = [0]

    def mock_sender(step, cmd):
        r = responses[min(idx[0], len(responses) - 1)]
        idx[0] += 1
        return r

    return SequenceRunner(target, sender=mock_sender)


class TestSequenceRunner:
    def test_single_step_through(self):
        runner = _mock_runner([Response(THROUGH, "200", 100, 0.1, "ok")])
        seq = AttackSequence("t", [RequestStep(params={"q": "{PAYLOAD}"})])
        result = runner.run(seq, "test")
        assert result.verdict == THROUGH
        assert result.requests == 1
        assert result.through

    def test_single_step_blocked(self):
        runner = _mock_runner([Response(BLOCKED, "403", 50, 0.1, "blocked")])
        seq = AttackSequence("t", [RequestStep(params={"q": "{PAYLOAD}"})])
        result = runner.run(seq, "test")
        assert result.verdict == BLOCKED
        assert not result.through

    def test_multi_step_extraction(self):
        login_resp = Response(THROUGH, "200", 200, 0.1,
                              '{"authentication": {"token": "jwt123"}}')
        search_resp = Response(THROUGH, "200", 100, 0.1, '{"data": []}')

        runner = _mock_runner([login_resp, search_resp])
        seq = AttackSequence("t", [
            RequestStep(method="POST", path="/login",
                        body='{"email":"a"}',
                        extract={"token": "$.authentication.token"}),
            RequestStep(method="GET", path="/search",
                        params={"q": "{PAYLOAD}"},
                        headers={"Authorization": "Bearer {token}"}),
        ])
        result = runner.run(seq, "' OR 1=1--")
        assert result.requests == 2
        assert result.verdict == THROUGH
        assert result.steps[0].extracted["token"] == "jwt123"

    def test_last_step_determines_verdict(self):
        # First step passes, last step blocked
        runner = _mock_runner([
            Response(THROUGH, "200", 100, 0.1, "ok"),
            Response(BLOCKED, "403", 50, 0.1, "blocked"),
        ])
        seq = AttackSequence("t", [
            RequestStep(path="/setup"),
            RequestStep(path="/inject", params={"q": "{PAYLOAD}"}),
        ])
        result = runner.run(seq, "test")
        assert result.verdict == BLOCKED

    def test_context_passes_between_steps(self):
        runner = _mock_runner([
            Response(THROUGH, "200", 10, 0.1, '{"id": 42}'),
            Response(THROUGH, "200", 10, 0.1, "ok"),
        ])
        seq = AttackSequence("t", [
            RequestStep(path="/create", extract={"user_id": "$.id"}),
            RequestStep(path="/user/{user_id}"),
        ])
        result = runner.run(seq)
        assert result.steps[0].extracted["user_id"] == "42"
        assert result.requests == 2

    def test_payload_in_sequence_name(self):
        runner = _mock_runner([Response(THROUGH, "200", 10, 0.1, "")])
        seq = AttackSequence("test_seq", [RequestStep()])
        result = runner.run(seq, "payload123")
        assert result.payload == "payload123"
        assert result.sequence_name == "test_seq"

    def test_empty_sequence(self):
        runner = _mock_runner([])
        seq = AttackSequence("empty", [])
        result = runner.run(seq)
        assert result.requests == 0
        assert result.verdict == DOWN


# ---------------------------------------------------------------------------
# Built-in sequences
# ---------------------------------------------------------------------------

class TestBuiltinSequences:
    def test_sequences_not_empty(self):
        assert len(SEQUENCES) >= 5

    def test_all_have_names(self):
        for s in SEQUENCES:
            assert s.name
            assert s.steps

    def test_by_name_lookup(self):
        for s in SEQUENCES:
            assert BY_NAME[s.name] is s

    def test_get_sequence(self):
        assert get_sequence("auth_then_inject") is not None
        assert get_sequence("nonexistent") is None

    def test_all_sequences(self):
        assert len(all_sequences()) == len(SEQUENCES)

    def test_sequence_names(self):
        names = sequence_names()
        assert "auth_then_inject" in names
        assert "store_then_trigger" in names
        assert "cookie_inject" in names

    def test_auth_then_inject_has_extract(self):
        seq = get_sequence("auth_then_inject")
        extracts = [s.extract for s in seq.steps if s.extract]
        assert len(extracts) >= 1
        assert "token" in extracts[0]

    def test_with_payload_on_builtins(self):
        for s in SEQUENCES:
            resolved = s.with_payload("' OR 1=1--")
            # Should not raise
            assert resolved.name == s.name

    def test_store_then_trigger_has_three_steps(self):
        seq = get_sequence("store_then_trigger")
        assert len(seq.steps) >= 3

    def test_warmup_inject_has_multiple_benign(self):
        seq = get_sequence("warmup_inject")
        assert len(seq.steps) >= 4


# ---------------------------------------------------------------------------
# SequenceResult properties
# ---------------------------------------------------------------------------

class TestSequenceResult:
    def test_through_property(self):
        r = SequenceResult("t", "p", verdict=THROUGH)
        assert r.through is True

    def test_blocked_not_through(self):
        r = SequenceResult("t", "p", verdict=BLOCKED)
        assert r.through is False
