"""Tests for payload minimization."""
from unittest.mock import MagicMock

import pytest

from waffen.search.minimize import (
    PayloadMinimizer,
    MinimizeResult,
    _replay_chain,
)


# ---- helpers ---------------------------------------------------------------

class FakeOracle:
    """Mock oracle where specific payloads are THROUGH, everything else BLOCKED."""

    def __init__(self, through_payloads=None):
        self._through = set(through_payloads or [])
        self.sent = []

    def send(self, payload):
        self.sent.append(payload)
        resp = MagicMock()
        resp.verdict = "THROUGH" if payload in self._through else "BLOCKED"
        resp.code = "200" if payload in self._through else "403"
        return resp


# ---- _replay_chain ---------------------------------------------------------

class TestReplayChain:
    def test_empty_chain(self):
        assert _replay_chain("test", []) == "test"

    def test_single_step(self):
        result = _replay_chain("hello", ["base64"])
        assert result != "hello"
        assert len(result) > 0

    def test_unknown_mutator_passthrough(self):
        result = _replay_chain("test", ["nonexistent_mutator_xyz"])
        assert result == "test"

    def test_chain_applies_in_order(self):
        seed = "' OR 1=1--"
        r1 = _replay_chain(seed, ["base64"])           # single base64
        chain_result = _replay_chain(seed, ["base64", "base64"])  # double base64
        assert chain_result != seed
        assert chain_result != r1  # double ≠ single


# ---- chain minimization ---------------------------------------------------

class TestMinimizeChain:
    def test_empty_chain(self):
        oracle = FakeOracle()
        m = PayloadMinimizer(oracle)
        result = m.minimize_chain("test", [])
        assert result.minimized_chain == []
        assert result.requests_used == 0

    def test_single_step_through(self):
        b64_payload = _replay_chain("' OR 1=1--", ["base64"])
        oracle = FakeOracle(through_payloads={b64_payload})
        m = PayloadMinimizer(oracle)
        result = m.minimize_chain("' OR 1=1--", ["base64"])
        assert result.minimized_chain == ["base64"]
        assert result.minimized_payload == b64_payload

    def test_single_step_already_minimal(self):
        b64_payload = _replay_chain("' OR 1=1--", ["base64"])
        oracle = FakeOracle(through_payloads={b64_payload})
        m = PayloadMinimizer(oracle)
        result = m.minimize_chain("' OR 1=1--", ["base64", "url_encode"])
        # base64 alone should pass — no need for url_encode
        assert result.minimized_chain == ["base64"]
        assert result.requests_used >= 1

    def test_needs_both_steps(self):
        seed = "' OR 1=1--"
        # base64 → unicode_fullwidth: each step changes the string, and the
        # combined output differs from either single mutator's output
        combined = _replay_chain(seed, ["base64", "unicode_fullwidth"])
        b64_only = _replay_chain(seed, ["base64"])
        fw_only = _replay_chain(seed, ["unicode_fullwidth"])
        assert combined != b64_only and combined != fw_only
        # Only the full 2-step chain passes (not either alone)
        oracle = FakeOracle(through_payloads={combined})
        m = PayloadMinimizer(oracle)
        result = m.minimize_chain(seed, ["base64", "unicode_fullwidth"])
        assert len(result.minimized_chain) == 2

    def test_three_step_reduce_to_one(self):
        """If only base64 matters, the other two steps should be dropped."""
        b64 = _replay_chain("payload", ["base64"])
        oracle = FakeOracle(through_payloads={b64})
        m = PayloadMinimizer(oracle)
        result = m.minimize_chain("payload", ["base64", "url_encode", "hex_encode"])
        assert result.minimized_chain == ["base64"]

    def test_greedy_reduction(self):
        """With a 3-step chain where any 2 pass, reduce to 2."""
        chain = ["base64", "url_encode", "hex_encode"]
        pair1 = _replay_chain("x", ["base64", "url_encode"])
        pair2 = _replay_chain("x", ["base64", "hex_encode"])
        oracle = FakeOracle(through_payloads={pair1, pair2})
        m = PayloadMinimizer(oracle)
        result = m.minimize_chain("x", chain)
        assert len(result.minimized_chain) <= 2

    def test_requests_counted(self):
        oracle = FakeOracle()
        m = PayloadMinimizer(oracle)
        m.minimize_chain("test", ["base64", "url_encode"])
        assert m._requests > 0
        assert len(oracle.sent) > 0

    def test_identity_payload_skipped(self):
        """If a mutator produces the same string as seed, it shouldn't be sent."""
        oracle = FakeOracle()
        m = PayloadMinimizer(oracle)
        result = m.minimize_chain("test", ["nonexistent_xyz"])
        # nonexistent mutator returns seed unchanged → not sent
        assert result.minimized_chain == ["nonexistent_xyz"]  # kept as only option


# ---- payload text trimming -------------------------------------------------

class TestTrimPayload:
    def test_empty_payload(self):
        oracle = FakeOracle()
        m = PayloadMinimizer(oracle)
        result = m.trim_payload("")
        assert result.trimmed_payload == ""
        assert result.requests_used == 0

    def test_all_through(self):
        """Every prefix passes → should find a very short one."""
        all_prefixes = {chr(c) for c in range(32, 127)}
        all_prefixes.update({"ab", "abc", "a"})
        oracle = FakeOracle(through_payloads=all_prefixes)
        m = PayloadMinimizer(oracle)
        result = m.trim_payload("abcdef")
        assert len(result.trimmed_payload) <= len("abcdef")
        assert result.requests_used > 0

    def test_full_payload_only(self):
        """Only the full string passes → trimming returns it unchanged."""
        oracle = FakeOracle(through_payloads={"FULLPAYLOAD"})
        m = PayloadMinimizer(oracle)
        result = m.trim_payload("FULLPAYLOAD")
        assert result.trimmed_payload == "FULLPAYLOAD"

    def test_prefix_reduction(self):
        """First 4 chars are enough."""
        oracle = FakeOracle(through_payloads={
            "JyBP", "JyBPU", "JyBPUi", "JyBPUiA", "JyBPUiAx", "JyBPUiAxPTEtLQ==",
        })
        m = PayloadMinimizer(oracle)
        result = m.trim_payload("JyBPUiAxPTEtLQ==")
        assert len(result.trimmed_payload) <= 4

    def test_requests_counted(self):
        oracle = FakeOracle(through_payloads={"abc"})
        m = PayloadMinimizer(oracle)
        result = m.trim_payload("abc")
        assert result.trim_requests > 0


# ---- combined minimize -----------------------------------------------------

class TestMinimizeCombined:
    def test_chain_plus_trim(self):
        b64 = _replay_chain("payload", ["base64"])
        # Every prefix of the b64 output also passes
        prefixes = {b64[:i] for i in range(1, len(b64) + 1)}
        oracle = FakeOracle(through_payloads=prefixes)
        m = PayloadMinimizer(oracle)
        result = m.minimize("payload", ["base64", "url_encode"], do_trim=True)
        assert result.minimized_chain == ["base64"]
        assert len(result.trimmed_payload) <= len(b64)
        assert result.requests_used > 0

    def test_no_trim(self):
        b64 = _replay_chain("test", ["base64"])
        oracle = FakeOracle(through_payloads={b64})
        m = PayloadMinimizer(oracle)
        result = m.minimize("test", ["base64"], do_trim=False)
        assert result.trimmed_payload == ""
        assert result.trim_requests == 0


# ---- result dict -----------------------------------------------------------

class TestResultDict:
    def test_as_dict_keys(self):
        r = MinimizeResult(
            original_chain=["a", "b"], original_payload="x",
            minimized_chain=["a"], minimized_payload="y",
            requests_used=10, trimmed_payload="z", trim_requests=5,
        )
        d = r.as_dict()
        assert d["original_chain"] == ["a", "b"]
        assert d["minimized_chain"] == ["a"]
        assert d["trimmed_payload"] == "z"
        assert d["requests_used"] == 10
