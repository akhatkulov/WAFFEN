"""Tests for the RL (Q-learning) bypass search."""
import json
import os
import tempfile
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from waffen.search.rl import (
    WAFState,
    INITIAL_STATE,
    QLearningAgent,
    compute_reward,
    rl_search,
)
from waffen.search.beam import Finding, SearchResult


# ---------------------------------------------------------------------------
# WAFState
# ---------------------------------------------------------------------------

class TestWAFState:
    def test_initial_state(self):
        s = INITIAL_STATE
        assert s.last_verdicts == ()
        assert s.last_mutator == ""
        assert s.depth == 0

    def test_to_key_deterministic(self):
        s = WAFState(("BLOCKED", "THROUGH"), ("403", "200"), "base64", 3)
        assert s.to_key() == s.to_key()

    def test_to_key_captures_last_3(self):
        s = WAFState(("A", "B", "C", "D"), (), "m", 1)
        assert "('B', 'C', 'D')" in s.to_key()

    def test_to_key_depth_capped_at_6(self):
        s1 = WAFState((), (), "m", 10)
        s2 = WAFState((), (), "m", 100)
        assert s1.to_key() == s2.to_key()

    def test_frozen(self):
        s = INITIAL_STATE
        with pytest.raises(AttributeError):
            s.depth = 5  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Reward
# ---------------------------------------------------------------------------

class TestReward:
    def _resp(self, verdict, code="403", score=0.0):
        return SimpleNamespace(verdict=verdict, code=code, score=score)

    def test_through_gives_100(self):
        r = compute_reward(self._resp("THROUGH", "200"), 0.0)
        assert r == 100.0

    def test_blocked_gives_negative(self):
        r = compute_reward(self._resp("BLOCKED"), 0.0)
        assert r < 0

    def test_down_gives_large_negative(self):
        r = compute_reward(self._resp("DOWN", "000"), 0.0)
        assert r == -5.0

    def test_score_improvement_positive(self):
        r = compute_reward(self._resp("BLOCKED", score=5.0), 2.0)
        assert r > 0

    def test_no_improvement_negative(self):
        r = compute_reward(self._resp("BLOCKED", score=1.0), 5.0)
        assert r < 0


# ---------------------------------------------------------------------------
# QLearningAgent
# ---------------------------------------------------------------------------

class TestQLearningAgent:
    def test_init(self):
        agent = QLearningAgent(["a", "b", "c"])
        assert len(agent.actions) == 3
        assert agent.epsilon == 0.3
        assert agent.states_seen == 0

    def test_choose_action_returns_valid(self):
        agent = QLearningAgent(["a", "b", "c"])
        s = INITIAL_STATE
        action = agent.choose_action(s)
        assert action in ["a", "b", "c"]

    def test_exploit_prefers_highest_q(self):
        agent = QLearningAgent(["a", "b"], epsilon=0.0)
        key = INITIAL_STATE.to_key()
        agent.q_table[key] = {"a": 1.0, "b": 10.0}
        for _ in range(20):
            assert agent.choose_action(INITIAL_STATE) == "b"

    def test_explore_with_high_epsilon(self):
        agent = QLearningAgent(["a", "b"], epsilon=1.0)
        actions = {agent.choose_action(INITIAL_STATE) for _ in range(100)}
        assert len(actions) == 2

    def test_update_creates_q_entry(self):
        agent = QLearningAgent(["a"])
        s1 = INITIAL_STATE
        s2 = WAFState(("BLOCKED",), ("403",), "a", 1)
        agent.update(s1, "a", -1.0, s2)
        assert s1.to_key() in agent.q_table
        assert "a" in agent.q_table[s1.to_key()]

    def test_update_q_value_moves_toward_reward(self):
        agent = QLearningAgent(["a"], alpha=1.0, gamma=0.0)
        s1 = INITIAL_STATE
        s2 = WAFState(("BLOCKED",), ("403",), "a", 1)
        agent.update(s1, "a", 50.0, s2)
        assert agent.q_table[s1.to_key()]["a"] == 50.0

    def test_decay_epsilon(self):
        agent = QLearningAgent(["a"], epsilon=0.3)
        old = agent.epsilon
        agent.decay_epsilon()
        assert agent.epsilon < old
        assert agent.epsilon > 0.05

    def test_decay_respects_minimum(self):
        agent = QLearningAgent(["a"], epsilon=0.06)
        agent.decay_epsilon(min_epsilon=0.05)
        assert agent.epsilon >= 0.05

    def test_top_actions(self):
        agent = QLearningAgent(["a", "b", "c"], epsilon=0.0)
        key = INITIAL_STATE.to_key()
        agent.q_table[key] = {"a": 5.0, "b": 10.0, "c": 1.0}
        top = agent.top_actions(INITIAL_STATE, n=2)
        assert top[0] == ("b", 10.0)
        assert len(top) == 2

    def test_states_seen(self):
        agent = QLearningAgent(["a"])
        assert agent.states_seen == 0
        agent.q_table["k1"] = {"a": 1.0}
        agent.q_table["k2"] = {"a": 2.0}
        assert agent.states_seen == 2

    def test_total_reward_accumulates(self):
        agent = QLearningAgent(["a"])
        s1, s2 = INITIAL_STATE, WAFState(("B",), ("403",), "a", 1)
        agent.update(s1, "a", 10.0, s2)
        agent.update(s2, "a", 5.0, s1)
        assert agent.total_reward == 15.0
        assert agent.steps == 2


# ---------------------------------------------------------------------------
# Policy save / load
# ---------------------------------------------------------------------------

class TestPolicySaveLoad:
    def test_roundtrip(self, tmp_path):
        agent = QLearningAgent(["x", "y"], alpha=0.2, gamma=0.9, epsilon=0.1)
        agent.q_table["s1"] = {"x": 3.0, "y": 7.0}
        agent.total_reward = 42.0
        agent.steps = 10
        path = str(tmp_path / "policy.json")
        agent.save_policy(path)

        loaded = QLearningAgent.load_policy(path)
        assert loaded.actions == ["x", "y"]
        assert loaded.alpha == 0.2
        assert loaded.gamma == 0.9
        assert loaded.epsilon == 0.1
        assert loaded.q_table["s1"]["y"] == 7.0
        assert loaded.total_reward == 42.0
        assert loaded.steps == 10

    def test_save_creates_valid_json(self, tmp_path):
        agent = QLearningAgent(["a"])
        path = str(tmp_path / "p.json")
        agent.save_policy(path)
        with open(path) as f:
            data = json.load(f)
        assert "actions" in data
        assert "q_table" in data


# ---------------------------------------------------------------------------
# rl_search
# ---------------------------------------------------------------------------

class _FakeOracle:
    """Mock oracle that blocks everything except payloads containing 'MAGIC'."""
    def __init__(self):
        self.calls = 0

    def send(self, payload):
        self.calls += 1
        if "MAGIC" in payload:
            return SimpleNamespace(verdict="THROUGH", code="200", score=1e9,
                                   size=100, time=0.01, body="ok", through=True)
        return SimpleNamespace(verdict="BLOCKED", code="403", score=0.0,
                               size=50, time=0.01, body="blocked", through=False)


class _FakeMutator:
    def __init__(self, name, fn):
        self.name = name
        self.desc = name
        self.multi = False
        self._fn = fn

    def apply(self, payload):
        return self._fn(payload)

    def apply_multi(self, payload):
        return [self.apply(payload)]


class TestRLSearch:
    def _mutators(self):
        return [
            _FakeMutator("noop", lambda p: p),
            _FakeMutator("add_magic", lambda p: p + "MAGIC"),
            _FakeMutator("upper", lambda p: p.upper()),
        ]

    def test_basic_search_runs(self):
        oracle = _FakeOracle()
        res = rl_search(oracle, "test", self._mutators(), max_requests=50,
                        attack_class="sqli")
        assert isinstance(res, SearchResult)
        assert res.requests <= 50

    def test_finds_magic_bypass(self):
        oracle = _FakeOracle()
        res = rl_search(oracle, "test", self._mutators(), max_requests=200,
                        attack_class="sqli")
        assert len(res.findings) > 0
        assert any("MAGIC" in f.payload for f in res.findings)

    def test_stop_on_first(self):
        oracle = _FakeOracle()
        res = rl_search(oracle, "test", self._mutators(), max_requests=200,
                        attack_class="sqli", stop_on_first=True)
        throughs = [f for f in res.findings]
        assert len(throughs) >= 1
        assert res.requests < 200  # stopped early

    def test_respects_budget(self):
        oracle = _FakeOracle()
        res = rl_search(oracle, "test", self._mutators(), max_requests=10)
        assert oracle.calls <= 10

    def test_agent_learns(self):
        oracle = _FakeOracle()
        res = rl_search(oracle, "test", self._mutators(), max_requests=200)
        agent = res._rl_agent
        assert agent.states_seen > 0
        assert agent.steps > 0

    def test_preloaded_agent(self):
        agent = QLearningAgent(["noop", "add_magic", "upper"], epsilon=0.0)
        key = INITIAL_STATE.to_key()
        agent.q_table[key] = {"add_magic": 100.0, "noop": -1.0, "upper": -1.0}

        oracle = _FakeOracle()
        res = rl_search(oracle, "test", self._mutators(), max_requests=5,
                        agent=agent)
        assert len(res.findings) > 0

    def test_policy_saved_on_result(self):
        oracle = _FakeOracle()
        res = rl_search(oracle, "test", self._mutators(), max_requests=20)
        assert hasattr(res, "_rl_agent")
        assert isinstance(res._rl_agent, QLearningAgent)

    def test_on_progress_called(self):
        events = []
        def cb(**kw):
            events.append(kw)

        oracle = _FakeOracle()
        rl_search(oracle, "test", self._mutators(), max_requests=100,
                  on_progress=cb)
        assert len(events) > 0
        assert "depth" in events[0]
        assert "throughs" in events[0]

    def test_empty_mutators(self):
        oracle = _FakeOracle()
        res = rl_search(oracle, "test", [], max_requests=10)
        assert res.requests == 0
        assert res.findings == []

    def test_on_event_on_through(self):
        events = []
        def ev(kind, **kw):
            events.append((kind, kw))

        oracle = _FakeOracle()
        rl_search(oracle, "test", self._mutators(), max_requests=100,
                  on_event=ev)
        found_events = [e for e in events if e[0] == "found"]
        assert len(found_events) > 0


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------

class TestCLI:
    def test_strategy_rl_in_parser(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args(["bypass", "--mock", "--payload", "test",
                             "--strategy", "rl", "--max-requests", "10"])
        assert args.strategy == "rl"

    def test_policy_flags_in_parser(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args(["bypass", "--mock", "--payload", "test",
                             "--strategy", "rl",
                             "--save-policy", "out.json",
                             "--load-policy", "in.json"])
        assert args.save_policy == "out.json"
        assert args.load_policy == "in.json"
