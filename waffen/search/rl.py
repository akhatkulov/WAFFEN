"""Reinforcement-learning WAF bypass search — Q-learning agent.

Instead of treating each request independently (beam/genetic), the RL agent
learns from SEQUENCES of actions. It models the WAF as an MDP: state = recent
verdicts + last mutator + depth; action = pick mutator; reward = score delta
toward THROUGH.  After training on one WAF the Q-table is a reusable POLICY
that can be saved, loaded, and transferred to similar WAFs.

Usage as a strategy:
    waffen bypass --target URL --strategy rl --max-requests 1000

Policy transfer:
    waffen bypass --strategy rl --save-policy waf-a.json  # train on WAF-A
    waffen bypass --strategy rl --load-policy waf-a.json  # re-use on WAF-B
"""
from __future__ import annotations

import json
import math
import random
from dataclasses import dataclass, field
from typing import Optional

from ..core.oracle import Oracle, Response, THROUGH, BLOCKED, DOWN
from .beam import Finding, SearchResult, finalize_finding


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class WAFState:
    last_verdicts: tuple[str, ...]  # trailing N verdicts
    last_codes: tuple[str, ...]
    last_mutator: str
    depth: int

    def to_key(self) -> str:
        v = self.last_verdicts[-3:] if self.last_verdicts else ()
        return f"{v}|{self.last_mutator}|{min(self.depth, 6)}"


INITIAL_STATE = WAFState(last_verdicts=(), last_codes=(), last_mutator="", depth=0)


# ---------------------------------------------------------------------------
# Reward
# ---------------------------------------------------------------------------

def compute_reward(resp: Response, prev_best: float) -> float:
    """Sparse reward favouring THROUGH, with a shaping bonus for score
    improvement and a small penalty for blocked / down responses."""
    if resp.verdict == THROUGH:
        return 100.0
    if resp.verdict == DOWN:
        return -5.0
    score = getattr(resp, "score", 0.0) or 0.0
    if score > prev_best:
        return 10.0 * (score - prev_best)
    return -1.0


# ---------------------------------------------------------------------------
# Q-learning agent
# ---------------------------------------------------------------------------

class QLearningAgent:
    """Tabular Q-learning with ε-greedy exploration."""

    def __init__(self, actions: list[str], *, alpha: float = 0.1,
                 gamma: float = 0.95, epsilon: float = 0.3):
        self.actions = list(actions)
        self.alpha = alpha
        self.gamma = gamma
        self.epsilon = epsilon
        self.q_table: dict[str, dict[str, float]] = {}
        self.total_reward: float = 0.0
        self.steps: int = 0

    # -- action selection ----------------------------------------------------

    def choose_action(self, state: WAFState) -> str:
        if random.random() < self.epsilon:
            return random.choice(self.actions)
        key = state.to_key()
        q = self.q_table.get(key)
        if not q:
            return random.choice(self.actions)
        return max(q, key=q.get)

    # -- learning ------------------------------------------------------------

    def update(self, state: WAFState, action: str, reward: float,
               next_state: WAFState):
        key = state.to_key()
        nk = next_state.to_key()
        if key not in self.q_table:
            self.q_table[key] = {}
        if action not in self.q_table[key]:
            self.q_table[key][action] = 0.0

        next_max = 0.0
        nq = self.q_table.get(nk)
        if nq:
            next_max = max(nq.values())

        old = self.q_table[key][action]
        self.q_table[key][action] = old + self.alpha * (
            reward + self.gamma * next_max - old
        )
        self.total_reward += reward
        self.steps += 1

    def decay_epsilon(self, min_epsilon: float = 0.05):
        self.epsilon = max(min_epsilon, self.epsilon * 0.995)

    # -- persistence ---------------------------------------------------------

    def save_policy(self, path: str):
        data = {
            "actions": self.actions,
            "alpha": self.alpha,
            "gamma": self.gamma,
            "epsilon": self.epsilon,
            "q_table": self.q_table,
            "total_reward": self.total_reward,
            "steps": self.steps,
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    @classmethod
    def load_policy(cls, path: str) -> "QLearningAgent":
        with open(path) as f:
            data = json.load(f)
        agent = cls(
            data.get("actions", []),
            alpha=data.get("alpha", 0.1),
            gamma=data.get("gamma", 0.95),
            epsilon=data.get("epsilon", 0.05),
        )
        agent.q_table = data.get("q_table", {})
        agent.total_reward = data.get("total_reward", 0.0)
        agent.steps = data.get("steps", 0)
        return agent

    # -- introspection -------------------------------------------------------

    def top_actions(self, state: WAFState, n: int = 5) -> list[tuple[str, float]]:
        q = self.q_table.get(state.to_key(), {})
        return sorted(q.items(), key=lambda kv: kv[1], reverse=True)[:n]

    @property
    def states_seen(self) -> int:
        return len(self.q_table)


# ---------------------------------------------------------------------------
# RL bypass search
# ---------------------------------------------------------------------------

def rl_search(
    oracle: Oracle,
    seed: str,
    mutators,
    *,
    max_requests: int = 1000,
    attack_class: str = "",
    stop_on_first: bool = False,
    verify_fn=None,
    on_event=None,
    on_progress=None,
    agent: QLearningAgent | None = None,
    concurrency: int = 1,          # unused, kept for interface compat
    **_extra,
) -> SearchResult:
    """Q-learning search over the mutator space."""

    action_names = [m.name for m in mutators]
    if not action_names:
        return SearchResult(seed=seed, attack_class=attack_class)

    if agent is None:
        agent = QLearningAgent(action_names)
    elif not agent.actions:
        agent.actions = action_names

    mutator_map = {m.name: m for m in mutators}
    result = SearchResult(seed=seed, attack_class=attack_class)
    state = INITIAL_STATE
    payload = seed
    best_score: float = 0.0
    best_payload = seed
    requests_used = 0

    for step in range(max_requests):
        # choose
        action = agent.choose_action(state)
        m = mutator_map.get(action)
        if m is None:
            continue

        # mutate
        try:
            if getattr(m, "multi", False):
                variants = m.apply_multi(payload)
                new_payload = variants[0] if variants else payload
            else:
                new_payload = m.apply(payload)
        except Exception:
            new_payload = payload
        if not new_payload or not new_payload.strip():
            new_payload = payload

        # send
        resp = oracle.send(new_payload)
        requests_used += 1
        r = compute_reward(resp, best_score)

        # next state
        next_state = WAFState(
            last_verdicts=state.last_verdicts[-4:] + (resp.verdict,),
            last_codes=state.last_codes[-4:] + (resp.code,),
            last_mutator=action,
            depth=state.depth + 1,
        )

        # learn
        agent.update(state, action, r, next_state)
        agent.decay_epsilon()

        # track score
        score = getattr(resp, "score", 0.0) or 0.0
        if score > best_score:
            best_score = score
            best_payload = new_payload

        # finding?
        if resp.verdict == THROUGH:
            f = Finding(
                payload=new_payload,
                chain=[action],
                code=resp.code,
                attack_class=attack_class,
            )
            is_real = finalize_finding(f, verify_fn)
            result.findings.append(f)
            if is_real and stop_on_first:
                break
            payload = new_payload  # build on success

        state = next_state

        # progress
        if on_progress and step % 50 == 0:
            on_progress(
                depth=state.depth,
                max_depth=max_requests,
                requests=requests_used,
                budget=max_requests,
                throughs=len(result.findings),
                best_score=best_score,
                frontier_size=agent.states_seen,
            )

        if on_event and resp.verdict == THROUGH:
            on_event("found", chain=[action], code=resp.code,
                     payload=new_payload[:50], depth=state.depth,
                     verified=result.findings[-1].verified if result.findings else None)

    result.requests = requests_used

    # attach the agent to the result so the caller can save the policy
    result._rl_agent = agent  # type: ignore[attr-defined]
    return result
