"""A4 — Monte-Carlo Tree Search over a CFG of semantics-preserving rewrites.

The flagship strategy, after AdvSQLi (TIFS'24) / AutoSpear (BH Asia'22) / WAFUzz
(2025): treat bypass discovery as a tree search where each node is a payload
*state* and each edge is a grammar production — here, one of WAFFEN's
semantics-preserving mutators. Classic MCTS loop:

    Selection   — descend from the root by UCB1 until a not-fully-expanded node
    Expansion   — add one child by applying an untried mutator
    Simulation  — random rollout of further mutators to a bounded depth
    Backprop    — propagate the rollout reward up the visited path

Design choices vs the papers:
- Those parse SQL into a token tree and rewrite sub-trees. We instead use the
  mutator set itself as the production rules over the whole payload string — a
  lighter abstraction that generalizes across attack classes (as WAFUzz showed
  CFG+MCTS does beyond SQLi), not just SQL.
- **Geometric rule-weight decay** (weight = decay^uses-in-chain) stops any one
  rule from being applied over and over (runaway chains), exactly as AdvSQLi's
  recursive-rule weighting does.
- Reward is the A1 `gradient_score` squashed to [0,1]; a THROUGH saturates to 1.
  So MCTS runs on **pure binary WAF feedback** — no model score required, which
  is precisely where WAF-A-MoLE degenerates.

Shares beam's State/Finding/SearchResult types.
"""
from __future__ import annotations

import math
import random
from collections import Counter

from ..core.oracle import Oracle, Response
from .bandit import UCB1, reward_from_score
from .beam import Finding, SearchResult, finalize_finding
from .scoring import gradient_score


class _Node:
    __slots__ = ("payload", "chain", "resp", "N", "W", "children", "untried")

    def __init__(self, payload, chain, resp, untried):
        self.payload = payload
        self.chain = chain
        self.resp = resp
        self.N = 0
        self.W = 0.0
        self.children: dict[str, _Node] = {}
        self.untried: list[str] = untried

    @property
    def fully_expanded(self) -> bool:
        return not self.untried

    def ucb_child(self, c: float) -> "_Node":
        logN = math.log(max(self.N, 1))
        best, best_val = None, -1.0
        for ch in self.children.values():
            if ch.N == 0:
                return ch
            val = ch.W / ch.N + c * math.sqrt(logN / ch.N)
            if val > best_val:
                best, best_val = ch, val
        return best


def _weighted_choice(rng, items, weights):
    tot = sum(weights)
    if tot <= 0:
        return rng.choice(items)
    r = rng.random() * tot
    upto = 0.0
    for it, w in zip(items, weights):
        upto += w
        if upto >= r:
            return it
    return items[-1]


def mcts_search(oracle: Oracle, seed: str, mutators, *,
                iterations: int = 200, rollout_depth: int = 3, c: float = 1.4,
                decay: float = 0.5, max_requests: int = 400,
                attack_class: str = "", stop_on_first: bool = False,
                timing_threshold: float | None = None, seed_rng: int = 1337,
                verify_fn=None, on_event=None) -> SearchResult:
    def emit(kind, **kw):
        if on_event:
            on_event(kind, **kw)

    rng = random.Random(seed_rng)
    names = [m.name for m in mutators]
    by_name = {m.name: m for m in mutators}
    result = SearchResult(seed=seed, attack_class=attack_class)

    baseline = oracle.send(seed)
    result.baseline_verdict = baseline.verdict
    emit("baseline", verdict=baseline.verdict, code=baseline.code)
    if baseline.through:
        f = Finding(seed, [], baseline.code, attack_class)
        finalize_finding(f, verify_fn)
        result.findings.append(f)
        result.requests = oracle.requests
        emit("found", chain=[], code=baseline.code, payload=seed, depth=0, verified=f.verified)
        return result

    cache: dict[str, Response] = {seed: baseline}
    found_payloads: set[str] = set()
    real_hit = [False]  # a verified (or, with no verifier, any) THROUGH was found
    prior = UCB1(names)  # global prior to order expansion across the whole tree

    def evaluate(payload, chain):
        """Memoized send + reward; records findings. Returns (resp, reward) or (None,None) on budget."""
        resp = cache.get(payload)
        if resp is None:
            if oracle.requests >= max_requests:
                return None, None
            resp = oracle.send(payload)
            cache[payload] = resp
        sc = gradient_score(resp, baseline, seed_payload=seed,
                            chain_len=len(chain), timing_threshold=timing_threshold)
        r = reward_from_score(sc, 0.0)
        if resp.through and payload not in found_payloads:
            found_payloads.add(payload)
            f = Finding(payload, list(chain), resp.code, attack_class)
            real = finalize_finding(f, verify_fn)
            real_hit[0] = real_hit[0] or real
            result.findings.append(f)
            emit("found", chain=list(chain), code=resp.code, payload=payload, depth=len(chain), verified=f.verified)
        return resp, r

    root = _Node(seed, [], baseline, prior.rank())

    for it in range(iterations):
        if oracle.requests >= max_requests:
            emit("budget_exhausted", requests=oracle.requests)
            break
        # --- Selection ---
        node = root
        while node.fully_expanded and node.children:
            node = node.ucb_child(c)

        # --- Expansion ---
        leaf = node
        if node.untried:
            # order untried by global prior; try until one yields a new payload
            node.untried.sort(key=lambda n: prior.rank().index(n) if n in prior.arms else 1e9)
            child = None
            while node.untried:
                name = node.untried.pop(0)
                m = by_name.get(name)
                if m is None:
                    continue
                try:
                    cp = m.apply(node.payload)
                except Exception:
                    continue
                if not cp or cp == node.payload or name in node.children:
                    continue
                chain = node.chain + [name]
                resp, r = evaluate(cp, chain)
                if resp is None:
                    break
                child = _Node(cp, chain, resp, prior.rank())
                node.children[name] = child
                prior.update(name, r)
                if stop_on_first and real_hit[0]:
                    result.requests = oracle.requests
                    return result
                break
            if child is not None:
                leaf = child

        # --- Simulation (rollout) ---
        best_r = leaf.W / leaf.N if leaf.N else 0.0
        cur_payload, cur_chain = leaf.payload, list(leaf.chain)
        uses = Counter(cur_chain)
        _, r0 = evaluate(cur_payload, cur_chain)
        if r0 is not None:
            best_r = max(best_r, r0)
        for _ in range(rollout_depth):
            if oracle.requests >= max_requests:
                break
            weights = [decay ** uses[n] for n in names]
            name = _weighted_choice(rng, names, weights)
            m = by_name[name]
            try:
                np_ = m.apply(cur_payload)
            except Exception:
                continue
            if not np_ or np_ == cur_payload:
                continue
            cur_payload = np_
            cur_chain.append(name)
            uses[name] += 1
            resp, r = evaluate(cur_payload, cur_chain)
            if resp is None:
                break
            if r is not None:
                best_r = max(best_r, r)
            if stop_on_first and real_hit[0]:
                result.requests = oracle.requests
                return result

        # --- Backpropagation ---
        n = leaf
        # walk back to root via chain prefixes
        path = [root]
        cur = root
        for nm in leaf.chain:
            cur = cur.children.get(nm, cur)
            path.append(cur)
        for nd in path:
            nd.N += 1
            nd.W += best_r
        emit("iter", i=it, requests=oracle.requests, root_children=len(root.children))

    result.requests = oracle.requests
    result.findings.sort(key=lambda f: (len(f.chain), f.payload))
    return result
