"""A5 — best-first (priority-queue) search with bandit-guided expansion.

Where beam keeps a fixed-width frontier and genetic breeds a population, this is
a WAF-A-MoLE-style best-first frontier: a priority queue ordered by the A1
gradient fitness, always expanding the single most-promising state next. Operator
choice at each expansion is guided by a UCB1 bandit (A3) that learns which
mutators pay off against *this* target, and a BlockedMemory prunes dead-ends and
exact duplicates. Memoization means no payload is ever sent twice.

Shares beam's State/Finding/SearchResult so the CLI/report layer is agnostic.
Runs on pure binary WAF feedback — no WAF score required.
"""
from __future__ import annotations

import heapq
import itertools

from ..core.oracle import Oracle, Response
from .bandit import UCB1, BlockedMemory, reward_from_score
from .beam import Finding, SearchResult, State, finalize_finding
from .scoring import gradient_score


def best_first_search(oracle: Oracle, seed: str, mutators, *,
                      branch: int = 4, max_requests: int = 400,
                      attack_class: str = "", stop_on_first: bool = False,
                      timing_threshold: float | None = None, verify_fn=None,
                      on_event=None) -> SearchResult:
    """Best-first evasion search. `branch` = mutators tried per expansion (by UCB)."""
    def emit(kind, **kw):
        if on_event:
            on_event(kind, **kw)

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

    by_name = {m.name: m for m in mutators}
    bandit = UCB1([m.name for m in mutators])
    mem = BlockedMemory()
    mem.add_seen(seed)
    cache: dict[str, Response] = {seed: baseline}

    counter = itertools.count()  # tie-breaker for the heap (stable, avoids State compare)
    # min-heap on negative score => best (highest score) pops first
    start = State(seed, [], baseline, 0.0)
    heap = [(-0.0, next(counter), start)]

    while heap and oracle.requests < max_requests:
        neg, _, st = heapq.heappop(heap)
        parent_score = -neg
        for name in bandit.select(branch):
            if oracle.requests >= max_requests:
                break
            m = by_name.get(name)
            if m is None:
                continue
            try:
                mp = m.apply(st.payload)
            except Exception:
                continue
            if not mp or mp == st.payload or mem.is_dup(mp) or mem.looks_dead(mp):
                continue
            mem.add_seen(mp)
            resp = cache.get(mp)
            if resp is None:
                resp = oracle.send(mp)
                cache[mp] = resp
            chain = st.chain + [name]
            sc = gradient_score(resp, baseline, seed_payload=seed,
                                chain_len=len(chain), timing_threshold=timing_threshold)
            bandit.update(name, reward_from_score(sc, parent_score))
            if resp.through:
                f = Finding(mp, chain, resp.code, attack_class)
                real = finalize_finding(f, verify_fn)
                result.findings.append(f)
                emit("found", chain=chain, code=resp.code, payload=mp, depth=len(chain), verified=f.verified)
                if stop_on_first and real:
                    result.requests = oracle.requests
                    return result
                # A passed-but-unconfirmed bypass is still a live frontier: mutating it
                # further may reach an exploitable variant that stays past the WAF. Keep
                # it in the search instead of dropping it (otherwise the frontier can
                # empty out and the search halts on a dead bypass).
                heapq.heappush(heap, (-sc, next(counter), State(mp, chain, resp, sc)))
                continue
            if resp.verdict == "BLOCKED":
                mem.mark_blocked(mp)
            heapq.heappush(heap, (-sc, next(counter), State(mp, chain, resp, sc)))
        emit("expanded", frontier=len(heap), requests=oracle.requests,
             bandit=bandit.stats())

    result.requests = oracle.requests
    result.findings.sort(key=lambda f: (len(f.chain), f.payload))
    return result
