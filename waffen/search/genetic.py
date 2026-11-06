"""Evolutionary search over mutation chains.

`beam.py` explores the mutation-chain space breadth-first: it keeps the top-B
partial chains at each depth and only ever extends them by one more mutator.
That's cheap and well-behaved, but it's a greedy hill-climb — if the best
single-step move at depth 1 doesn't lead anywhere, beam search can get stuck
re-exploring minor variants of the same local optimum, and it can only ever
produce chains that improve *monotonically* step by step.

This module adds a genetic/evolutionary alternative. A "genome" here is just an
ordered list of mutator *names* (a chain, exactly like beam's `State.chain`).
Instead of growing chains one step at a time from a fixed frontier, we keep a
*population* of whole chains, score them with `scoring.composite_score`, and
breed the next generation via crossover (splicing two parent chains) and
mutation (insert/delete/swap a mutator name). This lets the search jump past
the local optima that pure hill-climbing gets trapped in, at the cost of a
less predictable (but budget-capped) number of requests.

Both searches share `beam.py`'s `State` / `Finding` / `SearchResult` types and
report back through the same `on_event` callback shape, so callers (CLI,
reporting) can swap one for the other without caring which algorithm ran.
"""
from __future__ import annotations

import random

from ..core.oracle import Oracle, Response
from .beam import Finding, SearchResult, State, finalize_finding
from .scoring import composite_score

Genome = tuple[str, ...]


def _decode(genome: Genome, seed: str, by_name: dict[str, object]) -> str:
    """Apply a chain of named mutators to `seed`, in order.

    Unknown mutator names, mutators that raise, and no-op steps are silently
    skipped (same tolerant behaviour as beam_search) so a genome with a "dead"
    gene still decodes to *something* useful instead of failing outright.
    """
    payload = seed
    for name in genome:
        m = by_name.get(name)
        if m is None:
            continue
        try:
            mp = m.apply(payload)
        except Exception:
            continue
        if not mp:
            continue
        payload = mp
    return payload


def _random_genome(rng: random.Random, names: list[str], min_len=1, max_len=4) -> Genome:
    n = rng.randint(min_len, max_len)
    return tuple(rng.choice(names) for _ in range(n))


def _crossover(rng: random.Random, a: Genome, b: Genome) -> Genome:
    """Splice two parent chains at random cut points."""
    if not a or not b:
        return a or b
    ca = rng.randint(0, len(a))
    cb = rng.randint(0, len(b))
    child = a[:ca] + b[cb:]
    if not child:
        child = a or b
    return child[:8]  # keep chains from growing unbounded


def _mutate_genome(rng: random.Random, g: Genome, names: list[str]) -> Genome:
    """Insert, delete, or swap a single gene."""
    g = list(g)
    if not g:
        return (rng.choice(names),)
    op = rng.choice(("insert", "delete", "swap") if len(g) > 1 else ("insert", "swap"))
    if op == "insert" and len(g) < 8:
        g.insert(rng.randint(0, len(g)), rng.choice(names))
    elif op == "delete" and len(g) > 1:
        del g[rng.randint(0, len(g) - 1)]
    else:  # swap
        g[rng.randint(0, len(g) - 1)] = rng.choice(names)
    return tuple(g)


class _Memo:
    """Shared payload -> Response cache so identical decoded payloads are
    never sent to the oracle twice across the whole run."""

    def __init__(self, oracle: Oracle):
        self._oracle = oracle
        self._cache: dict[str, Response] = {}

    def __len__(self) -> int:
        return len(self._cache)

    def get(self, payload: str, max_requests: int) -> Response | None:
        """Return a cached Response, or send+cache it if under budget.

        Returns None if the payload is new but the budget is exhausted.
        """
        cached = self._cache.get(payload)
        if cached is not None:
            return cached
        if self._oracle.requests >= max_requests:
            return None
        resp = self._oracle.send(payload)
        self._cache[payload] = resp
        return resp


def genetic_search(oracle: Oracle, seed: str, mutators, *,
                    pop_size: int = 20, generations: int = 8,
                    max_requests: int = 400, attack_class: str = "",
                    elitism: int = 4, mutation_rate: float = 0.6,
                    stop_on_first: bool = False, verify_fn=None, on_event=None,
                    seed_rng: int = 1337) -> SearchResult:
    """Evolve mutator-name chains against `oracle` to find evasion chains.

    `mutators` is a list of Mutator objects (same contract as beam_search).
    Returns a SearchResult identical in shape to beam_search's, with
    `findings` sorted best-first (THROUGH first, shortest chain first).
    """
    def emit(kind: str, **kw):
        if on_event:
            on_event(kind, **kw)

    rng = random.Random(seed_rng)
    result = SearchResult(seed=seed, attack_class=attack_class)

    by_name = {m.name: m for m in mutators}
    names = list(by_name.keys())

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

    if not names:
        result.requests = oracle.requests
        return result

    memo = _Memo(oracle)
    memo._cache[seed] = baseline
    found_payloads: set[str] = set()
    real_hit = [False]  # a verified (or, with no verifier, any) THROUGH was found

    def evaluate(genome: Genome) -> tuple[float, str, Response | None]:
        payload = _decode(genome, seed, by_name)
        resp = memo.get(payload, max_requests)
        if resp is None:
            # budget exhausted; treat as worst-case so it sorts last
            return -1e6, payload, None
        sc = composite_score(resp, baseline, len(genome))
        if resp.through and payload not in found_payloads:
            found_payloads.add(payload)
            f = Finding(payload, list(genome), resp.code, attack_class)
            real = finalize_finding(f, verify_fn)
            real_hit[0] = real_hit[0] or real
            result.findings.append(f)
            emit("found", chain=list(genome), code=resp.code, payload=payload,
                 depth=len(genome), verified=f.verified)
        return sc, payload, resp

    def budget_left() -> bool:
        return oracle.requests < max_requests

    # -- initial population --------------------------------------------------
    population: list[Genome] = [
        _random_genome(rng, names) for _ in range(max(pop_size, 1))
    ]

    scored: list[tuple[float, Genome]] = []
    for g in population:
        sc, _, _ = evaluate(g)
        scored.append((sc, g))
        if stop_on_first and real_hit[0]:
            result.requests = oracle.requests
            result.findings.sort(key=_finding_sort_key)
            return result
        if not budget_left():
            break

    for gen in range(1, generations + 1):
        if not budget_left():
            emit("budget_exhausted", requests=oracle.requests)
            break

        scored.sort(key=lambda t: -t[0])
        elites = [g for _, g in scored[:max(elitism, 0)]]
        best_score = scored[0][0] if scored else 0.0
        emit("generation", gen=gen, pop=len(scored), best_score=best_score,
             requests=oracle.requests, findings=len(result.findings))

        if not elites:
            break

        # -- breed next generation -------------------------------------------
        parents_pool = [g for _, g in scored[:max(pop_size // 2, 2)]] or elites
        children: list[Genome] = list(elites)
        attempts = 0
        max_attempts = pop_size * 4
        while len(children) < pop_size and attempts < max_attempts:
            attempts += 1
            pa = rng.choice(parents_pool)
            pb = rng.choice(parents_pool)
            child = _crossover(rng, pa, pb)
            if rng.random() < mutation_rate:
                child = _mutate_genome(rng, child, names)
            if not child:
                continue
            children.append(child)

        new_scored: list[tuple[float, Genome]] = []
        for g in children:
            if not budget_left():
                break
            sc, _, _ = evaluate(g)
            new_scored.append((sc, g))
            if stop_on_first and real_hit[0]:
                result.requests = oracle.requests
                result.findings.sort(key=_finding_sort_key)
                return result
        scored = new_scored or scored

    result.requests = oracle.requests
    result.findings.sort(key=_finding_sort_key)
    return result


def _finding_sort_key(f: Finding):
    """Best-first: all recorded findings are THROUGH, so prefer the shortest
    chain (cheaper/more robust evasion), tie-broken deterministically."""
    return (len(f.chain), f.payload)
