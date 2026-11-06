"""Feedback-driven beam search over mutation chains.

Given a seed payload that the WAF BLOCKS, explore sequences of mutators to find a
chain whose output goes THROUGH while (best-effort) staying valid for the attack
class. Binary block/through feedback is sparse, so between depths we rank the
still-blocked frontier by the oracle's perturbation `score()` and keep the top-B.

This is the heart of WAFFEN: a bounded, budget-aware search for an evasion *path*,
not a blind payload dump. Found chains feed the knowledge base.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..core.oracle import Oracle, Response


@dataclass
class State:
    payload: str
    chain: list[str]
    resp: Response
    score: float = 0.0


@dataclass
class Finding:
    payload: str
    chain: list[str]
    code: str
    attack_class: str = ""
    verified: bool | None = None       # None = not checked; set by inline verification
    confidence: float | None = None

    def as_dict(self) -> dict:
        return {"attack_class": self.attack_class, "chain": self.chain,
                "http_code": self.code, "payload": self.payload,
                "verified_exploitable": self.verified, "verify_confidence": self.confidence}


def finalize_finding(finding: "Finding", verify_fn) -> bool:
    """Inline-verify a THROUGH finding. Fills verified/confidence on it and returns
    whether it counts as a REAL (exploitable) success. With no verifier, every
    THROUGH is treated as a success (verified stays None)."""
    if verify_fn is None:
        return True
    try:
        v = verify_fn(finding.payload)
        finding.verified = bool(getattr(v, "exploitable", None))
        finding.confidence = getattr(v, "confidence", None)
        return finding.verified
    except Exception:
        finding.verified = None
        return True  # don't let a verifier crash block a reported bypass


@dataclass
class SearchResult:
    seed: str
    attack_class: str
    findings: list[Finding] = field(default_factory=list)
    requests: int = 0
    baseline_verdict: str = ""


def _expand_frontier(frontier, mutators, visited: set[str]):
    """Build the list of (state, mutator, mutated_payload) candidates for the next
    depth, applying mutators and skipping no-ops / already-visited / in-batch dups.
    Does NOT send anything and does NOT mutate `visited` — the caller decides which
    of the returned candidates are actually kept (budget truncation) before
    recording them as visited."""
    seen_batch: set[str] = set()
    pending: list[tuple[State, object, str]] = []
    for st in frontier:
        for m in mutators:
            try:
                mp = m.apply(st.payload)
            except Exception:
                continue
            if not mp or mp == st.payload or mp in visited or mp in seen_batch:
                continue
            seen_batch.add(mp)
            pending.append((st, m, mp))
    return pending


def beam_search(oracle: Oracle, seed: str, mutators, *,
                width: int = 6, depth: int = 4, max_requests: int = 400,
                attack_class: str = "", stop_on_first: bool = False,
                verify_fn=None, on_event=None, concurrency: int = 1) -> SearchResult:
    """Search for evasion chains. `mutators` is a list of Mutator objects.

    `verify_fn(payload)->Verification`, when given, inline-verifies each THROUGH;
    an unverified (semantically dead) bypass is still recorded but does NOT satisfy
    stop_on_first — the search keeps hunting for a genuinely exploitable one.

    `concurrency` (default 1) is opt-in: with 1, every mutation is sent sequentially
    via `oracle.send`, one at a time, in the exact same order as before — behaviour
    and request order are unchanged. With `concurrency > 1`, each depth's whole
    candidate frontier is first expanded (without sending), then evaluated in ONE
    `oracle.send_many(..., concurrency=concurrency)` batch — same budget cap,
    THROUGH/verify/stop_on_first semantics and score-based frontier selection, just
    faster and with non-deterministic request *order* (threads reorder)."""
    def emit(kind: str, **kw):
        if on_event:
            on_event(kind, **kw)

    result = SearchResult(seed=seed, attack_class=attack_class)
    baseline = oracle.send(seed)
    result.baseline_verdict = baseline.verdict
    emit("baseline", verdict=baseline.verdict, code=baseline.code)

    if baseline.through:
        # the raw payload is already a gap — no mutation needed
        f = Finding(seed, [], baseline.code, attack_class)
        finalize_finding(f, verify_fn)
        result.findings.append(f)
        result.requests = oracle.requests
        emit("found", chain=[], code=baseline.code, payload=seed, depth=0, verified=f.verified)
        return result

    frontier = [State(seed, [], baseline, 0.0)]
    visited: set[str] = {seed}

    if concurrency <= 1:
        for d in range(1, depth + 1):
            candidates: list[State] = []
            for st in frontier:
                for m in mutators:
                    if oracle.requests >= max_requests:
                        emit("budget_exhausted", requests=oracle.requests)
                        break
                    try:
                        mp = m.apply(st.payload)
                    except Exception:
                        continue
                    if not mp or mp == st.payload or mp in visited:
                        continue
                    visited.add(mp)
                    resp = oracle.send(mp)
                    sc = oracle.score(resp, baseline)
                    ns = State(mp, st.chain + [m.name], resp, sc)
                    if resp.through:
                        f = Finding(mp, ns.chain, resp.code, attack_class)
                        real = finalize_finding(f, verify_fn)
                        result.findings.append(f)
                        emit("found", chain=ns.chain, code=resp.code, payload=mp, depth=d, verified=f.verified)
                        if stop_on_first and real:
                            result.requests = oracle.requests
                            return result
                    else:
                        candidates.append(ns)
                if oracle.requests >= max_requests:
                    break
            if not candidates:
                emit("frontier_empty", depth=d)
                break
            candidates.sort(key=lambda s: -s.score)
            frontier = candidates[:width]
            emit("depth_done", depth=d, kept=len(frontier),
                 best_score=frontier[0].score if frontier else 0.0,
                 requests=oracle.requests)
            if oracle.requests >= max_requests:
                break

        result.requests = oracle.requests
        return result

    # -- concurrent path: evaluate each depth's frontier in one batched send -----
    for d in range(1, depth + 1):
        pending = _expand_frontier(frontier, mutators, visited)
        if not pending:
            emit("frontier_empty", depth=d)
            break

        remaining = max_requests - oracle.requests
        if remaining <= 0:
            emit("budget_exhausted", requests=oracle.requests)
            break
        truncated = len(pending) > remaining
        if truncated:
            pending = pending[:remaining]
        for (_, _, mp) in pending:
            visited.add(mp)

        payloads = [mp for (_, _, mp) in pending]
        responses = oracle.send_many(payloads, concurrency=concurrency)

        candidates: list[State] = []
        stop = False
        for (st, m, mp), resp in zip(pending, responses):
            sc = oracle.score(resp, baseline)
            ns = State(mp, st.chain + [m.name], resp, sc)
            if resp.through:
                f = Finding(mp, ns.chain, resp.code, attack_class)
                real = finalize_finding(f, verify_fn)
                result.findings.append(f)
                emit("found", chain=ns.chain, code=resp.code, payload=mp, depth=d, verified=f.verified)
                if stop_on_first and real:
                    stop = True
                    break
            else:
                candidates.append(ns)

        if stop:
            result.requests = oracle.requests
            return result

        if truncated:
            emit("budget_exhausted", requests=oracle.requests)
        if not candidates:
            emit("frontier_empty", depth=d)
            break
        candidates.sort(key=lambda s: -s.score)
        frontier = candidates[:width]
        emit("depth_done", depth=d, kept=len(frontier),
             best_score=frontier[0].score if frontier else 0.0,
             requests=oracle.requests)
        if oracle.requests >= max_requests:
            break

    result.requests = oracle.requests
    return result
