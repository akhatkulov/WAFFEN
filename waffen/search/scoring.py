"""Richer fitness scoring for evasion search.

`Oracle.score()` gives a coarse perturbation signal (status drift + size delta,
with THROUGH dominating at 1e9 and DOWN penalized at -1). That's a fine default
for beam search, but a population-based search benefits from two refinements
that don't require touching the oracle:

1. A *chain-length penalty*: among two candidates that perturb the WAF equally,
   prefer the shorter mutation chain — it is more likely to survive WAF updates
   and is cheaper to replay/report.
2. A *status-transition bonus*: a 403 -> 5xx drift (or any 4xx -> 5xx) suggests
   the payload is reaching past the WAF into the origin/parser stack (e.g.
   triggering a backend error), which is a stronger "we're getting somewhere"
   signal than a same-class size wobble.

`composite_score` is intentionally stateless and side-effect free so both the
genetic search and (later) beam search can import it without any coupling.
"""
from __future__ import annotations

from ..core.oracle import DOWN, THROUGH, Response

# tunables
CHAIN_PENALTY_PER_STEP = 0.15
TRANSITION_BONUS = 1.5


def _is_5xx(code: str) -> bool:
    return len(code) == 3 and code[0] == "5"


def _is_4xx(code: str) -> bool:
    return len(code) == 3 and code[0] == "4"


def composite_score(resp: Response, baseline: Response, chain_len: int) -> float:
    """Higher = more promising candidate. THROUGH still dominates everything.

    Mirrors Oracle.score()'s shape (so DOWN/THROUGH short-circuits behave the
    same) but adds a length penalty and a status-transition bonus on top of the
    BLOCKED-vs-BLOCKED perturbation gradient.
    """
    if resp.verdict == DOWN:
        return -1.0
    if resp.verdict == THROUGH:
        # still prefer shorter THROUGH chains among themselves, but never let
        # the penalty bring a success below a BLOCKED candidate's score.
        return 1e9 - CHAIN_PENALTY_PER_STEP * max(chain_len, 0)

    s = 0.0
    if resp.code != baseline.code:
        s += 3.0
    denom = max(baseline.size, 1)
    s += min(abs(resp.size - baseline.size) / denom, 2.0)

    if _is_4xx(baseline.code) and _is_5xx(resp.code):
        s += TRANSITION_BONUS

    s -= CHAIN_PENALTY_PER_STEP * max(chain_len, 0)
    return s


# --------------------------------------------------------------------------- A1
# Composite response-differential + timing gradient.
#
# A real WAF gives only block/allow — a sparse binary signal. To get a dense
# gradient to climb, we squeeze more bits out of each Response (status, size,
# timing, reflection) and lay them on an ORDERED ladder of "how far did this
# payload get?":
#
#   blocked-fast  <  blocked-but-reached-backend (5xx / slow / error echo)
#                 <  reflected-but-neutralized   <  reflected-intact
#                 <  executed / THROUGH (bypass)
#
# This is what turns WAFFEN's binary oracle into something WAF-A-MoLE needs a
# model score for — and it needs no score from the WAF.

# ladder tunables (kept below TRANSITION/size so THROUGH still dominates)
REACHED_BACKEND_BONUS = 2.0     # 5xx or measurably slower than a fast block
REFLECT_NEUTRALIZED_BONUS = 2.5  # attack tokens echoed, but entity/encoded
REFLECT_INTACT_BONUS = 4.0       # attack tokens echoed verbatim (near-hit)
SLOW_FACTOR = 1.6                # resp.time > baseline.time * SLOW_FACTOR => reached backend


def _attack_tokens(payload: str) -> list[str]:
    """Pull signature-ish tokens from a seed payload to test for reflection."""
    import re
    toks = re.findall(r"[A-Za-z/][A-Za-z0-9_/.:]{3,}", payload or "")
    # keep the most attack-salient, dedup, cap
    out, seen = [], set()
    for t in toks:
        tl = t.lower()
        if tl in seen:
            continue
        seen.add(tl)
        out.append(t)
    return out[:6]


def _reflection(body: str, tokens: list[str]) -> str:
    """Return 'intact' | 'neutralized' | 'none' for how tokens appear in body."""
    if not body or not tokens:
        return "none"
    low = body.lower()
    intact = any(t.lower() in low for t in tokens)
    if intact:
        # if the dangerous chars survive un-entity-encoded near a token, call it intact
        if ("<" in body or ">" in body or "'" in body or '"' in body):
            return "intact"
        return "neutralized"
    # tokens present only in entity/encoded form?
    enc = body.replace("&lt;", "<").replace("&gt;", ">").replace("&#", "#")
    if any(t.lower() in enc.lower() for t in tokens):
        return "neutralized"
    return "none"


def gradient_score(resp: Response, baseline: Response, *, seed_payload: str = "",
                   chain_len: int = 0, timing_threshold: float | None = None) -> float:
    """A1 dense fitness. Higher = closer to a bypass. THROUGH dominates; DOWN worst."""
    if resp.verdict == DOWN:
        return -1.0
    if resp.verdict == THROUGH:
        return 1e9 - CHAIN_PENALTY_PER_STEP * max(chain_len, 0)

    s = 0.0
    # (1) status drift / transition
    if resp.code != baseline.code:
        s += 3.0
    if _is_4xx(baseline.code) and _is_5xx(resp.code):
        s += TRANSITION_BONUS

    # (2) reached-backend signal: 5xx, or measurably slower than a fast block
    reached = _is_5xx(resp.code)
    if timing_threshold is not None and resp.time > timing_threshold:
        reached = True
    elif baseline.time > 0 and resp.time > baseline.time * SLOW_FACTOR:
        reached = True
    if reached:
        s += REACHED_BACKEND_BONUS

    # (3) reflection of attack tokens in the response body (near-hit gradient)
    refl = _reflection(resp.body, _attack_tokens(seed_payload))
    if refl == "intact":
        s += REFLECT_INTACT_BONUS
    elif refl == "neutralized":
        s += REFLECT_NEUTRALIZED_BONUS

    # (4) size micro-delta (small weight, breaks ties)
    denom = max(baseline.size, 1)
    s += min(abs(resp.size - baseline.size) / denom, 2.0)

    # (5) prefer shorter chains
    s -= CHAIN_PENALTY_PER_STEP * max(chain_len, 0)
    return s
