"""Obfuscation mutators — keep the payload's wire bytes mostly ASCII but rewrite
its *structure* (case, comments, whitespace, token splitting) so signature rules
miss it while the target parser still accepts it.
"""
from __future__ import annotations

import random

from .base import REGISTRY

_SQL = {"SQL Injection", "NoSQL Injection", "*"}
_XSS = {"XSS Injection", "*"}


def case_toggle(s: str) -> str:
    return "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(s))


def case_random(s: str) -> str:
    rnd = random.Random(1337)
    return "".join(c.upper() if rnd.random() > 0.5 else c.lower() for c in s)


def case_upper(s: str) -> str:
    return s.upper()


def sql_inline_comment(s: str) -> str:
    # insert /**/ between whitespace-separated tokens
    return s.replace(" ", "/**/")


def sql_versioned_comment(s: str) -> str:
    # MySQL version-gated comment wrapping SQL keywords
    for kw in ("UNION", "SELECT", "OR", "AND", "WHERE", "FROM"):
        for variant in (kw, kw.lower()):
            s = s.replace(variant, f"/*!50000{variant}*/")
    return s


def whitespace_tab(s: str) -> str:
    return s.replace(" ", "\t")


def whitespace_newline(s: str) -> str:
    return s.replace(" ", "\n")


def whitespace_comment_paren(s: str) -> str:
    # SQL: spaces are optional around parentheses / comments
    return s.replace(" ", "/**/").replace("=", "/**/=/**/")


def sql_scientific(s: str) -> str:
    # 'OR 1=1' style -> 'OR 1.e(1)=1' tricks for numeric contexts (best effort)
    return s.replace("=", " like ")


def xss_comment_break(s: str) -> str:
    # break tag/attr names with HTML/JS comments and null-ish tokens
    return (s.replace("script", "scr<!---->ipt")
             .replace("alert", "al/**/ert")
             .replace("onerror", "on<>error"))


def xss_event_case(s: str) -> str:
    return (s.replace("onerror", "OnErRoR")
             .replace("onload", "OnLoAd")
             .replace("javascript", "JaVaScRiPt"))


def null_byte(s: str) -> str:
    return s + "%00"


def trailing_junk(s: str) -> str:
    # append a benign-looking parameter tail some WAFs stop parsing before
    return s + "&z=1"


def token_concat_sql(s: str) -> str:
    # CONCAT/char tricks (best effort for quoted strings)
    return s.replace("'", "''")


def _register() -> None:
    R = REGISTRY
    R.add("case_toggle", case_toggle, "obfuscator", "aLtErNaTiNg case")
    R.add("case_random", case_random, "obfuscator", "deterministic random case")
    R.add("case_upper", case_upper, "obfuscator", "UPPERCASE")
    R.add("sql_inline_comment", sql_inline_comment, "obfuscator", "spaces -> /**/", classes=_SQL)
    R.add("sql_versioned_comment", sql_versioned_comment, "obfuscator", "MySQL /*!50000..*/", classes=_SQL)
    R.add("whitespace_comment_paren", whitespace_comment_paren, "obfuscator", "comment-wrap spaces & =", classes=_SQL)
    R.add("sql_scientific", sql_scientific, "obfuscator", "= -> like", classes=_SQL)
    R.add("token_concat_sql", token_concat_sql, "obfuscator", "quote doubling", classes=_SQL)
    R.add("whitespace_tab", whitespace_tab, "obfuscator", "spaces -> tab")
    R.add("whitespace_newline", whitespace_newline, "obfuscator", "spaces -> newline")
    R.add("xss_comment_break", xss_comment_break, "obfuscator", "break XSS keywords with comments", classes=_XSS)
    R.add("xss_event_case", xss_event_case, "obfuscator", "mixed-case XSS event handlers", classes=_XSS)
    R.add("null_byte", null_byte, "obfuscator", "append %00")
    R.add("trailing_junk", trailing_junk, "obfuscator", "append &z=1 tail")


_register()
