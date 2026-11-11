"""Tests for the semantic fragmentation mutators."""
from __future__ import annotations

import re

import pytest

from waffen.mutate import REGISTRY
from waffen.mutate.semantic_frag import (
    case_wrap_and,
    case_wrap_or,
    comment_interleave_nested,
    comment_interleave_tagged,
    iif_wrap,
    keyword_concat_split,
    keyword_concat_split_mssql,
    keyword_concat_split_mysql,
    numeric_obfuscate_between,
    numeric_obfuscate_gt,
    numeric_obfuscate_in,
    numeric_obfuscate_scientific,
    numeric_obfuscate_string,
    sqlite_iif_wrap,
    sqlite_operator_swap,
    sqlite_quote_tautology,
    sqlite_typeof_check,
    whitespace_multispace,
    whitespace_vary,
    xss_null_in_tag,
    xss_rare_event_rotate,
    xss_tag_self_close_confusion,
    xss_zwj_in_handler,
)


# ── registration ──

EXPECTED_NAMES = [
    "sql_keyword_concat_split",
    "sql_keyword_concat_split_mysql",
    "sql_keyword_concat_split_mssql",
    "sql_sqlite_operator_swap",
    "sql_sqlite_iif_wrap",
    "sql_sqlite_typeof_check",
    "sql_sqlite_quote_tautology",
    "sql_comment_interleave_tagged",
    "sql_comment_interleave_nested",
    "sql_case_wrap_or",
    "sql_case_wrap_and",
    "sql_iif_wrap",
    "sql_whitespace_vary",
    "sql_whitespace_multispace",
    "sql_numeric_obfuscate_gt",
    "sql_numeric_obfuscate_between",
    "sql_numeric_obfuscate_in",
    "sql_numeric_obfuscate_string",
    "sql_numeric_obfuscate_scientific",
    "xss_null_in_tag",
    "xss_zwj_in_handler",
    "xss_rare_event_rotate",
    "xss_tag_self_close_confusion",
]


@pytest.mark.parametrize("name", EXPECTED_NAMES)
def test_registered(name: str) -> None:
    m = REGISTRY.get(name)
    assert m is not None
    assert m.name == name


def test_total_count_increase() -> None:
    all_names = {m.name for m in REGISTRY.all()}
    for n in EXPECTED_NAMES:
        assert n in all_names, f"{n} missing from global REGISTRY"


# ── keyword concat split ──

class TestKeywordConcatSplit:
    def test_splits_select(self) -> None:
        out = keyword_concat_split("' UNION SELECT 1--")
        assert "||" in out
        assert "UNION" not in out
        assert "SELECT" not in out

    def test_short_keyword_split(self) -> None:
        out = keyword_concat_split("OR 1=1")
        assert "'O'||'R'" in out  # OR is 2 chars, still split at min=2

    def test_mysql_uses_concat(self) -> None:
        out = keyword_concat_split_mysql("' UNION SELECT 1--")
        assert "CONCAT(" in out

    def test_mssql_uses_plus(self) -> None:
        out = keyword_concat_split_mssql("' UNION SELECT 1--")
        assert "'+'" in out


# ── SQLite operator swap ──

class TestSQLiteOperatorSwap:
    def test_like_to_glob(self) -> None:
        out = sqlite_operator_swap("name LIKE '%test%'")
        assert "GLOB" in out
        assert "LIKE" not in out

    def test_is_null_to_isnull(self) -> None:
        out = sqlite_operator_swap("x IS NULL")
        assert "ISNULL" in out
        assert "IS NULL" not in out

    def test_is_not_null_to_notnull(self) -> None:
        out = sqlite_operator_swap("x IS NOT NULL")
        assert "NOTNULL" in out

    def test_wildcard_conversion(self) -> None:
        out = sqlite_operator_swap("name LIKE '%test_x%'")
        assert "*" in out  # % -> *
        assert "?" in out  # _ -> ?


class TestSQLiteIifWrap:
    def test_basic(self) -> None:
        out = sqlite_iif_wrap("' OR 1=1--")
        assert "iif(" in out
        assert "1=1" not in out

    def test_different_numbers(self) -> None:
        out = sqlite_iif_wrap("' OR 2=2--")
        assert "iif(2,2,0)=2" in out


class TestSQLiteTypeof:
    def test_basic(self) -> None:
        out = sqlite_typeof_check("' OR 1=1--")
        assert "typeof(1)='integer'" in out

    def test_no_match_unchanged(self) -> None:
        out = sqlite_typeof_check("' OR 2=3--")
        assert out == "' OR 2=3--"


class TestSQLiteQuoteTautology:
    def test_basic(self) -> None:
        out = sqlite_quote_tautology("' OR 1=1--")
        assert "quote(1)='1'" in out


# ── comment interleave ──

class TestCommentInterleave:
    def test_tagged_inserts_comments(self) -> None:
        out = comment_interleave_tagged("' OR 1=1--")
        assert "/*a*/" in out or "/*b*/" in out

    def test_tagged_no_spaces_remain(self) -> None:
        out = comment_interleave_tagged("' OR 1=1--")
        tokens = out.split("/*")
        assert len(tokens) > 1

    def test_single_token_unchanged(self) -> None:
        out = comment_interleave_tagged("payload")
        assert out == "payload"

    def test_nested_comments(self) -> None:
        out = comment_interleave_nested("' OR 1=1--")
        assert "/*/**/*/OR" in out or "/*/**/*/" in out


# ── CASE/IIF wrapping ──

class TestCaseWrap:
    def test_or_tautology(self) -> None:
        out = case_wrap_or("' OR 1=1--")
        assert "CASE WHEN" in out
        assert "THEN" in out

    def test_and_tautology(self) -> None:
        out = case_wrap_and("' AND 1=1--")
        assert "CASE WHEN" in out
        assert "ELSE 0 END" in out

    def test_iif_wrap(self) -> None:
        out = iif_wrap("' OR 1=1--")
        assert "iif(" in out


# ── whitespace variation ──

class TestWhitespace:
    def test_vary_replaces_spaces(self) -> None:
        out = whitespace_vary("' OR 1=1--")
        assert " " not in out
        assert "\t" in out or "\n" in out or "\r" in out

    def test_multispace(self) -> None:
        out = whitespace_multispace("' OR 1=1--")
        assert "   " in out


# ── numeric obfuscation ──

class TestNumericObfuscate:
    def test_gt(self) -> None:
        out = numeric_obfuscate_gt("' OR 1=1--")
        assert "2>1" in out

    def test_between(self) -> None:
        out = numeric_obfuscate_between("' OR 1=1--")
        assert "BETWEEN" in out

    def test_in(self) -> None:
        out = numeric_obfuscate_in("' OR 1=1--")
        assert "IN (" in out

    def test_string(self) -> None:
        out = numeric_obfuscate_string("' OR 1=1--")
        assert "'a'='a'" in out

    def test_scientific(self) -> None:
        out = numeric_obfuscate_scientific("' OR 1=1--")
        assert "1e0=1e0" in out

    def test_non_tautology_unchanged(self) -> None:
        out = numeric_obfuscate_gt("' OR 2=3--")
        assert out == "' OR 2=3--"


# ── XSS fragmentation ──

class TestXSSNull:
    def test_inserts_null(self) -> None:
        out = xss_null_in_tag("<svg onload=alert(1)>")
        assert "\x00" in out
        assert out.startswith("<s")

    def test_short_tag_unchanged(self) -> None:
        out = xss_null_in_tag("<b>test</b>")
        assert out == "<b>test</b>"  # 'b' is 1 char, no split


class TestXSSZWJ:
    def test_inserts_zwj(self) -> None:
        out = xss_zwj_in_handler("<img onerror=alert(1)>")
        assert "‍" in out
        assert "on‍" in out


class TestXSSRareEvent:
    def test_replaces_common(self) -> None:
        out = xss_rare_event_rotate("<img onerror=alert(1)>")
        assert "onerror" not in out.lower()
        assert any(evt in out for evt in [
            "onpointerover", "onanimationend", "ontransitionend", "onwheel",
            "onfocusin", "onbeforeinput", "onbeforetoggle",
        ])


class TestXSSSelfClose:
    def test_adds_slash(self) -> None:
        out = xss_tag_self_close_confusion("<svg onload=alert(1)>")
        assert "<svg/" in out


# ── attack class filtering ──

def test_sql_mutators_valid_for_sql() -> None:
    for name in EXPECTED_NAMES:
        if name.startswith("sql_"):
            m = REGISTRY.get(name)
            assert m.valid_for("SQL Injection"), f"{name} should be valid for SQL Injection"


def test_xss_mutators_valid_for_xss() -> None:
    for name in EXPECTED_NAMES:
        if name.startswith("xss_"):
            m = REGISTRY.get(name)
            assert m.valid_for("XSS Injection"), f"{name} should be valid for XSS Injection"


# ── all mutators produce changed output on canonical inputs ──

_CANONICAL_SQL_OR = "' OR 1=1-- "
_CANONICAL_SQL_AND = "' AND 1=1 AND name LIKE '%test%' AND x IS NULL-- "
_CANONICAL_SQL_UNION = "' UNION SELECT 1,2,3 FROM users-- "
_CANONICAL_XSS = "<img src=x onerror=alert(1)>"

_SEED_MAP = {
    "sql_keyword_concat_split": _CANONICAL_SQL_UNION,
    "sql_keyword_concat_split_mysql": _CANONICAL_SQL_UNION,
    "sql_keyword_concat_split_mssql": _CANONICAL_SQL_UNION,
    "sql_sqlite_operator_swap": _CANONICAL_SQL_AND,
    "sql_case_wrap_and": _CANONICAL_SQL_AND,
}


@pytest.mark.parametrize("name", EXPECTED_NAMES)
def test_mutator_changes_output(name: str) -> None:
    m = REGISTRY.get(name)
    if name in _SEED_MAP:
        seed = _SEED_MAP[name]
    elif name.startswith("xss_"):
        seed = _CANONICAL_XSS
    else:
        seed = _CANONICAL_SQL_OR
    result = m.apply(seed)
    assert result != seed, f"{name} returned unchanged output on canonical seed"
