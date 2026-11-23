"""Tests for the SQL-AST-aware mutation engine."""
from __future__ import annotations

import pytest

from waffen.mutate.sql_ast import (
    SQLToken,
    STRATEGIES,
    apply_strategy,
    ast_mutate,
    reconstruct,
    strategy_case_mix,
    strategy_comment_split,
    strategy_comment_swap,
    strategy_concat_build,
    strategy_function_wrap,
    strategy_iif_wrap,
    strategy_number_obfuscate,
    strategy_operator_equiv,
    strategy_sqlite_swap,
    strategy_whitespace_swap,
    tokenize,
)


# ---- tokenizer ------------------------------------------------------------

class TestTokenize:
    def test_simple_or(self):
        tokens = tokenize("' OR 1=1--")
        kinds = [t.kind for t in tokens]
        assert "QUOTE" in kinds
        assert "KEYWORD" in kinds
        assert "NUMBER" in kinds
        assert "COMMENT" in kinds

    def test_union_select(self):
        tokens = tokenize("' UNION SELECT 1,2,3--")
        kws = [t.value.upper() for t in tokens if t.kind == "KEYWORD"]
        assert "UNION" in kws
        assert "SELECT" in kws

    def test_quoted_string(self):
        tokens = tokenize("'admin'")
        assert any(t.kind == "STRING" and "admin" in t.value for t in tokens)

    def test_function_call(self):
        tokens = tokenize("CHAR(49)")
        assert any(t.kind == "FUNCTION" and t.value == "CHAR" for t in tokens)

    def test_operators(self):
        tokens = tokenize("1=1")
        ops = [t for t in tokens if t.kind == "OPERATOR"]
        assert len(ops) == 1
        assert ops[0].value == "="

    def test_two_char_operator(self):
        tokens = tokenize("1<>2")
        ops = [t for t in tokens if t.kind == "OPERATOR"]
        assert any(o.value == "<>" for o in ops)

    def test_hex_number(self):
        tokens = tokenize("0x41")
        assert any(t.kind == "NUMBER" and t.value == "0x41" for t in tokens)

    def test_float_number(self):
        tokens = tokenize("1.5")
        assert any(t.kind == "NUMBER" and t.value == "1.5" for t in tokens)

    def test_scientific_number(self):
        tokens = tokenize("1e0")
        assert any(t.kind == "NUMBER" for t in tokens)

    def test_block_comment(self):
        tokens = tokenize("/*comment*/")
        assert any(t.kind == "COMMENT" for t in tokens)

    def test_line_comment_hash(self):
        tokens = tokenize("test #comment")
        assert any(t.kind == "COMMENT" and "#" in t.value for t in tokens)

    def test_whitespace(self):
        tokens = tokenize("  \t ")
        assert all(t.kind == "WHITESPACE" for t in tokens)

    def test_parentheses(self):
        tokens = tokenize("(1)")
        kinds = [t.kind for t in tokens]
        assert "OPEN_PAREN" in kinds
        assert "CLOSE_PAREN" in kinds

    def test_comma(self):
        tokens = tokenize("1,2,3")
        commas = [t for t in tokens if t.kind == "COMMA"]
        assert len(commas) == 2

    def test_identifier(self):
        tokens = tokenize("tablename")
        assert any(t.kind == "IDENTIFIER" for t in tokens)

    def test_sqlite_keywords(self):
        tokens = tokenize("GLOB COLLATE MATCH ISNULL NOTNULL")
        kws = {t.value.upper() for t in tokens if t.kind == "KEYWORD"}
        assert "GLOB" in kws
        assert "ISNULL" in kws
        assert "NOTNULL" in kws

    def test_multi_word_keyword_order_by(self):
        tokens = tokenize("ORDER BY name")
        kws = [t for t in tokens if t.kind == "KEYWORD"]
        assert any("ORDER BY" in t.value.upper() for t in kws)

    def test_complex_payload(self):
        tokens = tokenize("' UNION SELECT username,password FROM users WHERE id=1--")
        kws = {t.value.upper() for t in tokens if t.kind == "KEYWORD"}
        assert "UNION" in kws or "UNION SELECT" in " ".join(t.value.upper() for t in tokens if t.kind == "KEYWORD")
        assert "FROM" in kws
        assert "WHERE" in kws

    def test_roundtrip(self):
        payload = "' OR 1=1--"
        assert reconstruct(tokenize(payload)) == payload

    def test_roundtrip_complex(self):
        payload = "' UNION SELECT 1,2,3 FROM users--"
        assert reconstruct(tokenize(payload)) == payload

    def test_empty(self):
        assert tokenize("") == []

    def test_just_quote(self):
        tokens = tokenize("'")
        assert len(tokens) == 1
        assert tokens[0].kind == "QUOTE"


# ---- individual strategies -------------------------------------------------

class TestStrategySqliteSwap:
    def test_like_to_glob(self):
        tokens = tokenize("' LIKE '%")
        result = strategy_sqlite_swap(tokens)
        out = reconstruct(result)
        assert "GLOB" in out
        assert "LIKE" not in out.upper().replace("GLOB", "")

    def test_preserves_non_keywords(self):
        tokens = tokenize("' OR 1=1--")
        result = strategy_sqlite_swap(tokens)
        out = reconstruct(result)
        assert "OR" in out


class TestStrategyCommentSplit:
    def test_splits_keyword(self):
        tokens = tokenize("' UNION SELECT 1--")
        result = strategy_comment_split(tokens)
        out = reconstruct(result)
        assert "/**/" in out
        # original keywords should be broken
        assert "UNION" not in out or "/**/" in out

    def test_preserves_numbers(self):
        tokens = tokenize("1=1")
        result = strategy_comment_split(tokens)
        out = reconstruct(result)
        assert "1" in out


class TestStrategyCaseMix:
    def test_alternates_case(self):
        tokens = tokenize("' UNION SELECT 1--")
        result = strategy_case_mix(tokens)
        out = reconstruct(result)
        assert out != "' UNION SELECT 1--"
        assert out.upper().replace(" ", "") != out.replace(" ", "")

    def test_single_char_keyword(self):
        # edge case: very short keywords shouldn't crash
        tokens = [SQLToken("A", "KEYWORD")]
        result = strategy_case_mix(tokens)
        assert len(result) == 1


class TestStrategyWhitespaceSwap:
    def test_replaces_spaces(self):
        tokens = tokenize("' OR 1=1--")
        result = strategy_whitespace_swap(tokens, variant=0)
        out = reconstruct(result)
        assert "\t" in out or "\n" in out or " " not in out.strip("'")

    def test_different_variants(self):
        tokens = tokenize("' OR 1--")
        v0 = reconstruct(strategy_whitespace_swap(tokens, variant=0))
        v1 = reconstruct(strategy_whitespace_swap(tokens, variant=1))
        assert v0 != v1


class TestStrategyOperatorEquiv:
    def test_equals_to_like(self):
        tokens = tokenize("1=1")
        result = strategy_operator_equiv(tokens)
        out = reconstruct(result)
        assert "LIKE" in out or "=" not in out or out != "1=1"


class TestStrategyCommentSwap:
    def test_dash_to_hash(self):
        tokens = tokenize("' OR 1=1--")
        result = strategy_comment_swap(tokens)
        out = reconstruct(result)
        assert "#" in out

    def test_hash_to_dash(self):
        tokens = tokenize("' OR 1=1#")
        result = strategy_comment_swap(tokens)
        out = reconstruct(result)
        assert "-- -" in out


class TestStrategyFunctionWrap:
    def test_number_to_char(self):
        tokens = tokenize("1=1")
        result = strategy_function_wrap(tokens)
        out = reconstruct(result)
        assert "CHAR(" in out

    def test_large_number_unchanged(self):
        tokens = tokenize("999")
        result = strategy_function_wrap(tokens)
        out = reconstruct(result)
        # 999 > 127 so _num_to_char leaves it as-is
        assert out == "999"


class TestStrategyConcatBuild:
    def test_string_split(self):
        tokens = tokenize("'admin'")
        result = strategy_concat_build(tokens)
        out = reconstruct(result)
        assert "||" in out

    def test_short_string_unchanged(self):
        tokens = tokenize("'a'")
        result = strategy_concat_build(tokens)
        out = reconstruct(result)
        assert out == "'a'"


class TestStrategyIifWrap:
    def test_comparison_wrapped(self):
        tokens = tokenize("1=1")
        result = strategy_iif_wrap(tokens)
        out = reconstruct(result)
        assert "IIF(" in out

    def test_no_comparison_unchanged(self):
        tokens = tokenize("test")
        result = strategy_iif_wrap(tokens)
        out = reconstruct(result)
        assert "IIF" not in out


class TestStrategyNumberObfuscate:
    def test_one_to_hex(self):
        tokens = tokenize("1=1")
        result = strategy_number_obfuscate(tokens, variant=0)
        out = reconstruct(result)
        assert "0x1" in out

    def test_different_variants(self):
        tokens = tokenize("1")
        v0 = reconstruct(strategy_number_obfuscate(tokens, variant=0))
        v1 = reconstruct(strategy_number_obfuscate(tokens, variant=1))
        assert v0 != v1


# ---- composite AST mutation ------------------------------------------------

class TestAstMutate:
    def test_produces_variants(self):
        variants = ast_mutate("' OR 1=1--")
        assert len(variants) >= 5

    def test_all_different(self):
        variants = ast_mutate("' OR 1=1--")
        assert len(set(variants)) == len(variants)

    def test_no_identity(self):
        payload = "' OR 1=1--"
        variants = ast_mutate(payload)
        assert payload not in variants

    def test_max_combos_respected(self):
        variants = ast_mutate("' OR 1=1--", max_combos=3)
        assert len(variants) <= 25  # single strats + limited combos

    def test_union_select_payload(self):
        variants = ast_mutate("' UNION SELECT 1,2,3--")
        assert len(variants) >= 5
        # at least one should have comment splitting
        assert any("/**/" in v for v in variants)

    def test_specific_strategies(self):
        variants = ast_mutate("' OR 1=1--",
                              strategies=["comment_split", "case_mix"])
        assert len(variants) >= 2

    def test_empty_payload(self):
        variants = ast_mutate("")
        assert variants == []

    def test_no_sql_tokens(self):
        variants = ast_mutate("hello world")
        # should still produce some variants (whitespace swap, etc.)
        assert isinstance(variants, list)


# ---- registry integration --------------------------------------------------

class TestRegistration:
    def test_all_strategies_registered(self):
        from waffen.mutate.base import REGISTRY
        for name in STRATEGIES:
            m = REGISTRY.get(f"ast_{name}")
            assert m is not None, f"ast_{name} not registered"

    def test_combined_registered(self):
        from waffen.mutate.base import REGISTRY
        m = REGISTRY.get("ast_combined")
        assert m is not None
        assert m.multi is True

    def test_combined_multi_output(self):
        from waffen.mutate.base import REGISTRY
        m = REGISTRY.get("ast_combined")
        variants = m.apply_multi("' OR 1=1--")
        assert len(variants) >= 5
        assert all(isinstance(v, str) for v in variants)

    def test_single_strategy_mutator(self):
        from waffen.mutate.base import REGISTRY
        m = REGISTRY.get("ast_comment_split")
        result = m.apply("' UNION SELECT 1--")
        assert "/**/" in result

    def test_classes_are_sql(self):
        from waffen.mutate.base import REGISTRY
        m = REGISTRY.get("ast_combined")
        assert m.valid_for("SQL Injection")
        assert m.valid_for("NoSQL Injection")

    def test_mutator_count_increased(self):
        from waffen.mutate.base import REGISTRY
        ast_mutators = [n for n in REGISTRY._m if n.startswith("ast_")]
        # 10 strategies + 1 combined = 11
        assert len(ast_mutators) == 11
