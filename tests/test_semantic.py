"""Tests for the semantic preservation engine."""
import pytest

from waffen.mutate.semantic import (
    TAUTOLOGIES,
    OR_EQUIVALENTS,
    COMMENT_EQUIVALENTS,
    SemanticEngine,
    string_equivalents,
    number_equivalents,
    column_count_nulls,
    semantic_all,
)
from waffen.mutate.base import REGISTRY


# ---- equivalence tables ---------------------------------------------------

class TestTautologies:
    def test_has_at_least_30(self):
        assert len(TAUTOLOGIES) >= 30

    def test_no_duplicates(self):
        assert len(TAUTOLOGIES) == len(set(TAUTOLOGIES))

    def test_includes_basic(self):
        assert "1=1" in TAUTOLOGIES
        assert "2>1" in TAUTOLOGIES

    def test_includes_sqlite_specific(self):
        assert "'a' GLOB '*'" in TAUTOLOGIES

    def test_includes_function_based(self):
        assert any("IIF" in t for t in TAUTOLOGIES)
        assert any("CASE" in t for t in TAUTOLOGIES)
        assert any("TYPEOF" in t for t in TAUTOLOGIES)

    def test_includes_exists(self):
        assert any("EXISTS" in t for t in TAUTOLOGIES)


class TestStringEquivalents:
    def test_produces_multiple(self):
        equivs = string_equivalents("admin")
        assert len(equivs) >= 4

    def test_includes_original(self):
        equivs = string_equivalents("test")
        assert "'test'" in equivs

    def test_includes_char(self):
        equivs = string_equivalents("ab")
        assert any("CHAR(" in e for e in equivs)

    def test_includes_hex(self):
        equivs = string_equivalents("ab")
        assert any("X'" in e for e in equivs)

    def test_includes_concat(self):
        equivs = string_equivalents("admin")
        assert any("||" in e for e in equivs)

    def test_single_char(self):
        equivs = string_equivalents("a")
        assert len(equivs) >= 3


class TestNumberEquivalents:
    def test_produces_multiple(self):
        equivs = number_equivalents(1)
        assert len(equivs) >= 5

    def test_includes_original(self):
        assert "1" in number_equivalents(1)

    def test_includes_hex(self):
        equivs = number_equivalents(1)
        assert any("0x" in e for e in equivs)

    def test_includes_float(self):
        equivs = number_equivalents(1)
        assert any("1.0" in e for e in equivs)

    def test_zero(self):
        equivs = number_equivalents(0)
        assert "0" in equivs
        assert len(equivs) >= 4


class TestColumnCountNulls:
    def test_basic(self):
        variants = column_count_nulls(3)
        assert len(variants) >= 2
        assert ["NULL", "NULL", "NULL"] in variants

    def test_has_numbered(self):
        variants = column_count_nulls(3)
        assert any("1" in v for v in variants)


# ---- semantic engine ------------------------------------------------------

class TestSemanticEngine:
    def setup_method(self):
        self.engine = SemanticEngine(dbms="generic")

    def test_tautology_injections(self):
        payloads = self.engine.generate_tautology_injections()
        assert len(payloads) > 50
        assert all(isinstance(p, str) for p in payloads)

    def test_tautology_no_duplicates(self):
        payloads = self.engine.generate_tautology_injections()
        assert len(payloads) == len(set(payloads))

    def test_tautology_contains_or(self):
        payloads = self.engine.generate_tautology_injections()
        assert any("OR" in p for p in payloads)

    def test_tautology_contains_glob(self):
        payloads = self.engine.generate_tautology_injections()
        assert any("GLOB" in p for p in payloads)

    def test_union_injections(self):
        payloads = self.engine.generate_union_injections(columns=3)
        assert len(payloads) > 5
        assert any("UNION" in p for p in payloads)

    def test_union_respects_column_count(self):
        payloads = self.engine.generate_union_injections(columns=5)
        assert any(p.count("NULL") >= 4 for p in payloads)

    def test_blind_injections(self):
        payloads = self.engine.generate_blind_injections()
        assert len(payloads) > 5
        assert any("SUBSTR" in p for p in payloads)

    def test_time_injections_generic(self):
        payloads = self.engine.generate_time_injections()
        assert len(payloads) > 3

    def test_time_injections_sqlite(self):
        eng = SemanticEngine(dbms="sqlite")
        payloads = eng.generate_time_injections()
        assert any("randomblob" in p for p in payloads)

    def test_time_injections_mysql(self):
        eng = SemanticEngine(dbms="mysql")
        payloads = eng.generate_time_injections()
        assert any("SLEEP" in p for p in payloads)

    def test_time_injections_mssql(self):
        eng = SemanticEngine(dbms="mssql")
        payloads = eng.generate_time_injections()
        assert any("WAITFOR" in p for p in payloads)


class TestSemanticExpand:
    def setup_method(self):
        self.engine = SemanticEngine()

    def test_expand_basic(self):
        variants = self.engine.semantic_expand("' OR 1=1--")
        assert len(variants) > 5
        assert "' OR 1=1--" in variants

    def test_expand_different_from_input(self):
        variants = self.engine.semantic_expand("' OR 1=1--")
        non_original = [v for v in variants if v != "' OR 1=1--"]
        assert len(non_original) > 3

    def test_expand_no_duplicates(self):
        variants = self.engine.semantic_expand("' OR 1=1--")
        assert len(variants) == len(set(variants))

    def test_expand_tautology_substitution(self):
        variants = self.engine.semantic_expand("' OR 1=1--")
        assert any("2>1" in v for v in variants)

    def test_expand_or_substitution(self):
        variants = self.engine.semantic_expand("' OR 1=1--")
        assert any("||" in v for v in variants)

    def test_expand_comment_substitution(self):
        variants = self.engine.semantic_expand("' OR 1=1--")
        assert any(v.endswith("#") for v in variants)

    def test_expand_max_variants(self):
        engine = SemanticEngine(max_variants=10)
        variants = engine.semantic_expand("' OR 1=1--")
        assert len(variants) <= 10

    def test_expand_non_sqli_passthrough(self):
        variants = self.engine.semantic_expand("hello world")
        assert "hello world" in variants


class TestSemanticReduce:
    def setup_method(self):
        self.engine = SemanticEngine()

    def test_normalise_whitespace(self):
        result = self.engine.semantic_reduce("'  OR   1=1--")
        assert "  " not in result

    def test_normalise_comment(self):
        result = self.engine.semantic_reduce("' OR 1=1-- -")
        assert result.endswith("--")

    def test_normalise_or_case(self):
        result = self.engine.semantic_reduce("' or 1=1--")
        assert "OR" in result


class TestSemanticAll:
    def test_returns_list(self):
        result = semantic_all("' OR 1=1--")
        assert isinstance(result, list)
        assert len(result) > 5

    def test_max_variants(self):
        result = semantic_all("' OR 1=1--", max_variants=10)
        assert len(result) <= 10

    def test_dbms_specific(self):
        result = semantic_all("' OR 1=1--", dbms="sqlite")
        assert isinstance(result, list)


class TestSchemaQueries:
    def test_sqlite(self):
        eng = SemanticEngine(dbms="sqlite")
        q = eng._schema_queries()
        assert any("sqlite_master" in s for s in q)

    def test_mysql(self):
        eng = SemanticEngine(dbms="mysql")
        q = eng._schema_queries()
        assert any("information_schema" in s for s in q)

    def test_postgresql(self):
        eng = SemanticEngine(dbms="postgresql")
        q = eng._schema_queries()
        assert any("pg_tables" in s for s in q)

    def test_mssql(self):
        eng = SemanticEngine(dbms="mssql")
        q = eng._schema_queries()
        assert any("sysobjects" in s for s in q)


# ---- mutator registration ------------------------------------------------

class TestRegistration:
    def test_semantic_tautology_registered(self):
        m = REGISTRY.get("semantic_tautology")
        assert m is not None
        assert m.multi is True

    def test_semantic_expand_registered(self):
        m = REGISTRY.get("semantic_expand")
        assert m is not None
        assert m.multi is True

    def test_semantic_union_registered(self):
        m = REGISTRY.get("semantic_union")
        assert m is not None

    def test_semantic_blind_registered(self):
        m = REGISTRY.get("semantic_blind")
        assert m is not None

    def test_semantic_time_registered(self):
        m = REGISTRY.get("semantic_time")
        assert m is not None

    def test_tautology_multi_output(self):
        m = REGISTRY.get("semantic_tautology")
        variants = m.apply_multi("' OR 1=1--")
        assert len(variants) > 1

    def test_expand_multi_output(self):
        m = REGISTRY.get("semantic_expand")
        variants = m.apply_multi("' OR 1=1--")
        assert len(variants) > 1

    def test_classes_are_sql(self):
        m = REGISTRY.get("semantic_tautology")
        assert m.valid_for("SQL Injection")

    def test_total_mutator_count_increased(self):
        count = len(REGISTRY._m)
        assert count >= 236, f"expected >=236 mutators, got {count}"


# ---- CLI ------------------------------------------------------------------

class TestCLI:
    def test_parser_has_semantic(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args(["semantic", "--payload", "' OR 1=1--", "-n", "10"])
        assert args.payload == "' OR 1=1--"
        assert args.count == 10
        assert hasattr(args, "func")

    def test_parser_modes(self):
        from waffen.cli import build_parser
        p = build_parser()
        for mode in ["tautology", "union", "blind", "time"]:
            args = p.parse_args(["semantic", "--mode", mode])
            assert args.mode == mode

    def test_parser_dbms(self):
        from waffen.cli import build_parser
        p = build_parser()
        for db in ["generic", "sqlite", "mysql", "postgresql", "mssql"]:
            args = p.parse_args(["semantic", "--dbms", db])
            assert args.dbms == db
