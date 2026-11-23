"""Tests for grammar-guided payload generation."""
import pytest

from waffen.grammar.engine import Grammar
from waffen.grammar.sql import SQL_GRAMMAR
from waffen.grammar.xss import XSS_GRAMMAR
from waffen.grammar.ssti import SSTI_GRAMMAR
from waffen.grammar import GRAMMARS


# ---- engine basics ---------------------------------------------------------

class TestGrammarEngine:
    def test_simple_grammar(self):
        import random
        g = Grammar({"s": [["hello"], ["world"]]}, start="s")
        p = g.generate(rng=random.Random(0))
        assert p in ("hello", "world")

    def test_nested_grammar(self):
        g = Grammar({
            "s": [["a", "b"]],
            "a": [["x"]],
            "b": [["y"]],
        }, start="s")
        assert g.generate() == "xy"

    def test_generate_n_unique(self):
        g = Grammar({"s": [["a"], ["b"], ["c"], ["d"]]}, start="s")
        results = g.generate_n(4, seed=42)
        assert len(results) == len(set(results))

    def test_generate_n_respects_count(self):
        g = Grammar({"s": [["a"], ["b"], ["c"]]}, start="s")
        results = g.generate_n(3, seed=42)
        assert len(results) <= 3

    def test_max_depth_prevents_infinite(self):
        g = Grammar({
            "s": [["a", "s"], ["end"]],
        }, start="s")
        p = g.generate(max_depth=5)
        assert "end" in p
        assert len(p) < 500

    def test_all_terminals(self):
        g = Grammar({
            "s": [["hello", " ", "b"]],
            "b": [["world"]],
        }, start="s")
        terms = g.all_terminals()
        assert "hello" in terms
        assert " " in terms
        assert "world" in terms
        assert "s" not in terms
        assert "b" not in terms

    def test_all_nonterminals(self):
        g = Grammar({
            "s": [["a"]],
            "a": [["x"]],
        }, start="s")
        assert g.all_nonterminals() == {"s", "a"}

    def test_targeted_generation(self):
        g = Grammar({
            "s": [["a", "b"], ["c"]],
            "a": [["GLOB"], ["LIKE"]],
            "b": [["x"]],
        }, start="s")
        results = g.generate_targeted({"GLOB"}, attempts=50, seed=42)
        assert any("GLOB" in r for r in results)

    def test_coverage_generate(self):
        g = Grammar({
            "s": [["a"], ["b"], ["c"], ["d"]],
        }, start="s")
        results = g.coverage_generate(n=10, seed=42)
        result_set = set(results)
        assert "a" in result_set
        assert "b" in result_set
        assert "c" in result_set
        assert "d" in result_set

    def test_deterministic_with_seed(self):
        g = Grammar({"s": [["a"], ["b"], ["c"]]}, start="s")
        r1 = g.generate_n(5, seed=123)
        r2 = g.generate_n(5, seed=123)
        assert r1 == r2


# ---- SQL grammar -----------------------------------------------------------

class TestSQLGrammar:
    def test_generates_strings(self):
        payloads = SQL_GRAMMAR.generate_n(20, seed=42)
        assert len(payloads) >= 10
        for p in payloads:
            assert isinstance(p, str)
            assert len(p) > 0

    def test_contains_sql_keywords(self):
        payloads = SQL_GRAMMAR.generate_n(100, seed=42)
        all_text = " ".join(payloads)
        assert any(kw in all_text for kw in ["OR", "AND", "UNION", "SELECT",
                                              "or", "and", "GLOB", "LIKE"])

    def test_starts_with_quote(self):
        payloads = SQL_GRAMMAR.generate_n(50, seed=42)
        quote_chars = ("'", '"', ")", "-")
        starts_with_quote = sum(1 for p in payloads
                                if p.strip() and p.strip()[0] in quote_chars)
        assert starts_with_quote > len(payloads) * 0.5

    def test_has_union_payloads(self):
        payloads = SQL_GRAMMAR.generate_n(200, seed=42)
        has_union = any("UNION" in p for p in payloads)
        assert has_union

    def test_has_blind_payloads(self):
        payloads = SQL_GRAMMAR.generate_n(200, seed=42)
        has_blind = any("SUBSTR" in p or "SLEEP" in p or "WAITFOR" in p
                        or "pg_sleep" in p or "BENCHMARK" in p
                        for p in payloads)
        assert has_blind

    def test_has_error_payloads(self):
        payloads = SQL_GRAMMAR.generate_n(200, seed=42)
        has_error = any("EXTRACTVALUE" in p or "UPDATEXML" in p
                        or "CAST" in p or "CONVERT" in p
                        for p in payloads)
        assert has_error

    def test_coverage_hits_many_rules(self):
        payloads = SQL_GRAMMAR.coverage_generate(n=200, seed=42)
        all_text = " ".join(payloads)
        expected = ["OR", "UNION", "SELECT", "SLEEP", "--", "NULL",
                    "EXTRACTVALUE", "GLOB"]
        found = sum(1 for kw in expected if kw in all_text)
        assert found >= 5

    def test_targeted_glob(self):
        payloads = SQL_GRAMMAR.generate_targeted({"GLOB"}, attempts=100, seed=42)
        assert len(payloads) > 0
        assert all("GLOB" in p for p in payloads)

    def test_targeted_iif(self):
        payloads = SQL_GRAMMAR.generate_targeted({"IIF"}, attempts=100, seed=42)
        assert len(payloads) > 0
        assert all("IIF" in p for p in payloads)

    def test_no_empty_payloads(self):
        payloads = SQL_GRAMMAR.generate_n(100, seed=42)
        for p in payloads:
            assert len(p.strip()) > 0


# ---- XSS grammar ----------------------------------------------------------

class TestXSSGrammar:
    def test_generates_strings(self):
        payloads = XSS_GRAMMAR.generate_n(20, seed=42)
        assert len(payloads) >= 10

    def test_contains_html_tags(self):
        payloads = XSS_GRAMMAR.generate_n(50, seed=42)
        all_text = " ".join(payloads)
        assert "<" in all_text

    def test_has_event_handlers(self):
        payloads = XSS_GRAMMAR.generate_n(100, seed=42)
        handlers = ["onerror", "onload", "onfocus", "onmouseover", "ontoggle",
                     "onclick", "onanimationend"]
        all_text = " ".join(payloads)
        found = sum(1 for h in handlers if h in all_text)
        assert found >= 3

    def test_has_script_tags(self):
        payloads = XSS_GRAMMAR.generate_n(100, seed=42)
        has_script = any("<script" in p.lower() or "<ScRiPt" in p for p in payloads)
        assert has_script

    def test_has_javascript_uri(self):
        payloads = XSS_GRAMMAR.generate_n(100, seed=42)
        has_js = any("javascript:" in p for p in payloads)
        assert has_js

    def test_has_svg_payloads(self):
        payloads = XSS_GRAMMAR.generate_n(100, seed=42)
        has_svg = any("<svg" in p for p in payloads)
        assert has_svg

    def test_coverage(self):
        payloads = XSS_GRAMMAR.coverage_generate(n=100, seed=42)
        all_text = " ".join(payloads)
        assert "<img" in all_text or "<svg" in all_text
        assert "alert" in all_text


# ---- SSTI grammar ----------------------------------------------------------

class TestSSTIGrammar:
    def test_generates_strings(self):
        payloads = SSTI_GRAMMAR.generate_n(20, seed=42)
        assert len(payloads) >= 10

    def test_has_jinja2(self):
        payloads = SSTI_GRAMMAR.generate_n(100, seed=42)
        has_jinja = any("{{" in p and "}}" in p for p in payloads)
        assert has_jinja

    def test_has_twig(self):
        payloads = SSTI_GRAMMAR.generate_n(200, seed=42)
        has_twig = any("dump()" in p or "_self.env" in p for p in payloads)
        assert has_twig

    def test_has_freemarker(self):
        payloads = SSTI_GRAMMAR.generate_n(200, seed=42)
        has_fm = any("${" in p for p in payloads)
        assert has_fm

    def test_has_erb(self):
        payloads = SSTI_GRAMMAR.generate_n(200, seed=42)
        has_erb = any("<%" in p for p in payloads)
        assert has_erb

    def test_has_commands(self):
        payloads = SSTI_GRAMMAR.generate_n(200, seed=42)
        all_text = " ".join(payloads)
        assert any(cmd in all_text for cmd in ["whoami", "id", "cat /etc/passwd"])

    def test_coverage(self):
        payloads = SSTI_GRAMMAR.coverage_generate(n=100, seed=42)
        all_text = " ".join(payloads)
        assert "{{" in all_text
        assert any(x in all_text for x in ["${", "<%"])


# ---- GRAMMARS registry ----------------------------------------------------

class TestGrammarsRegistry:
    def test_all_types_present(self):
        assert "sqli" in GRAMMARS
        assert "sql" in GRAMMARS
        assert "xss" in GRAMMARS
        assert "ssti" in GRAMMARS

    def test_all_are_grammar_instances(self):
        for name, g in GRAMMARS.items():
            assert isinstance(g, Grammar), f"{name} is not a Grammar"

    def test_all_generate(self):
        for name, g in GRAMMARS.items():
            payloads = g.generate_n(5, seed=42)
            assert len(payloads) >= 1, f"{name} generated nothing"


# ---- CLI integration -------------------------------------------------------

class TestCLIGrammar:
    def test_parser_has_grammar(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args(["grammar", "--type", "sqli", "--generate", "10"])
        assert args.type == "sqli"
        assert args.generate == 10
        assert hasattr(args, "func")

    def test_bypass_has_grammar_flag(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args(["bypass", "--mock", "--grammar", "sqli"])
        assert args.grammar == "sqli"

    def test_gather_seeds_with_grammar(self):
        from waffen.cli import _gather_seeds
        import argparse
        args = argparse.Namespace(
            payload="", attack_class="", all_classes=False,
            corpus=False, grammar="sqli")
        seeds = _gather_seeds(args)
        assert len(seeds) > 0
        assert all(cls == "SQL Injection" for cls, _ in seeds)

    def test_gather_seeds_without_grammar(self):
        from waffen.cli import _gather_seeds
        import argparse
        args = argparse.Namespace(
            payload="' OR 1=1--", attack_class="SQL Injection",
            all_classes=False, corpus=False, grammar="")
        seeds = _gather_seeds(args)
        assert len(seeds) == 1
        assert seeds[0][1] == "' OR 1=1--"
