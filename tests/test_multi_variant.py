"""Tests for multi-variant mutator support."""
from waffen.mutate.base import Mutator, Registry


class TestMutatorApplyMulti:
    def test_default_returns_single(self):
        m = Mutator("id", fn=lambda s: s.upper(), category="encoder")
        assert m.apply_multi("hello") == ["HELLO"]

    def test_multi_false_uses_apply(self):
        m = Mutator("x", fn=lambda s: s + "!", category="encoder", multi=False)
        assert m.apply_multi("a") == ["a!"]

    def test_multi_true_uses_multi_fn(self):
        m = Mutator("x", fn=lambda s: s, category="encoder",
                    multi=True, _multi_fn=lambda s: [s + "1", s + "2", s + "3"])
        result = m.apply_multi("a")
        assert result == ["a1", "a2", "a3"]

    def test_multi_fn_capped_at_max(self):
        m = Mutator("x", fn=lambda s: s, category="encoder",
                    multi=True, _multi_fn=lambda s: [s + str(i) for i in range(20)])
        result = m.apply_multi("a", max_variants=5)
        assert len(result) == 5

    def test_multi_fn_none_fallback(self):
        m = Mutator("x", fn=lambda s: s.upper(), category="encoder", multi=True)
        assert m.apply_multi("hello") == ["HELLO"]

    def test_apply_still_works(self):
        m = Mutator("x", fn=lambda s: s + "!", category="encoder",
                    multi=True, _multi_fn=lambda s: [s + "1", s + "2"])
        assert m.apply("a") == "a!"


class TestRegistryMulti:
    def test_add_multi(self):
        r = Registry()
        r.add("test", fn=lambda s: s, category="encoder",
              multi=True, multi_fn=lambda s: [s + "a", s + "b"])
        m = r.get("test")
        assert m.multi is True
        assert m.apply_multi("x") == ["xa", "xb"]

    def test_add_non_multi_default(self):
        r = Registry()
        r.add("test", fn=lambda s: s.upper(), category="encoder")
        m = r.get("test")
        assert m.multi is False
        assert m.apply_multi("hi") == ["HI"]


class TestSemanticFragMultiVariant:
    def test_keyword_concat_split_multi(self):
        from waffen.mutate.semantic_frag import keyword_concat_split_all
        result = keyword_concat_split_all("' UNION SELECT 1--")
        assert len(result) >= 2
        assert any("||" in v for v in result)
        assert any("CONCAT" in v or "+" in v for v in result)

    def test_whitespace_vary_all(self):
        from waffen.mutate.semantic_frag import whitespace_vary_all
        result = whitespace_vary_all("' OR 1=1--")
        assert len(result) >= 4
        assert any("\t" in v for v in result)
        assert any("\n" in v for v in result)

    def test_numeric_obfuscate_all(self):
        from waffen.mutate.semantic_frag import numeric_obfuscate_all
        result = numeric_obfuscate_all("' OR 1=1--")
        assert len(result) >= 3
        assert any(">" in v for v in result)
        assert any("BETWEEN" in v for v in result)

    def test_sqlite_tautology_all(self):
        from waffen.mutate.semantic_frag import sqlite_tautology_all
        result = sqlite_tautology_all("' OR 1=1--")
        assert len(result) >= 2
        assert any("iif" in v for v in result)
        assert any("typeof" in v for v in result)

    def test_xss_event_all(self):
        from waffen.mutate.semantic_frag import xss_event_all
        result = xss_event_all("<img src=x onerror=alert(1)>")
        assert len(result) >= 3
        assert any("onpointerover" in v for v in result)

    def test_no_change_returns_empty(self):
        from waffen.mutate.semantic_frag import keyword_concat_split_all
        result = keyword_concat_split_all("hello world")
        assert result == []

    def test_whitespace_no_spaces_empty(self):
        from waffen.mutate.semantic_frag import whitespace_vary_all
        result = whitespace_vary_all("nospaces")
        assert result == []


class TestRegisteredMultiMutators:
    def test_multi_mutators_registered(self):
        from waffen.mutate import REGISTRY
        multi_names = [m.name for m in REGISTRY.all() if m.multi]
        assert "sql_keyword_concat_split" in multi_names
        assert "sql_whitespace_vary" in multi_names
        assert "sql_numeric_obfuscate_gt" in multi_names
        assert "sql_sqlite_iif_wrap" in multi_names
        assert "xss_rare_event_rotate" in multi_names

    def test_multi_count(self):
        from waffen.mutate import REGISTRY
        multi = [m for m in REGISTRY.all() if m.multi]
        assert len(multi) >= 5

    def test_multi_mutators_produce_variants(self):
        from waffen.mutate import REGISTRY
        payload = "' OR 1=1--"
        for m in REGISTRY.all():
            if m.multi:
                variants = m.apply_multi(payload)
                assert isinstance(variants, list), f"{m.name} should return list"


class TestBeamWithMultiVariant:
    def test_expand_frontier_multi(self):
        from waffen.search.beam import _expand_frontier, State, Response

        class FakeResp:
            through = False
            verdict = "BLOCKED"
            code = "403"

        states = [State("' OR 1=1--", [], FakeResp(), 0.0)]
        multi_m = Mutator("multi_test", fn=lambda s: s + "A", category="encoder",
                          multi=True, _multi_fn=lambda s: [s + "X", s + "Y", s + "Z"])
        single_m = Mutator("single_test", fn=lambda s: s + "!", category="encoder")

        pending = _expand_frontier(states, [multi_m, single_m], set())
        payloads = [p for (_, _, p) in pending]

        assert "' OR 1=1--X" in payloads
        assert "' OR 1=1--Y" in payloads
        assert "' OR 1=1--Z" in payloads
        assert "' OR 1=1--!" in payloads
        assert len(payloads) == 4
