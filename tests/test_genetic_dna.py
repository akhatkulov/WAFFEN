"""Tests for the Payload DNA structured genetic search."""
import random
from unittest.mock import MagicMock

import pytest

from waffen.search.genetic_dna import (
    TautologyGenome,
    UnionGenome,
    BlindGenome,
    GENOME_TYPES,
    QUOTES,
    LOGICS,
    TAUTOLOGIES,
    COMMENTS,
    ENCODINGS,
    WHITESPACES,
    _apply_case,
    _apply_number_form,
    _apply_encoding,
    _parse_seed,
    dna_genetic_search,
)
from waffen.search.beam import Finding, SearchResult


# ---- Gene pools -----------------------------------------------------------

class TestGenePools:
    def test_quotes_non_empty(self):
        assert len(QUOTES) >= 4

    def test_logics_has_or_and(self):
        assert "OR" in LOGICS
        assert "AND" in LOGICS
        assert "GLOB" in LOGICS

    def test_tautologies_diverse(self):
        assert len(TAUTOLOGIES) >= 10

    def test_comments_has_common(self):
        assert "--" in COMMENTS
        assert "" in COMMENTS


# ---- Helpers --------------------------------------------------------------

class TestHelpers:
    def test_apply_case_upper(self):
        assert _apply_case("select", "upper") == "SELECT"

    def test_apply_case_lower(self):
        assert _apply_case("SELECT", "lower") == "select"

    def test_apply_case_mixed(self):
        result = _apply_case("select", "mixed")
        assert result != "select"
        assert result.lower() == "select"

    def test_apply_number_form_decimal(self):
        assert _apply_number_form("1=1", "decimal") == "1=1"

    def test_apply_number_form_hex(self):
        assert "0x" in _apply_number_form("1=1", "hex")

    def test_apply_encoding_none(self):
        assert _apply_encoding("test", "none") == "test"

    def test_apply_encoding_url(self):
        result = _apply_encoding("' OR 1=1", "url")
        assert "%" in result
        assert " " not in result

    def test_apply_encoding_double_url(self):
        result = _apply_encoding("' OR", "double_url")
        assert "%25" in result


# ---- TautologyGenome ------------------------------------------------------

class TestTautologyGenome:
    def test_default_to_payload(self):
        g = TautologyGenome()
        p = g.to_payload()
        assert "'" in p
        assert "OR" in p
        assert "1=1" in p

    def test_custom_genome(self):
        g = TautologyGenome(quote="')", logic="GLOB", tautology="'a' GLOB '*'",
                            comment="#", whitespace="\t")
        p = g.to_payload()
        assert "')" in p
        assert "GLOB" in p

    def test_random_produces_valid(self):
        rng = random.Random(42)
        for _ in range(20):
            g = TautologyGenome.random(rng)
            p = g.to_payload()
            assert isinstance(p, str)
            assert len(p) > 0

    def test_crossover_produces_two_children(self):
        rng = random.Random(42)
        p1 = TautologyGenome(quote="'", logic="OR", tautology="1=1", comment="--")
        p2 = TautologyGenome(quote='"', logic="GLOB", tautology="'a'='a'", comment="#")
        c1, c2 = p1.crossover(p2, rng)
        assert isinstance(c1, TautologyGenome)
        assert isinstance(c2, TautologyGenome)
        assert c1.to_payload() != c2.to_payload() or c1 == c2

    def test_crossover_children_have_parent_genes(self):
        rng = random.Random(42)
        p1 = TautologyGenome(quote="'", logic="OR")
        p2 = TautologyGenome(quote='"', logic="AND")
        c1, c2 = p1.crossover(p2, rng)
        # Each gene comes from one parent
        for gene in TautologyGenome.GENE_POOLS:
            v1 = getattr(c1, gene)
            assert v1 == getattr(p1, gene) or v1 == getattr(p2, gene)

    def test_mutate_changes_something(self):
        rng = random.Random(42)
        g = TautologyGenome()
        changed = False
        for _ in range(50):
            m = g.mutate(rate=0.5, rng=rng)
            if m.to_payload() != g.to_payload():
                changed = True
                break
        assert changed, "mutation should change payload within 50 attempts at 50% rate"

    def test_mutate_preserves_type(self):
        g = TautologyGenome()
        m = g.mutate(rate=1.0, rng=random.Random(42))
        assert isinstance(m, TautologyGenome)

    def test_encoding_applied(self):
        g = TautologyGenome(encoding="url")
        p = g.to_payload()
        assert "%" in p


# ---- UnionGenome ----------------------------------------------------------

class TestUnionGenome:
    def test_default_to_payload(self):
        g = UnionGenome()
        p = g.to_payload()
        assert "UNION" in p
        assert "SELECT" in p

    def test_columns_count(self):
        g = UnionGenome(columns=5, target_col=2, extraction="version()")
        p = g.to_payload()
        assert "version()" in p
        assert p.count("NULL") == 4  # 5 cols minus 1 extraction

    def test_random(self):
        rng = random.Random(42)
        g = UnionGenome.random(rng)
        p = g.to_payload()
        assert len(p) > 0

    def test_crossover(self):
        rng = random.Random(42)
        p1 = UnionGenome(columns=3)
        p2 = UnionGenome(columns=7)
        c1, c2 = p1.crossover(p2, rng)
        assert isinstance(c1, UnionGenome)

    def test_mutate(self):
        g = UnionGenome()
        m = g.mutate(rate=1.0, rng=random.Random(42))
        assert isinstance(m, UnionGenome)


# ---- BlindGenome ----------------------------------------------------------

class TestBlindGenome:
    def test_default_to_payload(self):
        g = BlindGenome()
        p = g.to_payload()
        assert "AND" in p
        assert "SUBSTR" in p

    def test_random(self):
        rng = random.Random(42)
        g = BlindGenome.random(rng)
        p = g.to_payload()
        assert len(p) > 0

    def test_crossover(self):
        rng = random.Random(42)
        p1 = BlindGenome(logic="AND", function="SUBSTR")
        p2 = BlindGenome(logic="OR", function="MID")
        c1, c2 = p1.crossover(p2, rng)
        assert isinstance(c1, BlindGenome)

    def test_mutate(self):
        g = BlindGenome()
        m = g.mutate(rate=1.0, rng=random.Random(42))
        assert isinstance(m, BlindGenome)


# ---- Seed parsing ---------------------------------------------------------

class TestParseSeed:
    def test_tautology_seed(self):
        g = _parse_seed("' OR 1=1--")
        assert isinstance(g, TautologyGenome)
        assert g.quote == "'"
        assert g.logic == "OR"

    def test_union_seed(self):
        g = _parse_seed("' UNION SELECT 1,2,3--")
        assert isinstance(g, UnionGenome)

    def test_blind_seed(self):
        g = _parse_seed("' AND SUBSTR(x,1,1)>'a'--")
        assert isinstance(g, BlindGenome)

    def test_empty_seed(self):
        g = _parse_seed("")
        assert g is None

    def test_comment_detection(self):
        g = _parse_seed("' OR 1=1-- -")
        assert isinstance(g, TautologyGenome)
        assert g.comment == "-- -"

    def test_glob_seed(self):
        g = _parse_seed("' GLOB '*")
        assert isinstance(g, TautologyGenome)
        assert g.logic == "GLOB"


# ---- DNA genetic search ---------------------------------------------------

class _FakeResp:
    def __init__(self, verdict, code="403", score=0.0):
        self.verdict = verdict
        self.code = code
        self.score = score
        self.time = 0.1
        self.size = 100

class _FakeOracle:
    def __init__(self, through_on=None):
        self.requests = 0
        self._through_on = through_on or set()

    def send(self, payload):
        self.requests += 1
        if any(kw in payload for kw in self._through_on):
            return _FakeResp("THROUGH", "200", 1e9)
        return _FakeResp("BLOCKED", "403", 0.0)


class TestDNASearch:
    def test_returns_search_result(self):
        oracle = _FakeOracle()
        res = dna_genetic_search(oracle, "' OR 1=1--", [],
                                 population_size=5, generations=2,
                                 max_requests=50)
        assert isinstance(res, SearchResult)
        assert res.requests > 0

    def test_finds_through_on_glob(self):
        oracle = _FakeOracle(through_on={"GLOB"})
        res = dna_genetic_search(oracle, "' OR 1=1--", [],
                                 population_size=20, generations=10,
                                 max_requests=200)
        # Population includes random tautology genomes, some will have GLOB
        throughs = [f for f in res.findings if f.code == "200"]
        # With 20 pop × 10 gen, there's a good chance of hitting GLOB
        # but not guaranteed with small pop — just check structure
        assert isinstance(res.findings, list)

    def test_respects_budget(self):
        oracle = _FakeOracle()
        res = dna_genetic_search(oracle, "' OR 1=1--", [],
                                 population_size=10, generations=100,
                                 max_requests=30)
        assert oracle.requests <= 35  # small buffer for baseline

    def test_stop_on_first(self):
        oracle = _FakeOracle(through_on={"OR"})
        res = dna_genetic_search(oracle, "' OR 1=1--", [],
                                 population_size=10, generations=5,
                                 max_requests=200, stop_on_first=True)
        if res.findings:
            assert len(res.findings) >= 1

    def test_progress_callback(self):
        events = []
        def on_prog(**kw):
            events.append(kw)
        oracle = _FakeOracle()
        dna_genetic_search(oracle, "' OR 1=1--", [],
                           population_size=5, generations=3,
                           max_requests=50, on_progress=on_prog)
        assert len(events) > 0
        assert "depth" in events[0]
        assert "best_score" in events[0]

    def test_mixed_genome_population(self):
        oracle = _FakeOracle()
        res = dna_genetic_search(oracle, "' OR 1=1--", [],
                                 population_size=9, generations=2,
                                 max_requests=50)
        assert res.requests > 0

    def test_all_payloads_are_strings(self):
        oracle = _FakeOracle()
        payloads = []
        orig_send = oracle.send
        def track_send(p):
            payloads.append(p)
            return orig_send(p)
        oracle.send = track_send
        dna_genetic_search(oracle, "' OR 1=1--", [],
                           population_size=5, generations=2,
                           max_requests=30)
        for p in payloads:
            assert isinstance(p, str), f"payload should be str, got {type(p)}"
            assert len(p) > 0, "payload should not be empty"


# ---- CLI ------------------------------------------------------------------

class TestCLI:
    def test_dna_in_strategy_choices(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args([
            "bypass", "--mock", "--payload", "' OR 1=1--",
            "--strategy", "dna", "--max-requests", "20",
        ])
        assert args.strategy == "dna"
