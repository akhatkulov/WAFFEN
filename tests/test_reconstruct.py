"""Tests for the feedback-aware payload reconstruction module."""
from dataclasses import dataclass, field
from typing import List

import pytest

from waffen.recon.reconstruct import (
    Template,
    PayloadReconstructor,
    from_score_probe,
    from_libinjection_gaps,
    from_both,
    expand_all,
)


# ---- mock data structures matching score_probe / libinjection_gaps --------

@dataclass
class MockKeywordResult:
    token: str
    single_blocked: bool
    in_quote_blocked: bool

    @property
    def detected(self) -> bool:
        return self.single_blocked or self.in_quote_blocked


@dataclass
class MockBoundaryPayload:
    payload: str
    verdict: str
    note: str


@dataclass
class MockScoreProbeResult:
    target_url: str = "https://test.com"
    attack_class: str = "sqli"
    keyword_map: list = field(default_factory=list)
    strip_chain: list = field(default_factory=list)
    boundary_payloads: list = field(default_factory=list)
    flip_index: int = -1
    requests_used: int = 0


@dataclass
class MockToken:
    name: str
    kind: str = "operator"
    engine: str = "sqlite"


@dataclass
class MockTokenProbe:
    token: MockToken
    template: str = "op_wildcard"
    payload: str = ""
    code: str = "200"
    verdict: str = "THROUGH"


@dataclass
class MockGapReport:
    engine: str
    total: int = 30
    blocked: int = 25
    through: int = 5
    down: int = 0
    gaps: list = field(default_factory=list)
    seeds: list = field(default_factory=list)


# ---- Template dataclass ---------------------------------------------------

class TestTemplate:
    def test_expand_no_params(self):
        t = Template(pattern="' GLOB '*", engine="sqlite", attack_class="SQL Injection")
        assert t.expand() == ["' GLOB '*"]

    def test_expand_single_param(self):
        t = Template(
            pattern="pg_sleep({sec})",
            engine="postgresql", attack_class="SQL Injection",
            params={"sec": ["3", "5"]},
        )
        expanded = t.expand()
        assert "pg_sleep(3)" in expanded
        assert "pg_sleep(5)" in expanded
        assert len(expanded) == 2

    def test_expand_multi_param(self):
        t = Template(
            pattern="SELECT {col} FROM {table}",
            engine="generic", attack_class="SQL Injection",
            params={"col": ["email", "name"], "table": ["Users", "admins"]},
        )
        expanded = t.expand()
        assert len(expanded) == 4
        assert "SELECT email FROM Users" in expanded
        assert "SELECT name FROM admins" in expanded

    def test_expand_char_param(self):
        t = Template(
            pattern="' GLOB '{char}*' GLOB '",
            engine="sqlite", attack_class="SQL Injection",
            params={"char": list("abc")},
        )
        expanded = t.expand()
        assert len(expanded) == 3
        assert "' GLOB 'a*' GLOB '" in expanded


# ---- from_score_probe ------------------------------------------------------

class TestFromScoreProbe:
    def test_boundary_payloads_become_templates(self):
        result = MockScoreProbeResult(
            boundary_payloads=[
                MockBoundaryPayload("' OR 1", "THROUGH", "strip: OR 1"),
                MockBoundaryPayload("'--", "THROUGH", "strip: comment only"),
            ],
            keyword_map=[],
        )
        templates = from_score_probe(result)
        patterns = [t.pattern for t in templates]
        assert "' OR 1" in patterns
        assert "'--" in patterns

    def test_invisible_glob_generates_sqlite_templates(self):
        result = MockScoreProbeResult(
            keyword_map=[
                MockKeywordResult("SELECT", True, True),
                MockKeywordResult("GLOB", False, False),
                MockKeywordResult("COLLATE", False, False),
            ],
            boundary_payloads=[],
        )
        templates = from_score_probe(result)
        patterns = [t.pattern for t in templates]
        assert any("GLOB" in p for p in patterns)
        assert any("COLLATE" in p for p in patterns)

    def test_invisible_isnull(self):
        result = MockScoreProbeResult(
            keyword_map=[
                MockKeywordResult("ISNULL", False, False),
            ],
            boundary_payloads=[],
        )
        templates = from_score_probe(result)
        assert any("ISNULL" in t.pattern for t in templates)

    def test_xss_class(self):
        result = MockScoreProbeResult(
            attack_class="xss",
            keyword_map=[
                MockKeywordResult("<svg", False, False),
                MockKeywordResult("onload", False, False),
                MockKeywordResult("alert(", False, False),
            ],
            boundary_payloads=[],
        )
        templates = from_score_probe(result)
        assert any("XSS" in t.attack_class for t in templates)
        assert any("svg" in t.pattern for t in templates)

    def test_ssti_class(self):
        result = MockScoreProbeResult(
            attack_class="ssti",
            keyword_map=[
                MockKeywordResult("{{", False, False),
            ],
            boundary_payloads=[],
        )
        templates = from_score_probe(result)
        assert any("{{7*7}}" in t.pattern for t in templates)

    def test_empty_result(self):
        result = MockScoreProbeResult(keyword_map=[], boundary_payloads=[])
        templates = from_score_probe(result)
        assert templates == []


# ---- from_libinjection_gaps ------------------------------------------------

class TestFromLibinjectionGaps:
    def test_sqlite_glob_gap(self):
        report = MockGapReport(
            engine="sqlite",
            gaps=[MockTokenProbe(token=MockToken("GLOB", "operator", "sqlite"))],
        )
        templates = from_libinjection_gaps([report])
        patterns = [t.pattern for t in templates]
        assert any("GLOB" in p for p in patterns)
        assert all(t.engine == "sqlite" for t in templates)

    def test_postgresql_ilike_gap(self):
        report = MockGapReport(
            engine="postgresql",
            gaps=[MockTokenProbe(token=MockToken("ILIKE", "operator", "postgresql"))],
        )
        templates = from_libinjection_gaps([report])
        assert any("ILIKE" in t.pattern for t in templates)

    def test_mysql_rlike_gap(self):
        report = MockGapReport(
            engine="mysql",
            gaps=[MockTokenProbe(token=MockToken("RLIKE", "operator", "mysql"))],
        )
        templates = from_libinjection_gaps([report])
        assert any("RLIKE" in t.pattern for t in templates)

    def test_mssql_waitfor_gap(self):
        report = MockGapReport(
            engine="mssql",
            gaps=[MockTokenProbe(token=MockToken("WAITFOR", "keyword", "mssql"))],
        )
        templates = from_libinjection_gaps([report])
        assert any("WAITFOR" in t.pattern for t in templates)

    def test_no_gaps_no_templates(self):
        report = MockGapReport(engine="sqlite", gaps=[])
        templates = from_libinjection_gaps([report])
        assert templates == []

    def test_multiple_engines(self):
        reports = [
            MockGapReport(
                engine="sqlite",
                gaps=[MockTokenProbe(token=MockToken("GLOB", "operator", "sqlite"))],
            ),
            MockGapReport(
                engine="mysql",
                gaps=[MockTokenProbe(token=MockToken("RLIKE", "operator", "mysql"))],
            ),
        ]
        templates = from_libinjection_gaps(reports)
        engines = {t.engine for t in templates}
        assert "sqlite" in engines
        assert "mysql" in engines

    def test_sqlite_multiple_gaps(self):
        gaps = [
            MockTokenProbe(token=MockToken("GLOB")),
            MockTokenProbe(token=MockToken("COLLATE", "keyword")),
            MockTokenProbe(token=MockToken("iif", "function")),
            MockTokenProbe(token=MockToken("typeof", "function")),
        ]
        report = MockGapReport(engine="sqlite", gaps=gaps, through=4)
        templates = from_libinjection_gaps([report])
        patterns = [t.pattern for t in templates]
        assert any("COLLATE" in p for p in patterns)
        assert any("iif" in p for p in patterns)

    def test_glob_blind_char_template(self):
        report = MockGapReport(
            engine="sqlite",
            gaps=[MockTokenProbe(token=MockToken("GLOB"))],
        )
        templates = from_libinjection_gaps([report])
        char_templates = [t for t in templates if t.params.get("char")]
        assert len(char_templates) >= 1
        expanded = char_templates[0].expand()
        assert len(expanded) >= 26  # a-z at minimum


# ---- from_both -------------------------------------------------------------

class TestFromBoth:
    def test_combines_both_sources(self):
        score = MockScoreProbeResult(
            keyword_map=[MockKeywordResult("GLOB", False, False)],
            boundary_payloads=[MockBoundaryPayload("' GLOB '*", "THROUGH", "edge")],
        )
        gap_report = MockGapReport(
            engine="sqlite",
            gaps=[MockTokenProbe(token=MockToken("MATCH"))],
        )
        templates = from_both(score, [gap_report])
        patterns = [t.pattern for t in templates]
        assert any("GLOB" in p for p in patterns)
        assert any("MATCH" in p for p in patterns)

    def test_deduplicates(self):
        score = MockScoreProbeResult(
            keyword_map=[MockKeywordResult("GLOB", False, False)],
            boundary_payloads=[],
        )
        gap_report = MockGapReport(
            engine="sqlite",
            gaps=[MockTokenProbe(token=MockToken("GLOB"))],
        )
        templates = from_both(score, [gap_report])
        patterns = [t.pattern for t in templates]
        glob_count = sum(1 for p in patterns if p == "' GLOB '*")
        assert glob_count == 1

    def test_none_inputs(self):
        assert from_both(None, None) == []
        assert from_both(None, []) == []


# ---- expand_all ------------------------------------------------------------

class TestExpandAll:
    def test_returns_class_payload_pairs(self):
        templates = [
            Template(pattern="' GLOB '*", engine="sqlite", attack_class="SQL Injection"),
            Template(pattern="' MATCH '*", engine="sqlite", attack_class="SQL Injection"),
        ]
        pairs = expand_all(templates)
        assert len(pairs) == 2
        assert all(cls == "SQL Injection" for cls, _ in pairs)
        assert ("SQL Injection", "' GLOB '*") in pairs

    def test_deduplicates_payloads(self):
        templates = [
            Template(pattern="' GLOB '*", engine="sqlite", attack_class="SQL Injection"),
            Template(pattern="' GLOB '*", engine="sqlite", attack_class="SQL Injection"),
        ]
        pairs = expand_all(templates)
        assert len(pairs) == 1

    def test_expands_params(self):
        templates = [Template(
            pattern="pg_sleep({sec})", engine="postgresql",
            attack_class="SQL Injection",
            params={"sec": ["3", "5"]},
        )]
        pairs = expand_all(templates)
        assert len(pairs) == 2


# ---- PayloadReconstructor facade -------------------------------------------

class TestPayloadReconstructor:
    def test_full_pipeline(self):
        score = MockScoreProbeResult(
            keyword_map=[
                MockKeywordResult("GLOB", False, False),
                MockKeywordResult("SELECT", True, True),
            ],
            boundary_payloads=[
                MockBoundaryPayload("' GLOB '*", "THROUGH", "boundary"),
            ],
        )
        gap_reports = [MockGapReport(
            engine="sqlite",
            gaps=[MockTokenProbe(token=MockToken("MATCH"))],
        )]

        r = PayloadReconstructor()
        r.add_score_probe(score)
        r.add_gap_reports(gap_reports)
        templates = r.build()
        seeds = r.seeds()

        assert len(templates) > 0
        assert len(seeds) > 0
        assert all(isinstance(s, tuple) and len(s) == 2 for s in seeds)

    def test_chaining(self):
        r = PayloadReconstructor()
        result = r.add_score_probe(MockScoreProbeResult(
            keyword_map=[], boundary_payloads=[],
        )).add_gap_reports([])
        assert result is r

    def test_empty(self):
        r = PayloadReconstructor()
        seeds = r.seeds()
        assert seeds == []
