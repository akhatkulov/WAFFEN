"""Tests for the libinjection gap hunter."""
import types
from unittest.mock import MagicMock

import pytest

from waffen.recon.libinjection_gaps import (
    ALL_TOKENS,
    LibinjectionGapHunter,
    Token,
    _templates_for,
    generate_exploit_seeds,
    GapReport,
    TokenProbe,
)


# ---- token database completeness ------------------------------------------

def test_all_engines_present():
    assert set(ALL_TOKENS) == {"sqlite", "postgresql", "mysql", "mssql"}


@pytest.mark.parametrize("engine", ALL_TOKENS.keys())
def test_engine_has_tokens(engine):
    assert len(ALL_TOKENS[engine]) >= 10, f"{engine} should have ≥10 tokens"


@pytest.mark.parametrize("engine", ALL_TOKENS.keys())
def test_tokens_have_required_fields(engine):
    for tok in ALL_TOKENS[engine]:
        assert tok.name, f"token in {engine} has empty name"
        assert tok.kind in ("operator", "function", "keyword", "variable")
        assert tok.engine == engine


def test_sqlite_has_glob():
    names = {t.name for t in ALL_TOKENS["sqlite"]}
    for kw in ("GLOB", "COLLATE", "MATCH", "ISNULL", "NOTNULL"):
        assert kw in names, f"SQLite missing {kw}"


def test_postgresql_has_ilike():
    names = {t.name for t in ALL_TOKENS["postgresql"]}
    assert "ILIKE" in names


def test_mysql_has_rlike():
    names = {t.name for t in ALL_TOKENS["mysql"]}
    assert "RLIKE" in names


def test_mssql_has_waitfor():
    names = {t.name for t in ALL_TOKENS["mssql"]}
    assert "WAITFOR" in names


# ---- template selection ----------------------------------------------------

def test_operator_gets_operator_templates():
    tok = Token("GLOB", "operator", "sqlite")
    templates = _templates_for(tok)
    names = [t[0] for t in templates]
    assert "op_wildcard" in names
    assert "func_call" not in names


def test_function_gets_function_templates():
    tok = Token("typeof", "function", "sqlite")
    templates = _templates_for(tok)
    names = [t[0] for t in templates]
    assert "func_call" in names
    assert "op_wildcard" not in names


def test_variable_gets_variable_templates():
    tok = Token("@@version", "variable", "mysql")
    templates = _templates_for(tok)
    names = [t[0] for t in templates]
    assert "variable" in names


def test_keyword_gets_keyword_templates():
    tok = Token("ISNULL", "keyword", "sqlite")
    templates = _templates_for(tok)
    names = [t[0] for t in templates]
    assert "postfix" in names


# ---- seed generation -------------------------------------------------------

def _make_gap(name, engine):
    return TokenProbe(
        token=Token(name, "operator", engine),
        template="op_wildcard", payload=f"' {name} '*",
        code="200", verdict="THROUGH",
    )


def test_sqlite_seeds_from_glob():
    gaps = [_make_gap("GLOB", "sqlite")]
    seeds = generate_exploit_seeds("sqlite", gaps)
    assert any("GLOB" in s for s in seeds)
    assert len(seeds) >= 1


def test_sqlite_seeds_from_collate_glob():
    gaps = [_make_gap("GLOB", "sqlite"), _make_gap("COLLATE", "sqlite")]
    seeds = generate_exploit_seeds("sqlite", gaps)
    assert any("COLLATE" in s and "GLOB" in s for s in seeds)


def test_postgresql_seeds_from_ilike():
    gaps = [_make_gap("ILIKE", "postgresql")]
    seeds = generate_exploit_seeds("postgresql", gaps)
    assert any("ILIKE" in s for s in seeds)


def test_mysql_seeds_from_rlike():
    gaps = [_make_gap("RLIKE", "mysql")]
    seeds = generate_exploit_seeds("mysql", gaps)
    assert any("RLIKE" in s for s in seeds)


def test_mssql_seeds_from_waitfor():
    gaps = [_make_gap("WAITFOR", "mssql")]
    seeds = generate_exploit_seeds("mssql", gaps)
    assert any("WAITFOR" in s for s in seeds)


def test_no_gaps_no_seeds():
    seeds = generate_exploit_seeds("sqlite", [])
    assert seeds == []


def test_seeds_use_only_gap_tokens():
    gaps = [_make_gap("GLOB", "sqlite")]
    seeds = generate_exploit_seeds("sqlite", gaps)
    for seed in seeds:
        assert "LIKE" not in seed, f"seed should not use LIKE (detected): {seed}"


# ---- hunter with mock oracle -----------------------------------------------

class _FakeResp:
    def __init__(self, code, verdict):
        self.code = code
        self.verdict = verdict


def _make_hunter(responses):
    """Build a hunter with a fake oracle that returns canned responses."""
    target = MagicMock()
    idx = [0]

    def fake_send(payload):
        r = responses[min(idx[0], len(responses) - 1)]
        idx[0] += 1
        return r

    hunter = LibinjectionGapHunter(target, engines=["sqlite"])
    # Patch _oracle to return a mock with our fake_send
    mock_oracle = MagicMock()
    mock_oracle.send = fake_send
    hunter._oracle = lambda: mock_oracle
    return hunter


def test_scan_detects_gap():
    # GLOB probed in op_wildcard context → THROUGH
    all_through = [_FakeResp("200", "THROUGH")] * 200
    hunter = _make_hunter(all_through)
    reports = hunter.scan_all()
    assert len(reports) == 1
    r = reports[0]
    assert r.engine == "sqlite"
    assert r.through > 0
    assert len(r.gaps) > 0


def test_scan_all_blocked():
    all_blocked = [_FakeResp("403", "BLOCKED")] * 500
    hunter = _make_hunter(all_blocked)
    reports = hunter.scan_all()
    r = reports[0]
    assert r.through == 0
    assert r.blocked > 0
    assert len(r.gaps) == 0


def test_probe_single_token():
    hunter = _make_hunter([_FakeResp("200", "THROUGH")])
    tok = Token("GLOB", "operator", "sqlite")
    probes = hunter.probe_token(tok)
    assert len(probes) >= 1
    assert probes[0].verdict == "THROUGH"


def test_probe_stops_on_first_through():
    call_count = [0]
    orig_through = _FakeResp("200", "THROUGH")

    def counting_send(payload):
        call_count[0] += 1
        return orig_through

    target = MagicMock()
    hunter = LibinjectionGapHunter(target, engines=["sqlite"])
    mock_oracle = MagicMock()
    mock_oracle.send = counting_send
    hunter._oracle = lambda: mock_oracle

    tok = Token("GLOB", "operator", "sqlite")
    probes = hunter.probe_token(tok)
    assert call_count[0] == 1, "should stop after first THROUGH"
