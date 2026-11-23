"""Tests for WAF rule reverse engineering (rulemap)."""
import json
import os
import tempfile
from unittest.mock import MagicMock

import pytest

from waffen.recon.rulemap import (
    CRS_RULES,
    CATEGORIES,
    RuleSignature,
    RuleProbe,
    RuleMapReport,
    RuleMapper,
    write_rulemap_json,
)


# ---- rule database ---------------------------------------------------------

class TestRuleDatabase:
    def test_minimum_rule_count(self):
        assert len(CRS_RULES) >= 80, f"expected >=80 CRS rules, got {len(CRS_RULES)}"

    def test_all_rules_have_required_fields(self):
        for r in CRS_RULES:
            assert r.rule_id, f"rule missing id: {r}"
            assert r.description, f"rule {r.rule_id} missing description"
            assert r.category, f"rule {r.rule_id} missing category"
            assert r.paranoia_level in (1, 2, 3, 4), f"rule {r.rule_id} bad PL: {r.paranoia_level}"
            assert r.trigger_payload, f"rule {r.rule_id} missing trigger payload"
            assert r.false_positive_risk in ("low", "medium", "high")

    def test_rule_ids_unique(self):
        ids = [r.rule_id for r in CRS_RULES]
        assert len(ids) == len(set(ids)), "duplicate rule IDs found"

    def test_categories_present(self):
        assert "sqli" in CATEGORIES
        assert "xss" in CATEGORIES
        assert "rce" in CATEGORIES
        assert "lfi" in CATEGORIES

    def test_sqli_rules_exist(self):
        sqli = [r for r in CRS_RULES if r.category == "sqli"]
        assert len(sqli) >= 20

    def test_xss_rules_exist(self):
        xss = [r for r in CRS_RULES if r.category == "xss"]
        assert len(xss) >= 15

    def test_rce_rules_exist(self):
        rce = [r for r in CRS_RULES if r.category == "rce"]
        assert len(rce) >= 5

    def test_all_paranoia_levels_covered(self):
        pls = {r.paranoia_level for r in CRS_RULES}
        assert 1 in pls
        assert 2 in pls
        assert 3 in pls

    def test_pl1_has_most_rules(self):
        pl1 = [r for r in CRS_RULES if r.paranoia_level == 1]
        pl4 = [r for r in CRS_RULES if r.paranoia_level == 4]
        assert len(pl1) > len(pl4)

    def test_payloads_are_nonempty_strings(self):
        for r in CRS_RULES:
            assert isinstance(r.trigger_payload, str)
            assert len(r.trigger_payload.strip()) > 0


# ---- RuleProbe -------------------------------------------------------------

class TestRuleProbe:
    def test_create(self):
        sig = CRS_RULES[0]
        probe = RuleProbe(rule=sig, blocked=True, code="403")
        assert probe.blocked is True
        assert probe.code == "403"

    def test_not_blocked(self):
        sig = CRS_RULES[0]
        probe = RuleProbe(rule=sig, blocked=False, code="200")
        assert probe.blocked is False


# ---- RuleMapReport --------------------------------------------------------

class TestRuleMapReport:
    def test_empty_report(self):
        r = RuleMapReport()
        assert r.waf_type == "unknown"
        assert r.estimated_paranoia_level == 0
        assert len(r.rules_active) == 0

    def test_summary_contains_waf_type(self):
        r = RuleMapReport(waf_type="CRS-like", total_probes=10,
                          rules_active=[CRS_RULES[0]], rules_inactive=[],
                          categories={"sqli": {"active": 1, "total": 1, "by_pl": {}}})
        s = r.summary()
        assert "CRS-like" in s

    def test_summary_shows_gaps(self):
        gap = CRS_RULES[5]
        r = RuleMapReport(waf_type="CRS-like", total_probes=1,
                          rules_active=[], rules_inactive=[gap],
                          gaps=[gap], categories={})
        s = r.summary()
        assert "GAPS" in s
        assert gap.rule_id in s

    def test_as_dict(self):
        r = RuleMapReport(waf_type="CRS-like", estimated_paranoia_level=2,
                          total_probes=10, rules_active=CRS_RULES[:5],
                          rules_inactive=CRS_RULES[5:7],
                          gaps=CRS_RULES[5:7],
                          categories={"sqli": {"active": 5, "total": 7, "by_pl": {}}})
        d = r.as_dict()
        assert d["waf_type"] == "CRS-like"
        assert d["paranoia_level"] == 2
        assert d["active"] == 5
        assert d["inactive"] == 2
        assert len(d["gaps"]) == 2
        assert d["gaps"][0]["rule_id"] == CRS_RULES[5].rule_id


# ---- RuleMapper with mock oracle -------------------------------------------

class _FakeResp:
    def __init__(self, verdict, code="403"):
        self.verdict = verdict
        self.code = code

def _make_mapper(block_rule_ids: set[str]):
    """Return a RuleMapper with a mock sender that blocks specific rule IDs."""
    def sender(payload):
        for r in CRS_RULES:
            if r.trigger_payload == payload and r.rule_id in block_rule_ids:
                return _FakeResp("BLOCKED", "403")
        return _FakeResp("THROUGH", "200")
    target = MagicMock()
    mapper = RuleMapper(target, sender=sender)
    mock_oracle = MagicMock()
    mock_oracle.send = sender
    mapper._oracle = lambda: mock_oracle
    return mapper


class TestRuleMapper:
    def test_all_blocked(self):
        all_ids = {r.rule_id for r in CRS_RULES}
        mapper = _make_mapper(all_ids)
        report = mapper.map_rules()
        assert report.waf_type == "CRS-like"
        assert len(report.rules_active) == len(CRS_RULES)
        assert len(report.gaps) == 0

    def test_none_blocked(self):
        mapper = _make_mapper(set())
        report = mapper.map_rules()
        assert report.waf_type == "none-or-passthrough"
        assert len(report.rules_active) == 0
        assert len(report.gaps) == len(CRS_RULES)

    def test_partial_block(self):
        pl1_ids = {r.rule_id for r in CRS_RULES if r.paranoia_level == 1}
        mapper = _make_mapper(pl1_ids)
        report = mapper.map_rules()
        assert report.waf_type == "CRS-like"
        assert len(report.rules_active) == len(pl1_ids)
        for g in report.gaps:
            assert g.paranoia_level > 1

    def test_categories_populated(self):
        all_ids = {r.rule_id for r in CRS_RULES}
        mapper = _make_mapper(all_ids)
        report = mapper.map_rules()
        assert "sqli" in report.categories
        assert "xss" in report.categories
        assert report.categories["sqli"]["active"] > 0

    def test_gaps_are_unblocked_rules(self):
        block_ids = {r.rule_id for r in CRS_RULES[:5]}
        mapper = _make_mapper(block_ids)
        report = mapper.map_rules()
        gap_ids = {g.rule_id for g in report.gaps}
        for g_id in gap_ids:
            assert g_id not in block_ids


# ---- paranoia level detection -----------------------------------------------

class TestParanoiaDetection:
    def test_pl1_only(self):
        pl1_ids = {r.rule_id for r in CRS_RULES if r.paranoia_level == 1}
        mapper = _make_mapper(pl1_ids)
        report = mapper.map_rules()
        assert report.estimated_paranoia_level == 1

    def test_pl1_and_pl2(self):
        ids = {r.rule_id for r in CRS_RULES if r.paranoia_level <= 2}
        mapper = _make_mapper(ids)
        report = mapper.map_rules()
        assert report.estimated_paranoia_level == 2

    def test_all_pls(self):
        all_ids = {r.rule_id for r in CRS_RULES}
        mapper = _make_mapper(all_ids)
        report = mapper.map_rules()
        assert report.estimated_paranoia_level >= 3

    def test_no_blocks_pl0(self):
        mapper = _make_mapper(set())
        report = mapper.map_rules()
        assert report.estimated_paranoia_level == 0

    def test_sparse_pl1_still_detected(self):
        pl1 = [r for r in CRS_RULES if r.paranoia_level == 1]
        half_pl1 = {r.rule_id for r in pl1[:len(pl1)//2 + 1]}
        mapper = _make_mapper(half_pl1)
        report = mapper.map_rules()
        assert report.estimated_paranoia_level >= 1


# ---- JSON export -----------------------------------------------------------

class TestJsonExport:
    def test_write_and_read(self):
        report = RuleMapReport(
            waf_type="CRS-like", estimated_paranoia_level=2,
            total_probes=5, rules_active=CRS_RULES[:3],
            rules_inactive=CRS_RULES[3:5], gaps=CRS_RULES[3:5],
            categories={"sqli": {"active": 3, "total": 5, "by_pl": {1: {"active": 3, "total": 3}}}},
        )
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            path = f.name
        try:
            write_rulemap_json(report, path)
            with open(path) as f:
                data = json.load(f)
            assert data["waf_type"] == "CRS-like"
            assert data["paranoia_level"] == 2
            assert len(data["gaps"]) == 2
        finally:
            os.unlink(path)


# ---- CLI integration -------------------------------------------------------

class TestCLI:
    def test_parser_has_rulemap(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args(["rulemap", "--target", "https://test.com"])
        assert hasattr(args, "func")

    def test_parser_accepts_out(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args(["rulemap", "--target", "https://test.com", "--out", "rm.json"])
        assert args.out == "rm.json"
