"""Tests for the WAF rule generation module (waffen/report/defend.py)."""
import json
import os
import tempfile
from types import SimpleNamespace

import pytest

from waffen.report.defend import (
    DefenseRule,
    ENGINES,
    _extract_patterns,
    format_rule,
    generate_rules,
    render_rules,
    write_rules,
    write_all_engines,
)


# ---- fixtures ---------------------------------------------------------------

def _finding(payload="' OR 1=1--", chain=None, attack_class="SQL Injection",
             verified=True, confidence=0.9):
    return SimpleNamespace(
        payload=payload,
        chain=chain or ["base64"],
        attack_class=attack_class,
        verified=verified,
        confidence=confidence,
    )


# ---- pattern extraction -----------------------------------------------------

class TestExtractPatterns:
    def test_base64_chain(self):
        f = _finding(chain=["base64"])
        patterns = _extract_patterns(f)
        assert len(patterns) >= 1
        assert any("base64" in desc.lower() for _, desc in patterns)

    def test_comment_split_chain(self):
        f = _finding(chain=["comment_split"])
        patterns = _extract_patterns(f)
        assert len(patterns) >= 1
        assert any("comment" in desc.lower() for _, desc in patterns)

    def test_ast_sqlite_swap_chain(self):
        f = _finding(chain=["ast_sqlite_swap"])
        patterns = _extract_patterns(f)
        assert any("sqlite" in desc.lower() for _, desc in patterns)

    def test_multiple_chain_steps(self):
        f = _finding(chain=["comment_split", "case_swap", "base64"])
        patterns = _extract_patterns(f)
        assert len(patterns) >= 2  # deduped but should have multiple

    def test_unknown_chain_falls_back_to_payload(self):
        f = _finding(chain=["some_unknown_mutator_xyz"])
        patterns = _extract_patterns(f)
        assert len(patterns) >= 1  # falls back to literal payload match

    def test_empty_chain(self):
        f = _finding(chain=[])
        patterns = _extract_patterns(f)
        assert len(patterns) >= 1  # falls back to payload

    def test_xss_chain(self):
        f = _finding(chain=["xss_event_alternatives"], attack_class="XSS Injection")
        patterns = _extract_patterns(f)
        assert any("event" in desc.lower() for _, desc in patterns)

    def test_ssti_chain(self):
        f = _finding(chain=["ssti_jinja2_filter_chain"], attack_class="SSTI")
        patterns = _extract_patterns(f)
        assert any("jinja" in desc.lower() for _, desc in patterns)

    def test_ssrf_chain(self):
        f = _finding(chain=["ssrf_ip_decimal"], attack_class="SSRF")
        patterns = _extract_patterns(f)
        assert any("decimal" in desc.lower() for _, desc in patterns)


# ---- rule generation --------------------------------------------------------

class TestGenerateRules:
    def test_basic_generation(self):
        findings = [_finding()]
        rules = generate_rules(findings, "modsecurity")
        assert len(rules) >= 1
        assert all(isinstance(r, DefenseRule) for r in rules)

    def test_rule_has_required_fields(self):
        rules = generate_rules([_finding()], "modsecurity")
        r = rules[0]
        assert r.id >= 900_001
        assert r.engine == "modsecurity"
        assert r.pattern
        assert r.description
        assert r.attack_class == "SQL Injection"

    def test_verified_confidence_high(self):
        rules = generate_rules([_finding(verified=True)], "modsecurity")
        assert rules[0].confidence == "high"

    def test_unverified_confidence_medium(self):
        rules = generate_rules([_finding(verified=None)], "modsecurity")
        assert rules[0].confidence == "medium"

    def test_not_verified_confidence_low(self):
        rules = generate_rules([_finding(verified=False)], "modsecurity")
        assert rules[0].confidence == "low"

    def test_deduplicates_patterns(self):
        # Two findings with same chain → same pattern → one rule
        f1 = _finding(payload="' OR 1=1--", chain=["base64"])
        f2 = _finding(payload="' AND 1=1--", chain=["base64"])
        rules = generate_rules([f1, f2], "modsecurity")
        assert len(rules) == 1  # same pattern deduped

    def test_different_chains_different_rules(self):
        f1 = _finding(chain=["base64"])
        f2 = _finding(chain=["comment_split"])
        rules = generate_rules([f1, f2], "modsecurity")
        assert len(rules) >= 2

    def test_empty_findings(self):
        rules = generate_rules([], "modsecurity")
        assert rules == []

    def test_incremental_ids(self):
        findings = [
            _finding(chain=["base64"]),
            _finding(chain=["comment_split"]),
            _finding(chain=["ast_sqlite_swap"]),
        ]
        rules = generate_rules(findings, "modsecurity")
        ids = [r.id for r in rules]
        assert ids == sorted(ids)
        assert len(set(ids)) == len(ids)  # unique


# ---- formatting per engine --------------------------------------------------

class TestFormatRule:
    def _rule(self, engine="modsecurity"):
        return DefenseRule(
            id=900001, engine=engine,
            pattern=r"(?i)(?:\w+\s*/\*[^*]*\*/\s*\w+)",
            description="inline comment splitting SQL keywords",
            bypass_payload="UN/**/ION SEL/**/ECT 1",
            chain=["comment_split"],
            attack_class="SQL Injection",
            confidence="high",
        )

    def test_modsecurity_format(self):
        out = format_rule(self._rule("modsecurity"))
        assert "SecRule" in out
        assert "ARGS" in out
        assert "id:900001" in out
        assert "phase:2" in out
        assert "deny" in out
        assert "403" in out

    def test_naxsi_format(self):
        out = format_rule(self._rule("naxsi"))
        assert "MainRule" in out
        assert "rx:" in out
        assert "id:900001" in out
        assert "$SQL:8" in out

    def test_cloudflare_format(self):
        out = format_rule(self._rule("cloudflare"))
        assert "http.request.uri.query" in out
        assert "matches" in out
        assert "http.request.body" in out

    def test_aws_format(self):
        out = format_rule(self._rule("aws"))
        parsed = json.loads(out)
        assert "WAFFEN-900001" in parsed["Name"]
        assert "Block" in parsed["Action"]
        assert parsed["_waffen_meta"]["pattern"]

    def test_unknown_engine_raises(self):
        with pytest.raises(ValueError, match="Unknown engine"):
            format_rule(self._rule("nonexistent"))


# ---- rendering --------------------------------------------------------------

class TestRenderRules:
    def test_modsecurity_header(self):
        rules = generate_rules([_finding()], "modsecurity")
        out = render_rules(rules, "modsecurity")
        assert "ModSecurity" in out
        assert "SecRule" in out

    def test_naxsi_header(self):
        rules = generate_rules([_finding()], "naxsi")
        out = render_rules(rules, "naxsi")
        assert "NAXSI" in out
        assert "MainRule" in out

    def test_empty_rules(self):
        out = render_rules([], "modsecurity")
        assert "No bypass findings" in out

    def test_cloudflare_output(self):
        rules = generate_rules([_finding(chain=["comment_split"])], "cloudflare")
        out = render_rules(rules, "cloudflare")
        assert "Cloudflare" in out


# ---- file I/O ---------------------------------------------------------------

class TestWriteRules:
    def test_write_single_engine(self, tmp_path):
        rules = generate_rules([_finding()], "modsecurity")
        p = str(tmp_path / "rules.conf")
        write_rules(rules, p, "modsecurity")
        content = open(p).read()
        assert "SecRule" in content

    def test_write_all_engines(self, tmp_path):
        d = str(tmp_path / "rules_dir")
        rules = generate_rules([_finding(chain=["comment_split"])])
        paths = write_all_engines(rules, d)
        assert len(paths) == len(ENGINES)
        for p in paths:
            assert os.path.exists(p)
            assert os.path.getsize(p) > 0


# ---- as_dict ----------------------------------------------------------------

class TestAsDict:
    def test_rule_as_dict(self):
        rules = generate_rules([_finding()], "modsecurity")
        d = rules[0].as_dict()
        assert d["engine"] == "modsecurity"
        assert d["attack_class"] == "SQL Injection"
        assert d["confidence"] == "high"
        assert "pattern" in d


# ---- CLI integration --------------------------------------------------------

class TestCLIDefend:
    def test_parser_has_defend(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args(["defend", "--findings", "test.jsonl"])
        assert args.findings == "test.jsonl"
        assert args.engine == "modsecurity"
        assert hasattr(args, "func")

    def test_bypass_has_defend_flag(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args(["bypass", "--target", "http://x", "--payload", "test",
                            "--defend", "modsecurity", "--mock"])
        assert args.defend == "modsecurity"
