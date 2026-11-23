"""Tests for WAF configuration synthesizer."""
import json
import os
import tempfile

import pytest

from waffen.report.synthesize_config import (
    WAFConfig,
    WAFConfigSynthesizer,
    _make_exclusion,
    write_config,
    load_findings_jsonl,
)


# ---------------------------------------------------------------------------
# WAFConfig
# ---------------------------------------------------------------------------

class TestWAFConfig:
    def test_defaults(self):
        cfg = WAFConfig()
        assert cfg.engine == "modsecurity"
        assert cfg.paranoia_level == 2
        assert cfg.custom_rules == []
        assert cfg.exclusions == []

    def test_as_dict(self):
        cfg = WAFConfig(engine="nginx", paranoia_level=3)
        d = cfg.as_dict()
        assert d["engine"] == "nginx"
        assert d["paranoia_level"] == 3
        assert "custom_rules" in d

    def test_as_dict_roundtrip(self):
        cfg = WAFConfig(custom_rules=["rule1"], exclusions=["exc1"],
                        recommendations=["rec1"])
        d = cfg.as_dict()
        assert d["custom_rules"] == ["rule1"]
        assert d["recommendations"] == ["rec1"]


# ---------------------------------------------------------------------------
# Synthesizer — inputs
# ---------------------------------------------------------------------------

class TestSynthesizerInputs:
    def test_add_bypasses_dict(self):
        s = WAFConfigSynthesizer()
        s.add_bypasses([{"payload": "' OR 1=1--", "chain": ["base64"],
                         "attack_class": "SQL Injection"}])
        assert len(s.bypasses) == 1
        assert s.bypasses[0]["payload"] == "' OR 1=1--"

    def test_add_bypasses_object(self):
        class F:
            def as_dict(self):
                return {"payload": "test", "chain": [], "attack_class": "XSS"}
        s = WAFConfigSynthesizer()
        s.add_bypasses([F()])
        assert s.bypasses[0]["payload"] == "test"

    def test_add_rulemap_dict(self):
        s = WAFConfigSynthesizer()
        s.add_rulemap({"paranoia_level": 2, "gaps": []})
        assert s.rulemap["paranoia_level"] == 2

    def test_add_benchmark(self):
        s = WAFConfigSynthesizer()
        s.add_benchmark({"per_class": {"sqli": {"detection_rate": 0.85}}})
        assert s.benchmark is not None

    def test_add_false_positives(self):
        s = WAFConfigSynthesizer()
        s.add_false_positives(["benign1", "benign2"])
        assert len(s.fp_data) == 2

    def test_chaining(self):
        s = WAFConfigSynthesizer()
        result = s.add_bypasses([]).add_rulemap({}).add_false_positives([])
        assert result is s


# ---------------------------------------------------------------------------
# Synthesizer — synthesize
# ---------------------------------------------------------------------------

class TestSynthesize:
    def test_empty_inputs(self):
        s = WAFConfigSynthesizer()
        cfg = s.synthesize()
        assert cfg.engine == "modsecurity"
        assert cfg.paranoia_level == 3  # grade A default → PL3
        assert cfg.custom_rules == []

    def test_grade_sets_paranoia(self):
        s = WAFConfigSynthesizer()
        for grade, expected_pl in [("A+", 4), ("A", 3), ("B", 2), ("D", 1)]:
            cfg = s.synthesize(target_grade=grade)
            assert cfg.paranoia_level == expected_pl, f"grade {grade}"

    def test_bypass_generates_custom_rules(self):
        s = WAFConfigSynthesizer()
        s.add_bypasses([{
            "payload": "' OR 1=1--",
            "chain": ["base64"],
            "attack_class": "SQL Injection",
            "verified": True,
        }])
        cfg = s.synthesize()
        assert len(cfg.custom_rules) > 0
        assert any("SecRule" in r for r in cfg.custom_rules)

    def test_rulemap_gaps_add_enabled(self):
        s = WAFConfigSynthesizer()
        s.add_rulemap({
            "paranoia_level": 2,
            "gaps": [
                {"rule_id": "942150", "description": "SQL function names"},
                {"rule_id": "942160", "description": "Blind SQLi tests"},
            ]
        })
        cfg = s.synthesize()
        assert "942150" in cfg.rules_enabled
        assert "942160" in cfg.rules_enabled
        assert any("942150" in r for r in cfg.recommendations)

    def test_benchmark_low_detection_recommendation(self):
        s = WAFConfigSynthesizer()
        s.add_benchmark({
            "per_class": {
                "sqli": {"detection_rate": 0.75},
                "xss": {"detection_rate": 0.95},
            }
        })
        cfg = s.synthesize()
        assert any("sqli" in r.lower() or "Low detection" in r for r in cfg.recommendations)

    def test_false_positives_generate_exclusions(self):
        s = WAFConfigSynthesizer()
        s.add_false_positives(["O'Reilly Media", "search term with 1=1"])
        cfg = s.synthesize()
        assert len(cfg.exclusions) == 2

    def test_paranoia_upgrade_recommendation(self):
        s = WAFConfigSynthesizer()
        s.add_rulemap({"paranoia_level": 1, "gaps": []})
        cfg = s.synthesize(target_grade="A")
        assert any("Upgrade paranoia" in r for r in cfg.recommendations)

    def test_nginx_engine(self):
        s = WAFConfigSynthesizer()
        s.add_bypasses([{"payload": "test", "chain": [], "attack_class": "XSS"}])
        cfg = s.synthesize(engine="nginx")
        assert cfg.engine == "nginx"


# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------

class TestRender:
    def test_modsecurity_render(self):
        s = WAFConfigSynthesizer()
        s.add_bypasses([{"payload": "' OR 1=1--", "chain": ["base64"],
                         "attack_class": "SQL Injection"}])
        cfg = s.synthesize(engine="modsecurity")
        output = s.render(cfg)
        assert "WAFFEN-generated" in output
        assert "SecAction" in output
        assert "paranoia_level" in output

    def test_nginx_render(self):
        s = WAFConfigSynthesizer()
        cfg = s.synthesize(engine="nginx")
        output = s.render(cfg)
        assert "NGINX" in output

    def test_generic_render(self):
        s = WAFConfigSynthesizer()
        cfg = WAFConfig(engine="custom")
        output = s.render(cfg)
        assert "custom" in output

    def test_render_includes_exclusions(self):
        s = WAFConfigSynthesizer()
        s.add_false_positives(["benign test"])
        cfg = s.synthesize()
        output = s.render(cfg)
        assert "Exclusion" in output

    def test_render_includes_recommendations(self):
        s = WAFConfigSynthesizer()
        s.add_rulemap({"paranoia_level": 1, "gaps": [{"rule_id": "942100", "description": "test"}]})
        cfg = s.synthesize(target_grade="A")
        output = s.render(cfg)
        assert "TODO" in output


# ---------------------------------------------------------------------------
# Validate
# ---------------------------------------------------------------------------

class TestValidate:
    def test_pl4_warning(self):
        s = WAFConfigSynthesizer()
        cfg = WAFConfig(paranoia_level=4)
        warnings = s.validate(cfg)
        assert any("PL4" in w for w in warnings)

    def test_many_rules_warning(self):
        s = WAFConfigSynthesizer()
        cfg = WAFConfig(custom_rules=["r"] * 60)
        warnings = s.validate(cfg)
        assert any("consolidating" in w for w in warnings)

    def test_no_rules_warning(self):
        s = WAFConfigSynthesizer()
        cfg = WAFConfig()
        warnings = s.validate(cfg)
        assert any("No rules" in w for w in warnings)

    def test_low_pl_high_grade_warning(self):
        s = WAFConfigSynthesizer()
        cfg = WAFConfig(paranoia_level=1, settings={"target_grade": "A"})
        warnings = s.validate(cfg)
        assert any("PL3+" in w for w in warnings)

    def test_clean_config_no_warnings(self):
        s = WAFConfigSynthesizer()
        cfg = WAFConfig(paranoia_level=3, custom_rules=["r1", "r2"], rules_enabled=["942100"])
        warnings = s.validate(cfg)
        assert len(warnings) == 0


# ---------------------------------------------------------------------------
# Exclusion helper
# ---------------------------------------------------------------------------

class TestExclusion:
    def test_modsecurity_exclusion(self):
        exc = _make_exclusion("O'Reilly", "modsecurity")
        assert "SecRule" in exc

    def test_nginx_exclusion(self):
        exc = _make_exclusion("test", "nginx")
        assert "BasicRule" in exc

    def test_generic_exclusion(self):
        exc = _make_exclusion("test", "other")
        assert "Exclude" in exc


# ---------------------------------------------------------------------------
# File I/O
# ---------------------------------------------------------------------------

class TestWriteConfig:
    def test_write_modsecurity(self, tmp_path):
        s = WAFConfigSynthesizer()
        s.add_bypasses([{"payload": "' OR 1=1--", "chain": ["base64"],
                         "attack_class": "SQL Injection"}])
        cfg = s.synthesize()
        out_dir = str(tmp_path / "waf-config")
        files = write_config(s, cfg, out_dir)
        assert "modsecurity.conf" in files
        assert "README.md" in files
        assert os.path.exists(os.path.join(out_dir, "modsecurity.conf"))
        assert os.path.exists(os.path.join(out_dir, "README.md"))

    def test_write_nginx(self, tmp_path):
        s = WAFConfigSynthesizer()
        cfg = s.synthesize(engine="nginx")
        out_dir = str(tmp_path / "nginx-waf")
        files = write_config(s, cfg, out_dir)
        assert "nginx-waf.conf" in files

    def test_write_with_exclusions(self, tmp_path):
        s = WAFConfigSynthesizer()
        s.add_false_positives(["fp1"])
        cfg = s.synthesize()
        out_dir = str(tmp_path / "out")
        files = write_config(s, cfg, out_dir)
        assert "exclusions.conf" in files


class TestLoadFindings:
    def test_load_jsonl(self, tmp_path):
        p = tmp_path / "findings.jsonl"
        p.write_text(json.dumps({"findings": [{"payload": "test"}]}) + "\n")
        findings = load_findings_jsonl(str(p))
        assert len(findings) == 1
        assert findings[0]["payload"] == "test"

    def test_load_flat_jsonl(self, tmp_path):
        p = tmp_path / "findings.jsonl"
        p.write_text(json.dumps({"payload": "a"}) + "\n" + json.dumps({"payload": "b"}) + "\n")
        findings = load_findings_jsonl(str(p))
        assert len(findings) == 2


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

class TestCLI:
    def test_parser_has_synthesize_config(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args(["synthesize-config", "--engine", "modsecurity",
                             "--target-grade", "A"])
        assert args.engine == "modsecurity"
        assert args.target_grade == "A"
        assert hasattr(args, "func")

    def test_parser_all_grades(self):
        from waffen.cli import build_parser
        p = build_parser()
        for grade in ["A+", "A", "B+", "B", "C", "D", "F"]:
            args = p.parse_args(["synthesize-config", "--target-grade", grade])
            assert args.target_grade == grade
