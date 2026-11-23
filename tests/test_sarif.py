"""Tests for the SARIF 2.1.0 reporter."""
import json
import os
import tempfile

import pytest

from waffen.report.sarif import findings_to_sarif, write_sarif


def _finding(payload="' OR 1=1--", chain=None, attack_class="SQL Injection",
             verified=None, code="200"):
    return {
        "payload": payload,
        "chain": chain or ["base64"],
        "attack_class": attack_class,
        "verified_exploitable": verified,
        "http_code": code,
    }


class TestFindingsToSarif:
    def test_basic_structure(self):
        sarif = findings_to_sarif([_finding()], "https://example.com")
        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert len(sarif["runs"]) == 1
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "WAFFEN"
        assert "rules" in run["tool"]["driver"]
        assert "results" in run

    def test_empty_findings(self):
        sarif = findings_to_sarif([], "https://example.com")
        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["rules"] == []

    def test_single_finding(self):
        sarif = findings_to_sarif([_finding()], "https://t.com")
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        r = results[0]
        assert "waffen/" in r["ruleId"]
        assert "WAF bypass" in r["message"]["text"]
        assert r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "https://t.com"

    def test_verified_is_error(self):
        sarif = findings_to_sarif([_finding(verified=True)], "https://t.com")
        assert sarif["runs"][0]["results"][0]["level"] == "error"

    def test_unverified_is_warning(self):
        sarif = findings_to_sarif([_finding(verified=None)], "https://t.com")
        assert sarif["runs"][0]["results"][0]["level"] == "warning"

    def test_not_exploitable_is_note(self):
        sarif = findings_to_sarif([_finding(verified=False)], "https://t.com")
        assert sarif["runs"][0]["results"][0]["level"] == "note"

    def test_multiple_findings(self):
        fs = [_finding(payload="p1"), _finding(payload="p2", attack_class="XSS Injection")]
        sarif = findings_to_sarif(fs, "https://t.com")
        results = sarif["runs"][0]["results"]
        assert len(results) == 2
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 2

    def test_same_class_shares_rule(self):
        fs = [_finding(payload="p1"), _finding(payload="p2")]
        sarif = findings_to_sarif(fs, "https://t.com")
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1

    def test_rule_id_format(self):
        sarif = findings_to_sarif([_finding(attack_class="SQL Injection")], "https://t.com")
        rid = sarif["runs"][0]["results"][0]["ruleId"]
        assert rid == "waffen/sql-injection"

    def test_chain_in_message(self):
        sarif = findings_to_sarif([_finding(chain=["url_encode", "base64"])], "https://t.com")
        msg = sarif["runs"][0]["results"][0]["message"]["text"]
        assert "url_encode" in msg
        assert "base64" in msg

    def test_verified_status_in_message(self):
        sarif = findings_to_sarif([_finding(verified=True)], "https://t.com")
        msg = sarif["runs"][0]["results"][0]["message"]["text"]
        assert "VERIFIED" in msg

    def test_valid_json_output(self):
        sarif = findings_to_sarif([_finding()], "https://t.com")
        dumped = json.dumps(sarif)
        parsed = json.loads(dumped)
        assert parsed["version"] == "2.1.0"


class TestWriteSarif:
    def test_writes_file(self):
        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
            path = f.name
        try:
            result = write_sarif([_finding()], "https://t.com", path)
            assert result == path
            assert os.path.exists(path)
            with open(path) as f:
                data = json.load(f)
            assert data["version"] == "2.1.0"
            assert len(data["runs"][0]["results"]) == 1
        finally:
            os.unlink(path)

    def test_writes_empty_findings(self):
        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
            path = f.name
        try:
            write_sarif([], "https://t.com", path)
            with open(path) as f:
                data = json.load(f)
            assert data["runs"][0]["results"] == []
        finally:
            os.unlink(path)


class TestWithObjectFindings:
    """Test with Finding-like objects instead of dicts."""

    def test_object_finding(self):
        class FakeFinding:
            payload = "' OR 1=1--"
            chain = ["base64"]
            attack_class = "SQL Injection"
            verified = True
            code = "200"

        sarif = findings_to_sarif([FakeFinding()], "https://t.com")
        assert len(sarif["runs"][0]["results"]) == 1
        assert sarif["runs"][0]["results"][0]["level"] == "error"


class TestCliIntegration:
    def test_sarif_flag_exists(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args(["bypass", "--target", "https://t.com",
                             "--payload", "test", "--sarif", "out.sarif"])
        assert args.sarif == "out.sarif"
