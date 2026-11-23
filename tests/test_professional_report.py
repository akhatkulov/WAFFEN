"""Tests for the professional HTML report generator."""
import json
import os
import tempfile

import pytest

from waffen.report.professional import (
    ReportConfig,
    generate_html_report,
    generate_summary_card,
    load_findings_jsonl,
    severity,
    write_html_report,
)


def _finding(**kw):
    base = {
        "attack_class": "SQL Injection",
        "chain": ["base64"],
        "http_code": "200",
        "payload": "' OR 1=1--",
        "verified_exploitable": None,
        "verify_confidence": None,
    }
    base.update(kw)
    return base


# --- severity ---

class TestSeverity:
    def test_verified_sqli_is_critical(self):
        assert severity(_finding(verified_exploitable=True)) == "CRITICAL"

    def test_verified_cmdi_is_critical(self):
        assert severity(_finding(attack_class="Command Injection",
                                 verified_exploitable=True)) == "CRITICAL"

    def test_verified_xss_is_high(self):
        assert severity(_finding(attack_class="XSS Injection",
                                 verified_exploitable=True)) == "HIGH"

    def test_unverified_500_is_medium(self):
        assert severity(_finding(http_code="500")) == "MEDIUM"

    def test_unverified_502_is_medium(self):
        assert severity(_finding(http_code="502")) == "MEDIUM"

    def test_unverified_200_is_low(self):
        assert severity(_finding(http_code="200")) == "LOW"

    def test_no_code_is_low(self):
        assert severity(_finding(http_code="")) == "LOW"

    def test_works_with_object(self):
        class F:
            attack_class = "SQL Injection"
            verified = True
            code = "200"
        assert severity(F()) == "CRITICAL"


# --- ReportConfig ---

class TestReportConfig:
    def test_default_date(self):
        cfg = ReportConfig()
        assert cfg.date  # auto-filled
        assert len(cfg.date) == 10  # YYYY-MM-DD

    def test_custom_date_preserved(self):
        cfg = ReportConfig(date="2026-01-01")
        assert cfg.date == "2026-01-01"


# --- generate_html_report ---

class TestGenerateHtmlReport:
    def test_empty_findings(self):
        html = generate_html_report([])
        assert "<!DOCTYPE html>" in html
        assert "No bypass findings" in html

    def test_basic_structure(self):
        html = generate_html_report([_finding()])
        assert "Executive Summary" in html
        assert "Methodology" in html
        assert "Findings" in html
        assert "Recommendations" in html
        assert "Appendix" in html

    def test_contains_payload(self):
        html = generate_html_report([_finding(payload="test_payload_xyz")])
        assert "test_payload_xyz" in html

    def test_contains_target(self):
        cfg = ReportConfig(target="https://example.com")
        html = generate_html_report([], cfg)
        assert "https://example.com" in html

    def test_classification_banner(self):
        cfg = ReportConfig(classification="TOP SECRET")
        html = generate_html_report([], cfg)
        assert "TOP SECRET" in html

    def test_toc_links(self):
        html = generate_html_report([])
        assert 'href="#executive"' in html
        assert 'href="#findings"' in html

    def test_critical_summary_text(self):
        html = generate_html_report([_finding(verified_exploitable=True)])
        assert "critical" in html.lower()

    def test_no_verified_summary_text(self):
        html = generate_html_report([_finding()])
        assert "No verified-exploitable" in html

    def test_multiple_findings(self):
        findings = [_finding(payload=f"payload_{i}") for i in range(5)]
        html = generate_html_report(findings)
        for i in range(5):
            assert f"payload_{i}" in html

    def test_xss_escaping(self):
        html = generate_html_report([_finding(payload="<script>alert(1)</script>")])
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_chain_display(self):
        html = generate_html_report([_finding(chain=["base64", "url_encode"])])
        assert "base64" in html
        assert "url_encode" in html

    def test_verified_finding_shown(self):
        f = _finding(verified_exploitable=True, verify_confidence=0.95)
        html = generate_html_report([f])
        assert "95%" in html

    def test_sqli_recommendation(self):
        html = generate_html_report([_finding()])
        assert "SQL injection" in html

    def test_xss_recommendation(self):
        html = generate_html_report([_finding(attack_class="XSS Injection")])
        assert "XSS" in html

    def test_css_embedded(self):
        html = generate_html_report([])
        assert "<style>" in html
        assert "sev-badge" in html

    def test_print_media_query(self):
        html = generate_html_report([])
        assert "@media print" in html

    def test_dark_mode_support(self):
        html = generate_html_report([])
        assert "prefers-color-scheme: dark" in html


# --- generate_summary_card ---

class TestSummaryCard:
    def test_empty(self):
        html = generate_summary_card([])
        assert "Summary Card" in html
        assert "<!DOCTYPE html>" in html

    def test_shows_findings_count(self):
        html = generate_summary_card([_finding(), _finding()])
        assert ">2<" in html

    def test_shows_verified_count(self):
        html = generate_summary_card([_finding(verified_exploitable=True)])
        assert ">1<" in html or "<strong>1</strong>" in html

    def test_top_findings_table(self):
        html = generate_summary_card([_finding(payload="card_test")])
        assert "card_test" in html

    def test_truncates_long_payload(self):
        html = generate_summary_card([_finding(payload="A" * 100)])
        assert "A" * 50 in html
        assert "A" * 100 not in html


# --- write_html_report ---

class TestWriteHtmlReport:
    def test_writes_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "test.html")
            write_html_report("<html>test</html>", path)
            assert os.path.exists(path)
            with open(path) as f:
                assert f.read() == "<html>test</html>"

    def test_creates_parent_dirs(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "sub", "dir", "report.html")
            write_html_report("<html></html>", path)
            assert os.path.exists(path)


# --- load_findings_jsonl ---

class TestLoadFindings:
    def test_load(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write(json.dumps(_finding()) + "\n")
            f.write(json.dumps(_finding(payload="second")) + "\n")
            f.flush()
            findings = load_findings_jsonl(f.name)
        os.unlink(f.name)
        assert len(findings) == 2
        assert findings[1]["payload"] == "second"

    def test_empty_lines_skipped(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write(json.dumps(_finding()) + "\n\n\n")
            f.flush()
            findings = load_findings_jsonl(f.name)
        os.unlink(f.name)
        assert len(findings) == 1


# --- CLI integration ---

class TestCLI:
    def test_report_subcommand_exists(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args(["report", "--findings", "x.jsonl", "--html", "out.html"])
        assert args.html == "out.html"
        assert hasattr(args, "func")

    def test_bypass_html_report_flag(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args(["bypass", "--target", "https://x.com",
                             "--class", "SQL Injection",
                             "--html-report", "report.html"])
        assert args.html_report == "report.html"

    def test_summary_only_flag(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args(["report", "--findings", "x.jsonl",
                             "--html", "out.html", "--summary-only"])
        assert args.summary_only is True
