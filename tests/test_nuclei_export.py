"""Tests for the Nuclei differential WAF-audit exporter (report/nuclei.py)."""
import shutil
import subprocess

import pytest

from waffen.core.oracle import Target
from waffen.report import nuclei


class _Find:
    def __init__(self, payload, attack_class, chain):
        self.payload = payload
        self.attack_class = attack_class
        self.chain = chain


class _Res:
    def __init__(self, seed, findings):
        self.seed = seed
        self.findings = findings


class _Run:
    def __init__(self, result, transform="identity"):
        self.result = result
        self.transform = transform


def test_build_template_is_a_blocked_vs_passed_differential():
    tid, y = nuclei.build_template(
        "1' UNION SELECT 1-- -", "1'/**//**/UNION/**//**/SELECT/**//**/1-- -",
        "SQL Injection", ["sql_adjacent_comment"],
        path="/rest/products/search", param="q")
    assert tid.startswith("waffen-bypass-sql-injection-")
    assert "req-condition: true" in y
    assert "X-WAFFEN-Audit: baseline" in y and "X-WAFFEN-Audit: probe" in y
    # the differential: baseline blocked AND probe not blocked
    assert "status_code_1 == 403" in y and "status_code_2 != 403" in y
    assert "severity: high" in y
    assert "tags: waf-audit,waffen,sql-injection" in y
    # two raw requests
    assert y.count("- |") == 2


def test_body_inject_emits_post_with_content_type():
    t = Target(base_url="https://x.example", path="/api", param="q", inject="body")
    out = nuclei.render_nuclei([_Run(_Res("<x>", [_Find("<X>", "XSS Injection", ["c"])]))], t)
    (_, y), = out.items()
    assert "POST {{BaseURL}}/api" in y
    assert "Content-Type: application/x-www-form-urlencoded" in y


def test_render_one_template_per_finding():
    res = _Res("<script>alert(1)</script>", [
        _Find("<ScRiPt>alert(1)</ScRiPt>", "XSS Injection", ["xss_tag_case_mix"]),
        _Find("<svg onload=alert(1)>", "XSS Injection", ["xss_svg_onload"]),
    ])
    t = Target(base_url="https://x.example", path="/s", param="q")
    out = nuclei.render_nuclei([_Run(res)], t)
    assert len(out) == 2
    assert all("XSS Injection" in y for y in out.values())


def test_write_nuclei_writes_files(tmp_path):
    t = Target(base_url="https://x.example", path="/s", param="q")
    run = _Run(_Res("a' OR 1=1", [_Find("a'/**//**/OR/**//**/1=1", "SQL Injection", ["x"])]))
    paths = nuclei.write_nuclei([run], t, str(tmp_path))
    assert len(paths) == 1 and paths[0].endswith(".yaml")
    written = list(tmp_path.glob("waffen-bypass-sql-injection-*.yaml"))
    assert len(written) == 1
    content = written[0].read_text()
    assert "req-condition: true" in content


def test_pair_input_shape():
    # render_nuclei also accepts (seed, finding) tuples
    t = Target(base_url="https://x.example", path="/s", param="q")
    out = nuclei.render_nuclei([("a' OR 1=1", _Find("a'/**/OR/**/1=1", "SQL Injection", ["x"]))], t)
    assert len(out) == 1


def test_generated_templates_pass_nuclei_validate(tmp_path):
    if not shutil.which("nuclei"):
        pytest.skip("nuclei binary not installed")
    t = Target(base_url="https://x.example", path="/rest/products/search", param="q")
    runs = [
        _Run(_Res("1' UNION SELECT 1-- -",
                  [_Find("1'/**//**/UNION/**//**/SELECT/**//**/1-- -", "SQL Injection", ["sql_adjacent_comment"])])),
        _Run(_Res("<script>alert(1)</script>",
                  [_Find("<svg/onload=alert(1)>", "XSS Injection", ["xss_svg_onload"])])),
    ]
    nuclei.write_nuclei(runs, t, str(tmp_path))
    p = subprocess.run(["nuclei", "-validate", "-t", str(tmp_path), "-duc", "-disable-update-check"],
                       capture_output=True, text=True, timeout=120)
    combined = p.stdout + p.stderr
    assert "validated successfully" in combined or p.returncode == 0, combined[-800:]
