"""Integration tests against the local CRS lab (Docker).

These tests are SKIPPED if the lab isn't running — they won't break CI.
Start the lab: cd lab && docker compose -p waffen-lab up -d
"""
import subprocess
import pytest


def _lab_running():
    """Check if the CRS lab is up at localhost:18080."""
    try:
        result = subprocess.run(
            ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}",
             "http://localhost:18080/"],
            capture_output=True, timeout=5,
        )
        return result.stdout.strip() == b"200"
    except Exception:
        return False


skip_no_lab = pytest.mark.skipif(not _lab_running(), reason="CRS lab not running (start with: cd lab && docker compose up -d)")


@skip_no_lab
def test_bypass_crs_lab():
    """Full bypass search against local CRS lab."""
    from waffen.cli import build_parser
    args = build_parser().parse_args([
        "bypass", "--target", "http://localhost:18080",
        "--path", "/rest/products/search", "--param", "q",
        "--class", "SQL Injection", "--strategy", "beam",
        "--max-requests", "50", "--width", "4", "--depth", "2",
        "--calibrate",
    ])
    result = args.func(args)
    assert result == 0


@skip_no_lab
def test_fingerprint_crs_lab():
    """Fingerprint should detect ModSecurity/CRS on the lab."""
    from waffen.cli import build_parser
    args = build_parser().parse_args([
        "fingerprint", "--target", "http://localhost:18080",
    ])
    result = args.func(args)
    assert result == 0


@skip_no_lab
def test_score_probe_crs_lab():
    """Score probe should map CRS keyword detection."""
    from waffen.cli import build_parser
    args = build_parser().parse_args([
        "score-probe", "--target", "http://localhost:18080",
        "--path", "/rest/products/search", "--param", "q",
        "--class", "sqli", "--calibrate",
    ])
    result = args.func(args)
    assert result == 0


@skip_no_lab
def test_fuzz_crs_lab():
    """Quick fuzz against CRS lab with built-in wordlist."""
    from waffen.cli import build_parser
    args = build_parser().parse_args([
        "fuzz", "--target", "http://localhost:18080",
        "--path", "/rest/products/search", "--param", "q",
        "--builtin", "sqli", "-c", "5",
    ])
    result = args.func(args)
    assert result == 0


@skip_no_lab
def test_libinjection_scan_crs_lab():
    """libinjection gap scan against CRS lab."""
    from waffen.cli import build_parser
    args = build_parser().parse_args([
        "libinjection-scan", "--target", "http://localhost:18080",
        "--path", "/rest/products/search", "--param", "q",
        "--engines", "sqlite",
    ])
    result = args.func(args)
    assert result == 0
