"""Tests for the eval HTML report renderer (escaping + structure)."""
from waffen.eval.coverage import EvalResult, ClassScore
from waffen.report.html import render_eval_html


def _result():
    r = EvalResult(target="https://waf.example")
    r.per_class["XSS Injection"] = ClassScore(blocked=8, through=2)
    r.per_class["SQL Injection"] = ClassScore(blocked=10, through=0)
    r.through_samples["XSS Injection"] = ['<script>alert(1)</script>', '"><svg/onload=alert(1)>']
    r.benign_total = 10
    r.benign_blocked = 1
    return r


def test_payloads_are_escaped():
    h = render_eval_html(_result())
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in h
    assert "<script>alert(1)</script>" not in h   # never emit a raw live payload


def test_has_core_sections_and_numbers():
    h = render_eval_html(_result(), meta={"cases": 10, "inject": "query"})
    assert h.startswith("<!doctype html>")
    assert "<title>WAFFEN" in h
    assert "Overall coverage" in h and "False positives" in h
    assert "80.0%" in h            # XSS 8/10
    assert "10.0%" in h            # FP 1/10
    assert "SQL Injection" in h and "XSS Injection" in h


def test_dark_mode_and_selfcontained():
    h = render_eval_html(_result())
    assert "prefers-color-scheme: dark" in h
    assert "http://" not in h and "https://cdn" not in h  # no external resources
    assert "cases: 10" not in h  # meta only shown when passed; none here


def test_empty_gaps_message():
    r = EvalResult(target="t")
    r.per_class["SQL Injection"] = ClassScore(blocked=5, through=0)
    h = render_eval_html(r)
    assert "No coverage gaps recorded." in h
