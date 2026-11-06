"""Integration tests for this round's CLI wiring: upload inject, search concurrency,
canary flags, rules output, kb-update, and fingerprint's recommend_plan hookup.

These test the WIRING only (argparse + glue code) — the underlying modules
(oracle upload/canary, search concurrency, report/rules, kb/update, fingerprint
recommend_plan) each have their own dedicated unit tests already.
"""
import contextlib
import io

from waffen.cli import build_parser, main


def _run(argv):
    """Run main() with stdout captured; return (exit_code, stdout_text)."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = main(argv)
    return code, buf.getvalue()


def test_inject_upload_accepted_by_bypass_eval_dataset():
    p = build_parser()
    for sub in ("bypass", "eval", "dataset"):
        ns = p.parse_args([sub, "--inject", "upload"])
        assert ns.inject == "upload"


def test_bypass_mock_with_rules_flag_no_crash():
    code, out = _run(["bypass", "--mock", "--payload", "<script>alert(1)</script>",
                      "--class", "XSS Injection", "--transforms", "identity",
                      "--strategy", "bestfirst", "--stop-on-first",
                      "--max-requests", "50", "--rules"])
    assert code == 0
    assert "BYPASS SWEEP" in out


def test_bypass_mock_concurrency_flag_accepted():
    code, out = _run(["bypass", "--mock", "--payload", "<script>alert(1)</script>",
                      "--class", "XSS Injection", "--transforms", "identity",
                      "--strategy", "beam", "--concurrency", "4",
                      "--stop-on-first", "--max-requests", "100"])
    assert code == 0
    assert "bypass(es)" in out


def test_bypass_mock_canary_flag_accepted_no_crash():
    code, out = _run(["bypass", "--mock", "--payload", "<script>alert(1)</script>",
                      "--class", "XSS Injection", "--transforms", "identity",
                      "--strategy", "beam", "--canary", "benign-probe",
                      "--canary-every", "5", "--stop-on-first", "--max-requests", "50"])
    assert code == 0


def test_eval_upload_class_produces_rule_recommendation(tmp_path):
    out_md = tmp_path / "rules.md"
    code, out = _run(["eval", "--mock", "--class", "Upload Insecure Files",
                      "--inject", "upload", "--param", "file",
                      "--rules", "--rules-out", str(out_md)])
    assert code == 0
    assert "SUGGESTED WAF RULES" in out
    assert out_md.exists()
    text = out_md.read_text()
    assert "Upload Insecure Files" in text
    assert "filename" in text.lower()


def test_eval_no_gaps_reports_nothing_to_recommend():
    # XSS raw signatures ARE blocked by the mock -> no coverage gap -> no rule noise
    code, out = _run(["eval", "--mock", "--class", "XSS Injection", "--rules"])
    assert code == 0
    assert "nothing to recommend" in out


def test_kb_update_no_source_configured_is_a_clean_noop():
    code, out = _run(["kb-update"])
    assert code == 0
    assert "no KB source configured" in out


def test_kb_update_rejects_half_configured_source_gracefully():
    # --name without --kind: falls through to the "no source" branch rather than crashing
    code, out = _run(["kb-update", "--name", "something"])
    assert code == 0


def test_transforms_lists_graphql_placeholder():
    code, out = _run(["transforms"])
    assert code == 0
    assert "graphql_body" in out


def test_fingerprint_help_mentions_no_crash_on_build():
    # fingerprint needs a live target to run meaningfully (no --mock support) —
    # just confirm the subcommand + its argparse wiring (incl. recommend_plan's
    # import path being reachable) doesn't break parser construction.
    p = build_parser()
    ns = p.parse_args(["fingerprint", "--target", "https://example.invalid"])
    assert ns.target == "https://example.invalid"
