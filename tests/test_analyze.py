"""Offline log analyzer tests."""
import json

from waffen.report.analyze import (analyze, ban_heuristic, load_log, summary_text, to_html)


def _m(cls, verdict, text="p"):
    return {"text": text, "label": "malicious", "attack_class": cls, "verdict": verdict,
            "url": "http://t/x"}


def _b(verdict):
    return {"text": "hi", "label": "benign", "attack_class": "", "verdict": verdict}


def _records():
    return [
        _m("SQLi", "block"), _m("SQLi", "block"), _m("SQLi", "pass", "' or 1=1"),
        _m("SQLi", "unresolved"),
        _m("XSS", "pass", "<x>"), _m("XSS", "down"), _m("XSS", "block"),
        _m("SSRF", "block"),
        _b("pass"), _b("block"), _b("pass"), _b("pass"),
    ]


def test_analyze_counts():
    r = analyze(_records())
    assert r.target == "http://t/x"
    s = r.per_class["SQLi"]
    assert (s.blocked, s.through, s.unresolved, s.down) == (2, 1, 1, 0)
    assert round(s.coverage, 1) == 66.7
    x = r.per_class["XSS"]
    assert (x.blocked, x.through, x.down) == (1, 1, 1)
    assert r.per_class["SSRF"].coverage == 100.0
    assert r.benign_total == 4 and r.benign_blocked == 1
    assert r.fp_rate == 25.0
    assert r.through_samples["SQLi"] == ["' or 1=1"]


def test_through_samples_capped():
    r = analyze([_m("X", "pass", str(i)) for i in range(80)])
    assert len(r.through_samples["X"]) == 50


def test_load_log_skips_bad_lines(tmp_path):
    p = tmp_path / "log.jsonl"
    p.write_text(json.dumps(_m("A", "block")) + "\n\n{not json\n[1,2]\n"
                 + json.dumps(_b("pass")) + "\n")
    recs = load_log(p)
    assert len(recs) == 2 and recs[0]["attack_class"] == "A"


def test_ban_clean():
    recs = [_m("A", "block" if i % 2 else "pass") for i in range(40)] + [_b("pass")] * 10
    recs = recs[:30] + recs[40:] + recs[30:40]  # keep mixed tail
    h = ban_heuristic(_records()[:8] + [_b("pass")] * 4)
    assert not h.suspected
    assert not ban_heuristic(recs).suspected


def test_ban_high_benign_block():
    h = ban_heuristic([_b("block")] * 3 + [_b("pass")] + [_m("A", "pass")] * 6)
    assert h.suspected and "benign" in h.reason
    assert h.benign_block_rate == 0.75


def test_ban_tail_all_block():
    recs = [_m("A", "block" if i % 2 else "pass") for i in range(50)] + [_m("A", "block")] * 10
    h = ban_heuristic(recs)
    assert h.suspected and "mid-run" in h.reason
    assert h.tail_block_rate == 1.0


def test_summary_text():
    r = analyze(_records())
    t = summary_text(r, ban_heuristic(_records()))
    assert "Overall coverage" in t and "False-positive rate: 25.0%" in t
    for c in ("SQLi", "XSS", "SSRF"):
        assert c in t
    assert "\x1b[" not in t
    # worst-first: XSS (50%) before SQLi (66.7%) before SSRF (100%)
    assert t.index("XSS  ") < t.index("SQLi  ") < t.rindex("SSRF  ")


def test_to_html(tmp_path):
    out = tmp_path / "r.html"
    to_html(analyze(_records()), out, {"title": "t"})
    assert out.read_text(encoding="utf-8").lower().startswith("<!doctype html>")


def test_empty():
    r = analyze([])
    assert r.target == "" and r.benign_total == 0 and r.overall.coverage == 0.0
    h = ban_heuristic([])
    assert not h.suspected and h.benign_block_rate == 0.0 and h.tail_block_rate == 0.0
    assert "Overall coverage" in summary_text(r, h)
