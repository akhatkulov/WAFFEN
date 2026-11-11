"""Tests for the scoring-engine threshold prober (recon/score_probe.py)."""
from waffen.core.oracle import BLOCKED, THROUGH, DOWN, Response, Target
from waffen.recon import score_probe as sp


def _make_sender(blocked_tokens=None):
    """Mock sender: blocks if any of the tokens appear in the payload."""
    blocked_tokens = blocked_tokens or {"union", "select", " or ", "'--", "1=1",
                                         "<script", "onerror", "javascript:", "{{"}

    def sender(payload: str) -> Response:
        low = payload.lower()
        is_blocked = any(t in low for t in blocked_tokens)
        return Response(
            BLOCKED if is_blocked else THROUGH,
            "403" if is_blocked else "200",
            100 if is_blocked else 50,
            0.01 if is_blocked else 0.05,
            "blocked" if is_blocked else "ok",
        )
    return sender


def _oracle(blocked_tokens=None) -> "Oracle":
    from waffen.core.oracle import Oracle
    target = Target(base_url="mock://local", param="q")
    return Oracle(target, sender=_make_sender(blocked_tokens))


# ── keyword map ──────────────────────────────────────────────────────────

def test_keyword_map_detects_blocked_tokens():
    o = _oracle(blocked_tokens={"union", "select", " or ", "1=1"})
    prober = sp.ScoreProber(o)
    kw = prober.map_keyword_detection("sqli")
    detected = {k.token for k in kw if k.detected}
    assert "UNION" in detected
    assert "SELECT" in detected


def test_keyword_map_passes_invisible_tokens():
    o = _oracle(blocked_tokens={"union", "select"})
    prober = sp.ScoreProber(o)
    kw = prober.map_keyword_detection("sqli")
    invisible = {k.token for k in kw if not k.detected}
    assert "GLOB" in invisible
    assert "COLLATE" in invisible
    assert "ISNULL" in invisible


def test_keyword_map_xss_class():
    o = _oracle(blocked_tokens={"<script", "onerror", "javascript:"})
    prober = sp.ScoreProber(o)
    kw = prober.map_keyword_detection("xss")
    detected = {k.token for k in kw if k.detected}
    assert "<script>" in detected
    assert "onerror" in detected
    invisible = {k.token for k in kw if not k.detected}
    assert "<svg" in invisible


# ── progressive strip ────────────────────────────────────────────────────

def test_strip_chain_finds_flip():
    o = _oracle(blocked_tokens={"union", "select", " or ", "1=1", "'--"})
    prober = sp.ScoreProber(o)
    results, flip = prober.probe_threshold("sqli")
    assert flip >= 0
    assert results[flip].verdict == THROUGH
    if flip > 0:
        assert results[flip - 1].verdict == BLOCKED


def test_strip_chain_all_blocked():
    o = _oracle(blocked_tokens={"'", "or", "and", "union", "select", "--"})
    prober = sp.ScoreProber(o)
    results, flip = prober.probe_threshold("sqli")
    assert flip == -1


def test_strip_chain_ssti():
    o = _oracle(blocked_tokens={"{{", "${", "<%="})
    prober = sp.ScoreProber(o)
    results, flip = prober.probe_threshold("ssti")
    assert any(s.verdict == BLOCKED for s in results)
    assert flip >= 0 or all(s.verdict == BLOCKED for s in results)


# ── boundary payloads ────────────────────────────────────────────────────

def test_boundary_payloads_nonempty_on_flip():
    o = _oracle(blocked_tokens={"union", "select", " or ", "1=1", "'--"})
    prober = sp.ScoreProber(o)
    result = prober.run("sqli")
    assert result.flip_index >= 0
    assert len(result.boundary_payloads) > 0
    for b in result.boundary_payloads:
        assert b.verdict == THROUGH


def test_boundary_payloads_empty_when_no_flip():
    o = _oracle(blocked_tokens={"'", "or", "and", "union", "select", "--",
                                 "sleep", "order", "group", "having"})
    prober = sp.ScoreProber(o)
    strip_results, flip = prober.probe_threshold("sqli")
    boundaries = prober.find_boundary_payloads("sqli", strip_results, flip)
    if flip < 0:
        assert len(boundaries) == 0


# ── full run ─────────────────────────────────────────────────────────────

def test_full_run_produces_result():
    o = _oracle()
    prober = sp.ScoreProber(o)
    result = prober.run("sqli")
    assert result.target_url == "mock://local"
    assert result.attack_class == "sqli"
    assert len(result.keyword_map) > 0
    assert len(result.strip_chain) > 0
    assert result.requests_used > 0


def test_full_run_as_dict():
    o = _oracle()
    result = sp.ScoreProber(o).run("sqli")
    d = result.as_dict()
    assert "keyword_map" in d
    assert "strip_chain" in d
    assert "boundary_payloads" in d
    assert d["class"] == "sqli"
    assert isinstance(d["requests"], int)


def test_xss_full_run():
    o = _oracle(blocked_tokens={"<script", "onerror", "javascript:", "alert("})
    result = sp.ScoreProber(o).run("xss")
    assert result.attack_class == "xss"
    assert len(result.keyword_map) > 0
    detected = [k for k in result.keyword_map if k.detected]
    assert len(detected) > 0


# ── CLI integration ──────────────────────────────────────────────────────

def test_cli_score_probe_registers():
    from waffen.cli import build_parser
    parser = build_parser()
    args = parser.parse_args(["score-probe", "--target", "http://example.com",
                              "--class", "sqli"])
    assert args.cmd == "score-probe"
    assert args.attack_class == "sqli"
    assert hasattr(args, "func")
