"""Tests for D3 raw-socket smuggling probe construction and timing detection.

Live desync needs a vulnerable front/back pair to validate; here we test the raw
request BYTES are well-formed per variant and that detect()'s timing logic flags a
stalling probe (via a fake send_raw)."""
from waffen.core import smuggle as S
from waffen.core.rawhttp import parse_target


def test_parse_target():
    assert parse_target("https://x.example/a", "/p") == ("x.example", 443, True, "/p")
    assert parse_target("http://h:8080") == ("h", 8080, False, "/")


def test_clte_bytes_have_both_framings():
    raw = S.clte_req("h", "/").decode()
    assert "Content-Length: 4" in raw and "Transfer-Encoding: chunked" in raw
    assert raw.endswith("1\r\nA\r\nX") and "POST / HTTP/1.1" in raw


def test_tecl_bytes_have_both_framings():
    raw = S.tecl_req("h", "/").decode()
    assert "Content-Length: 6" in raw and "Transfer-Encoding: chunked" in raw
    assert raw.endswith("0\r\n\r\nX")


def test_baseline_is_clean():
    raw = S.baseline_req("h", "/").decode()
    assert "GET / HTTP/1.1" in raw and "Content-Length: 0" in raw
    assert "Transfer-Encoding" not in raw


def test_te_obfuscations_present():
    assert len(S.TE_OBFUSCATIONS) >= 5
    assert any("\t" in t for t in S.TE_OBFUSCATIONS)          # tab variant
    assert any(" : chunked" in t for t in S.TE_OBFUSCATIONS)  # space-before-colon


def test_detect_flags_a_stall(monkeypatch=None):
    # fake send_raw: baseline fast; the first CL.TE probe stalls to timeout; rest fast
    calls = {"n": 0}

    def fake(host, port, tls, raw, timeout=8.0, verify=False):
        r = raw.decode("latin1")
        if r.startswith("GET"):  # baseline
            return {"status": "200", "elapsed": 0.10, "body": "", "error": None}
        calls["n"] += 1
        if calls["n"] == 1:      # first CL.TE probe stalls
            return {"status": "000", "elapsed": timeout, "body": "", "error": None}
        return {"status": "403", "elapsed": 0.20, "body": "", "error": None}

    orig = S.send_raw
    S.send_raw = fake
    try:
        findings = S.detect("http://victim.example", "/", timeout=8.0, stall_factor=3.0)
    finally:
        S.send_raw = orig

    assert findings, "expected probe findings"
    stalled = [f for f in findings if f.suspected]
    assert len(stalled) == 1 and stalled[0].elapsed == 8.0
    assert findings[0].name == "CL.TE"


def test_detect_no_false_positive_when_all_fast():
    def fake(host, port, tls, raw, timeout=8.0, verify=False):
        return {"status": "200", "elapsed": 0.12, "body": "", "error": None}
    orig = S.send_raw
    S.send_raw = fake
    try:
        findings = S.detect("http://victim.example", "/")
    finally:
        S.send_raw = orig
    assert findings and not any(f.suspected for f in findings)
