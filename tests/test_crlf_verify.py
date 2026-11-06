"""Tests for the CRLF-injection verifier — run offline with fake senders and a
monkeypatched header-fetch (no network / no real curl calls).

Written so it can also be driven by simply importing it and calling each
test_* function (see tests/test_verify_recon.py for the same convention).
"""
from __future__ import annotations

import waffen.verify.verifier as verifier
from waffen.core.oracle import Oracle, Target, Response
from waffen.verify import verify


def _oracle(sender):
    return Oracle(Target(base_url="mock://local"), sender=sender)


def test_crlf_marker_in_headers_is_exploitable(monkeypatch):
    # Headers contain our injected marker header (with the real random token
    # the checker generated) -> strong, direct proof.
    def fake_fetch_headers(target, payload, timeout=None):
        import re
        m = re.search(r"X-Waffen-CRLF: wfxcrlf\d+", payload)
        marker = m.group(0) if m else "X-Waffen-CRLF: unknown"
        return f"HTTP/1.1 200 OK\r\n{marker}\r\nContent-Type: text/html"

    monkeypatch.setattr(verifier, "_fetch_headers", fake_fetch_headers)

    def sender(p):
        return Response("THROUGH", "200", 10, 0.01, "<html>ok</html>")

    v = verifier._check_crlf(_oracle(sender), "foo%0d%0abar", "CRLF Injection")
    assert v.exploitable is True
    assert v.confidence >= 0.8
    assert "headers" in v.reason.lower()
    assert v.attack_class == "CRLF Injection"


def test_crlf_marker_only_in_body_is_lower_confidence(monkeypatch):
    # Headers never show the marker, but the token leaks into the body.
    captured_token = {}

    def fake_fetch_headers(target, payload, timeout=None):
        return "HTTP/1.1 200 OK\r\nContent-Type: text/html"

    monkeypatch.setattr(verifier, "_fetch_headers", fake_fetch_headers)

    def sender(p):
        # extract the token waffen generated so the body "reflects" it
        import re
        m = re.search(r"wfxcrlf\d+", p)
        if m:
            captured_token["tok"] = m.group(0)
            return Response("THROUGH", "200", 50, 0.01, f"<html>echo: {m.group(0)}</html>")
        return Response("THROUGH", "200", 10, 0.01, "<html>ok</html>")

    v = verifier._check_crlf(_oracle(sender), "foo%0d%0abar", "CRLF Injection")
    assert captured_token  # sanity: our fake sender actually saw the marker
    assert v.exploitable is True
    assert v.confidence < 0.85
    assert "body" in v.reason.lower()


def test_crlf_marker_absent_is_not_exploitable(monkeypatch):
    def fake_fetch_headers(target, payload, timeout=None):
        return "HTTP/1.1 200 OK\r\nContent-Type: text/html"

    monkeypatch.setattr(verifier, "_fetch_headers", fake_fetch_headers)

    def sender(p):
        return Response("THROUGH", "200", 10, 0.01, "<html>nothing here</html>")

    v = verifier._check_crlf(_oracle(sender), "foo%0d%0abar", "CRLF Injection")
    assert v.exploitable is False
    assert v.confidence < 0.5


def test_crlf_header_fetch_unavailable_falls_back_to_body(monkeypatch):
    # _fetch_headers failing (returns "") must not be treated as "confirmed
    # absent" -- it must fall back to the body check.
    def fake_fetch_headers(target, payload, timeout=None):
        return ""

    monkeypatch.setattr(verifier, "_fetch_headers", fake_fetch_headers)

    def sender(p):
        import re
        m = re.search(r"wfxcrlf\d+", p)
        if m:
            return Response("THROUGH", "200", 50, 0.01, f"<html>echo: {m.group(0)}</html>")
        return Response("THROUGH", "200", 10, 0.01, "<html>ok</html>")

    v = verifier._check_crlf(_oracle(sender), "foo%0d%0abar", "CRLF Injection")
    assert v.exploitable is True
    assert v.confidence < 0.85


def test_verify_dispatches_crlf_injection_class(monkeypatch):
    def fake_fetch_headers(target, payload, timeout=None):
        import re
        m = re.search(r"X-Waffen-CRLF: wfxcrlf\d+", payload)
        marker = m.group(0) if m else "X-Waffen-CRLF: unknown"
        return f"HTTP/1.1 200 OK\r\n{marker}\r\nContent-Type: text/html"

    monkeypatch.setattr(verifier, "_fetch_headers", fake_fetch_headers)

    def sender(p):
        return Response("THROUGH", "200", 10, 0.01, "<html>ok</html>")

    v = verify(_oracle(sender), "foo%0d%0abar", "CRLF Injection")
    assert v.attack_class == "CRLF Injection"
    assert v.exploitable is True


def test_verify_never_raises_for_crlf_even_if_header_fetch_breaks(monkeypatch):
    def broken_fetch_headers(target, payload, timeout=None):
        raise RuntimeError("curl exploded")

    monkeypatch.setattr(verifier, "_fetch_headers", broken_fetch_headers)

    def sender(p):
        return Response("THROUGH", "200", 10, 0.01, "<html>ok</html>")

    v = verify(_oracle(sender), "foo%0d%0abar", "CRLF Injection")
    # verify() wraps checkers in try/except -- a blown-up header fetch must
    # degrade to a safe, low-confidence verdict, not crash the caller.
    assert v.exploitable is False
    assert v.confidence == 0.0
