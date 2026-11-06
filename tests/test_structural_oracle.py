"""Tests for the WAFFLED 3-part structural oracle — run offline with fake
senders (same convention as tests/test_verify_recon.py / tests/test_engine.py:
importable and runnable without pytest).
"""
from __future__ import annotations

from waffen.core.oracle import Oracle, Target, Response
from waffen.verify.structural import verify_structural, landed, StructuralVerification


def _oracle(sender):
    return Oracle(Target(base_url="mock://local"), sender=sender)


# ---------------------------------------------------------------------------
# All three parts hold: passed WAF + backend parsed/reflected + exploitable
# ---------------------------------------------------------------------------
def test_all_three_parts_hold_is_exploitable_high_confidence():
    payload = "<script>alert(1)</script>"

    def sender(p):
        # the distorted envelope reached the backend, which extracted the
        # field and reflected it verbatim, unescaped.
        body = f"<html><body>echo: {p}</body></html>"
        return Response("THROUGH", "200", len(body), 0.01, body)

    v = verify_structural(_oracle(sender), payload, "XSS Injection")
    assert isinstance(v, StructuralVerification)
    assert v.passed_waf is True
    assert v.backend_parsed is True
    assert v.landed is True
    assert v.exploitable is True
    assert v.confidence > 0.6
    assert "passed WAF" in v.reason


# ---------------------------------------------------------------------------
# Passed WAF but no reflection at all -> backend never parsed the envelope
# ---------------------------------------------------------------------------
def test_passed_waf_but_no_reflection_backend_did_not_parse():
    payload = "<script>alert(1)</script>"

    def sender(p):
        body = "<html><body>static page, nothing reflected here</body></html>"
        return Response("THROUGH", "200", len(body), 0.01, body)

    v = verify_structural(_oracle(sender), payload, "XSS Injection")
    assert v.passed_waf is True
    assert v.backend_parsed is False
    assert v.landed is False
    assert v.exploitable is False
    assert "did not reflect" in v.reason or "not" in v.reason.lower()


# ---------------------------------------------------------------------------
# WAF blocked outright -> part 1 fails, nothing else checked
# ---------------------------------------------------------------------------
def test_waf_blocked_fails_part_one():
    payload = "<script>alert(1)</script>"

    def sender(p):
        body = "<html>Request blocked by RedEye</html>"
        return Response("BLOCKED", "403", len(body), 0.01, body)

    v = verify_structural(_oracle(sender), payload, "XSS Injection")
    assert v.passed_waf is False
    assert v.exploitable is False
    assert v.confidence == 0.0
    assert "blocked" in v.reason.lower()


# ---------------------------------------------------------------------------
# Reflected but escaped (semantic verifier says not exploitable) -> all three
# gate checks (waf/parsed/landed) pass but exploitable stays False because
# the inner verifier found it was neutralized.
# ---------------------------------------------------------------------------
def test_reflected_but_escaped_is_not_exploitable():
    payload = "<script>alert(1)</script>"

    def sender(p):
        escaped = p.replace("<", "&lt;").replace(">", "&gt;")
        body = f"<html><body>{escaped}</body></html>"
        return Response("THROUGH", "200", len(body), 0.01, body)

    v = verify_structural(_oracle(sender), payload, "XSS Injection")
    assert v.passed_waf is True
    # raw payload won't reflect (it's escaped) -> our reflection probe fails,
    # which is itself the correct signal: the field didn't land intact.
    assert v.exploitable is False


# ---------------------------------------------------------------------------
# Inner verifier raising an exception degrades gracefully, no crash
# ---------------------------------------------------------------------------
def test_inner_verifier_exception_degrades_gracefully(monkeypatch):
    payload = "<script>alert(1)</script>"

    def sender(p):
        body = f"<html><body>{p}</body></html>"
        return Response("THROUGH", "200", len(body), 0.01, body)

    import waffen.verify.structural as structural_mod

    def boom(oracle, payload, attack_class):
        raise RuntimeError("inner verifier exploded")

    monkeypatch_target = structural_mod._verifier
    original = monkeypatch_target.verify
    monkeypatch_target.verify = boom
    try:
        v = verify_structural(_oracle(sender), payload, "XSS Injection")
    finally:
        monkeypatch_target.verify = original

    assert isinstance(v, StructuralVerification)
    assert v.exploitable is False
    assert v.passed_waf is True
    assert v.landed is True
    assert "exception" in v.reason.lower()


# ---------------------------------------------------------------------------
# landed() helper: marker reflects
# ---------------------------------------------------------------------------
def test_landed_true_when_payload_reflects():
    def sender(p):
        body = f"<html>{p}</html>"
        return Response("THROUGH", "200", len(body), 0.01, body)

    assert landed(_oracle(sender), "unique-payload-slice-xyz") is True


def test_landed_false_when_body_empty():
    def sender(p):
        return Response("THROUGH", "200", 0, 0.01, "")

    assert landed(_oracle(sender), "unique-payload-slice-xyz") is False


def test_landed_false_on_sender_exception():
    def sender(p):
        raise RuntimeError("transport died")

    assert landed(_oracle(sender), "whatever") is False


# ---------------------------------------------------------------------------
# A sender that returns something odd (e.g. a non-Response-shaped object)
# should not crash verify_structural either.
# ---------------------------------------------------------------------------
def test_send_raises_degrades_gracefully():
    def sender(p):
        raise RuntimeError("connection reset")

    v = verify_structural(_oracle(sender), "<script>alert(1)</script>", "XSS Injection")
    assert isinstance(v, StructuralVerification)
    assert v.exploitable is False
    assert v.passed_waf is False


if __name__ == "__main__":
    import sys

    class _FakeMonkeypatch:
        def setattr(self, *a, **k):
            pass

    mod = sys.modules[__name__]
    fns = [getattr(mod, n) for n in dir(mod) if n.startswith("test_")]
    failures = 0
    for fn in fns:
        try:
            if fn.__code__.co_argcount == 1:
                fn(_FakeMonkeypatch())
            else:
                fn()
            print(f"PASS {fn.__name__}")
        except AssertionError as e:
            failures += 1
            print(f"FAIL {fn.__name__}: {e}")
        except Exception as e:
            failures += 1
            print(f"ERROR {fn.__name__}: {e!r}")
    print(f"\n{len(fns) - failures}/{len(fns)} passed")
    if failures:
        sys.exit(1)
