"""Tests for waffen.verify.calibrate — runtime auto-calibration (ROADMAP A2).

Uses fake senders (no network / no curl) feeding `Oracle(sender=...)`, same
pattern as tests/test_engine.py. Run via import-and-call (no pytest).
"""
from waffen.core.oracle import Oracle, Response, Target
from waffen.verify.calibrate import calibrate, DEFAULT_BENIGN_PROBES, DEFAULT_ATTACK_PROBES

_MALICIOUS = set(DEFAULT_ATTACK_PROBES)


def _classic_waf_sender(payload: str) -> Response:
    if payload in _MALICIOUS:
        return Response("BLOCKED", "403", 6000, 0.05,
                         "<html>Request blocked by RedEye WAF. Incident logged.</html>")
    return Response("THROUGH", "200", 1200, 0.3, "<html>search results for your query</html>")


def _oracle(sender):
    return Oracle(Target(base_url="mock://local"), sender=sender)


def test_classic_waf_detected_and_classifies():
    o = _oracle(_classic_waf_sender)
    cal = calibrate(o)
    assert cal.waf_detected is True
    assert cal.block_marker  # learned a shared marker
    assert "403" in cal.block_codes
    assert "200" in cal.pass_codes

    block_like = Response("BLOCKED", "403", 6100, 0.06,
                           "<html>Request blocked by RedEye WAF. Incident logged.</html>")
    assert cal.classify(block_like) == "block"
    assert cal.is_block(block_like) is True

    pass_like = Response("THROUGH", "200", 1250, 0.28, "<html>search results for your query</html>")
    assert cal.classify(pass_like) == "pass"
    assert cal.is_block(pass_like) is False


def test_classic_waf_edge_app_403_without_marker():
    """A 403 that is the APP's own response (e.g. auth-required), not the
    WAF's block page: same status code the WAF uses, but no block marker and
    a body size well outside the learned block band. Must not be blindly
    called "block" — should land on "unresolved" (or "pass" if timing/size
    happens to favor it), never silently misclassified as a confident block.
    """
    o = _oracle(_classic_waf_sender)
    cal = calibrate(o)

    app_403 = Response("BLOCKED", "403", 40, 0.31, "<html>403 Forbidden: login required</html>")
    verdict = cal.classify(app_403)
    assert verdict in ("unresolved", "pass")
    assert verdict != "block"


def test_no_waf_present():
    def sender(payload: str) -> Response:
        return Response("THROUGH", "200", 500, 0.2, "<html>same old page every time</html>")

    o = _oracle(sender)
    cal = calibrate(o)
    assert cal.waf_detected is False
    # with no WAF, nothing should ever be classified as a confident block
    resp = Response("THROUGH", "200", 500, 0.2, "<html>same old page every time</html>")
    assert cal.classify(resp) == "pass"
    assert cal.confidence < 0.3


def test_timing_separated_learns_threshold():
    def sender(payload: str) -> Response:
        if payload in _MALICIOUS:
            # WAF rejects fast, at the edge, before reaching the backend
            return Response("BLOCKED", "403", 300, 0.01, "Blocked at edge by RedEye")
        # legit traffic takes much longer reaching the real backend
        return Response("THROUGH", "200", 2000, 0.5, "normal app response")

    o = _oracle(sender)
    cal = calibrate(o)
    assert cal.waf_detected is True
    assert cal.timing_reliable is True
    assert cal.block_is_faster is True
    assert cal.timing_threshold is not None
    assert 0.01 < cal.timing_threshold < 0.5


def test_custom_sample_overrides_and_n():
    calls = []

    def sender(payload: str) -> Response:
        calls.append(payload)
        if payload == "evil":
            return Response("BLOCKED", "403", 10, 0.01, "nope, blocked here")
        return Response("THROUGH", "200", 999, 0.2, "ok page")

    o = _oracle(sender)
    cal = calibrate(o, benign_samples=["fine", "also fine"], attack_samples=["evil"], n=10)
    assert calls == ["fine", "also fine", "evil"]
    assert cal.waf_detected is True
    assert cal.samples == 3


def run_all():
    tests = [v for k, v in globals().items() if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"ok  {t.__name__}")
    print(f"\n{len(tests)} calibration tests passed")


if __name__ == "__main__":
    run_all()
