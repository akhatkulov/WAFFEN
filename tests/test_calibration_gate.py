"""Low-confidence calibration must NOT override the naive verdict — otherwise a
mislearned model (e.g. 0.4 confidence vs open-appsec, overlapping size bands)
classifies benign as 'unresolved' -> BLOCKED and inflates false-positives to 100%."""
from waffen.core.oracle import Oracle, Target, Response, BLOCKED, THROUGH


class _FakeCal:
    def __init__(self, confidence, result):
        self.waf_detected = True
        self.confidence = confidence
        self._result = result

    def classify(self, resp):
        return self._result


def _oracle(cal):
    return Oracle(Target(base_url="mock://x"),
                  sender=lambda p: Response(THROUGH, "200", 10, 0.0, "ok"),
                  calibration=cal, backoff=False)


def test_low_confidence_calibration_does_not_override_benign():
    # calibration would flip benign THROUGH -> BLOCKED, but its confidence is below the gate
    o = _oracle(_FakeCal(0.4, "block"))
    assert o.send("benign").verdict == THROUGH          # naive verdict kept -> no false positive


def test_low_confidence_unresolved_keeps_naive():
    o = _oracle(_FakeCal(0.3, "unresolved"))
    assert o.send("benign").verdict == THROUGH          # the 100%-FP artifact is gone


def test_high_confidence_calibration_still_overrides():
    o = _oracle(_FakeCal(0.9, "block"))
    assert o.send("x").verdict == BLOCKED               # trusted when confident


def test_gate_boundary_is_inclusive():
    o = _oracle(_FakeCal(0.5, "block"))
    assert o.send("x").verdict == BLOCKED               # exactly at threshold -> applies
