"""The WAFFLED "3-part oracle" for structural / parser-differential bypasses.

A structural transform (json_dup_key, mp_dup_disposition, xml_body, ...) can
return a THROUGH verdict for a reason that has nothing to do with the WAF
being fooled: maybe the backend simply 500'd, or silently dropped the
distorted field, or the WAF passed it precisely because the backend was never
going to parse it anyway. None of that is a real bypass.

A structural bypass is only REAL when all three hold:

  1. passed_waf     — the distorted request got past the WAF (THROUGH).
  2. backend_parsed — the backend actually parsed the distorted envelope
                       (duplicate JSON key, double Content-Disposition, XML
                       wrapper, ...) and extracted the target field at all.
  3. landed         — the payload arrived in that field in exploitable form
                       (reflected intact, not swallowed/escaped/truncated).

(2) and (3) are checked together here: the only externally-observable
evidence that the backend parsed the weird envelope *and* exposed the field
is that the field's content (payload, or a unique marker standing in for it)
shows up in the response. We call that single observation `landed()` and it
backs both signals. Part (3)'s "exploitable form" question — whether the
landed field data would actually fire the vulnerability — is handed off to
`waffen.verify.verifier.verify()`, which already does class-specific
semantic verification (unescaped reflection, DB error signature, etc.).
"""
from __future__ import annotations

import random
import string
from dataclasses import dataclass

from . import verifier as _verifier


@dataclass
class StructuralVerification:
    passed_waf: bool
    backend_parsed: bool
    landed: bool
    exploitable: bool
    confidence: float
    reason: str


# Attack classes where it's safe/meaningful to splice in a random marker token
# in place of (or alongside) the real payload to test pure reflection, without
# disturbing the class-specific syntax the inner verifier relies on. For
# everything else we fall back to looking for a distinctive slice of the
# payload itself.
_MARKER_FRIENDLY = {"XSS Injection"}


def _make_marker() -> str:
    return "wfs" + "".join(random.choices(string.ascii_lowercase + string.digits, k=10))


def landed(oracle, payload: str, *, marker: str | None = None) -> bool:
    """Send `payload` (or a marker-bearing variant of it) and check whether it
    reflects in the response body — evidence the backend actually parsed the
    distorted envelope and surfaced the field's content.

    Returns False (rather than raising) on any send/transport failure.
    """
    try:
        probe = payload
        needle = payload
        if marker:
            probe = marker
            needle = marker
        resp = oracle.send(probe)
        body = resp.body or ""
        if not body:
            return False
        if needle in body:
            return True
        # distinctive slice fallback: a short exact substring match is weaker
        # evidence than a full match but still rules out a blank/boilerplate
        # error page that never touched our data.
        if len(needle) > 12:
            slice_ = needle[: max(12, len(needle) // 2)]
            return slice_ in body
        return False
    except Exception:
        return False


def _reflection_probe(oracle, payload: str, attack_class: str) -> bool:
    """Pick the cheapest reliable reflection check for this attack class."""
    if attack_class in _MARKER_FRIENDLY:
        marker = _make_marker()
        # splice the marker where the payload's injectable text would go, so
        # the distorted envelope is still exercised the same way the real
        # payload would exercise it.
        variant = payload.replace("alert(1)", marker) if "alert(1)" in payload else f"{payload}{marker}"
        return landed(oracle, variant, marker=marker)
    return landed(oracle, payload)


def verify_structural(oracle, payload: str, attack_class: str) -> StructuralVerification:
    """Run the full 3-part oracle against a structural (request_transform-
    carrying) `oracle` for `payload` / `attack_class`.

    Never raises; any checker exception degrades to a low-confidence,
    non-exploitable result rather than crashing the caller.
    """
    try:
        gate = oracle.send(payload)
        passed_waf = bool(getattr(gate, "through", False))
    except Exception as exc:
        return StructuralVerification(
            False, False, False, False, 0.0,
            f"could not even send the probe request: {exc!r}",
        )

    if not passed_waf:
        return StructuralVerification(
            passed_waf=False, backend_parsed=False, landed=False,
            exploitable=False, confidence=0.0,
            reason="WAF blocked the structurally-transformed request — no bypass to verify",
        )

    try:
        reflected = _reflection_probe(oracle, payload, attack_class)
    except Exception as exc:
        return StructuralVerification(
            passed_waf=True, backend_parsed=False, landed=False,
            exploitable=False, confidence=0.1,
            reason=f"passed WAF, but the reflection probe raised an exception: {exc!r}",
        )

    backend_parsed = reflected
    field_landed = reflected

    if not reflected:
        return StructuralVerification(
            passed_waf=True, backend_parsed=False, landed=False,
            exploitable=False, confidence=0.15,
            reason="passed WAF but payload did not reflect — backend likely did not parse "
                   "the distorted envelope (or dropped/escaped the field)",
        )

    try:
        inner = _verifier.verify(oracle, payload, attack_class)
    except Exception as exc:
        return StructuralVerification(
            passed_waf=True, backend_parsed=True, landed=True,
            exploitable=False, confidence=0.3,
            reason=f"passed WAF and reflected, but semantic verification raised an "
                   f"exception: {exc!r}",
        )

    exploitable = bool(passed_waf and field_landed and inner.exploitable)
    confidence = (1.0 if passed_waf else 0.0) + (1.0 if field_landed else 0.0) + inner.confidence
    confidence = round(confidence / 3.0, 3)
    if not exploitable:
        confidence = min(confidence, 0.6)

    if exploitable:
        reason = f"passed WAF, reflected intact, {inner.reason}"
    else:
        reason = (
            f"passed WAF and reflected (backend parsed the envelope), but semantic "
            f"verification found it not exploitable: {inner.reason}"
        )

    return StructuralVerification(
        passed_waf=passed_waf,
        backend_parsed=backend_parsed,
        landed=field_landed,
        exploitable=exploitable,
        confidence=confidence,
        reason=reason,
    )
