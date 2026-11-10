"""Tests for the expanded WAF signature set in waffen.recon.fingerprint.

Covers the vendors appended to SIGNATURES beyond the original nine. Run offline
with fake senders, same pattern as tests/test_verify_recon.py: a tiny FakeResp
(.code/.body/.headers) exercises header/cookie signatures, and plain
waffen.core.oracle.Response (which has no .headers) exercises body signatures
and the graceful no-headers degradation.

Like tests/test_verify_recon.py this module is also runnable standalone
(``python3 tests/test_fingerprint_expansion.py``) without pytest.
"""
from __future__ import annotations

from waffen.core.oracle import Response, Target
from waffen.recon import WafGuess, fingerprint
from waffen.recon.fingerprint import SIGNATURES


# A deliberately bland block page: must match NO vendor body signature, so that
# header/cookie-only tests below isolate exactly one vendor via its header/cookie.
_NEUTRAL_BODY = "<html><body>hello</body></html>"


class FakeResp:
    """Minimal response with headers (what plain Response lacks). Cookie
    signatures read headers['set-cookie'], so that key must be lowercase."""

    def __init__(self, code, body, headers):
        self.code = code
        self.body = body
        self.headers = headers


def _fp(sender):
    return fingerprint(Target(base_url="mock://local"), sender=sender)


def _top(sender):
    guesses = _fp(sender)
    assert guesses, "expected at least one WAF guess"
    assert isinstance(guesses[0], WafGuess)
    assert guesses[0].confidence > 0
    return guesses[0]


# ---------------------------------------------------------------------------
# Header-based detections
# ---------------------------------------------------------------------------
def test_fingerprint_detects_citrix_netscaler_misspelled_header():
    # "Cneonction" is NetScaler's famously-misspelled Connection header.
    def sender(p):
        return FakeResp("200", _NEUTRAL_BODY, {"cneonction": "close"})

    assert _top(sender).name == "Citrix NetScaler AppFirewall"


def test_fingerprint_detects_dotdefender_denied_header():
    def sender(p):
        return FakeResp("403", _NEUTRAL_BODY, {"x-dotdefender-denied": "1"})

    assert _top(sender).name == "dotDefender (Applicure)"


def test_fingerprint_detects_ibm_datapower_backside_transport_header():
    def sender(p):
        return FakeResp("200", _NEUTRAL_BODY, {"x-backside-transport": "OK"})

    assert _top(sender).name == "IBM DataPower"


def test_fingerprint_detects_azure_application_gateway_server_header():
    def sender(p):
        return FakeResp("403", _NEUTRAL_BODY,
                        {"server": "Microsoft-Azure-Application-Gateway/v2"})

    assert _top(sender).name == "Azure Application Gateway"


# ---------------------------------------------------------------------------
# Cookie-based detections
# ---------------------------------------------------------------------------
def test_fingerprint_detects_fortiweb_session_cookie():
    def sender(p):
        return FakeResp("403", _NEUTRAL_BODY,
                        {"set-cookie": "FORTIWAFSID=0123456789abcdef; path=/; HttpOnly"})

    assert _top(sender).name == "FortiWeb (Fortinet)"


def test_fingerprint_detects_barracuda_counter_session_cookie():
    def sender(p):
        return FakeResp("200", _NEUTRAL_BODY,
                        {"set-cookie": "barra_counter_session=98765; path=/"})

    assert _top(sender).name == "Barracuda"


# ---------------------------------------------------------------------------
# Body-based detection (via plain Response, which carries no .headers — proves
# the body path and the graceful no-headers degradation together).
# ---------------------------------------------------------------------------
def test_fingerprint_detects_palo_alto_block_page_body():
    block_body = ("<html><body>Download of virus/spyware blocked. "
                  "Palo Alto Next Generation Security Platform</body></html>")

    def sender(p):
        return Response("BLOCKED", "403", len(block_body), 0.01, block_body)

    assert _top(sender).name == "Palo Alto Networks"


# ---------------------------------------------------------------------------
# Structural sanity: the append preserved the public table and its shape.
# ---------------------------------------------------------------------------
def test_expansion_preserves_original_signatures_and_grows_table():
    names = [sig["name"] for sig in SIGNATURES]
    # original nine must survive the append unchanged
    for original in ["RedEye", "Cloudflare", "AWS WAF", "Akamai",
                     "Imperva/Incapsula", "F5 BIG-IP ASM", "ModSecurity",
                     "Sucuri", "Wordfence"]:
        assert original in names, f"lost original signature {original!r}"
    # at least 25 vendors appended on top of the original nine
    assert len(SIGNATURES) >= 9 + 25
    # no duplicate vendor names (Sucuri was already present and must not be re-added)
    assert len(names) == len(set(names)), "duplicate vendor name in SIGNATURES"
    assert names.count("Sucuri") == 1


def test_every_signature_has_the_required_shape():
    for sig in SIGNATURES:
        assert set(("name", "header", "cookie", "body")) <= set(sig), sig
        assert isinstance(sig["name"], str) and sig["name"]
        for key in ("header", "cookie", "body"):
            assert isinstance(sig[key], list), (sig["name"], key)
            assert all(isinstance(pat, str) for pat in sig[key]), (sig["name"], key)
        # every vendor must have at least one pattern to match on
        assert sig["header"] or sig["cookie"] or sig["body"], sig["name"]


if __name__ == "__main__":
    import sys
    mod = sys.modules[__name__]
    fns = [getattr(mod, n) for n in dir(mod) if n.startswith("test_")]
    failures = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except AssertionError as e:
            failures += 1
            print(f"FAIL {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failures += 1
            print(f"ERROR {fn.__name__}: {e!r}")
    print(f"\n{len(fns) - failures}/{len(fns)} passed")
    if failures:
        sys.exit(1)
