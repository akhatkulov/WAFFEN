"""Depth tests for the expanded waffen.recon.fingerprint SIGNATURES table.

These exercise the second expansion block of vendor signatures (ported from
wafw00f's plugin set, github.com/EnableSecurity/wafw00f, BSD 3-Clause) and
guard the table's structural invariants: every regex must compile and every
vendor name must be unique.

Like the rest of the suite (see tests/test_verify_recon.py), this runs offline
with a fake sender and can also be driven by importing it and calling each
test_* function directly when pytest is unavailable.
"""
from __future__ import annotations

import re

from waffen.recon.fingerprint import SIGNATURES, fingerprint
from waffen.core.oracle import Target


class FakeResp:
    """Minimal response shape fingerprint() reads: .code / .body / .headers.

    Same convention as the FakeResp in tests/test_verify_recon.py — headers is
    a plain dict keyed by lowercase header name; cookies live under 'set-cookie'.
    """

    def __init__(self, code="200", body="", headers=None):
        self.code = code
        self.body = body
        self.headers = headers or {}


def _fp(resp):
    """Run fingerprint() with a sender that returns `resp` for both probes."""
    t = Target(base_url="mock://local")
    return fingerprint(t, sender=lambda payload, r=resp: r)


# ---------------------------------------------------------------------------
# Newly-added vendors: a crafted fingerprint should name that vendor top.
# Each case keys on a signal that is unique to one vendor (a Server token, a
# vendor cookie name, a branded header, or a branded block-page string), so the
# target vendor must be the sole / top-ranked guess with no cross-match.
# ---------------------------------------------------------------------------
def test_fastly_header_detection():
    # wafw00f fastly.py — X-Fastly-Request-ID is Fastly-only.
    g = _fp(FakeResp(headers={"x-fastly-request-id": "3b70a1d4f9c2"}))
    assert g and g[0].name == "Fastly"


def test_ddosguard_cookie_detection():
    # wafw00f ddosguard.py — __ddg* cookies.
    g = _fp(FakeResp(code="403", headers={"set-cookie": "__ddg1=Qr7z; path=/"}))
    assert g and g[0].name == "DDoS-GUARD"


def test_imunify360_server_detection():
    # wafw00f imunify360.py — Server: imunify360.
    g = _fp(FakeResp(code="403", headers={"server": "imunify360-webshield/1.19"}))
    assert g and g[0].name == "Imunify360"


def test_safedog_cookie_detection():
    # wafw00f safedog.py — safedog-flow-item cookie.
    g = _fp(FakeResp(code="403", headers={"set-cookie": "safedog-flow-item=a1b2c3"}))
    assert g and g[0].name == "Safedog"


def test_huawei_cloud_cookie_detection():
    # wafw00f huaweicloud.py — HWWAFSESID cookie.
    g = _fp(FakeResp(code="418", headers={"set-cookie": "HWWAFSESID=0f3e9a; path=/"}))
    assert g and g[0].name == "Huawei Cloud Firewall"


def test_webseal_server_detection():
    # wafw00f webseal.py — Server: WebSEAL.
    g = _fp(FakeResp(headers={"server": "WebSEAL/6.1.1.0"}))
    assert g and g[0].name == "WebSEAL (IBM)"


def test_anubis_body_detection():
    # wafw00f anubis.py — the within.website challenge asset path is Anubis-only.
    body = ("<html><body>Making sure you're not a bot"
            "<img src='/.within.website/x/cmd/anubis/static/img/pensive.webp'></body></html>")
    g = _fp(FakeResp(code="200", body=body))
    assert g and g[0].name == "Anubis (Techaro)"


def test_xlabs_header_detection():
    # wafw00f xlabssecuritywaf.py — Secured: By XLabs Security.
    g = _fp(FakeResp(code="403", headers={"secured": "By XLabs Security"}))
    assert g and g[0].name == "XLabs Security WAF"


def test_wts_waf_server_detection():
    # wafw00f wts.py — Server: wts/<version>.
    g = _fp(FakeResp(code="403", headers={"server": "wts/1.2.0"}))
    assert g and g[0].name == "WTS-WAF"


def test_link11_server_detection():
    # wafw00f link11.py — Server: rhino-core-shield.
    g = _fp(FakeResp(code="403", headers={"server": "rhino-core-shield"}))
    assert g and g[0].name == "Link11"


def test_stackpath_body_detection():
    # wafw00f stackpath.py — the StackPath-branded <title> block page.
    body = "<html><head><title>StackPath - Access Denied</title></head><body>blocked</body></html>"
    g = _fp(FakeResp(code="403", body=body))
    assert g and g[0].name == "StackPath"


def test_tencent_cloud_body_detection():
    # wafw00f tencent.py — the Tencent Cloud WAF block-page domain.
    g = _fp(FakeResp(code="403", body="redirecting to https://waf.tencent-cloud.com/501page.html"))
    assert g and g[0].name == "Tencent Cloud WAF"


# ---------------------------------------------------------------------------
# Structural invariants of the whole table.
# ---------------------------------------------------------------------------
def test_all_signature_regexes_compile():
    errors = []
    for sig in SIGNATURES:
        for key in ("header", "cookie", "body"):
            for pat in sig.get(key, []):
                try:
                    re.compile(pat)
                except re.error as exc:  # pragma: no cover - only on a bad pattern
                    errors.append(f"{sig['name']} [{key}] /{pat}/: {exc}")
    assert not errors, "uncompilable regex(es):\n" + "\n".join(errors)


def test_no_duplicate_signature_names():
    names = [sig["name"] for sig in SIGNATURES]
    dupes = sorted({n for n in names if names.count(n) > 1})
    assert not dupes, f"duplicate signature names: {dupes}"


def test_every_signature_has_at_least_one_pattern():
    # A signature with no header/cookie/body pattern can never match — guard
    # against an accidentally-empty entry slipping into the table.
    empties = [sig["name"] for sig in SIGNATURES
               if not (sig.get("header") or sig.get("cookie") or sig.get("body"))]
    assert not empties, f"signatures with no patterns: {empties}"


def test_table_roughly_doubled():
    # The expansion targets ~100-120 solid vendors (up from the original 48).
    assert len(SIGNATURES) >= 100, f"expected >=100 signatures, got {len(SIGNATURES)}"


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
        except Exception as e:  # pragma: no cover
            failures += 1
            print(f"ERROR {fn.__name__}: {e!r}")
    print(f"\n{len(fns) - failures}/{len(fns)} passed")
    if failures:
        sys.exit(1)
