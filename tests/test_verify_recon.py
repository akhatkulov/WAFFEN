"""Tests for waffen.verify and waffen.recon — run offline with fake senders.

pytest may not be installed in this environment; this module is written so it
can also be driven by simply importing it and calling each test_* function
(see tests/test_engine.py for the same convention).
"""
from __future__ import annotations

from waffen.core.oracle import Oracle, Target, Response
from waffen.verify import verify
from waffen.recon import fingerprint, WafGuess


def _oracle(sender):
    return Oracle(Target(base_url="mock://local"), sender=sender)


# ---------------------------------------------------------------------------
# verify(): XSS
# ---------------------------------------------------------------------------
def test_xss_unescaped_reflection_is_exploitable():
    payload = "<script>alert(1)</script>"

    def sender(p):
        body = f"<html><body>Results for: {p}</body></html>"
        return Response("THROUGH", "200", len(body), 0.01, body)

    v = verify(_oracle(sender), payload, "XSS Injection")
    assert v.exploitable is True
    assert v.confidence > 0.5
    assert v.attack_class == "XSS Injection"


def test_xss_escaped_reflection_is_not_exploitable():
    payload = "<script>alert(1)</script>"

    def sender(p):
        escaped = p.replace("<", "&lt;").replace(">", "&gt;")
        body = f"<html><body>Results for: {escaped}</body></html>"
        return Response("THROUGH", "200", len(body), 0.01, body)

    v = verify(_oracle(sender), payload, "XSS Injection")
    assert v.exploitable is False
    assert "encoded" in v.reason.lower()


# ---------------------------------------------------------------------------
# verify(): SQL Injection
# ---------------------------------------------------------------------------
def test_sqli_error_signature_is_exploitable():
    payload = "' OR 1=1-- -"

    def sender(p):
        body = "You have an error in your SQL syntax; check the manual..."
        return Response("THROUGH", "500", len(body), 0.01, body)

    v = verify(_oracle(sender), payload, "SQL Injection")
    assert v.exploitable is True


def test_sqli_boolean_differential_is_exploitable():
    payload = "' OR 1=1-- -"

    def sender(p):
        if "1=2" in p:
            body = "<html>No results</html>"
        else:
            body = "<html>" + ("row " * 200) + "</html>"
        return Response("THROUGH", "200", len(body), 0.01, body)

    v = verify(_oracle(sender), payload, "SQL Injection")
    assert v.exploitable is True


def test_sqli_identical_responses_not_exploitable():
    payload = "' OR 1=1-- -"

    def sender(p):
        body = "<html>same every time</html>"
        return Response("THROUGH", "200", len(body), 0.01, body)

    v = verify(_oracle(sender), payload, "SQL Injection")
    assert v.exploitable is False


# ---------------------------------------------------------------------------
# verify(): Command Injection
# ---------------------------------------------------------------------------
def test_cmdi_echo_marker_confirms_execution():
    payload = "; whoami"

    def sender(p):
        # simulate a shell that actually runs whatever follows "echo "
        if "echo " in p:
            token = p.split("echo ", 1)[1].strip()
            body = f"<pre>{token}</pre>"
        else:
            body = "<pre>no output</pre>"
        return Response("THROUGH", "200", len(body), 0.01, body)

    v = verify(_oracle(sender), payload, "Command Injection")
    assert v.exploitable is True


def test_cmdi_no_marker_not_exploitable():
    payload = "; whoami"

    def sender(p):
        body = "<pre>static page, nothing executed</pre>"
        return Response("THROUGH", "200", len(body), 0.01, body)

    v = verify(_oracle(sender), payload, "Command Injection")
    assert v.exploitable is False


# ---------------------------------------------------------------------------
# verify(): Directory Traversal / File Inclusion
# ---------------------------------------------------------------------------
def test_traversal_passwd_signature_is_exploitable():
    payload = "../../../../etc/passwd"

    def sender(p):
        body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin"
        return Response("THROUGH", "200", len(body), 0.01, body)

    v = verify(_oracle(sender), payload, "Directory Traversal")
    assert v.exploitable is True

    v2 = verify(_oracle(sender), "/etc/passwd", "File Inclusion")
    assert v2.exploitable is True


def test_traversal_no_signature_not_exploitable():
    payload = "../../../../etc/passwd"

    def sender(p):
        body = "<html>404 not found</html>"
        return Response("THROUGH", "404", len(body), 0.01, body)

    v = verify(_oracle(sender), payload, "Directory Traversal")
    assert v.exploitable is False


# ---------------------------------------------------------------------------
# verify(): SSTI
# ---------------------------------------------------------------------------
def test_ssti_product_reflected_is_exploitable():
    payload = "{{7*7}}"

    def sender(p):
        # simulate a real template engine: extract "{{a*b}}" and evaluate it
        import re
        m = re.search(r"\{\{(\d+)\*(\d+)\}\}", p)
        result = str(int(m.group(1)) * int(m.group(2))) if m else "0"
        body = f"<html>{result}</html>"
        return Response("THROUGH", "200", len(body), 0.01, body)

    v = verify(_oracle(sender), payload, "SSTI")
    assert v.exploitable is True


def test_ssti_no_evaluation_not_exploitable():
    payload = "{{7*7}}"

    def sender(p):
        body = f"<html>{p}</html>"  # reflected verbatim, never evaluated
        return Response("THROUGH", "200", len(body), 0.01, body)

    v = verify(_oracle(sender), payload, "SSTI")
    assert v.exploitable is False


# ---------------------------------------------------------------------------
# verify(): unknown class
# ---------------------------------------------------------------------------
def test_unknown_class_has_no_verifier():
    def sender(p):
        return Response("THROUGH", "200", 10, 0.01, "ok")

    # a class with no registered checker (XXE has seeds elsewhere but no verifier yet)
    v = verify(_oracle(sender), "whatever", "XML External Entity")
    assert v.exploitable is False
    assert v.confidence == 0.0
    assert "no verifier" in v.reason.lower()


# ---------------------------------------------------------------------------
# fingerprint()
# ---------------------------------------------------------------------------
def test_fingerprint_detects_redeye_as_top_guess():
    block_body = ("<!doctype html><title>403 Forbidden</title>"
                  "Request blocked by RedEye")

    def sender(p):
        return Response("BLOCKED", "403", len(block_body), 0.01, block_body)

    t = Target(base_url="mock://local")
    guesses = fingerprint(t, sender=sender)
    assert guesses, "expected at least one WAF guess"
    assert isinstance(guesses[0], WafGuess)
    assert guesses[0].name == "RedEye"
    assert guesses[0].confidence > 0


def test_fingerprint_no_match_returns_empty_list():
    def sender(p):
        return Response("THROUGH", "200", 20, 0.01, "<html>plain app, no WAF</html>")

    t = Target(base_url="mock://local")
    guesses = fingerprint(t, sender=sender)
    assert guesses == []


def test_fingerprint_header_based_cloudflare_detection():
    class FakeResp:
        def __init__(self, body, headers):
            self.code = "200"
            self.body = body
            self.headers = headers

    def sender(p):
        return FakeResp("<html>ok</html>", {"server": "cloudflare", "cf-ray": "abc123-DFW"})

    t = Target(base_url="mock://local")
    guesses = fingerprint(t, sender=sender)
    assert guesses and guesses[0].name == "Cloudflare"


def test_fingerprint_generic_behavioral_differential():
    # No vendor signature (e.g. OWASP CRS behind nginx: generic 403, Server: nginx),
    # but the benign probe passes and the attack probe is blocked -> report a generic
    # inline WAF instead of a misleading empty "no WAF" result.
    def sender(p):
        if "OR 1=1" in p or "script" in p:           # the malicious probe
            return Response("BLOCKED", "403", 146, 0.01,
                            "<html><title>403 Forbidden</title><center>nginx</center></html>")
        return Response("THROUGH", "200", 500, 0.01, "<html>home page</html>")

    t = Target(base_url="mock://local")
    guesses = fingerprint(t, sender=sender)
    assert guesses and guesses[0].name == "Generic/Unknown WAF"
    assert guesses[0].confidence == 0.3


def test_fingerprint_app_error_on_attack_is_not_a_waf():
    # a 500 on the attack probe is an origin error, not a block -> no WAF fabricated
    def sender(p):
        if "OR 1=1" in p or "script" in p:
            return Response("THROUGH", "500", 100, 0.01, "Internal Server Error")
        return Response("THROUGH", "200", 500, 0.01, "home")

    t = Target(base_url="mock://local")
    assert fingerprint(t, sender=sender) == []


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
        except Exception as e:
            failures += 1
            print(f"ERROR {fn.__name__}: {e!r}")
    print(f"\n{len(fns) - failures}/{len(fns)} passed")
    if failures:
        sys.exit(1)
