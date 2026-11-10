"""Phase 5 verifier-coverage expansion: new class verifiers (Open Redirect, SSI,
LDAP, XXE, SSRF) plus the deepened SQL verifier (UNION column-count + time-based
blind). Driven with fake oracles — a payload->Response map (like
tests/test_verifier_hardening.py's MapOracle) and a function-based oracle for the
marker/differential checkers whose probes carry unpredictable random tokens.
"""
from __future__ import annotations

import re

from waffen.core.oracle import Response, Target
from waffen.verify import verifier as V


class MapOracle:
    """Fake oracle mapping a payload string to a canned Response."""
    def __init__(self, mapping, default=None, inject="query"):
        self.mapping = mapping
        self.default = default or Response("THROUGH", "200", 10, 0.0, "ok")
        self.t = Target(base_url="https://t", inject=inject)

    def send(self, payload):
        return self.mapping.get(payload, self.default)


class FuncOracle:
    """Fake oracle computing a Response from the payload — needed where the probe
    carries a random marker/token the checker generates at call time."""
    def __init__(self, fn, inject="query"):
        self.fn = fn
        self.t = Target(base_url="https://t", inject=inject)
        self.sends = []

    def send(self, payload):
        self.sends.append(payload)
        return self.fn(payload)


# ---------------------------------------------------------------------------
# Open Redirect  (Location-header authority confirmation via _fetch_headers)
# ---------------------------------------------------------------------------
def _proc(stdout):
    return type("FakeProc", (), {"stdout": stdout})()


def test_open_redirect_confirms_on_location_host(monkeypatch):
    monkeypatch.setattr(V.subprocess, "run", lambda cmd, **kw: _proc(
        "HTTP/1.1 302 Found\r\nLocation: https://evil.example/cb\r\nContent-Length: 0\r\n\r\n"))
    o = FuncOracle(lambda p: Response("THROUGH", "302", 0, 0.0, ""))
    v = V._check_open_redirect(o, "https://evil.example/cb", "Open Redirect")
    assert v.exploitable and v.confidence >= 0.8


def test_open_redirect_backslash_trick_confirms(monkeypatch):
    # browsers parse '/\evil' as '//evil'; _authority_host folds backslashes to '/'
    monkeypatch.setattr(V.subprocess, "run", lambda cmd, **kw: _proc(
        "HTTP/1.1 301 Moved\r\nLocation: https://evil.example/\r\n\r\n"))
    o = FuncOracle(lambda p: Response("THROUGH", "301", 0, 0.0, ""))
    v = V._check_open_redirect(o, "/\\evil.example", "Open Redirect")
    assert v.exploitable


def test_open_redirect_same_origin_location_not_confirmed(monkeypatch):
    monkeypatch.setattr(V.subprocess, "run", lambda cmd, **kw: _proc(
        "HTTP/1.1 302 Found\r\nLocation: /dashboard\r\n\r\n"))
    o = FuncOracle(lambda p: Response("THROUGH", "302", 0, 0.0, ""))
    v = V._check_open_redirect(o, "https://evil.example/cb", "Open Redirect")
    assert not v.exploitable


def test_open_redirect_host_only_in_query_not_confirmed(monkeypatch):
    # evil host echoed as a ?next= param but NOT the Location authority -> not confirmed
    monkeypatch.setattr(V.subprocess, "run", lambda cmd, **kw: _proc(
        "HTTP/1.1 302 Found\r\nLocation: https://safe.test/login?next=//evil.example\r\n\r\n"))
    o = FuncOracle(lambda p: Response("THROUGH", "302", 0, 0.0, ""))
    v = V._check_open_redirect(o, "//evil.example", "Open Redirect")
    assert not v.exploitable


# ---------------------------------------------------------------------------
# SSI  (arithmetic exec marker)
# ---------------------------------------------------------------------------
def test_ssi_arithmetic_marker_confirms():
    def sender(p):
        m = re.search(r"\$\(\((\d+)\*(\d+)\)\)", p)
        if m:                                   # simulate exec-enabled SSI evaluating it
            return Response("THROUGH", "200", 40, 0.0,
                            f"<html>out: {int(m.group(1)) * int(m.group(2))}</html>")
        return Response("THROUGH", "200", 20, 0.0, "<html>nope</html>")
    v = V._check_ssi(FuncOracle(sender), '<!--#exec cmd="id" -->', "SSI")
    assert v.exploitable and v.confidence >= 0.8


def test_ssi_reflected_not_evaluated_not_confirmed():
    o = FuncOracle(lambda p: Response("THROUGH", "200", len(p), 0.0, f"<html>{p}</html>"))
    v = V._check_ssi(o, '<!--#exec cmd="id" -->', "SSI")
    assert not v.exploitable


# ---------------------------------------------------------------------------
# LDAP Injection  (error signature / boolean differential)
# ---------------------------------------------------------------------------
def test_ldap_error_signature_confirms():
    o = MapOracle({"*)(uid=*)": Response("THROUGH", "500", 80, 0.0,
                   "javax.naming.directory.InvalidSearchFilterException: bad filter")})
    v = V._check_ldap(o, "*)(uid=*)", "LDAP Injection")
    assert v.exploitable and v.confidence >= 0.7


def test_ldap_boolean_differential_confirms():
    payload = "*)(uid=*)"
    false_variant = V._flip_ldap(payload)
    assert false_variant and false_variant != payload
    o = MapOracle({
        payload: Response("THROUGH", "200", 600, 0.0, "directory entry " * 40),
        false_variant: Response("THROUGH", "200", 30, 0.0, "none"),
    })
    v = V._check_ldap(o, payload, "LDAP Injection")
    assert v.exploitable


def test_ldap_identical_responses_not_confirmed():
    payload = "*)(uid=*)"
    false_variant = V._flip_ldap(payload)
    same = Response("THROUGH", "200", 100, 0.0, "same body")
    o = MapOracle({payload: same, false_variant: same})
    v = V._check_ldap(o, payload, "LDAP Injection")
    assert not v.exploitable


# ---------------------------------------------------------------------------
# XXE  (unique nested-entity expansion marker)
# ---------------------------------------------------------------------------
def test_xxe_entity_expansion_confirms():
    def sender(p):
        defs = dict(re.findall(r'<!ENTITY (\w+) "([^"]*)"', p))
        m = re.search(r"<wfxxxe>&(\w+);</wfxxxe>", p)
        if m and m.group(1) in defs:            # simulate the parser expanding &wfx;
            val = re.sub(r"&(\w+);", lambda mm: defs.get(mm.group(1), mm.group(0)),
                         defs[m.group(1)])
            return Response("THROUGH", "200", 40, 0.0, f"<r>parsed {val}</r>")
        return Response("THROUGH", "200", 20, 0.0, "<r>no</r>")
    v = V._check_xxe(FuncOracle(sender), "<xxe/>", "XXE")
    assert v.exploitable and v.confidence >= 0.7


def test_xxe_reflected_not_expanded_not_confirmed():
    # raw reflection: the two halves appear but never contiguously -> not confirmed
    o = FuncOracle(lambda p: Response("THROUGH", "200", len(p), 0.0, f"<echo>{p}</echo>"))
    v = V._check_xxe(o, "<xxe/>", "XXE")
    assert not v.exploitable


# ---------------------------------------------------------------------------
# SSRF  (best-effort metadata signature, honestly low-confidence)
# ---------------------------------------------------------------------------
def test_ssrf_metadata_signature_confirms():
    o = FuncOracle(lambda p: Response("THROUGH", "200", 200, 0.0,
        '{"Code":"Success","AccessKeyId":"ASIAABCDEFGHIJKLMNOP"}\n'
        "iam/security-credentials/web-role"))
    v = V._check_ssrf(o, "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "SSRF")
    assert v.exploitable and v.confidence <= 0.65     # honestly capped


def test_ssrf_internal_host_without_leak_is_unconfirmed():
    o = FuncOracle(lambda p: Response("THROUGH", "200", 10, 0.0, "forbidden"))
    v = V._check_ssrf(o, "http://169.254.169.254/latest/meta-data/", "SSRF")
    assert not v.exploitable and 0.3 <= v.confidence < 0.5


def test_ssrf_no_signal_not_confirmed():
    o = FuncOracle(lambda p: Response("THROUGH", "200", 10, 0.0, "hello world"))
    v = V._check_ssrf(o, "http://example.com/img?u=1", "SSRF")
    assert not v.exploitable


# ---------------------------------------------------------------------------
# Deepened SQL verifier: UNION column-count + time-based blind
# ---------------------------------------------------------------------------
def test_sqli_union_column_count_confirms():
    def sender(p):
        m = re.search(r"UNION SELECT ((?:NULL,?)+)", p, re.I)
        if not m:                               # non-UNION probe (the initial send)
            return Response("THROUGH", "200", 100, 0.0, "<html>home</html>")
        ncols = m.group(1).count("NULL")
        if ncols == 3:                          # columns balance at 3 -> error clears
            return Response("THROUGH", "200", 500, 0.0, "<html>admin secret rows</html>")
        return Response("THROUGH", "200", 80, 0.0,
                        "The used SELECT statements have a different number of columns")
    v = V.verify(FuncOracle(sender), "1' OR 'a'='a", "SQL Injection")
    assert v.exploitable
    assert "UNION" in v.reason or "column" in v.reason.lower()


def test_sqli_time_based_blind_confirms():
    def sender(p):
        m = re.search(r"(?:SLEEP|pg_sleep)\((\d+)\)", p, re.I)
        delay = int(m.group(1)) if m else 0     # a vulnerable backend runs the sleep
        return Response("THROUGH", "200", 100, 0.05 + delay, "<html>ok</html>")
    v = V.verify(FuncOracle(sender), "9 AND 1=1", "SQL Injection")
    assert v.exploitable and "time-based" in v.reason.lower()


def test_sqli_deep_probes_do_not_false_confirm_on_static_site():
    # every response identical, no errors, no timing jump -> must stay NOT exploitable
    o = FuncOracle(lambda p: Response("THROUGH", "200", 120, 0.05, "<html>static</html>"))
    v = V.verify(o, "1' OR 'a'='a", "SQL Injection")
    assert not v.exploitable


# ---------------------------------------------------------------------------
# Dispatch: verify() now routes the new classes (reason != "no verifier")
# ---------------------------------------------------------------------------
def test_verify_dispatches_new_classes(monkeypatch):
    monkeypatch.setattr(V.subprocess, "run", lambda cmd, **kw: _proc(""))
    o = FuncOracle(lambda p: Response("THROUGH", "200", 10, 0.0, "ok"))
    for cls in ("Open Redirect", "SSI", "Server-Side Includes", "LDAP Injection",
                "XXE", "XXE Injection", "SSRF", "Server Side Request Forgery"):
        v = V.verify(o, "probe", cls)
        assert "no verifier" not in v.reason.lower(), cls
        assert v.attack_class == cls


def test_xml_external_entity_name_stays_unregistered():
    # locks the deliberate choice: an existing recon test uses this exact name as the
    # canonical "no verifier" example, so it must remain unregistered.
    o = FuncOracle(lambda p: Response("THROUGH", "200", 10, 0.0, "ok"))
    v = V.verify(o, "x", "XML External Entity")
    assert "no verifier" in v.reason.lower() and not v.exploitable
