"""Tests for the 2026 engine CVE behavioural probe (recon/cve_probe.py)."""
from waffen.core.oracle import BLOCKED, THROUGH, Response, Target
from waffen.recon import cve_probe as cp


def test_classify_present():
    v, _ = cp.classify("403", "200")
    assert v == "PRESENT"


def test_classify_absent_when_both_blocked():
    assert cp.classify("403", "406")[0] == "ABSENT"
    assert cp.classify("406", "403")[0] == "ABSENT"


def test_classify_inconclusive_when_baseline_not_blocked():
    assert cp.classify("200", "200")[0] == "INCONCLUSIVE"
    assert cp.classify("", "200")[0] == "INCONCLUSIVE"


def test_classify_server_errors_and_limits_are_not_bypasses():
    # 400/414/5xx mean the server rejected the request shape, not a WAF bypass
    for noise in ("429", "000", "400", "414", "500", "502", "503"):
        assert cp.classify("403", noise)[0] == "INCONCLUSIVE", noise


def test_classify_only_clean_backend_response_is_present():
    for ok in ("200", "204", "302", "404", "422"):
        assert cp.classify("403", ok)[0] == "PRESENT", ok


def _vuln_sender(payload: str) -> Response:
    """Simulate a removeComments-style WAF: blocks UNION SELECT unless the keyword
    pair is split by adjacent /**//**/ comments, or hidden by base64."""
    low = payload.lower()
    blocked = ("union" in low) and ("/**//**/" not in payload)
    return Response(BLOCKED if blocked else THROUGH, "403" if blocked else "200", 0, 0.0, "")


def test_probe_returns_all_six_cves():
    probes = cp.probe_cve_primitives(Target(base_url="http://x.example"), sender=_vuln_sender)
    cves = {p.cve for p in probes}
    assert cves == {
        "CVE-2026-104259", "GHSA-5m93-4h75-3p2w", "CVE-2026-41508",
        "CVE-2026-104269", "CVE-2026-111497", "GHSA-4j47-8qcr-jf59",
    }
    assert all(p.verdict in {"PRESENT", "ABSENT", "INCONCLUSIVE"} for p in probes)


def test_probe_detects_removecomments_present():
    probes = {p.cve: p for p in
              cp.probe_cve_primitives(Target(base_url="http://x.example"), sender=_vuln_sender)}
    # adjacent /**//**/ slips the simulated detector -> PRESENT
    assert probes["CVE-2026-104259"].verdict == "PRESENT"
    assert "exploitable" in probes["CVE-2026-104259"].detail
