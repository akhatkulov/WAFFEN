"""Tests for injection-point auto-discovery."""
from dataclasses import dataclass
from unittest.mock import MagicMock

import pytest

from waffen.recon.discover import (
    InjectionDiscovery,
    InjectionPoint,
    DiscoveryReport,
    BENIGN_VALUE,
    KNOWN_BAD,
)


@dataclass
class FakeTarget:
    base_url: str = "https://example.com"
    path: str = "/search"
    param: str = "q"
    timeout: int = 5
    user_agent: str = "test"
    tls_verify: bool = False
    extra_headers: tuple = ()
    cookie: str = ""

    def url(self):
        return self.base_url.rstrip("/") + self.path

    def curl_sec(self, with_i=False):
        return "-sk"


def _make_sender(waf_params=None, waf_locations=None):
    """Return a fake sender that simulates WAF on specified params/locations.

    waf_params: set of param names where WAF is active
    waf_locations: set of location names where WAF is active (if None, all locations)
    """
    waf_params = waf_params or set()
    waf_locations = waf_locations or {"query", "json", "body", "cookie", "header", "path"}

    @dataclass
    class FakeResp:
        code: str

    def sender(inject, param, payload):
        if inject in waf_locations and param in waf_params and payload == KNOWN_BAD:
            return FakeResp(code="403")
        return FakeResp(code="200")

    return sender


# ---- InjectionPoint tests ----

class TestInjectionPoint:
    def test_str_active(self):
        p = InjectionPoint("query", "q", True, "200", "403", 1.0)
        assert "WAF active" in str(p)
        assert "query" in str(p)

    def test_str_inactive(self):
        p = InjectionPoint("header", "Referer", False, "200", "200", 0.0)
        assert "no WAF" in str(p)


# ---- DiscoveryReport tests ----

class TestDiscoveryReport:
    def test_active_points(self):
        rpt = DiscoveryReport(
            target_url="https://x.com",
            points=[
                InjectionPoint("query", "q", True, "200", "403"),
                InjectionPoint("query", "id", False, "200", "200"),
                InjectionPoint("json", "email", True, "200", "403"),
            ],
        )
        assert len(rpt.active_points) == 2
        assert rpt.best.param == "q"

    def test_no_active_best_is_none(self):
        rpt = DiscoveryReport(
            target_url="https://x.com",
            points=[InjectionPoint("query", "id", False, "200", "200")],
        )
        assert rpt.best is None

    def test_as_dict(self):
        rpt = DiscoveryReport(
            target_url="https://x.com", requests_used=10,
            points=[InjectionPoint("query", "q", True, "200", "403", 1.0)],
        )
        d = rpt.as_dict()
        assert d["target"] == "https://x.com"
        assert d["requests_used"] == 10
        assert d["active_points"] == 1
        assert d["points"][0]["waf_active"] is True

    def test_empty_report(self):
        rpt = DiscoveryReport(target_url="https://x.com")
        assert rpt.active_points == []
        assert rpt.best is None


# ---- InjectionDiscovery tests ----

class TestDiscoveryWafDetection:
    def test_detects_waf_on_query_param(self):
        target = FakeTarget()
        sender = _make_sender(waf_params={"q"})
        disc = InjectionDiscovery(target, sender=sender)
        report = disc.discover(query_params=["q"], skip_json=True,
                               skip_headers=True, skip_cookies=True, skip_path=True)
        assert len(report.active_points) == 1
        assert report.active_points[0].param == "q"
        assert report.active_points[0].location == "query"
        assert report.active_points[0].waf_active is True

    def test_no_waf_when_both_200(self):
        target = FakeTarget()
        sender = _make_sender(waf_params=set())  # no WAF anywhere
        disc = InjectionDiscovery(target, sender=sender)
        report = disc.discover(query_params=["q"], skip_json=True,
                               skip_headers=True, skip_cookies=True, skip_path=True)
        assert len(report.active_points) == 0

    def test_multiple_params_some_active(self):
        target = FakeTarget()
        sender = _make_sender(waf_params={"q", "search"})
        disc = InjectionDiscovery(target, sender=sender)
        report = disc.discover(query_params=["q", "search", "id", "page"],
                               skip_json=True, skip_headers=True,
                               skip_cookies=True, skip_path=True)
        active_params = {p.param for p in report.active_points}
        assert active_params == {"q", "search"}

    def test_json_injection_detected(self):
        target = FakeTarget()
        sender = _make_sender(waf_params={"email"}, waf_locations={"json"})
        disc = InjectionDiscovery(target, sender=sender)
        report = disc.discover(query_params=[], json_keys=["email", "name"],
                               skip_headers=True, skip_cookies=True, skip_path=True)
        assert len(report.active_points) == 1
        assert report.active_points[0].location == "json"
        assert report.active_points[0].param == "email"

    def test_header_injection_detected(self):
        target = FakeTarget()
        sender = _make_sender(waf_params={"Referer"}, waf_locations={"header"})
        disc = InjectionDiscovery(target, sender=sender)
        report = disc.discover(query_params=[], skip_json=True,
                               headers=["Referer", "X-Custom"],
                               skip_cookies=True, skip_path=True)
        assert len(report.active_points) == 1
        assert report.active_points[0].param == "Referer"

    def test_cookie_injection_detected(self):
        target = FakeTarget()
        sender = _make_sender(waf_params={"session"}, waf_locations={"cookie"})
        disc = InjectionDiscovery(target, sender=sender)
        report = disc.discover(query_params=[], skip_json=True,
                               skip_headers=True, skip_path=True)
        assert len(report.active_points) == 1
        assert report.active_points[0].location == "cookie"

    def test_path_injection_detected(self):
        target = FakeTarget()
        sender = _make_sender(waf_params={"(path_segment)"}, waf_locations={"path"})
        disc = InjectionDiscovery(target, sender=sender)
        report = disc.discover(query_params=[], skip_json=True,
                               skip_headers=True, skip_cookies=True)
        assert len(report.active_points) == 1
        assert report.active_points[0].location == "path"


class TestDiscoverySorting:
    def test_active_sorted_first(self):
        target = FakeTarget()
        sender = _make_sender(waf_params={"search"})
        disc = InjectionDiscovery(target, sender=sender)
        report = disc.discover(query_params=["id", "search", "page"],
                               skip_json=True, skip_headers=True,
                               skip_cookies=True, skip_path=True)
        assert report.points[0].waf_active is True
        assert report.points[0].param == "search"


class TestDiscoveryRequestCounting:
    def test_request_count(self):
        target = FakeTarget()
        sender = _make_sender(waf_params=set())
        disc = InjectionDiscovery(target, sender=sender)
        report = disc.discover(query_params=["q", "id"], skip_json=True,
                               skip_headers=True, skip_cookies=True, skip_path=True)
        assert report.requests_used == 4  # 2 params × 2 probes each


class TestDiscoveryFullScan:
    def test_full_scan_with_all_locations(self):
        target = FakeTarget()
        sender = _make_sender(waf_params={"q", "email", "Referer", "session", "(path_segment)"},
                              waf_locations={"query", "json", "header", "cookie", "path"})
        disc = InjectionDiscovery(target, sender=sender)
        report = disc.discover(query_params=["q"],
                               json_keys=["email"],
                               headers=["Referer"])
        assert len(report.active_points) >= 4  # q, email, Referer, session, path
        locations = {p.location for p in report.active_points}
        assert "query" in locations
        assert "json" in locations
        assert "header" in locations


class TestDiscoveryEdgeCases:
    def test_target_unreachable(self):
        """When sender returns 000, the point should be excluded (confidence < 0)."""
        @dataclass
        class DownResp:
            code: str = "000"

        target = FakeTarget()
        disc = InjectionDiscovery(target, sender=lambda i, p, v: DownResp())
        report = disc.discover(query_params=["q"], skip_json=True,
                               skip_headers=True, skip_cookies=True, skip_path=True)
        assert len(report.points) == 0  # excluded due to negative confidence

    def test_both_blocked(self):
        """If benign also gets 403, the WAF blocks everything — not a useful point."""
        @dataclass
        class AlwaysBlocked:
            code: str = "403"

        target = FakeTarget()
        disc = InjectionDiscovery(target, sender=lambda i, p, v: AlwaysBlocked())
        report = disc.discover(query_params=["q"], skip_json=True,
                               skip_headers=True, skip_cookies=True, skip_path=True)
        assert len(report.active_points) == 0

    def test_custom_benign_and_bad(self):
        target = FakeTarget()
        calls = []

        @dataclass
        class Resp:
            code: str

        def tracking_sender(inject, param, payload):
            calls.append(payload)
            if payload == "EVIL":
                return Resp(code="403")
            return Resp(code="200")

        disc = InjectionDiscovery(target, sender=tracking_sender,
                                  benign="SAFE", known_bad="EVIL")
        report = disc.discover(query_params=["q"], skip_json=True,
                               skip_headers=True, skip_cookies=True, skip_path=True)
        assert "SAFE" in calls
        assert "EVIL" in calls
        assert report.active_points[0].waf_active is True
