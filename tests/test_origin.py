"""Tests for origin IP discovery."""
from unittest.mock import patch, MagicMock

import pytest

from waffen.recon.origin import (
    OriginCandidate,
    OriginDiscovery,
    OriginReport,
    _extract_spf_ips,
    _ORIGIN_SUBDOMAINS,
)


# ---- helpers ---------------------------------------------------------------

def _mock_resolver(mapping: dict):
    """Return a resolver that maps hostnames to IP lists."""
    def resolver(hostname):
        return mapping.get(hostname, [])
    return resolver


def _mock_mx(records: list[str]):
    def mx_resolver(domain):
        return records
    return mx_resolver


def _mock_txt(records: list[str]):
    def txt_resolver(domain):
        return records
    return txt_resolver


def _mock_headers(headers: dict):
    def fetcher(url):
        return headers
    return fetcher


def _mock_verifier(verified_ips: set):
    def verifier(ip, domain):
        return ip in verified_ips
    return verifier


# ---- OriginCandidate -------------------------------------------------------

class TestOriginCandidate:
    def test_fields(self):
        c = OriginCandidate("1.2.3.4", "subdomain", "high", "staging → 1.2.3.4")
        assert c.ip == "1.2.3.4"
        assert c.source == "subdomain"
        assert c.confidence == "high"


# ---- SPF extraction --------------------------------------------------------

class TestSPFExtraction:
    def test_extracts_ip4(self):
        ips = _extract_spf_ips(["v=spf1 ip4:10.0.0.1 ip4:10.0.0.2 -all"])
        assert "10.0.0.1" in ips
        assert "10.0.0.2" in ips

    def test_extracts_ip6(self):
        ips = _extract_spf_ips(["v=spf1 ip6:2001:db8::1 -all"])
        assert "2001:db8::1" in ips

    def test_ignores_non_spf(self):
        ips = _extract_spf_ips(["some random txt record ip4:1.2.3.4"])
        assert ips == []

    def test_strips_cidr(self):
        ips = _extract_spf_ips(["v=spf1 ip4:10.0.0.0/24 -all"])
        assert "10.0.0.0" in ips

    def test_empty_records(self):
        assert _extract_spf_ips([]) == []


# ---- Subdomain discovery ---------------------------------------------------

class TestSubdomainDiscovery:
    def test_finds_origin_subdomain(self):
        resolver = _mock_resolver({
            "example.com": ["1.1.1.1"],
            "origin.example.com": ["10.0.0.1"],
        })
        d = OriginDiscovery("example.com", resolver=resolver,
                           mx_resolver=_mock_mx([]),
                           txt_resolver=_mock_txt([]),
                           header_fetcher=_mock_headers({}))
        report = d.discover()
        ips = [c.ip for c in report.candidates]
        assert "10.0.0.1" in ips

    def test_high_confidence_for_origin_subdomains(self):
        resolver = _mock_resolver({
            "example.com": ["1.1.1.1"],
            "direct.example.com": ["10.0.0.1"],
        })
        d = OriginDiscovery("example.com", resolver=resolver,
                           mx_resolver=_mock_mx([]),
                           txt_resolver=_mock_txt([]),
                           header_fetcher=_mock_headers({}))
        report = d.discover()
        direct = [c for c in report.candidates if c.ip == "10.0.0.1"]
        assert direct[0].confidence == "high"

    def test_medium_confidence_for_staging(self):
        resolver = _mock_resolver({
            "example.com": ["1.1.1.1"],
            "staging.example.com": ["10.0.0.2"],
        })
        d = OriginDiscovery("example.com", resolver=resolver,
                           mx_resolver=_mock_mx([]),
                           txt_resolver=_mock_txt([]),
                           header_fetcher=_mock_headers({}))
        report = d.discover()
        staging = [c for c in report.candidates if c.ip == "10.0.0.2"]
        assert staging[0].confidence == "medium"

    def test_excludes_main_ip(self):
        resolver = _mock_resolver({
            "example.com": ["1.1.1.1"],
            "staging.example.com": ["1.1.1.1"],  # same as main
        })
        d = OriginDiscovery("example.com", resolver=resolver,
                           mx_resolver=_mock_mx([]),
                           txt_resolver=_mock_txt([]),
                           header_fetcher=_mock_headers({}))
        report = d.discover()
        assert len(report.candidates) == 0

    def test_no_subdomains_resolve(self):
        resolver = _mock_resolver({"example.com": ["1.1.1.1"]})
        d = OriginDiscovery("example.com", resolver=resolver,
                           mx_resolver=_mock_mx([]),
                           txt_resolver=_mock_txt([]),
                           header_fetcher=_mock_headers({}))
        report = d.discover()
        assert len(report.candidates) == 0


# ---- Mail record discovery -------------------------------------------------

class TestMailDiscovery:
    def test_finds_self_hosted_mx(self):
        # Use a MX hostname that is NOT in _ORIGIN_SUBDOMAINS to avoid
        # the subdomain check claiming the IP first.
        resolver = _mock_resolver({
            "example.com": ["1.1.1.1"],
            "mailrelay.example.com": ["10.0.0.5"],
        })
        d = OriginDiscovery("example.com", resolver=resolver,
                           mx_resolver=_mock_mx(["mailrelay.example.com"]),
                           txt_resolver=_mock_txt([]),
                           header_fetcher=_mock_headers({}))
        report = d.discover()
        mail_cands = [c for c in report.candidates if c.source == "mail"]
        assert len(mail_cands) == 1
        assert mail_cands[0].ip == "10.0.0.5"
        assert mail_cands[0].confidence == "high"

    def test_external_mx_low_confidence(self):
        resolver = _mock_resolver({
            "example.com": ["1.1.1.1"],
            "mx1.googlemail.com": ["172.16.0.1"],
        })
        d = OriginDiscovery("example.com", resolver=resolver,
                           mx_resolver=_mock_mx(["mx1.googlemail.com"]),
                           txt_resolver=_mock_txt([]),
                           header_fetcher=_mock_headers({}))
        report = d.discover()
        mail_cands = [c for c in report.candidates if c.source == "mail"]
        assert mail_cands[0].confidence == "low"

    def test_no_mx(self):
        resolver = _mock_resolver({"example.com": ["1.1.1.1"]})
        d = OriginDiscovery("example.com", resolver=resolver,
                           mx_resolver=_mock_mx([]),
                           txt_resolver=_mock_txt([]),
                           header_fetcher=_mock_headers({}))
        report = d.discover()
        assert all(c.source != "mail" for c in report.candidates)


# ---- SPF discovery ---------------------------------------------------------

class TestSPFDiscovery:
    def test_finds_spf_ip(self):
        resolver = _mock_resolver({"example.com": ["1.1.1.1"]})
        d = OriginDiscovery("example.com", resolver=resolver,
                           mx_resolver=_mock_mx([]),
                           txt_resolver=_mock_txt(["v=spf1 ip4:10.0.0.9 -all"]),
                           header_fetcher=_mock_headers({}))
        report = d.discover()
        spf_cands = [c for c in report.candidates if c.source == "spf"]
        assert len(spf_cands) == 1
        assert spf_cands[0].ip == "10.0.0.9"
        assert spf_cands[0].confidence == "medium"


# ---- Header leak discovery -------------------------------------------------

class TestHeaderDiscovery:
    def test_finds_ip_in_x_served_by(self):
        resolver = _mock_resolver({"example.com": ["1.1.1.1"]})
        d = OriginDiscovery("example.com", resolver=resolver,
                           mx_resolver=_mock_mx([]),
                           txt_resolver=_mock_txt([]),
                           header_fetcher=_mock_headers({"X-Served-By": "10.0.0.7"}))
        report = d.discover()
        hdr_cands = [c for c in report.candidates if c.source == "header"]
        assert len(hdr_cands) == 1
        assert hdr_cands[0].ip == "10.0.0.7"
        assert hdr_cands[0].confidence == "high"

    def test_ignores_non_ip_header(self):
        resolver = _mock_resolver({"example.com": ["1.1.1.1"]})
        d = OriginDiscovery("example.com", resolver=resolver,
                           mx_resolver=_mock_mx([]),
                           txt_resolver=_mock_txt([]),
                           header_fetcher=_mock_headers({"Via": "1.1 varnish"}))
        report = d.discover()
        hdr_cands = [c for c in report.candidates if c.source == "header"]
        assert len(hdr_cands) == 0

    def test_no_leak_headers(self):
        resolver = _mock_resolver({"example.com": ["1.1.1.1"]})
        d = OriginDiscovery("example.com", resolver=resolver,
                           mx_resolver=_mock_mx([]),
                           txt_resolver=_mock_txt([]),
                           header_fetcher=_mock_headers({}))
        report = d.discover()
        assert all(c.source != "header" for c in report.candidates)


# ---- Deduplication and sorting ---------------------------------------------

class TestDedup:
    def test_deduplicates_by_ip(self):
        resolver = _mock_resolver({
            "example.com": ["1.1.1.1"],
            "origin.example.com": ["10.0.0.1"],
            "direct.example.com": ["10.0.0.1"],  # same IP
        })
        d = OriginDiscovery("example.com", resolver=resolver,
                           mx_resolver=_mock_mx([]),
                           txt_resolver=_mock_txt([]),
                           header_fetcher=_mock_headers({}))
        report = d.discover()
        ips = [c.ip for c in report.candidates]
        assert ips.count("10.0.0.1") == 1

    def test_keeps_highest_confidence(self):
        resolver = _mock_resolver({
            "example.com": ["1.1.1.1"],
            "origin.example.com": ["10.0.0.1"],  # high
            "staging.example.com": ["10.0.0.1"],  # medium (same IP)
        })
        d = OriginDiscovery("example.com", resolver=resolver,
                           mx_resolver=_mock_mx([]),
                           txt_resolver=_mock_txt([]),
                           header_fetcher=_mock_headers({}))
        report = d.discover()
        c = [c for c in report.candidates if c.ip == "10.0.0.1"][0]
        assert c.confidence == "high"

    def test_sorted_by_confidence(self):
        resolver = _mock_resolver({
            "example.com": ["1.1.1.1"],
            "staging.example.com": ["10.0.0.2"],  # medium
        })
        d = OriginDiscovery("example.com", resolver=resolver,
                           mx_resolver=_mock_mx(["mail.example.com"]),
                           txt_resolver=_mock_txt([]),
                           header_fetcher=_mock_headers({"X-Served-By": "10.0.0.7"}))
        # mock mail resolution
        orig_resolve = resolver
        def multi_resolve(h):
            if h == "mail.example.com":
                return ["10.0.0.5"]
            return orig_resolve(h)
        d._resolve = multi_resolve
        report = d.discover()
        confs = [c.confidence for c in report.candidates]
        assert confs == sorted(confs, key=lambda c: {"high": 0, "medium": 1, "low": 2}[c])


# ---- Verification ----------------------------------------------------------

class TestVerification:
    def test_verifies_candidates(self):
        resolver = _mock_resolver({
            "example.com": ["1.1.1.1"],
            "origin.example.com": ["10.0.0.1"],
            "staging.example.com": ["10.0.0.2"],
        })
        d = OriginDiscovery("example.com", resolver=resolver,
                           mx_resolver=_mock_mx([]),
                           txt_resolver=_mock_txt([]),
                           header_fetcher=_mock_headers({}),
                           verifier=_mock_verifier({"10.0.0.1"}))
        report = d.discover_and_verify()
        assert len(report.verified) == 1
        assert report.verified[0].ip == "10.0.0.1"
        assert len(report.unverified) == 1
        assert report.unverified[0].ip == "10.0.0.2"


# ---- Report ----------------------------------------------------------------

class TestReport:
    def test_as_dict(self):
        report = OriginReport(
            domain="example.com",
            main_ips=["1.1.1.1"],
            candidates=[OriginCandidate("10.0.0.1", "subdomain", "high", "origin → 10.0.0.1")],
            verified=[OriginCandidate("10.0.0.1", "subdomain", "high", "origin → 10.0.0.1")],
        )
        d = report.as_dict()
        assert d["domain"] == "example.com"
        assert len(d["candidates"]) == 1
        assert d["verified"] == ["10.0.0.1"]

    def test_empty_report(self):
        report = OriginReport(domain="example.com")
        d = report.as_dict()
        assert d["candidates"] == []
        assert d["verified"] == []


# ---- Subdomain list --------------------------------------------------------

class TestSubdomainList:
    def test_has_common_entries(self):
        for sub in ("direct", "origin", "backend", "staging", "dev", "api", "mail", "ftp"):
            assert sub in _ORIGIN_SUBDOMAINS

    def test_no_duplicates(self):
        assert len(_ORIGIN_SUBDOMAINS) == len(set(_ORIGIN_SUBDOMAINS))
