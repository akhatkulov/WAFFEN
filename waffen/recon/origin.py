"""Origin IP discovery — find the real server behind a WAF.

If the origin server is accessible directly (by IP with the right Host header),
the WAF is bypassed entirely. This module probes DNS records, common subdomains,
MX records, and response headers to find candidate origin IPs, then optionally
verifies each by sending a direct request.

All techniques use stdlib only (socket, subprocess for dig).
"""
from __future__ import annotations

import socket
import subprocess
import urllib.parse
import urllib.request
import ssl
from dataclasses import dataclass, field


@dataclass
class OriginCandidate:
    ip: str
    source: str
    confidence: str
    evidence: str


@dataclass
class OriginReport:
    domain: str
    main_ips: list[str] = field(default_factory=list)
    candidates: list[OriginCandidate] = field(default_factory=list)
    verified: list[OriginCandidate] = field(default_factory=list)
    unverified: list[OriginCandidate] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "domain": self.domain,
            "main_ips": self.main_ips,
            "candidates": [
                {"ip": c.ip, "source": c.source,
                 "confidence": c.confidence, "evidence": c.evidence}
                for c in self.candidates
            ],
            "verified": [c.ip for c in self.verified],
        }


_ORIGIN_SUBDOMAINS = [
    "direct", "origin", "backend", "real", "server",
    "staging", "stage", "dev", "development", "test",
    "api", "admin", "panel", "cpanel", "webmail",
    "mail", "smtp", "imap", "pop", "pop3",
    "ftp", "sftp", "ssh", "vpn",
    "ns1", "ns2", "dns", "dns1", "dns2",
    "db", "database", "mysql", "postgres", "mongo",
    "internal", "intranet", "old", "legacy", "backup",
    "www2", "web", "web1", "web2", "app", "app1",
]

_CONF_ORDER = {"high": 0, "medium": 1, "low": 2}


def _is_ip(s: str) -> bool:
    """Check if a string is a valid IPv4 or IPv6 address (strict)."""
    # IPv4: must have exactly 4 dotted decimal octets
    parts = s.split(".")
    if len(parts) == 4:
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
    # IPv6
    try:
        socket.inet_pton(socket.AF_INET6, s)
        return True
    except (OSError, ValueError):
        return False


def _resolve(hostname: str) -> list[str]:
    """Resolve hostname to IP addresses via getaddrinfo."""
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ips = list(dict.fromkeys(r[4][0] for r in results))
        return ips
    except (socket.gaierror, OSError):
        return []


def _dig_mx(domain: str) -> list[str]:
    """Get MX record hostnames via dig (falls back to nslookup)."""
    hostnames = []
    try:
        out = subprocess.run(
            ["dig", "+short", "MX", domain],
            capture_output=True, text=True, timeout=10,
        )
        for line in out.stdout.strip().splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                mx_host = parts[-1].rstrip(".")
                if mx_host:
                    hostnames.append(mx_host)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        try:
            out = subprocess.run(
                ["nslookup", "-type=MX", domain],
                capture_output=True, text=True, timeout=10,
            )
            for line in out.stdout.splitlines():
                if "mail exchanger" in line.lower():
                    parts = line.strip().split()
                    mx_host = parts[-1].rstrip(".")
                    if mx_host:
                        hostnames.append(mx_host)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    return hostnames


def _dig_txt(domain: str) -> list[str]:
    """Get TXT records — SPF records may contain origin IPs."""
    records = []
    try:
        out = subprocess.run(
            ["dig", "+short", "TXT", domain],
            capture_output=True, text=True, timeout=10,
        )
        for line in out.stdout.strip().splitlines():
            records.append(line.strip().strip('"'))
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return records


def _extract_spf_ips(txt_records: list[str]) -> list[str]:
    """Extract IP addresses from SPF TXT records."""
    ips = []
    for rec in txt_records:
        if "v=spf1" not in rec.lower():
            continue
        for token in rec.split():
            token_lower = token.lower()
            if token_lower.startswith("ip4:"):
                ip = token[4:].split("/")[0]
                ips.append(ip)
            elif token_lower.startswith("ip6:"):
                ip = token[4:].split("/")[0]
                ips.append(ip)
    return ips


def _fetch_headers(url: str, timeout: int = 10) -> dict[str, str]:
    """Fetch response headers from a URL."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, method="HEAD")
        req.add_header("User-Agent", "WAFFEN/origin-discovery")
        resp = urllib.request.urlopen(req, context=ctx, timeout=timeout)
        return dict(resp.headers)
    except Exception:
        return {}


def _verify_origin_ip(ip: str, domain: str, timeout: int = 5) -> bool:
    """Verify an IP is the real origin by sending a request with Host header."""
    for scheme in ("https", "http"):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            url = f"{scheme}://{ip}/"
            req = urllib.request.Request(url)
            req.add_header("Host", domain)
            req.add_header("User-Agent", "WAFFEN/origin-verify")
            resp = urllib.request.urlopen(req, context=ctx, timeout=timeout)
            body = resp.read(4096).decode(errors="replace")
            if resp.status in (200, 301, 302, 403) and len(body) > 50:
                return True
        except Exception:
            continue
    return False


class OriginDiscovery:
    """Discover origin IPs behind a WAF."""

    def __init__(self, domain: str, *, resolver=None, mx_resolver=None,
                 txt_resolver=None, header_fetcher=None, verifier=None):
        self.domain = domain.lower().strip()
        self._resolve = resolver or _resolve
        self._dig_mx = mx_resolver or _dig_mx
        self._dig_txt = txt_resolver or _dig_txt
        self._fetch_headers = header_fetcher or _fetch_headers
        self._verify = verifier or _verify_origin_ip

    def discover(self) -> OriginReport:
        report = OriginReport(domain=self.domain)
        report.main_ips = self._resolve(self.domain)

        seen_ips: set[str] = set(report.main_ips)
        candidates: list[OriginCandidate] = []

        candidates.extend(self._check_subdomains(seen_ips))
        candidates.extend(self._check_mail_records(seen_ips))
        candidates.extend(self._check_spf_records(seen_ips))
        candidates.extend(self._check_response_headers())

        # dedupe by IP, keep highest confidence
        deduped: dict[str, OriginCandidate] = {}
        for c in candidates:
            if c.ip not in deduped or _CONF_ORDER[c.confidence] < _CONF_ORDER[deduped[c.ip].confidence]:
                deduped[c.ip] = c
        report.candidates = sorted(
            deduped.values(),
            key=lambda c: _CONF_ORDER[c.confidence],
        )
        return report

    def discover_and_verify(self) -> OriginReport:
        report = self.discover()
        for c in report.candidates:
            if self._verify(c.ip, self.domain):
                report.verified.append(c)
            else:
                report.unverified.append(c)
        return report

    def _check_subdomains(self, exclude_ips: set[str]) -> list[OriginCandidate]:
        candidates = []
        for sub in _ORIGIN_SUBDOMAINS:
            hostname = f"{sub}.{self.domain}"
            ips = self._resolve(hostname)
            for ip in ips:
                if ip not in exclude_ips:
                    conf = "high" if sub in ("direct", "origin", "backend", "real", "server") else "medium"
                    candidates.append(OriginCandidate(
                        ip=ip, source="subdomain", confidence=conf,
                        evidence=f"{hostname} → {ip}",
                    ))
                    exclude_ips.add(ip)
        return candidates

    def _check_mail_records(self, exclude_ips: set[str]) -> list[OriginCandidate]:
        candidates = []
        mx_hosts = self._dig_mx(self.domain)
        for mx in mx_hosts:
            ips = self._resolve(mx)
            for ip in ips:
                if ip not in exclude_ips:
                    is_self_hosted = self.domain in mx.lower() or mx.lower().startswith("mail")
                    conf = "high" if is_self_hosted else "low"
                    candidates.append(OriginCandidate(
                        ip=ip, source="mail", confidence=conf,
                        evidence=f"MX {mx} → {ip}",
                    ))
                    exclude_ips.add(ip)
        return candidates

    def _check_spf_records(self, exclude_ips: set[str]) -> list[OriginCandidate]:
        candidates = []
        txt_records = self._dig_txt(self.domain)
        spf_ips = _extract_spf_ips(txt_records)
        for ip in spf_ips:
            if ip not in exclude_ips:
                candidates.append(OriginCandidate(
                    ip=ip, source="spf", confidence="medium",
                    evidence=f"SPF ip4:{ip}",
                ))
                exclude_ips.add(ip)
        return candidates

    def _check_response_headers(self) -> list[OriginCandidate]:
        candidates = []
        leak_headers = [
            "X-Served-By", "X-Backend-Server", "X-Real-IP",
            "X-Origin-Server", "X-Host", "X-Forwarded-Server",
            "Via", "Server",
        ]
        headers = self._fetch_headers(f"https://{self.domain}/")
        for hdr in leak_headers:
            val = headers.get(hdr, "")
            if not val:
                continue
            # check if the value looks like an IP
            parts = val.replace(",", " ").split()
            for part in parts:
                part = part.strip()
                if _is_ip(part):
                    candidates.append(OriginCandidate(
                        ip=part, source="header", confidence="high",
                        evidence=f"{hdr}: {part}",
                    ))
        return candidates
