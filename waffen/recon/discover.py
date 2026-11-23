"""Injection-point auto-discovery.

Probes a target at multiple request locations (query params, JSON keys,
cookies, headers, path segments) with a benign and a known-bad payload to
find which ones are WAF-inspected.  The WAF signal is a response-code
delta: benign gets 200 while known-bad gets 403 → WAF is active there.

Usage::

    disc = InjectionDiscovery(target)
    points = disc.discover()
    best = points[0]  # sorted by WAF signal strength
"""
from __future__ import annotations

import json
import subprocess
import urllib.parse
from dataclasses import dataclass, field
from typing import Sequence


BENIGN_VALUE = "waffen_probe_safe_7z"
KNOWN_BAD = "' OR 1=1--"

COMMON_QUERY_PARAMS = [
    "q", "search", "query", "s", "keyword", "id", "user", "name",
    "email", "page", "sort", "order", "filter", "category", "type",
    "action", "file", "path", "url", "redirect", "callback", "next",
    "return", "input", "value", "text", "term", "lang",
]

COMMON_JSON_KEYS = [
    "email", "password", "username", "name", "query", "search",
    "message", "comment", "data", "value", "text", "input", "q",
    "title", "body", "content",
]

PROBE_HEADERS = [
    "X-Forwarded-For", "Referer", "User-Agent", "X-Custom-Header",
    "Accept-Language", "Origin",
]


@dataclass
class InjectionPoint:
    location: str       # query | json | cookie | header | path
    param: str
    waf_active: bool
    baseline_code: str
    blocked_code: str
    confidence: float = 0.0  # 0.0–1.0, based on response delta

    def __str__(self) -> str:
        status = "WAF active" if self.waf_active else "no WAF"
        return f"{self.location} {self.param:20s} {status} ({self.baseline_code}→{self.blocked_code})"


@dataclass
class DiscoveryReport:
    target_url: str
    points: list[InjectionPoint] = field(default_factory=list)
    requests_used: int = 0

    @property
    def active_points(self) -> list[InjectionPoint]:
        return [p for p in self.points if p.waf_active]

    @property
    def best(self) -> InjectionPoint | None:
        active = self.active_points
        return active[0] if active else None

    def as_dict(self) -> dict:
        return {
            "target": self.target_url,
            "requests_used": self.requests_used,
            "total_points": len(self.points),
            "active_points": len(self.active_points),
            "points": [
                {"location": p.location, "param": p.param,
                 "waf_active": p.waf_active, "baseline": p.baseline_code,
                 "blocked": p.blocked_code, "confidence": p.confidence}
                for p in self.points
            ],
        }


_BLOCK_CODES = {"403", "406", "429"}


class InjectionDiscovery:
    """Probe a target to find WAF-inspected injection points."""

    def __init__(self, target, *, sender=None, benign: str = BENIGN_VALUE,
                 known_bad: str = KNOWN_BAD):
        self.target = target
        self._sender = sender
        self._benign = benign
        self._known_bad = known_bad
        self._requests = 0

    def _send(self, inject: str, param: str, payload: str) -> str:
        """Send a probe and return the HTTP status code as a string."""
        if self._sender is not None:
            resp = self._sender(inject, param, payload)
            self._requests += 1
            return getattr(resp, "code", str(resp))

        t = self.target
        cmd = ["curl", t.curl_sec(), "-m", str(t.timeout), "-o", "/dev/null",
               "-w", "%{http_code}", "-A", t.user_agent]
        url = t.url()

        if inject == "query":
            qp = urllib.parse.urlencode({param: payload})
            sep = "&" if "?" in url else "?"
            cmd += ["-X", "GET", f"{url}{sep}{qp}"]
        elif inject == "json":
            cmd += ["-X", "POST", url, "-H", "Content-Type: application/json",
                    "-d", json.dumps({param: payload})]
        elif inject == "body":
            cmd += ["-X", "POST", url,
                    "-H", "Content-Type: application/x-www-form-urlencoded",
                    "--data-urlencode", f"{param}={payload}"]
        elif inject == "cookie":
            cmd += ["-X", "GET", url, "-H", f"Cookie: {param}={payload}"]
        elif inject == "header":
            cmd += ["-X", "GET", url, "-H", f"{param}: {payload}"]
        elif inject == "path":
            cmd += ["-X", "GET", f"{url}/{urllib.parse.quote(payload, safe='')}"]
        else:
            return "000"

        from ..core.oracle import apply_auth
        cmd = apply_auth(cmd, t)

        try:
            out = subprocess.run(cmd, capture_output=True, text=True,
                                 timeout=t.timeout + 5).stdout.strip()
            self._requests += 1
            return out or "000"
        except Exception:
            self._requests += 1
            return "000"

    def _probe_point(self, location: str, param: str) -> InjectionPoint:
        baseline = self._send(location, param, self._benign)
        blocked = self._send(location, param, self._known_bad)

        waf_active = (baseline not in _BLOCK_CODES
                      and baseline not in {"000", ""}
                      and blocked in _BLOCK_CODES
                      and baseline != blocked)

        confidence = 0.0
        if waf_active:
            confidence = 0.9
            if blocked == "403":
                confidence = 1.0
        elif baseline == blocked and baseline not in {"000", ""}:
            confidence = 0.0
        elif baseline in {"000", ""}:
            confidence = -1.0  # target unreachable at this point

        return InjectionPoint(
            location=location, param=param,
            waf_active=waf_active,
            baseline_code=baseline, blocked_code=blocked,
            confidence=confidence,
        )

    def discover(self, *, query_params: Sequence[str] | None = None,
                 json_keys: Sequence[str] | None = None,
                 headers: Sequence[str] | None = None,
                 skip_json: bool = False,
                 skip_headers: bool = False,
                 skip_cookies: bool = False,
                 skip_path: bool = False) -> DiscoveryReport:
        """Probe all configured injection locations."""
        report = DiscoveryReport(target_url=self.target.url())

        qparams = list(query_params or COMMON_QUERY_PARAMS)
        for param in qparams:
            point = self._probe_point("query", param)
            if point.confidence >= 0:
                report.points.append(point)

        if not skip_json:
            jkeys = list(json_keys or COMMON_JSON_KEYS)
            for key in jkeys:
                point = self._probe_point("json", key)
                if point.confidence >= 0:
                    report.points.append(point)

        if not skip_headers:
            hdrs = list(headers or PROBE_HEADERS)
            for hdr in hdrs:
                point = self._probe_point("header", hdr)
                if point.confidence >= 0:
                    report.points.append(point)

        if not skip_cookies:
            for ck in ["session", "token", "id", "user"]:
                point = self._probe_point("cookie", ck)
                if point.confidence >= 0:
                    report.points.append(point)

        if not skip_path:
            point = self._probe_point("path", "(path_segment)")
            if point.confidence >= 0:
                report.points.append(point)

        report.points.sort(key=lambda p: (p.waf_active, p.confidence), reverse=True)
        report.requests_used = self._requests
        return report


