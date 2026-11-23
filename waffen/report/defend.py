"""Generate deployable WAF rules from bypass findings.

Takes confirmed bypass findings and produces rules in real WAF engine
syntax: ModSecurity/Coraza SecRule, NAXSI MainRule, Cloudflare expression,
and AWS WAF JSON.  Unlike report/rules.py (prose recommendations), this
module outputs copy-paste-deployable configuration.

No external dependencies.  Deterministic: same findings → same rules.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Sequence, TYPE_CHECKING

if TYPE_CHECKING:
    from ..search.beam import Finding

ENGINES = ("modsecurity", "naxsi", "cloudflare", "aws")

_BASE_ID = 900_001


# ---------------------------------------------------------------------------
# Pattern extraction — the core: finding → regex that blocks the evasion
# ---------------------------------------------------------------------------

_CHAIN_PATTERNS: dict[str, tuple[str, str]] = {
    # chain_name → (regex_pattern, human description)
    "ast_comment_split": (
        r"(?i)(?:\w+\s*/\*[^*]*\*/\s*\w+)",
        "inline comment splitting SQL keywords",
    ),
    "comment_split": (
        r"(?i)(?:\w+\s*/\*[^*]*\*/\s*\w+)",
        "inline comment splitting SQL keywords",
    ),
    "ast_sqlite_swap": (
        r"(?i)(?:'\s*(?:glob|match|isnull|notnull|collate)\s)",
        "SQLite-specific operator injection",
    ),
    "sqlite_operator_swap": (
        r"(?i)(?:'\s*(?:glob|match|isnull|notnull|collate)\s)",
        "SQLite-specific operator injection",
    ),
    "ast_case_mix": (
        r"(?i)(?:[a-z][A-Z]|[A-Z][a-z]){2,}",
        "mixed-case keyword evasion",
    ),
    "case_swap": (
        r"(?i)(?:[a-z][A-Z]|[A-Z][a-z]){2,}",
        "mixed-case keyword evasion",
    ),
    "ast_whitespace_swap": (
        r"(?:[\x09\x0a\x0b\x0c\x0d])",
        "non-space whitespace between SQL tokens",
    ),
    "whitespace_vary": (
        r"(?:[\x09\x0a\x0b\x0c\x0d])",
        "non-space whitespace between SQL tokens",
    ),
    "ast_concat_build": (
        r"(?i)(?:'\|\|'|concat\s*\(|'\+')",
        "string concatenation rebuilding keywords",
    ),
    "keyword_concat_split": (
        r"(?i)(?:'\|\|'|concat\s*\(|'\+')",
        "string concatenation rebuilding keywords",
    ),
    "ast_iif_wrap": (
        r"(?i)(?:iif\s*\(|case\s+when\b)",
        "IIF/CASE conditional wrapping",
    ),
    "case_wrap": (
        r"(?i)(?:iif\s*\(|case\s+when\b)",
        "IIF/CASE conditional wrapping",
    ),
    "ast_function_wrap": (
        r"(?i)(?:char\s*\(\s*\d+(?:\s*,\s*\d+)*\s*\))",
        "CHAR() function building strings",
    ),
    "ast_number_obfuscate": (
        r"(?i)(?:0x[0-9a-f]+|(?:\d+\.?\d*)[eE][+-]?\d+)",
        "hex/scientific number obfuscation",
    ),
    "ast_operator_equiv": (
        r"(?i)(?:\bbetween\b|\bnot\s+\d+\s*!=)",
        "operator equivalence substitution",
    ),
    "ast_comment_swap": (
        r"(?:#|;%00)",
        "alternative SQL comment syntax",
    ),
    "base64": (
        r"(?:[A-Za-z0-9+/]{4}){2,}(?:={0,2})",
        "base64-encoded payload",
    ),
    "url_double_encode": (
        r"%25[0-9a-fA-F]{2}",
        "double URL-encoded characters",
    ),
    "hex_encode": (
        r"(?:0x[0-9a-fA-F]{2,}|\\x[0-9a-fA-F]{2})",
        "hex-encoded payload",
    ),
    "unicode_escape": (
        r"(?:\\u[0-9a-fA-F]{4}|%u[0-9a-fA-F]{4})",
        "unicode-escaped payload",
    ),
    # XSS-specific
    "xss_tag_construct": (
        r"(?i)<\s*(?:img|svg|iframe|body|input|details|marquee|a\s)[^>]*>",
        "HTML tag injection",
    ),
    "xss_event_alternatives": (
        r"(?i)\bon(?:pointer|animation|transition|wheel|focusin|beforeinput|beforetoggle)\w*\s*=",
        "uncommon event handler",
    ),
    # SSTI
    "ssti_jinja2_filter_chain": (
        r"(?:\{\{.*?\|(?:attr|join|format).*?\}\}|\{%.*?set\b)",
        "Jinja2 filter/set bypass",
    ),
    "ssti_jinja2_string_concat": (
        r"(?:\{\{.*?~.*?\}\})",
        "Jinja2 tilde string concat",
    ),
    # SSRF
    "ssrf_ip_decimal": (
        r"\b(?:\d{8,10})\b",
        "decimal IP representation",
    ),
    "ssrf_ip_octal": (
        r"\b0[0-7]{1,3}(?:\.0[0-7]{1,3}){0,3}\b",
        "octal IP representation",
    ),
    "ssrf_ip_hex": (
        r"(?i)0x[0-9a-f]{2,8}\b",
        "hex IP representation",
    ),
    "ssrf_dns_rebind": (
        r"(?i)(?:nip\.io|xip\.io|sslip\.io|localtest\.me)\b",
        "DNS rebinding service",
    ),
}

_PAYLOAD_FALLBACK_CHARS = re.compile(r"([.*+?^${}()|[\]\\])")


def _escape_regex(s: str) -> str:
    return _PAYLOAD_FALLBACK_CHARS.sub(r"\\\1", s)


def _extract_patterns(finding) -> list[tuple[str, str]]:
    """Return (regex, description) pairs for the bypass technique(s) used."""
    chain = list(getattr(finding, "chain", None) or [])
    results = []
    seen = set()
    for step in chain:
        key = step.lower().strip()
        for chain_name, (pattern, desc) in _CHAIN_PATTERNS.items():
            if chain_name in key or key in chain_name:
                if pattern not in seen:
                    seen.add(pattern)
                    results.append((pattern, desc))
    if not results:
        payload = getattr(finding, "payload", "") or ""
        if payload:
            escaped = _escape_regex(payload[:80])
            results.append((escaped, f"literal bypass payload match"))
    return results


# ---------------------------------------------------------------------------
# DefenseRule
# ---------------------------------------------------------------------------

@dataclass
class DefenseRule:
    id: int
    engine: str
    pattern: str
    description: str
    bypass_payload: str
    chain: list[str]
    attack_class: str
    confidence: str  # high / medium / low

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "engine": self.engine,
            "pattern": self.pattern,
            "description": self.description,
            "bypass_payload": self.bypass_payload,
            "chain": self.chain,
            "attack_class": self.attack_class,
            "confidence": self.confidence,
        }


# ---------------------------------------------------------------------------
# Engine-specific formatters
# ---------------------------------------------------------------------------

def _fmt_modsecurity(rule: DefenseRule) -> str:
    safe_msg = rule.description.replace("'", "\\'")
    return (
        f'SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx {rule.pattern}" \\\n'
        f'    "id:{rule.id},phase:2,deny,status:403,'
        f"msg:'WAFFEN: {safe_msg}',tag:'waffen/{rule.attack_class}'\""
    )


def _fmt_naxsi(rule: DefenseRule) -> str:
    score_var = "$SQL" if "sql" in rule.attack_class.lower() else "$ATTACK"
    return (
        f'MainRule "rx:{rule.pattern}" '
        f'"msg:WAFFEN: {rule.description}" '
        f'"mz:ARGS|BODY" '
        f'"s:{score_var}:8" '
        f"id:{rule.id};"
    )


def _fmt_cloudflare(rule: DefenseRule) -> str:
    return (
        f"# WAFFEN rule {rule.id}: {rule.description}\n"
        f"# Chain: {' -> '.join(rule.chain) if rule.chain else 'raw'}\n"
        f'(http.request.uri.query matches "{rule.pattern}") or '
        f'(http.request.body matches "{rule.pattern}")'
    )


def _fmt_aws(rule: DefenseRule) -> str:
    return json.dumps({
        "Name": f"WAFFEN-{rule.id}-{rule.attack_class.replace(' ', '-')}",
        "Priority": rule.id - _BASE_ID + 1,
        "Statement": {
            "RegexPatternSetReferenceStatement": {
                "FieldToMatch": {"AllQueryArguments": {}},
                "TextTransformations": [
                    {"Priority": 0, "Type": "URL_DECODE"},
                    {"Priority": 1, "Type": "LOWERCASE"},
                ],
            }
        },
        "Action": {"Block": {}},
        "VisibilityConfig": {
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": f"WAFFEN-{rule.id}",
        },
        "_waffen_meta": {
            "pattern": rule.pattern,
            "description": rule.description,
            "bypass_payload": rule.bypass_payload[:80],
        },
    }, indent=2)


_FORMATTERS = {
    "modsecurity": _fmt_modsecurity,
    "naxsi": _fmt_naxsi,
    "cloudflare": _fmt_cloudflare,
    "aws": _fmt_aws,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_rules(findings: Sequence, engine: str = "modsecurity") -> list[DefenseRule]:
    """Convert bypass findings into defense rules for the given engine."""
    rules: list[DefenseRule] = []
    seen_patterns: set[str] = set()
    rule_id = _BASE_ID

    for finding in findings:
        payload = getattr(finding, "payload", "") or ""
        chain = list(getattr(finding, "chain", None) or [])
        attack_class = getattr(finding, "attack_class", "") or "Unknown"
        verified = getattr(finding, "verified", None)

        confidence = "high" if verified is True else "medium" if verified is None else "low"

        for pattern, desc in _extract_patterns(finding):
            if pattern in seen_patterns:
                continue
            seen_patterns.add(pattern)

            rules.append(DefenseRule(
                id=rule_id,
                engine=engine,
                pattern=pattern,
                description=desc,
                bypass_payload=payload[:120],
                chain=chain,
                attack_class=attack_class,
                confidence=confidence,
            ))
            rule_id += 1

    return rules


def format_rule(rule: DefenseRule) -> str:
    """Format a single rule in its engine's syntax."""
    fmt = _FORMATTERS.get(rule.engine)
    if fmt is None:
        raise ValueError(f"Unknown engine: {rule.engine!r} (supported: {', '.join(ENGINES)})")
    return fmt(rule)


def render_rules(rules: list[DefenseRule], engine: str | None = None) -> str:
    """Render all rules as a single deployable config string."""
    if not rules:
        return f"# No bypass findings — no defense rules to generate.\n"

    eng = engine or (rules[0].engine if rules else "modsecurity")

    header_map = {
        "modsecurity": (
            "# WAFFEN Defense Rules — ModSecurity/Coraza\n"
            f"# Generated from {len(rules)} bypass finding(s)\n"
            "# Deploy: Include this file in your ModSecurity configuration\n\n"
        ),
        "naxsi": (
            "# WAFFEN Defense Rules — NAXSI\n"
            f"# Generated from {len(rules)} bypass finding(s)\n"
            "# Deploy: Include this file in your nginx naxsi configuration\n\n"
        ),
        "cloudflare": (
            "# WAFFEN Defense Rules — Cloudflare WAF Expressions\n"
            f"# Generated from {len(rules)} bypass finding(s)\n"
            "# Deploy: Add each expression as a Cloudflare WAF custom rule\n\n"
        ),
        "aws": (
            "// WAFFEN Defense Rules — AWS WAF\n"
            f"// Generated from {len(rules)} bypass finding(s)\n"
            "// Deploy: Add each rule to your AWS WAF WebACL\n\n"
        ),
    }
    lines = [header_map.get(eng, f"# WAFFEN Defense Rules — {eng}\n\n")]

    for i, rule in enumerate(rules):
        r = DefenseRule(**{**rule.__dict__, "engine": eng})
        lines.append(f"# Rule {i + 1}: {rule.description}")
        lines.append(f"# Bypass chain: {' -> '.join(rule.chain) if rule.chain else 'raw payload'}")
        lines.append(f"# Confidence: {rule.confidence}")
        lines.append(format_rule(r))
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def write_rules(rules: list[DefenseRule], path: str, engine: str | None = None):
    """Write rules to a file."""
    with open(path, "w") as f:
        f.write(render_rules(rules, engine))


def write_all_engines(rules: list[DefenseRule], out_dir: str):
    """Write rules for all supported engines into a directory."""
    import os
    os.makedirs(out_dir, exist_ok=True)
    ext_map = {
        "modsecurity": "conf",
        "naxsi": "rules",
        "cloudflare": "txt",
        "aws": "json",
    }
    paths = []
    for eng in ENGINES:
        ext = ext_map.get(eng, "txt")
        p = os.path.join(out_dir, f"waffen-rules.{ext}")
        engine_rules = [DefenseRule(**{**r.__dict__, "engine": eng}) for r in rules]
        write_rules(engine_rules, p, eng)
        paths.append(p)
    return paths
