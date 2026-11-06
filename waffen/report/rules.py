"""Close the loop from "found a bypass/gap" to "here's the WAF rule to add."

Takes a confirmed `Finding` (from `waffen.search.beam`) or a coverage gap
(`EvalResult.through_samples`, from `waffen.eval.coverage`) and emits a
human-readable + structured rule recommendation the RedEye team can act on.

Deliberately duck-typed: this module does NOT hard-import `Finding` or
`EvalResult` at runtime (only under `TYPE_CHECKING`, for editor/type-checker
benefit). It only reads attributes it needs via `getattr`, so it keeps
working even while `search/`, `eval/`, `recon/`, `core/transforms.py` and
`kb/` are being edited concurrently elsewhere.

`suggested_rule` strings are deliberately prose + pseudo-rule, not a real
WAF engine's config syntax (we don't know which engine RedEye runs) — they
are written so a WAF engineer can translate them directly into ModSecurity/
NGINX/whatever rule language is in use. No network access, no randomness:
same inputs always produce the same report.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - type hints only, no runtime import
    from ..search.beam import Finding
    from ..eval.coverage import EvalResult


@dataclass
class RuleSuggestion:
    """One actionable WAF-rule recommendation for a single attack class."""

    attack_class: str
    title: str
    rationale: str
    suggested_rule: str
    severity: str  # "low" | "medium" | "high" | "critical"
    references: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "attack_class": self.attack_class,
            "title": self.title,
            "rationale": self.rationale,
            "suggested_rule": self.suggested_rule,
            "severity": self.severity,
            "references": list(self.references),
        }


# --------------------------------------------------------------------------- #
# Severity heuristic
# --------------------------------------------------------------------------- #
# Classes where a VERIFIED finding means server compromise / data exfiltration /
# arbitrary code execution are top severity; an unverified/gap-only hit for the
# same class is one notch down (reached origin, impact not proven yet).
_SEVERITY_ORDER = ("critical", "high", "medium", "low")  # critical first
_SEVERITY_RANK = {name: i for i, name in enumerate(_SEVERITY_ORDER)}

_TIER_CRITICAL = frozenset({
    "Upload Insecure Files", "Command Injection", "SQL Injection",
    "SSTI", "File Inclusion",
})
_TIER_HIGH = frozenset({
    "CRLF Injection", "XSS Injection", "Directory Traversal",
    "NoSQL Injection", "LDAP Injection",
})


def _severity_for(attack_class: str, verified: bool | None) -> str:
    """verified is True -> top tier for the class; False/None (not confirmed
    exploitable) -> one notch lower. Unknown classes get a conservative default."""
    is_verified = verified is True
    if attack_class in _TIER_CRITICAL:
        return "critical" if is_verified else "high"
    if attack_class in _TIER_HIGH:
        return "high" if is_verified else "medium"
    return "medium" if is_verified else "low"


# --------------------------------------------------------------------------- #
# References (static labels — no network lookups)
# --------------------------------------------------------------------------- #
_REFERENCES: dict[str, list[str]] = {
    "XSS Injection": [
        "OWASP Top 10 A03:2021 - Injection",
        "OWASP XSS Filter Evasion Cheat Sheet",
    ],
    "SQL Injection": [
        "OWASP Top 10 A03:2021 - Injection",
        "OWASP SQL Injection Prevention Cheat Sheet",
    ],
    "Command Injection": [
        "OWASP Top 10 A03:2021 - Injection",
        "OWASP OS Command Injection Defense Cheat Sheet",
    ],
    "Directory Traversal": [
        "OWASP Path Traversal",
        "CWE-22: Improper Limitation of a Pathname",
    ],
    "File Inclusion": [
        "CWE-98 / CWE-99: PHP/Java Remote & Local File Inclusion",
        "OWASP Top 10 A03:2021 - Injection",
    ],
    "SSTI": [
        "PortSwigger: Server-Side Template Injection",
        "OWASP Server-Side Template Injection Cheat Sheet",
    ],
    "NoSQL Injection": [
        "OWASP Testing for NoSQL Injection",
        "CWE-943: Improper Neutralization of Special Elements in Data Query Logic",
    ],
    "CRLF Injection": [
        "OWASP HTTP Response Splitting",
        "CWE-93: Improper Neutralization of CRLF Sequences",
    ],
    "Upload Insecure Files": [
        "OWASP Unrestricted File Upload",
        "OWASP File Upload Cheat Sheet",
    ],
    "LDAP Injection": [
        "OWASP LDAP Injection Prevention Cheat Sheet",
        "CWE-90: Improper Neutralization of Special Elements used in an LDAP Query",
    ],
}
_GENERIC_REFERENCES = ["OWASP Top 10", "OWASP Web Security Testing Guide (WSTG)"]


def _references_for(attack_class: str) -> list[str]:
    return list(_REFERENCES.get(attack_class, _GENERIC_REFERENCES))


# --------------------------------------------------------------------------- #
# Class-specific suggested-rule templates
# --------------------------------------------------------------------------- #
def _where(endpoint: str) -> str:
    return f" at {endpoint}" if endpoint else ""


def _tmpl_xss(endpoint: str) -> str:
    return (
        "Canonicalize the value (URL-decode, HTML-entity decode -- named entities as well as "
        "hex/decimal numeric character references, not a named-entity list alone -- unescape "
        "JS string escapes, strip NULs/zero-width chars) iteratively to a fixed "
        f"point BEFORE signature matching{_where(endpoint)}, then block on tag/event-handler/"
        "URI-scheme markers (<script, <svg, <img ... onerror=, on\\w+=, javascript:, "
        "srcdoc=) case-insensitively. A single literal-string match on the raw parameter "
        "misses case-swapped tags, HTML-entity-obfuscated brackets and double-encoded "
        "payloads, which is exactly how this bypass got through — match only after "
        "normalization, and re-normalize until the string stops changing."
    )


def _tmpl_sqli(endpoint: str) -> str:
    return (
        "Normalize the parameter (URL-decode, strip/collapse inline SQL comments like "
        "/*...*/ and -- , fold encoded whitespace such as %0a/%09/%0b into a single "
        f"space, lower-case keywords) before evaluating it{_where(endpoint)}, then flag "
        "tautologies (OR 1=1), UNION-based exfiltration (UNION SELECT), stacked/batched "
        "queries (; DROP/; INSERT) and time-based blind probes (SLEEP(, BENCHMARK(, "
        "pg_sleep(). Comment-splitting and mixed-encoding were used to break up "
        "blacklisted keywords, so a raw-string keyword regex alone will miss it — prefer "
        "a tokenizer/parser-based or libinjection-style grammar check over pure regex."
    )


def _tmpl_cmdi(endpoint: str) -> str:
    return (
        "Block shell metacharacters and command-substitution syntax ( ; | & ` $( ) "
        f"and literal newlines ) in any parameter that reaches a shell/exec sink{_where(endpoint)}, "
        "after normalizing whitespace-substitution tricks ($IFS, ${IFS}, tabs, brace "
        "expansion {cat,/etc/passwd}) and quote-split keywords (c''at, w\"h\"oami). The "
        "confirmed chain evaded a naive separator blacklist by splitting/reassembling the "
        "command token around alternate whitespace, so detection must canonicalize those "
        "substitutions before matching — pair with a deny-by-default allowlist of expected "
        "argument characters for this parameter rather than relying on blacklist-only."
    )


def _tmpl_traversal(endpoint: str) -> str:
    return (
        "Canonicalize the path before access-checking it: percent-decode (including "
        "double/overlong encodings like %252e%252e%252f), decode backslash/mixed-slash "
        "variants, and resolve every ./.. segment, THEN reject any result that escapes "
        f"the intended base directory{_where(endpoint)} — do not blacklist the literal "
        "string '../'. The observed bypass used segment obfuscation (....// collapsing "
        "to ../, encoded slashes %2f, absolute-path smuggling) that a single-pass '../' "
        "filter does not catch; resolve to a real absolute path and compare prefixes."
    )


def _tmpl_lfi(endpoint: str) -> str:
    return (
        "Enforce an allowlist of includable file identifiers (not a blacklist of bad "
        "ones) and reject PHP/Java stream-wrapper and remote schemes (php://, phar://, "
        "data://, expect://, file://, zip://, and SSRF-adjacent targets like "
        f"http://169.254.169.254/) on the include/file parameter{_where(endpoint)}, after "
        "fully URL-decoding nested encodings. The confirmed chain used wrapper chaining "
        "(e.g. php://filter/convert.base64-encode/resource=...) to read source instead of "
        "executing it, so blocking only 'http://' or only one wrapper name is insufficient "
        "— match the wrapper-scheme family as a whole and validate the resolved resource."
    )


def _tmpl_ssti(endpoint: str) -> str:
    return (
        "Never let user input be parsed as template source: if it must appear in a "
        "rendered template, render it as plain data (auto-escaped) in a sandboxed/logic-"
        f"less mode{_where(endpoint)}, and separately block template-delimiter sequences "
        "({{ }}, ${ }, <% %>, and Ruby/JSP-EL hash-brace interpolation) plus known sandbox-"
        "escape gadgets (__class__, __mro__, "
        "__globals__, config.items, request.application) reaching that parameter. A "
        "filter that only looks for a bare '{{' misses whitespace/comment-split variants "
        "and nested-brace tricks — the arithmetic-canary chain here ({{7*7}} style) proves "
        "expression evaluation, which is one gadget chain away from RCE in most engines."
    )


def _tmpl_nosqli(endpoint: str) -> str:
    return (
        "Reject operator-bearing input ($gt, $ne, $where, $regex, $exists, or a raw JSON "
        "object/array) in any field that should be a plain scalar string or number"
        f"{_where(endpoint)}, and enforce strict server-side type coercion-and-compare "
        "instead of trusting the client-supplied JSON shape (e.g. a PHP/Node app that "
        "turns param[$ne]=1 into an array). The confirmed bypass smuggled a query "
        "operator where a literal value was expected — a WAF that only looks for SQL "
        "keywords or quotes will never see this, since there is no SQL syntax involved."
    )


def _tmpl_crlf(endpoint: str) -> str:
    return (
        "Strip or reject raw AND percent-/double-encoded CR/LF sequences (\\r, \\n, "
        "%0d, %0a, %0D, %0A, and re-encoded forms like %250d%250a) in the injected "
        f"parameter{_where(endpoint)} before it reaches response-header, redirect-"
        "Location, Set-Cookie, or log-line construction. Decode fully and iteratively to "
        "a fixed point before validating — the confirmed bypass used an encoded CRLF "
        "that a filter checking only literal \\r\\n bytes would miss — and validate again "
        "at the sink (the header-writing code), not only at the edge/WAF layer."
    )


def _tmpl_upload(endpoint: str) -> str:
    return (
        "Block multipart uploads where the Content-Disposition filename matches a "
        "dangerous/executable pattern — /\\.(php[0-9]?|phtml?|phar|pht|jspx?|aspx?|sh|"
        f"cgi|exe|htaccess)$/i{_where(endpoint)} — regardless of the declared Content-Type/"
        "MIME header, which the client fully controls and must never be trusted as the "
        "sole gate. Canonicalize the filename first: strip trailing dots/spaces/semicolons "
        "and null-bytes (shell.php;.jpg, shell.php%00.jpg), then take the LAST real "
        "extension after stripping those — the confirmed bypass relied on exactly these "
        "tricks plus case variation (shell.PhP, shell.pHtMl) and double extensions "
        "(shell.php.jpg), all of which must be caught by the same normalized check."
    )


def _tmpl_ldap(endpoint: str) -> str:
    return (
        "Escape or reject LDAP filter metacharacters ( * ( ) \\ NUL ) and their encoded "
        f"forms (%28, %29, %2a, %5c) in any field used to build an LDAP search filter{_where(endpoint)}, "
        "and replace string-concatenated filter construction with proper per-value "
        "escaping (RFC 4515) or a parameterized filter API. The confirmed bypass used "
        "filter metacharacters to close an attribute clause early and inject an always-"
        "true/wildcard condition — a check that only looks for SQL-style quotes will not "
        "catch LDAP-specific syntax."
    )


def _tmpl_generic(endpoint: str, attack_class: str) -> str:
    return (
        f"No class-specific evasion model is registered yet for '{attack_class}'. As a "
        "provisional baseline: canonicalize the input (URL/HTML-decode, normalize "
        "whitespace and case) before any signature match, deny-list the concrete markers "
        f"seen in the sample payload below{_where(endpoint)}, and confirm server-side that "
        "this input cannot reach a sensitive sink (filesystem, shell, database, template "
        "engine, deserializer) unsanitized. Replace this with a dedicated, mechanic-"
        "specific rule once the evasion technique for this class is understood."
    )


_TEMPLATES: dict[str, Callable[[str], str]] = {
    "XSS Injection": _tmpl_xss,
    "SQL Injection": _tmpl_sqli,
    "Command Injection": _tmpl_cmdi,
    "Directory Traversal": _tmpl_traversal,
    "File Inclusion": _tmpl_lfi,
    "SSTI": _tmpl_ssti,
    "NoSQL Injection": _tmpl_nosqli,
    "CRLF Injection": _tmpl_crlf,
    "Upload Insecure Files": _tmpl_upload,
    "LDAP Injection": _tmpl_ldap,
}


def _suggested_rule_for(attack_class: str, endpoint: str) -> str:
    tmpl = _TEMPLATES.get(attack_class)
    if tmpl is None:
        return _tmpl_generic(endpoint, attack_class)
    return tmpl(endpoint)


# --------------------------------------------------------------------------- #
# Small text helpers
# --------------------------------------------------------------------------- #
def _truncate(value: object, limit: int = 80) -> str:
    text = str(value) if value is not None else ""
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)].rstrip() + "..."


def _verified_phrase(verified: bool | None, confidence: float | None) -> str:
    if verified is True:
        if isinstance(confidence, (int, float)):
            return f"verified exploitable (confidence {confidence:.2f})"
        return "verified exploitable"
    if verified is False:
        return "reached origin but NOT confirmed exploitable by the verifier"
    return "unverified (no exploit verifier was run on it)"


# --------------------------------------------------------------------------- #
# Public builders
# --------------------------------------------------------------------------- #
def recommend_from_finding(finding: "Finding", *, endpoint: str = "") -> RuleSuggestion:
    """Build one `RuleSuggestion` from a search Finding.

    Duck-typed: accepts anything exposing `.attack_class`, `.payload`, `.chain`,
    `.verified`, `.confidence` (a real `waffen.search.beam.Finding`, or a
    `types.SimpleNamespace` standing in for one in tests)."""
    attack_class = getattr(finding, "attack_class", "") or "Unknown"
    payload = getattr(finding, "payload", "") or ""
    chain = list(getattr(finding, "chain", None) or [])
    verified = getattr(finding, "verified", None)
    confidence = getattr(finding, "confidence", None)

    chain_desc = " -> ".join(chain) if chain else "raw payload (no mutation required)"
    rationale = (
        f"Bypass search confirmed a {attack_class} evasion{_where(endpoint)} via chain "
        f"[{chain_desc}]; payload '{_truncate(payload)}' reached the origin and is "
        f"{_verified_phrase(verified, confidence)}."
    )

    return RuleSuggestion(
        attack_class=attack_class,
        title=f"{attack_class} - WAF bypass via {chain_desc}",
        rationale=rationale,
        suggested_rule=_suggested_rule_for(attack_class, endpoint),
        severity=_severity_for(attack_class, verified),
        references=_references_for(attack_class),
    )


def recommend_from_eval(eval_result: "EvalResult", *, endpoint: str = "",
                        min_through: int = 1) -> list[RuleSuggestion]:
    """Build one `RuleSuggestion` per attack class in `eval_result.through_samples`
    that has >= `min_through` sample payloads that got through.

    Duck-typed on `.through_samples` (dict[class -> list[payload]]) and
    `.per_class` (dict[class -> ClassScore-like, optional coverage/blocked/through])."""
    through_samples = getattr(eval_result, "through_samples", None) or {}
    per_class = getattr(eval_result, "per_class", None) or {}

    suggestions: list[RuleSuggestion] = []
    for attack_class in sorted(through_samples):
        samples = list(through_samples[attack_class] or [])
        if len(samples) < min_through:
            continue

        preview = ", ".join(f"'{_truncate(p, 40)}'" for p in samples[:3])
        extra = f" (+{len(samples) - 3} more)" if len(samples) > 3 else ""

        coverage_note = ""
        score = per_class.get(attack_class) if isinstance(per_class, dict) else None
        if score is not None:
            try:
                coverage_note = (
                    f" Current coverage for this class is {score.coverage:.1f}% "
                    f"({score.blocked} blocked / {score.through} through)."
                )
            except Exception:
                coverage_note = ""

        rationale = (
            f"Coverage eval found {len(samples)} payload(s) for {attack_class}"
            f"{_where(endpoint)} reaching origin unblocked: {preview}{extra}.{coverage_note}"
        )

        suggestions.append(RuleSuggestion(
            attack_class=attack_class,
            title=f"{attack_class} - coverage gap ({len(samples)} payload(s) through)",
            rationale=rationale,
            suggested_rule=_suggested_rule_for(attack_class, endpoint),
            severity=_severity_for(attack_class, None),
            references=_references_for(attack_class),
        ))
    return suggestions


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def _sort_key(s: RuleSuggestion):
    return (_SEVERITY_RANK.get(s.severity, len(_SEVERITY_ORDER)), s.attack_class, s.title)


def render_markdown(suggestions: list["RuleSuggestion"]) -> str:
    """Render a Markdown report, grouped/sorted by severity (critical first),
    suitable for pasting straight into a ticket."""
    lines = ["# WAFFEN Rule Recommendations", ""]
    if not suggestions:
        lines.append("No findings or coverage gaps to report.")
        return "\n".join(lines) + "\n"

    ordered = sorted(suggestions, key=_sort_key)
    counts = Counter(s.severity for s in ordered)
    summary = ", ".join(f"{counts[sev]} {sev}" for sev in _SEVERITY_ORDER if counts.get(sev))
    lines.append(f"{len(ordered)} recommendation(s): {summary}")
    lines.append("")
    lines.append("| Severity | Attack class | Title |")
    lines.append("|---|---|---|")
    for s in ordered:
        lines.append(f"| {s.severity.upper()} | {s.attack_class} | {s.title} |")
    lines.append("")

    current_sev = None
    for s in ordered:
        if s.severity != current_sev:
            current_sev = s.severity
            lines.append(f"## {current_sev.upper()}")
            lines.append("")
        lines.append(f"### {s.title}")
        lines.append("")
        lines.append(f"- **Attack class:** {s.attack_class}")
        lines.append(f"- **Severity:** {s.severity}")
        lines.append(f"- **Rationale:** {s.rationale}")
        lines.append(f"- **Suggested rule:** {s.suggested_rule}")
        if s.references:
            lines.append(f"- **References:** {'; '.join(s.references)}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_text(suggestions: list["RuleSuggestion"]) -> str:
    """Plain-text/console-friendly variant (no Markdown syntax) for CLI printing."""
    header = "WAFFEN RULE RECOMMENDATIONS"
    lines = [header, "=" * len(header), ""]
    if not suggestions:
        lines.append("No findings or coverage gaps to report.")
        return "\n".join(lines) + "\n"

    ordered = sorted(suggestions, key=_sort_key)
    lines.append(f"{len(ordered)} recommendation(s)")
    lines.append("")
    for i, s in enumerate(ordered, 1):
        lines.append(f"[{i}] {s.severity.upper()} - {s.attack_class}")
        lines.append(f"    Title: {s.title}")
        lines.append(f"    Rationale: {s.rationale}")
        lines.append(f"    Suggested rule: {s.suggested_rule}")
        if s.references:
            lines.append(f"    References: {', '.join(s.references)}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
