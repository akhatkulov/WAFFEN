"""Class-specific semantic verification of THROUGH payloads.

The search engine's oracle only answers "did this get past the WAF?" (BLOCKED /
THROUGH / DOWN). A THROUGH verdict proves the mutated payload reached the
origin — it does NOT prove the underlying vulnerability actually fired. A WAF
bypass that reaches the app but gets neutralized there (escaped, parameterized,
sandboxed, etc.) is a false positive for "exploitable".

Each `_check_*` function below sends one or two extra, carefully-crafted
requests through the same `Oracle` used by the rest of the toolchain and
inspects the *response body* for class-specific evidence that the exploit
actually executed. These are heuristics, not proof — `Verification.reason`
says plainly what was (and wasn't) actually confirmed, and `confidence` is a
float in [0, 1] reflecting how strong that evidence is.
"""
from __future__ import annotations

import base64
import re
import random
from dataclasses import dataclass


@dataclass
class Verification:
    exploitable: bool
    confidence: float
    reason: str
    attack_class: str


# ---------------------------------------------------------------------------
# XSS Injection
# ---------------------------------------------------------------------------
_TAG_PATTERN = re.compile(r"<\s*(script|img|svg|iframe|body|details)\b", re.I)
_EVENT_PATTERN = re.compile(r"on[a-z]+\s*=", re.I)


def _check_xss(oracle, payload: str, attack_class: str) -> Verification:
    """Reflected-XSS heuristic.

    Confirms the payload reflects verbatim (not HTML-entity-encoded) in the
    response body, and that it still carries an executable-context marker
    (a tag like <script>/<svg>, or an on*= event handler, or javascript:).
    A verbatim-but-encoded reflection (&lt;script&gt;) is explicitly treated
    as NOT exploitable — that's exactly the "got through as garbage" case
    this verifier exists to catch.
    """
    resp = oracle.send(payload)
    body = resp.body or ""
    if not body:
        return Verification(False, 0.1, "empty response body; cannot confirm reflection", attack_class)

    body_l = body.lower()
    reflected_raw = payload.lower() in body_l
    escaped = payload.replace("<", "&lt;").replace(">", "&gt;")
    reflected_escaped = escaped.lower() in body_l and escaped != payload

    if reflected_escaped and not reflected_raw:
        return Verification(False, 0.85,
                             "payload reflected but HTML-entity encoded — not executable", attack_class)

    if reflected_raw:
        if _TAG_PATTERN.search(body) or _EVENT_PATTERN.search(body) or "javascript:" in body_l:
            return Verification(True, 0.85,
                                 "payload reflected verbatim with an unescaped executable-context marker"
                                 " (tag/event-handler/javascript:)", attack_class)
        return Verification(True, 0.5,
                             "payload reflected verbatim, but no distinct executable marker found "
                             "near it — likely exploitable but unconfirmed context", attack_class)

    return Verification(False, 0.3, "payload not found reflected anywhere in the response body", attack_class)


# ---------------------------------------------------------------------------
# SQL Injection
# ---------------------------------------------------------------------------
_SQL_ERROR_PATTERNS = [
    r"sql syntax.*mysql", r"warning:\s*mysql_", r"mysql_fetch_array",
    r"ora-\d{5}", r"postgresql.*error", r"pg_query\(\)", r"sqlite3::",
    r"unclosed quotation mark", r"microsoft ole db provider for sql server",
    r"sqlstate\[", r"you have an error in your sql syntax",
]


def _flip_boolean(payload: str) -> str | None:
    """Best-effort: turn a true-ish boolean payload into its false counterpart."""
    pairs = [
        ("1=1", "1=2"), ("'1'='1'", "'1'='2'"), ("'1'='1", "'1'='2"),
        ("1=='1'", "1=='2'"), ("or 1=1", "or 1=2"), ("OR 1=1", "OR 1=2"),
    ]
    for true_tok, false_tok in pairs:
        if true_tok in payload:
            return payload.replace(true_tok, false_tok)
    return None


def _check_sqli(oracle, payload: str, attack_class: str) -> Verification:
    """Error-based or boolean-differential heuristic.

    First looks for a verbatim DB error signature in the response (strong,
    direct evidence the DB parsed the injected syntax). Failing that, it
    flips the boolean sense of the payload (1=1 -> 1=2, etc.) and compares
    the two responses: a meaningful size/body differential between the
    "true" and "false" variants is evidence of a working boolean-blind SQLi.
    """
    resp_true = oracle.send(payload)
    body = resp_true.body or ""
    for pat in _SQL_ERROR_PATTERNS:
        if re.search(pat, body, re.I):
            return Verification(True, 0.8, f"database error signature matched in response ({pat!r})",
                                 attack_class)

    false_variant = _flip_boolean(payload)
    if false_variant is None or false_variant == payload:
        return Verification(False, 0.2,
                             "no SQL error signature found, and payload has no recognizable boolean "
                             "clause to differential-test", attack_class)

    resp_false = oracle.send(false_variant)
    if resp_true.body == resp_false.body:
        return Verification(False, 0.4,
                             "true/false variants produced byte-identical responses; "
                             "no boolean differential observed", attack_class)

    denom = max(resp_true.size, resp_false.size, 1)
    size_delta_ratio = abs(resp_true.size - resp_false.size) / denom
    if resp_true.verdict == "THROUGH" and size_delta_ratio > 0.02:
        return Verification(True, 0.7,
                             f"boolean differential: true-variant size={resp_true.size} vs "
                             f"false-variant size={resp_false.size} (Δ={size_delta_ratio:.1%})",
                             attack_class)

    return Verification(False, 0.3,
                         "true/false variants differ slightly but not enough to confirm a boolean "
                         "differential", attack_class)


# ---------------------------------------------------------------------------
# Command Injection
# ---------------------------------------------------------------------------
_CMD_WORDS = ["uname -a", "cat /etc/passwd", "whoami", "ls -la", "ls", "id"]


def _check_cmdi(oracle, payload: str, attack_class: str) -> Verification:
    """Benign echo-marker technique.

    Swaps the command word in the payload for `echo <unique-token>` (preserving
    whatever separator/injection syntax the bypass found — ;, |, &&, $(), ``).
    If the token comes back verbatim in the response body, the shell actually
    executed our injected command — direct proof of command execution, with no
    destructive side effects.
    """
    token = f"wfx{random.randint(100000, 999999)}"
    variant = None
    for word in _CMD_WORDS:
        if word in payload:
            variant = payload.replace(word, f"echo {token}")
            break
    if variant is None:
        # no recognizable command word — append a benign echo using the
        # payload's own injection syntax, best-effort.
        variant = payload + f";echo {token}"

    resp = oracle.send(variant)
    body = resp.body or ""
    if token in body:
        return Verification(True, 0.85,
                             f"injected echo marker '{token}' appeared verbatim in response body "
                             "— command execution confirmed", attack_class)
    return Verification(False, 0.3,
                         "echo-marker probe did not appear in the response; command execution "
                         "not confirmed (THROUGH may just mean the WAF let inert text past)",
                         attack_class)


# ---------------------------------------------------------------------------
# Directory Traversal / File Inclusion
# ---------------------------------------------------------------------------
_PASSWD_RE = re.compile(r"root:.*?:0:0:", re.I)
_WININI_MARKERS = ("[boot loader]", "for 16-bit app support")
_B64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


def _check_traversal(oracle, payload: str, attack_class: str) -> Verification:
    """Looks for known file-disclosure content in the response body.

    Covers the classic /etc/passwd signature, a Windows win.ini signature, and
    the php://filter/convert.base64-encode trick (decodes long base64 blobs in
    the body and checks whether any of them is actually PHP source).
    """
    resp = oracle.send(payload)
    body = resp.body or ""

    if _PASSWD_RE.search(body):
        return Verification(True, 0.9, "/etc/passwd signature ('root:...:0:0:') found in response body",
                             attack_class)

    if any(m in body.lower() for m in _WININI_MARKERS):
        return Verification(True, 0.8, "win.ini signature found in response body", attack_class)

    if "php://filter" in payload.lower():
        for m in _B64_BLOB_RE.finditer(body):
            blob = m.group(0)
            padded = blob + "=" * (-len(blob) % 4)
            try:
                decoded = base64.b64decode(padded, validate=False).decode("utf-8", errors="ignore")
            except Exception:
                continue
            if "<?php" in decoded.lower() or "<?=" in decoded:
                return Verification(True, 0.85,
                                     "base64 blob in response decodes to PHP source — "
                                     "php://filter wrapper confirmed working", attack_class)

    return Verification(False, 0.25,
                         "no known file-disclosure signature (/etc/passwd, win.ini, decoded PHP "
                         "source) found in the response body", attack_class)


# ---------------------------------------------------------------------------
# SSTI
# ---------------------------------------------------------------------------
_SSTI_SYNTAXES = [
    (re.compile(r"\{\{.*?\}\}"), lambda a, b: f"{{{{{a}*{b}}}}}"),
    (re.compile(r"\$\{.*?\}"), lambda a, b: f"${{{a}*{b}}}"),
    (re.compile(r"<%=.*?%>"), lambda a, b: f"<%= {a}*{b} %>"),
    (re.compile(r"#\{.*?\}"), lambda a, b: f"#{{{a}*{b}}}"),
]


def _check_ssti(oracle, payload: str, attack_class: str) -> Verification:
    """Arithmetic-marker technique.

    Rewrites the template expression in the payload to multiply two random
    3-digit numbers and checks whether their (otherwise astronomically
    unlikely to appear by chance) product shows up in the response — proof
    the template engine actually evaluated our expression server-side.
    """
    a, b = random.randint(100, 199), random.randint(100, 199)
    product = a * b

    variant = None
    for pattern, build in _SSTI_SYNTAXES:
        if pattern.search(payload):
            variant = pattern.sub(build(a, b), payload, count=1)
            break
    if variant is None:
        variant = f"{{{{{a}*{b}}}}}"

    resp = oracle.send(variant)
    body = resp.body or ""
    if str(product) in body:
        return Verification(True, 0.9,
                             f"arithmetic marker {a}*{b}={product} was evaluated and appeared in the "
                             "response — template evaluation confirmed", attack_class)
    return Verification(False, 0.3,
                         f"arithmetic marker {a}*{b}={product} did not appear in the response; "
                         "template evaluation not confirmed", attack_class)


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
_CHECKS = {
    "XSS Injection": _check_xss,
    "SQL Injection": _check_sqli,
    "Command Injection": _check_cmdi,
    "Directory Traversal": _check_traversal,
    "File Inclusion": _check_traversal,
    "SSTI": _check_ssti,
}


def verify(oracle, payload: str, attack_class: str) -> Verification:
    """Best-effort semantic verification that `payload` really exercises
    `attack_class`'s vulnerability, not just that it got a THROUGH verdict.

    Sends 1-2 extra requests via the same `oracle` (an `Oracle` instance from
    waffen.core.oracle) and inspects response bodies for class-specific
    evidence. Never raises — a checker failure degrades to a low-confidence
    Verification rather than crashing the caller.
    """
    checker = _CHECKS.get(attack_class)
    if checker is None:
        return Verification(False, 0.0, "no verifier for class", attack_class)
    try:
        return checker(oracle, payload, attack_class)
    except Exception as exc:  # defensive: verification must never crash the run
        return Verification(False, 0.0, f"verifier raised an exception: {exc!r}", attack_class)
