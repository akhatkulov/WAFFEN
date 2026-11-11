"""Encoding mutators — represent the payload in an alternate wire form that a
WAF's signature engine may fail to normalize but the target still decodes.

Grounded in the GoTestWAF encoder set (URL, double-URL, base64, JS-unicode,
HTML/XML entity) plus common pentest variants.
"""
from __future__ import annotations

import base64
import urllib.parse

from .base import REGISTRY

_SPECIAL = "<>\"'`;()&|=/\\ "


def url_all(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def url_special(s: str) -> str:
    return "".join(f"%{ord(c):02X}" if c in _SPECIAL else c for c in s)


def double_url(s: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")


def url_plus_space(s: str) -> str:
    return s.replace(" ", "+")


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def b64_malformed_prefix(s: str) -> str:
    """base64(payload) prefixed with a malformed single-char padding group 'A=='.

    ModSecurity t:base64DecodeExt (GHSA-4j47-8qcr-jf59) discards the ENTIRE
    decoded value when it meets a malformed single-char padding group, so the WAF
    inspects an empty string while tolerant backend decoders still recover the
    payload after the bad group. For params the app base64-decodes.
    """
    return "A==" + base64.b64encode(s.encode()).decode()


def js_unicode(s: str) -> str:
    return "".join(f"\\u{ord(c):04x}" for c in s)


def js_hex(s: str) -> str:
    return "".join(f"\\x{ord(c):02x}" if ord(c) < 256 else c for c in s)


def html_entity_dec(s: str) -> str:
    return "".join(f"&#{ord(c)};" for c in s)


def html_entity_hex(s: str) -> str:
    return "".join(f"&#x{ord(c):x};" for c in s)


def html_entity_special(s: str) -> str:
    return "".join(f"&#{ord(c)};" if c in _SPECIAL else c for c in s)


def utf8_overlong_slash(s: str) -> str:
    # overlong UTF-8 for '/' and '.' used in path-traversal evasions
    return s.replace("/", "%c0%af").replace(".", "%c0%ae")


def mixed_percent(s: str) -> str:
    # percent-encode every other character to break naive substring matches
    out = []
    for i, c in enumerate(s):
        out.append(f"%{ord(c):02X}" if (i % 2 == 0 and ord(c) < 256) else c)
    return "".join(out)


def unicode_fullwidth(s: str) -> str:
    # map ASCII to fullwidth forms (U+FF01..) that some normalizers fold to ASCII
    def fw(c: str) -> str:
        o = ord(c)
        return chr(o + 0xFEE0) if 0x21 <= o <= 0x7E else c
    return "".join(fw(c) for c in s)


def _register() -> None:
    R = REGISTRY
    R.add("url_all", url_all, "encoder", "percent-encode every char")
    R.add("url_special", url_special, "encoder", "percent-encode only special chars")
    R.add("double_url", double_url, "encoder", "double percent-encode")
    R.add("url_plus_space", url_plus_space, "encoder", "spaces -> '+'")
    R.add("base64", b64, "encoder", "base64 (for params the app decodes)")
    R.add("base64_malformed_prefix", b64_malformed_prefix, "encoder",
          "base64 with malformed 'A==' prefix (ModSecurity t:base64DecodeExt GHSA-4j47-8qcr-jf59)")
    R.add("js_unicode", js_unicode, "encoder", r"\uXXXX escapes", classes={"XSS Injection", "*"})
    R.add("js_hex", js_hex, "encoder", r"\xNN escapes", classes={"XSS Injection", "*"})
    R.add("html_entity_dec", html_entity_dec, "encoder", "&#NN; entities", classes={"XSS Injection", "*"})
    R.add("html_entity_hex", html_entity_hex, "encoder", "&#xNN; entities", classes={"XSS Injection", "*"})
    R.add("html_entity_special", html_entity_special, "encoder", "entity-encode specials only",
          classes={"XSS Injection", "*"})
    R.add("utf8_overlong_slash", utf8_overlong_slash, "encoder", "overlong UTF-8 for / and .",
          classes={"Directory Traversal", "File Inclusion", "*"})
    R.add("mixed_percent", mixed_percent, "encoder", "percent-encode every other char")
    R.add("unicode_fullwidth", unicode_fullwidth, "encoder", "ASCII -> fullwidth unicode")


_register()
