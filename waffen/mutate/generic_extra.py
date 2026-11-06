"""Cross-class encoders/obfuscators — generic wire-level tricks that are not
tied to a specific attack class (classes=None -> valid for "*").
"""
from __future__ import annotations

import urllib.parse

from .base import REGISTRY

_ZERO_WIDTH = "​"  # zero-width space


def triple_url(s: str) -> str:
    """Percent-encode three times (defeats double-decode normalizers)."""
    out = s
    for _ in range(3):
        out = urllib.parse.quote(out, safe="")
    return out


def mixed_single_double_url(s: str) -> str:
    """Alternate single/double percent-encoding per character."""
    out = []
    toggle = False
    for c in s:
        if toggle:
            out.append(urllib.parse.quote(urllib.parse.quote(c, safe=""), safe=""))
        else:
            out.append(urllib.parse.quote(c, safe=""))
        toggle = not toggle
    return "".join(out)


def unicode_nfkc_fold(s: str) -> str:
    """Replace ASCII letters with NFKC-foldable fullwidth lookalikes."""
    def fw(c: str) -> str:
        o = ord(c)
        if 0x41 <= o <= 0x5A or 0x61 <= o <= 0x7A:
            return chr(o + 0xFEE0)
        return c
    return "".join(fw(c) for c in s)


def zero_width_insert(s: str) -> str:
    """Insert zero-width spaces between every character."""
    return _ZERO_WIDTH.join(s)


def zero_width_insert_keywords(s: str) -> str:
    """Insert zero-width spaces only between word characters (keeps punctuation intact)."""
    out = []
    for i, c in enumerate(s):
        out.append(c)
        if c.isalnum() and i + 1 < len(s) and s[i + 1].isalnum():
            out.append(_ZERO_WIDTH)
    return "".join(out)


def overlong_utf8_generic(s: str) -> str:
    """Overlong 2-byte UTF-8 encode a broader char set (/ . < > ' \" space)."""
    table = {
        "/": "%c0%af", ".": "%c0%ae", "<": "%c0%bc", ">": "%c0%be",
        "'": "%c0%a7", '"': "%c0%a2", " ": "%c0%a0",
    }
    return "".join(table.get(c, c) for c in s)


def tab_injection(s: str) -> str:
    """Insert a literal tab character after every 3rd character."""
    out = []
    for i, c in enumerate(s):
        out.append(c)
        if (i + 1) % 3 == 0:
            out.append("\t")
    return "".join(out)


def crlf_injection_tail(s: str) -> str:
    """Append a CRLF-separated bogus header-like tail (header/response-splitting probe)."""
    return s + "\r\nX-Waffen: 1"

def crlf_inside(s: str) -> str:
    """Insert CRLF in the middle of the payload (parsers that split on lines may rejoin)."""
    mid = len(s) // 2
    return s[:mid] + "\r\n" + s[mid:]


def param_pad_leading_zeros(s: str) -> str:
    """Pad any standalone integer tokens with leading zeros (001 == 1 in most parsers)."""
    import re
    return re.sub(r"(?<!\d)(\d+)(?!\d)", lambda m: "0" * 3 + m.group(1), s)


def param_value_padding(s: str) -> str:
    """Prepend a long run of benign padding + comment-safe separator before the payload."""
    return ("A" * 64) + "\x00" + s


def whitespace_vtab_generic(s: str) -> str:
    """Replace spaces with raw vertical-tab byte (0x0b), valid whitespace to many parsers."""
    return s.replace(" ", "\x0b")


def case_swap_extremes(s: str) -> str:
    """Swap-case only the first and last alphabetic character of each word."""
    import re
    def repl(m: re.Match) -> str:
        w = m.group(0)
        if len(w) < 2:
            return w.swapcase()
        return w[0].swapcase() + w[1:-1] + w[-1].swapcase()
    return re.sub(r"[A-Za-z]+", repl, s)


def _register() -> None:
    R = REGISTRY
    R.add("triple_url", triple_url, "encoder", "triple percent-encode")
    R.add("mixed_single_double_url", mixed_single_double_url, "encoder",
          "alternate single/double percent-encoding per char")
    R.add("unicode_nfkc_fold", unicode_nfkc_fold, "encoder",
          "ASCII letters -> NFKC-foldable fullwidth lookalikes")
    R.add("zero_width_insert", zero_width_insert, "obfuscator",
          "zero-width space between every character")
    R.add("zero_width_insert_keywords", zero_width_insert_keywords, "obfuscator",
          "zero-width space only between alphanumerics")
    R.add("overlong_utf8_generic", overlong_utf8_generic, "encoder",
          "overlong UTF-8 for / . < > ' \" and space")
    R.add("tab_injection", tab_injection, "obfuscator",
          "insert tab character every 3rd char")
    R.add("crlf_injection_tail", crlf_injection_tail, "obfuscator",
          "append CRLF + bogus header tail")
    R.add("crlf_inside", crlf_inside, "obfuscator",
          "insert CRLF in the middle of the payload")
    R.add("param_pad_leading_zeros", param_pad_leading_zeros, "obfuscator",
          "pad standalone integers with leading zeros")
    R.add("param_value_padding", param_value_padding, "obfuscator",
          "prepend long benign padding + null byte before payload")
    R.add("whitespace_vtab_generic", whitespace_vtab_generic, "encoder",
          "spaces -> raw vertical-tab byte 0x0b")
    R.add("case_swap_extremes", case_swap_extremes, "obfuscator",
          "swap-case first/last letter of each word")


_register()
