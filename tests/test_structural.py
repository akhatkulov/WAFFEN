"""Tests for D2 structural / parser-differential request transforms."""
import json

from waffen.core import transforms as T
from waffen.core.oracle import Target


def _t():
    return Target(base_url="https://x.example", path="/api", param="q")


def _argv(name, payload="<script>alert(1)</script>"):
    return T.get(name).build(_t(), payload)


def test_structural_set_selectable():
    sel = {t.name for t in T.select({"structural"})}
    assert sel == T.STRUCTURAL and len(sel) == 10


def test_all_structural_registered_and_build():
    for name in T.STRUCTURAL:
        argv = _argv(name)
        assert argv and argv[0] == "curl"
        assert "-X" in argv and "POST" in argv            # structural transforms POST a body
        assert any("Content-Type" in a for a in argv)


def test_json_dup_key_has_two_keys_and_payload():
    argv = _argv("json_dup_key", "PAY")
    body = argv[-1]
    assert body.count('"q"') == 2 and "PAY" in body       # duplicate key, payload present

def test_json_unicode_key_escapes_name():
    body = _argv("json_unicode_key", "PAY")[-1]
    assert "\\u0071" in body and "q\":" not in body        # key 'q' hidden as q


def test_json_array_wrap_is_valid_json_array():
    body = _argv("json_array_wrap", "PAY")[-1]
    parsed = json.loads(body)
    assert parsed["q"] == ["PAY"]


def test_multipart_dup_disposition_has_two_lines():
    body = _argv("mp_dup_disposition", "PAY")[-1]
    assert body.count("Content-Disposition") == 2 and "PAY" in body
    # content-type header carries a boundary
    argv = _argv("mp_dup_disposition", "PAY")
    assert any("multipart/form-data; boundary=" in a for a in argv)


def test_xml_body_escapes_and_wraps():
    body = _argv("xml_body", "<x>")[-1]
    assert "<q>" in body and "&lt;x&gt;" in body           # payload XML-escaped inside <q>


def test_mp_truncated_has_no_closing_boundary():
    argv = _argv("mp_truncated", "PAY")
    body = argv[-1]
    assert "PAY" in body and body.endswith("PAY")          # unterminated: ends at the payload
    assert "--WAFFENb0undary--" not in body                # no closing boundary -> ErrUnexpectedEOF
    assert any("multipart/form-data; boundary=" in a for a in argv)


def test_mp_filename_rfc2231_carries_payload_in_extended_param():
    argv = _argv("mp_filename_rfc2231", "../x.jsp")
    body = argv[-1]
    assert 'filename="decoy.txt"' in body                  # benign decoy the WAF reads
    assert "filename*=UTF-8''" in body                     # RFC 2231 extended param
    assert "%2F" in body or "%2f" in body                  # payload percent-encoded (/ -> %2F)
    assert body.rstrip().endswith("--WAFFENb0undary--")    # properly closed (unlike mp_truncated)
