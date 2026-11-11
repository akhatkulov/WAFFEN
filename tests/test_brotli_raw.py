"""Tests for the pure-stdlib Brotli stored-stream encoder and the brotli_body
request transform (CVE-2026-111497 compression blind-spot primitive).

The encoder's correctness is checked two ways: structural assertions that always
run, and a byte-for-byte round-trip through a real external decoder (`brotli` CLI
or `node`'s zlib.brotliDecompressSync) that is skipped when neither is installed,
so CI without those tools still passes.
"""
import os
import shutil
import subprocess
import urllib.parse

import pytest

from waffen.core import transforms as T
from waffen.core.brotli_raw import compress_stored
from waffen.core.oracle import Target


def _external_decode(b: bytes):
    """Decode a Brotli stream with whatever real decoder is available, or None."""
    if shutil.which("brotli"):
        p = subprocess.run(["brotli", "-dc"], input=b, capture_output=True)
        if p.returncode == 0:
            return p.stdout
    if shutil.which("node"):
        p = subprocess.run(
            ["node", "-e",
             "const z=require('zlib');const c=[];process.stdin.on('data',d=>c.push(d));"
             "process.stdin.on('end',()=>process.stdout.write(z.brotliDecompressSync(Buffer.concat(c))))"],
            input=b, capture_output=True)
        if p.returncode == 0:
            return p.stdout
    return None


CASES = [b"", b"q", b'{"audit":"ok"}', b"<script>alert(1)</script>",
         b"' OR 1=1-- -" * 20, bytes(range(256)), os.urandom(4096)]


def test_stored_stream_structure():
    # empty input -> WBITS + empty last meta-block only
    assert compress_stored(b"") == bytes([0x06]) or compress_stored(b"")[-1] == 0x03
    for data in CASES:
        enc = compress_stored(data)
        assert isinstance(enc, bytes) and len(enc) >= 1
        if data:
            assert enc[-1] == 0x03          # final empty ISLAST/ISLASTEMPTY meta-block
            assert len(enc) >= len(data)    # stored: payload rides verbatim + framing


@pytest.mark.parametrize("data", CASES)
def test_round_trip_through_real_decoder(data):
    dec = _external_decode(compress_stored(data))
    if dec is None:
        pytest.skip("no external brotli decoder (brotli CLI / node) available")
    assert dec == data


def _t():
    return Target(base_url="https://x.example", path="/api", param="q")


def test_brotli_body_transform_argv_uses_stdin():
    argv = T.get("brotli_body").build(_t(), "<script>alert(1)</script>")
    assert argv[0] == "curl" and "-X" in argv and "POST" in argv
    assert any(a == "Content-Encoding: br" for a in argv)
    assert "@-" in argv                      # binary body is piped on stdin, not in argv


def test_brotli_body_stdin_is_valid_brotli_of_the_form_field():
    tr = T.get("brotli_body")
    payload = "<script>alert(1)</script>"
    blob = tr.stdin(_t(), payload)
    assert isinstance(blob, bytes) and blob[-1] == 0x03
    expected = urllib.parse.urlencode({"q": payload}).encode()
    dec = _external_decode(blob)
    if dec is None:
        pytest.skip("no external brotli decoder available")
    assert dec == expected                   # br stream decodes to the urlencoded field


def test_non_binary_transforms_have_no_stdin():
    # the stdin channel is opt-in: ordinary transforms never trigger the stdin path
    for name in ("identity", "graphql_body", "json_body", "mp_truncated"):
        assert T.get(name).stdin(_t(), "PAY") is None
