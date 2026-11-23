"""Tests for the HTTP/2 transport and attack modules.

All tests use mock sockets — no real network.
"""
from unittest.mock import MagicMock, patch
import struct
import pytest

from waffen.core.h2 import (
    H2Connection,
    H2Frame,
    H2Response,
    build_frame,
    parse_frame,
    hpack_encode,
    hpack_decode_status,
    _encode_int,
    _encode_string,
    CONNECTION_PREFACE,
    FRAME_DATA,
    FRAME_HEADERS,
    FRAME_SETTINGS,
    FRAME_GOAWAY,
    FRAME_CONTINUATION,
    FRAME_WINDOW_UPDATE,
    FRAME_RST_STREAM,
    FLAG_END_STREAM,
    FLAG_END_HEADERS,
    FLAG_ACK,
)


# -- HPACK encoding ----------------------------------------------------------

class TestEncodeInt:
    def test_small_value(self):
        assert _encode_int(5, 5) == bytes([5])

    def test_max_prefix(self):
        result = _encode_int(31, 5)
        assert result[0] == 31
        assert len(result) == 2

    def test_zero(self):
        assert _encode_int(0, 7) == bytes([0])

    def test_large_value(self):
        result = _encode_int(300, 5)
        assert len(result) >= 3


class TestEncodeString:
    def test_simple_string(self):
        result = _encode_string("hello")
        assert len(result) == 1 + 5  # 1 byte length + 5 bytes
        assert result[0] == 5  # length without huffman flag
        assert result[1:] == b"hello"

    def test_empty_string(self):
        result = _encode_string("")
        assert result == bytes([0])

    def test_unicode_string(self):
        result = _encode_string("/path?q=' OR 1=1--")
        assert b"OR 1=1" in result


class TestHpackEncode:
    def test_basic_request(self):
        headers = [
            (":method", "GET"),
            (":path", "/"),
            (":scheme", "https"),
            (":authority", "example.com"),
        ]
        encoded = hpack_encode(headers)
        assert len(encoded) > 0
        assert isinstance(encoded, bytes)

    def test_with_custom_headers(self):
        headers = [
            (":method", "POST"),
            (":path", "/api"),
            (":scheme", "https"),
            (":authority", "example.com"),
            ("content-type", "application/json"),
            ("x-custom", "value"),
        ]
        encoded = hpack_encode(headers)
        assert b"application/json" in encoded
        assert b"x-custom" in encoded

    def test_never_index(self):
        headers = [(":method", "GET"), (":path", "/secret")]
        enc_ni = hpack_encode(headers, never_index=True)
        enc_no = hpack_encode(headers, never_index=False)
        # Both should produce valid HPACK — encoding differs by prefix bits
        assert len(enc_ni) > 0
        assert len(enc_no) > 0

    def test_payload_in_path(self):
        headers = [(":path", "/search?q=' OR 1=1--")]
        encoded = hpack_encode(headers)
        assert b"OR 1=1" in encoded


class TestHpackDecodeStatus:
    def test_indexed_200(self):
        # Static table entry 8 = :status 200 → indexed form 0x88
        assert hpack_decode_status(bytes([0x88])) == "200"

    def test_empty(self):
        assert hpack_decode_status(b"") == "0"

    def test_literal_status(self):
        # Literal with name index for :status (index 8 in static table)
        # Need to construct a valid literal-never-indexed with the status value
        # For robustness, test that non-200 status is extractable
        data = bytearray()
        data.append(0x18)  # literal never indexed, name index 8 (:status)
        data.append(3)     # value length
        data.extend(b"403")
        assert hpack_decode_status(bytes(data)) == "403"


# -- frame building/parsing --------------------------------------------------

class TestBuildFrame:
    def test_settings_frame(self):
        frame = build_frame(FRAME_SETTINGS, 0, b"")
        assert len(frame) == 9  # header only, no payload
        assert frame[3] == FRAME_SETTINGS
        assert frame[4] == 0  # no flags

    def test_data_frame(self):
        payload = b"hello world"
        frame = build_frame(FRAME_DATA, 1, payload, flags=FLAG_END_STREAM)
        assert len(frame) == 9 + len(payload)
        # check length field
        length = (frame[0] << 16) | (frame[1] << 8) | frame[2]
        assert length == len(payload)
        assert frame[3] == FRAME_DATA
        assert frame[4] == FLAG_END_STREAM

    def test_stream_id_in_frame(self):
        frame = build_frame(FRAME_HEADERS, 3, b"test")
        sid = struct.unpack(">I", frame[5:9])[0] & 0x7FFFFFFF
        assert sid == 3

    def test_goaway_frame(self):
        payload = struct.pack(">II", 0, 0)
        frame = build_frame(FRAME_GOAWAY, 0, payload)
        assert frame[3] == FRAME_GOAWAY


class TestParseFrame:
    def test_round_trip(self):
        original = build_frame(FRAME_DATA, 5, b"payload", flags=FLAG_END_STREAM)
        frame, remaining = parse_frame(original)
        assert frame is not None
        assert frame.frame_type == FRAME_DATA
        assert frame.stream_id == 5
        assert frame.payload == b"payload"
        assert frame.flags == FLAG_END_STREAM
        assert remaining == b""

    def test_incomplete_data(self):
        frame, remaining = parse_frame(b"\x00\x00")
        assert frame is None
        assert remaining == b"\x00\x00"

    def test_multiple_frames(self):
        f1 = build_frame(FRAME_SETTINGS, 0, b"", flags=FLAG_ACK)
        f2 = build_frame(FRAME_DATA, 1, b"hello")
        combined = f1 + f2
        frame1, rest = parse_frame(combined)
        assert frame1.frame_type == FRAME_SETTINGS
        frame2, rest2 = parse_frame(rest)
        assert frame2.frame_type == FRAME_DATA
        assert frame2.payload == b"hello"
        assert rest2 == b""

    def test_empty_input(self):
        frame, remaining = parse_frame(b"")
        assert frame is None


# -- H2Response ---------------------------------------------------------------

class TestH2Response:
    def test_defaults(self):
        r = H2Response()
        assert r.status == "0"
        assert r.body == b""
        assert r.frames == []


# -- H2Connection (mocked) ---------------------------------------------------

class TestH2Connection:
    def test_init(self):
        conn = H2Connection("example.com", 443)
        assert conn.host == "example.com"
        assert conn.port == 443
        assert conn._sock is None

    def test_next_stream_odd(self):
        conn = H2Connection("example.com")
        s1 = conn._next_stream()
        s2 = conn._next_stream()
        assert s1 % 2 == 1  # client streams are odd
        assert s2 == s1 + 2

    def test_close_no_connection(self):
        conn = H2Connection("example.com")
        conn.close()  # should not raise

    def test_send_frame_not_connected(self):
        conn = H2Connection("example.com")
        with pytest.raises(ConnectionError, match="not connected"):
            conn.send_frame(FRAME_DATA, 1, b"test")

    def test_send_raw_not_connected(self):
        conn = H2Connection("example.com")
        with pytest.raises(ConnectionError, match="not connected"):
            conn.send_raw(b"test")


# -- H2 attacks (unit level) ------------------------------------------------

class TestH2Attacks:
    """Test attack helper functions build correct frames/headers."""

    def test_import(self):
        from waffen.core import h2_attacks
        assert hasattr(h2_attacks, "pseudo_header_inject")
        assert hasattr(h2_attacks, "continuation_frame_split")
        assert hasattr(h2_attacks, "header_name_case")
        assert hasattr(h2_attacks, "stream_multiplex_race")
        assert hasattr(h2_attacks, "duplicate_pseudo_header")
        assert hasattr(h2_attacks, "oversized_header_block")

    def test_hpack_with_sqli_payload(self):
        headers = [
            (":method", "GET"),
            (":path", "/search?q=' OR 1=1--"),
            (":scheme", "https"),
            (":authority", "target.com"),
        ]
        enc = hpack_encode(headers)
        assert b"OR 1=1" in enc

    def test_continuation_builds_two_parts(self):
        # Verify the split produces two distinct HPACK blocks
        h1 = [(":method", "GET"), (":scheme", "https"), (":authority", "x")]
        h2 = [(":path", "/search?q=payload")]
        enc1 = hpack_encode(h1)
        enc2 = hpack_encode(h2)
        assert len(enc1) > 0
        assert len(enc2) > 0
        assert enc1 != enc2

    def test_uppercase_pseudo_headers(self):
        # Build HPACK with uppercase names manually
        hpack_bytes = bytearray()
        for name, value in [(":METHOD", "GET"), (":PATH", "/")]:
            hpack_bytes.append(0x10)
            hpack_bytes.extend(_encode_string(name))
            hpack_bytes.extend(_encode_string(value))
        result = bytes(hpack_bytes)
        assert b":METHOD" in result
        assert b":PATH" in result

    def test_duplicate_path_in_hpack(self):
        headers = [
            (":path", "/safe"),
            (":path", "/search?q=' OR 1=1--"),
        ]
        enc = hpack_encode(headers)
        assert b"/safe" in enc
        assert b"OR 1=1" in enc


# -- Oracle h2 transport integration -----------------------------------------

class TestOracleH2Transport:
    def test_oracle_accepts_h2_transport(self):
        from waffen.core.oracle import Oracle, Target
        t = Target(base_url="https://example.com", path="/")
        # With a mock sender to avoid real connection
        o = Oracle(t, transport="h2")
        assert o.transport == "h2"

    def test_oracle_h2_sender_set(self):
        from waffen.core.oracle import Oracle, Target
        t = Target(base_url="https://example.com", path="/")
        o = Oracle(t, transport="h2")
        assert o._sender == o._h2_send
