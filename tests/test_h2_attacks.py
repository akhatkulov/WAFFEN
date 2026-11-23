"""Tests for HTTP/2 WAF bypass attack functions.

Uses a mock H2Connection to avoid real network calls.
"""
from unittest.mock import MagicMock, call, patch
from dataclasses import dataclass

import pytest

from waffen.core.h2 import (
    H2Response, hpack_encode, FRAME_HEADERS, FRAME_CONTINUATION,
    FLAG_END_STREAM, FLAG_END_HEADERS, _encode_string,
)
from waffen.core.h2_attacks import (
    pseudo_header_inject,
    pseudo_header_raw_inject,
    continuation_frame_split,
    header_name_case,
    stream_multiplex_race,
    duplicate_pseudo_header,
    oversized_header_block,
)


def _mock_conn(host="test.com"):
    """Create a mock H2Connection that records calls."""
    conn = MagicMock()
    conn.host = host
    conn._stream_id = 1

    def next_stream():
        conn._stream_id += 2
        return conn._stream_id
    conn._next_stream = next_stream

    fake_resp = H2Response(status="200", headers_raw=b"", body=b"ok", frames=[])
    conn.request.return_value = fake_resp
    conn.request_raw_headers.return_value = fake_resp
    conn.multiplex.return_value = [fake_resp]
    conn._assemble_response.return_value = fake_resp
    conn._read_frames.return_value = []
    return conn


class TestPseudoHeaderInject:
    def test_calls_request_with_payload_in_path(self):
        conn = _mock_conn()
        pseudo_header_inject(conn, "/search", "' OR 1=1--", method="GET")
        conn.request.assert_called_once()
        path_arg = conn.request.call_args[0][1]
        assert "' OR 1=1--" not in path_arg  # should be URL-encoded
        assert "%27" in path_arg or "OR" in path_arg

    def test_appends_to_existing_query(self):
        conn = _mock_conn()
        pseudo_header_inject(conn, "/search?existing=1", "payload")
        path_arg = conn.request.call_args[0][1]
        assert "existing=1" in path_arg
        assert "&q=" in path_arg


class TestPseudoHeaderRawInject:
    def test_sends_unencoded_payload(self):
        conn = _mock_conn()
        pseudo_header_raw_inject(conn, "/search", "' OR 1=1--")
        conn.request_raw_headers.assert_called_once()
        hpack_bytes = conn.request_raw_headers.call_args[0][0]
        assert isinstance(hpack_bytes, bytes)


class TestContinuationFrameSplit:
    def test_sends_headers_then_continuation(self):
        conn = _mock_conn()
        conn.send_frame = MagicMock()
        continuation_frame_split(conn, "/search", "' OR 1=1--")

        assert conn.send_frame.call_count == 2
        # First call: HEADERS without END_HEADERS
        first = conn.send_frame.call_args_list[0]
        assert first[0][0] == FRAME_HEADERS
        assert first[1].get("flags", first[0][3] if len(first[0]) > 3 else 0) & FLAG_END_HEADERS == 0

        # Second call: CONTINUATION with END_HEADERS
        second = conn.send_frame.call_args_list[1]
        assert second[0][0] == FRAME_CONTINUATION
        flags = second[1].get("flags", second[0][3] if len(second[0]) > 3 else 0)
        assert flags & FLAG_END_HEADERS != 0

    def test_uses_same_stream_id(self):
        conn = _mock_conn()
        conn.send_frame = MagicMock()
        continuation_frame_split(conn, "/search", "test")
        sid1 = conn.send_frame.call_args_list[0][0][1]
        sid2 = conn.send_frame.call_args_list[1][0][1]
        assert sid1 == sid2


class TestHeaderNameCase:
    def test_sends_raw_hpack_with_uppercase(self):
        conn = _mock_conn()
        header_name_case(conn, "/search", "' OR 1=1--")
        conn.request_raw_headers.assert_called_once()
        hpack_bytes = conn.request_raw_headers.call_args[0][0]
        # Should contain uppercase :METHOD, :PATH etc
        assert b":METHOD" in hpack_bytes or b"METHOD" in hpack_bytes


class TestStreamMultiplexRace:
    def test_calls_multiplex_with_all_payloads(self):
        conn = _mock_conn()
        payloads = ["' OR 1=1--", "<script>alert(1)</script>", "{{7*7}}"]
        stream_multiplex_race(conn, "/search", payloads)
        conn.multiplex.assert_called_once()
        requests = conn.multiplex.call_args[0][0]
        assert len(requests) == 3


class TestDuplicatePseudoHeader:
    def test_sends_two_path_headers(self):
        conn = _mock_conn()
        duplicate_pseudo_header(conn, "/search", "' OR 1=1--")
        conn.request_raw_headers.assert_called_once()
        hpack_bytes = conn.request_raw_headers.call_args[0][0]
        assert isinstance(hpack_bytes, bytes)


class TestOversizedHeaderBlock:
    def test_pads_headers(self):
        conn = _mock_conn()
        oversized_header_block(conn, "/search", "' OR 1=1--", pad_size=2000)
        conn.request_raw_headers.assert_called_once()
        hpack_bytes = conn.request_raw_headers.call_args[0][0]
        # Padded headers should make the block much larger than a normal request
        assert len(hpack_bytes) > 1000

    def test_default_pad_size(self):
        conn = _mock_conn()
        oversized_header_block(conn, "/search", "test")
        hpack_bytes = conn.request_raw_headers.call_args[0][0]
        assert len(hpack_bytes) > 5000
