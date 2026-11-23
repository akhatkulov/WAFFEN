"""Minimal HTTP/2 client for WAF bypass testing (stdlib-only).

NOT a general-purpose H2 client — just enough to send crafted requests
through an H2 connection for testing WAF inspection of HTTP/2 traffic.
Supports HPACK literal encoding, CONTINUATION frame splitting, raw frame
injection, and stream multiplexing.

TLS ALPN negotiates h2; falls back to ConnectionError if the server
does not support it.
"""
from __future__ import annotations

import socket
import ssl
import struct
from dataclasses import dataclass, field

# -- frame types (RFC 7540 §6) -----------------------------------------------
FRAME_DATA = 0x0
FRAME_HEADERS = 0x1
FRAME_PRIORITY = 0x2
FRAME_RST_STREAM = 0x3
FRAME_SETTINGS = 0x4
FRAME_PUSH_PROMISE = 0x5
FRAME_PING = 0x6
FRAME_GOAWAY = 0x7
FRAME_WINDOW_UPDATE = 0x8
FRAME_CONTINUATION = 0x9

# -- flags --------------------------------------------------------------------
FLAG_END_STREAM = 0x1
FLAG_END_HEADERS = 0x4
FLAG_ACK = 0x1
FLAG_PADDED = 0x8

# -- settings (RFC 7540 §6.5.2) ----------------------------------------------
SETTINGS_HEADER_TABLE_SIZE = 0x1
SETTINGS_ENABLE_PUSH = 0x2
SETTINGS_MAX_CONCURRENT_STREAMS = 0x3
SETTINGS_INITIAL_WINDOW_SIZE = 0x4
SETTINGS_MAX_FRAME_SIZE = 0x5
SETTINGS_MAX_HEADER_LIST_SIZE = 0x6

CONNECTION_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# -- HPACK (minimal literal-only, RFC 7541) -----------------------------------

# Partial static table — the entries we actually use for injection.
HPACK_STATIC: dict[int, tuple[str, str]] = {
    1: (":authority", ""),
    2: (":method", "GET"),
    3: (":method", "POST"),
    4: (":path", "/"),
    5: (":path", "/index.html"),
    6: (":scheme", "http"),
    7: (":scheme", "https"),
    8: (":status", "200"),
    15: ("accept-charset", ""),
    16: ("accept-encoding", "gzip, deflate"),
    17: ("accept-language", ""),
    19: ("accept", ""),
    28: ("content-length", ""),
    31: ("content-type", ""),
    32: ("cookie", ""),
    33: ("date", ""),
    38: ("host", ""),
    58: ("user-agent", ""),
}

_STATIC_BY_NAME: dict[str, int] = {}
_STATIC_BY_PAIR: dict[tuple[str, str], int] = {}
for _idx, (_n, _v) in HPACK_STATIC.items():
    _STATIC_BY_PAIR[(_n, _v)] = _idx
    if _n not in _STATIC_BY_NAME:
        _STATIC_BY_NAME[_n] = _idx


def _encode_int(value: int, prefix_bits: int) -> bytes:
    """HPACK integer encoding (RFC 7541 §5.1)."""
    max_prefix = (1 << prefix_bits) - 1
    if value < max_prefix:
        return bytes([value])
    out = bytearray([max_prefix])
    value -= max_prefix
    while value >= 128:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _encode_string(s: str, huffman: bool = False) -> bytes:
    """HPACK string literal (RFC 7541 §5.2). No Huffman for now."""
    raw = s.encode("utf-8")
    prefix = 0x80 if huffman else 0x00
    length = _encode_int(len(raw), 7)
    return bytes([prefix | length[0]]) + length[1:] + raw


def hpack_encode(headers: list[tuple[str, str]],
                 never_index: bool = True) -> bytes:
    """Encode a header list as HPACK literals.

    Uses *literal-never-indexed* by default (0x10 prefix) which prevents WAFs
    from relying on HPACK dynamic table state — each request is self-contained.
    Set ``never_index=False`` to use *literal-without-indexing* (0x00).
    """
    out = bytearray()
    for name, value in headers:
        # Check if the name is in the static table
        pair_idx = _STATIC_BY_PAIR.get((name, value))
        if pair_idx is not None:
            # Indexed header field (top bit set)
            out.extend(bytes([0x80]) + _encode_int(pair_idx, 7)[0:1])
            # Actually: fully indexed = single byte 0x80|idx
            out.clear()  # redo properly
            break

    # Simpler: always literal-never-indexed for reliability
    out = bytearray()
    for name, value in headers:
        name_idx = _STATIC_BY_NAME.get(name)
        if name_idx is not None and never_index:
            # Literal never indexed with name index (0001xxxx)
            idx_bytes = _encode_int(name_idx, 4)
            out.append(0x10 | idx_bytes[0])
            out.extend(idx_bytes[1:])
        elif name_idx is not None:
            # Literal without indexing with name index (0000xxxx)
            idx_bytes = _encode_int(name_idx, 4)
            out.append(0x00 | idx_bytes[0])
            out.extend(idx_bytes[1:])
        else:
            # Literal with new name
            out.append(0x10 if never_index else 0x00)
            out.extend(_encode_string(name))
        out.extend(_encode_string(value))
    return bytes(out)


def hpack_decode_status(data: bytes) -> str:
    """Extract :status from an HPACK-encoded header block (best effort).

    Only handles the indexed form (0x80|8 = 0x88 for 200, etc.) and
    literal forms. Returns the status string or '0' on failure.
    """
    if not data:
        return "0"
    pos = 0
    while pos < len(data):
        byte = data[pos]
        if byte & 0x80:  # indexed
            idx = byte & 0x7F
            static = HPACK_STATIC.get(idx)
            if static and static[0] == ":status":
                return static[1]
            pos += 1
        elif byte & 0x40:  # literal with incremental indexing
            if byte & 0x3F:
                idx = byte & 0x3F
                pos += 1
            else:
                pos += 1
                name_len = data[pos] & 0x7F
                pos += 1 + name_len
            val_len = data[pos] & 0x7F if pos < len(data) else 0
            pos += 1 + val_len
            static = HPACK_STATIC.get(byte & 0x3F) if byte & 0x3F else None
            if static and static[0] == ":status" and val_len:
                return data[pos - val_len:pos].decode("utf-8", "replace")
        else:  # literal without indexing or never indexed
            if byte & 0x0F:
                idx = byte & 0x0F
                pos += 1
            else:
                pos += 1
                if pos >= len(data):
                    break
                name_len = data[pos] & 0x7F
                pos += 1 + name_len
            if pos >= len(data):
                break
            val_len = data[pos] & 0x7F
            val_start = pos + 1
            pos = val_start + val_len
            static = HPACK_STATIC.get(byte & 0x0F) if byte & 0x0F else None
            if static and static[0] == ":status":
                return data[val_start:pos].decode("utf-8", "replace")
    return "0"


# -- H2 frame helpers ---------------------------------------------------------

@dataclass
class H2Frame:
    frame_type: int
    flags: int
    stream_id: int
    payload: bytes


def build_frame(frame_type: int, stream_id: int, payload: bytes,
                flags: int = 0) -> bytes:
    """Build a raw HTTP/2 frame (9-byte header + payload)."""
    length = len(payload)
    header = struct.pack(">I", length)[1:]     # 3-byte length
    header += struct.pack("B", frame_type)
    header += struct.pack("B", flags)
    header += struct.pack(">I", stream_id & 0x7FFFFFFF)
    return header + payload


def parse_frame(data: bytes) -> tuple[H2Frame | None, bytes]:
    """Parse one frame from the front of *data*. Returns (frame, remaining).
    Returns (None, data) if not enough bytes yet."""
    if len(data) < 9:
        return None, data
    length = (data[0] << 16) | (data[1] << 8) | data[2]
    if len(data) < 9 + length:
        return None, data
    frame_type = data[3]
    flags = data[4]
    stream_id = struct.unpack(">I", data[5:9])[0] & 0x7FFFFFFF
    payload = data[9:9 + length]
    return H2Frame(frame_type, flags, stream_id, payload), data[9 + length:]


# -- connection ----------------------------------------------------------------

@dataclass
class H2Response:
    status: str = "0"
    headers_raw: bytes = b""
    body: bytes = b""
    frames: list[H2Frame] = field(default_factory=list)


class H2Connection:
    """Minimal HTTP/2 connection for WAF bypass testing."""

    def __init__(self, host: str, port: int = 443, timeout: float = 10.0,
                 tls_verify: bool = False):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.tls_verify = tls_verify
        self._sock: ssl.SSLSocket | socket.socket | None = None
        self._stream_id = -1  # next odd stream id
        self._buf = b""

    def connect(self):
        """TLS connect with ALPN h2 negotiation + connection preface."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if not self.tls_verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2", "http/1.1"])

        raw = socket.create_connection((self.host, self.port),
                                       timeout=self.timeout)
        self._sock = ctx.wrap_socket(raw, server_hostname=self.host)

        proto = self._sock.selected_alpn_protocol()
        if proto != "h2":
            raise ConnectionError(
                f"ALPN negotiated {proto!r}, expected 'h2' "
                f"(server may not support HTTP/2)")

        # Connection preface (RFC 7540 §3.5)
        self._sock.sendall(CONNECTION_PREFACE)

        # Client SETTINGS (we accept defaults)
        self._sock.sendall(build_frame(FRAME_SETTINGS, 0, b""))

        # Read until we get the server's SETTINGS frame
        self._drain_until_settings()

        # ACK server settings
        self._sock.sendall(build_frame(FRAME_SETTINGS, 0, b"",
                                        flags=FLAG_ACK))

    def _drain_until_settings(self):
        """Read frames until we see SETTINGS from the server (and ACK it)."""
        for _ in range(20):  # safety bound
            frame = self._read_one_frame()
            if frame is None:
                break
            if frame.frame_type == FRAME_SETTINGS and not (frame.flags & FLAG_ACK):
                return
            if frame.frame_type == FRAME_GOAWAY:
                raise ConnectionError("Server sent GOAWAY during setup")

    def _next_stream(self) -> int:
        self._stream_id += 2
        return self._stream_id

    # -- low-level I/O ---------------------------------------------------------

    def send_frame(self, frame_type: int, stream_id: int, payload: bytes,
                   flags: int = 0):
        """Send a single H2 frame."""
        if self._sock is None:
            raise ConnectionError("not connected")
        self._sock.sendall(build_frame(frame_type, stream_id, payload, flags))

    def send_raw(self, data: bytes):
        """Send raw bytes — for HPACK/frame injection testing."""
        if self._sock is None:
            raise ConnectionError("not connected")
        self._sock.sendall(data)

    def _recv(self, n: int = 16384) -> bytes:
        if self._sock is None:
            return b""
        self._sock.settimeout(self.timeout)
        try:
            return self._sock.recv(n)
        except (socket.timeout, ssl.SSLError):
            return b""

    def _read_one_frame(self) -> H2Frame | None:
        """Read exactly one frame (blocking, with timeout)."""
        while True:
            frame, self._buf = parse_frame(self._buf)
            if frame is not None:
                return frame
            chunk = self._recv()
            if not chunk:
                return None
            self._buf += chunk

    def _read_frames(self, stream_id: int, timeout: float | None = None) -> list[H2Frame]:
        """Read all frames for *stream_id* until END_STREAM or timeout."""
        import time
        t = timeout or self.timeout
        deadline = time.monotonic() + t
        frames: list[H2Frame] = []
        while time.monotonic() < deadline:
            frame = self._read_one_frame()
            if frame is None:
                break
            # Window update on stream 0 — ACK it and continue
            if frame.frame_type == FRAME_WINDOW_UPDATE and frame.stream_id == 0:
                continue
            if frame.stream_id == stream_id or frame.stream_id == 0:
                frames.append(frame)
            if (frame.stream_id == stream_id and
                    frame.flags & FLAG_END_STREAM):
                break
            if frame.frame_type == FRAME_GOAWAY:
                break
            if frame.frame_type == FRAME_RST_STREAM and frame.stream_id == stream_id:
                break
        return frames

    # -- high-level request ----------------------------------------------------

    def request(self, method: str, path: str,
                headers: dict[str, str] | None = None,
                body: bytes | None = None) -> H2Response:
        """Send an HTTP/2 request and read the response."""
        sid = self._next_stream()

        h2_headers = [
            (":method", method),
            (":path", path),
            (":scheme", "https"),
            (":authority", self.host),
        ]
        if headers:
            for k, v in headers.items():
                h2_headers.append((k.lower(), v))

        encoded = hpack_encode(h2_headers)

        flags = FLAG_END_HEADERS
        if body is None:
            flags |= FLAG_END_STREAM
        self.send_frame(FRAME_HEADERS, sid, encoded, flags=flags)

        if body is not None:
            self.send_frame(FRAME_DATA, sid, body, flags=FLAG_END_STREAM)

        # Read response
        resp_frames = self._read_frames(sid)
        return self._assemble_response(resp_frames)

    def request_raw_headers(self, hpack_bytes: bytes, stream_id: int | None = None,
                            body: bytes | None = None) -> H2Response:
        """Send a request with pre-built HPACK bytes — for injection testing."""
        sid = stream_id or self._next_stream()
        flags = FLAG_END_HEADERS
        if body is None:
            flags |= FLAG_END_STREAM
        self.send_frame(FRAME_HEADERS, sid, hpack_bytes, flags=flags)
        if body is not None:
            self.send_frame(FRAME_DATA, sid, body, flags=FLAG_END_STREAM)
        return self._assemble_response(self._read_frames(sid))

    def _assemble_response(self, frames: list[H2Frame]) -> H2Response:
        resp = H2Response(frames=frames)
        header_data = b""
        body_data = b""
        for f in frames:
            if f.frame_type in (FRAME_HEADERS, FRAME_CONTINUATION):
                header_data += f.payload
            elif f.frame_type == FRAME_DATA:
                body_data += f.payload
        resp.headers_raw = header_data
        resp.body = body_data
        resp.status = hpack_decode_status(header_data)
        return resp

    # -- multiplex: send multiple requests on one connection --------------------

    def multiplex(self, requests: list[tuple[str, str, dict | None, bytes | None]],
                  ) -> list[H2Response]:
        """Send multiple requests simultaneously (different streams).

        Each entry is (method, path, headers_dict_or_None, body_or_None).
        Returns a response per request.
        """
        sids = []
        for method, path, hdrs, body in requests:
            sid = self._next_stream()
            sids.append(sid)
            h2h = [
                (":method", method),
                (":path", path),
                (":scheme", "https"),
                (":authority", self.host),
            ]
            if hdrs:
                for k, v in hdrs.items():
                    h2h.append((k.lower(), v))
            enc = hpack_encode(h2h)
            flags = FLAG_END_HEADERS
            if body is None:
                flags |= FLAG_END_STREAM
            self.send_frame(FRAME_HEADERS, sid, enc, flags=flags)
            if body is not None:
                self.send_frame(FRAME_DATA, sid, body, flags=FLAG_END_STREAM)

        # Read all responses
        import time
        deadline = time.monotonic() + self.timeout
        by_stream: dict[int, list[H2Frame]] = {s: [] for s in sids}
        done = set()
        while len(done) < len(sids) and time.monotonic() < deadline:
            frame = self._read_one_frame()
            if frame is None:
                break
            if frame.stream_id in by_stream:
                by_stream[frame.stream_id].append(frame)
                if frame.flags & FLAG_END_STREAM:
                    done.add(frame.stream_id)
                if frame.frame_type == FRAME_RST_STREAM:
                    done.add(frame.stream_id)
            if frame.frame_type == FRAME_GOAWAY:
                break

        return [self._assemble_response(by_stream.get(s, [])) for s in sids]

    # -- close -----------------------------------------------------------------

    def close(self):
        if self._sock is not None:
            try:
                self.send_frame(FRAME_GOAWAY, 0,
                                struct.pack(">II", self._stream_id, 0))
            except Exception:
                pass  # cleanup: goaway send must never crash
            try:
                self._sock.close()
            except Exception:
                pass  # cleanup
            self._sock = None
