"""Minimal stdlib-only WebSocket client for WAF bypass testing."""
from __future__ import annotations

import base64
import hashlib
import os
import socket
import ssl
import struct
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse


_WS_MAGIC = "258EAFA5-E914-47DA-95CA-5AB5AA29D950"


@dataclass
class WSFrame:
    opcode: int  # 0x1=text, 0x2=binary, 0x8=close, 0x9=ping, 0xA=pong
    payload: bytes
    fin: bool = True


class WSClient:
    """Minimal RFC 6455 WebSocket client (stdlib-only, no dependencies)."""

    def __init__(self, url: str, tls_verify: bool = False, timeout: float = 10.0,
                 extra_headers: tuple[str, ...] = (), origin: str = ""):
        self.url = url
        self.tls_verify = tls_verify
        self.timeout = timeout
        self.extra_headers = extra_headers
        self._origin = origin
        self._sock: Optional[socket.socket] = None
        self._connected = False

        parsed = urlparse(url)
        self._host = parsed.hostname or "localhost"
        self._port = parsed.port or (443 if parsed.scheme in ("wss", "https") else 80)
        self._path = parsed.path or "/"
        if parsed.query:
            self._path += "?" + parsed.query
        self._use_tls = parsed.scheme in ("wss", "https")

    def connect(self) -> bool:
        """Perform HTTP upgrade handshake. Returns True on success."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        if self._use_tls:
            ctx = ssl.create_default_context()
            if not self.tls_verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=self._host)
        sock.connect((self._host, self._port))

        key = base64.b64encode(os.urandom(16)).decode()
        origin = self._origin or f"{'https' if self._use_tls else 'http'}://{self._host}"

        req = (
            f"GET {self._path} HTTP/1.1\r\n"
            f"Host: {self._host}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"Origin: {origin}\r\n"
        )
        for h in self.extra_headers:
            req += f"{h}\r\n"
        req += "\r\n"

        sock.sendall(req.encode())

        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = sock.recv(4096)
            if not chunk:
                sock.close()
                return False
            resp += chunk

        if b"101" not in resp.split(b"\r\n")[0]:
            sock.close()
            return False

        expected_accept = base64.b64encode(
            hashlib.sha1((key + _WS_MAGIC).encode()).digest()
        ).decode()
        if expected_accept.encode() not in resp:
            sock.close()
            return False

        self._sock = sock
        self._connected = True
        return True

    def send(self, message: str) -> None:
        """Send a text frame."""
        self._send_frame(0x1, message.encode())

    def send_binary(self, data: bytes) -> None:
        """Send a binary frame."""
        self._send_frame(0x2, data)

    def send_fragmented(self, message: str, fragment_size: int = 10) -> None:
        """Send a text message split into multiple frames."""
        payload = message.encode()
        chunks = [payload[i:i + fragment_size]
                  for i in range(0, len(payload), fragment_size)]
        for i, chunk in enumerate(chunks):
            is_first = i == 0
            is_last = i == len(chunks) - 1
            opcode = 0x1 if is_first else 0x0  # continuation frame
            fin = is_last
            self._send_frame(opcode, chunk, fin=fin)

    def recv(self, timeout: float = 5.0) -> Optional[WSFrame]:
        """Receive one WebSocket frame."""
        if not self._sock:
            return None
        self._sock.settimeout(timeout)
        try:
            data = self._sock.recv(16384)
            if not data or len(data) < 2:
                return None
            return self._parse_frame(data)
        except (socket.timeout, OSError):
            return None

    def close(self) -> None:
        """Send close frame and tear down."""
        if self._sock and self._connected:
            try:
                self._send_frame(0x8, b"")
            except OSError:
                pass
            try:
                self._sock.close()
            except OSError:
                pass
        self._connected = False
        self._sock = None

    @property
    def connected(self) -> bool:
        return self._connected

    def _send_frame(self, opcode: int, payload: bytes, fin: bool = True) -> None:
        if not self._sock:
            raise ConnectionError("not connected")
        frame = bytearray()
        frame.append((0x80 if fin else 0x00) | opcode)

        length = len(payload)
        if length < 126:
            frame.append(0x80 | length)
        elif length < 65536:
            frame.append(0x80 | 126)
            frame.extend(struct.pack(">H", length))
        else:
            frame.append(0x80 | 127)
            frame.extend(struct.pack(">Q", length))

        mask = os.urandom(4)
        frame.extend(mask)
        for i, b in enumerate(payload):
            frame.append(b ^ mask[i % 4])

        self._sock.sendall(bytes(frame))

    @staticmethod
    def _parse_frame(data: bytes) -> WSFrame:
        fin = bool(data[0] & 0x80)
        opcode = data[0] & 0x0F
        masked = bool(data[1] & 0x80)
        length = data[1] & 0x7F

        offset = 2
        if length == 126:
            length = struct.unpack(">H", data[2:4])[0]
            offset = 4
        elif length == 127:
            length = struct.unpack(">Q", data[2:10])[0]
            offset = 10

        if masked:
            mask = data[offset:offset + 4]
            offset += 4
            payload = bytearray()
            for i in range(min(length, len(data) - offset)):
                payload.append(data[offset + i] ^ mask[i % 4])
        else:
            payload = data[offset:offset + length]

        return WSFrame(opcode=opcode, payload=bytes(payload), fin=fin)
