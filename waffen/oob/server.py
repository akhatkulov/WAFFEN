"""Lightweight HTTP callback server for OOB (out-of-band) verification.

Generates unique callback URLs, listens for incoming requests, and records
which payloads triggered a callback — proving blind SSRF, blind XSS, blind
XXE, and RCE without requiring Burp Collaborator.

Usage::

    srv = OOBServer(listen_port=8888, external_host="my-vps.com")
    srv.start()
    cb = srv.generate(context="SSRF on /api/fetch")
    # ... send cb.url inside an SSRF payload ...
    if srv.wait(cb.id, timeout=30):
        print("Blind SSRF confirmed!")
    srv.stop()
"""
from __future__ import annotations

import http.server
import json
import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class Callback:
    id: str
    url: str
    protocol: str = "http"
    payload_context: str = ""
    received: bool = False
    received_at: str = ""
    source_ip: str = ""
    request_method: str = ""
    request_path: str = ""
    request_headers: dict = field(default_factory=dict)
    request_body: str = ""

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "url": self.url,
            "protocol": self.protocol,
            "payload_context": self.payload_context,
            "received": self.received,
            "received_at": self.received_at,
            "source_ip": self.source_ip,
            "request_method": self.request_method,
            "request_path": self.request_path,
            "request_body": self.request_body[:500],
        }


def _make_handler(callbacks: dict, lock: threading.Lock):
    """Build a request handler class that closes over the callback registry."""

    class _Handler(http.server.BaseHTTPRequestHandler):

        def _record(self, method: str):
            path = self.path or ""
            # /cb/<token> or /cb/<token>/extra
            parts = path.strip("/").split("/")
            token = parts[1] if len(parts) >= 2 and parts[0] == "cb" else None

            body = ""
            clen = int(self.headers.get("Content-Length", 0) or 0)
            if clen > 0:
                body = self.rfile.read(min(clen, 65536)).decode(errors="replace")

            if token:
                with lock:
                    cb = callbacks.get(token)
                    if cb and not cb.received:
                        cb.received = True
                        cb.received_at = datetime.now(timezone.utc).isoformat()
                        cb.source_ip = self.client_address[0]
                        cb.request_method = method
                        cb.request_path = path
                        cb.request_headers = dict(self.headers)
                        cb.request_body = body

            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def do_GET(self):
            self._record("GET")

        def do_POST(self):
            self._record("POST")

        def do_PUT(self):
            self._record("PUT")

        def do_HEAD(self):
            self._record("HEAD")

        def do_OPTIONS(self):
            self._record("OPTIONS")

        def log_message(self, format, *args):
            pass  # silence stdlib logging

    return _Handler


class OOBServer:
    """HTTP callback listener for out-of-band verification."""

    def __init__(self, listen_host: str = "127.0.0.1", listen_port: int = 8888,
                 external_host: str = ""):
        self.host = listen_host
        self.port = listen_port
        self.external = external_host or listen_host
        self.callbacks: dict[str, Callback] = {}
        self._lock = threading.Lock()
        self._server: Optional[http.server.HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self):
        """Start the callback listener in a daemon thread."""
        if self.running:
            return
        handler = _make_handler(self.callbacks, self._lock)
        self._server = http.server.HTTPServer((self.host, self.port), handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        """Shut down the listener."""
        if self._server:
            self._server.shutdown()
            self._server = None
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    def generate(self, context: str = "") -> Callback:
        """Create a unique callback URL with a tracking token."""
        token = secrets.token_hex(8)
        cb = Callback(
            id=token,
            url=f"http://{self.external}:{self.port}/cb/{token}",
            protocol="http",
            payload_context=context,
        )
        with self._lock:
            self.callbacks[token] = cb
        return cb

    def check(self, callback_id: str) -> bool:
        """Return True if the callback with *callback_id* was received."""
        with self._lock:
            cb = self.callbacks.get(callback_id)
            return cb.received if cb else False

    def check_any(self) -> list[Callback]:
        """Return all callbacks that have been received."""
        with self._lock:
            return [cb for cb in self.callbacks.values() if cb.received]

    def pending(self) -> list[Callback]:
        """Return callbacks that have NOT yet been received."""
        with self._lock:
            return [cb for cb in self.callbacks.values() if not cb.received]

    def wait(self, callback_id: str, timeout: float = 30.0) -> bool:
        """Block until the callback is received or *timeout* seconds pass."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.check(callback_id):
                return True
            time.sleep(0.25)
        return False

    def wait_any(self, timeout: float = 30.0) -> list[Callback]:
        """Block until at least one callback arrives or timeout."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            received = self.check_any()
            if received:
                return received
            time.sleep(0.25)
        return []

    def reset(self):
        """Clear all registered callbacks."""
        with self._lock:
            self.callbacks.clear()

    def summary(self) -> dict:
        """Return a summary of callback status."""
        with self._lock:
            total = len(self.callbacks)
            received = sum(1 for cb in self.callbacks.values() if cb.received)
        return {
            "total": total,
            "received": received,
            "pending": total - received,
            "listen": f"{self.host}:{self.port}",
            "external": f"{self.external}:{self.port}",
        }

    def write_jsonl(self, path: str):
        """Write all callbacks (received and pending) to a JSONL file."""
        with self._lock:
            cbs = list(self.callbacks.values())
        with open(path, "w") as f:
            for cb in cbs:
                f.write(json.dumps(cb.as_dict()) + "\n")
