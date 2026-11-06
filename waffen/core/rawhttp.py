"""Raw-socket HTTP sender — for request-smuggling probes curl cannot express.

curl always emits a well-formed request and controls its own framing, so CL.TE /
TE.CL / TE.TE desync tests are impossible through it. This sends exact bytes over
a socket (TLS via ssl) and times the response. A response that stalls to the
timeout is the signal a smuggling probe is looking for (the back-end is waiting
for bytes a desync withheld).

Authorized targets only. Experimental: timing is environment-sensitive; treat a
flag as "investigate", not proof.
"""
from __future__ import annotations

import socket
import ssl
import time
import urllib.parse


def parse_target(base_url: str, path: str = "/"):
    u = urllib.parse.urlparse(base_url if "://" in base_url else "http://" + base_url)
    tls = u.scheme == "https"
    host = u.hostname or "localhost"
    port = u.port or (443 if tls else 80)
    p = path or u.path or "/"
    return host, port, tls, p


def send_raw(host: str, port: int, tls: bool, raw: bytes, timeout: float = 10.0,
             verify: bool = False) -> dict:
    """Send raw bytes; return {status, elapsed, body, error}. A stall returns
    elapsed≈timeout with whatever arrived — that delay is the desync signal.

    `verify` controls TLS cert checking. Default is off (matching the toolchain's
    `curl -sk`): a WAF tester must reach self-signed / demo endpoints. Pass
    verify=True to enforce. Authorized targets only."""
    start = time.time()
    data = b""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if tls:
            ctx = ssl.create_default_context()
            if not verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(raw)
        sock.settimeout(timeout)
        try:
            while len(data) < 65536:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        except (socket.timeout, TimeoutError):
            pass  # the stall IS the signal
        finally:
            try:
                sock.close()
            except Exception:
                pass
    except Exception as e:
        return {"status": "000", "elapsed": round(time.time() - start, 3), "body": "", "error": str(e)}

    elapsed = round(time.time() - start, 3)
    status = "000"
    body = ""
    if data:
        head, _, rest = data.partition(b"\r\n\r\n")
        first = head.split(b"\r\n", 1)[0].decode("latin1", "replace")
        parts = first.split(" ")
        if len(parts) >= 2:
            status = parts[1]
        body = rest.decode("latin1", "replace")
    return {"status": status, "elapsed": elapsed, "body": body, "error": None}
