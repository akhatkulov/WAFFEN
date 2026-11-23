"""WebSocket attack techniques — frame-level injection, binary frames, fragmentation."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Optional

from ..core.oracle import Target
from .client import WSClient, WSFrame


@dataclass
class WSAttackResult:
    technique: str
    payload: str
    connected: bool
    response: Optional[WSFrame]
    connection_alive: bool
    waf_blocked: bool


def _check_alive(ws: WSClient) -> bool:
    """Send a benign message and check if connection survives."""
    try:
        ws.send('42["ping","alive_check"]')
        time.sleep(0.5)
        frame = ws.recv(timeout=2.0)
        return frame is not None and frame.opcode != 0x8
    except Exception:
        return False


def _ws_url(target: Target) -> str:
    """Convert HTTP target URL to WebSocket URL."""
    url = target.url()
    if url.startswith("https://"):
        return "wss://" + url[8:]
    elif url.startswith("http://"):
        return "ws://" + url[7:]
    return url


def ws_inject(target: Target, payload: str, event: str = "message",
              ws_path: str = "/socket.io/?EIO=4&transport=websocket"
              ) -> WSAttackResult:
    """Send payload via WebSocket text frame after upgrade."""
    base = target.base_url.rstrip("/")
    if base.startswith("https://"):
        ws_url = "wss://" + base[8:] + ws_path
    elif base.startswith("http://"):
        ws_url = "ws://" + base[7:] + ws_path
    else:
        ws_url = base + ws_path

    ws = WSClient(ws_url, tls_verify=target.tls_verify, timeout=target.timeout,
                  extra_headers=target.extra_headers)
    if not ws.connect():
        return WSAttackResult("ws_inject", payload, False, None, False, False)

    # Drain welcome
    ws.recv(timeout=2.0)
    # Connect namespace (socket.io)
    ws.send("40")
    time.sleep(0.3)
    ws.recv(timeout=1.0)

    # Send payload
    msg = f'42["{event}",{json.dumps(payload)}]'
    ws.send(msg)
    time.sleep(1.0)

    alive = _check_alive(ws)
    blocked = not alive  # WAF tears down connection on block
    response = ws.recv(timeout=1.0)
    ws.close()

    return WSAttackResult("ws_inject", payload, True, response, alive, blocked)


def ws_binary_inject(target: Target, payload: str,
                     ws_path: str = "/socket.io/?EIO=4&transport=websocket"
                     ) -> WSAttackResult:
    """Send payload as binary frame — WAFs typically skip binary inspection."""
    base = target.base_url.rstrip("/")
    scheme = "wss://" if base.startswith("https://") else "ws://"
    host = base.split("://", 1)[1] if "://" in base else base
    ws_url = scheme + host + ws_path

    ws = WSClient(ws_url, tls_verify=target.tls_verify, timeout=target.timeout)
    if not ws.connect():
        return WSAttackResult("ws_binary_inject", payload, False, None, False, False)

    ws.recv(timeout=2.0)
    ws.send("40")
    time.sleep(0.3)
    ws.recv(timeout=1.0)

    ws.send_binary(payload.encode())
    time.sleep(1.0)

    alive = _check_alive(ws)
    response = ws.recv(timeout=1.0)
    ws.close()

    return WSAttackResult("ws_binary_inject", payload, True, response, alive, not alive)


def ws_fragment_inject(target: Target, payload: str, fragment_size: int = 5,
                       ws_path: str = "/socket.io/?EIO=4&transport=websocket"
                       ) -> WSAttackResult:
    """Split payload across multiple small WS frames."""
    base = target.base_url.rstrip("/")
    scheme = "wss://" if base.startswith("https://") else "ws://"
    host = base.split("://", 1)[1] if "://" in base else base
    ws_url = scheme + host + ws_path

    ws = WSClient(ws_url, tls_verify=target.tls_verify, timeout=target.timeout)
    if not ws.connect():
        return WSAttackResult("ws_fragment_inject", payload, False, None, False, False)

    ws.recv(timeout=2.0)
    ws.send("40")
    time.sleep(0.3)
    ws.recv(timeout=1.0)

    msg = f'42["message",{json.dumps(payload)}]'
    ws.send_fragmented(msg, fragment_size=fragment_size)
    time.sleep(1.0)

    alive = _check_alive(ws)
    response = ws.recv(timeout=1.0)
    ws.close()

    return WSAttackResult("ws_fragment_inject", payload, True, response, alive, not alive)


def ws_upgrade_inject(target: Target, payload: str) -> WSAttackResult:
    """Inject payload in the WebSocket upgrade request URL."""
    import urllib.parse
    base = target.base_url.rstrip("/")
    scheme = "wss://" if base.startswith("https://") else "ws://"
    host = base.split("://", 1)[1] if "://" in base else base
    encoded = urllib.parse.quote(payload, safe="")
    ws_url = f"{scheme}{host}/socket.io/?EIO=4&transport=websocket&q={encoded}"

    ws = WSClient(ws_url, tls_verify=target.tls_verify, timeout=target.timeout)
    connected = ws.connect()

    alive = False
    response = None
    blocked = False
    if connected:
        response = ws.recv(timeout=2.0)
        alive = True
    else:
        blocked = True

    if ws.connected:
        ws.close()

    return WSAttackResult("ws_upgrade_inject", payload, connected, response, alive, blocked)
