"""Tests for WebSocket client and attack module."""
import struct
import os
from unittest.mock import patch, MagicMock, PropertyMock

import pytest

from waffen.ws.client import WSClient, WSFrame, _WS_MAGIC
from waffen.ws.attacks import (
    ws_inject, ws_binary_inject, ws_fragment_inject,
    ws_upgrade_inject, WSAttackResult,
)
from waffen.core.oracle import Target


def _target():
    return Target(base_url="https://test.example", path="/",
                  block_signature="WAF_BLOCK")


class TestWSFrame:
    def test_text_frame(self):
        f = WSFrame(opcode=0x1, payload=b"hello", fin=True)
        assert f.opcode == 0x1
        assert f.payload == b"hello"
        assert f.fin

    def test_binary_frame(self):
        f = WSFrame(opcode=0x2, payload=b"\x00\x01\x02")
        assert f.opcode == 0x2

    def test_close_frame(self):
        f = WSFrame(opcode=0x8, payload=b"")
        assert f.opcode == 0x8


class TestWSClientParsing:
    def test_parse_unmasked_text(self):
        payload = b"hello"
        data = bytes([0x81, len(payload)]) + payload
        frame = WSClient._parse_frame(data)
        assert frame.opcode == 0x1
        assert frame.payload == b"hello"
        assert frame.fin

    def test_parse_binary_frame(self):
        payload = b"\x00\x01\x02"
        data = bytes([0x82, len(payload)]) + payload
        frame = WSClient._parse_frame(data)
        assert frame.opcode == 0x2
        assert frame.payload == b"\x00\x01\x02"

    def test_parse_close_frame(self):
        data = bytes([0x88, 0x00])
        frame = WSClient._parse_frame(data)
        assert frame.opcode == 0x8

    def test_parse_medium_length(self):
        payload = b"x" * 200
        data = bytes([0x81, 126]) + struct.pack(">H", 200) + payload
        frame = WSClient._parse_frame(data)
        assert len(frame.payload) == 200

    def test_parse_masked_frame(self):
        payload = b"test"
        mask = b"\x01\x02\x03\x04"
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        data = bytes([0x81, 0x80 | len(payload)]) + mask + masked
        frame = WSClient._parse_frame(data)
        assert frame.payload == b"test"

    def test_non_fin_frame(self):
        payload = b"part"
        data = bytes([0x01, len(payload)]) + payload  # no FIN bit
        frame = WSClient._parse_frame(data)
        assert not frame.fin
        assert frame.opcode == 0x1


class TestWSClientInit:
    def test_wss_url(self):
        ws = WSClient("wss://example.com/ws?token=abc")
        assert ws._host == "example.com"
        assert ws._port == 443
        assert ws._path == "/ws?token=abc"
        assert ws._use_tls

    def test_ws_url(self):
        ws = WSClient("ws://localhost:8080/chat")
        assert ws._host == "localhost"
        assert ws._port == 8080
        assert ws._path == "/chat"
        assert not ws._use_tls

    def test_default_path(self):
        ws = WSClient("wss://example.com")
        assert ws._path == "/"

    def test_not_connected_initially(self):
        ws = WSClient("wss://example.com")
        assert not ws.connected


class TestWSAttackResult:
    def test_blocked(self):
        r = WSAttackResult("ws_inject", "test", True, None, False, True)
        assert r.waf_blocked
        assert r.connected

    def test_passed(self):
        r = WSAttackResult("ws_inject", "test", True,
                           WSFrame(0x1, b"ok"), True, False)
        assert not r.waf_blocked
        assert r.connection_alive


class TestWSUpgradeInject:
    @patch("waffen.ws.attacks.WSClient")
    def test_blocked_on_failed_connect(self, MockWS):
        instance = MockWS.return_value
        instance.connect.return_value = False
        instance.connected = False
        r = ws_upgrade_inject(_target(), "' OR 1=1--")
        assert r.waf_blocked
        assert not r.connected

    @patch("waffen.ws.attacks.WSClient")
    def test_passed_on_connect(self, MockWS):
        instance = MockWS.return_value
        instance.connect.return_value = True
        instance.connected = True
        instance.recv.return_value = WSFrame(0x1, b"welcome")
        r = ws_upgrade_inject(_target(), "' OR 1=1--")
        assert not r.waf_blocked
        assert r.connected


class TestCLIParserWS:
    def test_parser_has_ws(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args(["ws", "--target", "https://x.com", "--text",
                             "--payload", "test"])
        assert args.text is True
        assert hasattr(args, "func")

    def test_parser_ws_all(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args(["ws", "--target", "https://x.com", "--all"])
        assert args.all_techniques is True

    def test_ws_path_default(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args(["ws", "--target", "https://x.com", "--text"])
        assert "socket.io" in args.ws_path


class TestGraphQLTransforms:
    def test_transforms_include_graphql_batch(self):
        from waffen.core.transforms import TRANSFORMS
        names = {t.name for t in TRANSFORMS}
        assert "graphql_batch" in names
        assert "graphql_alias_flood" in names
        assert "graphql_persisted" in names
        assert "graphql_multipart" in names


class TestSeeds:
    def test_graphql_seeds_exist(self):
        from waffen.kb.seeds import seeds_for
        assert len(seeds_for("graphql")) >= 5
        assert len(seeds_for("gql")) >= 5

    def test_websocket_seeds_exist(self):
        from waffen.kb.seeds import seeds_for
        assert len(seeds_for("ws")) >= 5
        assert len(seeds_for("websocket")) >= 5
