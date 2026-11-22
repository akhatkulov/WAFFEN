"""Tests for waffen/core/rawhttp.py — raw socket HTTP sender."""
import socket
from unittest.mock import patch, MagicMock

from waffen.core.rawhttp import parse_target, send_raw


class TestParseTarget:
    def test_https_url(self):
        host, port, tls, path = parse_target("https://example.com", "/test")
        assert host == "example.com"
        assert port == 443
        assert tls is True
        assert path == "/test"

    def test_http_url(self):
        host, port, tls, path = parse_target("http://example.com", "/")
        assert host == "example.com"
        assert port == 80
        assert tls is False

    def test_custom_port(self):
        host, port, tls, path = parse_target("https://example.com:8443", "/api")
        assert port == 8443
        assert tls is True

    def test_no_scheme(self):
        host, port, tls, path = parse_target("example.com", "/")
        assert host == "example.com"
        assert port == 80
        assert tls is False

    def test_default_path(self):
        _, _, _, path = parse_target("http://example.com")
        assert path == "/"

    def test_path_from_url(self):
        host, port, tls, path = parse_target("http://example.com/api/v1", "")
        assert path == "/api/v1"

    def test_explicit_path_overrides(self):
        _, _, _, path = parse_target("http://example.com/ignored", "/used")
        assert path == "/used"


class TestSendRaw:
    def test_connection_error(self):
        result = send_raw("192.0.2.1", 1, False, b"GET / HTTP/1.1\r\n\r\n",
                          timeout=0.1, verify=False)
        assert result["status"] == "000"
        assert result["error"]
        assert result["elapsed"] >= 0

    def test_response_parsing(self):
        fake_response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Length: 5\r\n"
            b"\r\n"
            b"hello"
        )

        mock_sock = MagicMock()
        mock_sock.recv = MagicMock(side_effect=[fake_response, b""])

        with patch("waffen.core.rawhttp.socket.create_connection", return_value=mock_sock):
            result = send_raw("localhost", 80, False, b"GET / HTTP/1.1\r\n\r\n",
                              timeout=5, verify=False)

        assert result["status"] == "200"
        assert result["body"] == "hello"
        assert result["error"] is None
        assert result["elapsed"] >= 0

    def test_403_response(self):
        fake_response = (
            b"HTTP/1.1 403 Forbidden\r\n"
            b"\r\n"
            b"blocked"
        )

        mock_sock = MagicMock()
        mock_sock.recv = MagicMock(side_effect=[fake_response, b""])

        with patch("waffen.core.rawhttp.socket.create_connection", return_value=mock_sock):
            result = send_raw("localhost", 80, False, b"GET / HTTP/1.1\r\n\r\n")

        assert result["status"] == "403"
        assert result["body"] == "blocked"

    def test_timeout_stall(self):
        mock_sock = MagicMock()
        mock_sock.recv = MagicMock(side_effect=socket.timeout("stall"))

        with patch("waffen.core.rawhttp.socket.create_connection", return_value=mock_sock):
            result = send_raw("localhost", 80, False, b"smuggle", timeout=0.1)

        assert result["status"] == "000"
        assert result["error"] is None
        assert result["elapsed"] >= 0

    def test_empty_response(self):
        mock_sock = MagicMock()
        mock_sock.recv = MagicMock(return_value=b"")

        with patch("waffen.core.rawhttp.socket.create_connection", return_value=mock_sock):
            result = send_raw("localhost", 80, False, b"GET / HTTP/1.1\r\n\r\n")

        assert result["status"] == "000"
        assert result["body"] == ""

    def test_tls_wrapping(self):
        fake_response = b"HTTP/1.1 200 OK\r\n\r\nok"
        mock_sock = MagicMock()
        mock_sock.recv = MagicMock(side_effect=[fake_response, b""])

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket = MagicMock(return_value=mock_sock)

        with patch("waffen.core.rawhttp.socket.create_connection", return_value=mock_sock), \
             patch("waffen.core.rawhttp.ssl.create_default_context", return_value=mock_ctx):
            result = send_raw("localhost", 443, True, b"GET / HTTP/1.1\r\n\r\n",
                              verify=False)

        assert result["status"] == "200"
        mock_ctx.wrap_socket.assert_called_once()
        assert mock_ctx.check_hostname is False

    def test_malformed_first_line(self):
        fake_response = b"GARBAGE\r\n\r\nbody"
        mock_sock = MagicMock()
        mock_sock.recv = MagicMock(side_effect=[fake_response, b""])

        with patch("waffen.core.rawhttp.socket.create_connection", return_value=mock_sock):
            result = send_raw("localhost", 80, False, b"x")

        assert result["status"] == "000"
        assert result["body"] == "body"
