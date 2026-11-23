"""Tests for the OOB callback server and payload generators."""
import json
import threading
import time
import urllib.request
import urllib.error

import pytest

from waffen.oob.server import OOBServer, Callback
from waffen.oob.payloads import (
    ssrf_oob, xxe_oob, xss_oob, rce_oob, ssti_oob,
    oob_payloads_for, ALL_GENERATORS,
)


# ---- Callback dataclass ---------------------------------------------------

class TestCallback:
    def test_defaults(self):
        cb = Callback(id="abc", url="http://x/cb/abc")
        assert cb.received is False
        assert cb.source_ip == ""

    def test_as_dict(self):
        cb = Callback(id="abc", url="http://x/cb/abc", payload_context="test")
        d = cb.as_dict()
        assert d["id"] == "abc"
        assert d["payload_context"] == "test"
        assert d["received"] is False

    def test_as_dict_truncates_body(self):
        cb = Callback(id="a", url="u", request_body="X" * 1000)
        d = cb.as_dict()
        assert len(d["request_body"]) == 500


# ---- OOBServer (no network) -----------------------------------------------

class TestServerNoNetwork:
    def test_generate(self):
        srv = OOBServer(external_host="my-vps.com", listen_port=9999)
        cb = srv.generate(context="ssrf test")
        assert cb.id in cb.url
        assert "my-vps.com:9999" in cb.url
        assert cb.payload_context == "ssrf test"
        assert not cb.received

    def test_generate_unique(self):
        srv = OOBServer()
        ids = {srv.generate().id for _ in range(20)}
        assert len(ids) == 20

    def test_check_false_before_receive(self):
        srv = OOBServer()
        cb = srv.generate()
        assert srv.check(cb.id) is False

    def test_check_nonexistent(self):
        srv = OOBServer()
        assert srv.check("nonexistent") is False

    def test_check_any_empty(self):
        srv = OOBServer()
        srv.generate()
        assert srv.check_any() == []

    def test_pending(self):
        srv = OOBServer()
        srv.generate()
        srv.generate()
        assert len(srv.pending()) == 2

    def test_reset(self):
        srv = OOBServer()
        srv.generate()
        srv.reset()
        assert srv.pending() == []
        assert srv.check_any() == []

    def test_summary(self):
        srv = OOBServer(listen_port=7777, external_host="ext.com")
        srv.generate()
        s = srv.summary()
        assert s["total"] == 1
        assert s["received"] == 0
        assert s["pending"] == 1
        assert "ext.com:7777" in s["external"]

    def test_running_false_before_start(self):
        srv = OOBServer()
        assert srv.running is False


# ---- OOBServer with real HTTP (loopback) -----------------------------------

def _free_port():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestServerLive:
    def test_start_stop(self):
        port = _free_port()
        srv = OOBServer(listen_host="127.0.0.1", listen_port=port)
        srv.start()
        assert srv.running
        srv.stop()
        assert not srv.running

    def test_callback_received_via_get(self):
        port = _free_port()
        srv = OOBServer(listen_host="127.0.0.1", listen_port=port,
                        external_host="127.0.0.1")
        srv.start()
        try:
            cb = srv.generate(context="unit test")
            # Hit the callback URL
            try:
                urllib.request.urlopen(cb.url, timeout=5)
            except Exception:
                pass
            time.sleep(0.3)
            assert srv.check(cb.id) is True
            assert cb.received is True
            assert cb.source_ip == "127.0.0.1"
            assert cb.request_method == "GET"
        finally:
            srv.stop()

    def test_callback_received_via_post(self):
        port = _free_port()
        srv = OOBServer(listen_host="127.0.0.1", listen_port=port,
                        external_host="127.0.0.1")
        srv.start()
        try:
            cb = srv.generate()
            try:
                req = urllib.request.Request(cb.url, data=b"exfil=secret", method="POST")
                urllib.request.urlopen(req, timeout=5)
            except Exception:
                pass
            time.sleep(0.3)
            assert srv.check(cb.id)
            assert cb.request_method == "POST"
            assert "exfil=secret" in cb.request_body
        finally:
            srv.stop()

    def test_wait_success(self):
        port = _free_port()
        srv = OOBServer(listen_host="127.0.0.1", listen_port=port,
                        external_host="127.0.0.1")
        srv.start()
        try:
            cb = srv.generate()
            # Fire callback in background after small delay
            def _fire():
                time.sleep(0.3)
                try:
                    urllib.request.urlopen(cb.url, timeout=5)
                except Exception:
                    pass
            threading.Thread(target=_fire, daemon=True).start()
            assert srv.wait(cb.id, timeout=5) is True
        finally:
            srv.stop()

    def test_wait_timeout(self):
        port = _free_port()
        srv = OOBServer(listen_host="127.0.0.1", listen_port=port)
        srv.start()
        try:
            cb = srv.generate()
            assert srv.wait(cb.id, timeout=0.5) is False
        finally:
            srv.stop()

    def test_unregistered_path_no_crash(self):
        port = _free_port()
        srv = OOBServer(listen_host="127.0.0.1", listen_port=port,
                        external_host="127.0.0.1")
        srv.start()
        try:
            # Hit a path with no registered token
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/cb/nosuchtoken", timeout=5)
            except Exception:
                pass
            time.sleep(0.2)
            assert srv.check_any() == []
        finally:
            srv.stop()

    def test_check_any_returns_received(self):
        port = _free_port()
        srv = OOBServer(listen_host="127.0.0.1", listen_port=port,
                        external_host="127.0.0.1")
        srv.start()
        try:
            cb1 = srv.generate()
            cb2 = srv.generate()
            try:
                urllib.request.urlopen(cb1.url, timeout=5)
            except Exception:
                pass
            time.sleep(0.3)
            received = srv.check_any()
            assert len(received) == 1
            assert received[0].id == cb1.id
        finally:
            srv.stop()

    def test_write_jsonl(self, tmp_path):
        port = _free_port()
        srv = OOBServer(listen_host="127.0.0.1", listen_port=port,
                        external_host="127.0.0.1")
        srv.start()
        try:
            cb = srv.generate(context="write test")
            try:
                urllib.request.urlopen(cb.url, timeout=5)
            except Exception:
                pass
            time.sleep(0.3)
            out = str(tmp_path / "cbs.jsonl")
            srv.write_jsonl(out)
            with open(out) as f:
                lines = f.readlines()
            assert len(lines) == 1
            d = json.loads(lines[0])
            assert d["received"] is True
            assert d["payload_context"] == "write test"
        finally:
            srv.stop()


# ---- Payload generators ---------------------------------------------------

class TestPayloads:
    def test_ssrf_non_empty(self):
        ps = ssrf_oob("http://evil.com:8888/cb/abc")
        assert len(ps) >= 5
        assert all(isinstance(p, str) for p in ps)

    def test_ssrf_contains_url(self):
        url = "http://evil.com:8888/cb/abc"
        ps = ssrf_oob(url)
        assert any(url in p for p in ps)

    def test_xxe_non_empty(self):
        ps = xxe_oob("http://evil.com/cb/abc")
        assert len(ps) >= 4
        assert all("ENTITY" in p or "xi:include" in p for p in ps)

    def test_xss_non_empty(self):
        ps = xss_oob("http://evil.com/cb/abc")
        assert len(ps) >= 5
        assert any("<script>" in p or "<img" in p for p in ps)

    def test_rce_non_empty(self):
        ps = rce_oob("http://evil.com/cb/abc")
        assert len(ps) >= 5
        assert any("curl" in p for p in ps)

    def test_ssti_non_empty(self):
        ps = ssti_oob("http://evil.com/cb/abc")
        assert len(ps) >= 3

    def test_oob_payloads_for_ssrf(self):
        ps = oob_payloads_for("SSRF", "http://x/cb/1")
        assert len(ps) >= 5

    def test_oob_payloads_for_xxe(self):
        ps = oob_payloads_for("XXE Injection", "http://x/cb/1")
        assert len(ps) >= 4

    def test_oob_payloads_for_xss(self):
        ps = oob_payloads_for("XSS Injection", "http://x/cb/1")
        assert len(ps) >= 5

    def test_oob_payloads_for_cmdi(self):
        ps = oob_payloads_for("Command Injection", "http://x/cb/1")
        assert len(ps) >= 5

    def test_oob_payloads_for_ssti(self):
        ps = oob_payloads_for("SSTI", "http://x/cb/1")
        assert len(ps) >= 3

    def test_oob_payloads_for_unknown(self):
        ps = oob_payloads_for("Unknown Class", "http://x/cb/1")
        assert ps == []

    def test_oob_payloads_partial_match(self):
        ps = oob_payloads_for("ssrf", "http://x/cb/1")
        assert len(ps) >= 5

    def test_all_generators_keys(self):
        assert "SSRF" in ALL_GENERATORS
        assert "XXE Injection" in ALL_GENERATORS
        assert "XSS Injection" in ALL_GENERATORS
        assert "Command Injection" in ALL_GENERATORS
        assert "SSTI" in ALL_GENERATORS


# ---- CLI integration -------------------------------------------------------

class TestCLI:
    def test_oob_subcommand_exists(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args(["oob", "--generate", "--external", "my-vps.com"])
        assert hasattr(args, "func")
        assert args.external == "my-vps.com"
        assert args.generate is True

    def test_oob_payloads_flag(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args(["oob", "--payloads", "--payloads-class", "SSRF"])
        assert args.payloads is True
        assert args.payloads_class == "SSRF"
