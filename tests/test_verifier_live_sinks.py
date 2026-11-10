"""Live end-to-end validation of the 5 verifiers that were otherwise unit-only
(Open Redirect, SSI, LDAP, XXE, SSRF): spin up the purpose-built vulnerable sink
app (lab/vuln_sinks.py) on a real socket and confirm the REAL verifier (real curl,
real _fetch_headers) confirms each against it. Closes the 'heuristics unproven
against a live sink' gap from the self-audit."""
import importlib.util
import pathlib
import socketserver
import threading

import pytest

from waffen.core.oracle import Target, Oracle
from waffen.verify.verifier import verify

_SINK = pathlib.Path(__file__).resolve().parent.parent / "lab" / "vuln_sinks.py"
_spec = importlib.util.spec_from_file_location("vuln_sinks", _SINK)
vuln_sinks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vuln_sinks)


@pytest.fixture(scope="module")
def sink_url():
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), vuln_sinks.Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        srv.shutdown()
        srv.server_close()


@pytest.mark.parametrize("cls,cfg,payload,min_conf", [
    ("Open Redirect",  {"path": "/redirect", "param": "to"},  "https://attacker.evil/landing?x=1", 0.8),
    ("SSI",            {"path": "/ssi",      "param": "q"},   '<!--#exec cmd="id" -->',            0.8),
    ("LDAP Injection", {"path": "/ldap",     "param": "q"},   "*)(uid=*))(|(uid=*",                0.6),
    ("XXE Injection",  {"path": "/xxe",      "param": "q"},   "<x>seed</x>",                       0.7),
    ("SSRF",           {"path": "/ssrf",     "param": "url"},
     "http://169.254.169.254/latest/meta-data/iam/security-credentials/role",                     0.5),
])
def test_verifier_confirms_against_a_live_vulnerable_sink(sink_url, cls, cfg, payload, min_conf):
    t = Target(base_url=sink_url, inject="query", **cfg)
    v = verify(Oracle(t), payload, cls)
    assert v.exploitable is True, f"{cls} not confirmed live: {v.reason}"
    assert v.confidence >= min_conf, f"{cls} confidence {v.confidence} < {min_conf}: {v.reason}"
    assert v.attack_class == cls


def test_verifier_rejects_a_non_vulnerable_sink(sink_url):
    # a benign path that never emits the expected signal -> no false positive
    t = Target(base_url=sink_url, inject="query", path="/ssi", param="q")
    v = verify(Oracle(t), "nothing-interesting", "Open Redirect")  # /ssi never sets Location
    assert v.exploitable is False
