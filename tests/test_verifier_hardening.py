"""Phase 4 verifier hardening: retry transient DOWN (no false negatives) and
thread --header/--cookie through the verifier's own curl path (_fetch_headers)."""
from waffen.core.oracle import Response, Target
from waffen.verify import verifier as V


class SeqOracle:
    """Fake oracle returning a scripted sequence of verdicts, counting sends."""
    def __init__(self, verdicts):
        self.verdicts = list(verdicts)
        self.calls = 0
        self.t = Target(base_url="https://t")

    def send(self, payload):
        v = self.verdicts[min(self.calls, len(self.verdicts) - 1)]
        self.calls += 1
        return Response(v, "200" if v == "THROUGH" else "000", 0, 0.0, "body" if v == "THROUGH" else "")


def test_send_retries_on_down_then_succeeds():
    o = SeqOracle(["DOWN", "DOWN", "THROUGH"])
    r = V._send(o, "x")
    assert r.verdict == "THROUGH"
    assert o.calls == 3                       # initial + 2 retries, stops on success


def test_send_is_bounded_when_always_down():
    o = SeqOracle(["DOWN"] * 10)
    r = V._send(o, "x", retries=2)
    assert r.verdict == "DOWN"
    assert o.calls == 3                        # initial + exactly 2 retries — no runaway


def test_send_no_retry_when_first_is_through():
    o = SeqOracle(["THROUGH", "THROUGH"])
    r = V._send(o, "x")
    assert r.verdict == "THROUGH" and o.calls == 1


def test_fetch_headers_threads_auth(monkeypatch):
    captured = {}

    class FakeProc:
        stdout = "HTTP/1.1 200 OK\r\nX: y\r\n\r\nbody"

    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        return FakeProc()

    monkeypatch.setattr(V.subprocess, "run", fake_run)
    t = Target(base_url="https://t", inject="query",
               extra_headers=("Authorization: Bearer tok",), cookie="sid=abc")
    V._fetch_headers(t, "payload")
    joined = " ".join(captured["cmd"])
    assert "Authorization: Bearer tok" in joined
    assert "Cookie: sid=abc" in joined


class MapOracle:
    """Fake oracle mapping a payload string to a canned Response."""
    def __init__(self, mapping, default=None, inject="upload"):
        self.mapping = mapping
        self.default = default or Response("THROUGH", "200", 10, 0.0, "ok")
        self.t = Target(base_url="https://t", inject=inject)

    def send(self, payload):
        return self.mapping.get(payload, self.default)


def test_nosql_error_signature_confirms():
    o = MapOracle({"p": Response("THROUGH", "200", 60, 0.0, "MongoError: E11000 duplicate key")})
    v = V._check_nosql(o, "p", "NoSQL Injection")
    assert v.exploitable and v.confidence >= 0.7


def test_nosql_boolean_differential_confirms():
    o = MapOracle({
        "user[$ne]=1": Response("THROUGH", "200", 500, 0.0, "many results here"),
        "user[$eq]=1": Response("THROUGH", "200", 40, 0.0, "none"),
    })
    v = V._check_nosql(o, "user[$ne]=1", "NoSQL Injection")
    assert v.exploitable  # true/false variants differ substantially


def test_nosql_identical_responses_not_confirmed():
    same = Response("THROUGH", "200", 100, 0.0, "same body")
    o = MapOracle({"a[$ne]=1": same, "a[$eq]=1": same})
    v = V._check_nosql(o, "a[$ne]=1", "NoSQL Injection")
    assert not v.exploitable


def test_upload_rejection_is_not_exploitable():
    o = MapOracle({"shell.php": Response("THROUGH", "200", 30, 0.0, "Error: file type not allowed")})
    v = V._check_upload(o, "shell.php", "Upload Insecure Files")
    assert not v.exploitable and v.confidence >= 0.6


def test_upload_acceptance_is_exploitable():
    o = MapOracle({"shell.phtml": Response("THROUGH", "201", 40, 0.0, '{"status":"ok","file":"shell.phtml"}')})
    v = V._check_upload(o, "shell.phtml", "Upload Insecure Files")
    assert v.exploitable and v.confidence >= 0.55


def test_upload_transport_down_not_confirmed():
    o = MapOracle({"shell.php": Response("DOWN", "000", 0, 0.0, "")})
    v = V._check_upload(o, "shell.php", "Upload Insecure Files")
    assert not v.exploitable


def test_dispatch_now_covers_nosql_and_upload():
    for cls in ("NoSQL Injection", "Upload Insecure Files"):
        v = V.verify(MapOracle({"x": Response("THROUGH", "200", 10, 0.0, "ok")}), "x", cls)
        assert "no verifier" not in v.reason


def test_fetch_headers_merges_auth_cookie_under_cookie_inject(monkeypatch):
    captured = {}

    class FakeProc:
        stdout = "HTTP/1.1 200 OK\r\n\r\n"

    monkeypatch.setattr(V.subprocess, "run", lambda cmd, **kw: (captured.__setitem__("cmd", cmd), FakeProc())[1])
    t = Target(base_url="https://t", inject="cookie", param="q", cookie="sid=abc")
    V._fetch_headers(t, "PAY")
    cookie_hdrs = [captured["cmd"][i + 1] for i in range(len(captured["cmd"]) - 1)
                   if captured["cmd"][i] == "-H" and captured["cmd"][i + 1].lower().startswith("cookie:")]
    assert len(cookie_hdrs) == 1 and "q=PAY" in cookie_hdrs[0] and "sid=abc" in cookie_hdrs[0]
