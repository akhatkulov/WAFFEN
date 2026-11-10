"""Pooled (keep-alive http.client) transport: request-spec construction mirrors the
curl path, and a request_transform transparently falls back to curl (Phase 2)."""
from waffen.core.oracle import Target, Oracle, Response


def _spec(inject, payload="x", **kw):
    t = Target(base_url="http://h", path=kw.pop("path", "/s"), param=kw.pop("param", "q"),
               method=kw.pop("method", "GET"), inject=inject, **kw)
    return Oracle(t, transport="pooled")._http_spec(payload)


def test_http_spec_query():
    m, target, headers, body = _spec("query", "a b")
    assert m == "GET" and target.startswith("/s?") and "q=a+b" in target and body is None
    assert headers["User-Agent"] and headers["Accept"] == "*/*"


def test_http_spec_json():
    m, target, headers, body = _spec("json", "v", method="POST")
    assert m == "POST" and headers["Content-Type"] == "application/json"
    assert b'"q"' in body and b'"v"' in body


def test_http_spec_body_form():
    m, target, headers, body = _spec("body", "a b", method="POST")
    assert headers["Content-Type"].startswith("application/x-www-form-urlencoded")
    assert body == b"q=a+b"


def test_http_spec_header_inject():
    m, target, headers, body = _spec("header", "P", param="X-Test")
    assert headers["X-Test"] == "P" and body is None


def test_http_spec_cookie_inject():
    m, target, headers, body = _spec("cookie", "P", param="sid")
    assert headers["Cookie"] == "sid=P"


def test_http_spec_upload_multipart():
    m, target, headers, body = _spec("upload", "shell.phtml", path="/file-upload",
                                     param="file", method="POST")
    assert headers["Content-Type"].startswith("multipart/form-data; boundary=")
    assert b'name="file"' in body and b'filename="shell.phtml"' in body


def test_http_spec_rawpath_keeps_traversal():
    m, target, headers, body = _spec("rawpath", "../../etc/passwd", path="/")
    assert "etc/passwd" in target


def test_http_spec_auth_headers_and_cookie():
    t = Target(base_url="http://h", path="/s", inject="query",
               extra_headers=("Authorization: Bearer tok",), cookie="sid=1")
    _, _, headers, _ = Oracle(t, transport="pooled")._http_spec("x")
    assert headers["Authorization"] == "Bearer tok" and headers["Cookie"] == "sid=1"


def test_http_spec_auth_cookie_merges_with_cookie_inject():
    t = Target(base_url="http://h", path="/s", inject="cookie", param="q", cookie="sid=1")
    _, _, headers, _ = Oracle(t, transport="pooled")._http_spec("PAY")
    assert headers["Cookie"] == "q=PAY; sid=1"


def test_pooled_selected_as_sender():
    assert Oracle(Target(base_url="http://h"), transport="pooled")._sender.__name__ == "_pooled_send"
    assert Oracle(Target(base_url="http://h"))._sender.__name__ == "_curl_send"      # default
    # explicit sender override still wins over transport
    mark = lambda p: Response("THROUGH", "200", 1, 0.0, "x")
    assert Oracle(Target(base_url="http://h"), sender=mark, transport="pooled")._sender is mark


def test_pooled_falls_back_to_curl_for_transforms(monkeypatch):
    sentinel = Response("THROUGH", "201", 5, 0.0, "via-curl")

    class FakeTransform:
        name = "fake"
        def build(self, target, payload):
            return ["curl", "-s", target.url()]

    o = Oracle(Target(base_url="http://h", inject="query"),
               transport="pooled", request_transform=FakeTransform())
    monkeypatch.setattr(o, "_curl_send", lambda p: sentinel)
    assert o._pooled_send("x") is sentinel          # transform present -> delegates to curl


def test_unknown_inject_raises_in_spec():
    o = Oracle(Target(base_url="http://h", inject="bogus"), transport="pooled")
    try:
        o._http_spec("x")
        assert False, "expected ValueError"
    except ValueError as e:
        assert "unknown inject mode" in str(e)
