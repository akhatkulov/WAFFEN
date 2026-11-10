"""Session/auth threading: --header / --cookie must reach EVERY inject mode and
every request transform via Oracle._with_auth (Phase 3)."""
from waffen.core.oracle import Oracle, Target


def _argv(target, payload="x", transform=None):
    return Oracle(target, request_transform=transform)._build(payload)


def test_no_auth_leaves_argv_unchanged():
    base = _argv(Target(base_url="https://t", inject="query"))
    assert "-H" not in base or "Authorization" not in " ".join(base)
    assert "Cookie:" not in " ".join(base)


def test_header_and_cookie_threaded_on_query():
    t = Target(base_url="https://t", inject="query",
               extra_headers=("Authorization: Bearer tok", "X-CSRF: z"), cookie="sid=abc")
    argv = _argv(t)
    assert argv[0] == "curl"
    # headers present as -H pairs
    hdrs = [argv[i + 1] for i in range(len(argv) - 1) if argv[i] == "-H"]
    assert "Authorization: Bearer tok" in hdrs
    assert "X-CSRF: z" in hdrs
    assert "Cookie: sid=abc" in hdrs


def test_auth_inserted_right_after_curl():
    t = Target(base_url="https://t", inject="query", cookie="sid=abc")
    argv = _argv(t)
    # the auth block is spliced in immediately after the program name
    assert argv[1] == "-H" and argv[2] == "Cookie: sid=abc"


def test_cookie_merges_into_cookie_inject_header():
    # --inject cookie builds `-H "Cookie: q=<payload>"`; an auth cookie must fold
    # into that SAME header (one valid Cookie line), not spawn a second one.
    t = Target(base_url="https://t", inject="cookie", param="q", cookie="sid=abc")
    argv = _argv(t, payload="PAY")
    cookie_hdrs = [argv[i + 1] for i in range(len(argv) - 1)
                   if argv[i] == "-H" and argv[i + 1].lower().startswith("cookie:")]
    assert len(cookie_hdrs) == 1
    assert "q=PAY" in cookie_hdrs[0] and "sid=abc" in cookie_hdrs[0]


def test_auth_threads_through_a_request_transform():
    # a transform builds its own curl argv; auth must still be injected into it.
    class FakeTransform:
        name = "fake"
        def build(self, target, payload):
            return ["curl", "-s", "-X", "POST", target.url(), "-d", payload]
    t = Target(base_url="https://t", extra_headers=("Authorization: Bearer tok",), cookie="sid=1")
    argv = _argv(t, transform=FakeTransform())
    joined = " ".join(argv)
    assert "Authorization: Bearer tok" in joined
    assert "Cookie: sid=1" in joined
    assert argv[0] == "curl"


def test_auth_kwargs_roundtrip_through_effective_and_resolve():
    # per-class routing uses dataclasses.replace; auth fields must survive it.
    from waffen.kb.inject_map import effective, resolve_base
    t = Target(base_url="https://t", inject="auto",
               extra_headers=("Authorization: Bearer tok",), cookie="sid=abc")
    eff = effective(t, "Directory Traversal")
    assert eff.extra_headers == ("Authorization: Bearer tok",) and eff.cookie == "sid=abc"
    rb = resolve_base(t)
    assert rb.extra_headers == ("Authorization: Bearer tok",) and rb.cookie == "sid=abc"
