"""Audit-driven robustness fixes: concurrent-batch ban detection (#4), bounded deep-SQLi
request budget (#5), and a capped pooled-transport body read (#6)."""
import inspect
from waffen.core.oracle import Oracle, Target, Response, BLOCKED, THROUGH, _MAX_BODY_BYTES
from waffen.verify import verifier as V


# -- #4: ban detection survives concurrency (post-batch canary) ---------------
def test_concurrent_send_many_post_batch_ban_check():
    def sender(p):
        return Response(BLOCKED, "403", 10, 0.0, "blocked") if p == "CANARY" \
            else Response(THROUGH, "200", 10, 0.0, "ok")
    o = Oracle(Target(base_url="mock://x"), sender=sender, canary_payload="CANARY", backoff=False)
    out = o.send_many(["a", "b", "c", "d"], concurrency=4)
    assert len(out) == 4
    assert o.ban_suspected is True          # post-batch canary caught the ban


def test_concurrent_send_many_no_canary_leaves_ban_flag_false():
    o = Oracle(Target(base_url="mock://x"),
               sender=lambda p: Response(THROUGH, "200", 10, 0.0, "ok"))
    o.send_many(["a", "b"], concurrency=4)
    assert o.ban_suspected is False         # nothing to probe -> no false alarm


def test_concurrent_send_many_canary_ok_keeps_ban_false():
    o = Oracle(Target(base_url="mock://x"),
               sender=lambda p: Response(THROUGH, "200", 10, 0.0, "ok"),
               canary_payload="CANARY")
    o.send_many(["a", "b"], concurrency=4)
    assert o.ban_suspected is False         # canary still passes -> not banned


# -- #5: deep-SQLi request budget is bounded ----------------------------------
def test_union_column_budget_is_bounded_and_named():
    assert V._UNION_MAX_COLS == 6
    assert inspect.signature(V._sqli_union_confirm).parameters["max_cols"].default == 6


# -- #6: pooled transport caps the response body read -------------------------
def test_pooled_body_read_is_capped(monkeypatch):
    big = b"A" * (_MAX_BODY_BYTES + 5000)

    class FakeResp:
        status = 200
        def read(self, n=None):
            return big[:n] if n is not None else big

    class FakeConn:
        def request(self, *a, **k):
            pass
        def getresponse(self):
            return FakeResp()

    o = Oracle(Target(base_url="http://h", block_signature="zzz"), transport="pooled")
    monkeypatch.setattr(o, "_get_conn", lambda force_new=False: FakeConn())
    closed = {"n": 0}
    monkeypatch.setattr(o, "_close_conn", lambda: closed.__setitem__("n", closed["n"] + 1))
    r = o._pooled_send("x")
    assert r.size == _MAX_BODY_BYTES        # capped, not the full oversized body
    assert closed["n"] >= 1                 # oversized -> connection dropped, not drained
