"""Tests for speed optimizations: response caching, connection reuse."""
from unittest.mock import MagicMock, patch

from waffen.core.oracle import Oracle, Target, Response, BLOCKED, THROUGH, DOWN


def _make_oracle(cache_size=256, transport="curl"):
    target = Target(base_url="https://test.local", param="q")
    sender = MagicMock(return_value=Response(BLOCKED, "403", 100, 0.1, "blocked"))
    oracle = Oracle(target, sender=sender, transport=transport, cache_size=cache_size)
    return oracle, sender


class TestResponseCache:
    def test_cache_hit_avoids_sender(self):
        oracle, sender = _make_oracle()
        r1 = oracle.send("test")
        r2 = oracle.send("test")
        assert sender.call_count == 1
        assert r1.verdict == r2.verdict
        assert oracle._cache_hits == 1

    def test_different_payloads_no_cache(self):
        oracle, sender = _make_oracle()
        oracle.send("a")
        oracle.send("b")
        assert sender.call_count == 2
        assert oracle._cache_hits == 0

    def test_down_responses_not_cached(self):
        target = Target(base_url="https://test.local")
        sender = MagicMock(return_value=Response(DOWN, "000", 0, 0.0, ""))
        oracle = Oracle(target, sender=sender, cache_size=256)
        oracle.send("test")
        oracle.send("test")
        assert sender.call_count == 2  # DOWN not cached

    def test_cache_disabled_when_size_zero(self):
        oracle, sender = _make_oracle(cache_size=0)
        oracle.send("test")
        oracle.send("test")
        assert sender.call_count == 2
        assert oracle._cache_hits == 0

    def test_cache_eviction_at_max_size(self):
        oracle, sender = _make_oracle(cache_size=2)
        oracle.send("a")
        oracle.send("b")
        oracle.send("c")  # evicts "a"
        assert len(oracle._cache) == 2
        # "a" evicted, should be re-sent
        oracle.send("a")
        assert sender.call_count == 4  # a, b, c, a-again

    def test_cache_key_includes_transform(self):
        oracle, sender = _make_oracle()
        oracle.send("test")
        # Change transform → different cache key
        oracle.request_transform = MagicMock()
        oracle.request_transform.name = "hpp"
        oracle.send("test")
        assert sender.call_count == 2  # not a cache hit

    def test_through_response_cached(self):
        target = Target(base_url="https://test.local")
        sender = MagicMock(return_value=Response(THROUGH, "200", 50, 0.1, "ok"))
        oracle = Oracle(target, sender=sender, cache_size=256)
        oracle.send("test")
        oracle.send("test")
        assert sender.call_count == 1
        assert oracle._cache_hits == 1


class TestConnectionReuse:
    def test_pooled_reuses_connection(self):
        """The pooled transport reuses http.client connection across sends."""
        target = Target(base_url="https://test.local")
        oracle = Oracle(target, transport="pooled", cache_size=0)
        # _get_conn without force_new should return same object
        with patch.object(oracle, "_get_conn") as mock_conn:
            mock_resp = MagicMock()
            mock_resp.status = 403
            mock_resp.read.return_value = b"blocked by WAF"
            mock_conn.return_value.getresponse.return_value = mock_resp
            oracle._pooled_send("test1")
            oracle._pooled_send("test2")
            # Both calls should use _get_conn (not force_new on first attempt)
            assert mock_conn.call_count == 2
            for call in mock_conn.call_args_list:
                assert call.kwargs.get("force_new", False) is False


class TestSendMany:
    def test_send_many_concurrent(self):
        oracle, sender = _make_oracle(cache_size=0)
        results = oracle.send_many(["a", "b", "c"], concurrency=3)
        assert len(results) == 3
        assert sender.call_count == 3

    def test_send_many_sequential(self):
        oracle, sender = _make_oracle(cache_size=0)
        results = oracle.send_many(["a", "b"], concurrency=1)
        assert len(results) == 2
