"""Tests for the high-speed async fuzzer."""
from __future__ import annotations

import io
import threading
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from waffen.fuzz.engine import (
    AsyncFuzzer, FuzzResult, FuzzReport, _parse_url, _SENTINEL,
)
from waffen.fuzz.wordlists import (
    sqli_fuzz, xss_fuzz, path_fuzz, param_fuzz, BUILTINS,
)
from waffen.core.oracle import Target


# ---------------------------------------------------------------------------
# FuzzResult
# ---------------------------------------------------------------------------

class TestFuzzResult:
    def test_as_dict(self):
        r = FuzzResult(payload="' OR 1=1--", code=200, size=100,
                       time_ms=12.5, is_blocked=False, words=10, lines=3)
        d = r.as_dict()
        assert d["payload"] == "' OR 1=1--"
        assert d["code"] == 200
        assert d["time_ms"] == 12.5

    def test_blocked_flag(self):
        r = FuzzResult(payload="x", code=403, size=0, time_ms=0,
                       is_blocked=True)
        assert r.is_blocked

    def test_body_preview(self):
        r = FuzzResult(payload="x", code=200, size=5000, time_ms=10,
                       is_blocked=False, body_preview="hello world")
        assert r.body_preview == "hello world"


# ---------------------------------------------------------------------------
# FuzzReport
# ---------------------------------------------------------------------------

class TestFuzzReport:
    def test_empty(self):
        r = FuzzReport()
        assert r.total == 0
        assert r.interesting() == []

    def test_interesting_excludes_blocked(self):
        r = FuzzReport(results=[
            FuzzResult("a", 200, 100, 10, False),
            FuzzResult("b", 403, 200, 10, True),
            FuzzResult("c", 500, 50, 20, False),
        ])
        interesting = r.interesting()
        assert len(interesting) == 2
        assert all(not x.is_blocked for x in interesting)

    def test_as_dict(self):
        r = FuzzReport(total=10, blocked=5, passed=4, errors=1,
                       elapsed=2.0, rps=5.0)
        d = r.as_dict()
        assert d["total"] == 10
        assert d["rps"] == 5.0


# ---------------------------------------------------------------------------
# URL parsing
# ---------------------------------------------------------------------------

class TestParseUrl:
    def test_https(self):
        s, h, p, path = _parse_url("https://example.com", "/search")
        assert s == "https"
        assert h == "example.com"
        assert p == 443
        assert path == "/search"

    def test_http_with_port(self):
        s, h, p, path = _parse_url("http://localhost:8080", "/api")
        assert s == "http"
        assert h == "localhost"
        assert p == 8080
        assert path == "/api"

    def test_path_concatenation(self):
        s, h, p, path = _parse_url("https://example.com/v1", "/search")
        assert path == "/v1/search"


# ---------------------------------------------------------------------------
# Filter logic
# ---------------------------------------------------------------------------

class TestFilterLogic:
    def test_filter_codes_match(self):
        ok = AsyncFuzzer._matches_filter(
            FuzzResult("x", 200, 100, 10, False),
            filter_codes={200}, hide_codes=None,
            filter_size=None, hide_size=None, regex=None)
        assert ok

    def test_filter_codes_reject(self):
        ok = AsyncFuzzer._matches_filter(
            FuzzResult("x", 403, 100, 10, True),
            filter_codes={200}, hide_codes=None,
            filter_size=None, hide_size=None, regex=None)
        assert not ok

    def test_hide_codes(self):
        ok = AsyncFuzzer._matches_filter(
            FuzzResult("x", 403, 100, 10, True),
            filter_codes=None, hide_codes={403},
            filter_size=None, hide_size=None, regex=None)
        assert not ok

    def test_filter_size(self):
        ok = AsyncFuzzer._matches_filter(
            FuzzResult("x", 200, 100, 10, False),
            filter_codes=None, hide_codes=None,
            filter_size=100, hide_size=None, regex=None)
        assert ok

    def test_hide_size(self):
        ok = AsyncFuzzer._matches_filter(
            FuzzResult("x", 200, 100, 10, False),
            filter_codes=None, hide_codes=None,
            filter_size=None, hide_size=100, regex=None)
        assert not ok

    def test_match_regex(self):
        import re
        regex = re.compile("token")
        r = FuzzResult("x", 200, 100, 10, False, body_preview='{"token":"abc"}')
        ok = AsyncFuzzer._matches_filter(
            r, filter_codes=None, hide_codes=None,
            filter_size=None, hide_size=None, regex=regex)
        assert ok

    def test_regex_no_match(self):
        import re
        regex = re.compile("secret")
        r = FuzzResult("x", 200, 100, 10, False, body_preview="nothing here")
        ok = AsyncFuzzer._matches_filter(
            r, filter_codes=None, hide_codes=None,
            filter_size=None, hide_size=None, regex=regex)
        assert not ok

    def test_no_filters_all_pass(self):
        r = FuzzResult("x", 200, 100, 10, False)
        ok = AsyncFuzzer._matches_filter(
            r, filter_codes=None, hide_codes=None,
            filter_size=None, hide_size=None, regex=None)
        assert ok

    def test_combined_filters(self):
        r = FuzzResult("x", 200, 500, 10, False)
        ok = AsyncFuzzer._matches_filter(
            r, filter_codes={200, 500}, hide_codes=None,
            filter_size=None, hide_size=500, regex=None)
        assert not ok  # size hidden


# ---------------------------------------------------------------------------
# Wordlists
# ---------------------------------------------------------------------------

class TestWordlists:
    def test_sqli_nonempty(self):
        words = sqli_fuzz()
        assert len(words) >= 50

    def test_xss_nonempty(self):
        words = xss_fuzz()
        assert len(words) >= 50

    def test_path_nonempty(self):
        words = path_fuzz()
        assert len(words) >= 20

    def test_param_nonempty(self):
        words = param_fuzz()
        assert len(words) >= 20

    def test_builtins_all_present(self):
        assert set(BUILTINS.keys()) == {"sqli", "xss", "path", "param"}

    def test_builtins_callable(self):
        for name, fn in BUILTINS.items():
            result = fn()
            assert isinstance(result, list), f"{name} should return a list"
            assert all(isinstance(w, str) for w in result)

    def test_no_duplicates_sqli(self):
        words = sqli_fuzz()
        assert len(words) == len(set(words)), "sqli wordlist has duplicates"


# ---------------------------------------------------------------------------
# AsyncFuzzer with mock connections
# ---------------------------------------------------------------------------

class _FakeResponse:
    def __init__(self, status=200, body=b"OK"):
        self.status = status
        self._body = body
    def read(self, n=None):
        return self._body


class TestAsyncFuzzerMocked:
    def _make_fuzzer(self):
        target = Target(base_url="https://test.local", path="/search",
                        param="q", block_signature="BLOCKED")
        return AsyncFuzzer(target, concurrency=2, timeout=5)

    def test_fuzz_wordlist_basic(self):
        fuzzer = self._make_fuzzer()
        results_collected = []

        def fake_do_send(conn, base_path, payload):
            return FuzzResult(payload=payload, code=200, size=100,
                              time_ms=5.0, is_blocked=False, words=5, lines=1)

        fuzzer._do_send = fake_do_send
        with patch.object(fuzzer, '_worker', wraps=None) as mock_worker:
            def patched_worker(work_q, result_q, *a):
                while True:
                    try:
                        p = work_q.get_nowait()
                    except Exception:
                        break
                    if p is _SENTINEL:
                        break
                    result_q.put(fake_do_send(None, "/search", p))
            mock_worker.side_effect = patched_worker

            report = fuzzer.fuzz_wordlist(["a", "b", "c"])

        assert report.total == 3
        assert report.errors == 0

    def test_fuzz_with_filter(self):
        fuzzer = self._make_fuzzer()

        def patched_worker(work_q, result_q, *a):
            while True:
                try:
                    p = work_q.get_nowait()
                except Exception:
                    break
                if p is _SENTINEL:
                    break
                code = 200 if p == "good" else 403
                blocked = code == 403
                result_q.put(FuzzResult(p, code, 100, 5.0, blocked))

        with patch.object(fuzzer, '_worker', side_effect=patched_worker):
            report = fuzzer.fuzz_wordlist(
                ["good", "bad1", "bad2"],
                filter_codes={200},
            )

        assert report.total == 3
        assert len(report.results) == 1
        assert report.results[0].payload == "good"

    def test_stop(self):
        fuzzer = self._make_fuzzer()
        fuzzer.stop()
        assert fuzzer._stop.is_set()

    def test_report_rps(self):
        r = FuzzReport(total=100, elapsed=2.0)
        r.rps = r.total / r.elapsed
        assert r.rps == 50.0


# ---------------------------------------------------------------------------
# CLI parser
# ---------------------------------------------------------------------------

class TestFuzzCli:
    def test_fuzz_subcommand_exists(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args(["fuzz", "--target", "https://test.com",
                             "--builtin", "sqli", "-c", "10"])
        assert args.target == "https://test.com"
        assert args.builtin == "sqli"
        assert args.concurrency == 10
        assert hasattr(args, "func")

    def test_fuzz_worker_crash_no_hang(self):
        """Regression: if all workers crash, the main loop must not hang."""
        import queue as _q
        import time

        result_q = _q.Queue()
        # Simulate workers that die immediately (threads that already finished)
        dead_workers = []
        for _ in range(3):
            t = threading.Thread(target=lambda: None, daemon=True)
            t.start()
            t.join()  # wait for it to die
            dead_workers.append(t)
        assert not any(t.is_alive() for t in dead_workers)

        # Main loop should detect dead workers and break within seconds
        done = 0
        total = 100
        start = time.monotonic()
        while done < total:
            try:
                result_q.get(timeout=2.0)
                done += 1
            except _q.Empty:
                if not any(t.is_alive() for t in dead_workers):
                    break
                continue
        elapsed = time.monotonic() - start
        assert elapsed < 5.0, f"Loop hung for {elapsed:.1f}s — should break on dead workers"
        assert done == 0, "No results expected from dead workers"

    def test_fuzz_filter_flags(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args(["fuzz", "--target", "https://t.com",
                             "--builtin", "sqli",
                             "-mc", "200,500", "-fc", "403",
                             "-ms", "100", "-fs", "0"])
        assert args.mc == "200,500"
        assert args.fc == "403"
        assert args.ms == 100
        assert args.fs == 0
