"""High-speed concurrent fuzzer using threaded keep-alive connections.

Each worker thread maintains its own persistent ``http.client`` connection
and pulls payloads from a shared queue.  The GIL is irrelevant here — the
threads spend almost all their time waiting on I/O.

Typical throughput: 300-800 req/s depending on target latency and
concurrency setting (default 50 threads).
"""
from __future__ import annotations

import http.client
import json
import queue
import re
import ssl
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable, Optional

from ..core.oracle import Target


@dataclass
class FuzzResult:
    payload: str
    code: int
    size: int
    time_ms: float
    is_blocked: bool
    words: int = 0
    lines: int = 0
    body_preview: str = ""

    def as_dict(self) -> dict:
        return {
            "payload": self.payload,
            "code": self.code,
            "size": self.size,
            "time_ms": round(self.time_ms, 1),
            "is_blocked": self.is_blocked,
            "words": self.words,
            "lines": self.lines,
        }


@dataclass
class FuzzReport:
    total: int = 0
    blocked: int = 0
    passed: int = 0
    errors: int = 0
    results: list[FuzzResult] = field(default_factory=list)
    elapsed: float = 0.0
    rps: float = 0.0

    def interesting(self) -> list[FuzzResult]:
        return [r for r in self.results if not r.is_blocked and r.code > 0]

    def as_dict(self) -> dict:
        return {
            "total": self.total, "blocked": self.blocked,
            "passed": self.passed, "errors": self.errors,
            "elapsed": round(self.elapsed, 2), "rps": round(self.rps, 1),
            "results": [r.as_dict() for r in self.results],
        }


_SENTINEL = None  # poison pill for workers


def _parse_url(base_url: str, path: str):
    """Parse URL into (scheme, host, port, path)."""
    u = urllib.parse.urlparse(base_url)
    scheme = u.scheme or "https"
    host = u.hostname or "localhost"
    port = u.port or (443 if scheme == "https" else 80)
    full_path = (u.path.rstrip("/") + path) if path else u.path
    return scheme, host, port, full_path or "/"


def _make_conn(scheme: str, host: str, port: int,
               timeout: float, tls_verify: bool):
    """Create an http.client connection (keep-alive by default)."""
    if scheme == "https":
        ctx = ssl.create_default_context()
        if not tls_verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return http.client.HTTPSConnection(host, port,
                                           timeout=timeout, context=ctx)
    return http.client.HTTPConnection(host, port, timeout=timeout)


class AsyncFuzzer:
    """Thread-pool fuzzer with keep-alive connections and live filtering."""

    def __init__(self, target: Target, concurrency: int = 50,
                 timeout: float = 10.0, block_signature: str = ""):
        self.target = target
        self.concurrency = max(1, concurrency)
        self.timeout = timeout
        self.block_sig = block_signature or target.block_signature
        self._stop = threading.Event()

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    def fuzz_wordlist(
        self,
        wordlist: list[str],
        on_result: Optional[Callable[[FuzzResult], None]] = None,
        filter_codes: Optional[set[int]] = None,
        hide_codes: Optional[set[int]] = None,
        filter_size: Optional[int] = None,
        hide_size: Optional[int] = None,
        match_regex: Optional[str] = None,
    ) -> FuzzReport:
        """Fuzz the target with *wordlist* using a thread pool.

        Returns a :class:`FuzzReport` with every result that passed the
        filters.  ``on_result`` is called (from the collector thread) for
        each filtered-in result as it arrives — use it for live output.
        """
        self._stop.clear()
        scheme, host, port, base_path = _parse_url(
            self.target.base_url, self.target.path)

        work_q: queue.Queue = queue.Queue()
        result_q: queue.Queue = queue.Queue()

        for payload in wordlist:
            work_q.put(payload)
        for _ in range(self.concurrency):
            work_q.put(_SENTINEL)

        regex = re.compile(match_regex) if match_regex else None

        workers = []
        for _ in range(min(self.concurrency, len(wordlist))):
            t = threading.Thread(
                target=self._worker,
                args=(work_q, result_q, scheme, host, port, base_path),
                daemon=True,
            )
            t.start()
            workers.append(t)

        report = FuzzReport()
        start = time.monotonic()
        done = 0
        total = len(wordlist)

        while done < total:
            try:
                res = result_q.get(timeout=self.timeout + 5)
            except queue.Empty:
                break
            if self._stop.is_set():
                break
            done += 1
            report.total += 1
            if res.code == 0:
                report.errors += 1
                continue
            if res.is_blocked:
                report.blocked += 1
            else:
                report.passed += 1

            if not self._matches_filter(
                res, filter_codes, hide_codes, filter_size, hide_size, regex
            ):
                continue

            report.results.append(res)
            if on_result:
                on_result(res)

        for t in workers:
            t.join(timeout=2)

        report.elapsed = time.monotonic() - start
        report.rps = report.total / report.elapsed if report.elapsed > 0 else 0
        return report

    def fuzz_file(self, wordlist_path: str, **kwargs) -> FuzzReport:
        """Load a wordlist from *wordlist_path* and fuzz."""
        with open(wordlist_path) as f:
            words = [line.strip() for line in f if line.strip()]
        return self.fuzz_wordlist(words, **kwargs)

    def stop(self):
        """Signal all workers to stop."""
        self._stop.set()

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _worker(self, work_q, result_q, scheme, host, port, base_path):
        """Worker loop: pull payloads, send requests, push results."""
        conn = _make_conn(scheme, host, port,
                          self.timeout, self.target.tls_verify)
        while not self._stop.is_set():
            try:
                payload = work_q.get_nowait()
            except queue.Empty:
                break
            if payload is _SENTINEL:
                break
            result_q.put(self._send_one(conn, scheme, host, port,
                                        base_path, payload))
        try:
            conn.close()
        except Exception:
            pass

    def _send_one(self, conn, scheme, host, port,
                  base_path, payload) -> FuzzResult:
        """Send a single request; reconnect once on failure."""
        for attempt in range(2):
            try:
                return self._do_send(conn, base_path, payload)
            except Exception:
                if attempt == 0:
                    try:
                        conn.close()
                    except Exception:
                        pass
                    conn = _make_conn(scheme, host, port,
                                      self.timeout, self.target.tls_verify)
                else:
                    return FuzzResult(payload=payload, code=0, size=0,
                                     time_ms=0, is_blocked=False)
        return FuzzResult(payload=payload, code=0, size=0,
                          time_ms=0, is_blocked=False)

    def _do_send(self, conn, base_path, payload) -> FuzzResult:
        t = self.target
        encoded = urllib.parse.quote(payload, safe="")

        if t.inject == "query":
            sep = "&" if "?" in base_path else "?"
            full = f"{base_path}{sep}{urllib.parse.urlencode({t.param: payload})}"
            method = t.method
            body = None
            headers = {"User-Agent": t.user_agent, "Host": conn.host}
        elif t.inject == "json":
            full = base_path
            method = t.method if t.method != "GET" else "POST"
            body = json.dumps({t.param: payload})
            headers = {"User-Agent": t.user_agent, "Host": conn.host,
                       "Content-Type": "application/json"}
        elif t.inject == "body":
            full = base_path
            method = t.method if t.method != "GET" else "POST"
            body = urllib.parse.urlencode({t.param: payload})
            headers = {"User-Agent": t.user_agent, "Host": conn.host,
                       "Content-Type": "application/x-www-form-urlencoded"}
        else:
            full = f"{base_path}{encoded}"
            method = t.method
            body = None
            headers = {"User-Agent": t.user_agent, "Host": conn.host}

        for h in t.extra_headers:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()
        if t.cookie:
            headers["Cookie"] = t.cookie

        start = time.monotonic()
        conn.request(method, full, body=body, headers=headers)
        resp = conn.getresponse()
        body_bytes = resp.read(512 * 1024)  # 512 KB max
        elapsed_ms = (time.monotonic() - start) * 1000

        body_text = body_bytes.decode("utf-8", errors="replace")
        is_blocked = (
            resp.status == 403 and self.block_sig and
            self.block_sig in body_text
        )

        return FuzzResult(
            payload=payload,
            code=resp.status,
            size=len(body_bytes),
            time_ms=elapsed_ms,
            is_blocked=is_blocked,
            words=len(body_text.split()),
            lines=body_text.count("\n") + 1,
            body_preview=body_text[:200],
        )

    @staticmethod
    def _matches_filter(res, filter_codes, hide_codes,
                        filter_size, hide_size, regex) -> bool:
        if filter_codes and res.code not in filter_codes:
            return False
        if hide_codes and res.code in hide_codes:
            return False
        if filter_size is not None and res.size != filter_size:
            return False
        if hide_size is not None and res.size == hide_size:
            return False
        if regex and not regex.search(res.body_preview):
            return False
        return True
