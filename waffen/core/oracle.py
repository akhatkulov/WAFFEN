"""The oracle: send one payload at the target and classify the response.

Verdict convention matches the RedEye/Auto.sh family:
  BLOCKED  = HTTP 403 whose body contains the configured block signature
  THROUGH  = any other non-error response (reached origin)  <- a bypass candidate
  DOWN     = 000/502/503/504 or transport error (inconclusive)

Because the oracle only yields a *binary* block/through signal, the search engine
needs a secondary "are we perturbing the WAF?" gradient. `score()` provides it by
measuring how far a candidate's response drifts from the baseline blocked response
(status-code change, body-length delta). A drifting response means the mutation is
reaching deeper into the stack — a promising direction even while still BLOCKED.
"""
from __future__ import annotations

import json
import subprocess
import urllib.parse
from dataclasses import dataclass


@dataclass
class Target:
    base_url: str
    path: str = "/"
    param: str = "q"
    method: str = "GET"
    inject: str = "query"  # query|path|rawpath|body|json|header|cookie
    block_signature: str = "Request blocked by RedEye"
    timeout: int = 15
    user_agent: str = "WAFFEN/0.1 (+authorized-waf-testing)"
    # TLS policy: WAF testers routinely hit self-signed / demo endpoints, so the
    # default is insecure (curl -k), like every comparable tool. It is NOT silently
    # scattered — it is this one explicit, overridable setting (CLI: --tls-verify).
    tls_verify: bool = False

    def url(self) -> str:
        return self.base_url.rstrip("/") + self.path

    def curl_sec(self, with_i: bool = False) -> str:
        """The curl security flag for this target: -s/-sk, plus 'i' to include headers."""
        flag = "-s" if self.tls_verify else "-sk"
        return flag + ("i" if with_i else "")


@dataclass
class Response:
    verdict: str          # BLOCKED | THROUGH | DOWN
    code: str
    size: int
    time: float
    body: str

    @property
    def through(self) -> bool:
        return self.verdict == "THROUGH"


# verdicts
BLOCKED, THROUGH, DOWN = "BLOCKED", "THROUGH", "DOWN"
_DOWN_CODES = {"", "000", "502", "503", "504"}


class Oracle:
    """Sends payloads via curl (same transport as the rest of the toolchain).

    An optional `request_transform` reshapes the whole HTTP request (HPP, chunked,
    multipart, verb tampering, ...) — an axis orthogonal to payload mutation. When
    set, it builds the curl argv in place of the default injection logic.
    """

    def __init__(self, target: Target, sender=None, request_transform=None, calibration=None,
                 delay: float = 0.0, backoff: bool = True):
        self.t = target
        self._sender = sender or self._curl_send
        self.request_transform = request_transform
        # optional learned block/pass model (verify.calibrate.Calibration); when set and
        # it detected a WAF, it REPLACES the naive 403-based verdict.
        self.calibration = calibration
        self.delay = delay          # fixed throttle between requests (be a good neighbour)
        self.backoff = backoff      # exponential backoff on consecutive DOWN (avoid hammering a struggling/ban-dropping WAF)
        self._down_streak = 0
        self.requests = 0

    _CAL_MAP = {"block": BLOCKED, "pass": THROUGH, "unresolved": BLOCKED}

    def _apply_calibration(self, resp: "Response") -> "Response":
        cal = self.calibration
        if cal is not None and getattr(cal, "waf_detected", False):
            try:
                resp.verdict = self._CAL_MAP.get(cal.classify(resp), resp.verdict)
            except Exception:
                pass
        return resp

    # -- request building -----------------------------------------------------
    def _build(self, payload: str) -> list[str]:
        if self.request_transform is not None:
            argv = self.request_transform.build(self.t, payload)
            if argv:
                return argv
        t = self.t
        cmd = ["curl", t.curl_sec(), "-m", str(t.timeout),
               "-w", "\n%{http_code} %{size_download} %{time_total}",
               "-A", t.user_agent]
        url = t.url()
        if t.inject == "query":
            qp = urllib.parse.urlencode({t.param: payload})
            sep = "&" if "?" in url else "?"
            cmd += ["-X", t.method, f"{url}{sep}{qp}"]
        elif t.inject == "path":
            cmd += ["-X", t.method, f"{url}/{urllib.parse.quote(payload, safe='')}"]
        elif t.inject == "rawpath":
            enc = urllib.parse.quote(payload, safe="/.-_~")
            cmd += ["-X", t.method, f"{url.rstrip('/')}/{enc.lstrip('/')}"]
        elif t.inject == "body":
            cmd += ["-X", t.method, url,
                    "-H", "Content-Type: application/x-www-form-urlencoded",
                    "--data-urlencode", f"{t.param}={payload}"]
        elif t.inject == "json":
            cmd += ["-X", t.method, url, "-H", "Content-Type: application/json",
                    "-d", json.dumps({t.param: payload})]
        elif t.inject == "header":
            cmd += ["-X", t.method, url, "-H", f"{t.param}: {payload}"]
        elif t.inject == "cookie":
            cmd += ["-X", t.method, url, "-H", f"Cookie: {t.param}={payload}"]
        else:
            raise ValueError(f"unknown inject mode: {t.inject}")
        return cmd

    def _curl_send(self, payload: str) -> Response:
        cmd = self._build(payload)
        try:
            out = subprocess.run(cmd, capture_output=True, text=True,
                                 timeout=self.t.timeout + 5).stdout
        except Exception:
            return Response(DOWN, "000", 0, 0.0, "")
        nl = out.rfind("\n")
        body, stat = (out[:nl], out[nl + 1:].strip()) if nl != -1 else ("", out.strip())
        parts = stat.split()
        code = parts[0] if parts else ""
        size = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else len(body)
        try:
            tt = float(parts[2]) if len(parts) > 2 else 0.0
        except ValueError:
            tt = 0.0
        return Response(self._classify(code, body), code, size, tt, body)

    def _classify(self, code: str, body: str) -> str:
        if code in _DOWN_CODES:
            return DOWN
        if code == "403" and self.t.block_signature.lower() in body.lower():
            return BLOCKED
        return THROUGH

    # -- public API -----------------------------------------------------------
    def send(self, payload: str) -> Response:
        import time as _time
        if self.delay:
            _time.sleep(self.delay)
        self.requests += 1
        resp = self._apply_calibration(self._sender(payload))
        if self.backoff:
            if resp.verdict == DOWN:
                self._down_streak += 1
                _time.sleep(min(0.2 * (2 ** self._down_streak), 5.0))
            else:
                self._down_streak = 0
        return resp

    def send_many(self, payloads, concurrency: int = 8, delay: float = 0.0):
        """Send many payloads concurrently; returns a list of Response in order.

        Lets a search strategy evaluate a whole frontier/generation in parallel.
        `delay` throttles per-request (applied inside each worker before sending).
        """
        import concurrent.futures as _cf
        import time as _time
        payloads = list(payloads)

        def one(p):
            if delay:
                _time.sleep(delay)
            self.requests += 1
            return self._apply_calibration(self._sender(p))

        if concurrency <= 1:
            return [one(p) for p in payloads]
        with _cf.ThreadPoolExecutor(max_workers=concurrency) as ex:
            return list(ex.map(one, payloads))

    @staticmethod
    def score(resp: Response, baseline: Response) -> float:
        """Higher = the mutation perturbs the stack more (more promising)."""
        if resp.verdict == DOWN:
            return -1.0
        if resp.verdict == THROUGH:
            return 1e9  # success dominates
        s = 0.0
        if resp.code != baseline.code:
            s += 3.0
        denom = max(baseline.size, 1)
        s += min(abs(resp.size - baseline.size) / denom, 2.0)
        return s
