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
import os
import subprocess
import tempfile
import urllib.parse
from dataclasses import dataclass


@dataclass
class Target:
    base_url: str
    path: str = "/"
    param: str = "q"
    method: str = "GET"
    inject: str = "query"  # query|path|rawpath|body|json|header|cookie|upload
    block_signature: str = "Request blocked by RedEye"
    timeout: int = 15
    user_agent: str = "WAFFEN/0.1 (+authorized-waf-testing)"
    # TLS policy: WAF testers routinely hit self-signed / demo endpoints, so the
    # default is insecure (curl -k), like every comparable tool. It is NOT silently
    # scattered — it is this one explicit, overridable setting (CLI: --tls-verify).
    tls_verify: bool = False
    # session / auth: extra request headers (e.g. "Authorization: Bearer ...",
    # "X-CSRF-Token: ...") and a cookie string ("sid=abc; csrf=xyz"). These thread
    # through EVERY inject mode and EVERY request transform (see Oracle._with_auth),
    # so a bypass search can run behind a login instead of only on open endpoints.
    extra_headers: tuple[str, ...] = ()
    cookie: str = ""

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


def apply_auth(argv: list[str], target) -> list[str]:
    """Splice session/auth into a curl argv, right after 'curl'.

    Single source of truth for `--header`/`--cookie`, shared by Oracle._build and
    the verifier's own separate curl path, so authentication threads through every
    request either of them issues (every inject mode, every transform, and the
    verifier's header-fetch probe). An auth cookie folds into an existing `Cookie:`
    header when one is present (e.g. under `--inject cookie`) so a session cookie
    and a cookie-injection payload share one valid header instead of colliding."""
    eh = tuple(getattr(target, "extra_headers", ()) or ())
    ck = getattr(target, "cookie", "") or ""
    if not argv or argv[0] != "curl" or not (eh or ck):
        return argv
    rest = list(argv[1:])
    inject: list[str] = []
    for h in eh:
        inject += ["-H", h]
    if ck:
        for i in range(1, len(rest)):
            if rest[i - 1] == "-H" and rest[i].lower().startswith("cookie:"):
                rest[i] = rest[i].rstrip() + "; " + ck
                break
        else:
            inject += ["-H", f"Cookie: {ck}"]
    return [argv[0]] + inject + rest


class Oracle:
    """Sends payloads via curl (same transport as the rest of the toolchain).

    An optional `request_transform` reshapes the whole HTTP request (HPP, chunked,
    multipart, verb tampering, ...) — an axis orthogonal to payload mutation. When
    set, it builds the curl argv in place of the default injection logic.
    """

    def __init__(self, target: Target, sender=None, request_transform=None, calibration=None,
                 delay: float = 0.0, backoff: bool = True,
                 canary_payload: str | None = None, canary_every: int = 25):
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
        self._tmp_cleanup: list[str] = []  # upload-probe temp files pending deletion

        # Ban-onset circuit breaker (canary probe). A rate-limit ban usually looks
        # like a clean, fast 403 — NOT a transport DOWN — so the backoff-on-DOWN path
        # above never caught it; this session got self-banned repeatedly for exactly
        # that reason. If `canary_payload` (a string expected to always be BENIGN) is
        # given, every `canary_every` sends we re-probe it; if it now classifies as
        # BLOCKED, the test source is very likely banned, not the content being newly
        # risky. `ban_suspected` reflects the *latest* canary read (not sticky), so a
        # caller can warn/abort, and recovers on its own once the ban clears.
        self.canary_payload = canary_payload
        self.canary_every = max(canary_every, 1)
        self.ban_suspected = False
        self._since_canary = 0

    def _make_probe_file(self, content: bytes = b"WAFFEN-upload-probe-marker\n") -> str:
        """Write a small benign-content temp file for a multipart upload probe.
        Tracked for cleanup right after the curl subprocess that references it runs."""
        fd, path = tempfile.mkstemp(prefix="waffen_upload_")
        with os.fdopen(fd, "wb") as f:
            f.write(content)
        self._tmp_cleanup.append(path)
        return path

    def _cleanup_tmp_files(self) -> None:
        while self._tmp_cleanup:
            p = self._tmp_cleanup.pop()
            try:
                os.unlink(p)
            except OSError:
                pass

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
    def _with_auth(self, argv: list[str]) -> list[str]:
        """Thread session/auth (`--header`, `--cookie`) into a curl argv, for BOTH
        the default-built request and any transform-built one. See `apply_auth`."""
        return apply_auth(argv, self.t)

    def _build(self, payload: str) -> list[str]:
        if self.request_transform is not None:
            argv = self.request_transform.build(self.t, payload)
            if argv:
                return self._with_auth(argv)
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
        elif t.inject == "upload":
            # `payload` controls the UPLOADED FILENAME, not a param value — this is
            # the real-world test for "Upload Insecure Files": does the WAF filter
            # dangerous extensions on a genuine multipart upload? A bare extension
            # (no '.') gets a benign-looking stem; a dotted payload is used verbatim
            # so seeds can carry full bypass filenames (double-ext, case, etc.).
            fname = payload if "." in payload else f"waffen_probe.{payload}"
            tmp_path = self._make_probe_file()
            # curl's -F mini-syntax splits on ';'; quoting the filename value lets it
            # safely contain one (e.g. the classic "shell.php;.jpg" multiviews trick).
            cmd += ["-X", t.method, url, "-F", f'{t.param}=@{tmp_path};filename="{fname}"']
        else:
            raise ValueError(f"unknown inject mode: {t.inject}")
        return self._with_auth(cmd)

    def _curl_send(self, payload: str) -> Response:
        cmd = self._build(payload)
        try:
            out = subprocess.run(cmd, capture_output=True, text=True,
                                 timeout=self.t.timeout + 5).stdout
        except Exception:
            return Response(DOWN, "000", 0, 0.0, "")
        finally:
            self._cleanup_tmp_files()  # any upload-probe temp file `_build` created
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

        # Canary ban check (see __init__ docstring note): a clean fast 403 ban looks
        # just like a normal BLOCKED verdict, so it must be checked against a payload
        # we *know* is benign, not inferred from this response alone.
        canary_just_confirmed_ban = False
        if self.canary_payload is not None:
            self._since_canary += 1
            if self._since_canary >= self.canary_every:
                self._since_canary = 0
                self.requests += 1
                canary_resp = self._apply_calibration(self._sender(self.canary_payload))
                self.ban_suspected = (canary_resp.verdict == BLOCKED)
                canary_just_confirmed_ban = self.ban_suspected

        if canary_just_confirmed_ban and self.backoff:
            # Pause hard right when a FRESH canary check confirms the ban — once per
            # check, not on every intervening send. `ban_suspected` otherwise stays
            # readable between checks (for a caller to notice and decide to stop) but
            # must NOT re-trigger this sleep on every one of the next `canary_every`
            # sends, or a suspected ban turns a run into an hours-long near-hang
            # instead of a bounded pause-and-reassess.
            self._down_streak += 1
            _time.sleep(min(1.0 * (2 ** min(self._down_streak, 5)), 30.0))
        elif self.backoff:
            if resp.verdict == DOWN:
                self._down_streak += 1
                _time.sleep(min(0.2 * (2 ** self._down_streak), 5.0))
            else:
                self._down_streak = 0
        return resp

    def send_many(self, payloads, concurrency: int = 8, delay: float = 0.0):
        """Send many payloads; returns a list of Response in the same order.

        Lets a search strategy or a bulk eval/dataset run evaluate a whole
        batch in parallel. `delay` throttles per-request (applied before each send).

        concurrency<=1 routes every send through `self.send()` — the same path
        a sequential caller would use — so it gets canary ban-detection and
        DOWN-backoff for free; this is what a large, unattended, log-collection
        run over a full corpus should use. concurrency>1 uses a raw parallel
        path with NEITHER (no stable request ordering under concurrency makes a
        canary re-probe meaningless, and backoff would serialize the pool
        anyway) — a deliberate tradeoff: pick concurrency=1 when ban detection
        matters more than throughput, concurrency>1 when it doesn't.
        """
        import concurrent.futures as _cf
        import time as _time
        payloads = list(payloads)

        if concurrency <= 1:
            out = []
            for p in payloads:
                if delay:
                    _time.sleep(delay)
                out.append(self.send(p))
            return out

        def one(p):
            if delay:
                _time.sleep(delay)
            self.requests += 1
            return self._apply_calibration(self._sender(p))
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
