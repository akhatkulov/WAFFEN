"""Multi-request attack sequences — split an attack across HTTP requests.

WAF scoring engines inspect each request independently. By splitting an attack
into two or more steps — one that sets up state (registers, logs in, stores a
fragment) and another that triggers execution — neither step alone triggers the
WAF's signature match, while the backend processes the combined effect.

A ``Sequence`` is a list of ``RequestStep`` s. Each step can extract values from
its response (via JSONPath-like dot notation, header names, or regex) and pass
them as ``{placeholder}`` tokens into later steps. Only the **last** step is
scored for WAF bypass — earlier steps are setup.
"""
from __future__ import annotations

import copy
import json
import re
import subprocess
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional

from .oracle import Target, Response, BLOCKED, THROUGH, DOWN


@dataclass
class RequestStep:
    method: str = "GET"
    path: str = "/"
    params: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    body: Optional[str] = None
    content_type: str = ""
    extract: dict = field(default_factory=dict)

    def with_context(self, ctx: dict) -> "RequestStep":
        """Return a copy with ``{key}`` placeholders resolved from *ctx*."""
        s = copy.deepcopy(self)
        s.path = _sub(s.path, ctx)
        s.params = {k: _sub(v, ctx) for k, v in s.params.items()}
        s.headers = {k: _sub(v, ctx) for k, v in s.headers.items()}
        if s.body is not None:
            s.body = _sub(s.body, ctx)
        s.content_type = _sub(s.content_type, ctx)
        return s


@dataclass
class AttackSequence:
    name: str
    steps: list[RequestStep]
    description: str = ""

    def with_payload(self, payload: str) -> "AttackSequence":
        """Return a copy with ``{PAYLOAD}`` replaced in every step."""
        new_steps = []
        for step in self.steps:
            new_steps.append(step.with_context({"PAYLOAD": payload}))
        return AttackSequence(name=self.name, steps=new_steps,
                              description=self.description)


@dataclass
class StepResult:
    index: int
    code: str
    body: str
    extracted: dict = field(default_factory=dict)


@dataclass
class SequenceResult:
    sequence_name: str
    payload: str
    steps: list[StepResult] = field(default_factory=list)
    verdict: str = DOWN
    final_code: str = "000"
    final_body: str = ""
    requests: int = 0

    @property
    def through(self) -> bool:
        return self.verdict == THROUGH


# ---------------------------------------------------------------------------
# placeholder substitution
# ---------------------------------------------------------------------------

def _sub(s: str, ctx: dict) -> str:
    """Replace ``{key}`` tokens in *s* from *ctx*."""
    if not ctx or "{" not in s:
        return s
    for k, v in ctx.items():
        s = s.replace("{" + k + "}", str(v))
    return s


# ---------------------------------------------------------------------------
# value extraction
# ---------------------------------------------------------------------------

_DOT_RE = re.compile(r"^\$\.([A-Za-z0-9_.]+)$")
_HEADER_RE = re.compile(r"^[A-Z][A-Za-z0-9-]+$")


def _extract(body: str, headers: dict, pattern: str) -> str:
    """Extract a value from a response.

    Supported patterns:
      ``$.json.path``        — dot-separated JSON path (``$.authentication.token``)
      ``Header-Name``        — response header value
      ``/regex/``            — first capture group of a regex on the body
    """
    m = _DOT_RE.match(pattern)
    if m:
        return _jsonpath(body, m.group(1))

    if _HEADER_RE.match(pattern):
        return headers.get(pattern, headers.get(pattern.lower(), ""))

    if pattern.startswith("/") and pattern.endswith("/") and len(pattern) > 2:
        rx = re.search(pattern[1:-1], body)
        if rx:
            return rx.group(1) if rx.lastindex else rx.group(0)
        return ""

    return ""


def _jsonpath(body: str, dotpath: str) -> str:
    """Minimal JSON dot-path extractor: ``authentication.token``."""
    try:
        obj = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return ""
    for key in dotpath.split("."):
        if isinstance(obj, dict):
            obj = obj.get(key, "")
        elif isinstance(obj, list) and key.isdigit():
            idx = int(key)
            obj = obj[idx] if idx < len(obj) else ""
        else:
            return ""
    return str(obj) if obj is not None else ""


# ---------------------------------------------------------------------------
# runner
# ---------------------------------------------------------------------------

class SequenceRunner:
    """Execute multi-step attack sequences against a target."""

    def __init__(self, target: Target, sender=None):
        self.target = target
        self._sender = sender

    def run(self, sequence: AttackSequence, payload: str = "") -> SequenceResult:
        """Run all steps, threading extracted values between them.

        Only the **last** step's response determines the WAF verdict.
        """
        seq = sequence.with_payload(payload) if payload else sequence
        result = SequenceResult(sequence_name=seq.name, payload=payload)
        ctx: dict = {}

        for i, step in enumerate(seq.steps):
            resolved = step.with_context(ctx)
            resp, resp_headers = self._send_step(resolved)
            result.requests += 1

            extracted: dict = {}
            for var_name, pattern in resolved.extract.items():
                extracted[var_name] = _extract(resp.body, resp_headers, pattern)
                ctx[var_name] = extracted[var_name]

            result.steps.append(StepResult(
                index=i, code=resp.code, body=resp.body[:500],
                extracted=extracted,
            ))

            if i == len(seq.steps) - 1:
                result.verdict = resp.verdict
                result.final_code = resp.code
                result.final_body = resp.body

        return result

    def _send_step(self, step: RequestStep) -> tuple[Response, dict]:
        """Send one step via curl and return (Response, header_dict)."""
        t = self.target
        url = t.base_url.rstrip("/") + step.path

        if step.params:
            qs = urllib.parse.urlencode(step.params)
            sep = "&" if "?" in url else "?"
            url = url + sep + qs

        cmd = ["curl", t.curl_sec(with_i=True), "-m", str(t.timeout),
               "-w", "\n%{http_code} %{size_download} %{time_total}",
               "-A", t.user_agent, "-X", step.method]

        if step.body is not None:
            ct = step.content_type or "application/json"
            cmd += ["-H", f"Content-Type: {ct}", "-d", step.body]

        for hk, hv in step.headers.items():
            cmd += ["-H", f"{hk}: {hv}"]

        for eh in t.extra_headers:
            cmd += ["-H", eh]
        if t.cookie:
            cmd += ["-H", f"Cookie: {t.cookie}"]

        cmd.append(url)

        if self._sender is not None:
            resp = self._sender(step, cmd)
            return resp, {}

        try:
            out = subprocess.run(cmd, capture_output=True, text=True,
                                 timeout=t.timeout + 5).stdout
        except Exception:
            return Response(DOWN, "000", 0, 0.0, ""), {}

        resp_headers = {}
        lines = out.split("\n")
        body_start = 0
        for idx, line in enumerate(lines):
            stripped = line.strip()
            if not stripped and idx > 0:
                body_start = idx + 1
                break
            if ":" in stripped:
                hk, _, hv = stripped.partition(":")
                resp_headers[hk.strip()] = hv.strip()

        body_and_stat = "\n".join(lines[body_start:])
        nl = body_and_stat.rfind("\n")
        body = body_and_stat[:nl] if nl != -1 else ""
        stat = body_and_stat[nl + 1:].strip() if nl != -1 else body_and_stat.strip()

        parts = stat.split()
        code = parts[0] if parts else "000"
        size = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else len(body)
        try:
            tt = float(parts[2]) if len(parts) > 2 else 0.0
        except ValueError:
            tt = 0.0

        verdict = self._classify(code, body)
        return Response(verdict, code, size, tt, body), resp_headers

    def _classify(self, code: str, body: str) -> str:
        if code in ("", "000", "502", "503", "504"):
            return DOWN
        if code == "403" and self.target.block_signature in body:
            return BLOCKED
        return THROUGH
