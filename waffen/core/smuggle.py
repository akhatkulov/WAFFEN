"""HTTP request-smuggling probes (CL.TE / TE.CL / TE obfuscations).

Front-end (often the WAF) and back-end can disagree on how a request is framed —
which of Content-Length vs Transfer-Encoding wins. That differential lets a
request smuggle past the WAF. These are the standard PortSwigger *timing* probes:
craft a request so that, under a given desync, the back-end waits for bytes that
never arrive and the response stalls. A probe that stalls (elapsed ≈ timeout)
while a normal request is fast is a strong desync signal.

Authorized targets only. Experimental and timing-sensitive — a flag means
"investigate manually", never "confirmed". Validate on infrastructure you own.
"""
from __future__ import annotations

from dataclasses import dataclass

from .rawhttp import parse_target, send_raw


def _req(method, path, host, headers: list[str], body: str) -> bytes:
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"] + headers + ["Connection: close"]
    return ("\r\n".join(lines) + "\r\n\r\n" + body).encode("latin1", "replace")


def baseline_req(host, path) -> bytes:
    return _req("GET", path, host, ["Content-Length: 0"], "")


def clte_req(host, path, te_header="Transfer-Encoding: chunked") -> bytes:
    # front-end honours Content-Length (forwards 4 bytes "1\r\nA"), back-end honours
    # chunked and then waits for the next chunk -> stall. te_header lets us test
    # obfuscated TE variants the WAF may not recognise but the back-end does.
    body = "1\r\nA\r\nX"
    return _req("POST", path, host, ["Content-Length: 4", te_header], body)


def tecl_req(host, path, te_header="Transfer-Encoding: chunked") -> bytes:
    # front honours chunked (sees terminating 0 chunk), back honours Content-Length=6
    # and waits for 6 body bytes it never gets -> stall.
    body = "0\r\n\r\nX"
    return _req("POST", path, host, [te_header, "Content-Length: 6"], body)


# Transfer-Encoding header obfuscations a WAF may fail to parse (so it falls back to
# Content-Length) while a lenient back-end still treats the request as chunked.
TE_OBFUSCATIONS = [
    "Transfer-Encoding: chunked",
    "Transfer-Encoding:\tchunked",         # tab instead of space
    "Transfer-Encoding : chunked",         # space before colon
    "Transfer-Encoding: xchunked",         # prefixed value
    "Transfer-Encoding:  chunked",         # double space
    "X: X\r\nTransfer-Encoding: chunked",  # header smuggled via folded line
]


@dataclass
class SmuggleFinding:
    name: str
    elapsed: float
    status: str
    suspected: bool
    detail: str


def detect(base_url: str, path: str = "/", *, timeout: float = 8.0,
           stall_factor: float = 3.0, on_event=None) -> list[SmuggleFinding]:
    """Send a baseline + CL.TE/TE.CL probes (incl. TE obfuscations) and flag any
    whose response stalls far longer than the baseline — a desync signal."""
    host, port, tls, p = parse_target(base_url, path)

    def run(name, raw):
        r = send_raw(host, port, tls, raw, timeout=timeout)
        if on_event:
            on_event("probe", name=name, elapsed=r["elapsed"], status=r["status"], error=r.get("error"))
        return r

    base = run("baseline", baseline_req(host, p))
    base_t = max(base["elapsed"], 0.05)
    threshold = max(base_t * stall_factor, base_t + 2.0)

    findings: list[SmuggleFinding] = []
    probes = [("CL.TE", clte_req(host, p)), ("TE.CL", tecl_req(host, p))]
    for i, te in enumerate(TE_OBFUSCATIONS[1:], start=1):  # obfuscated TE as CL.TE variants
        probes.append((f"CL.TE/obf[{i}]", clte_req(host, p, te_header=te)))

    for name, raw in probes:
        r = run(name, raw)
        stalled = r["elapsed"] >= threshold and r["error"] is None
        detail = (f"stalled {r['elapsed']}s vs baseline {base_t}s (threshold {round(threshold,2)}s)"
                  if stalled else f"{r['elapsed']}s, status {r['status']}")
        findings.append(SmuggleFinding(name, r["elapsed"], r["status"], stalled, detail))
    return findings
