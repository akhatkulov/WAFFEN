"""Emit Nuclei v3 *differential* WAF-audit templates from WAFFEN findings.

Each template sends two requests to the same endpoint — a **baseline** (the raw
seed attack the WAF is expected to block) and a **probe** (the bypass payload
WAFFEN found) — and fires only when the baseline is blocked (403/406) but the
probe is let through. That is exactly the block/allow differential WAFFEN's own
verdict uses, turned into a shareable, re-runnable regression test so a team can
confirm a virtual patch closed the gap.

Canary-safe by construction: the payloads are the ones WAFFEN already sent against
an authorized target during the search — this adds no new exploit content, it only
re-frames a found bypass as a pass/fail check. Stdlib-only (hand-built YAML).
"""
from __future__ import annotations

import hashlib
import re
import urllib.parse
from pathlib import Path

_SEV = {
    "SQL Injection": "high", "NoSQL Injection": "high", "XSS Injection": "medium",
    "Command Injection": "critical", "Directory Traversal": "high",
    "File Inclusion": "high", "SSTI": "high", "CRLF Injection": "medium",
    "XXE": "high", "SSRF": "high", "Open Redirect": "low", "LDAP Injection": "high",
    "SSI Injection": "high", "Upload Insecure Files": "high",
}


def _slug(s: str, n: int = 24) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (s or "").lower()).strip("-")
    return s[:n] or "x"


def _tag(attack_class: str) -> str:
    return _slug(attack_class) or "generic"


def _request(method: str, path: str, param: str, value: str, inject: str, marker: str) -> str:
    """One raw HTTP request (lines only) for a Nuclei literal block."""
    path = path or "/"
    if inject in ("body", "json"):
        if inject == "json":
            import json
            body = json.dumps({param: value})
            ctype = "application/json"
        else:
            body = urllib.parse.urlencode({param: value})
            ctype = "application/x-www-form-urlencoded"
        return (f"POST {{{{BaseURL}}}}{path} HTTP/1.1\n"
                f"Host: {{{{Hostname}}}}\n"
                f"Content-Type: {ctype}\n"
                f"X-WAFFEN-Audit: {marker}\n"
                f"\n"
                f"{body}")
    # default: query string
    q = urllib.parse.urlencode({param: value})
    sep = "&" if "?" in path else "?"
    return (f"{method} {{{{BaseURL}}}}{path}{sep}{q} HTTP/1.1\n"
            f"Host: {{{{Hostname}}}}\n"
            f"X-WAFFEN-Audit: {marker}")


def _block(lines: str, indent: str = "        ") -> str:
    return "\n".join(indent + ln for ln in lines.split("\n"))


def build_template(seed: str, payload: str, attack_class: str, chain, *,
                   path: str = "/", param: str = "q", inject: str = "query",
                   method: str = "GET") -> tuple[str, str]:
    """Return (template_id, yaml_text) for one baseline-vs-probe differential."""
    chain = list(chain or [])
    chain_str = " + ".join(chain) if chain else "identity"
    digest = hashlib.sha1(f"{attack_class}|{payload}|{chain_str}".encode()).hexdigest()[:8]
    tid = f"waffen-bypass-{_tag(attack_class)}-{digest}"
    sev = _SEV.get(attack_class, "info")
    baseline_req = _request(method, path, param, seed, inject, "baseline")
    probe_req = _request(method, path, param, payload, inject, "probe")
    yaml = f"""id: {tid}

info:
  name: WAFFEN differential WAF-audit — {attack_class or 'generic'} bypass
  author: waffen
  severity: {sev}
  description: |
    Regression check for a bypass WAFFEN found. Request 1 sends the raw seed (the
    WAF should block it); request 2 sends the WAFFEN mutation [{chain_str}] (it
    should also be blocked once the gap is patched). Fires only if the baseline is
    blocked but the probe passes — i.e. the bypass is still open.
  tags: waf-audit,waffen,{_tag(attack_class)}

http:
  - raw:
      - |
{_block(baseline_req)}

      - |
{_block(probe_req)}

    req-condition: true
    matchers:
      - type: dsl
        name: waf-bypass-still-open
        dsl:
          - "(status_code_1 == 403 || status_code_1 == 406) && (status_code_2 != 403 && status_code_2 != 406 && status_code_2 != 429)"
"""
    return tid, yaml


def render_nuclei(runs, target) -> dict:
    """Build {template_id: yaml} from engine runs (or a (seed, finding) iterable).

    Duck-typed: `runs` items expose `.result.seed`, `.result.findings`, and
    optionally `.transform`; or each item is a `(seed, finding)` pair. `target`
    exposes `.path`, `.param`, `.inject`, `.method`.
    """
    path = getattr(target, "path", "/")
    param = getattr(target, "param", "q")
    inject = getattr(target, "inject", "query")
    method = getattr(target, "method", "GET")
    out: dict[str, str] = {}
    for item in runs:
        if isinstance(item, tuple):
            seed, findings = item[0], [item[1]]
        else:
            seed = item.result.seed
            findings = item.result.findings
        for f in findings:
            tid, yaml = build_template(
                seed, f.payload, getattr(f, "attack_class", ""), getattr(f, "chain", []),
                path=path, param=param, inject=inject, method=method)
            out[tid] = yaml
    return out


def write_nuclei(runs, target, out_dir: str) -> list[str]:
    """Write one <template_id>.yaml per finding into out_dir; return the paths."""
    d = Path(out_dir)
    d.mkdir(parents=True, exist_ok=True)
    paths = []
    for tid, yaml in render_nuclei(runs, target).items():
        p = d / f"{tid}.yaml"
        p.write_text(yaml, encoding="utf-8")
        paths.append(str(p))
    return paths
