"""GraphQL introspection probing — schema discovery and bypass techniques."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional

from ..core.oracle import Target

_FULL_INTROSPECTION = """{
  __schema {
    queryType { name }
    mutationType { name }
    types { name kind fields { name type { name kind ofType { name kind } } } }
  }
}"""

_PARTIAL_TYPE = """{ __type(name: "%s") { name fields { name type { name } } } }"""

_TYPENAME = "{ __typename }"


@dataclass
class IntrospectionResult:
    success: bool = False
    schema: dict | None = None
    method: str = ""
    types: list[str] = field(default_factory=list)
    bypass_used: str = ""


def _send_graphql(target: Target, query: str, *, method: str = "POST",
                  content_type: str = "application/json",
                  sender=None) -> tuple[str, str]:
    """Send a GraphQL query and return (status_code, response_body)."""
    import subprocess
    url = target.url()
    body = json.dumps({"query": query})

    cmd = ["curl", target.curl_sec(), "-m", str(target.timeout),
           "-w", "\n%{http_code}", "-A", target.user_agent]

    if method == "GET":
        import urllib.parse
        sep = "&" if "?" in url else "?"
        cmd += ["-X", "GET", f"{url}{sep}query={urllib.parse.quote(query)}"]
    else:
        cmd += ["-X", method, url, "-H", f"Content-Type: {content_type}",
                "-d", body]

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


def introspect(target: Target, sender=None) -> IntrospectionResult:
    """Send full introspection query. Return schema if exposed."""
    code, body = _send_graphql(target, _FULL_INTROSPECTION, sender=sender)
    if code.startswith("2") and "__schema" in body:
        try:
            data = json.loads(body)
            schema = data.get("data", {}).get("__schema", {})
            types = [t["name"] for t in schema.get("types", [])
                     if not t["name"].startswith("__")]
            return IntrospectionResult(
                success=True, schema=schema, method="POST",
                types=types, bypass_used="direct")
        except (json.JSONDecodeError, KeyError):
            pass
    return IntrospectionResult()


def probe_introspection_bypass(target: Target, sender=None) -> list[IntrospectionResult]:
    """Try multiple techniques to bypass introspection blocking."""
    results: list[IntrospectionResult] = []

    techniques = [
        ("GET method", {"method": "GET"}),
        ("POST application/graphql", {"content_type": "application/graphql"}),
        ("aliased __schema",
         {"query": "{ schema: __schema { queryType { name } types { name } } }"}),
        ("partial __type",
         {"query": _PARTIAL_TYPE % "Query"}),
        ("__typename only",
         {"query": _TYPENAME}),
        ("case variation __Schema",
         {"query": "{ __Schema { queryType { name } } }"}),
        ("GET with operationName",
         {"method": "GET",
          "query": "query IntrospectionQuery " + _FULL_INTROSPECTION}),
    ]

    for name, kwargs in techniques:
        query = kwargs.pop("query", _FULL_INTROSPECTION)
        method = kwargs.pop("method", "POST")
        ct = kwargs.pop("content_type", "application/json")
        code, body = _send_graphql(target, query, method=method,
                                   content_type=ct, sender=sender)
        success = code.startswith("2") and ("__schema" in body or "__type" in body
                                            or "__typename" in body)
        r = IntrospectionResult(success=success, method=method, bypass_used=name)
        if success:
            try:
                data = json.loads(body)
                r.schema = data.get("data", {})
                types_raw = (r.schema.get("__schema", {}).get("types", [])
                             if "__schema" in (r.schema or {}) else [])
                r.types = [t["name"] for t in types_raw
                           if not t.get("name", "").startswith("__")]
            except Exception:
                pass
        results.append(r)

    return results
