"""SARIF 2.1.0 reporter — findings as GitHub Security tab entries."""
from __future__ import annotations

import json
from typing import Sequence

from .. import __version__

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_RULE_INDEX: dict[str, int] = {}


def _rule_id(attack_class: str) -> str:
    return f"waffen/{attack_class.lower().replace(' ', '-')}" if attack_class else "waffen/unknown"


def _severity(verified: bool | None) -> str:
    if verified is True:
        return "error"
    if verified is False:
        return "note"
    return "warning"


def _build_rules(findings) -> list[dict]:
    rules = []
    seen: set[str] = {}
    _RULE_INDEX.clear()
    for f in findings:
        rid = _rule_id(_cls(f))
        if rid not in seen:
            seen[rid] = len(rules)
            _RULE_INDEX[rid] = len(rules)
            rules.append({
                "id": rid,
                "shortDescription": {"text": f"WAF bypass via {_cls(f) or 'unknown class'}"},
                "helpUri": "https://github.com/akhatkulov/WAFFEN",
                "defaultConfiguration": {"level": "error"},
            })
        else:
            _RULE_INDEX[rid] = seen[rid]
    return rules


def _cls(f) -> str:
    if isinstance(f, dict):
        return f.get("attack_class", "")
    return getattr(f, "attack_class", "")


def _payload(f) -> str:
    if isinstance(f, dict):
        return f.get("payload", "")
    return getattr(f, "payload", "")


def _chain(f) -> list:
    if isinstance(f, dict):
        return f.get("chain", [])
    return getattr(f, "chain", [])


def _verified(f):
    if isinstance(f, dict):
        v = f.get("verified_exploitable")
        if v is None:
            v = f.get("verified")
        return v
    return getattr(f, "verified", None)


def _result(f, target: str) -> dict:
    rid = _rule_id(_cls(f))
    payload = _payload(f)
    chain = _chain(f)
    v = _verified(f)

    msg_parts = [f"WAF bypass: {payload[:80]}"]
    if chain:
        msg_parts.append(f"Chain: {' → '.join(chain)}")
    if v is True:
        msg_parts.append("Status: VERIFIED EXPLOITABLE")
    elif v is False:
        msg_parts.append("Status: through but not exploitable")
    else:
        msg_parts.append("Status: unverified")

    return {
        "ruleId": rid,
        "ruleIndex": _RULE_INDEX.get(rid, 0),
        "level": _severity(v),
        "message": {"text": "\n".join(msg_parts)},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": target},
            }
        }],
    }


def findings_to_sarif(findings: Sequence, target: str) -> dict:
    """Convert WAFFEN findings to SARIF 2.1.0 format."""
    rules = _build_rules(findings)
    results = [_result(f, target) for f in findings]

    return {
        "$schema": _SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "WAFFEN",
                    "semanticVersion": __version__,
                    "informationUri": "https://github.com/akhatkulov/WAFFEN",
                    "rules": rules,
                }
            },
            "results": results,
        }],
    }


def write_sarif(findings: Sequence, target: str, path: str) -> str:
    """Write SARIF JSON to *path* and return the path."""
    data = findings_to_sarif(findings, target)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    return path
