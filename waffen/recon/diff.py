"""Differential testing — compare WAF vs origin to disambiguate blocks.

When WAFFEN gets a 403, it's ambiguous: was it the WAF or the app? When it
gets 200, did the payload reach the backend or was it sanitized? Sending the
same payload to both the WAF-fronted endpoint and the bare origin answers
this definitively.

Diagnosis matrix:
  WAF blocks  + origin passes  = WAF_ONLY    (confirmed WAF block)
  WAF passes  + origin blocks  = APP_ONLY    (app-level defense, not WAF)
  both block                   = BOTH_BLOCK  (defense in depth)
  both pass                    = BOTH_PASS   (no defense — potential bypass)
  mismatch (e.g. 500 vs 200)  = DESYNC      (payload handled differently)
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

from ..core.oracle import Oracle, Target, Response, BLOCKED, THROUGH, DOWN


@dataclass
class DiffProbe:
    payload: str
    attack_class: str
    waf_code: str
    waf_verdict: str
    origin_code: str
    origin_verdict: str
    diagnosis: str

    def as_dict(self) -> dict:
        return {
            "payload": self.payload,
            "attack_class": self.attack_class,
            "waf_code": self.waf_code,
            "waf_verdict": self.waf_verdict,
            "origin_code": self.origin_code,
            "origin_verdict": self.origin_verdict,
            "diagnosis": self.diagnosis,
        }


@dataclass
class DiffReport:
    waf_target: str
    origin_target: str
    probes: list[DiffProbe] = field(default_factory=list)

    @property
    def waf_only(self) -> list[DiffProbe]:
        return [p for p in self.probes if p.diagnosis == "WAF_ONLY"]

    @property
    def app_only(self) -> list[DiffProbe]:
        return [p for p in self.probes if p.diagnosis == "APP_ONLY"]

    @property
    def both_block(self) -> list[DiffProbe]:
        return [p for p in self.probes if p.diagnosis == "BOTH_BLOCK"]

    @property
    def both_pass(self) -> list[DiffProbe]:
        return [p for p in self.probes if p.diagnosis == "BOTH_PASS"]

    @property
    def desync(self) -> list[DiffProbe]:
        return [p for p in self.probes if p.diagnosis == "DESYNC"]

    def as_dict(self) -> dict:
        return {
            "waf_target": self.waf_target,
            "origin_target": self.origin_target,
            "total": len(self.probes),
            "waf_only": len(self.waf_only),
            "app_only": len(self.app_only),
            "both_block": len(self.both_block),
            "both_pass": len(self.both_pass),
            "desync": len(self.desync),
            "probes": [p.as_dict() for p in self.probes],
        }


def _diagnose(waf: Response, origin: Response) -> str:
    """Classify the WAF-vs-origin pair into a diagnosis."""
    w_blocked = waf.verdict == BLOCKED
    o_blocked = origin.verdict == BLOCKED

    if waf.verdict == DOWN or origin.verdict == DOWN:
        return "DESYNC"

    if w_blocked and not o_blocked:
        return "WAF_ONLY"
    if not w_blocked and o_blocked:
        return "APP_ONLY"
    if w_blocked and o_blocked:
        return "BOTH_BLOCK"
    if not w_blocked and not o_blocked:
        # Both passed — but check for 5xx on origin (payload reached and broke something)
        if origin.code.startswith("5"):
            return "DESYNC"
        return "BOTH_PASS"

    return "DESYNC"


class DifferentialTester:
    """Send the same payloads to WAF-fronted and bare-origin targets, compare."""

    def __init__(self, waf_target: Target, origin_target: Target,
                 waf_sender=None, origin_sender=None):
        self.waf_oracle = Oracle(waf_target, sender=waf_sender)
        self.origin_oracle = Oracle(origin_target, sender=origin_sender)
        self._waf_url = waf_target.base_url
        self._origin_url = origin_target.base_url

    def probe(self, payload: str, attack_class: str = "") -> DiffProbe:
        """Send one payload to both targets and diagnose."""
        waf_resp = self.waf_oracle.send(payload)
        origin_resp = self.origin_oracle.send(payload)
        diagnosis = _diagnose(waf_resp, origin_resp)
        return DiffProbe(
            payload=payload,
            attack_class=attack_class,
            waf_code=waf_resp.code,
            waf_verdict=waf_resp.verdict,
            origin_code=origin_resp.code,
            origin_verdict=origin_resp.verdict,
            diagnosis=diagnosis,
        )

    def run_payloads(self, payloads: Sequence[tuple[str, str]]) -> DiffReport:
        """Test a list of (class, payload) pairs differentially."""
        report = DiffReport(waf_target=self._waf_url, origin_target=self._origin_url)
        for cls, payload in payloads:
            report.probes.append(self.probe(payload, attack_class=cls))
        return report

    def run_seeds(self, attack_classes: Sequence[str] | None = None) -> DiffReport:
        """Test all KB seeds for the given classes."""
        from ..kb.seeds import seeds_for
        classes = attack_classes or ["SQL Injection"]
        payloads = []
        for cls in classes:
            for p in seeds_for(cls):
                payloads.append((cls, p))
        return self.run_payloads(payloads)

    def run_findings(self, findings_path: str) -> DiffReport:
        """Re-test findings from a JSONL produced by `waffen bypass --out`."""
        report = DiffReport(waf_target=self._waf_url, origin_target=self._origin_url)
        path = Path(findings_path)
        if not path.exists():
            return report
        with path.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                payload = rec.get("payload", "")
                cls = rec.get("attack_class", "")
                if payload:
                    report.probes.append(self.probe(payload, attack_class=cls))
        return report


def write_diff_jsonl(report: DiffReport, path: str) -> None:
    """Write a diff report to JSONL."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w") as f:
        for probe in report.probes:
            f.write(json.dumps(probe.as_dict(), ensure_ascii=False) + "\n")
