"""WAF bypass regression watch — re-test saved findings and track what still works.

A bypass's half-life against an active WAF team can be hours. `waffen watch`
re-sends each discovered bypass and reports which are still alive, which got
patched, and which flipped since the last check.

Usage:
    waffen watch --findings results.jsonl --target https://target.com --once
    waffen watch --findings results.jsonl --target https://target.com --interval 3600 --rounds 24
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .core.oracle import Oracle, Target, Response
from .core import transforms as T


@dataclass
class WatchEntry:
    payload: str
    transform: str
    attack_class: str
    chain: list[str]
    original_verdict: str
    current_verdict: str   # ALIVE | BLOCKED | ERROR
    response_code: str
    timestamp: str

    def as_dict(self) -> dict:
        return {
            "payload": self.payload,
            "transform": self.transform,
            "attack_class": self.attack_class,
            "chain": self.chain,
            "original_verdict": self.original_verdict,
            "current_verdict": self.current_verdict,
            "response_code": self.response_code,
            "timestamp": self.timestamp,
        }


@dataclass
class WatchReport:
    target: str
    round_num: int
    timestamp: str
    entries: list[WatchEntry] = field(default_factory=list)

    @property
    def alive(self) -> int:
        return sum(1 for e in self.entries if e.current_verdict == "ALIVE")

    @property
    def blocked(self) -> int:
        return sum(1 for e in self.entries if e.current_verdict == "BLOCKED")

    @property
    def errored(self) -> int:
        return sum(1 for e in self.entries if e.current_verdict == "ERROR")

    def as_dict(self) -> dict:
        return {
            "target": self.target,
            "round": self.round_num,
            "timestamp": self.timestamp,
            "alive": self.alive,
            "blocked": self.blocked,
            "errored": self.errored,
            "entries": [e.as_dict() for e in self.entries],
        }


@dataclass
class WatchDiff:
    newly_blocked: list[WatchEntry] = field(default_factory=list)
    newly_alive: list[WatchEntry] = field(default_factory=list)
    unchanged: int = 0


@dataclass
class SavedFinding:
    payload: str
    attack_class: str
    chain: list[str]
    transform: str
    http_code: str


def load_findings(path: str) -> list[SavedFinding]:
    """Load findings from a JSONL file produced by `waffen bypass --out`."""
    findings = []
    seen = set()
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        payload = rec.get("payload", "")
        transform = rec.get("request_transform", "identity")
        key = (payload, transform)
        if key in seen:
            continue
        seen.add(key)
        findings.append(SavedFinding(
            payload=payload,
            attack_class=rec.get("attack_class", ""),
            chain=rec.get("chain", []),
            transform=transform,
            http_code=rec.get("http_code", ""),
        ))
    return findings


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class WatchRunner:
    """Re-test saved bypass findings against a live target."""

    def __init__(self, target: Target, *, sender=None, transport: str = "curl"):
        self.target = target
        self._sender = sender
        self._transport = transport

    def _make_oracle(self, transform_name: str) -> Oracle:
        rt = None
        if transform_name and transform_name != "identity":
            try:
                rt = T.get(transform_name)
            except KeyError:
                pass
        return Oracle(self.target, sender=self._sender,
                      request_transform=rt, transport=self._transport)

    def retest(self, findings: list[SavedFinding], round_num: int = 1) -> WatchReport:
        """Re-send each finding and classify ALIVE/BLOCKED/ERROR."""
        report = WatchReport(
            target=self.target.url(),
            round_num=round_num,
            timestamp=_now_iso(),
        )

        for f in findings:
            oracle = self._make_oracle(f.transform)
            try:
                resp = oracle.send(f.payload)
                if resp.verdict == "THROUGH":
                    verdict = "ALIVE"
                elif resp.verdict == "BLOCKED":
                    verdict = "BLOCKED"
                else:
                    verdict = "ERROR"
                code = resp.code
            except Exception:
                verdict = "ERROR"
                code = "000"

            report.entries.append(WatchEntry(
                payload=f.payload,
                transform=f.transform,
                attack_class=f.attack_class,
                chain=f.chain,
                original_verdict="THROUGH",
                current_verdict=verdict,
                response_code=code,
                timestamp=report.timestamp,
            ))

        return report

    @staticmethod
    def diff_report(prev: Optional[WatchReport], current: WatchReport) -> WatchDiff:
        """Compare two reports to find what changed."""
        if prev is None:
            return WatchDiff(unchanged=len(current.entries))

        prev_map = {(e.payload, e.transform): e.current_verdict for e in prev.entries}
        diff = WatchDiff()

        for e in current.entries:
            key = (e.payload, e.transform)
            old_verdict = prev_map.get(key)
            if old_verdict is None:
                diff.unchanged += 1
            elif old_verdict != e.current_verdict:
                if e.current_verdict == "BLOCKED":
                    diff.newly_blocked.append(e)
                elif e.current_verdict == "ALIVE":
                    diff.newly_alive.append(e)
                else:
                    diff.unchanged += 1
            else:
                diff.unchanged += 1

        return diff

    def run_loop(self, findings: list[SavedFinding], *,
                 interval: int = 3600, max_rounds: int = 0,
                 printer=None) -> list[WatchReport]:
        """Retest in a loop. max_rounds=0 means infinite (until KeyboardInterrupt)."""
        reports: list[WatchReport] = []
        prev: Optional[WatchReport] = None
        round_num = 0

        try:
            while True:
                round_num += 1
                if max_rounds > 0 and round_num > max_rounds:
                    break

                report = self.retest(findings, round_num=round_num)
                diff = self.diff_report(prev, report)
                reports.append(report)

                if printer:
                    printer(report, diff, max_rounds)

                prev = report

                if max_rounds > 0 and round_num >= max_rounds:
                    break
                time.sleep(interval)
        except KeyboardInterrupt:
            pass

        return reports


def write_watch_jsonl(reports: list[WatchReport], path: str) -> None:
    """Write watch reports as JSONL."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w") as f:
        for r in reports:
            f.write(json.dumps(r.as_dict(), ensure_ascii=False) + "\n")
