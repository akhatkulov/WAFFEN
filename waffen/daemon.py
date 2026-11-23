"""Continuous autonomous WAF assessment daemon.

Runs WAFFEN on a schedule: re-fingerprints, re-calibrates, checks bypass
survival, searches for new bypasses, detects WAF configuration changes,
and alerts via webhook (Slack/Discord/generic).

Usage:
    waffen daemon --target https://target.com --interval 6 --class sqli \
        --profile daemon.json --webhook https://hooks.slack.com/...

The daemon saves state to a profile after each cycle, so it can be
restarted without losing history.
"""
from __future__ import annotations

import json
import time
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Sequence

from .core.oracle import Oracle, Target


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class DaemonConfig:
    target_url: str
    path: str = "/"
    param: str = "q"
    inject: str = "query"
    method: str = "GET"
    interval_hours: float = 6.0
    attack_classes: list[str] = field(default_factory=lambda: ["sqli"])
    max_requests_per_cycle: int = 500
    profile_path: str = ""
    webhook_url: str = ""
    block_signature: str = ""
    timeout: int = 15
    tls_verify: bool = False
    transport: str = "auto"
    extra_headers: tuple = ()
    cookie: str = ""
    alert_on: list[str] = field(
        default_factory=lambda: ["new_bypass", "bypass_fixed", "waf_change"])


@dataclass
class CycleResult:
    timestamp: str
    cycle_number: int
    waf_fingerprint: str = ""
    calibration_confidence: float = 0.0
    new_bypasses: list = field(default_factory=list)
    fixed_bypasses: list = field(default_factory=list)
    still_alive: list = field(default_factory=list)
    all_findings: list = field(default_factory=list)
    waf_changed: bool = False
    requests_used: int = 0

    def as_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "cycle_number": self.cycle_number,
            "waf_fingerprint": self.waf_fingerprint,
            "calibration_confidence": self.calibration_confidence,
            "new_bypasses": len(self.new_bypasses),
            "fixed_bypasses": len(self.fixed_bypasses),
            "still_alive": len(self.still_alive),
            "total_findings": len(self.all_findings),
            "waf_changed": self.waf_changed,
            "requests_used": self.requests_used,
        }


class WAFFENDaemon:
    """Continuous WAF assessment loop."""

    def __init__(self, config: DaemonConfig):
        self.config = config
        self.history: list[CycleResult] = []
        self._last_fingerprint: str = ""
        self._last_confidence: float = 0.0
        self._known_bypasses: list[dict] = []

    def _target(self) -> Target:
        return Target(
            base_url=self.config.target_url,
            path=self.config.path,
            param=self.config.param,
            inject=self.config.inject,
            method=self.config.method,
            timeout=self.config.timeout,
            tls_verify=self.config.tls_verify,
            block_signature=self.config.block_signature,
            extra_headers=self.config.extra_headers,
            cookie=self.config.cookie,
        )

    def _oracle(self) -> Oracle:
        return Oracle(self._target(), transport=self.config.transport)

    # ---- per-cycle steps ---------------------------------------------------

    def _fingerprint(self) -> str:
        try:
            from .recon.fingerprint import fingerprint
            guesses = fingerprint(self._target())
            if guesses:
                return getattr(guesses[0], "name", "unknown")
        except Exception:
            pass
        return "unknown"

    def _calibrate(self) -> float:
        try:
            from .verify.calibrate import calibrate
            oracle = self._oracle()
            cal = calibrate(oracle)
            return getattr(cal, "confidence", 0.0)
        except Exception:
            return 0.0

    def _survival_check(self) -> tuple[list[dict], list[dict]]:
        """Re-test known bypasses. Returns (still_alive, fixed)."""
        if not self._known_bypasses:
            return [], []
        alive, fixed = [], []
        oracle = self._oracle()
        for bp in self._known_bypasses:
            payload = bp.get("payload", "")
            try:
                resp = oracle.send(payload)
                if resp.verdict == "THROUGH":
                    alive.append(bp)
                else:
                    fixed.append(bp)
            except Exception:
                fixed.append(bp)
        return alive, fixed

    def _search(self) -> list[dict]:
        """Quick bypass search with limited budget."""
        from .kb import seeds as kb_seeds
        from .engine import run_bypass

        all_seeds = []
        for cls in self.config.attack_classes:
            for p in kb_seeds.seeds_for(cls):
                all_seeds.append((cls, p))

        if not all_seeds:
            return []

        try:
            runs = run_bypass(
                self._target(), all_seeds,
                strategy="beam",
                max_requests=self.config.max_requests_per_cycle,
                do_calibrate=True,
                do_verify=True,
                transport=self.config.transport,
                stop_on_first=False,
                width=4, depth=3,
            )
        except Exception:
            return []

        findings = []
        for run in runs:
            for f in run.result.findings:
                findings.append({
                    "payload": f.payload,
                    "chain": getattr(f, "chain", []),
                    "attack_class": getattr(f, "attack_class", ""),
                    "verified": getattr(f, "verified", False),
                    "code": getattr(f, "code", ""),
                    "transform": getattr(f, "request_transform", "identity"),
                })
        return findings

    # ---- diff logic --------------------------------------------------------

    def _diff_findings(self, current: list[dict]) -> list[dict]:
        """Findings in current that are not in known_bypasses."""
        known_set = {f.get("payload", "") for f in self._known_bypasses}
        return [f for f in current if f.get("payload", "") not in known_set]

    # ---- the cycle ---------------------------------------------------------

    def run_cycle(self) -> CycleResult:
        """Execute one full assessment cycle."""
        cycle_num = len(self.history) + 1
        result = CycleResult(
            timestamp=_now_iso(),
            cycle_number=cycle_num,
        )

        fp = self._fingerprint()
        result.waf_fingerprint = fp
        if self._last_fingerprint and fp != self._last_fingerprint:
            result.waf_changed = True
        self._last_fingerprint = fp

        conf = self._calibrate()
        result.calibration_confidence = conf
        if (self._last_confidence > 0
                and abs(conf - self._last_confidence) > 0.1):
            result.waf_changed = True
        self._last_confidence = conf

        alive, fixed = self._survival_check()
        result.still_alive = alive
        result.fixed_bypasses = fixed

        findings = self._search()
        result.all_findings = findings
        new = self._diff_findings(findings)
        result.new_bypasses = new

        all_payloads = {f.get("payload", "") for f in alive}
        for f in new:
            all_payloads.add(f.get("payload", ""))
        self._known_bypasses = [
            f for f in (alive + new) if f.get("payload", "") in all_payloads
        ]

        self.history.append(result)

        if self.config.profile_path:
            self._save_profile()

        return result

    # ---- profile persistence -----------------------------------------------

    def _save_profile(self):
        data = {
            "target_url": self.config.target_url,
            "path": self.config.path,
            "param": self.config.param,
            "last_fingerprint": self._last_fingerprint,
            "last_confidence": self._last_confidence,
            "known_bypasses": self._known_bypasses,
            "history": [h.as_dict() for h in self.history],
        }
        try:
            with open(self.config.profile_path, "w") as f:
                json.dump(data, f, indent=2, default=str)
        except Exception:
            pass

    def _load_profile(self):
        if not self.config.profile_path:
            return
        try:
            with open(self.config.profile_path) as f:
                data = json.load(f)
            self._last_fingerprint = data.get("last_fingerprint", "")
            self._last_confidence = data.get("last_confidence", 0.0)
            self._known_bypasses = data.get("known_bypasses", [])
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    # ---- alerting ----------------------------------------------------------

    def _should_alert(self, result: CycleResult) -> bool:
        alerts = self.config.alert_on
        if "new_bypass" in alerts and result.new_bypasses:
            return True
        if "bypass_fixed" in alerts and result.fixed_bypasses:
            return True
        if "waf_change" in alerts and result.waf_changed:
            return True
        return False

    def _send_alert(self, result: CycleResult):
        if not self.config.webhook_url:
            return
        msg = format_alert(result, self.config.target_url)
        payload = json.dumps({"text": msg}).encode()
        req = urllib.request.Request(
            self.config.webhook_url,
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        try:
            urllib.request.urlopen(req, timeout=10)
        except Exception:
            import sys
            print("  [warn] webhook alert failed", file=sys.stderr)

    # ---- logging -----------------------------------------------------------

    def _log_cycle(self, result: CycleResult):
        import sys
        from . import ui
        c = result.cycle_number
        ts = result.timestamp
        fp = result.waf_fingerprint
        conf = result.calibration_confidence

        print(f"\n  {ui.bold(f'[Cycle {c}]')} {ts}")

        waf_note = ""
        if result.waf_changed:
            waf_note = ui.yellow(" — CHANGED")
        print(f"    WAF: {fp} (confidence {conf:.2f}){waf_note}")

        n_alive = len(result.still_alive)
        n_fixed = len(result.fixed_bypasses)
        n_new = len(result.new_bypasses)
        n_total = len(result.all_findings)

        if result.cycle_number == 1:
            print(f"    Search: {n_total} finding(s)")
            print(f"    Status: baseline established")
        else:
            if n_fixed:
                print(f"    Survival: {n_alive}/{n_alive + n_fixed} "
                      f"({n_fixed} FIXED)")
                for bp in result.fixed_bypasses[:3]:
                    p = bp.get("payload", "?")[:40]
                    print(f"      {ui.green('+')} FIXED: {p}")

            if n_new:
                print(f"    {ui.red(f'{n_new} NEW bypass(es)!')}")
                for bp in result.new_bypasses[:3]:
                    p = bp.get("payload", "?")[:40]
                    ch = ",".join(bp.get("chain", []))[:20]
                    print(f"      {ui.red('!')} NEW: {p}"
                          + (f" via {ch}" if ch else ""))
            elif not n_fixed:
                print(f"    Search: {n_total} finding(s), no changes")

        if self._should_alert(result):
            self._send_alert(result)
            print(f"    Alert sent {ui.green('OK')}")

    # ---- main loop ---------------------------------------------------------

    def run(self, max_cycles: int = 0):
        """Run the daemon loop. max_cycles=0 → infinite."""
        from . import ui
        self._load_profile()

        print(f"\n  {ui.bold('WAFFEN daemon started')}: "
              f"{self.config.target_url}")
        print(f"  Interval: {self.config.interval_hours}h, "
              f"classes: {self.config.attack_classes}")
        if self.config.webhook_url:
            print(f"  Webhook: {self.config.webhook_url[:50]}...")
        if self.config.profile_path:
            print(f"  Profile: {self.config.profile_path}")
            if self._known_bypasses:
                print(f"  Resumed: {len(self._known_bypasses)} "
                      f"known bypass(es) from profile")
        print(ui.rule())

        cycle = 0
        while True:
            cycle += 1
            result = self.run_cycle()
            self._log_cycle(result)

            if max_cycles and cycle >= max_cycles:
                break
            _interruptible_sleep(self.config.interval_hours * 3600)


# ---- public helpers --------------------------------------------------------

def format_alert(result: CycleResult, target: str) -> str:
    """Format a Slack-compatible alert message."""
    lines = [f"*WAFFEN Alert* — {result.timestamp}"]
    lines.append(f"Target: {target}")

    if result.new_bypasses:
        lines.append(
            f"*{len(result.new_bypasses)} NEW BYPASS(ES) FOUND*")
        for b in result.new_bypasses[:3]:
            p = b.get("payload", "?")[:50]
            lines.append(f"  `{p}`")

    if result.fixed_bypasses:
        lines.append(
            f"{len(result.fixed_bypasses)} bypass(es) FIXED by WAF team")

    if result.waf_changed:
        lines.append("WAF configuration CHANGED (fingerprint differs)")

    lines.append(f"Still alive: {len(result.still_alive)} bypass(es)")
    return "\n".join(lines)


def _interruptible_sleep(seconds: float):
    """Sleep in 1-minute chunks so KeyboardInterrupt lands quickly."""
    end = time.time() + seconds
    while time.time() < end:
        time.sleep(min(60.0, end - time.time()))
