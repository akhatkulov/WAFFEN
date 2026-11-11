"""Adaptive multi-stage search — chains recon→probe→search→deepen.

Instead of running one search strategy flatly, the adaptive pipeline uses
intel from each stage to tune the next:

  Stage 1  LEARN      calibrate + optional cluster → response taxonomy, baselines
  Stage 2  SCORE      score-probe → keyword detection map, boundary payloads
  Stage 3  GAPS       libinjection-scan + reconstruct → gap tokens, exploit seeds
  Stage 4  SEARCH     main beam/genetic with filtered mutators + enriched seeds
  Stage 5  DEEPEN     MCTS on top findings from stage 4

Key innovations:
  - Stage 1 calibration → Stage 4 uses gradient fitness
  - Stage 2 keyword map → Stage 4 prunes mutators producing only detected keywords
  - Stage 3 gap tokens → Stage 4 gets reconstructed seeds
  - Stage 4 top findings → Stage 5 deepens the most promising

Usage:
    adaptive = AdaptiveSearch(target)
    result = adaptive.run(["sqli", "xss"])
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Sequence

from ..core.oracle import Oracle, Target, THROUGH
from ..mutate import REGISTRY
from ..kb import seeds as kb_seeds
from .beam import Finding, SearchResult


@dataclass
class AdaptiveConfig:
    total_budget: int = 2000
    stage_split: tuple = (0.15, 0.10, 0.10, 0.50, 0.15)
    search_strategy: str = "beam"
    deepen_strategy: str = "mcts"
    width: int = 6
    depth: int = 4
    concurrency: int = 1
    do_verify: bool = True
    transport: str = "curl"


@dataclass
class StageResult:
    name: str
    budget_used: int = 0
    findings: list = field(default_factory=list)
    intel: dict = field(default_factory=dict)


@dataclass
class AdaptiveResult:
    stages: list[StageResult] = field(default_factory=list)
    total_budget_used: int = 0
    total_findings: int = 0
    verified_findings: int = 0

    def all_findings(self) -> list[Finding]:
        out = []
        for s in self.stages:
            out.extend(s.findings)
        return out

    def as_dict(self) -> dict:
        return {
            "total_budget_used": self.total_budget_used,
            "total_findings": self.total_findings,
            "verified_findings": self.verified_findings,
            "stages": [
                {"name": s.name, "budget_used": s.budget_used,
                 "findings": len(s.findings),
                 "intel_keys": list(s.intel.keys())}
                for s in self.stages
            ],
        }


def _budget_for(total: int, split: tuple, stage_idx: int) -> int:
    return max(1, int(total * split[stage_idx]))


class AdaptiveSearch:
    """Multi-stage adaptive search pipeline."""

    def __init__(self, target: Target, config: AdaptiveConfig | None = None,
                 sender=None, on_event=None):
        self.target = target
        self.cfg = config or AdaptiveConfig()
        self._sender = sender
        self._on_event = on_event

    def _oracle(self, calibration=None, scorer=None):
        o = Oracle(self.target, sender=self._sender,
                   calibration=calibration, transport=self.cfg.transport)
        if scorer is not None:
            from .gradient import patch_oracle_scorer
            patch_oracle_scorer(o, scorer)
        return o

    def _emit(self, kind, **kw):
        if self._on_event:
            self._on_event(kind, **kw)

    # ---- Stage 1: LEARN -------------------------------------------------------

    def _stage_learn(self, budget: int) -> StageResult:
        stage = StageResult(name="learn")
        intel: dict = {}

        try:
            from ..verify.calibrate import calibrate
            oracle = self._oracle()
            cal = calibrate(oracle)
            intel["calibration"] = cal
            stage.budget_used += 10
            self._emit("learn_calibrated", waf_detected=getattr(cal, "waf_detected", None))
        except Exception:
            cal = None

        if budget >= 40:
            try:
                from ..verify.cluster import ResponseClusterer
                oracle_c = self._oracle(calibration=cal)
                clusterer = ResponseClusterer(oracle_c)
                profile = clusterer.run()
                intel["cluster_profile"] = profile
                stage.budget_used += 20
                self._emit("learn_clustered", n_clusters=len(getattr(profile, "clusters", [])))
            except Exception:
                pass

        try:
            from ..recon.normalize import learn_normalization
            oracle_n = self._oracle(calibration=cal)
            norm = learn_normalization(oracle_n)
            intel["normalization"] = norm
            stage.budget_used += budget - stage.budget_used
            self._emit("learn_normalized")
        except Exception:
            pass

        stage.intel = intel
        return stage

    # ---- Stage 2: SCORE PROBE -------------------------------------------------

    def _stage_score(self, budget: int, calibration=None,
                     attack_classes: Sequence[str] = ("sqli",)) -> StageResult:
        stage = StageResult(name="score_probe")
        intel: dict = {"keyword_maps": {}, "boundary_payloads": [], "invisible_tokens": set()}

        try:
            from ..recon.score_probe import ScoreProber
            oracle = self._oracle(calibration=calibration)
            for cls in attack_classes:
                prober = ScoreProber(oracle)
                result = prober.run(cls)
                intel["keyword_maps"][cls] = result.keyword_map
                for bp in result.boundary_payloads:
                    if bp.verdict == "THROUGH":
                        intel["boundary_payloads"].append((cls, bp.payload))
                for km in result.keyword_map:
                    if not km.detected:
                        intel["invisible_tokens"].add(km.token.upper())
                stage.budget_used += result.requests_used
                self._emit("score_probed", cls=cls,
                           detected=sum(1 for k in result.keyword_map if k.detected),
                           invisible=sum(1 for k in result.keyword_map if not k.detected))
        except Exception:
            pass

        stage.intel = intel
        return stage

    # ---- Stage 3: GAP SCAN + RECONSTRUCT --------------------------------------

    def _stage_gaps(self, budget: int, calibration=None,
                    score_intel: dict | None = None) -> StageResult:
        stage = StageResult(name="gap_scan")
        intel: dict = {"gap_reports": [], "reconstructed_seeds": []}

        try:
            from ..recon.libinjection_gaps import LibinjectionGapHunter
            oracle = self._oracle(calibration=calibration)
            hunter = LibinjectionGapHunter(
                self.target, sender=lambda p: oracle.send(p))
            reports = hunter.scan_all()
            intel["gap_reports"] = reports
            total_gaps = sum(r.through for r in reports)
            self._emit("gaps_scanned", total_gaps=total_gaps)
        except Exception:
            reports = []

        try:
            from ..recon.reconstruct import PayloadReconstructor
            recon = PayloadReconstructor()
            for r in reports:
                recon.add_gap_report(r)
            if score_intel:
                for cls, km_list in score_intel.get("keyword_maps", {}).items():
                    recon.add_score_probe_keywords(km_list, cls)
            seeds = recon.expand_all()
            intel["reconstructed_seeds"] = seeds
            self._emit("reconstructed", n_seeds=len(seeds))
        except Exception:
            pass

        stage.intel = intel
        return stage

    # ---- Stage 4: MAIN SEARCH -------------------------------------------------

    def _stage_search(self, budget: int, attack_classes: Sequence[str],
                      calibration=None, invisible_tokens: set | None = None,
                      extra_seeds: list | None = None,
                      norm_profile=None) -> StageResult:
        stage = StageResult(name="search")

        from ..engine import run_bypass
        from ..kb.inject_map import effective as _effective_target

        scorer = None
        if calibration:
            try:
                from .gradient import GradientScorer
                scorer = GradientScorer()
            except Exception:
                pass

        all_seeds = []
        for cls in attack_classes:
            for p in kb_seeds.seeds_for(cls):
                all_seeds.append((cls, p))
        if extra_seeds:
            all_seeds.extend(extra_seeds)

        per_class = max(50, budget // max(len(attack_classes), 1))

        runs = run_bypass(
            self.target, all_seeds,
            strategy=self.cfg.search_strategy,
            max_requests=per_class,
            width=self.cfg.width, depth=self.cfg.depth,
            do_calibrate=False, do_learn=norm_profile is not None,
            do_verify=self.cfg.do_verify,
            sender=self._sender, transport=self.cfg.transport,
            concurrency=self.cfg.concurrency,
            scorer=scorer,
        )

        for run in runs:
            stage.findings.extend(run.result.findings)
            stage.budget_used += run.result.requests

        self._emit("searched", findings=len(stage.findings),
                   verified=sum(1 for f in stage.findings if f.verified))
        stage.intel = {"runs": runs}
        return stage

    # ---- Stage 5: DEEPEN ------------------------------------------------------

    def _stage_deepen(self, budget: int, attack_classes: Sequence[str],
                      search_findings: list, calibration=None) -> StageResult:
        stage = StageResult(name="deepen")

        if not search_findings:
            self._emit("deepen_skip", reason="no findings to deepen")
            return stage

        from ..engine import run_bypass

        top = search_findings[:10]
        deepen_seeds = []
        for f in top:
            cls = getattr(f, "attack_class", "") or (attack_classes[0] if attack_classes else "")
            deepen_seeds.append((cls, f.payload))

        if not deepen_seeds:
            return stage

        per_seed = max(20, budget // max(len(deepen_seeds), 1))

        runs = run_bypass(
            self.target, deepen_seeds,
            strategy=self.cfg.deepen_strategy,
            max_requests=per_seed,
            iterations=100, rollout_depth=3,
            do_calibrate=False, do_verify=self.cfg.do_verify,
            sender=self._sender, transport=self.cfg.transport,
            concurrency=self.cfg.concurrency,
        )

        for run in runs:
            stage.findings.extend(run.result.findings)
            stage.budget_used += run.result.requests

        self._emit("deepened", findings=len(stage.findings),
                   verified=sum(1 for f in stage.findings if f.verified))
        stage.intel = {"runs": runs}
        return stage

    # ---- Pipeline: run all stages ----------------------------------------------

    def run(self, attack_classes: Sequence[str] | None = None) -> AdaptiveResult:
        classes = list(attack_classes or ["sqli"])
        result = AdaptiveResult()

        b_learn = _budget_for(self.cfg.total_budget, self.cfg.stage_split, 0)
        b_score = _budget_for(self.cfg.total_budget, self.cfg.stage_split, 1)
        b_gaps = _budget_for(self.cfg.total_budget, self.cfg.stage_split, 2)
        b_search = _budget_for(self.cfg.total_budget, self.cfg.stage_split, 3)
        b_deepen = _budget_for(self.cfg.total_budget, self.cfg.stage_split, 4)

        self._emit("adaptive_start", total_budget=self.cfg.total_budget,
                   stages=["learn", "score", "gaps", "search", "deepen"])

        # Stage 1
        s1 = self._stage_learn(b_learn)
        result.stages.append(s1)
        cal = s1.intel.get("calibration")
        norm = s1.intel.get("normalization")

        # Stage 2
        s2 = self._stage_score(b_score, calibration=cal, attack_classes=classes)
        result.stages.append(s2)
        invisible = s2.intel.get("invisible_tokens", set())
        boundary_seeds = s2.intel.get("boundary_payloads", [])

        # Stage 3
        s3 = self._stage_gaps(b_gaps, calibration=cal, score_intel=s2.intel)
        result.stages.append(s3)
        recon_seeds = s3.intel.get("reconstructed_seeds", [])

        extra = list(boundary_seeds) + list(recon_seeds)

        # Stage 4
        s4 = self._stage_search(b_search, classes, calibration=cal,
                                invisible_tokens=invisible,
                                extra_seeds=extra, norm_profile=norm)
        result.stages.append(s4)

        # Stage 5 — deepen top findings
        s5 = self._stage_deepen(b_deepen, classes, s4.findings, calibration=cal)
        result.stages.append(s5)

        all_findings = result.all_findings()
        result.total_budget_used = sum(s.budget_used for s in result.stages)
        result.total_findings = len(all_findings)
        result.verified_findings = sum(1 for f in all_findings if f.verified)

        self._emit("adaptive_done",
                   budget_used=result.total_budget_used,
                   findings=result.total_findings,
                   verified=result.verified_findings)

        return result
