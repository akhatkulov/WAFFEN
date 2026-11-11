"""Tests for the adaptive multi-stage search pipeline."""
from __future__ import annotations

from unittest.mock import MagicMock, patch
import pytest

from waffen.search.adaptive import (
    AdaptiveConfig, AdaptiveSearch, AdaptiveResult, StageResult, _budget_for,
)
from waffen.core.oracle import Target


def _target():
    return Target(base_url="https://test.local", path="/search", param="q")


# ---- budget splitting -------------------------------------------------------

class TestBudgetSplit:
    def test_default_split(self):
        split = (0.15, 0.10, 0.10, 0.50, 0.15)
        assert _budget_for(2000, split, 0) == 300   # learn
        assert _budget_for(2000, split, 1) == 200   # score
        assert _budget_for(2000, split, 2) == 200   # gaps
        assert _budget_for(2000, split, 3) == 1000  # search
        assert _budget_for(2000, split, 4) == 300   # deepen

    def test_small_budget_floors_at_1(self):
        split = (0.15, 0.10, 0.10, 0.50, 0.15)
        assert _budget_for(5, split, 1) == 1

    def test_total_sums_close(self):
        split = (0.15, 0.10, 0.10, 0.50, 0.15)
        total = 2000
        parts = [_budget_for(total, split, i) for i in range(5)]
        assert sum(parts) <= total + 5  # rounding tolerance


# ---- config ------------------------------------------------------------------

class TestAdaptiveConfig:
    def test_defaults(self):
        cfg = AdaptiveConfig()
        assert cfg.total_budget == 2000
        assert cfg.search_strategy == "beam"
        assert cfg.deepen_strategy == "mcts"
        assert len(cfg.stage_split) == 5

    def test_custom(self):
        cfg = AdaptiveConfig(total_budget=500, search_strategy="genetic")
        assert cfg.total_budget == 500
        assert cfg.search_strategy == "genetic"


# ---- result ------------------------------------------------------------------

class TestAdaptiveResult:
    def test_empty_result(self):
        r = AdaptiveResult()
        assert r.total_findings == 0
        assert r.all_findings() == []

    def test_as_dict(self):
        r = AdaptiveResult(
            stages=[StageResult(name="test", budget_used=10)],
            total_budget_used=10, total_findings=0,
        )
        d = r.as_dict()
        assert d["total_budget_used"] == 10
        assert len(d["stages"]) == 1
        assert d["stages"][0]["name"] == "test"

    def test_all_findings_merges(self):
        f1 = MagicMock(verified=True)
        f2 = MagicMock(verified=False)
        r = AdaptiveResult(stages=[
            StageResult(name="a", findings=[f1]),
            StageResult(name="b", findings=[f2]),
        ])
        assert len(r.all_findings()) == 2


# ---- stage isolation ---------------------------------------------------------

class TestStageLearn:
    def test_learn_handles_import_failure(self):
        """Stage 1 must not crash even if calibrate module is missing."""
        target = _target()
        search = AdaptiveSearch(target, AdaptiveConfig(total_budget=100))
        # Patch calibrate to fail
        with patch("waffen.search.adaptive.Oracle") as mock_oracle_cls:
            mock_oracle_cls.return_value = MagicMock()
            with patch.dict("sys.modules", {"waffen.verify.calibrate": None}):
                stage = search._stage_learn(15)
        assert stage.name == "learn"
        # Should not crash — just empty intel
        assert isinstance(stage.intel, dict)

    def test_learn_returns_stage_result(self):
        target = _target()
        search = AdaptiveSearch(target, AdaptiveConfig(total_budget=100))
        with patch("waffen.search.adaptive.Oracle") as mock_cls:
            mock_oracle = MagicMock()
            mock_cls.return_value = mock_oracle
            with patch("waffen.verify.calibrate.calibrate") as mock_cal:
                mock_cal.return_value = MagicMock(waf_detected=True, confidence=0.9,
                                                   signature="test", timing_reliable=False)
                stage = search._stage_learn(15)
        assert stage.name == "learn"
        assert "calibration" in stage.intel


class TestStageScore:
    def test_score_empty_on_failure(self):
        target = _target()
        search = AdaptiveSearch(target, AdaptiveConfig(total_budget=100))
        with patch("waffen.recon.score_probe.ScoreProber") as mock_prober_cls:
            mock_prober_cls.side_effect = Exception("fail")
            stage = search._stage_score(20, attack_classes=["sqli"])
        assert stage.name == "score_probe"
        assert stage.intel["keyword_maps"] == {}


class TestStageGaps:
    def test_gaps_empty_on_failure(self):
        target = _target()
        search = AdaptiveSearch(target, AdaptiveConfig(total_budget=100))
        with patch("waffen.recon.libinjection_gaps.LibinjectionGapHunter") as mock:
            mock.side_effect = Exception("fail")
            stage = search._stage_gaps(20)
        assert stage.name == "gap_scan"
        assert stage.intel["gap_reports"] == []


class TestStageSearch:
    def test_search_calls_run_bypass(self):
        target = _target()
        search = AdaptiveSearch(target, AdaptiveConfig(total_budget=100))
        mock_result = MagicMock()
        mock_result.findings = []
        mock_result.requests = 10
        mock_run = MagicMock()
        mock_run.result = mock_result
        with patch("waffen.engine.run_bypass", return_value=[mock_run]) as mock_rb:
            stage = search._stage_search(50, ["sqli"])
        assert mock_rb.called
        assert stage.name == "search"


class TestStageDeepen:
    def test_deepen_skips_empty(self):
        target = _target()
        search = AdaptiveSearch(target, AdaptiveConfig(total_budget=100))
        stage = search._stage_deepen(15, ["sqli"], [])
        assert stage.name == "deepen"
        assert len(stage.findings) == 0

    def test_deepen_with_findings(self):
        target = _target()
        search = AdaptiveSearch(target, AdaptiveConfig(total_budget=100))
        mock_finding = MagicMock(payload="' OR 1=1--", attack_class="sqli", verified=True)
        mock_result = MagicMock()
        mock_result.findings = []
        mock_result.requests = 5
        mock_run = MagicMock()
        mock_run.result = mock_result
        with patch("waffen.engine.run_bypass", return_value=[mock_run]):
            stage = search._stage_deepen(15, ["sqli"], [mock_finding])
        assert stage.name == "deepen"


# ---- full pipeline -----------------------------------------------------------

class TestFullPipeline:
    def test_run_returns_adaptive_result(self):
        target = _target()
        search = AdaptiveSearch(target, AdaptiveConfig(total_budget=200))

        # Mock all external dependencies
        mock_result = MagicMock()
        mock_result.findings = []
        mock_result.requests = 5
        mock_run = MagicMock()
        mock_run.result = mock_result

        with patch("waffen.search.adaptive.Oracle"):
            with patch("waffen.verify.calibrate.calibrate",
                       return_value=MagicMock(waf_detected=True, confidence=0.9,
                                              signature="x", timing_reliable=False)):
                with patch("waffen.recon.score_probe.ScoreProber") as mock_sp:
                    mock_sp_inst = MagicMock()
                    mock_sp_inst.run.return_value = MagicMock(
                        keyword_map=[], boundary_payloads=[], requests_used=5,
                        attack_class="sqli", flip_index=-1, strip_chain=[],
                    )
                    mock_sp.return_value = mock_sp_inst
                    with patch("waffen.recon.libinjection_gaps.LibinjectionGapHunter") as mock_lh:
                        mock_lh_inst = MagicMock()
                        mock_lh_inst.scan_all.return_value = []
                        mock_lh.return_value = mock_lh_inst
                        with patch("waffen.engine.run_bypass",
                                   return_value=[mock_run]):
                            result = search.run(["sqli"])

        assert isinstance(result, AdaptiveResult)
        assert len(result.stages) == 5
        assert result.stages[0].name == "learn"
        assert result.stages[1].name == "score_probe"
        assert result.stages[2].name == "gap_scan"
        assert result.stages[3].name == "search"
        assert result.stages[4].name == "deepen"

    def test_events_emitted(self):
        target = _target()
        events = []
        search = AdaptiveSearch(
            target, AdaptiveConfig(total_budget=200),
            on_event=lambda kind, **kw: events.append(kind),
        )

        mock_result = MagicMock()
        mock_result.findings = []
        mock_result.requests = 5
        mock_run = MagicMock()
        mock_run.result = mock_result

        with patch("waffen.search.adaptive.Oracle"):
            with patch("waffen.verify.calibrate.calibrate",
                       return_value=MagicMock(waf_detected=True, confidence=0.9,
                                              signature="x", timing_reliable=False)):
                with patch("waffen.recon.score_probe.ScoreProber") as mock_sp:
                    mock_sp_inst = MagicMock()
                    mock_sp_inst.run.return_value = MagicMock(
                        keyword_map=[], boundary_payloads=[], requests_used=5,
                        attack_class="sqli", flip_index=-1, strip_chain=[],
                    )
                    mock_sp.return_value = mock_sp_inst
                    with patch("waffen.recon.libinjection_gaps.LibinjectionGapHunter") as mock_lh:
                        mock_lh_inst = MagicMock()
                        mock_lh_inst.scan_all.return_value = []
                        mock_lh.return_value = mock_lh_inst
                        with patch("waffen.engine.run_bypass",
                                   return_value=[mock_run]):
                            search.run(["sqli"])

        assert "adaptive_start" in events
        assert "adaptive_done" in events


class TestMutatorFiltering:
    def test_invisible_tokens_collected(self):
        """Score probe stage should collect invisible tokens into intel."""
        target = _target()
        search = AdaptiveSearch(target, AdaptiveConfig(total_budget=200))

        km_glob = MagicMock(token="GLOB", detected=False)
        km_or = MagicMock(token="OR", detected=True)
        mock_result = MagicMock(
            keyword_map=[km_glob, km_or],
            boundary_payloads=[],
            requests_used=5,
            attack_class="sqli",
        )

        with patch("waffen.recon.score_probe.ScoreProber") as mock_sp:
            mock_sp_inst = MagicMock()
            mock_sp_inst.run.return_value = mock_result
            mock_sp.return_value = mock_sp_inst
            with patch("waffen.search.adaptive.Oracle"):
                stage = search._stage_score(20, attack_classes=["sqli"])

        assert "GLOB" in stage.intel["invisible_tokens"]
        assert "OR" not in stage.intel["invisible_tokens"]
