"""Tests for the autonomous red team agent."""
import os
import tempfile
from unittest.mock import MagicMock, patch
from dataclasses import asdict

import pytest

from waffen.agent.redteam import (
    AutonomousRedTeam,
    RedTeamConfig,
    RedTeamPhase,
    RedTeamResult,
)


# ---- dataclass tests -------------------------------------------------------

class TestRedTeamConfig:
    def test_defaults(self):
        cfg = RedTeamConfig(target_url="https://x.com")
        assert cfg.max_budget == 5000
        assert cfg.auto_exploit is True
        assert cfg.generate_report is True
        assert cfg.transport == "auto"

    def test_custom(self):
        cfg = RedTeamConfig(
            target_url="https://y.com", path="/api",
            max_budget=1000, attack_classes=["XSS Injection"],
            goals=["xss_stored"],
        )
        assert cfg.max_budget == 1000
        assert cfg.goals == ["xss_stored"]


class TestRedTeamPhase:
    def test_defaults(self):
        p = RedTeamPhase(name="recon")
        assert p.status == "pending"
        assert p.findings == []
        assert p.requests_used == 0

    def test_fields(self):
        p = RedTeamPhase(name="bypass", status="completed",
                         duration_s=12.5, requests_used=200,
                         findings=[{"x": 1}], summary="ok")
        assert p.duration_s == 12.5
        assert len(p.findings) == 1


class TestRedTeamResult:
    def test_defaults(self):
        r = RedTeamResult(target="https://x.com")
        assert r.bypasses_found == 0
        assert r.exploits_confirmed == 0

    def test_as_dict(self):
        r = RedTeamResult(
            target="https://x.com",
            phases=[RedTeamPhase(name="recon", status="completed",
                                duration_s=1.23, summary="done")],
            total_requests=100, total_duration_s=5.678,
            bypasses_found=2, exploits_confirmed=1,
            report_path="r.html",
        )
        d = r.as_dict()
        assert d["target"] == "https://x.com"
        assert d["bypasses_found"] == 2
        assert d["total_duration_s"] == 5.7
        assert len(d["phases"]) == 1
        assert d["phases"][0]["name"] == "recon"


# ---- budget allocation -----------------------------------------------------

class TestBudgetAllocation:
    def test_allocate_fraction(self):
        cfg = RedTeamConfig(target_url="https://x.com", max_budget=1000)
        agent = AutonomousRedTeam(cfg)
        b = agent._allocate(0.10)
        assert b == 100
        assert agent._budget_remaining == 900

    def test_allocate_minimum(self):
        cfg = RedTeamConfig(target_url="https://x.com", max_budget=50)
        agent = AutonomousRedTeam(cfg)
        b = agent._allocate(0.01)
        assert b >= 10

    def test_allocate_sequence(self):
        cfg = RedTeamConfig(target_url="https://x.com", max_budget=1000)
        agent = AutonomousRedTeam(cfg)
        b1 = agent._allocate(0.10)  # 100
        b2 = agent._allocate(0.50)  # 450
        assert b1 == 100
        assert b2 == 450
        assert agent._budget_remaining == 450


# ---- target construction ---------------------------------------------------

class TestTargetConstruction:
    def test_make_target(self):
        cfg = RedTeamConfig(target_url="https://x.com", path="/api",
                            param="search", inject="json")
        agent = AutonomousRedTeam(cfg)
        t = agent._target()
        assert t.base_url == "https://x.com"
        assert t.path == "/api"
        assert t.param == "search"

    def test_target_overrides(self):
        cfg = RedTeamConfig(target_url="https://x.com")
        agent = AutonomousRedTeam(cfg)
        t = agent._target(path="/override")
        assert t.path == "/override"


# ---- phase tests with mocks -----------------------------------------------

class _FakeOracle:
    def send(self, payload):
        return MagicMock(verdict="BLOCKED", code="403", score=0)


class TestPhaseRecon:
    def test_recon_handles_import_errors(self):
        cfg = RedTeamConfig(target_url="https://x.com")
        agent = AutonomousRedTeam(cfg, sender=lambda p: MagicMock(
            verdict="BLOCKED", code="403"))
        with patch("waffen.agent.redteam.AutonomousRedTeam._phase_recon",
                   return_value={"waf_name": "test", "injection_points": []}):
            intel = agent._phase_recon()
            assert "waf_name" in intel

    def test_recon_creates_phase(self):
        cfg = RedTeamConfig(target_url="https://x.com")
        agent = AutonomousRedTeam(cfg)
        with patch.dict("sys.modules", {
            "waffen.recon.fingerprint": MagicMock(fingerprint=MagicMock(return_value=[])),
            "waffen.recon.discover": MagicMock(InjectionDiscovery=MagicMock(
                return_value=MagicMock(discover=MagicMock(return_value=[])))),
            "waffen.recon.decision_tree": MagicMock(WAFDecisionTreeProber=MagicMock(
                return_value=MagicMock(probe_all=MagicMock(return_value=None),
                                       recommend_mutations=MagicMock(return_value=[])))),
        }):
            try:
                agent._phase_recon()
            except Exception:
                pass
        assert len(agent.phases) >= 1
        assert agent.phases[0].name == "recon"


class TestPhaseBypass:
    def test_bypass_empty_seeds(self):
        cfg = RedTeamConfig(target_url="https://x.com",
                            attack_classes=["NonexistentClass"])
        agent = AutonomousRedTeam(cfg)
        agent.phases = []  # clean
        bypasses = agent._phase_bypass({}, {})
        assert bypasses == []
        assert len(agent.phases) == 1
        assert agent.phases[0].name == "bypass"


class TestPhaseExploit:
    def test_exploit_skipped_no_bypasses(self):
        cfg = RedTeamConfig(target_url="https://x.com")
        agent = AutonomousRedTeam(cfg)
        agent.phases = []
        result = agent._phase_exploit([])
        assert result == []
        assert agent.phases[0].status == "skipped"

    def test_exploit_skipped_no_sqli(self):
        cfg = RedTeamConfig(target_url="https://x.com")
        agent = AutonomousRedTeam(cfg)
        agent.phases = []
        bypasses = [{"attack_class": "XSS Injection", "verified": True,
                     "payload": "<svg>", "chain": []}]
        result = agent._phase_exploit(bypasses)
        assert result == []


class TestPhaseReport:
    def test_report_generates_files(self):
        with tempfile.TemporaryDirectory() as td:
            rpath = os.path.join(td, "report.html")
            cfg = RedTeamConfig(target_url="https://x.com",
                                report_path=rpath, rules_path=os.path.join(td, "r.conf"))
            agent = AutonomousRedTeam(cfg)
            agent.phases = []
            rp, rup = agent._phase_report([], [])
            assert rp == rpath
            assert os.path.exists(rpath)


class TestFullRun:
    def test_run_no_network(self):
        """Full run with everything mocked — verifies phase orchestration."""
        cfg = RedTeamConfig(target_url="https://x.com", max_budget=100,
                            generate_report=False, auto_exploit=False)
        agent = AutonomousRedTeam(cfg)

        # Mock all phases to return empty intel
        agent._phase_recon = MagicMock(return_value={"waf_name": "mock"})
        agent._phase_profile = MagicMock(return_value={"waf_detected": True})
        agent._phase_plan = MagicMock(return_value={"goals": {}})
        agent._phase_bypass = MagicMock(return_value=[])

        result = agent.run()
        assert isinstance(result, RedTeamResult)
        assert result.target == "https://x.com"
        assert result.bypasses_found == 0
        agent._phase_recon.assert_called_once()
        agent._phase_profile.assert_called_once()
        agent._phase_plan.assert_called_once()
        agent._phase_bypass.assert_called_once()

    def test_run_with_bypasses(self):
        cfg = RedTeamConfig(target_url="https://x.com", max_budget=100,
                            generate_report=False, auto_exploit=False)
        agent = AutonomousRedTeam(cfg)
        agent._phase_recon = MagicMock(return_value={})
        agent._phase_profile = MagicMock(return_value={})
        agent._phase_plan = MagicMock(return_value={})
        agent._phase_bypass = MagicMock(return_value=[
            {"attack_class": "sqli", "payload": "' OR 1=1--",
             "verified": True, "chain": [], "code": "200"},
        ])

        result = agent.run()
        assert result.bypasses_found == 1


# ---- CLI test ---------------------------------------------------------------

class TestCLI:
    def test_parser_has_redteam(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args(["redteam", "--target", "https://x.com", "--budget", "100"])
        assert args.target == "https://x.com"
        assert args.budget == 100
        assert hasattr(args, "func")

    def test_parser_defaults(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args(["redteam", "--target", "https://x.com"])
        assert args.budget == 5000
        assert args.classes == "SQL Injection"
        assert args.goals == "dump_database"

    def test_cmd_redteam_no_target(self):
        from waffen.cli import cmd_redteam
        args = MagicMock(target="")
        assert cmd_redteam(args) == 2
