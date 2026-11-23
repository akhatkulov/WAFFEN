"""Tests for the continuous autonomous daemon."""
import json
import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from waffen.daemon import (
    CycleResult,
    DaemonConfig,
    WAFFENDaemon,
    format_alert,
    _interruptible_sleep,
)


# ---- DaemonConfig ---------------------------------------------------------

class TestDaemonConfig:
    def test_defaults(self):
        cfg = DaemonConfig(target_url="https://t.com")
        assert cfg.interval_hours == 6.0
        assert cfg.attack_classes == ["sqli"]
        assert cfg.max_requests_per_cycle == 500
        assert cfg.webhook_url == ""
        assert cfg.profile_path == ""

    def test_custom(self):
        cfg = DaemonConfig(
            target_url="https://x.com",
            interval_hours=2.0,
            attack_classes=["sqli", "xss"],
            webhook_url="https://hooks.slack.com/xxx",
        )
        assert cfg.interval_hours == 2.0
        assert len(cfg.attack_classes) == 2
        assert cfg.webhook_url.startswith("https://hooks")


# ---- CycleResult ----------------------------------------------------------

class TestCycleResult:
    def test_as_dict(self):
        r = CycleResult(
            timestamp="2026-11-23T14:00:00Z",
            cycle_number=1,
            waf_fingerprint="TestWAF",
            new_bypasses=[{"payload": "test"}],
            fixed_bypasses=[],
            still_alive=[{"payload": "alive"}],
            waf_changed=False,
            requests_used=100,
        )
        d = r.as_dict()
        assert d["cycle_number"] == 1
        assert d["waf_fingerprint"] == "TestWAF"
        assert d["new_bypasses"] == 1
        assert d["still_alive"] == 1
        assert d["requests_used"] == 100

    def test_empty_result(self):
        r = CycleResult(timestamp="now", cycle_number=0)
        d = r.as_dict()
        assert d["new_bypasses"] == 0
        assert d["fixed_bypasses"] == 0
        assert d["waf_changed"] is False


# ---- format_alert ----------------------------------------------------------

class TestFormatAlert:
    def test_new_bypass_alert(self):
        r = CycleResult(
            timestamp="2026-11-23T14:00:00Z",
            cycle_number=2,
            new_bypasses=[{"payload": "' OR 1=1--"}],
            fixed_bypasses=[],
            still_alive=[],
        )
        msg = format_alert(r, "https://target.com")
        assert "WAFFEN Alert" in msg
        assert "NEW BYPASS" in msg
        assert "' OR 1=1--" in msg
        assert "target.com" in msg

    def test_fixed_alert(self):
        r = CycleResult(
            timestamp="now",
            cycle_number=3,
            new_bypasses=[],
            fixed_bypasses=[{"payload": "old"}],
            still_alive=[],
        )
        msg = format_alert(r, "https://t.com")
        assert "FIXED" in msg

    def test_waf_changed_alert(self):
        r = CycleResult(
            timestamp="now",
            cycle_number=4,
            waf_changed=True,
            new_bypasses=[],
            fixed_bypasses=[],
            still_alive=[],
        )
        msg = format_alert(r, "https://t.com")
        assert "CHANGED" in msg

    def test_still_alive_count(self):
        r = CycleResult(
            timestamp="now",
            cycle_number=5,
            new_bypasses=[],
            fixed_bypasses=[],
            still_alive=[{"p": 1}, {"p": 2}],
        )
        msg = format_alert(r, "https://t.com")
        assert "2 bypass(es)" in msg

    def test_multiple_new(self):
        r = CycleResult(
            timestamp="now",
            cycle_number=1,
            new_bypasses=[
                {"payload": "first"},
                {"payload": "second"},
                {"payload": "third"},
                {"payload": "fourth"},  # only first 3 shown
            ],
            fixed_bypasses=[],
            still_alive=[],
        )
        msg = format_alert(r, "https://t.com")
        assert "4 NEW" in msg
        assert "first" in msg
        assert "third" in msg


# ---- WAFFENDaemon ----------------------------------------------------------

class TestDaemon:
    def _make_daemon(self, **overrides):
        defaults = dict(
            target_url="https://test.com",
            path="/search",
            param="q",
        )
        defaults.update(overrides)
        cfg = DaemonConfig(**defaults)
        return WAFFENDaemon(cfg)

    def test_init(self):
        d = self._make_daemon()
        assert d.config.target_url == "https://test.com"
        assert d.history == []
        assert d._known_bypasses == []

    def test_should_alert_new_bypass(self):
        d = self._make_daemon()
        r = CycleResult(timestamp="now", cycle_number=1,
                        new_bypasses=[{"p": 1}])
        assert d._should_alert(r) is True

    def test_should_alert_fixed(self):
        d = self._make_daemon()
        r = CycleResult(timestamp="now", cycle_number=2,
                        fixed_bypasses=[{"p": 1}])
        assert d._should_alert(r) is True

    def test_should_alert_waf_change(self):
        d = self._make_daemon()
        r = CycleResult(timestamp="now", cycle_number=3,
                        waf_changed=True)
        assert d._should_alert(r) is True

    def test_should_not_alert_nothing(self):
        d = self._make_daemon()
        r = CycleResult(timestamp="now", cycle_number=1)
        assert d._should_alert(r) is False

    def test_should_not_alert_disabled(self):
        d = self._make_daemon(alert_on=[])
        r = CycleResult(timestamp="now", cycle_number=1,
                        new_bypasses=[{"p": 1}])
        assert d._should_alert(r) is False

    def test_diff_findings_new(self):
        d = self._make_daemon()
        d._known_bypasses = [{"payload": "old"}]
        current = [{"payload": "old"}, {"payload": "new"}]
        new = d._diff_findings(current)
        assert len(new) == 1
        assert new[0]["payload"] == "new"

    def test_diff_findings_all_known(self):
        d = self._make_daemon()
        d._known_bypasses = [{"payload": "a"}, {"payload": "b"}]
        new = d._diff_findings([{"payload": "a"}, {"payload": "b"}])
        assert new == []

    def test_diff_findings_empty_known(self):
        d = self._make_daemon()
        d._known_bypasses = []
        current = [{"payload": "x"}]
        new = d._diff_findings(current)
        assert len(new) == 1


# ---- profile save/load ----------------------------------------------------

class TestDaemonProfile:
    def test_save_load_roundtrip(self):
        d = self._make_daemon_with_profile()
        d._last_fingerprint = "TestWAF"
        d._last_confidence = 0.85
        d._known_bypasses = [{"payload": "' OR 1=1--", "chain": ["base64"]}]
        d._save_profile()

        d2 = self._make_daemon_with_profile(d.config.profile_path)
        d2._load_profile()
        assert d2._last_fingerprint == "TestWAF"
        assert d2._last_confidence == 0.85
        assert len(d2._known_bypasses) == 1
        assert d2._known_bypasses[0]["payload"] == "' OR 1=1--"

    def test_load_missing_file(self):
        d = self._make_daemon_with_profile("/nonexistent/path.json")
        d._load_profile()
        assert d._known_bypasses == []

    def _make_daemon_with_profile(self, path=None):
        if path is None:
            fd, path = tempfile.mkstemp(suffix=".json")
            os.close(fd)
        cfg = DaemonConfig(target_url="https://t.com", profile_path=path)
        return WAFFENDaemon(cfg)


# ---- webhook ---------------------------------------------------------------

class TestDaemonWebhook:
    def test_send_alert_calls_webhook(self):
        cfg = DaemonConfig(
            target_url="https://t.com",
            webhook_url="https://hooks.example.com/test",
        )
        d = WAFFENDaemon(cfg)
        result = CycleResult(
            timestamp="now", cycle_number=1,
            new_bypasses=[{"payload": "test"}],
        )

        with patch("waffen.daemon.urllib.request.urlopen") as mock_open:
            d._send_alert(result)
            assert mock_open.called
            call_args = mock_open.call_args
            req = call_args[0][0]
            assert req.full_url == "https://hooks.example.com/test"
            body = json.loads(req.data)
            assert "text" in body
            assert "NEW BYPASS" in body["text"]

    def test_no_webhook_no_call(self):
        cfg = DaemonConfig(target_url="https://t.com", webhook_url="")
        d = WAFFENDaemon(cfg)
        result = CycleResult(timestamp="now", cycle_number=1)
        with patch("waffen.daemon.urllib.request.urlopen") as mock_open:
            d._send_alert(result)
            assert not mock_open.called

    def test_webhook_failure_no_crash(self):
        cfg = DaemonConfig(
            target_url="https://t.com",
            webhook_url="https://hooks.example.com/fail",
        )
        d = WAFFENDaemon(cfg)
        result = CycleResult(timestamp="now", cycle_number=1)
        with patch("waffen.daemon.urllib.request.urlopen",
                   side_effect=Exception("network error")):
            d._send_alert(result)  # should not raise


# ---- CLI -------------------------------------------------------------------

class TestDaemonCLI:
    def test_parser_has_daemon(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args([
            "daemon",
            "--target", "https://test.com",
            "--interval", "2",
            "--cycles", "1",
            "--class", "sqli,xss",
        ])
        assert args.target == "https://test.com"
        assert args.interval == 2.0
        assert args.cycles == 1
        assert args.attack_class == "sqli,xss"
        assert hasattr(args, "func")

    def test_parser_defaults(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args(["daemon", "--target", "https://t.com"])
        assert args.interval == 6.0
        assert args.cycles == 0
        assert args.webhook == ""
        assert args.profile == ""
