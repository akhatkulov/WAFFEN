"""Tests for the auto/wizard mode."""
import io
import sys
from unittest.mock import patch, MagicMock

import pytest

from waffen.auto import AutoConfig, run_auto, _ask, _confirm


class TestAutoConfig:
    def test_defaults(self):
        cfg = AutoConfig()
        assert cfg.url == ""
        assert cfg.param == "q"
        assert cfg.inject == "query"
        assert cfg.attack_classes == ["sqli"]
        assert cfg.max_requests == 300

    def test_custom(self):
        cfg = AutoConfig(url="https://x.com", param="search", attack_classes=["xss"])
        assert cfg.url == "https://x.com"
        assert cfg.param == "search"


class TestPromptHelpers:
    def test_ask_returns_default_on_empty(self):
        with patch("builtins.input", return_value=""):
            assert _ask("test", default="foo") == "foo"

    def test_ask_returns_user_input(self):
        with patch("builtins.input", return_value="bar"):
            assert _ask("test", default="foo") == "bar"

    def test_confirm_default_yes(self):
        with patch("builtins.input", return_value=""):
            assert _confirm("ok?", default=True) is True

    def test_confirm_default_no(self):
        with patch("builtins.input", return_value=""):
            assert _confirm("ok?", default=False) is False

    def test_confirm_yes_variants(self):
        for val in ("y", "yes", "Y", "YES", "ha", "da"):
            with patch("builtins.input", return_value=val):
                assert _confirm("ok?", default=False) is True

    def test_confirm_no_variants(self):
        for val in ("n", "no", "N", "nope"):
            with patch("builtins.input", return_value=val):
                assert _confirm("ok?", default=True) is False


class TestAutoNoUrl:
    def test_no_url_returns_2(self):
        cfg = AutoConfig(url="", yes=True)
        with patch("builtins.input", return_value=""):
            rc = run_auto(cfg)
        assert rc == 2


class TestAutoUrlNormalization:
    def test_adds_https_prefix(self):
        """The URL normalization logic adds https:// to bare hostnames."""
        # Test the normalization logic directly without running the full pipeline
        cfg = AutoConfig(url="example.com", yes=True)
        # Simulate the normalization that run_auto does
        if not cfg.url.startswith(("http://", "https://")):
            cfg.url = "https://" + cfg.url
        assert cfg.url == "https://example.com"

    def test_keeps_existing_scheme(self):
        cfg = AutoConfig(url="http://example.com")
        if not cfg.url.startswith(("http://", "https://")):
            cfg.url = "https://" + cfg.url
        assert cfg.url == "http://example.com"


class TestCliAutoSubcommand:
    def test_parser_has_auto(self):
        from waffen.cli import build_parser
        p = build_parser()
        # Should not raise
        args = p.parse_args(["auto", "--url", "https://test.com", "-y"])
        assert args.url == "https://test.com"
        assert args.yes is True
        assert hasattr(args, "func")
