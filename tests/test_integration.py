"""Integration tests — run real CLI subcommands end-to-end (mock/offline only)."""
import io
import sys
from unittest.mock import patch

import pytest

from waffen.cli import build_parser


def _run(argv: list[str]) -> int:
    """Parse args and run the subcommand, capturing stdout."""
    p = build_parser()
    args = p.parse_args(argv)
    old_out = sys.stdout
    sys.stdout = io.StringIO()
    try:
        return args.func(args)
    finally:
        sys.stdout = old_out


class TestBypassMock:
    def test_sqli_beam(self):
        rc = _run(["bypass", "--mock", "--class", "SQL Injection",
                    "--strategy", "beam", "--max-requests", "15",
                    "--width", "3", "--depth", "2"])
        assert rc == 0

    def test_xss_genetic(self):
        rc = _run(["bypass", "--mock", "--class", "XSS Injection",
                    "--strategy", "genetic", "--max-requests", "15",
                    "--pop-size", "6", "--generations", "2"])
        assert rc == 0

    def test_single_payload_bestfirst(self):
        rc = _run(["bypass", "--mock", "--payload", "' OR 1=1--",
                    "--strategy", "bestfirst", "--max-requests", "15",
                    "--branch", "3"])
        assert rc == 0

    def test_mcts(self):
        rc = _run(["bypass", "--mock", "--class", "SQL Injection",
                    "--strategy", "mcts", "--max-requests", "15",
                    "--iterations", "10", "--rollout-depth", "2"])
        assert rc == 0

    def test_dry_run(self):
        rc = _run(["bypass", "--mock", "--class", "SQL Injection",
                    "--dry-run"])
        assert rc == 0

    def test_stop_on_first(self):
        rc = _run(["bypass", "--mock", "--class", "SQL Injection",
                    "--max-requests", "15", "--stop-on-first"])
        assert rc == 0


class TestListSubcommands:
    def test_mutators(self):
        rc = _run(["mutators"])
        assert rc == 0

    def test_transforms(self):
        rc = _run(["transforms"])
        assert rc == 0

    def test_version(self):
        rc = _run(["version"])
        assert rc == 0

    def test_corpus_count(self):
        rc = _run(["corpus", "--count"])
        assert rc == 0


class TestAutoNoTarget:
    def test_returns_error(self):
        with patch("builtins.input", return_value=""):
            rc = _run(["auto"])
        assert rc == 2


class TestBypassMissingTarget:
    def test_returns_error(self):
        rc = _run(["bypass", "--class", "SQL Injection"])
        assert rc == 2


class TestBypassMissingSeeds:
    def test_returns_error(self):
        rc = _run(["bypass", "--mock"])
        assert rc == 2


class TestParserCompleteness:
    """Verify all subcommands parse without error."""

    @pytest.mark.parametrize("cmd", [
        ["bypass", "--mock", "--class", "SQL Injection", "--dry-run"],
        ["mutators"],
        ["transforms"],
        ["version"],
        ["corpus", "--count"],
    ])
    def test_parse_succeeds(self, cmd):
        p = build_parser()
        args = p.parse_args(cmd)
        assert hasattr(args, "func")
