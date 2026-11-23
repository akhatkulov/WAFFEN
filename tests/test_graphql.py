"""Tests for GraphQL attack module."""
import json
from unittest.mock import patch, MagicMock

import pytest

from waffen.graphql.introspect import (
    IntrospectionResult, _FULL_INTROSPECTION, _PARTIAL_TYPE,
)
from waffen.graphql.attacks import (
    batch_bypass, alias_flood, directive_injection,
    field_suggestion_leak, persisted_query_bypass, GQLAttackResult,
)
from waffen.core.oracle import Target


def _target():
    return Target(base_url="https://test.example", path="/graphql",
                  block_signature="WAF_BLOCK")


class TestIntrospectionResult:
    def test_defaults(self):
        r = IntrospectionResult()
        assert not r.success
        assert r.schema is None
        assert r.types == []

    def test_full(self):
        r = IntrospectionResult(success=True, method="POST",
                                types=["User", "Query"], bypass_used="direct")
        assert r.success
        assert len(r.types) == 2


class TestGQLAttackResult:
    def test_blocked(self):
        r = GQLAttackResult("batch", "403", "WAF_BLOCK", True, "test")
        assert r.waf_blocked

    def test_passed(self):
        r = GQLAttackResult("batch", "200", "{}", False, "test")
        assert not r.waf_blocked


class TestBatchBypass:
    @patch("waffen.graphql.attacks._send")
    def test_sends_array_of_two(self, mock_send):
        mock_send.return_value = ("200", '{"data":{}}')
        r = batch_bypass(_target(), "' OR 1=1--")
        sent_body = mock_send.call_args[0][1]
        parsed = json.loads(sent_body)
        assert isinstance(parsed, list)
        assert len(parsed) == 2
        assert "__typename" in parsed[0]["query"]
        assert "OR 1=1" in parsed[1]["query"]
        assert not r.waf_blocked

    @patch("waffen.graphql.attacks._send")
    def test_detects_block(self, mock_send):
        mock_send.return_value = ("403", "WAF_BLOCK")
        r = batch_bypass(_target(), "test")
        assert r.waf_blocked


class TestAliasFlood:
    @patch("waffen.graphql.attacks._send")
    def test_generates_n_aliases(self, mock_send):
        mock_send.return_value = ("200", "{}")
        r = alias_flood(_target(), "test", n=10)
        body = json.loads(mock_send.call_args[0][1])
        query = body["query"]
        assert "a0:" in query
        assert "a9:" in query
        assert not r.waf_blocked

    @patch("waffen.graphql.attacks._send")
    def test_default_50_aliases(self, mock_send):
        mock_send.return_value = ("200", "{}")
        alias_flood(_target(), "test")
        body = json.loads(mock_send.call_args[0][1])
        assert "a49:" in body["query"]


class TestDirectiveInjection:
    @patch("waffen.graphql.attacks._send")
    def test_includes_include_directive(self, mock_send):
        mock_send.return_value = ("200", "{}")
        r = directive_injection(_target(), "' OR 1=1--")
        body = json.loads(mock_send.call_args[0][1])
        assert "@include" in body["query"]
        assert not r.waf_blocked


class TestFieldSuggestionLeak:
    @patch("waffen.graphql.attacks._send")
    def test_detects_suggestions(self, mock_send):
        mock_send.return_value = ("200", '{"errors":[{"message":"Did you mean \\"user\\"?"}]}')
        r = field_suggestion_leak(_target())
        assert "Did you mean" in r.body

    @patch("waffen.graphql.attacks._send")
    def test_no_suggestions(self, mock_send):
        mock_send.return_value = ("200", '{"errors":[{"message":"unknown field"}]}')
        r = field_suggestion_leak(_target())
        assert "no suggestions" in r.body


class TestPersistedQuery:
    @patch("waffen.graphql.attacks._send")
    def test_sends_hash(self, mock_send):
        mock_send.return_value = ("200", "{}")
        r = persisted_query_bypass(_target(), "test")
        body = json.loads(mock_send.call_args[0][1])
        assert "extensions" in body
        assert "sha256Hash" in body["extensions"]["persistedQuery"]
        assert len(body["extensions"]["persistedQuery"]["sha256Hash"]) == 64


class TestCLIParserGraphql:
    def test_parser_has_graphql(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args(["graphql", "--target", "https://x.com", "--introspect"])
        assert args.introspect is True
        assert hasattr(args, "func")

    def test_parser_graphql_all(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args(["graphql", "--target", "https://x.com", "--all",
                             "--payload", "test"])
        assert args.all_techniques is True
