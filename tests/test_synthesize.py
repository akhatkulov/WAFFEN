"""Tests for LLM-guided payload synthesis."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from unittest.mock import patch, MagicMock

import pytest

from waffen.ai.synthesize import (
    SynthesisConfig,
    SynthesisContext,
    PayloadSynthesizer,
    build_prompt,
    parse_payloads,
    _call_anthropic,
    _call_openai,
)


# ---- SynthesisContext construction -----------------------------------------

class TestSynthesisContext:
    def test_from_manual(self):
        ctx = SynthesisContext.from_manual(
            detected="OR,AND,UNION,SELECT",
            invisible="GLOB,COLLATE,ISNULL",
            gaps="typeof,hex,iif",
            db="sqlite",
            waf="RedEye",
        )
        assert ctx.waf_name == "RedEye"
        assert "OR" in ctx.detected_keywords
        assert "GLOB" in ctx.invisible_keywords
        assert "typeof" in ctx.gap_tokens
        assert ctx.backend_db == "sqlite"

    def test_from_manual_empty(self):
        ctx = SynthesisContext.from_manual()
        assert ctx.is_empty()

    def test_is_empty(self):
        ctx = SynthesisContext()
        assert ctx.is_empty()

    def test_is_not_empty_with_detected(self):
        ctx = SynthesisContext(detected_keywords=["OR"])
        assert not ctx.is_empty()

    def test_is_not_empty_with_gaps(self):
        ctx = SynthesisContext(gap_tokens=["GLOB"])
        assert not ctx.is_empty()

    def test_from_score_probe(self):
        @dataclass
        class FakeKM:
            token: str
            detected: bool
        @dataclass
        class FakeBP:
            payload: str
            verdict: str
        @dataclass
        class FakeStrip:
            payload: str
            verdict: str
        @dataclass
        class FakeResult:
            keyword_map: list = field(default_factory=list)
            boundary_payloads: list = field(default_factory=list)
            strip_chain: list = field(default_factory=list)

        result = FakeResult(
            keyword_map=[FakeKM("OR", True), FakeKM("GLOB", False)],
            boundary_payloads=[FakeBP("' GLOB '*", "THROUGH"), FakeBP("' OR 1=1--", "BLOCKED")],
            strip_chain=[FakeStrip("' OR 1=1--", "BLOCKED"), FakeStrip("'", "THROUGH")],
        )
        ctx = SynthesisContext.from_score_probe(result)
        assert "OR" in ctx.detected_keywords
        assert "GLOB" in ctx.invisible_keywords
        assert "' GLOB '*" in ctx.boundary_payloads
        assert "' OR 1=1--" not in ctx.boundary_payloads
        assert "' OR 1=1--" in ctx.block_examples
        assert "'" in ctx.pass_examples

    def test_from_gap_reports(self):
        @dataclass
        class FakeToken:
            name: str
        @dataclass
        class FakeGap:
            token: FakeToken
        @dataclass
        class FakeReport:
            engine: str
            gaps: list

        reports = [FakeReport("sqlite", [FakeGap(FakeToken("GLOB")), FakeGap(FakeToken("MATCH"))])]
        ctx = SynthesisContext.from_gap_reports(reports)
        assert ctx.backend_db == "sqlite"
        assert "GLOB" in ctx.gap_tokens
        assert "MATCH" in ctx.gap_tokens

    def test_from_profile(self):
        @dataclass
        class FakeProfile:
            fingerprint: dict = field(default_factory=lambda: {"name": "RedEye WAF"})
            score_probe: dict = field(default_factory=lambda: {
                "sqli": {
                    "keyword_map": {"OR": True, "GLOB": False, "AND": True},
                    "boundary_payloads": [
                        {"payload": "' GLOB '*", "verdict": "THROUGH"},
                    ],
                }
            })
            gap_reports: dict = field(default_factory=lambda: {
                "sqlite": {"gaps": [{"token": "COLLATE"}, {"token": "ISNULL"}]}
            })

        ctx = SynthesisContext.from_profile(FakeProfile())
        assert ctx.waf_name == "RedEye WAF"
        assert "OR" in ctx.detected_keywords
        assert "GLOB" in ctx.invisible_keywords
        assert "' GLOB '*" in ctx.boundary_payloads
        assert "COLLATE" in ctx.gap_tokens
        assert ctx.backend_db == "sqlite"


# ---- Prompt building -------------------------------------------------------

class TestBuildPrompt:
    def test_includes_waf_name(self):
        ctx = SynthesisContext(waf_name="RedEye", backend_db="sqlite")
        prompt = build_prompt(ctx, "sqli", 20)
        assert "RedEye" in prompt
        assert "sqlite" in prompt

    def test_includes_detected_keywords(self):
        ctx = SynthesisContext(detected_keywords=["OR", "AND", "SELECT"])
        prompt = build_prompt(ctx, "sqli", 10)
        assert "OR" in prompt
        assert "DETECTED" in prompt

    def test_includes_invisible(self):
        ctx = SynthesisContext(invisible_keywords=["GLOB", "COLLATE"])
        prompt = build_prompt(ctx, "sqli", 10)
        assert "GLOB" in prompt
        assert "INVISIBLE" in prompt

    def test_includes_gap_tokens(self):
        ctx = SynthesisContext(gap_tokens=["typeof", "hex"])
        prompt = build_prompt(ctx, "sqli", 10)
        assert "typeof" in prompt

    def test_includes_boundary(self):
        ctx = SynthesisContext(boundary_payloads=["' GLOB '*"])
        prompt = build_prompt(ctx, "sqli", 10)
        assert "GLOB" in prompt
        assert "boundary" in prompt.lower() or "Boundary" in prompt

    def test_xss_class(self):
        ctx = SynthesisContext()
        prompt = build_prompt(ctx, "xss", 10)
        assert "XSS" in prompt

    def test_max_payloads_in_prompt(self):
        ctx = SynthesisContext()
        prompt = build_prompt(ctx, "sqli", 42)
        assert "42" in prompt

    def test_no_markdown_fences_instruction(self):
        ctx = SynthesisContext()
        prompt = build_prompt(ctx, "sqli", 10)
        assert "no markdown" in prompt.lower() or "no numbering" in prompt.lower()


# ---- Response parsing -------------------------------------------------------

class TestParsePayloads:
    def test_simple_lines(self):
        raw = "' OR 1=1--\n' GLOB '*\n' UNION SELECT 1--"
        result = parse_payloads(raw)
        assert len(result) == 3
        assert "' OR 1=1--" in result

    def test_numbered_lines(self):
        raw = "1. ' OR 1=1--\n2. ' GLOB '*\n3. ' UNION SELECT 1--"
        result = parse_payloads(raw)
        assert len(result) == 3
        assert "' OR 1=1--" in result

    def test_numbered_paren(self):
        raw = "1) ' OR 1=1--\n2) ' GLOB '*"
        result = parse_payloads(raw)
        assert len(result) == 2
        assert "' OR 1=1--" in result

    def test_dash_prefix(self):
        raw = "- ' OR 1=1--\n- ' GLOB '*"
        result = parse_payloads(raw)
        assert len(result) == 2
        assert "' OR 1=1--" in result

    def test_skips_empty_lines(self):
        raw = "\n\n' OR 1=1--\n\n' GLOB '*\n\n"
        result = parse_payloads(raw)
        assert len(result) == 2

    def test_skips_comments(self):
        raw = "# SQLi payloads\n' OR 1=1--\n// another comment\n' GLOB '*"
        result = parse_payloads(raw)
        assert len(result) == 2

    def test_skips_code_fences(self):
        raw = "```\n' OR 1=1--\n' GLOB '*\n```"
        result = parse_payloads(raw)
        assert len(result) == 2

    def test_skips_separators(self):
        raw = "' OR 1=1--\n---\n' GLOB '*"
        result = parse_payloads(raw)
        assert len(result) == 2

    def test_empty_response(self):
        assert parse_payloads("") == []
        assert parse_payloads("   ") == []

    def test_mixed_format(self):
        raw = """# Generated payloads
1. ' OR 1=1--
2) ' GLOB '*
- ' COLLATE NOCASE
' ISNULL
```
' MATCH '*
```"""
        result = parse_payloads(raw)
        assert len(result) == 5


# ---- API callers (mocked) --------------------------------------------------

class TestAPICallers:
    def _mock_response(self, body: dict):
        resp = MagicMock()
        resp.read.return_value = json.dumps(body).encode()
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        return resp

    def test_anthropic_missing_key(self):
        config = SynthesisConfig(provider="anthropic", api_key="")
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
                _call_anthropic("test", config)

    def test_openai_missing_key(self):
        config = SynthesisConfig(provider="openai", api_key="")
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(ValueError, match="OPENAI_API_KEY"):
                _call_openai("test", config)

    def test_anthropic_success(self):
        config = SynthesisConfig(api_key="sk-ant-test123")
        mock_resp = self._mock_response({
            "content": [{"text": "' OR 1=1--\n' GLOB '*"}]
        })
        with patch("urllib.request.urlopen", return_value=mock_resp) as mock_open:
            result = _call_anthropic("test prompt", config)
            assert "' OR 1=1--" in result
            call_args = mock_open.call_args
            req = call_args[0][0]
            assert req.get_header("X-api-key") == "sk-ant-test123"
            assert "api.anthropic.com" in req.full_url

    def test_openai_success(self):
        config = SynthesisConfig(provider="openai", api_key="sk-test123", model="gpt-4o")
        mock_resp = self._mock_response({
            "choices": [{"message": {"content": "' OR 1=1--\n' GLOB '*"}}]
        })
        with patch("urllib.request.urlopen", return_value=mock_resp) as mock_open:
            result = _call_openai("test prompt", config)
            assert "' OR 1=1--" in result
            call_args = mock_open.call_args
            req = call_args[0][0]
            assert "openai.com" in req.full_url

    def test_openai_model_fallback(self):
        config = SynthesisConfig(provider="openai", api_key="sk-test", model="claude-sonnet-4-20250514")
        mock_resp = self._mock_response({
            "choices": [{"message": {"content": "payload"}}]
        })
        with patch("urllib.request.urlopen", return_value=mock_resp) as mock_open:
            _call_openai("test", config)
            req_body = json.loads(mock_open.call_args[0][0].data)
            assert req_body["model"] == "gpt-4o"

    def test_anthropic_key_from_env(self):
        config = SynthesisConfig(api_key="")
        mock_resp = self._mock_response({"content": [{"text": "payload"}]})
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-env-key"}):
            with patch("urllib.request.urlopen", return_value=mock_resp) as mock_open:
                _call_anthropic("test", config)
                req = mock_open.call_args[0][0]
                assert req.get_header("X-api-key") == "sk-env-key"


# ---- PayloadSynthesizer integration ----------------------------------------

class TestPayloadSynthesizer:
    def test_synthesize_calls_api(self):
        config = SynthesisConfig(api_key="sk-test")
        synth = PayloadSynthesizer(config)
        ctx = SynthesisContext(
            detected_keywords=["OR", "AND"],
            invisible_keywords=["GLOB"],
            backend_db="sqlite",
        )
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "content": [{"text": "' GLOB '*\n' COLLATE NOCASE"}]
        }).encode()
        with patch("urllib.request.urlopen", return_value=mock_resp):
            payloads = synth.synthesize(ctx, "sqli")
        assert len(payloads) == 2
        assert "' GLOB '*" in payloads

    def test_unknown_provider(self):
        config = SynthesisConfig(provider="unknown")
        synth = PayloadSynthesizer(config)
        with pytest.raises(ValueError, match="Unknown provider"):
            synth.synthesize(SynthesisContext(), "sqli")

    def test_synthesize_from_profile(self):
        @dataclass
        class FakeProfile:
            fingerprint: dict = field(default_factory=dict)
            score_probe: dict = field(default_factory=lambda: {
                "sqli": {"keyword_map": {"OR": True}, "boundary_payloads": []}
            })
            gap_reports: dict = field(default_factory=dict)

        config = SynthesisConfig(api_key="sk-test")
        synth = PayloadSynthesizer(config)
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "content": [{"text": "' GLOB '*"}]
        }).encode()
        with patch("urllib.request.urlopen", return_value=mock_resp):
            payloads = synth.synthesize_from_profile(FakeProfile(), "sqli")
        assert len(payloads) >= 1

    def test_default_config(self):
        synth = PayloadSynthesizer()
        assert synth.config.provider == "anthropic"
        assert synth.config.max_payloads == 50
