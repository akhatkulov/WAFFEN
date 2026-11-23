"""LLM-guided payload synthesis for WAF bypass research.

Uses a language model (Claude or GPT) to generate context-aware bypass
payloads based on the WAF profiling results from score-probe,
libinjection-scan, and other WAFFEN recon modules.

The LLM understands SQL/XSS/SSTI semantics and can generate creative
payloads that no mechanical mutation chain would produce — specifically
tailored to exploit the gaps in a particular WAF's detection logic.

**Privacy:** only the WAF profile (detected/invisible keywords, gap tokens)
is sent to the API. No target URLs, credentials, or response bodies leave
the machine. The user must explicitly opt in via ``--synthesize`` or the
``synthesize`` subcommand.

**Optional:** requires an API key (``ANTHROPIC_API_KEY`` or
``OPENAI_API_KEY``).  When no key is set, WAFFEN prints a helpful message
and suggests ``waffen bypass --corpus`` as the offline alternative.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Sequence


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass
class SynthesisConfig:
    provider: str = "anthropic"
    model: str = "claude-sonnet-4-20250514"
    api_key: str = ""
    max_payloads: int = 50
    temperature: float = 0.8
    timeout: int = 60


# ---------------------------------------------------------------------------
# Context — describes the WAF to the LLM
# ---------------------------------------------------------------------------

@dataclass
class SynthesisContext:
    waf_name: str = ""
    detected_keywords: list[str] = field(default_factory=list)
    invisible_keywords: list[str] = field(default_factory=list)
    gap_tokens: list[str] = field(default_factory=list)
    boundary_payloads: list[str] = field(default_factory=list)
    block_examples: list[str] = field(default_factory=list)
    pass_examples: list[str] = field(default_factory=list)
    backend_db: str = ""

    @classmethod
    def from_score_probe(cls, result: Any, attack_class: str = "sqli") -> "SynthesisContext":
        ctx = cls()
        if hasattr(result, "keyword_map"):
            for km in result.keyword_map:
                if km.detected:
                    ctx.detected_keywords.append(km.token)
                else:
                    ctx.invisible_keywords.append(km.token)
        if hasattr(result, "boundary_payloads"):
            for bp in result.boundary_payloads:
                v = getattr(bp, "verdict", "")
                if v == "THROUGH":
                    ctx.boundary_payloads.append(getattr(bp, "payload", str(bp)))
        if hasattr(result, "strip_chain"):
            for s in result.strip_chain:
                v = getattr(s, "verdict", "")
                p = getattr(s, "payload", str(s))
                if v == "BLOCKED":
                    ctx.block_examples.append(p)
                elif v == "THROUGH":
                    ctx.pass_examples.append(p)
        return ctx

    @classmethod
    def from_gap_reports(cls, reports: Sequence) -> "SynthesisContext":
        ctx = cls()
        for r in reports:
            engine = getattr(r, "engine", "")
            if not ctx.backend_db and engine:
                ctx.backend_db = engine
            for g in getattr(r, "gaps", []):
                tok = getattr(g, "token", g) if not isinstance(g, str) else g
                name = getattr(tok, "name", str(tok))
                ctx.gap_tokens.append(name)
        return ctx

    @classmethod
    def from_profile(cls, profile: Any) -> "SynthesisContext":
        ctx = cls()
        fp = getattr(profile, "fingerprint", None) or {}
        if isinstance(fp, dict) and fp.get("name"):
            ctx.waf_name = fp["name"]

        sp = getattr(profile, "score_probe", None) or {}
        for cls_name, data in sp.items():
            if isinstance(data, dict):
                km = data.get("keyword_map", {})
                for token, detected in km.items():
                    if detected:
                        ctx.detected_keywords.append(token)
                    else:
                        ctx.invisible_keywords.append(token)
                for bp in data.get("boundary_payloads", []):
                    if isinstance(bp, dict) and bp.get("verdict") == "THROUGH":
                        ctx.boundary_payloads.append(bp.get("payload", ""))
                    elif isinstance(bp, str):
                        ctx.boundary_payloads.append(bp)

        gr = getattr(profile, "gap_reports", None) or {}
        for engine, data in gr.items():
            if not ctx.backend_db:
                ctx.backend_db = engine
            if isinstance(data, dict):
                for g in data.get("gaps", []):
                    if isinstance(g, dict):
                        ctx.gap_tokens.append(g.get("token", ""))
                    elif isinstance(g, str):
                        ctx.gap_tokens.append(g)
        return ctx

    @classmethod
    def from_manual(cls, *, detected: str = "", invisible: str = "",
                    gaps: str = "", db: str = "",
                    waf: str = "") -> "SynthesisContext":
        return cls(
            waf_name=waf,
            detected_keywords=[k.strip() for k in detected.split(",") if k.strip()],
            invisible_keywords=[k.strip() for k in invisible.split(",") if k.strip()],
            gap_tokens=[k.strip() for k in gaps.split(",") if k.strip()],
            backend_db=db,
        )

    def is_empty(self) -> bool:
        return (not self.detected_keywords and not self.invisible_keywords
                and not self.gap_tokens and not self.boundary_payloads)


# ---------------------------------------------------------------------------
# Prompt builder
# ---------------------------------------------------------------------------

_CLASS_LABELS = {
    "sqli": "SQL Injection",
    "xss": "XSS (Cross-Site Scripting)",
    "ssti": "Server-Side Template Injection",
    "ssrf": "Server-Side Request Forgery",
    "xxe": "XML External Entity Injection",
    "cmdi": "OS Command Injection",
}


def build_prompt(ctx: SynthesisContext, attack_class: str = "sqli",
                 max_payloads: int = 50) -> str:
    cls_label = _CLASS_LABELS.get(attack_class, attack_class)
    db_label = ctx.backend_db or "unknown"

    sections = [
        "You are a WAF bypass research assistant for authorized security testing.",
        "",
        "Target WAF profile:",
    ]
    if ctx.waf_name:
        sections.append(f"- WAF: {ctx.waf_name}")
    sections.append(f"- Backend DB: {db_label}")

    if ctx.detected_keywords:
        sections.append(f"- Keywords DETECTED (blocked): {', '.join(ctx.detected_keywords[:30])}")
    if ctx.invisible_keywords:
        sections.append(f"- Keywords INVISIBLE (pass through): {', '.join(ctx.invisible_keywords[:20])}")
    if ctx.gap_tokens:
        sections.append(f"- DB-specific tokens that pass: {', '.join(ctx.gap_tokens[:20])}")
    if ctx.block_examples:
        sections.append(f"- Blocked payloads: {ctx.block_examples[:5]}")
    if ctx.pass_examples:
        sections.append(f"- Passing payloads: {ctx.pass_examples[:5]}")
    if ctx.boundary_payloads:
        sections.append(f"- Boundary payloads (max malice that passes): {ctx.boundary_payloads[:5]}")

    sections += [
        "",
        f"Generate {max_payloads} {cls_label} payloads that:",
        "1. Use ONLY invisible/gap tokens where possible",
        "2. Avoid detected keywords or obfuscate them",
        f"3. Are syntactically valid {db_label} {'SQL' if attack_class in ('sqli',) else 'injection'}",
        "4. Each uses a DIFFERENT bypass technique",
        "5. Include both detection evasion AND exploitation payloads",
        "",
        "Output one payload per line, no numbering, no explanation, no markdown fences.",
    ]
    return "\n".join(sections)


# ---------------------------------------------------------------------------
# Response parser
# ---------------------------------------------------------------------------

def parse_payloads(response: str) -> list[str]:
    payloads: list[str] = []
    for line in response.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        if line.startswith(("```", "#", "//", "---")):
            continue
        # Strip numbering: "1. payload" / "1) payload" / "- payload"
        if len(line) > 2 and line[0].isdigit():
            rest = line.lstrip("0123456789")
            if rest and rest[0] in ".)" :
                line = rest[1:].strip()
        if line.startswith("- "):
            line = line[2:]
        if line:
            payloads.append(line)
    return payloads


# ---------------------------------------------------------------------------
# API callers
# ---------------------------------------------------------------------------

def _call_anthropic(prompt: str, config: SynthesisConfig) -> str:
    api_key = config.api_key or os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        raise ValueError(
            "ANTHROPIC_API_KEY not set. "
            "Set it via: export ANTHROPIC_API_KEY=sk-ant-... "
            "or pass --api-key"
        )

    body = json.dumps({
        "model": config.model,
        "max_tokens": 4096,
        "temperature": config.temperature,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()

    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=body,
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
    )
    resp = urllib.request.urlopen(req, timeout=config.timeout)
    data = json.loads(resp.read())
    return data["content"][0]["text"]


def _call_openai(prompt: str, config: SynthesisConfig) -> str:
    api_key = config.api_key or os.environ.get("OPENAI_API_KEY", "")
    if not api_key:
        raise ValueError(
            "OPENAI_API_KEY not set. "
            "Set it via: export OPENAI_API_KEY=sk-... "
            "or pass --api-key"
        )

    model = config.model
    if model.startswith("claude"):
        model = "gpt-4o"

    body = json.dumps({
        "model": model,
        "temperature": config.temperature,
        "max_tokens": 4096,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()

    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
    )
    resp = urllib.request.urlopen(req, timeout=config.timeout)
    data = json.loads(resp.read())
    return data["choices"][0]["message"]["content"]


_PROVIDERS = {
    "anthropic": _call_anthropic,
    "openai": _call_openai,
}


# ---------------------------------------------------------------------------
# Main synthesizer
# ---------------------------------------------------------------------------

class PayloadSynthesizer:
    def __init__(self, config: SynthesisConfig | None = None):
        self.config = config or SynthesisConfig()

    def synthesize(self, context: SynthesisContext,
                   attack_class: str = "sqli") -> list[str]:
        prompt = build_prompt(context, attack_class, self.config.max_payloads)
        caller = _PROVIDERS.get(self.config.provider)
        if caller is None:
            raise ValueError(f"Unknown provider: {self.config.provider}. "
                             f"Supported: {', '.join(_PROVIDERS)}")
        raw = caller(prompt, self.config)
        return parse_payloads(raw)

    def synthesize_from_profile(self, profile: Any,
                                attack_class: str = "sqli") -> list[str]:
        ctx = SynthesisContext.from_profile(profile)
        return self.synthesize(ctx, attack_class)
