"""WAF configuration synthesizer — generate optimal, deployable WAF configs.

Combines bypass findings, rule-map intelligence, benchmark data and known
false positives to output a complete WAF configuration that blocks all
discovered issues with minimal false positives.

Engines: ModSecurity/Coraza, NGINX (naxsi-style), generic include.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Sequence


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class WAFConfig:
    engine: str = "modsecurity"
    paranoia_level: int = 2
    rules_enabled: list[str] = field(default_factory=list)
    rules_disabled: list[str] = field(default_factory=list)
    custom_rules: list[str] = field(default_factory=list)
    exclusions: list[str] = field(default_factory=list)
    settings: dict = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "engine": self.engine,
            "paranoia_level": self.paranoia_level,
            "rules_enabled": self.rules_enabled,
            "rules_disabled": self.rules_disabled,
            "custom_rules": self.custom_rules,
            "exclusions": self.exclusions,
            "settings": self.settings,
            "recommendations": self.recommendations,
        }


_GRADE_PL = {"A+": 4, "A": 3, "B+": 3, "B": 2, "C": 2, "D": 1, "F": 1}


class WAFConfigSynthesizer:
    """Combine WAFFEN intelligence into a deployable WAF configuration."""

    def __init__(self):
        self.bypasses: list[dict] = []
        self.rulemap: dict | None = None
        self.benchmark: dict | None = None
        self.fp_data: list[str] = []

    def add_bypasses(self, findings) -> "WAFConfigSynthesizer":
        for f in findings:
            if isinstance(f, dict):
                self.bypasses.append(f)
            elif hasattr(f, "as_dict"):
                self.bypasses.append(f.as_dict())
            else:
                self.bypasses.append(vars(f))
        return self

    def add_rulemap(self, rulemap) -> "WAFConfigSynthesizer":
        if isinstance(rulemap, dict):
            self.rulemap = rulemap
        elif hasattr(rulemap, "as_dict"):
            self.rulemap = rulemap.as_dict()
        else:
            self.rulemap = vars(rulemap)
        return self

    def add_benchmark(self, benchmark) -> "WAFConfigSynthesizer":
        if isinstance(benchmark, dict):
            self.benchmark = benchmark
        elif hasattr(benchmark, "as_dict"):
            self.benchmark = benchmark.as_dict()
        else:
            self.benchmark = vars(benchmark)
        return self

    def add_false_positives(self, fp_list: Sequence[str]) -> "WAFConfigSynthesizer":
        self.fp_data.extend(fp_list)
        return self

    def synthesize(self, engine: str = "modsecurity",
                   target_grade: str = "A") -> WAFConfig:
        cfg = WAFConfig(engine=engine)
        cfg.settings["target_grade"] = target_grade
        cfg.settings["bypass_count"] = len(self.bypasses)

        cfg.paranoia_level = _GRADE_PL.get(target_grade, 2)
        current_pl = 0
        if self.rulemap:
            current_pl = self.rulemap.get("paranoia_level", 0)
        if current_pl and current_pl < cfg.paranoia_level:
            cfg.recommendations.append(
                f"Upgrade paranoia level: PL{current_pl} -> PL{cfg.paranoia_level}"
            )

        from .defend import generate_rules, format_rule, ENGINES as _DEFEND_ENGINES
        if self.bypasses:
            _F = type("F", (), {})
            stubs = []
            for b in self.bypasses:
                f = _F()
                f.payload = b.get("payload", "")
                f.chain = b.get("chain", [])
                f.attack_class = b.get("attack_class", "Unknown")
                f.verified = b.get("verified_exploitable", b.get("verified", None))
                stubs.append(f)
            rule_engine = engine if engine in _DEFEND_ENGINES else "naxsi" if engine == "nginx" else "modsecurity"
            rules = generate_rules(stubs, engine=rule_engine)
            for r in rules:
                cfg.custom_rules.append(format_rule(r))

        if self.rulemap:
            for g in self.rulemap.get("gaps", []):
                rid = g.get("rule_id", g) if isinstance(g, dict) else str(g)
                desc = g.get("description", "") if isinstance(g, dict) else ""
                cfg.rules_enabled.append(str(rid))
                cfg.recommendations.append(f"Enable CRS rule {rid}: {desc}")

        if self.benchmark:
            for cls, data in self.benchmark.get("per_class", {}).items():
                if isinstance(data, dict) and data.get("detection_rate", 1.0) < 0.90:
                    cfg.recommendations.append(
                        f"Low detection for {cls} ({data['detection_rate']:.0%}) — add class-specific rules"
                    )

        for fp in self.fp_data:
            cfg.exclusions.append(_make_exclusion(fp, engine))

        return cfg

    def render(self, config: WAFConfig) -> str:
        if config.engine == "modsecurity":
            return self._render_modsecurity(config)
        elif config.engine == "nginx":
            return self._render_nginx(config)
        return self._render_generic(config)

    def _render_modsecurity(self, cfg: WAFConfig) -> str:
        lines = [
            "# WAFFEN-generated WAF configuration",
            "# Engine: ModSecurity / Coraza",
            f"# Target grade: {cfg.settings.get('target_grade', 'A')}",
            f"# Generated from {cfg.settings.get('bypass_count', 0)} bypass findings",
            "",
            "# ---- CRS Setup ----",
            f'SecAction "id:900000,phase:1,pass,t:none,nolog,'
            f'setvar:tx.paranoia_level={cfg.paranoia_level}"',
            "",
        ]
        if cfg.custom_rules:
            lines.append("# ---- Custom Rules (block discovered bypasses) ----")
            for rule in cfg.custom_rules:
                lines.append(rule)
                lines.append("")
        if cfg.rules_enabled:
            lines.append("# ---- Enable Missing Rules ----")
            for rid in cfg.rules_enabled:
                lines.append(f"SecRuleRemoveById !{rid}  # re-enable")
            lines.append("")
        if cfg.exclusions:
            lines.append("# ---- False Positive Exclusions ----")
            for exc in cfg.exclusions:
                lines.append(exc)
            lines.append("")
        if cfg.recommendations:
            lines.append("# ---- Recommendations ----")
            for rec in cfg.recommendations:
                lines.append(f"# TODO: {rec}")
        return "\n".join(lines)

    def _render_nginx(self, cfg: WAFConfig) -> str:
        lines = [
            "# WAFFEN-generated NGINX WAF configuration",
            f"# Target grade: {cfg.settings.get('target_grade', 'A')}",
            "",
        ]
        if cfg.custom_rules:
            lines.append("# ---- Custom Rules ----")
            for rule in cfg.custom_rules:
                lines.append(rule)
                lines.append("")
        if cfg.exclusions:
            lines.append("# ---- Exclusions ----")
            for exc in cfg.exclusions:
                lines.append(exc)
        return "\n".join(lines)

    def _render_generic(self, cfg: WAFConfig) -> str:
        lines = [
            f"# WAFFEN-generated WAF config ({cfg.engine})",
            f"# Paranoia level: {cfg.paranoia_level}",
            f"# Custom rules: {len(cfg.custom_rules)}",
            f"# Exclusions: {len(cfg.exclusions)}",
            "",
        ]
        for rule in cfg.custom_rules:
            lines.append(rule)
            lines.append("")
        for rec in cfg.recommendations:
            lines.append(f"# {rec}")
        return "\n".join(lines)

    def validate(self, config: WAFConfig) -> list[str]:
        warnings = []
        if config.paranoia_level > 3:
            warnings.append("PL4 has very high false-positive rate — test thoroughly")
        if len(config.custom_rules) > 50:
            warnings.append(f"{len(config.custom_rules)} custom rules — consider consolidating")
        if config.paranoia_level < 2 and config.settings.get("target_grade") in ("A+", "A"):
            warnings.append("Grade A/A+ requires PL3+ for adequate coverage")
        if not config.custom_rules and not config.rules_enabled:
            warnings.append("No rules generated — provide bypass findings or rulemap")
        return warnings


def _make_exclusion(fp_payload: str, engine: str) -> str:
    escaped = re.sub(r"([.*+?^${}()|[\]\\])", r"\\\1", fp_payload[:80])
    if engine == "modsecurity":
        return (
            f'SecRule REQUEST_URI "@rx ^/" "id:999001,phase:1,pass,t:none,nolog,'
            f'ctl:ruleRemoveTargetByTag=waffen;ARGS:{escaped}"'
        )
    elif engine in ("nginx", "naxsi"):
        return f'BasicRule wl:1000 "mz:$ARGS_VAR:q" "str:{escaped}";'
    return f"# Exclude: {escaped}"


def write_config(synthesizer: WAFConfigSynthesizer, config: WAFConfig,
                 out_dir: str) -> list[str]:
    os.makedirs(out_dir, exist_ok=True)
    main_content = synthesizer.render(config)
    main_name = {"modsecurity": "modsecurity.conf", "nginx": "nginx-waf.conf"}.get(
        config.engine, "waf-config.conf")

    files_written = []

    with open(os.path.join(out_dir, main_name), "w") as f:
        f.write(main_content)
    files_written.append(main_name)

    if config.custom_rules:
        path = os.path.join(out_dir, "custom-rules.conf")
        with open(path, "w") as f:
            f.write(f"# WAFFEN custom rules — {len(config.custom_rules)} rule(s)\n\n")
            for rule in config.custom_rules:
                f.write(rule + "\n\n")
        files_written.append("custom-rules.conf")

    if config.exclusions:
        path = os.path.join(out_dir, "exclusions.conf")
        with open(path, "w") as f:
            f.write(f"# WAFFEN FP exclusions — {len(config.exclusions)} exclusion(s)\n\n")
            for exc in config.exclusions:
                f.write(exc + "\n")
        files_written.append("exclusions.conf")

    readme = [
        "# WAFFEN-Generated WAF Configuration", "",
        f"**Engine:** {config.engine}",
        f"**Paranoia level:** {config.paranoia_level}",
        f"**Custom rules:** {len(config.custom_rules)}",
        f"**Exclusions:** {len(config.exclusions)}", "",
        "## Deployment", "",
    ]
    if config.engine == "modsecurity":
        readme.extend([
            "1. Copy `modsecurity.conf` to your ModSecurity config directory",
            "2. Copy `custom-rules.conf` alongside your CRS rules",
            "3. If you have false positives, include `exclusions.conf`",
            "4. Test with `SecRuleEngine DetectionOnly` first",
            "5. Switch to `SecRuleEngine On` after validation",
        ])
    elif config.engine == "nginx":
        readme.extend([
            "1. Include `nginx-waf.conf` in your nginx server block",
            "2. Test with `nginx -t` before reload",
            "3. Monitor logs for false positives",
        ])
    if config.recommendations:
        readme.extend(["", "## Recommendations", ""])
        for rec in config.recommendations:
            readme.append(f"- {rec}")
    with open(os.path.join(out_dir, "README.md"), "w") as f:
        f.write("\n".join(readme) + "\n")
    files_written.append("README.md")

    return files_written


def load_findings_jsonl(path: str) -> list[dict]:
    findings = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            if "findings" in d:
                findings.extend(d["findings"])
            else:
                findings.append(d)
    return findings


def load_rulemap_json(path: str) -> dict:
    with open(path) as f:
        return json.loads(f.read())
