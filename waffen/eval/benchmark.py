"""Standardized WAF benchmark — the "SSL Labs for WAFs."

Scores a WAF's detection rate per attack class + false-positive rate over a
standardized corpus, assigning a letter grade (A+ through F). Produces a
comparable score card and an optional HTML report.

Usage:
    benchmark = WAFBenchmark(target)
    score = benchmark.run()
    print(score.summary())
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Sequence

from ..core.oracle import Oracle, Target, BLOCKED, THROUGH, DOWN
from ..kb.seeds import resolve_class, classes as all_classes


# ---- data classes ----------------------------------------------------------

@dataclass
class ClassScore:
    attack_class: str
    payloads_tested: int = 0
    blocked: int = 0
    passed: int = 0
    down: int = 0
    detection_rate: float = 0.0
    bypasses: list[str] = field(default_factory=list)

    def _calc(self):
        tested = self.blocked + self.passed
        self.detection_rate = self.blocked / tested if tested > 0 else 0.0

    def as_dict(self) -> dict:
        return {
            "attack_class": self.attack_class,
            "payloads_tested": self.payloads_tested,
            "blocked": self.blocked,
            "passed": self.passed,
            "down": self.down,
            "detection_rate": round(self.detection_rate, 4),
            "bypasses": self.bypasses[:20],
        }


@dataclass
class BenchmarkScore:
    waf_name: str = ""
    target_url: str = ""
    timestamp: str = ""
    overall_grade: str = ""
    detection_rate: float = 0.0
    false_positive_rate: float = 0.0
    bypass_count: int = 0
    total_payloads: int = 0
    avg_response_ms: float = 0.0
    per_class: dict[str, ClassScore] = field(default_factory=dict)
    benign_tested: int = 0
    benign_blocked: int = 0
    top_bypasses: list[tuple[str, str]] = field(default_factory=list)
    duration_s: float = 0.0

    def summary(self) -> str:
        lines = [
            f"WAF Benchmark: {self.target_url}",
            "=" * 50,
            f"Overall Grade: {self.overall_grade}",
            f"Detection Rate: {self.detection_rate:.1%}",
            f"False Positive Rate: {self.false_positive_rate:.1%}",
            f"Avg Response: {self.avg_response_ms:.0f}ms",
            f"Total Payloads: {self.total_payloads}",
            f"Bypasses Found: {self.bypass_count}",
            "",
            "Per-Class Breakdown:",
        ]
        for cls, cs in sorted(self.per_class.items()):
            lines.append(
                f"  {cls:20s} {cs.detection_rate:6.1%} "
                f"({cs.passed} bypasses / {cs.payloads_tested} tested)"
            )
        if self.top_bypasses:
            lines.append("")
            lines.append("Top Bypasses:")
            for i, (cls, payload) in enumerate(self.top_bypasses[:10], 1):
                lines.append(f"  {i}. {cls}: {payload[:60]}")
        return "\n".join(lines)

    def as_dict(self) -> dict:
        return {
            "waf_name": self.waf_name,
            "target_url": self.target_url,
            "timestamp": self.timestamp,
            "overall_grade": self.overall_grade,
            "detection_rate": round(self.detection_rate, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "bypass_count": self.bypass_count,
            "total_payloads": self.total_payloads,
            "avg_response_ms": round(self.avg_response_ms, 2),
            "benign_tested": self.benign_tested,
            "benign_blocked": self.benign_blocked,
            "duration_s": round(self.duration_s, 2),
            "per_class": {k: v.as_dict() for k, v in self.per_class.items()},
            "top_bypasses": self.top_bypasses[:20],
        }


# ---- grading ---------------------------------------------------------------

def grade(detection: float, fp_rate: float) -> str:
    if detection >= 0.99 and fp_rate <= 0.01:
        return "A+"
    if detection >= 0.95 and fp_rate <= 0.03:
        return "A"
    if detection >= 0.90 and fp_rate <= 0.05:
        return "A-"
    if detection >= 0.90 and fp_rate <= 0.10:
        return "B+"
    if detection >= 0.85 and fp_rate <= 0.15:
        return "B"
    if detection >= 0.80 and fp_rate <= 0.20:
        return "B-"
    if detection >= 0.75:
        return "C+"
    if detection >= 0.70:
        return "C"
    if detection >= 0.60:
        return "D"
    return "F"


# ---- benign payloads -------------------------------------------------------

BENIGN_PAYLOADS = [
    "hello world",
    "search query",
    "product name 123",
    "john.doe@example.com",
    "New York, USA",
    "2026-11-23",
    "price: $19.99",
    "it's a nice day",
    "50% discount!",
    "red & blue",
    "1 + 1 = 2",
    "C++ programming",
    "rock'n'roll",
    "file.txt",
    "user@domain",
    "What is 2+2?",
    "Order #12345",
    "room 101",
    "(555) 123-4567",
    "https://example.com",
    "SELECT in English means to choose",
    "The <b>bold</b> tag",
    "10% OR more savings",
    "John's pizza",
    "Path: C:\\Users\\file",
    "1,000,000 items",
    "v1.2.3-beta",
    "config.yml",
    "index.html",
    "Robert'; DROP TABLE students;--",
]


# ---- benchmark engine ------------------------------------------------------

DEFAULT_CLASSES = [
    "sqli", "xss", "ssti", "cmdi", "traversal", "ssrf", "xxe",
    "crlf", "nosqli", "ldap", "ssi", "redirect",
]


class WAFBenchmark:
    """Run a standardized WAF benchmark and produce a comparable score card."""

    def __init__(self, target: Target, corpus_classes: Sequence[str] | None = None,
                 sender=None, transport: str = "auto", waf_name: str = ""):
        self.target = target
        self.classes = list(corpus_classes) if corpus_classes else list(DEFAULT_CLASSES)
        self._sender = sender
        self._transport = transport
        self.waf_name = waf_name

    def _oracle(self):
        return Oracle(self.target, sender=self._sender, transport=self._transport)

    def run(self, include_benign: bool = True,
            on_progress=None) -> BenchmarkScore:
        oracle = self._oracle()
        score = BenchmarkScore(
            waf_name=self.waf_name or "Unknown",
            target_url=self.target.url(),
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )
        start = time.time()
        all_times: list[float] = []
        total_blocked = 0
        total_tested = 0
        all_bypasses: list[tuple[str, str]] = []

        for cls_alias in self.classes:
            cls_name = resolve_class(cls_alias)
            payloads = self._get_payloads(cls_name)
            if not payloads:
                continue

            cs = ClassScore(attack_class=cls_name, payloads_tested=len(payloads))
            for payload in payloads:
                resp = oracle.send(payload)
                all_times.append(resp.time * 1000 if resp.time else 0)
                if resp.verdict == BLOCKED:
                    cs.blocked += 1
                elif resp.verdict == THROUGH:
                    cs.passed += 1
                    cs.bypasses.append(payload)
                    all_bypasses.append((cls_name, payload))
                else:
                    cs.down += 1
            cs._calc()
            score.per_class[cls_name] = cs
            total_blocked += cs.blocked
            total_tested += cs.blocked + cs.passed
            if on_progress:
                on_progress(cls_name, cs)

        score.total_payloads = total_tested
        score.detection_rate = total_blocked / total_tested if total_tested > 0 else 0.0
        score.bypass_count = len(all_bypasses)
        score.top_bypasses = all_bypasses[:20]
        score.avg_response_ms = sum(all_times) / len(all_times) if all_times else 0

        if include_benign:
            b_blocked = 0
            for payload in BENIGN_PAYLOADS:
                resp = oracle.send(payload)
                all_times.append(resp.time * 1000 if resp.time else 0)
                if resp.verdict == BLOCKED:
                    b_blocked += 1
            score.benign_tested = len(BENIGN_PAYLOADS)
            score.benign_blocked = b_blocked
            score.false_positive_rate = b_blocked / len(BENIGN_PAYLOADS)
        else:
            score.false_positive_rate = 0.0

        score.overall_grade = grade(score.detection_rate, score.false_positive_rate)
        score.duration_s = time.time() - start
        return score

    def _get_payloads(self, cls_name: str) -> list[str]:
        from ..kb.seeds import seeds_for
        return seeds_for(cls_name, include_corpus=True)


# ---- comparison -----------------------------------------------------------

def compare(a: BenchmarkScore, b: BenchmarkScore) -> str:
    lines = [
        f"{'Metric':<25s} {'WAF A':>12s} {'WAF B':>12s} {'Delta':>10s}",
        "-" * 60,
        f"{'Grade':<25s} {a.overall_grade:>12s} {b.overall_grade:>12s} {'':>10s}",
        f"{'Detection Rate':<25s} {a.detection_rate:>11.1%} {b.detection_rate:>11.1%} "
        f"{(b.detection_rate - a.detection_rate):>+9.1%}",
        f"{'False Positive Rate':<25s} {a.false_positive_rate:>11.1%} {b.false_positive_rate:>11.1%} "
        f"{(b.false_positive_rate - a.false_positive_rate):>+9.1%}",
        f"{'Bypasses':<25s} {a.bypass_count:>12d} {b.bypass_count:>12d} "
        f"{(b.bypass_count - a.bypass_count):>+10d}",
        f"{'Avg Response (ms)':<25s} {a.avg_response_ms:>11.0f} {b.avg_response_ms:>11.0f} "
        f"{(b.avg_response_ms - a.avg_response_ms):>+9.0f}",
    ]
    all_classes_set = set(a.per_class.keys()) | set(b.per_class.keys())
    if all_classes_set:
        lines.append("")
        lines.append("Per-Class Detection Rate:")
        for cls in sorted(all_classes_set):
            a_rate = a.per_class[cls].detection_rate if cls in a.per_class else 0
            b_rate = b.per_class[cls].detection_rate if cls in b.per_class else 0
            lines.append(f"  {cls:22s} {a_rate:>11.1%} {b_rate:>11.1%} {(b_rate-a_rate):>+9.1%}")
    return "\n".join(lines)


# ---- HTML report -----------------------------------------------------------

_GRADE_COLORS = {
    "A+": "#22c55e", "A": "#22c55e", "A-": "#4ade80",
    "B+": "#84cc16", "B": "#eab308", "B-": "#f59e0b",
    "C+": "#f97316", "C": "#f97316",
    "D": "#ef4444", "F": "#dc2626",
}


def generate_html_report(score: BenchmarkScore) -> str:
    gc = _GRADE_COLORS.get(score.overall_grade, "#6b7280")

    class_rows = ""
    for cls, cs in sorted(score.per_class.items()):
        pct = cs.detection_rate * 100
        bar_color = "#22c55e" if pct >= 90 else "#eab308" if pct >= 75 else "#ef4444"
        bypass_list = ""
        if cs.bypasses:
            items = "".join(
                f"<li><code>{_esc(b[:80])}</code></li>" for b in cs.bypasses[:5]
            )
            bypass_list = f'<details><summary>{cs.passed} bypass(es)</summary><ul>{items}</ul></details>'
        class_rows += f"""<tr>
            <td>{_esc(cls)}</td>
            <td>{cs.payloads_tested}</td>
            <td>{cs.blocked}</td>
            <td>{cs.passed}</td>
            <td>
              <div style="display:flex;align-items:center;gap:8px">
                <div style="background:{bar_color};height:14px;width:{pct:.0f}%;max-width:100%;border-radius:3px"></div>
                <span>{pct:.1f}%</span>
              </div>
            </td>
            <td>{bypass_list}</td>
        </tr>"""

    top_bypasses_html = ""
    if score.top_bypasses:
        rows = "".join(
            f"<tr><td>{_esc(cls)}</td><td><code>{_esc(p[:80])}</code></td></tr>"
            for cls, p in score.top_bypasses[:10]
        )
        top_bypasses_html = f"""
        <h2>Top Bypasses</h2>
        <table><thead><tr><th>Class</th><th>Payload</th></tr></thead>
        <tbody>{rows}</tbody></table>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WAF Benchmark — {_esc(score.waf_name)}</title>
<style>
:root {{ --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #f0f6fc; --muted: #8b949e; }}
@media (prefers-color-scheme: light) {{
  :root {{ --bg: #f6f8fa; --card: #fff; --border: #d0d7de; --text: #1f2328; --muted: #656d76; }}
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
       background: var(--bg); color: var(--text); padding: 24px; line-height: 1.5; }}
.container {{ max-width: 900px; margin: 0 auto; }}
.grade-card {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px;
              padding: 32px; text-align: center; margin-bottom: 24px; }}
.grade {{ font-size: 72px; font-weight: 800; color: {gc}; }}
.stats {{ display: flex; justify-content: center; gap: 32px; margin-top: 16px; flex-wrap: wrap; }}
.stat {{ text-align: center; }}
.stat-value {{ font-size: 24px; font-weight: 700; }}
.stat-label {{ font-size: 12px; color: var(--muted); text-transform: uppercase; }}
h2 {{ margin: 24px 0 12px; font-size: 18px; }}
table {{ width: 100%; border-collapse: collapse; background: var(--card);
         border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}
th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border); }}
th {{ font-size: 12px; text-transform: uppercase; color: var(--muted); }}
code {{ background: var(--bg); padding: 2px 6px; border-radius: 4px; font-size: 12px; }}
details summary {{ cursor: pointer; color: var(--muted); font-size: 13px; }}
.footer {{ margin-top: 32px; text-align: center; color: var(--muted); font-size: 13px; }}
@media print {{ body {{ background: #fff; color: #000; }} .grade {{ color: {gc} !important; }} }}
</style>
</head>
<body>
<div class="container">
  <div class="grade-card">
    <div style="font-size:14px;color:var(--muted)">WAF BENCHMARK</div>
    <div style="font-size:18px;margin:4px 0">{_esc(score.waf_name)}</div>
    <div class="grade">{score.overall_grade}</div>
    <div class="stats">
      <div class="stat"><div class="stat-value">{score.detection_rate:.1%}</div><div class="stat-label">Detection</div></div>
      <div class="stat"><div class="stat-value">{score.false_positive_rate:.1%}</div><div class="stat-label">False Positive</div></div>
      <div class="stat"><div class="stat-value">{score.bypass_count}</div><div class="stat-label">Bypasses</div></div>
      <div class="stat"><div class="stat-value">{score.avg_response_ms:.0f}ms</div><div class="stat-label">Avg Response</div></div>
      <div class="stat"><div class="stat-value">{score.total_payloads}</div><div class="stat-label">Payloads</div></div>
    </div>
  </div>

  <h2>Per-Class Detection</h2>
  <table>
    <thead><tr><th>Class</th><th>Tested</th><th>Blocked</th><th>Passed</th><th>Detection Rate</th><th>Details</th></tr></thead>
    <tbody>{class_rows}</tbody>
  </table>

  {top_bypasses_html}

  <div class="footer">
    Generated by WAFFEN Benchmark · {score.timestamp} · {score.duration_s:.1f}s
  </div>
</div>
</body>
</html>"""


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


# ---- I/O -------------------------------------------------------------------

def write_benchmark_json(score: BenchmarkScore, path: str):
    with open(path, "w") as f:
        json.dump(score.as_dict(), f, indent=2, ensure_ascii=False)


def load_benchmark_json(path: str) -> BenchmarkScore:
    with open(path) as f:
        d = json.load(f)
    score = BenchmarkScore(
        waf_name=d.get("waf_name", ""),
        target_url=d.get("target_url", ""),
        timestamp=d.get("timestamp", ""),
        overall_grade=d.get("overall_grade", ""),
        detection_rate=d.get("detection_rate", 0),
        false_positive_rate=d.get("false_positive_rate", 0),
        bypass_count=d.get("bypass_count", 0),
        total_payloads=d.get("total_payloads", 0),
        avg_response_ms=d.get("avg_response_ms", 0),
        benign_tested=d.get("benign_tested", 0),
        benign_blocked=d.get("benign_blocked", 0),
        duration_s=d.get("duration_s", 0),
        top_bypasses=[(b[0], b[1]) for b in d.get("top_bypasses", [])],
    )
    for cls, cd in d.get("per_class", {}).items():
        score.per_class[cls] = ClassScore(
            attack_class=cd.get("attack_class", cls),
            payloads_tested=cd.get("payloads_tested", 0),
            blocked=cd.get("blocked", 0),
            passed=cd.get("passed", 0),
            down=cd.get("down", 0),
            detection_rate=cd.get("detection_rate", 0),
            bypasses=cd.get("bypasses", []),
        )
    return score


def write_html_report(score: BenchmarkScore, path: str):
    html = generate_html_report(score)
    with open(path, "w") as f:
        f.write(html)
