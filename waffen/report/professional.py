"""Professional HTML report generation for pentest deliverables.

Generates a styled, print-friendly HTML report from WAFFEN findings.
Pure stdlib — no external dependencies. Open in browser and print to PDF.
"""
from __future__ import annotations

import html
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Sequence

from .. import __version__

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class ReportConfig:
    title: str = "WAF Bypass Assessment Report"
    author: str = "WAFFEN Automated Assessment"
    target: str = ""
    date: str = ""
    classification: str = "CONFIDENTIAL"

    def __post_init__(self):
        if not self.date:
            self.date = datetime.now().strftime("%Y-%m-%d")


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

_CRITICAL_CLASSES = frozenset({"SQL Injection", "Command Injection", "sqli", "cmdi"})

def severity(finding) -> str:
    ac = _get(finding, "attack_class", "")
    verified = _get(finding, "verified", None) or _get(finding, "verified_exploitable", None)
    code = str(_get(finding, "code", "") or _get(finding, "http_code", ""))
    if verified and ac in _CRITICAL_CLASSES:
        return "CRITICAL"
    if verified:
        return "HIGH"
    if code in ("500", "502"):
        return "MEDIUM"
    return "LOW"


_SEV_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#ca8a04",
    "LOW": "#2563eb",
    "INFO": "#6b7280",
}


def _get(obj, key, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


# ---------------------------------------------------------------------------
# HTML building helpers
# ---------------------------------------------------------------------------

def _esc(text) -> str:
    return html.escape(str(text)) if text else ""


def _sev_badge(sev: str) -> str:
    color = _SEV_COLORS.get(sev, "#6b7280")
    return (f'<span class="sev-badge" style="background:{color}">'
            f'{_esc(sev)}</span>')


def _code_block(text: str) -> str:
    return f'<pre class="code">{_esc(text)}</pre>'


def _collapsible(title: str, body: str, open_: bool = False) -> str:
    o = " open" if open_ else ""
    return (f'<details{o}><summary class="collapse-title">{title}</summary>'
            f'<div class="collapse-body">{body}</div></details>')


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _section_executive(findings: list, config: ReportConfig) -> str:
    sevs = [severity(f) for f in findings]
    crit = sevs.count("CRITICAL")
    high = sevs.count("HIGH")
    med = sevs.count("MEDIUM")
    low = sevs.count("LOW")
    verified = sum(1 for f in findings
                   if _get(f, "verified") or _get(f, "verified_exploitable"))

    if crit:
        risk = "CRITICAL"
    elif high:
        risk = "HIGH"
    elif med:
        risk = "MEDIUM"
    elif low:
        risk = "LOW"
    else:
        risk = "INFO"

    summary_text = (
        f"WAFFEN assessed the WAF at <strong>{_esc(config.target)}</strong> "
        f"on {_esc(config.date)}. "
        f"The assessment identified <strong>{len(findings)}</strong> finding(s), "
        f"of which <strong>{verified}</strong> were verified as exploitable. "
    )
    if crit:
        summary_text += (
            f"<strong>{crit} critical-severity bypass(es)</strong> were confirmed, "
            "indicating the WAF can be fully circumvented for high-impact attack classes. "
            "Immediate remediation is recommended."
        )
    elif high:
        summary_text += (
            f"{high} high-severity finding(s) indicate exploitable bypasses. "
            "Prompt rule updates are recommended."
        )
    elif verified:
        summary_text += "Verified bypasses were found at medium or low severity."
    else:
        summary_text += (
            "No verified-exploitable bypasses were found. "
            "The WAF appears to hold against the tested payload corpus, "
            "though coverage gaps may exist outside the tested classes."
        )

    return f"""
    <section id="executive">
      <h2>1. Executive Summary</h2>
      <table class="summary-table">
        <tr><td class="label">Target</td><td>{_esc(config.target)}</td></tr>
        <tr><td class="label">Date</td><td>{_esc(config.date)}</td></tr>
        <tr><td class="label">Overall Risk</td><td>{_sev_badge(risk)}</td></tr>
        <tr><td class="label">Total Findings</td><td>{len(findings)}</td></tr>
        <tr><td class="label">Verified Exploitable</td><td><strong>{verified}</strong></td></tr>
        <tr><td class="label">Critical</td><td>{crit}</td></tr>
        <tr><td class="label">High</td><td>{high}</td></tr>
        <tr><td class="label">Medium</td><td>{med}</td></tr>
        <tr><td class="label">Low</td><td>{low}</td></tr>
      </table>
      <p class="summary-text">{summary_text}</p>
    </section>"""


def _section_methodology(config: ReportConfig) -> str:
    return f"""
    <section id="methodology">
      <h2>2. Methodology</h2>
      <p>This assessment was performed using <strong>WAFFEN v{_esc(__version__)}</strong>,
      a WAF evaluation and bypass-research toolkit. The tool employs guided search
      strategies (beam search, genetic algorithm, MCTS, adaptive multi-stage pipeline)
      to discover evasion paths through WAF defenses.</p>
      <table class="summary-table">
        <tr><td class="label">Tool</td><td>WAFFEN v{_esc(__version__)}</td></tr>
        <tr><td class="label">Author</td><td>{_esc(config.author)}</td></tr>
        <tr><td class="label">Approach</td>
            <td>Mutation-chain search + request-transform sweep + semantic verification</td></tr>
        <tr><td class="label">Axes</td><td>231 payload mutators &times; 26 request transforms</td></tr>
      </table>
    </section>"""


def _section_findings(findings: list) -> str:
    if not findings:
        return """
        <section id="findings">
          <h2>3. Findings</h2>
          <p class="no-findings">No bypass findings were recorded.</p>
        </section>"""

    rows = []
    for i, f in enumerate(findings, 1):
        sev = severity(f)
        ac = _esc(_get(f, "attack_class", "?"))
        payload = _esc(_get(f, "payload", ""))
        chain_raw = _get(f, "chain", [])
        chain = " &rarr; ".join(_esc(c) for c in chain_raw) if chain_raw else "<em>raw</em>"
        code = _esc(_get(f, "code", "") or _get(f, "http_code", ""))
        verified = _get(f, "verified") or _get(f, "verified_exploitable")
        v_tag = "Yes" if verified else ("No" if verified is False else "N/A")
        transform = _esc(_get(f, "request_transform", "identity"))
        confidence = _get(f, "confidence", None) or _get(f, "verify_confidence", None)
        reason = _esc(_get(f, "verify_reason", "") or "")

        detail = f"""
        <div class="finding-detail">
          <table class="finding-table">
            <tr><td class="label">Attack Class</td><td>{ac}</td></tr>
            <tr><td class="label">HTTP Code</td><td><code>{code}</code></td></tr>
            <tr><td class="label">Mutation Chain</td><td><code>{chain}</code></td></tr>
            <tr><td class="label">Transform</td><td><code>{transform}</code></td></tr>
            <tr><td class="label">Verified</td><td>{v_tag}</td></tr>
            {"<tr><td class='label'>Confidence</td><td>" + f"{confidence:.0%}" + "</td></tr>" if confidence else ""}
            {"<tr><td class='label'>Reason</td><td>" + reason + "</td></tr>" if reason else ""}
          </table>
          <p class="payload-label">Payload:</p>
          {_code_block(payload)}
        </div>"""

        title = f"{_sev_badge(sev)} Finding #{i}: {ac}"
        rows.append(_collapsible(title, detail, open_=(i <= 5)))

    return f"""
    <section id="findings">
      <h2>3. Findings ({len(findings)})</h2>
      {"".join(rows)}
    </section>"""


def _section_recommendations(findings: list) -> str:
    classes_seen = set()
    for f in findings:
        ac = _get(f, "attack_class", "")
        if ac:
            classes_seen.add(ac)

    recs = [
        "<li>Review and update WAF rules for each bypassed attack class.</li>",
        "<li>Deploy rules generated by <code>waffen defend</code> for immediate coverage.</li>",
        "<li>Enable recursive URL decoding and body decompression in the WAF.</li>",
        "<li>Add SQLite/PostgreSQL/MySQL-specific keyword detection if the backend uses those engines.</li>",
        "<li>Set up <code>waffen watch</code> for continuous regression monitoring after rule updates.</li>",
        "<li>Re-test with <code>waffen bypass --verify</code> after applying fixes to confirm closure.</li>",
    ]
    if "SQL Injection" in classes_seen or "sqli" in classes_seen:
        recs.insert(0, "<li><strong>Critical:</strong> SQL injection bypasses require immediate rule patching. "
                       "Consider adding parameterized query enforcement at the application layer as defense in depth.</li>")
    if "XSS Injection" in classes_seen or "xss" in classes_seen:
        recs.insert(1, "<li><strong>High:</strong> XSS bypasses indicate incomplete HTML/JS sanitization rules. "
                       "Review Content-Security-Policy headers alongside WAF rules.</li>")

    return f"""
    <section id="recommendations">
      <h2>4. Recommendations</h2>
      <ul class="rec-list">
        {"".join(recs)}
      </ul>
    </section>"""


def _section_appendix(findings: list) -> str:
    if not findings:
        return ""
    payloads = []
    for i, f in enumerate(findings, 1):
        p = _esc(_get(f, "payload", ""))
        sev = severity(f)
        payloads.append(f"<tr><td>{i}</td><td>{_sev_badge(sev)}</td>"
                        f"<td><code>{p}</code></td></tr>")

    return f"""
    <section id="appendix">
      <h2>5. Appendix — Full Payload List</h2>
      <table class="payload-table">
        <thead><tr><th>#</th><th>Severity</th><th>Payload</th></tr></thead>
        <tbody>{"".join(payloads)}</tbody>
      </table>
    </section>"""


# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

_CSS = """
:root {
  --bg: #ffffff; --fg: #1a1a2e; --muted: #6b7280;
  --border: #e5e7eb; --card-bg: #f9fafb;
  --accent: #dc2626; --code-bg: #f3f4f6;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0f172a; --fg: #e2e8f0; --muted: #94a3b8;
    --border: #334155; --card-bg: #1e293b;
    --accent: #ef4444; --code-bg: #1e293b;
  }
}
@media print {
  :root { --bg: #fff; --fg: #000; --card-bg: #fff; --code-bg: #f5f5f5; --border: #ccc; }
  body { font-size: 10pt; }
  .no-print { display: none !important; }
  details { break-inside: avoid; }
  details[open] summary ~ * { break-inside: avoid; }
  section { break-before: auto; }
  @page { margin: 2cm; @bottom-center { content: "Page " counter(page) " of " counter(pages); } }
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  background: var(--bg); color: var(--fg);
  line-height: 1.6; padding: 40px; max-width: 960px; margin: 0 auto;
}
.banner {
  background: var(--accent); color: #fff; text-align: center;
  padding: 4px 0; font-size: 11px; font-weight: 700; letter-spacing: 2px;
  margin-bottom: 24px;
}
h1 { font-size: 28px; margin-bottom: 4px; }
.subtitle { color: var(--muted); font-size: 14px; margin-bottom: 32px; }
h2 {
  font-size: 20px; border-bottom: 2px solid var(--accent);
  padding-bottom: 6px; margin: 32px 0 16px;
}
.summary-table { width: 100%; border-collapse: collapse; margin: 12px 0; }
.summary-table td { padding: 8px 12px; border-bottom: 1px solid var(--border); }
.summary-table .label { font-weight: 600; width: 200px; color: var(--muted); }
.sev-badge {
  display: inline-block; padding: 2px 10px; border-radius: 4px;
  color: #fff; font-size: 12px; font-weight: 700; letter-spacing: 0.5px;
}
.code {
  background: var(--code-bg); border: 1px solid var(--border);
  border-radius: 4px; padding: 10px 14px; font-family: "SF Mono", "Fira Code", monospace;
  font-size: 13px; overflow-x: auto; white-space: pre-wrap; word-break: break-all;
}
.collapse-title {
  cursor: pointer; padding: 10px 14px; background: var(--card-bg);
  border: 1px solid var(--border); border-radius: 6px; margin: 8px 0 0;
  font-size: 14px; list-style: none;
}
.collapse-title::-webkit-details-marker { display: none; }
.collapse-title::before { content: "▸ "; color: var(--muted); }
details[open] > .collapse-title::before { content: "▾ "; }
.collapse-body { padding: 12px 14px; border: 1px solid var(--border); border-top: 0; border-radius: 0 0 6px 6px; }
.finding-table { width: 100%; border-collapse: collapse; }
.finding-table td { padding: 6px 10px; border-bottom: 1px solid var(--border); font-size: 13px; }
.finding-table .label { font-weight: 600; width: 160px; color: var(--muted); }
.payload-label { margin-top: 10px; font-weight: 600; font-size: 13px; }
.rec-list { margin-left: 20px; }
.rec-list li { margin-bottom: 8px; }
.payload-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.payload-table th, .payload-table td { padding: 6px 10px; border: 1px solid var(--border); text-align: left; }
.payload-table th { background: var(--card-bg); font-weight: 600; }
.no-findings { color: var(--muted); font-style: italic; }
.summary-text { margin-top: 16px; line-height: 1.7; }
.footer { margin-top: 40px; border-top: 1px solid var(--border); padding-top: 12px; color: var(--muted); font-size: 12px; text-align: center; }
.toc { margin: 16px 0; }
.toc a { color: var(--fg); text-decoration: none; }
.toc a:hover { text-decoration: underline; }
.toc li { margin: 4px 0; }
"""


# ---------------------------------------------------------------------------
# Main generators
# ---------------------------------------------------------------------------

def generate_html_report(findings: list, config: ReportConfig | None = None) -> str:
    cfg = config or ReportConfig()
    toc = """
    <nav class="toc">
      <strong>Table of Contents</strong>
      <ol>
        <li><a href="#executive">Executive Summary</a></li>
        <li><a href="#methodology">Methodology</a></li>
        <li><a href="#findings">Findings</a></li>
        <li><a href="#recommendations">Recommendations</a></li>
        <li><a href="#appendix">Appendix</a></li>
      </ol>
    </nav>"""

    body = (
        f'<div class="banner">{_esc(cfg.classification)}</div>\n'
        f'<h1>{_esc(cfg.title)}</h1>\n'
        f'<p class="subtitle">{_esc(cfg.target)} &mdash; {_esc(cfg.date)} &mdash; '
        f'WAFFEN v{_esc(__version__)}</p>\n'
        f'{toc}\n'
        f'{_section_executive(findings, cfg)}\n'
        f'{_section_methodology(cfg)}\n'
        f'{_section_findings(findings)}\n'
        f'{_section_recommendations(findings)}\n'
        f'{_section_appendix(findings)}\n'
        f'<div class="footer">{_esc(cfg.classification)} &mdash; '
        f'Generated by WAFFEN v{_esc(__version__)} &mdash; {_esc(cfg.date)}</div>\n'
    )

    return (
        '<!DOCTYPE html>\n<html lang="en">\n<head>\n'
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f'<title>{_esc(cfg.title)}</title>\n'
        f'<style>{_CSS}</style>\n'
        f'</head>\n<body>\n{body}</body>\n</html>'
    )


def generate_summary_card(findings: list, config: ReportConfig | None = None) -> str:
    cfg = config or ReportConfig()
    sevs = [severity(f) for f in findings]
    verified = sum(1 for f in findings
                   if _get(f, "verified") or _get(f, "verified_exploitable"))

    risk = "INFO"
    for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if s in sevs:
            risk = s
            break

    top_findings = ""
    for i, f in enumerate(findings[:10], 1):
        sev = severity(f)
        ac = _esc(_get(f, "attack_class", "?"))
        p = _esc(str(_get(f, "payload", ""))[:50])
        top_findings += (f'<tr><td>{_sev_badge(sev)}</td><td>{ac}</td>'
                         f'<td><code>{p}</code></td></tr>')

    return (
        '<!DOCTYPE html>\n<html lang="en">\n<head>\n'
        '<meta charset="utf-8">\n'
        f'<title>{_esc(cfg.title)} — Summary</title>\n'
        f'<style>{_CSS} body {{ max-width: 700px; }}</style>\n'
        '</head>\n<body>\n'
        f'<div class="banner">{_esc(cfg.classification)}</div>\n'
        f'<h1>{_esc(cfg.title)}</h1>\n'
        f'<p class="subtitle">Summary Card &mdash; {_esc(cfg.target)} &mdash; {_esc(cfg.date)}</p>\n'
        f'<table class="summary-table">'
        f'<tr><td class="label">Risk</td><td>{_sev_badge(risk)}</td></tr>'
        f'<tr><td class="label">Findings</td><td>{len(findings)}</td></tr>'
        f'<tr><td class="label">Verified</td><td><strong>{verified}</strong></td></tr>'
        f'</table>\n'
        f'<h2>Top Findings</h2>\n'
        f'<table class="payload-table"><thead><tr><th>Severity</th><th>Class</th>'
        f'<th>Payload</th></tr></thead><tbody>{top_findings}</tbody></table>\n'
        f'<div class="footer">WAFFEN v{_esc(__version__)} &mdash; {_esc(cfg.date)}</div>\n'
        '</body>\n</html>'
    )


def write_html_report(html_str: str, path: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(html_str, encoding="utf-8")


def load_findings_jsonl(path: str) -> list[dict]:
    findings = []
    with open(path) as f:
        for line in f:
            if line.strip():
                findings.append(json.loads(line))
    return findings
