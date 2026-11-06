"""Render a WAFFEN eval result to a self-contained, styled HTML report.

No external dependencies; inline CSS with light/dark support. Payloads are HTML-
escaped (they contain live attack strings). This is a file the `eval` command
writes to disk, not a published page.
"""
from __future__ import annotations

import datetime as _dt
import html as _html
from pathlib import Path


def _bar(pct: float) -> str:
    pct = max(0.0, min(100.0, pct))
    cls = "good" if pct >= 90 else ("mid" if pct >= 60 else "bad")
    return (f'<div class="bar"><div class="fill {cls}" style="width:{pct:.1f}%"></div>'
            f'<span class="pct">{pct:.1f}%</span></div>')


def render_eval_html(result, meta: dict | None = None) -> str:
    meta = meta or {}
    o = result.overall
    ts = _dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    fp = result.fp_rate
    fp_cls = "good" if fp == 0 else ("mid" if fp <= 5 else "bad")

    rows = []
    for cls in sorted(result.per_class, key=lambda c: result.per_class[c].coverage):
        s = result.per_class[cls]
        rows.append(
            f"<tr><td class='cls'>{_html.escape(cls)}</td>"
            f"<td class='barcell'>{_bar(s.coverage)}</td>"
            f"<td class='n blocked'>{s.blocked}</td><td class='n through'>{s.through}</td>"
            f"<td class='n'>{s.unresolved}</td><td class='n'>{s.down}</td></tr>"
        )

    gaps = []
    for cls, samples in result.through_samples.items():
        if not samples:
            continue
        items = "".join(f"<li><code>{_html.escape(p)}</code></li>" for p in samples)
        gaps.append(f"<details><summary>{_html.escape(cls)} "
                    f"<span class='count'>{len(samples)} gap sample(s)</span></summary>"
                    f"<ul>{items}</ul></details>")
    gaps_html = "".join(gaps) or "<p class='muted'>No coverage gaps recorded.</p>"

    meta_bits = " · ".join(
        f"{_html.escape(str(k))}: {_html.escape(str(v))}" for k, v in meta.items() if v
    )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WAFFEN — WAF Coverage Report</title>
<style>
:root {{
  --bg:#f7f7f9; --card:#fff; --ink:#1a1a1f; --muted:#6b7280; --line:#e5e7eb;
  --accent:#d4213d; --good:#16a34a; --mid:#d97706; --bad:#dc2626; --track:#eceef2;
}}
@media (prefers-color-scheme: dark) {{ :root:not([data-theme=light]) {{
  --bg:#0d0e12; --card:#15171e; --ink:#e7e9ee; --muted:#8b92a1; --line:#242733;
  --accent:#ff4d64; --good:#22c55e; --mid:#f59e0b; --bad:#ef4444; --track:#20232d;
}} }}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;padding:24px 16px}}
.wrap{{max-width:900px;margin:0 auto}}
.brand{{display:flex;align-items:center;gap:12px;margin-bottom:4px}}
.logo{{font:700 22px/1 ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--accent);letter-spacing:1px}}
.eye{{color:var(--accent)}}
.sub{{color:var(--muted);font-size:13px;margin:0 0 20px}}
.cards{{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:20px}}
@media (max-width:560px){{.cards{{grid-template-columns:1fr}}}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px}}
.card h2{{margin:0 0 10px;font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}}
.big{{font:700 34px/1 ui-sans-serif,system-ui;margin-bottom:10px}}
.big.good{{color:var(--good)}} .big.mid{{color:var(--mid)}} .big.bad{{color:var(--bad)}}
.bar{{position:relative;height:22px;background:var(--track);border-radius:6px;overflow:hidden}}
.fill{{position:absolute;inset:0 auto 0 0;border-radius:6px}}
.fill.good{{background:var(--good)}} .fill.mid{{background:var(--mid)}} .fill.bad{{background:var(--bad)}}
.pct{{position:absolute;right:8px;top:0;line-height:22px;font-size:12px;font-weight:600;
  color:var(--ink);mix-blend-mode:difference}}
table{{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);
  border-radius:12px;overflow:hidden}}
th,td{{padding:10px 12px;text-align:left;border-bottom:1px solid var(--line);font-size:14px}}
th{{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}}
tr:last-child td{{border-bottom:none}}
td.n{{text-align:right;font-variant-numeric:tabular-nums;color:var(--muted);width:60px}}
td.n.blocked{{color:var(--good);font-weight:600}} td.n.through{{color:var(--mid);font-weight:600}}
td.cls{{font-weight:600}} td.barcell{{width:46%}}
h3{{margin:26px 0 10px;font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}}
details{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 14px;margin-bottom:8px}}
summary{{cursor:pointer;font-weight:600}}
.count{{color:var(--muted);font-weight:400;font-size:12px}}
code{{font:13px/1.5 ui-monospace,Menlo,monospace;word-break:break-all}}
ul{{margin:10px 0 2px;padding-left:18px}} li{{margin:3px 0}}
.muted{{color:var(--muted)}}
footer{{margin-top:28px;color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:14px}}
</style></head>
<body><div class="wrap">
  <div class="brand"><span class="logo">WAFFEN</span><span class="eye">( ◉ )</span></div>
  <p class="sub">WAF Coverage Report · {_html.escape(result.target)} · {ts}{(' · ' + meta_bits) if meta_bits else ''}</p>

  <div class="cards">
    <div class="card"><h2>Overall coverage</h2>
      <div class="big {'good' if o.coverage>=90 else ('mid' if o.coverage>=60 else 'bad')}">{o.coverage:.1f}%</div>
      {_bar(o.coverage)}
      <p class="muted" style="margin:10px 0 0;font-size:13px">blocked {o.blocked} · gap {o.through} · unresolved {o.unresolved} · down {o.down}</p>
    </div>
    <div class="card"><h2>False positives</h2>
      <div class="big {fp_cls}">{fp:.1f}%</div>
      {_bar(100 - fp)}
      <p class="muted" style="margin:10px 0 0;font-size:13px">{result.benign_blocked} of {result.benign_total} benign requests wrongly blocked</p>
    </div>
  </div>

  <table>
    <thead><tr><th>Attack class</th><th>Coverage</th><th>Blk</th><th>Gap</th><th>Unr</th><th>Down</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>

  <h3>Coverage gaps (payloads that reached origin)</h3>
  {gaps_html}

  <footer>Generated by WAFFEN — WAF evasion-path finder. Authorized-testing use only.
  “Coverage” = blocked / (blocked + gap). Gap payloads reached the origin and warrant a WAF rule review.</footer>
</div></body></html>"""


def write_eval_html(result, path: str, meta: dict | None = None) -> None:
    Path(path).write_text(render_eval_html(result, meta), encoding="utf-8")
