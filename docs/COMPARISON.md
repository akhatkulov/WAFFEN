# WAFFEN vs existing tools — an honest comparison

> Short answer to "is WAFFEN better than every other tool?": **No — not at
> everything, and claiming so would be dishonest.** `sqlmap` exploits SQLi far
> deeper, `wafw00f` names far more WAF vendors, and full scanners (Burp, Nuclei)
> cover far more ground. **But for one specific job — _verified WAF-evasion-path
> research_ — WAFFEN is best-in-class, and the numbers below are real, reproducible
> measurements, not marketing.** Every figure here is backed by [VALIDATION.md](VALIDATION.md).

## What WAFFEN is for

A closed loop for the question **"can this WAF be evaded, by what, and is the evasion
actually exploitable?"**: `fingerprint → calibrate → search → verify → suggest a rule`.
It is not a general web scanner and not a SQLi exploitation framework.

## Capability matrix

Compared against the tools people actually reach for in this space. ✅ strong · ⚠️ partial/caveat · ❌ absent.

| Capability | **WAFFEN** | wafw00f | GoTestWAF | sqlmap |
|---|---|---|---|---|
| Name the WAF vendor | ⚠️ **119** sigs + behavioral fallback | ✅ **150+ WAF DB (best)** | ❌ | ❌ |
| WAF coverage % scoring | ✅ per-class + overall | ❌ | ✅ **de-facto standard** | ❌ |
| False-positive (benign) measurement | ✅ **benign-first, ban-safe** | ❌ | ⚠️ measures, but *after* attacks → self-ban artifact | ❌ |
| Active **guided bypass search** | ✅ **4 strategies** (beam/genetic/bestfirst/mcts) | ❌ | ❌ static corpus only | ⚠️ tamper scripts, SQL-only |
| **Exploitability verification** | ✅ **14 classes** + SQLi extracts a DB-evaluated value | ❌ | ❌ | ✅ SQL only (deepest) |
| Config-tradeoff quantification | ✅ **paranoia gradient** | ❌ | ❌ | ❌ |
| WAF-rule suggestions from findings | ✅ | ❌ | ❌ | ❌ |
| SQLi exploitation depth (dump/OOB/blind) | ⚠️ confirms, doesn't dump | ❌ | ❌ | ✅ **best** |
| Multi-class breadth (XSS/SQL/cmd/SSTI/…) | ✅ | ❌ | ✅ | ❌ SQL only |

**The one row no other tool fills:** *active guided search **×** per-finding exploitability
verification*. That combination is what makes WAFFEN's "bypass" count trustworthy.

## Real, reproducible results (all from VALIDATION.md)

Measured against **four WAFs across two detection models** — the team's RedEye, a local **OWASP
CRS / ModSecurity** lab, **BunkerWeb**, and **NAXSI** (a different, whitelist/scoring model)
([`lab/`](../lab)):

- **Search finds what static lists miss.** Against OWASP CRS paranoia-level 1, single-seed
  testing reads SQLi as "75% blocked" (1 seed through). WAFFEN's search engine found
  **137 distinct _verified_ SQLi evasions** — backslash-escaped quotes, backtick-quoted
  `OR`, zero-width-character insertion, `OR`→`||`, intra-keyword comments, NFKC-fold, exotic
  whitespace. A static payload list cannot discover these.
- **It quantifies the security/usability tradeoff** — the paranoia gradient:

  | CRS paranoia | verified SQLi bypasses found | benign false-positive rate |
  |---|---|---|
  | 1 | 137 | 0% |
  | 2 | 8 | 0% |
  | 3 | **0** | 0% |
  | 4 | 0 | **35%** |

  → a measured recommendation: **PL3** (every SQLi evasion closed, zero benign over-blocking;
  PL4 adds no SQLi protection yet blocks 35% of benign traffic). No other tool outputs this.

- **Verification kills false "bypasses".** On the CRS login SQLi, **1178** raw payloads got
  *through* the WAF; only **14** were verified to actually reach the database — WAFFEN reports
  14, every other tool would report 1178. On XSS, dozens of double-URL-encoded payloads evade
  CRS but land as inert text (HTTP 500) → WAFFEN verifies **0** as exploitable.
- **Honest false-positive measurement.** WAFFEN measures benign traffic *before* the attack
  flood, so a mid-run ban can't corrupt it. On RedEye, GoTestWAF reported **0% true-negative
  (141/141 benign "blocked")** — a self-ban artifact from measuring benign *after* 674 attacks;
  WAFFEN's benign-first ordering avoids exactly that.
- **Fingerprint beats the generic fallback where it can.** On RedEye, WAFFEN **named the WAF**
  (confidence 1.00) where wafw00f could only say "behind a WAF". On CRS-behind-nginx (no vendor
  signature) both fall back to generic — WAFFEN honestly reports `Generic/Unknown WAF`.
- **Two transports, proven equivalent.** `--transport pooled` (keep-alive) returned identical
  verdict/status to curl on 8/8 inject-mode checks, at ~1.6× the speed.

## Where WAFFEN is **not** the best tool (honest)

- **Vendor identification breadth** → **wafw00f** still leads (150+ signature DB vs WAFFEN's
  119 — up from 9; the +71 were ported straight from wafw00f's plugins), though WAFFEN's
  behavioral fallback also flags an inline WAF even when no signature matches.
- **Actually exploiting a SQLi** (dumping tables, OOB, deep blind) → use **sqlmap**. WAFFEN now
  *extracts a DB-evaluated proof value* (confirmed-with-evidence, not just "injectable"), but it is
  a verifier, not a data-exfiltration engine.
- **Broad vulnerability scanning** beyond evasion research → use **Burp Suite / Nuclei**.
- **A large standardized scoring corpus** → **GoTestWAF** ships one; WAFFEN's KB (181 seeds
  across 14 classes, up from 47) feeds the *search*, and it can harvest PayloadsAllTheThings,
  but that isn't a single curated-for-scoring corpus.
- **Scale of validation** → proven on **4** WAFs across **2 detection models**: RedEye + OWASP
  CRS + BunkerWeb (regex blacklist / anomaly-scoring) **and NAXSI** (whitelist/scoring — a
  genuinely different model, where WAFFEN measured a visibly different per-class profile, e.g.
  SSTI 50% vs CRS's 83–100%). Still not dozens, and no ML/semantic WAF (e.g. SafeLine) yet;
  transport is curl/http.client (no HTTP/2, no headless browser).

## Known limitations surfaced by self-audit (honest)

Beyond the head-to-head gaps above, a critical self-audit found these — stated plainly so the
numbers above aren't over-read:

- **All 14 verifier classes are now live-validated.** The 5 newer ones (XXE, SSRF, LDAP, SSI,
  Open Redirect) were initially unit-only — Juice Shop hardens (`/redirect` → 406) or lacks those
  sinks — so a purpose-built vulnerable sink app (`lab/vuln_sinks.py`) now exercises each end-to-end
  through the real verifier (real curl), confirming all five (0.60–0.90 confidence) with a
  no-false-positive check (`tests/test_verifier_live_sinks.py`). The confidence ceilings stay
  honest: SSRF caps at 0.60 (in-band only), XXE at 0.75 (proves parsing, not file read).
- **The 119 fingerprints are a wafw00f port tested on synthetic responses** — not yet matched
  against live traffic from each vendor, so a real deployment could differ in header casing/order.
- **The SQLi data-extraction channel (0.95) isn't live-proven** — on the error-leaking Juice Shop
  endpoint the error-signature channel confirms first, so extraction is exercised only by unit
  tests (for error-suppressed targets).
- **The 4 search strategies are now benchmarked** (`docs/VALIDATION.md` §6.11): head-to-head on
  CRS, **genetic** is the most efficient (581 bypasses / 1k requests, fastest) and **MCTS** the
  most thorough (1021 found); the benchmark also surfaced and fixed an `OverflowError` crash in
  best-first's bandit reward. Beam remains a solid default; pick genetic for budget-limited runs.
- **The self-updating KB ships no sources** (`kb-update`): the mechanism is real but there is no
  public WAFFEN KB yet, so auto-update is roadmap, not a working feature today.
- **Ban detection is real-time only at `--concurrency 1`.** Above that it is a single post-batch
  probe (added after the audit); unattended full-corpus runs should still prefer `--concurrency 1`.

## Bottom line

WAFFEN is **the strongest tool for verified WAF-evasion-path research specifically** — it is
the only one that *searches* for evasions **and** *proves* each one exploitable **and** measures
false positives without self-banning **and** turns the result into a config recommendation and
WAF rules. It does **not** replace sqlmap, wafw00f, or a full scanner; it's sharpest used
alongside them. Claims above are measured, with caveats stated — that honesty is itself the
point: a tool whose "bypass" count you can trust.
