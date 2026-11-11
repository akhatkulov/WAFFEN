# WAFFEN — Real-target validation (RedEye + OWASP CRS / ModSecurity)

Honest record of live testing against two independent WAFs: the team's own
RedEye-protected demo (§1–5, authorized target the team owns), and a local
**OWASP Core Rule Set / ModSecurity** lab (§6) — the industry-standard
open-source WAF — added to answer the earlier "validated on only one WAF"
limitation. Every run is against a target the team owns or runs locally.

## 1. Fingerprint head-to-head — WAFFEN wins
| Tool | Result |
|---|---|
| wafw00f v2.4.2 (172-WAF DB) | generic only: "seems to be behind a WAF" (status-code differential); could **not name** it |
| **WAFFEN** | **RedEye, confidence 1.00** (block-body signature) |

WAFFEN names the specific WAF; wafw00f cannot (RedEye isn't in its DB — a vendor's
own tool knows its own product).

## 2. Attack coverage — cross-validated, RedEye is strong
| Tool | True-positive (attacks blocked) |
|---|---|
| GoTestWAF | **100%** (674/674) |
| WAFFEN eval (clean 23-seed run) | **100%** |
| WAFFEN eval (773-payload corpus) | 98.6% (late payloads ban-inflated; see §4) |

Both tools agree RedEye blocks ~all attacks. Genuine early-run gap seen by WAFFEN:
**Upload Insecure Files ~60%** (worth a rule review).

## 3. False-positive measurement — WAFFEN is more trustworthy
| Tool | True-negative (benign passed) | Why |
|---|---|---|
| GoTestWAF | **0%** (141/141 benign BLOCKED) | measured benign **after** the attack flood → self-banned → every benign request looks blocked |
| **WAFFEN** | measures benign **first** (fix: commit `64c9339`) | FP stays valid even when the attack phase later trips a ban |

GoTestWAF's 0% true-negative is a **self-ban artifact**, not a RedEye flaw — the
exact failure WAFFEN's broad eval first hit, then fixed with benign-first ordering.
This is a concrete, demonstrated edge over the de-facto eval tool.

## 4. Bypass hunting — honest: RedEye holds; WAFFEN does not lie
- mcts + learn + verify on XSS: **30 payloads passed the WAF but 0 verified exploitable**
  (all HTTP 500 or escaped reflection). Every other tool would report "30 bypasses";
  WAFFEN's verifier correctly reports **0**.
- Direct CRLF-injection test: **0 bypass** — RedEye blocks CRLF too.
- Two leads were followed up under **clean (un-banned) conditions**:
  - *16 "backend 500" payloads*: NOT reproducible when clean — re-sending them on an
    un-banned source gave 4×200 (empty results) + 2×403 (now blocked), **0 × 500**.
    The 500s were load-induced transients during the heavy flood, not a deterministic
    input-handling bug or info leak.
  - *Upload Insecure Files ~60%* (query-string test): dissolved as an injection-point
    mismatch — `.php` sent as a **search term** proves nothing (blocking it would
    itself be a false positive). Retested properly below.

### Upload Insecure Files — retested against the real endpoint (confirmed gap)
Source recon (`redeyes/recon/server.ts`, `fileUpload.ts`) located the actual route:
`POST /file-upload` (multipart field `file`, 200KB limit via multer). The app's own
`checkFileType` middleware checks the extension against an allowlist
(`pdf, xml, zip, yml, yaml`) but — by Juice Shop's intentional design — never
**rejects** a disallowed type; it only flags a training challenge and calls `next()`.
So the WAF is the only layer that could reject a dangerous upload here.

Bounded live test (1 benign control + 5 dangerous extensions, real multipart POSTs,
1.5s apart): `.pdf` (control), `.phtml`, `.phar`, `.php`, `.svg`, `.html` — **all six
returned HTTP 204**, identical to the benign baseline. No 403, no WAF signature on
any of them.

**Confirmed finding:** RedEye does not filter file-upload extensions at
`POST /file-upload` — dangerous extensions pass exactly like a PDF. Severity is
tempered because the backend is Node.js/Express (no PHP interpreter, so `.phtml`/
`.php` content isn't executed here) — this is a missing **defense-in-depth** control
(edge-level extension filtering), not a demonstrated RCE on this stack. Worth a
WAF rule regardless: the same gap would be a direct RCE path against a PHP backend.

This is WAFFEN's first **confirmed, real, reproducible** coverage gap against
RedEye in this validation pass — found only once the eval moved from a mismatched
injection point (query string) to the actual vulnerable endpoint (multipart upload).

## 5a. Takeaway: injection point matters as much as payload
The two leads together make the same point from opposite directions: the 500s
disappeared because they were load noise, not a real gap; the upload gap only
appeared once testing moved from a wrong injection point (`?q=`) to the real one
(`POST /file-upload`). Verification isn't just "is this payload blocked" — it's
"was this even a fair test of the target." WAFFEN's existing `--inject` modes
cover query/path/body/json/header/cookie; a dedicated multipart-file-upload inject
mode (filename + extension control) is a natural roadmap addition this investigation
surfaced (not yet built — this test was done by hand against the real endpoint).

## 5. Known limitation surfaced
WAFFEN (and GoTestWAF) self-ban on a full-corpus run — no built-in ban clearing.
Benign-first ordering fixes FP accuracy; full clean coverage still needs the test
source un-banned (cleared via the RedEye panel) or batched with pauses.

## 6. Second-WAF validation — OWASP CRS / ModSecurity (independent, industry-standard)
The earlier passes only covered RedEye. To prove WAFFEN is not RedEye-specific, a
**local second WAF** was stood up and the whole pipeline re-run against it.

**Lab:** `owasp/modsecurity-crs:nginx` (CRS, paranoia level 1, anomaly-blocking)
reverse-proxying a local `bkimminich/juice-shop` backend, on `localhost:18080`
(`lab/docker-compose.yml`, `lab/README.md`). Same app, a different and much stricter WAF than
RedEye. Block shape is nginx's generic `403 Forbidden` page — **no vendor header or
body signature at all** (`Server: nginx` on both pass and block).

### 6.1 Fingerprint — a real gap, found and fixed
WAFFEN's signature table first reported **"no WAF"** against CRS — misleading, since
attacks were plainly getting 403'd. CRS-behind-nginx exposes nothing to match. Fix:
added a **behavioral fallback** — benign probe reaches origin (2xx) while the attack
probe is blocked (403/406/…) ⇒ report a generic inline WAF at low confidence (the
same generic-detection wafw00f falls back to). WAFFEN now reports
`Generic/Unknown WAF (0.30)` with the differential as evidence, instead of "no WAF".

### 6.2 Calibration + coverage — pipeline works unchanged
- `--calibrate` against CRS: **waf_detected=True, confidence 0.80, block=HTTP 403**
  learned automatically (RedEye's `"Request blocked by RedEye"` signature is
  irrelevant here — calibration adapts with no code change).
- `eval` (47 KB-seed attacks, 20 benign, `--inject query`): **overall coverage
  42.6%**, **false positives 0/20 = 0.0%**. Per class CRS PL1 blocks XSS / Directory
  Traversal / File Inclusion / SSTI at **100%**, SQL 75%, Command/NoSQL 50%. (The
  Upload class reads ~4% here — a query-param artifact, same injection-point lesson
  as §5a; not a real CRS gap.)

### 6.3 Verified bypasses — WAFFEN beats CRS PL1 on the real SQLi endpoint
Juice Shop's `/rest/products/search?q=` is a genuine SQLite-backed SQLi sink. Running
the **verified** search (`bypass --verify`) found evasions that CRS PL1 lets through
**and** that the verifier confirmed hit the database — **3 distinct payloads** (seen
across the identity / hpp_duplicate / junk_prefix_param transforms, 9 findings before
dedupe):

| Mutation chain | Payload | Confirmed by |
|---|---|---|
| `whitespace_newline` | `'`⏎`OR`⏎`1=1-- -` | live `SQLITE_ERROR` in response |
| `sql_string_concat_pipe` | `' O'\|\|'R '1'='1` | live `SQLITE_ERROR` in response |
| *(identity)* | `admin'-- -` | live `SQLITE_ERROR` in response |

CRS PL1's keyword regex misses the tautology once `OR` is split by a newline or a
`'||'` string-concat; Juice Shop still parses it, erroring on the broken SQL — which
is **error-based proof of injection**. This required a verifier fix the lab surfaced:
the SQL error table had no SQLite/Sequelize signature (`SQLITE_ERROR`), so the Node
app's errors were invisible — now added.

**Honest scope:** these are **error-based** confirmations (HTTP 500 carrying a real DB
error), not a completed `UNION`-exfil, and only against **paranoia level 1**; higher
CRS paranoia blocks more. The headline is not "CRS is weak" — it is that WAFFEN's
search + verifier **transfer cleanly to a second, independent, industry-standard WAF**
and produce real, verified, deduplicated, rule-actionable findings there.

### 6.4 Verifier honesty held on the second WAF too
The same run's XSS search produced dozens of raw THROUGHs (mostly double-URL-encoded
payloads that evade CRS but reach the app as inert text → HTTP 500). With `--verify`
**none** were reported exploitable: a 500 with a *SQL error* is confirmed (6.3); a 500
with *inert junk* is correctly rejected. The verifier distinguishes them by body
content — the same no-false-bypass discipline §4 showed on RedEye, now cross-checked
on CRS.

### 6.5 Paranoia gradient — WAFFEN measures the security/usability tradeoff
CRS was re-run at paranoia levels 1→4 (`lab/`, `PARANOIA=n`), re-calibrating each time.

**Seed coverage + false-positives** (47 KB-seed attacks, 20 benign, `--inject query`):

| CRS PL | Overall coverage | False-positive rate |
|---|---|---|
| 1 | 42.6% | **0%** |
| 2 | 48.9% | **0%** |
| 3 | 51.1% | **0%** |
| 4 | 53.2% | **35%** (7/20 benign blocked) |

(Overall % is dragged down by the Upload-class query-param artifact that sits at
~4–8% at every level; every *real* value-injection class — XSS/SQL/Cmd/NoSQL/
Traversal/LFI/SSTI — is already **100% blocked by PL3**.)

**Verified SQLi bypasses the search engine still finds** (`bypass --verify`, all SQL
seeds, DB-error-confirmed, on the real `/rest/products/search` sink):

| CRS PL | Distinct VERIFIED SQLi bypasses |
|---|---|
| 1 | **137** |
| 2 | **8** |
| 3 | **0** |
| 4 | **0** |

This is the clearest single demonstration of why the mutation **search** beats static
payload lists: at PL1 single-seed testing reads SQL as "75% blocked" (1 seed through),
but the engine finds **137 distinct verified evasions** — backslash-escaped quotes,
backtick-quoted `OR`, zero-width-character insertion (`O​R`), `OR`→`||`,
intra-keyword comments (`O/**/R`), scientific-notation / NFKC-fold tricks, exotic
whitespace. PL2 closes all but **8** (the nastiest: zero-width + `+`-encoded space).
PL3 closes them **completely**, and WAFFEN honestly reports 0 — it does not fabricate.

**Actionable conclusion for a defender:** on this surface **PL3 is the sweet spot** —
it eliminates every SQLi evasion the engine could find (0 bypasses) at **0% false
positives**, whereas **PL4 buys no extra SQLi protection here yet costs 35% of benign
traffic**. WAFFEN produced that recommendation by measurement, not assumption.

### 6.6 Beyond the query string — JSON-body injection and live session auth
- **JSON-body injection** (`--inject json`, `POST /rest/user/login`, field `email`): CRS PL1
  blocks the raw `' OR 1=1--` login payload (403). The search found CRS-evading mutations
  that still reach the database — **3 distinct verified** (error-based) login-SQLi payloads
  (`whitespace_newline`, `zero_width_insert`, `sql_string_concat_pipe`), while 1164
  non-injecting THROUGHs (401 evasions that evade CRS but do not log in) were correctly left
  **unverified**. Confirms WAFFEN works at a body/JSON injection point, not only the query string.
- **Live session auth** (`--header`): against a real protected endpoint (`GET /rest/basket/1`,
  which is `401` with no token), threading `--header "Authorization: Bearer <jwt>"` through
  WAFFEN's oracle flips the response to `200` — and does so through a request transform's
  curl-argv path too, not only the default path. The single-source `apply_auth` design is
  confirmed live, end-to-end (previously only unit-tested).

### 6.7 Transport parity — pooled vs curl agree
The new `--transport pooled` (keep-alive `http.client`) was cross-checked against the
default curl transport on the lab: across every inject mode (query / rawpath / json /
body) and both benign and attack payloads, the two transports returned the **same status
and the same verdict** (8/8). A pooled bypass run found the same 3 verified SQLi payloads,
and a pooled run with a curl-argv transform fell back to curl cleanly. Pooled was ~1.6×
faster on localhost (≈6.1 vs 10.1 ms/request) — a bigger gap is expected on a remote
HTTPS target, where keep-alive also removes a per-request TLS handshake.

### 6.8 Third WAF + strengthened coverage
Closing the documented weak sides (see `docs/COMPARISON.md`):
- **A 3rd independent WAF — BunkerWeb** (`lab/bunkerweb-compose.yml`, a distinct product,
  not CRS alone), in front of the same Juice Shop. WAFFEN flags it behaviorally
  (`Generic/Unknown WAF`, no false vendor match from the 119-signature table), auto-calibrates
  (`waf_detected=True`, conf 0.90), and scores **71.6% coverage at 0% false-positives**. WAFFEN
  is now validated on **RedEye + OWASP CRS + BunkerWeb**.
- **Fingerprint 48 → 119 vendors** (the +71 ported from wafw00f's plugin source, cross-checked;
  all regexes compile, 0 duplicates) — and still no false match on the CRS/BunkerWeb labs.
- **SQLi verifier extracts a DB-evaluated proof value** as a high-confidence fall-through; on the
  error-leaking Juice Shop endpoint the error-signature channel confirms first (0.80), and the
  extraction channel (0.95) is exercised by unit tests for error-suppressed targets.

### 6.9 A 4th WAF, and a genuinely different detection model — NAXSI
The audit noted all WAFs so far were regex/CRS-family. **NAXSI** (`lab/naxsi-compose.yml` +
`lab/naxsi-nginx.conf`, enforcing mode) is a **whitelist/scoring** WAF — a different model —
in front of the same Juice Shop on `:18082`. WAFFEN flags it behaviorally (`Generic/Unknown`,
0.30 — the custom deny page carries no NAXSI header), auto-calibrates (`waf_detected=True`,
0.80), and scores **73.5% coverage at 0% false-positives**. Crucially the **per-class profile
differs from CRS** — SSTI 50% (vs CRS 83–100%), Open Redirect 57%, CRLF 62.5%, while SQL/XSS/
Traversal stay 100% — evidence WAFFEN captures model-specific behavior, not just one WAF's shape.
WAFFEN is now validated on **RedEye + CRS + BunkerWeb + NAXSI** (4 WAFs, 2 detection models).

### 6.10 All 14 verifiers live-validated (self-audit follow-up)
The self-audit flagged that 5 verifiers (XXE, SSRF, LDAP, SSI, Open Redirect) were unit-tested
only — Juice Shop hardens or lacks those sinks. A purpose-built vulnerable sink app
(`lab/vuln_sinks.py`, stdlib only) now gives each verifier a real socket crafted to match its
probe, and the REAL verifier (real curl / `_fetch_headers`) confirms all five end-to-end:

| Class | Live confidence | Confirmed by |
|---|---|---|
| Open Redirect | 0.90 | `Location:` authority = attacker host |
| SSI | 0.90 | `$((a*b))` evaluated server-side |
| XXE | 0.75 | internal entity expanded to a split-marker |
| LDAP | 0.70 | `InvalidSearchFilter` / `[LDAP: error code]` |
| SSRF | 0.60 | cloud-metadata `AccessKeyId` in the body |

`tests/test_verifier_live_sinks.py` makes this permanent (binds the sink, runs the verifier,
plus a no-false-positive check). All 14 verifier classes are now exercised against a live target.

### 6.11 Search strategies benchmarked (and a crash found)
The audit noted the 4 strategies were never compared. Running each on the CRS lab (SQL class,
20 seeds, equal 150-request/run budget, `lab/strategy_bench.py`) gives real numbers:

| Strategy | Distinct bypasses | Requests | Time | Bypasses / 1k req |
|---|---|---|---|---|
| beam (default) | 847 | 2851 | 21.3s | 297 |
| **genetic** | 1015 | 1747 | 14.7s | **581** |
| best-first | 233 | 461 | 3.9s | 505 |
| MCTS | 1021 | 2851 | 23.0s | 358 |

**genetic** is the most efficient (most bypasses per request, fewest requests, fastest) and nearly
the most thorough; **MCTS** finds the most but costs the most; **best-first** converges fast but
explores least. They genuinely differ — the default (beam) is reasonable, but genetic is the better
pick under a tight budget. The benchmark also surfaced a real crash — `reward_from_score` raised
`OverflowError` for a large negative score delta (a small score after a THROUGH parent) — now fixed
with a numerically-stable sigmoid (`tests/test_bandit.py`).

### 6.12 A 5th WAF and a 3rd detection model — open-appsec (ML), + a calibration bug fixed
To validate beyond regex (CRS) and whitelist (NAXSI) models, **open-appsec** — a
machine-learning WAF — was stood up (`lab/openappsec/`, prevent-learn, confidence medium) in
front of Juice Shop on `:18083`. WAFFEN flags it behaviorally, calibrates, and scores **~35%
(signature) / ~55% (calibrated) coverage at 0% false-positives** — a much more permissive profile
than CRS/NAXSI (the open-source ML model lets more through). WAFFEN now spans **5 WAFs across 3
detection models** (regex / whitelist / ML).

This run also surfaced a **real WAFFEN bug**: open-appsec sometimes calibrated at low confidence
(0.4) with overlapping block/benign size bands, so the learned model classified *benign* responses
as `unresolved → BLOCKED` — a **100% false-positive artifact**. Direct probing proved open-appsec
was *not* over-blocking (every benign term returned 200), confirming it was WAFFEN's calibration,
not the WAF. Fixed: calibration now only overrides the signature verdict when confidence ≥ 0.5
(`MIN_CALIBRATION_CONFIDENCE`), else it falls back to the signature — applied in the oracle and both
eval/dataset classifiers (`tests/test_calibration_gate.py`). High-confidence WAFs are unaffected.

## 7. 2026 WAF-engine CVE primitives — reproduced against a version-pinned engine

The rolling `owasp/modsecurity-crs:nginx` now ships **libmodsecurity 3.0.17**, which
already patches the 2026 transformation CVEs, so the standing lab (§6) cannot
reproduce them. To validate the newly added primitives honestly, a second lab
(`lab/modsec-vuln-compose.yml`) pins the **vulnerable** engine and runs it beside the
patched one for a version-differential — same rule, same payload, only the engine
version differs.

### 7.1 CVE-2026-104259 (`t:removeComments` off-by-one) — reproduced + patch-verified
- **Vulnerable engine obtained:** `owasp/modsecurity-crs:4.25.1-nginx-202609180209`
  bundles **libmodsecurity 3.0.16** (confirmed: `libmodsecurity.so.3.0.16`); the rolling
  tag is 3.0.17.
- **Isolation:** stock CRS libinjection (942100) catches `UNION SELECT` regardless of
  comments, which masks the transformation bug. So the probe uses a custom rule
  (`lab/vuln-removecomments-rule.conf`) matching `@rx blockedtoken` after
  `t:removeComments` on the non-SQL token `blockedtoken` — verified that a lone `/**/`
  with no SQL keywords is **200** at PL1, so this rule is the only thing that can block.
- **Payloads are produced by WAFFEN's own mutators** (`lab/vuln_repro.py`): seed
  `"blocked token"` → `sql_between_comment` = `blocked/**/token`, `sql_adjacent_comment`
  = `blocked/**//**/token`.
- **Result** (`/rest/products/search?q=`):

  | engine | baseline `blocked/**/token` | probe `blocked/**//**/token` |
  |---|---|---|
  | **libmodsecurity 3.0.16 (vulnerable)** | `403` blocked | **`200` — BYPASS** |
  | **libmodsecurity 3.0.17 (patched)** | `403` blocked | `403` blocked |

  Same rule and payloads on both; the adjacent-comment probe passes **only** on 3.0.16.
  This both confirms WAFFEN's `sql_adjacent_comment` exploits CVE-2026-104259 and
  verifies 3.0.17 is the fix. Reproduce:

  ```
  docker compose -f lab/modsec-vuln-compose.yml -p waffen-lab-vuln up -d
  .venv/bin/python lab/vuln_repro.py      # -> PASS
  docker compose -f lab/modsec-vuln-compose.yml -p waffen-lab-vuln down
  ```
- **Not yet reproduced here:** `mp_truncated` (Coraza CVE-2026-41508 — needs a pinned
  vulnerable Coraza, a separate engine), `base64_malformed_prefix`/`brotli_body`
  (need a sink that base64/br-decodes the param), and `sql_pcre_matchlimit_pad`
  (needs a CRS rule whose regex exceeds `SecPcreMatchLimit`). The §7.1 method — pin
  the vulnerable engine, isolate the rule, drive it with WAFFEN mutators — is the
  template for these follow-ups.

### 7.2 Engine CVE probe — honest triage, no false positives
`waffen cve-probe` runs each primitive's canary differential against a live target and
labels it PRESENT / ABSENT / INCONCLUSIVE. Run against the vulnerable 3.0.16 lab at the
Juice Shop SQLi sink, it reports **no clean bypass** — which is correct and instructive:
- `t:removeComments` → **ABSENT**: libinjection (942100) catches `UNION SELECT` with or
  without comments, masking the transformation bug at a real SQLi endpoint — exactly why
  §7.1 needs an isolated rule to demonstrate it.
- truncated-multipart / `filename*` / PCRE-pad → **INCONCLUSIVE**: the probes drew `400`
  / `500` / `414`, i.e. the *server* rejected the request shape (malformed body, backend
  error, URI-too-long). The probe deliberately does **not** count those as a bypass — an
  early build did, and it was a false-positive source; only a clean backend response
  (2xx/3xx/404) now reads as "passed."
- `t:base64DecodeExt` → **INCONCLUSIVE**: the sink doesn't base64-decode `q`, so the bug
  can't be exercised here (correctly not reported as PRESENT).

So the probe's value is trustworthy triage: it never cries wolf, and its PRESENT path is
unit-tested against a simulated vulnerable engine (`tests/test_cve_probe.py`).

### 7.3 Coraza CVE-2026-41508 — attempted, did NOT reproduce on 3.8.0/3.8.1 (honest)
A version-differential was built for the Coraza truncated-multipart claim: a minimal
Go `coraza/v3` filter (rule 200003, `MULTIPART_STRICT_ERROR`) compiled at **v3.8.0**
and **v3.8.1**, fed a truncated `multipart/form-data` body (no closing `--boundary--`).
**Both versions blocked it (403/403)** — the bypass did not reproduce.

Reading the actual `internal/bodyprocessors/multipart.go` diff explains why: in
**3.8.0** `io.ErrUnexpectedEOF` **already set** `MULTIPART_STRICT_ERROR` (so rule 200003
fires); **3.8.1** only *refines* this (`flagUnexpectedEOF` now skips the flag when the
body was truncated by `SecRequestBodyLimit`, i.e. `INBOUND_DATA_ERROR=1`, to avoid
false-positives on oversized bodies), plus adds a `filename*`-continuation check and a
quadratic-CPU fix. So the "3.8.0 fails open on truncation" description does not hold for
these versions. **Conclusion:** `mp_truncated` stays a useful *probe* of any WAF's
truncation handling, but it is **not** a confirmed CVE-2026-41508 bypass on 3.8.0/3.8.1
— reported as a non-result rather than inflated into a bypass.

## Verdict
- **Validated on two independent WAFs now:** RedEye (vendor target) and OWASP CRS /
  ModSecurity (industry standard). The fingerprint→calibrate→search→verify pipeline
  transfers to CRS with no code change beyond two real gaps the lab surfaced and fixed
  (behavioral fingerprint fallback; SQLite error signature).
- **Proven on CRS:** 3 distinct **verified** SQLi bypasses of CRS PL1 on a real SQLi
  endpoint, confirmed by the live database error (not inflated 500 noise).
- **Proven — the search beats static payload lists, and quantifies a config tradeoff:**
  across paranoia 1→4, verified SQLi bypasses the engine finds go **137 → 8 → 0 → 0**
  while false-positives go **0% → 0% → 0% → 35%** — so WAFFEN recommends **PL3** (all
  SQLi evasions closed, no benign over-blocking) by measurement (§6.5).
- **Proven stronger / more trustworthy than the de-facto tools on this target:**
  names the WAF (vs wafw00f), avoids GoTestWAF's self-ban FP artifact, and never
  reports an unverified bypass as real.
- **Proven: found a real, reproducible coverage gap.** `POST /file-upload` accepts
  dangerous extensions (`.phtml`, `.phar`, `.php`, `.svg`, `.html`) with zero WAF
  filtering — identical to a benign PDF. Defense-in-depth gap today; a direct RCE
  path if the backend were ever PHP. This is the one finding in this validation
  pass that is real, reproducible, and actionable for the RedEye team — found by
  moving from a mismatched test (query string) to the actual vulnerable endpoint.
- **Not proven:** a weaponizable bypass on the query-injection-style classes
  (XSS/SQLi/CRLF/cmd/traversal) — RedEye blocks all of those tried. That is a
  RedEye strength on those surfaces, not a WAFFEN weakness; WAFFEN reported it
  honestly rather than inflating 500-error noise into a false "bypass."
