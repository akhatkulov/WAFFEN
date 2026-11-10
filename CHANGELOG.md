# Changelog

All notable changes to WAFFEN are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions follow SemVer.

## [Unreleased]

Validated against a **second, independent WAF** (local OWASP CRS / ModSecurity),
plus the fixes and features that cross-WAF validation surfaced.

### Added
- **Weak sides strengthened** (the honest gaps in `docs/COMPARISON.md`, each verified
  against real sources):
  - WAF **fingerprint signatures 48 → 119** — the +71 ported straight from wafw00f's plugin
    set (verified by cloning the repo; generic phrases dropped to avoid false matches).
  - **SQLi verifier now extracts a DB-evaluated value** (arithmetic/version marker via
    EXTRACTVALUE/CAST/CONVERT/`||` per MySQL/MariaDB/PostgreSQL/MSSQL/SQLite/Oracle, grounded
    in PayloadsAllTheThings) — "confirmed injectable" becomes "confirmed, here's the proof value".
  - **Stronger corpus harvester** (`eval/corpus.py`): broader PayloadsAllTheThings dir→class
    mapping + robust extraction; fixed a latent bug that dropped fence-lookalike wordlist lines.
  - **Validated on a 3rd independent WAF** — BunkerWeb (`lab/bunkerweb-compose.yml`): 71.6%
    coverage at 0% false-positives, behavioral fingerprint, auto-calibration.
- **Much wider coverage** (gaps from `docs/COMPARISON.md`, closed via an independently
  verified multi-agent pass):
  - WAF **fingerprint signatures 9 → 48** vendors (Barracuda, FortiWeb, Citrix NetScaler,
    Palo Alto, Radware, Wallarm, DataDome, PerimeterX, IBM DataPower, Azure App Gateway /
    Front Door, Aliyun, …) — grounded in wafw00f-known signatures; no false match on the lab.
  - **KB seeds 47 → 181** across **14 classes** (added CRLF, XXE, SSRF, Open Redirect, LDAP, SSI).
  - **Verifiers 9 → 14 classes** (+Open Redirect, SSI, LDAP, XXE, SSRF) and **deeper SQLi
    confirmation** (UNION column-count + time-based blind, on top of error-signature/boolean).
- **Pooled HTTP transport** (`--transport pooled`): a thread-local keep-alive
  `http.client` connection reused across requests, instead of one curl subprocess
  per request — ~1.6× faster on a localhost run (more on a remote HTTPS target,
  where it also avoids a fresh TLS handshake per request). Covers every built-in
  inject mode and transparently falls back to curl for `request_transform` sends
  (transforms emit curl argv). Default stays `curl`; verified to produce identical
  verdicts/status to curl across all inject modes against the CRS lab.
- **Session / auth support** (`--header`/`-H`, `--cookie`): threaded through every
  inject mode **and** every request transform via a single `oracle.apply_auth`, so a
  bypass search can run behind a login. An auth cookie folds into a cookie-injection
  payload's `Cookie:` header instead of colliding with it. (`bypass`, `eval`,
  `dataset`, `fingerprint`.)
- **Behavioral WAF fingerprinting**: when no vendor signature matches but a benign
  probe reaches the origin while the attack probe is blocked, report a generic inline
  WAF (low confidence) instead of a misleading "no WAF". Catches CRS/ModSecurity
  behind nginx (generic `403`, no vendor header) — which previously fingerprinted as
  nothing.
- **Two new semantic verifiers**: NoSQL Injection (engine-error + boolean
  differential) and Upload Insecure Files (app accept-vs-reject of a dangerous
  extension). Verified-class coverage is now 9 classes.
- **Second-WAF lab**: `lab/docker-compose.yml` + `lab/README.md` (OWASP CRS nginx +
  Juice Shop) and the validation record in `docs/VALIDATION.md` §6 — 3 distinct
  **verified** SQLi bypasses of CRS paranoia-level-1, confirmed by the live DB error.

### Fixed
- **Robustness (self-audit)**: concurrent batches now run a post-batch canary probe so
  ban detection isn't blind above `--concurrency 1` (and `eval`/`dataset` warn); the
  deep-SQLi UNION walk is bounded by `_UNION_MAX_COLS=6`; the pooled transport caps the
  body read at 8 MiB and drops an oversized connection instead of draining it. The audit's
  honest findings are documented in `docs/COMPARISON.md` ("Known limitations").
- **Verifier false negatives**: verification probes now retry on a transient `DOWN`
  (a flaky transport no longer reads as "exploit not confirmed"); the CRLF verifier's
  own `curl -i` header path now carries `--header`/`--cookie` too.
- **SQL verifier blind to Node ORMs**: added SQLite / Sequelize error signatures
  (`SQLITE_ERROR`, `unrecognized token`, …) — Juice Shop's injection errors were
  invisible to the old MySQL/Oracle/Postgres-only table.
- **Duplicate rule suggestions**: `bypass --rules` now emits one rule per distinct
  (class, payload); the same bypass rediscovered under several transforms no longer
  prints N copies.

## [0.1.0] — 2026-11-07

First tagged release. A closed-loop, verified WAF evasion-path finder for targets
you own or are authorized to test.

### Engine & search
- Two orthogonal evasion axes: **161 class-aware payload mutators** (encoders,
  obfuscators, SQLMap-tamper/PortSwigger-grade techniques) × **19 request-level
  transforms** (HPP, chunked/multipart framing, content-type confusion, verb
  tampering, GraphQL, WAFFLED-style structural/parser-differential distortions).
- **4 guided search strategies**: beam, genetic, best-first (UCB bandit), and
  MCTS+CFG — all operating on binary block/allow feedback. Optional per-round
  concurrency via `oracle.send_many` for beam/genetic/best-first.
- **Verified search**: each THROUGH is semantically verified; a payload that
  passed the WAF but is not actually exploitable never counts as a bypass, and
  the search keeps hunting past dead ones.

### Making results trustworthy
- **Runtime calibration** (`--calibrate`): learns the WAF's real block/pass/
  unresolved signature instead of assuming HTTP 403 = blocked.
- **GOFA-lite normalization learner** (`--learn`): probes which encodings the
  WAF's normalizer misses and tries those first.
- **Ban-onset canary detector** (`--canary`): re-probes a known-benign value;
  a rate-limit ban usually looks like a clean fast 403, so this catches it
  instead of mislabeling a banned source's responses.
- **Per-class injection routing** (`--inject auto`): routes each attack class to
  its correct injection point (traversal → URL path, uploads → multipart, etc.)
  in a single run, instead of forcing everything through one parameter.
- Real **multipart file-upload inject mode** (`--inject upload`) with
  filename/extension control.

### Evaluation, data & reporting
- `eval`: GoTestWAF-style coverage + false-positive scoring, API-vs-App split,
  JSON + styled **HTML report**, and a live body-inspection-cutoff binary search
  (`--find-cutoff`). Benign is measured before attacks so a mid-run ban can't
  inflate the false-positive rate.
- `dataset`: labelled attack+benign **training-set export** (JSONL/CSV, stratified
  train/val split) with class-stratified **balancing** (`analyze --balanced-out`).
- `analyze`: offline analysis of a collected log — coverage, FP rate, a
  ban-contamination heuristic, HTML report, and WAF-rule suggestions, no network.
- `fingerprint`: 9-vendor WAF identification plus a heuristic test-plan hint
  (body-inspection limit + historically-effective mutators).
- **WAF-rule recommendation generator** (`--rules`/`--rules-out`): turns a
  confirmed finding or coverage gap into an actionable, class-specific rule.
- `smuggle`: experimental timing-based CL.TE/TE.CL request-smuggling probes over
  a raw socket.
- `kb-update`: nuclei-style versioned knowledge-base auto-update (pluggable;
  ships with no default source yet).

### Quality & validation
- 258 tests; CI on Python 3.11/3.12.
- Red-team CLI: ASCII banner, red palette, coverage bars, colored verdicts
  (auto-disabled when piped / under `NO_COLOR`).
- Validated against a real RedEye-protected target (see `docs/VALIDATION.md`):
  named the WAF where wafw00f could not, matched GoTestWAF's coverage while
  avoiding its self-ban false-positive artifact, honestly reported 0 verified
  bypasses on hard classes, and found one real coverage gap (unfiltered
  dangerous-extension uploads at `POST /file-upload`).

[0.1.0]: https://github.com/akhatkulov/WAFFEN/releases/tag/v0.1.0
