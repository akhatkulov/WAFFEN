# Changelog

All notable changes to WAFFEN are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions follow SemVer.

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
