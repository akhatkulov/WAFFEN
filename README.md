<p align="center">
  <img src="docs/assets/banner.png" alt="WAFFEN — WAF evasion-path finder, by Akhatkulov (Me262), Offensive Security Engineer" width="640">
</p>

**WAF evaluation & bypass-research toolkit — for targets you own or are explicitly authorized to test.**

WAFFEN searches for *evasion paths* against a Web Application Firewall: given an
attack payload the WAF blocks, it discovers a chain of mutations (encodings,
obfuscations, request-level transforms) that still reaches the origin — so the
coverage gap can be found and fixed. It is built by and for the RedEye WAF team
as a red-team / regression instrument, in the same family as
[GoTestWAF](https://github.com/wallarm/gotestwaf), [wafw00f](https://github.com/EnableSecurity/wafw00f),
and WAFNinja.

> ⚠️ **Authorized use only.** WAFFEN sends attack-shaped traffic. Point it only at
> systems you own or have written permission to test. The default configuration
> targets the project's own RedEye demo. You are responsible for how you use it.

---

## Why WAFFEN is different

Existing tools split into **recon** (wafw00f fingerprints the WAF) and **evasion**
(WAFNinja/WhatWaf fuzz payloads). GoTestWAF measures coverage as a cartesian
product of `payload × encoder × placeholder`. WAFFEN adds the missing piece:

**A feedback-driven search for an evasion *path*, not a blind payload dump.**

It treats bypass discovery as a bounded search problem. A blocked payload is a
start state; mutators are the operators; a THROUGH response is the goal. Because
block/through feedback is binary and sparse, WAFFEN ranks the still-blocked
frontier by how much each mutation *perturbs* the stack (status-code / body-size
drift from the baseline block) and expands the most promising branches — a
beam search that converges on a working chain within a request budget.

Found chains feed a versioned **knowledge base** that updates over time (roadmap),
so the tool gets smarter about a given WAF the more it is run.

---

## Install

```bash
cd WAFFEN
pip install -e .          # or: pipx install .
waffen version
```
v1 core is **stdlib-only** (requests go through `curl`), so it also runs straight
from a checkout: `python3 -m waffen ...`.

## Usage Guide

WAFFEN has 9 subcommands. All of them share a few common flags (set via a helper
that every target-facing subcommand uses):

| Flag | Default | Meaning |
|---|---|---|
| `--target URL` | — | base URL of a target you own/are authorized to test |
| `--path PATH` | `/` | request path on the target |
| `--timeout N` | `15` | per-request curl timeout (seconds) |
| `--block-signature TEXT` | `"Request blocked by RedEye"` | body substring marking a WAF block (swap for your own WAF's) |
| `--tls-verify` | off | enforce TLS cert verification (default is insecure, like every comparable WAF tool, for self-signed test targets) |
| `--header 'Name: Value'` / `-H` | — | extra request header (repeatable), e.g. `Authorization: Bearer …`; threads through every inject mode and transform so a search can run behind auth |
| `--cookie 'a=1; b=2'` | — | cookie string sent with every request (session auth) |
| `--transport MODE` | `curl` | `curl` (uniform; required for request transforms) or `pooled` (keep-alive `http.client`, faster on long runs; falls back to curl for transform sends) |
| `--mock` | off | run against the built-in offline mock WAF instead of `--target` — no network, safe to experiment with |

Every example below is runnable as shown. Replace `https://your-waf.example` with
a target you own or are authorized to test, or add `--mock` to try it risk-free first.

---

### `waffen bypass` — search for an evasion chain

The core command: feeds one or more seed payloads through a guided search
(beam/genetic/best-first/MCTS) over 161 mutators × 19 request transforms, and
reports confirmed bypasses.

**Seed selection** (pick one):
| Flag | Meaning |
|---|---|
| `--payload TEXT` | a single explicit payload |
| `--class NAME` | use the built-in KB seeds for one attack class |
| `--all-classes` | run every built-in KB seed across every class |

Built-in KB classes: `XSS Injection`, `SQL Injection`, `Command Injection`,
`Directory Traversal`, `File Inclusion`, `SSTI`, `NoSQL Injection`,
`Upload Insecure Files`. List a class's valid mutators with `waffen mutators --class NAME`.

**Injection point:**
| Flag | Default | Meaning |
|---|---|---|
| `--inject MODE` | `query` | where the payload goes: `query`, `path`, `rawpath`, `body`, `json`, `header`, `cookie`, or `upload` |
| `--param NAME` | `q` | the param/header/cookie/multipart-field name |
| `--method M` | `GET` | HTTP method |

`--inject upload` sends a **real multipart file upload**: the payload controls the
probed filename/extension (a bare value like `phtml` becomes `waffen_probe.phtml`;
a dotted value like `shell.php;.jpg` is used verbatim) — this is the test that
finds unfiltered dangerous-extension uploads, not a query-string guess.

**Search strategy:**
| Flag | Default | Meaning |
|---|---|---|
| `--strategy S` | `beam` | `beam`, `genetic`, `bestfirst`, or `mcts` |
| `--width N` | `6` | beam: frontier width kept per depth |
| `--depth N` | `4` | beam: max mutation-chain length |
| `--pop-size N` | `20` | genetic: population size |
| `--generations N` | `8` | genetic: number of generations |
| `--branch N` | `4` | bestfirst: mutators tried per expansion (UCB-ranked) |
| `--iterations N` | `200` | mcts: tree-search iterations |
| `--rollout-depth N` | `3` | mcts: random-rollout depth per iteration |
| `--max-requests N` | `400` | request budget per (transform, seed) run |
| `--stop-on-first` | off | stop a run at its first **confirmed-exploitable** bypass (verified search keeps hunting past a dead one even with this set) |
| `--all-mutators` | off | ignore per-class mutator filtering, try everything |
| `--transforms LIST` | all | comma-separated request transforms to sweep; `structural` and `placeholder_extra` select whole groups (see `waffen transforms`) |
| `--concurrency N` | `1` | batch-evaluate N candidates per round via `oracle.send_many` — speeds up beam/genetic/bestfirst; MCTS is sequential by construction, so this has little effect there |

**Making results trustworthy (live targets):**
| Flag | Meaning |
|---|---|
| `--calibrate` | learn the WAF's actual block/pass/unresolved signature at runtime instead of assuming HTTP 403 = blocked |
| `--learn` | GOFA-lite: probe which encodings the WAF's normalizer misses, and try those mutators first |
| `--verify` | inline **verified search** — confirm each bypass is still exploitable (not just "got a 200"); `--stop-on-first` only fires on a confirmed one |
| `--canary TEXT` / `--canary-every N` (default `25`) | re-probe a known-**benign** value periodically; if it starts looking blocked, the test source is likely rate-limited/banned, not the content newly risky. A ban usually looks like a clean, fast 403 — easy to mistake for a real block without this. Only checked at `--concurrency 1` |
| `--delay SECONDS` | fixed throttle between requests, to be a good neighbour |

**Output:**
| Flag | Meaning |
|---|---|
| `--out FILE` | write all findings as JSONL |
| `--rules` | print a suggested WAF rule for each verified-exploitable finding |
| `--rules-out FILE` | write the same recommendations as a Markdown report |
| `--verbose` | print live search events (baseline, found, budget, calibration) as they happen |

```bash
# offline: try the whole engine against a built-in mock WAF — no network, no target
waffen bypass --mock --all-classes --stop-on-first

# live: genetic search + verify, sweeping three request transforms
waffen bypass --target https://your-waf.example \
  --class "XSS Injection" --inject query --path /search --param q \
  --strategy genetic --transforms identity,hpp_split,chunked_body \
  --verify --max-requests 400 --out findings.jsonl

# one explicit payload, body injection, beam search
waffen bypass --target https://your-waf.example \
  --payload "' OR 1=1-- -" --class "SQL Injection" --inject body --method POST

# real multipart file-upload test — dangerous extensions on the real endpoint
waffen bypass --target https://your-waf.example --inject upload --param file \
  --path /file-upload --method POST --class "Upload Insecure Files" \
  --strategy bestfirst --verify --rules

# long sequential run with a ban-detector and a rule report for anything confirmed
waffen bypass --target https://your-waf.example --class "XSS Injection" \
  --calibrate --learn --canary "harmless-probe-value" --canary-every 25 \
  --verify --strategy mcts --iterations 300 --rules-out rules.md

# batch-evaluate 4 candidates per round (speeds up beam/genetic/bestfirst)
waffen bypass --target https://your-waf.example --class "Command Injection" \
  --strategy bestfirst --concurrency 4 --max-requests 300

# export each verified bypass as a Nuclei v3 differential regression template
waffen bypass --target https://your-waf.example --class "SQL Injection" \
  --calibrate --verify --nuclei ./waf-audit-templates
```

---

### `waffen eval` — score coverage & false-positive rate over a corpus

GoTestWAF-style scoring: fires a whole corpus of attack payloads plus a benign
set at a target and reports per-class coverage and the false-positive rate.
**Benign traffic is measured first**, before the attack flood, so a self-triggered
ban during the attack phase can't silently inflate the false-positive number.

| Flag | Default | Meaning |
|---|---|---|
| `--class NAME` / `--all-classes` | — | use built-in KB seeds (same classes as `bypass`) |
| `--corpus DIR` | — | harvest payloads from a PayloadsAllTheThings-style directory tree instead |
| `--max-per-class N` | `0` (all) | cap payloads per class when using `--corpus` |
| `--benign FILE` | — | newline-separated benign values for false-positive testing |
| `--inject` / `--param` / `--method` | `query` / `q` / `GET` | same meaning as `bypass` |
| `--calibrate` | off | learn the block/pass/unresolved signature first |
| `--concurrency N` | `6` | parallel requests via `oracle.send_many` |
| `--delay SECONDS` | `0` | throttle between requests |
| `--out FILE` | — | write the coverage JSON (+ a `.through.txt` gap-payload dump) |
| `--html FILE` | — | write a standalone, styled HTML coverage report (works offline in a browser) |
| `--rules` / `--rules-out FILE` | — | suggested WAF rule per coverage gap, console or Markdown |
| `--find-cutoff` | off | binary-search the **real** body-inspection cutoff against the live target (nowafpls-style) instead of guessing; ignored with `--mock` |
| `--cutoff-probes N` | `12` | request budget for `--find-cutoff` |

`--inject auto` routes each attack class to its correct injection point in one run
(Directory Traversal → URL path, Upload Insecure Files → multipart upload, SQLi/
XSS/etc. → query) — so a full-corpus run doesn't score path/upload classes near-zero
just because they were forced through `?q=`.

```bash
# full corpus + benign set, calibrated, per-class injection routing, HTML report
waffen eval --target https://your-waf.example --all-classes \
  --corpus ./PayloadsAllTheThings --benign benign.txt \
  --calibrate --inject auto \
  --out coverage.json --html coverage.html

# quick built-in-seed check with a rule report for any gap found
waffen eval --target https://your-waf.example --all-classes --rules

# measure the real body-inspection cutoff instead of guessing
waffen eval --target https://your-waf.example --find-cutoff --cutoff-probes 16
```

---

### `waffen dataset` — build a labelled training set

Sends attack cases (KB seeds or a `--corpus`) and benign values at a target and
writes a labelled `malicious`/`benign` dataset — for training your own WAF.
Shares `--class`/`--all-classes`/`--corpus`/`--max-per-class`/`--benign`/`--inject`/
`--param`/`--method`/`--calibrate`/`--concurrency`/`--delay` with `eval` (same meaning).

| Flag | Default | Meaning |
|---|---|---|
| `--split FRACTION` | `0` (no split) | validation fraction for a stratified train/val split |
| `--out PREFIX` | `dataset` | output prefix — writes `<out>.jsonl`/`.csv`, or `<out>_train`/`_val` with `--split` |

```bash
waffen dataset --target https://your-waf.example --all-classes --inject auto \
  --benign benign.txt --calibrate --canary "harmless value" --split 0.2 \
  --concurrency 1 --delay 0.05 --out logs/waf_training
# -> logs/waf_training_train.jsonl/.csv, logs/waf_training_val.jsonl/.csv
```

---

### `waffen analyze` — read a collected log offline

Turn a `dataset` JSONL log into a coverage/FP report **without re-hitting the
target** — per-class coverage, false-positive rate, a ban-contamination heuristic,
optional HTML report and WAF-rule suggestions. All offline, no network.

| Flag | Meaning |
|---|---|
| `<log>` (positional) | path to a `.jsonl` written by `waffen dataset` |
| `--html FILE` | write the same styled HTML coverage report `eval` produces |
| `--rules` / `--rules-out FILE` | suggested WAF rule per coverage gap, console or Markdown |

```bash
waffen analyze logs/waf_training.jsonl --html report.html --rules-out rules.md
```

---

### `waffen fingerprint` — identify the WAF in front of a target

wafw00f-style identification (9 vendor signatures) plus a heuristic test-plan hint
(body-inspection limit + historically-effective mutators for that vendor).

```bash
waffen fingerprint --target https://your-waf.example
```

---

### `waffen cve-probe` — which 2026 WAF-engine CVE primitives look exploitable

A safe, canary-token behavioural differential for the 2026 ModSecurity/Coraza engine
CVEs (you can't read libmodsecurity's version over the wire, but you can test its
behaviour). Each primitive is labelled **PRESENT / ABSENT / INCONCLUSIVE**; it's
conservative — only a clean backend response (2xx/3xx/404) counts as a pass, so a
`400`/`414`/`5xx` server rejection is never mis-read as a bypass.

```bash
waffen cve-probe --target https://your-waf.example --path /api/v1/search --param q
```

Covered: `t:removeComments` off-by-one (CVE-2026-104259), PCRE2 `@rxGlobal` match-limit
(GHSA-5m93-4h75-3p2w), Coraza truncated-multipart (CVE-2026-41508), RFC 2231 `filename*`
(CVE-2026-104269), inbound Brotli blind spot (CVE-2026-111497), and `t:base64DecodeExt`
blanking (GHSA-4j47-8qcr-jf59) — the same primitives the search can then weaponise. See
`docs/VALIDATION.md` §7 for pinned-engine reproductions.

---

### `waffen smuggle` — experimental request-smuggling probes

Timing-based CL.TE/TE.CL/TE-obfuscation desync detection over a raw socket (curl
can't express these). A flagged stall means "investigate manually" — timing is
noisy, never treat it as confirmed on its own.

| Flag | Default | Meaning |
|---|---|---|
| `--stall-factor N` | `3.0` | flag a probe whose response is this many times slower than the baseline |

```bash
waffen smuggle --target https://your-waf.example
```

---

### `waffen kb-update` — check/apply a knowledge-base update

A nuclei-style versioned update mechanism. **Ships with zero default sources** —
there is no public WAFFEN community KB yet — so running it with no flags just
reports that honestly. Point it at a real source once one exists:

| Flag | Meaning |
|---|---|
| `--name NAME` | source name (required together with `--kind`) |
| `--kind {github_release,manifest}` | where to check: a GitHub repo's latest release tag, or a `{"version":...,"download_url":...}` JSON manifest |
| `--repo OWNER/NAME` | for `--kind github_release` |
| `--manifest-url URL` | for `--kind manifest` |
| `--dest DIR` | default `./waffen_kb` — where KB state/version files are stored |

```bash
waffen kb-update                                            # honest no-op today
waffen kb-update --name my-kb --kind manifest --manifest-url https://example.com/kb.json
```

---

### Reference listings

```bash
waffen mutators                           # all 161 mutators
waffen mutators --class "SQL Injection"   # only the ones valid for that class
waffen transforms                         # all 19 request-level transforms
waffen version                            # banner + version
```

---

## Architecture

```
waffen/
  engine.py             — orchestrator: sweep request-transform × seed × strategy (+verify)
  core/     oracle.py   — curl sender, BLOCKED/THROUGH/DOWN classifier, score(), send_many(),
                          upload-filename inject mode, ban-onset canary detector
            transforms.py — request-level transforms (HPP, chunked, multipart, verb, GraphQL,
                          structural/parser-differential, nowafpls-style padding + live cutoff search)
            mock.py     — offline signature-WAF simulator for tests
            rawhttp.py / smuggle.py — raw-socket transport + CL.TE/TE.CL desync probes
  mutate/   base.py     — Mutator + Registry (per-class operator selection)
            encoders.py / obfuscators.py / sql_tamper.py / xss_context.py /
            path_cmd.py / generic_extra.py / quickwin.py / advanced.py — 160+ class-aware mutators
  search/   beam.py / genetic.py / bestfirst.py / mcts.py — 4 guided search strategies, each
                          with optional `concurrency` (batched via oracle.send_many)
            bandit.py   — UCB1 operator-selection + blocked-pattern memory
            scoring.py  — composite fitness (chain-length penalty, 4xx→5xx bonus)
  verify/   verifier.py — per-class semantic check: is a THROUGH payload still exploitable?
            calibrate.py — learn the WAF's block/pass signature at runtime (ffuf -ac style)
            structural.py — WAFFLED 3-part oracle for parser-differential bypasses
  recon/    fingerprint.py — wafw00f-style WAF ID (9 vendors) + test-plan/body-limit hints
            normalize.py — GOFA-lite: probe which encodings the WAF's normalizer misses
  eval/     coverage.py — GoTestWAF-style coverage + false-positive scoring over a corpus
            corpus.py   — harvest payloads from a PayloadsAllTheThings-style tree
            dataset.py  — labelled attack+benign training-set export (benign measured first)
  kb/       seeds.py    — built-in seed payloads per attack class (bootstrap)
            inject_map.py — per-class injection routing for `--inject auto`
            update.py   — nuclei-style versioned KB auto-update (pluggable, no default source yet)
  report/   results.py  — console/JSONL findings summary
            html.py     — standalone styled HTML coverage report
            rules.py    — WAF-rule recommendation generator (finding/gap → actionable rule text)
            analyze.py  — offline analysis of a collected log (coverage, FP, ban heuristic, HTML)
  cli.py                — `waffen bypass | eval | dataset | analyze | smuggle | fingerprint |
                          kb-update | mutators | transforms | version`
```

### Two orthogonal evasion axes
- **Payload mutation** (`mutate/`): rewrite the string — 120+ encoders/obfuscators,
  each tagged with the attack classes it stays valid for, composed into chains.
- **Request transforms** (`core/transforms.py`): rewrite the whole HTTP request —
  HPP, chunked/multipart framing, content-type confusion, verb tampering, plus a
  **structural / parser-differential set** (`--transforms structural`): WAFFLED-style
  JSON/multipart/XML envelope distortions (duplicate/unicode keys, multipart
  disposition & boundary tricks) that make the WAF misparse the body while the
  backend still extracts the payload — a bypass class needing no payload encoding.
  Swept independently of payload mutation, so `engine.py` explores their product.

### The search loop (`search/beam.py`)
1. Send the seed. If already THROUGH → report a raw gap, done.
2. Otherwise expand the frontier: apply every class-valid mutator to each state,
   send each result, collect any THROUGH as a **finding**.
3. Rank the still-blocked candidates by `oracle.score()` (code/size drift from the
   baseline block) and keep the top-`width`.
4. Repeat to `depth` or until the request budget runs out.

The oracle decouples transport from search, so the same engine runs against a
live WAF (`curl`) or the offline mock (unit tests), and future senders (httpx,
raw sockets for HTTP-smuggling transforms) plug in without touching the search.

---

## Project status & further reading

161 mutators, 19 request transforms, 4 search strategies, calibration, GOFA-lite
normalization learning, verified search, coverage/FP eval, training-set export,
WAF fingerprinting + test-plan hints, experimental smuggling probes, a WAF-rule
recommendation generator, and a pluggable KB auto-update mechanism — all with
test coverage (`pytest`).

- **[`docs/COMPARISON.md`](docs/COMPARISON.md)** — honest, evidence-backed comparison
  vs wafw00f / GoTestWAF / sqlmap: where WAFFEN is best-in-class (verified evasion-path
  search) and where it is **not** (it doesn't replace sqlmap or a full scanner).
- **[`docs/VALIDATION.md`](docs/VALIDATION.md)** — real runs against **two independent
  WAFs** (RedEye + a local OWASP CRS lab): the paranoia gradient (verified SQLi bypasses
  137→8→0→0 vs false-positives 0→0→0→35%), a confirmed coverage gap, and the FP pitfalls
  found and fixed.
- **[`docs/ROADMAP.md`](docs/ROADMAP.md)** — full sprint history and what's still open.
- **[`docs/COMPETITIVE_RESEARCH.md`](docs/COMPETITIVE_RESEARCH.md)** — the teardown
  of existing WAF tools this project's design choices are grounded in.

## Prior art & credits

[GoTestWAF](https://github.com/wallarm/gotestwaf) (payload×encoder×placeholder model),
[wafw00f](https://github.com/EnableSecurity/wafw00f) (fingerprinting),
[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) (payload corpus),
[nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) (auto-update model),
and the [awesome-waf](https://github.com/0xInfection/Awesome-WAF) collection.

## License
MIT.
