# WAFFEN — Roadmap to beat every WAF bypass tool

Derived from `COMPETITIVE_RESEARCH.md`. Ordered by **bypass-power-per-effort**.
Effort: S = days · M = 1–2 weeks · L = multi-week. Module tags use the current layout.

Current state (v1, done): 123 mutators, 10 request transforms, beam + genetic
search (perturbation fitness), semantic verifier, 9-vendor fingerprint,
orchestrator, 37 tests — all validated against the mock WAF only.

---

> **Sprint 1 — DONE (2026-11):** A1, A2, A3, A5 + Phase-B quick-win cluster.
> 138 mutators, runtime calibration. Benchmark (mock, XSS, budget 300): beam 1200
> reqs → genetic 315 → **bestfirst 22**, all seeds solved.
>
> **Sprint 3 — DONE (2026-11):** +23 mutators (**161** total, SQLMap+PortSwigger superset),
> D2 **structural transforms** + WAFFLED **3-part oracle**, D3 **raw-socket HTTP
> smuggling** (`waffen smuggle`, experimental), **training export** (`waffen dataset`
> — closes the original WAF-training goal), **eval HTML report**, oracle throttle+backoff,
> LICENSE + pytest (138 tests). 8 subcommands. Committed on `feat/waffen-core`.
>
> **Live validation — DONE (2026-11):** real runs against juice-shop/RedEye.
> Named the WAF where wafw00f couldn't; matched GoTestWAF's 100% coverage while
> avoiding its self-ban false-positive artifact (fixed: eval now measures benign
> *before* attacks); verified search correctly dissolved a 30-payload "bypass" set
> as non-exploitable; found and confirmed one real gap — `POST /file-upload`
> accepts dangerous extensions unfiltered (see `docs/VALIDATION.md`).
>
> **Sprint 4 — DONE (2026-11):** closes the gaps the live validation exposed.
> **Real multipart-upload inject mode** (`--inject upload`) — the exact test that
> found the live finding, now repeatable/automatable, with an "Upload Insecure
> Files" seed list grounded in that finding. **Ban-onset canary detector** — a
> rate-limit ban usually looks like a clean fast 403 (not a transport DOWN), which
> the old backoff never caught (this session self-banned ~5 times); `--canary`
> periodically re-probes a known-benign value and escalates backoff hard if it
> starts looking blocked. **WAF-rule recommendation generator** (`--rules`/
> `--rules-out`) — closes the loop from "found a gap" to "here's the rule to add",
> with class-specific templates grounded in real evasion mechanics. **Search
> concurrency** extended to genetic/best-first (real batching via `send_many`);
> MCTS stays honestly sequential (documented why, not faked). **E2**: fingerprint
> → test-plan hints (vendor body-limits + historically-effective mutators) and a
> live binary-search for the *real* inspection cutoff (nowafpls++, `--find-cutoff`)
> replace guesswork. **GraphQL placeholder** transform (GoTestWAF-parity gap closed).
> **E1**: KB auto-update mechanism (`waffen kb-update`) — honestly ships with zero
> default sources (no public WAFFEN KB exists yet), ready to point at one.
> 231 tests, 9 subcommands, 46 modules, ~7,750 LOC.
> Still open: deeper live re-validation with the new upload/canary/rules tooling,
> D3 raw-socket smuggling validated on a real desync-vulnerable target, concurrency
> for a true grammar-based (CFG) payload synthesizer (research-grade, deferred).
>
> **Sprint 2 — DONE (2026-11):** A4 **MCTS+CFG** strategy (binary feedback, UCB,
> geometric decay). First **live run vs juice-shop** validated the pipeline AND
> exposed that search halted on a semantically-dead bypass — so **verified search**
> was added: all four strategies now inline-verify each THROUGH and only count a
> *confirmed-exploitable* one as a stop_on_first success, continuing to hunt past
> dead bypasses (the differentiator no other tool has). 4 strategies, 75 tests.
> Next: C2 eval/coverage port, D1 GOFA-lite normalization learner, deeper live sweeps.

## Phase A — Search & signal core  *(the decisive edge; do first)*

The thing no competitor has. These compound: every item makes all search
strategies sharper, and all run on **binary (block/allow) feedback** — which is
what we actually get from a real WAF and what cripples WAF-A-MoLE.

| # | Item | Effort | Module | Payoff |
|---|---|---|---|---|
| A1 | **Composite response-differential + timing fitness.** Replace binary/perturbation `score()` with an ordered gradient: `blocked-fast < reached-backend(5xx/slow/error-fingerprint) < reflected-neutralized < reflected-intact < executed`. Per-host timing calibration (median+MAD). | **S** | `search/scoring`, `core/oracle` | **Unblocks everything.** Turns binary WAF into a dense gradient (what WAF-A-MoLE needs a score for and can't get) |
| A2 | **Runtime auto-calibration of the WAF block/pass signature** (ffuf `-ac` + wfuzz baseline + wafw00f `genericdetect`). Probe benign + random, cluster block responses (status+len+body-hash+headers+timing), classify every test block/pass/**unresolved** against the learned model, not a hardcoded 403. | **M** | `verify/calibrate`, `recon` | Fixes the brittle "403 = blocked" assumption every tool shares |
| A3 | **UCB1 / Thompson bandit operator-selection** inside genetic/beam: sample operators by learned per-context value instead of uniformly. + **blocked-pattern memory** to prune. | **S** | `search` | Immediate sample-efficiency; fixes blind operator choice |
| A4 | **MCTS + CFG tree-search strategy** (AdvSQLi/AutoSpear/WAFUzz): token-tree states, UCB selection, CFG-equivalent expansion, geometric rule-weight decay, binary reward. New `--strategy mcts`. | **M** | `search/mcts` | Proven SOTA; beats WAF-A-MoLE at ~⅓ queries on binary feedback. Flagship strategy |
| A5 | **Best-first priority-queue frontier** (WAF-A-MoLE) as `--strategy bestfirst` + its 8 operators; benchmark harness vs beam/genetic/mcts on the mock. | **S** | `search` | Diversity + a baseline to benchmark against |

## Phase B — Mutation library → superset of SQLMap + PortSwigger  *(breadth; cheap)*

Full 42-item table below. Goal: WAFFEN's library becomes a strict superset of the
SQLMap tamper catalog + the PortSwigger/PayloadsAllTheThings evasion corpus.

**Quick-win cluster (all S, biggest signature-evasion ROI — do first):**
keyword-doubling `SELSELECTECT` · `%uXXXX` percent-unicode · intra-keyword random
comments · `space2dash/hash` · `information_schema` split · **mXSS** + polyglots ·
semicolon-less entities · **case-folding pre-images** (ſ→s, U+212A→k) · command
wildcard `/???/c?t` · `....//` self-referential traversal · gzip body · spoofed-IP headers.

Then: comma-less + function-equivalence SQL rewrites, vendor-tuned tampers (M);
**real charset body re-encode** EBCDIC/UTF-16/UTF-7 — *fixes today's label-only
`charset_header`* (M); multipart boundary tricks + JSON parser confusion + HPP
depth (M); new attack-class mutators + KB seeds: NoSQL/LDAP/XPath/SSTI-polyglot/CRLF/SSI (M).

## Phase C — Generation & eval model  *(GoTestWAF parity, then past it)*

| # | Item | Effort | Module |
|---|---|---|---|
| C1 | **`payload × encoder × placeholder` combinatorial generator** + full placeholder set (URLParam/Path, Header, UA, Body, JSON{Body,Request}, HTMLForm, Multipart, SOAP/XML, gRPC, **RawRequest `{{payload}}`**). | **L** | `engine`, `core/transforms` |
| C2 | **DONE.** Coverage / false-positive scoring (`waffen eval`): block/pass/unresolved via calibration, per-class coverage %, benign FP rate, corpus harvest, JSON + gap dump, and a **styled standalone HTML report** (`--html`, light/dark, escaped gap payloads). Ported `corpus_runner` into the tool. Remaining: API-vs-App split. | **M** | `eval`, `report/html` |
| C3 | **go-ftw / CRS YAML regression format** (`meta/rule_id/tests[]/stages[]`, `encoded_request`, `output.log.expect_ids`), + **auto-emit every confirmed bypass as a new RedEye negative test** (offense→defense loop). | **M** | `eval`, `kb` |
| C4 | **Generalized semantic verification**: extend v1 verifier with reflection-execution context, OOB/interactsh, and nuclei-style `time_delay` linear-regression confirmation. | **M** | `verify` |

## Phase D — Model-learning & structural  *(research frontier; unique to WAFFEN)*

| # | Item | Effort | Module |
|---|---|---|---|
| D1 | **DONE.** GOFA-lite normalization learner (`waffen bypass --learn`): membership-query probes map the WAF's fold/strip/decode behaviour; `blind_to` transforms (ones the WAF can't see) reorder the mutator set so informed mutations come first. `recon/normalize.py`, wired into engine; mock proves blind-spot detection (html-entity/unicode) + mutator reordering. | **M** | `recon`, `engine` |
| D2 | **DONE (transforms).** Parser-differential / structural transforms (WAFFLED split-brain): 8 envelope distortions — JSON (dup-key, unicode-key, array-wrap, nested-junk), multipart (dup-disposition, filename-confusion, boundary-whitespace), XML — sweepable via `--transforms structural`. Remaining: the full 3-part oracle (WAF passes + backend parses + payload lands) in `verify`. | **M** | `core/transforms`, `verify` |
| D3 | **Raw-socket transport** → real HTTP smuggling desync suite (CL.TE/TE.CL/TE.TE, TE obfuscations, H2 downgrade). Current curl path can't desync. | **L** | `core/http` |
| D4 | SFADiff-lite differential automata; DRL/PPO policy search. | **L** | `search` (defer; DRL breaks stdlib-only) |

## Phase E — Distribution, recon-driven planning, performance

| # | Item | Effort | Module |
|---|---|---|---|
| E1 | **Auto-updating KB** (nuclei model: local version stamp vs GitHub release tag → download on mismatch; `waffen kb update`; per-source toggles). Ship payload/tamper/signature packs independent of the binary. | **S/M** | `kb` |
| E2 | **Fingerprint → test-plan mapping**: each vendor record carries known-weak placeholder/encoder combos + body-inspection limit; recon auto-selects the search plan and padding size. + **content-type-aware padding with auto binary-search of the real cutoff** (nowafpls++). | **M** | `recon`, `core/transforms`, `kb` |
| E3 | **Concurrency / rate engine** (ffuf model: worker pool via `oracle.send_many`, `--rate`, matchers/filters, recursion). | **M** | `engine` |

---

## The 42 missing mutation techniques (Phase B detail)

Impl: **M** = str→str mutator · **T** = request transform.

SQLi: keyword-doubling(S) · `%uXXXX`(S) · percentage stray-%(S) · multibyte quote
`%bf%27`/`%00%27`(S) · whole-query `/*!…*/` wrap(S) · intra-keyword comments(S) ·
`(`→`/**/(`(S) · space2dash/hash/mysqldash/mssqlhash(S) · multiplespaces(S) ·
comma-less MID/LIMIT(M) · function-equivalence greatest/least/ifnull/if2case/
substring2leftright(M) · information_schema split(S) · `0x`↔CHAR()(S) · vendor-tuned
bluecoat/securesphere/luanginx/odbcbrace/oraclequote(M) · halfversioned+escapequotes(S).
XSS: **mXSS** vectors(M) · polyglots(S) · semicolon-less entities(S) · entity-break
scheme `java&Tab;script:`(S) · JS rebuild fromCodePoint/octal/`eval(atob())`/bracket-access(M)
· UTF-7(S) · rare tag/handler bank(S). Unicode: **case-folding pre-images**(M) ·
NFKC/best-fit pre-image mapper(M) · U+2028/2029(S). Cmd: wildcard glob(S) ·
backslash split(S) · `${IFS}`/`${PATH:0:1}` synthesis(M) · reverse/base64 exec(M) ·
quote/positional noise(S). Path: `....//` self-ref(S) · 16-bit `%uXXXX`+overlong(S) ·
Windows trailing-dots/`::$DATA`(S) · more wrappers php://input/expect://phar://glob://+RFI(S).
Body: **real charset re-encode** EBCDIC/UTF-16/UTF-7(T,M) · multipart boundary tricks(T,M) ·
JSON confusion dup-keys/`\u`(T,M) · gzip body(T,S) · absent Content-Type(T,S) ·
HPP depth body/cookie/`param[]=`(T,M) · spoofed-IP headers XFF/X-Originating-IP(T,S).
Smuggling: raw-socket desync suite(T,L).

---

## Recommended first sprint (max edge, ~1 week, all S + one M)

1. **A1** composite timing/differential fitness — the unlock.
2. **A3** bandit operator-selection + blocked-pattern memory.
3. **A5** best-first frontier + benchmark harness (beam vs genetic vs bestfirst).
4. **B quick-win cluster** (~12 high-ROI mutators, incl. fixing the label-only charset transform note).
5. **A2** auto-calibration (the one M) — so verdicts stop assuming "403 = blocked".

After that sprint, benchmark all strategies on the mock, then do the first
**live, isolated** run against juice-shop (needs the old `pathrun` stopped + IP
unbanned) to validate on the real RedEye WAF. Then A4 (MCTS) is the flagship push.
