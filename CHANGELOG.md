# Changelog

All notable changes to WAFFEN are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions follow SemVer.

## [2.0.0] — 2026-11-23

### Added
- **RL Q-learning bypass agent** (`--strategy rl`): treats the WAF as an MDP, learns which mutations work via epsilon-greedy exploration. Policy save/load for transfer between WAFs.
- **Semantic preservation engine** (`waffen semantic`): 35+ mathematically equivalent SQL tautologies, string/number equivalence generators. 5 multi-variant mutators. Mutators 231 → 236.
- **Attack graph planner** (`waffen plan`): model target as directed graph, Dijkstra shortest path to goals (dump_database, admin_access, rce, xss_stored, account_takeover). Auto-discover + execute.
- **Grammar-guided fuzzing** (`waffen grammar`): context-free grammars for SQL (30 rules), XSS (20 rules), SSTI (15 rules). Every payload syntactically valid by construction. Coverage and targeted modes.
- **LLM payload synthesis** (`waffen synthesize`): Claude/GPT API generates context-aware bypass payloads from WAF profile (detected keywords, gap tokens). Privacy-safe: only keyword lists sent.
- **WAF rule reverse engineering** (`waffen rulemap`): 86 CRS rule signatures across 11 categories, PL1–PL4. Black-box probing maps active/inactive rules, estimates paranoia level.
- **Multi-WAF differential fuzzing**: `waffen diff --targets "CRS=URL1,RedEye=URL2"` finds payloads one WAF blocks but another misses.
- **Side-channel timing oracle** (`waffen sidechannel`): extract WAF internal scoring from response timing. 1D k-means rule cluster mapping.
- **Autonomous daemon** (`waffen daemon`): 24/7 monitoring with periodic assessment cycles, Slack/Discord webhook alerts on new bypasses or WAF changes.

## [1.3.0] — 2026-11-23

### Added
- Grammar-guided fuzzing engine (`waffen/grammar/`): SQL, XSS, SSTI grammars.
- LLM-guided payload synthesis (`waffen/ai/`): Anthropic + OpenAI API support.
- WAF rule reverse engineering (`waffen/recon/rulemap.py`): 86 CRS signatures.

## [1.2.0] — 2026-11-23

### Added
- Multi-WAF differential fuzzing (`waffen diff --targets`).
- Side-channel timing oracle (`waffen sidechannel`).
- Continuous autonomous daemon (`waffen daemon`) with Slack webhook alerts.

## [1.1.0] — 2026-11-23

### Added
- **SQLi exploitation engine** (`waffen exploit`): 4 techniques (UNION, error-based, boolean-blind, time-blind) × 4 DBMS engines (SQLite, MySQL, PostgreSQL, MSSQL). Bypass-aware mutation wrapping.
- **Dockerfile** + docker-compose.yml: `docker run --rm akhatkulov/waffen auto --url URL -y`
- **Response LRU cache** (256 entries) and connection keep-alive reuse for speed.

## [1.0.1] — 2026-11-23

### Fixed
- README rewritten: all 39 subcommands documented.
- CLI consistency: `--target` alias on `auto` and `origin` subcommands.
- 15 integration tests (bypass e2e with 4 strategies, dry-run, CLI entrypoints).
- 13 h2_attacks tests covering all 7 HTTP/2 attack functions.
- Safe plugin loading: broken plugin prints warning instead of crashing WAFFEN.
- `--dry-run` flag on bypass: shows request estimate before spending budget.
- `--corpus` flag on auto mode.

## [1.0.0] — 2026-11-23

### Added
- **HTTP/2 native transport** (`--transport h2`): minimal stdlib-only H2 client with TLS ALPN, HPACK encoding, CONTINUATION frames. 7 H2-specific WAF bypass techniques (pseudo-header injection, continuation splitting, stream multiplex race, duplicate pseudo-headers, oversized header blocks, header case manipulation).

## [0.9.0] — 2026-11-23

### Added
- **High-speed async fuzzing** (`waffen fuzz`): threaded keep-alive pool, 500+ req/s. ffuf-style filters (-mc/-fc/-ms/-fs/-mr). Built-in wordlists (sqli/xss/path/param). Corpus integration.
- **Plugin system** (`waffen plugin`): `~/.waffen/plugins/` drop-in directory. Discover, load, unload, disable/enable. Scaffold template for new plugins.

## [0.8.0] — 2026-11-23

### Added
- **Origin IP discovery** (`waffen origin`): subdomain probing (45 names), MX records, SPF/TXT IPs, response header leaks, direct Host-header verification.
- **138 WAF fingerprint signatures**: cloud (Cloudflare, AWS, Azure, GCP, Akamai, Imperva, Sucuri, …), on-premise (ModSecurity, Coraza, NAXSI, Wallarm, …), CDN (Vercel, Netlify, Fly.io, …), regional (SafeLine, Safedog, 360, RedEye, …).
- **OOB callback server** (`waffen oob`): built-in HTTP listener for blind SSRF/XSS/XXE/RCE verification. Unique tracking tokens per payload. Payload generators for 5 vuln classes.
- **3002 payload corpus** (`waffen corpus`, `--corpus` flag): embedded across 14 attack classes.
- **Professional HTML reports** (`waffen report --html`): executive summary, findings with severity badges, remediation, dark/light theme, print-to-PDF.
- **GitHub Action security fix**: replaced eval + expression interpolation with env vars + bash array.

## [0.7.0] — 2026-11-23

### Added
- **GitHub Action CI gate** (`action.yml`): run WAF bypass testing in CI/CD, fail on verified bypass. SARIF output for GitHub Security tab.
- **WAF rule generation** (`waffen defend`): convert bypass findings into deployable rules for ModSecurity, NAXSI, Cloudflare, AWS WAF. Pattern extraction from 25+ chain types.
- **GraphQL attack module** (`waffen graphql`): introspection bypass (7 techniques), batch bypass, alias flood, directive injection, persisted query bypass. 4 new request transforms.
- **WebSocket attack module** (`waffen ws`): stdlib-only RFC 6455 client. Text/binary/fragmented frame injection, upgrade-request injection.

## [0.6.0] — 2026-11-23

### Added
- **SQL-AST-aware mutation** (`waffen/mutate/sql_ast.py`): lightweight SQL tokenizer (16 token kinds) + 10 mutation strategies (sqlite_swap, comment_split, case_mix, whitespace_swap, operator_equiv, comment_swap, function_wrap, concat_build, iif_wrap, number_obfuscate) + composite combinator. 11 new mutators including multi-variant `ast_combined`.
- **Multi-request attack sequences** (`waffen/core/sequence.py`): RequestStep chains with context extraction. 4 built-in sequences.

## [0.5.0] — 2026-11-23

### Added
- **Verifier-guided search**: 6 exploit signals (backend_error, sql_error, reflected, data_leak, response_diff, ssti) feed back into beam scoring. Eliminates ~90% false throughs.
- **Multi-variant mutators**: `apply_multi()` returns 5+ variants per call. Beam/bestfirst fan out all variants. 5 semantic_frag mutators upgraded.
- **Injection-point auto-discovery** (`waffen discover`): probes 28 query params, 16 JSON keys, 6 headers, 4 cookies, path segments.
- **Differential testing** (`waffen diff`): WAF vs origin comparison — WAF_ONLY / APP_ONLY / BOTH_BLOCK / BOTH_PASS / DESYNC.
- **Target profiles** (`--profile target.json --resume`): save/load/merge calibration, recon, search state.
- **Payload minimization** (`waffen minimize`): chain reduction + binary text trimming.
- **Live search progress**: per-depth callbacks in all 4 strategies. Per-transform status lines. Graceful Ctrl-C saves partial results.

## [0.4.1] — 2026-11-22

### Fixed
- **Adaptive pipeline crash**: 3 API mismatches in `_stage_gaps` (add_gap_report→add_gap_reports, wrong method names). This caused the adaptive run to hang on live targets.
- **54 silent `except Exception: pass`** replaced with proper error logging across 16 files.
- **36% mutator waste**: pre-filter drops identity/empty mutators before search. Identity check moved before oracle.send in beam sequential path.
- **Auto transport selection**: `transport="auto"` uses pooled for identity transforms, curl for structural.
- Deduplicated ~110 lines SQLite template logic. Fixed gradient.py monkey-patch. Added --no-reconstruct CLI flag. Interruptible watch sleep. Class name aliases.
- 97 new tests for 4 previously untested modules (scoring, rawhttp, coverage, update).

## [0.4.0] — 2026-11-11

### Added
- **Response clustering** (`waffen calibrate --cluster`): stdlib k-means++ with silhouette auto-k, discovers full WAF response taxonomy (PASS/BLOCK/CHALLENGE/RATELIMIT).
- **Gradient scoring** (`--fitness gradient`): 10-feature fitness from response metadata. Logistic regression weight calibration.
- **Payload reconstruction** (`waffen/recon/reconstruct.py`): auto-generates exploit templates from score-probe boundary payloads and libinjection gap tokens.
- **Cross-axis composition** (`--cross-axis`): mutated payload × structural transform simultaneously. Top-N payloads × top-J transforms.
- **Adaptive 5-stage pipeline** (`waffen adaptive`): learn → score-probe → gap-scan → search → deepen. Each stage's output tunes the next.

## [0.3.0] — 2026-11-11

### Added
- **Auto wizard mode** (`waffen auto`): guided interactive setup, runs fingerprint → calibrate → score-probe → libinjection-scan → bypass search automatically. Non-interactive with `-y`.
- **Score threshold prober** (`waffen score-probe`): WAF scoring engine threshold binary search. Keyword detection map, progressive strip chain, boundary payloads.
- **libinjection gap scanner** (`waffen libinjection-scan`): 110+ database-specific tokens across SQLite/PostgreSQL/MySQL/MSSQL. Context templates, exploit seed generator.
- **23 semantic fragmentation mutators**: keyword concat split (3 dialects), SQLite operator swap, comment interleave, CASE/IIF wrap, whitespace variation, numeric obfuscation, XSS tag/event fragmentation.
- **32 SSTI/SSRF/XXE class-specific mutators**: Jinja2/Twig/Freemarker, IP encoding variants, DTD/entity/XInclude. Mutators 165 → 220.
- **WAF regression watch** (`waffen watch`): re-test saved findings, track ALIVE/BLOCKED/ERROR, diff reports.

## [0.2.0] — 2026-11-10

Validated across **five WAFs and three detection models** (RedEye, OWASP CRS, BunkerWeb,
NAXSI, open-appsec). See prior changelog entry for full details.

## [0.1.0] — 2026-11-07

First tagged release. See prior changelog entry for full details.

[2.0.0]: https://github.com/akhatkulov/WAFFEN/releases/tag/v2.0.0
[1.3.0]: https://github.com/akhatkulov/WAFFEN/releases/tag/v1.3.0
[1.2.0]: https://github.com/akhatkulov/WAFFEN/releases/tag/v1.2.0
[1.1.0]: https://github.com/akhatkulov/WAFFEN/releases/tag/v1.1.0
[1.0.1]: https://github.com/akhatkulov/WAFFEN/releases/tag/v1.0.1
[1.0.0]: https://github.com/akhatkulov/WAFFEN/releases/tag/v1.0.0
[0.9.0]: https://github.com/akhatkulov/WAFFEN/releases/tag/v0.9.0
[0.8.0]: https://github.com/akhatkulov/WAFFEN/releases/tag/v0.8.0
[0.7.0]: https://github.com/akhatkulov/WAFFEN/releases/tag/v0.7.0
[0.6.0]: https://github.com/akhatkulov/WAFFEN/releases/tag/v0.6.0
[0.5.0]: https://github.com/akhatkulov/WAFFEN/releases/tag/v0.5.0
[0.4.1]: https://github.com/akhatkulov/WAFFEN/releases/tag/v0.4.1
[0.4.0]: https://github.com/akhatkulov/WAFFEN/releases/tag/v0.4.0
[0.3.0]: https://github.com/akhatkulov/WAFFEN/releases/tag/v0.3.0
[0.2.0]: https://github.com/akhatkulov/WAFFEN/releases/tag/v0.2.0
[0.1.0]: https://github.com/akhatkulov/WAFFEN/releases/tag/v0.1.0
