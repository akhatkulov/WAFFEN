# WAFFEN — Competitive R&D

Teardown of every notable WAF testing / evasion / bypass-discovery project, and
exactly what WAFFEN should take from each. Research basis for `ROADMAP.md`.
(For hardening our own RedEye WAF; all sources are public tools / papers.)

## The one-line thesis

**Every existing tool is static, open-loop, and unverified.** They fire fixed
payload sets (GoTestWAF, WAFNinja, WhatWaf, nuclei), match on generic response
shape (ffuf, wfuzz), only fingerprint (wafw00f), or are one-shot manual actions
(nowafpls). None does **feedback-driven search**, none **learns the WAF's
normalization model**, and none **verifies a bypass is still exploitable**.

WAFFEN wins by being **closed-loop + model-learning + verified**:
recon-driven plan → combinatorial generation → composable transforms → **guided
search (bandit/MCTS)** scored by a **runtime-learned WAF oracle + timing** →
**semantic verification** → auto-filed RedEye regressions, fed by an
**auto-updating KB**, graded on false-positives too.

---

## A. Open-source tooling

| Tool | Biggest strength | ADOPT | BEAT |
|---|---|---|---|
| **GoTestWAF** (Wallarm) | `payload × encoder × placeholder` matrix | The combinatorial generator; full placeholder set (URLParam, URLPath, Header, UserAgent, RequestBody, JSON{Body,Request}, HTMLForm, HTMLMultipartForm, SOAP/XMLBody, gRPC, **RawRequest** with `{{payload}}`); encoders (Base64, Base64Flat, JSUnicode, URL, Plain, XMLEntity); **block/pass/unresolved** buckets; **false-positive set** as a first-class pass; API-vs-App scoring; embedded OWASP/OWASP-API/community sets; converts OWASP CRS regression suite | Pure brute matrix, single-level encoders, no guided search, no semantic verification |
| **wafw00f** | 172-WAF fingerprint DB | Plugin model (`matchHeader/matchCookie/matchContent/matchStatus/matchReason`); **`genericdetect` differential** (UA removed, XSS/LFI/SQLi status differs, Server header differs) as active fingerprinting; attack probe strings | Fingerprint-only; static header/cookie regex; status-only differential (no full block-signature model) |
| **WAFNinja** | Shared payload DB with **expected-result** field | The `input / expected / type` knowledge triple → classify symbol as allowed/blocked/filtered-but-passed; team-shared DB (`set-db`); `FUZZ`/`PAYLOAD` injection tokens | Unmaintained; GET/POST+cookie only; replays static list; never synthesizes from the learned allowed-alphabet |
| **WhatWaf** | 36 composable **tamper scripts** | The full tamper taxonomy (whitespace/comment/encoding/case/null/junk/quote); `-e PAYLOAD tamper1 tamper2` **chaining**; `--verify-num` presence confirmation; JSON/YAML/CSV export + DB cache | Tampers applied blindly (no per-WAF feedback); manual chain order; nondeterministic randoms |
| **nowafpls** | Content-type-aware **junk padding** past body-inspection byte limit | The padding technique (URLEncoded/JSON/XML/multipart); the **vendor inspection-limit table** (CF 128KB, AWS 8–64KB, Akamai 8–128KB, Azure 128KB, GCP 8→128KB, …) → `kb/` | Manual one-shot; guesses size from static table (WAFFEN can binary-search the real cutoff) |
| **go-ftw** + OWASP CRS suite | Declarative YAML **regression** w/ rule-ID log assertions | The exact schema (`meta/rule_id/tests[]/stages[]`, `input` incl. `encoded_request`/`autocomplete_headers`, `output.log.expect_ids/no_expect_ids`); `X-CRS-TEST` log-marker race handling | Offense-blind (re-checks known rules only); needs WAF log (self-hosted) |
| **ffuf** | **Auto-calibration** of baseline/FP | `-ac/-acc/-acs/-ach` runtime baseline learning; matchers/filters (`-mc/-ml/-mw/-ms/-mr/-mt`, and/or modes); concurrency (`-t`, `-rate`, `-p` delay); recursion; clusterbomb/pitchfork/sniper | Content-discovery fuzzer, not WAF-aware (no block-vs-app-403 concept); one baseline only |
| **wfuzz** | Composable payload→iterator→encoder→filter pipeline | Multiple injection points (`FUZZ…FUZnZ`); iterators (product/zip/chain); chained+multiplied encoders (`-`/`@`); `FUZZ{baseline}`/BBB auto-filter; `--filter` boolean grammar | Same WAF-blindness as ffuf |
| **nuclei** + templates | Data-driven fuzzing schema + **time-based verification analyzer** | `fuzzing:` schema (`part/type/mode/keys/keys-regex/values/fuzz`, `pre-condition` DSL gate, named `payloads`); **`analyzer: time_delay`** (alternating-delay probes + linear regression) → generalize to all bypass verification; **auto-update** (local version stamp vs GitHub release tag → download on mismatch, `-ut/-tv/-duc`); DAST mode over real traffic | Rule-driven not search-driven; only time_delay verification; generic templates not WAF-tuned |

---

## B. Mutation / evasion technique catalog (gap analysis vs WAFFEN's 123+10)

Canonical sources: **SQLMap tamper (83 scripts)**, PayloadsAllTheThings (~65 classes),
PortSwigger/OWASP XSS cheat sheets, PortSwigger/Kettle HTTP smuggling, NCC/Dalili
charset bypasses, Awesome-WAF normalization tables.

**WAFFEN already has** broad equivalents of ~40 SQLMap tampers, core XSS context
tricks, traversal/cmd separators + wrappers, and url/entity/unicode/overlong
encoders. **Missing, high-value** (full 42-item table in `ROADMAP.md` Phase B):

- **SQLi:** keyword-doubling (`SELSELECTECT`, nonrecursive), `%uXXXX` percent-unicode,
  `percentage` stray-`%`, multibyte quote `%bf%27`, whole-query `/*!…*/` wrap,
  intra-keyword random comments, `space2dash/hash`, `information_schema` split,
  **comma-less** rewrites (MID…FROM…FOR, LIMIT…OFFSET), function-equivalence
  (greatest/least/ifnull/if2case), vendor-tuned (bluecoat/securesphere/luanginx/
  odbcbrace/oraclequote), `0x`↔`CHAR()`.
- **XSS:** **mutation XSS (mXSS)** (`</noscript>`, `<xmp>`, SVG/MathML foreign content),
  polyglots, **semicolon-less entities** (`&#106`, `&Tab`), entity-break in scheme
  (`java&Tab;script:`), JS rebuild (`fromCodePoint`, octal, `eval(atob())`, bracket
  property access), UTF-7, rare tag/handler bank.
- **Unicode:** **case-folding pre-images** (ſ→s, U+212A→k, İ/ı, ß→ss), systematic
  NFKC/best-fit pre-image mapper, U+2028/U+2029 JS separators.
- **Cmd:** wildcard/glob (`/???/c?t`), backslash split (`c\at`), `${IFS}`/`${PATH:0:1}`
  substring synthesis, reverse/base64-decode exec, quote/positional noise.
- **Path:** `....//` self-referential, 16-bit `%uXXXX`/extra overlong, Windows
  trailing-dots/`::$DATA`, more wrappers (php://input, expect://, phar://, glob://) + RFI.
- **Body framing:** **real charset re-encode** (EBCDIC/UTF-16/UTF-7 — current
  `charset_header` is label-only!), multipart boundary tricks, JSON parser confusion
  (duplicate keys, `\u`), gzip body, absent/mismatched Content-Type, HPP depth,
  spoofed-origin IP headers.
- **Smuggling (needs raw-socket transport):** CL.TE/TE.CL/TE.TE, TE obfuscations, H2 downgrade.

---

## C. State-of-the-art search algorithms (the decisive edge)

| Work | Core idea | ADOPT | Needs WAF score? |
|---|---|---|---|
| **WAF-A-MoLE** (SAC'20) | Best-first priority queue over payloads ranked by WAF confidence; 8 semantics-preserving MySQL operators | The priority-queue frontier; the 8 operators. **Benchmark to beat** | **Yes** — degenerates to random on binary feedback (its fatal weakness = our opening) |
| **AdvSQLi** (TIFS'24) / **AutoSpear** (BH Asia'22) / **WAFUzz** (2025) | **MCTS + UCB over a CFG** mutation tree; boundary locked, query mutates; geometric rule-weight decay | **The flagship new strategy.** Parse→token tree, UCB selection, CFG expansion, binary-reward backprop. Beats WAF-A-MoLE at ~⅓ the queries | **No** — explicitly works on **status-code-only** feedback. Generalizes to XSS too |
| **GOFA / SFADiff** (S&P'16/CCS'16) | Automata-learning of the filter model (membership + equivalence queries); bypass = string in `grammar ∩ ¬filter`; differential vs backend parser | **GOFA-lite normalization learner**: probe → learn WAF's fold/strip table → target mutations at the gaps. SFADiff-lite differential mode | **No** (binary) |
| **WAFFLED** (2025) | **Parser-differential / split-brain**: mutate the multipart/JSON/XML *envelope* so WAF misses the field but backend parses it; fixed un-obfuscated payload | Structural strategy with 3-part oracle (WAF passes + backend parses + payload lands in field). New bypass class needing **no obfuscation** | **No** (binary) |
| RL/PPO (Wang&Hu, Hemmati), bandits | Mutation-op policy from WAF reward | **UCB1/Thompson bandit operator-selection** folded into existing genetic/beam (cheapest sample-efficiency win); blocked-pattern memory | No (binary); DRL needs torch → defer |
| Timing side-channel (0xInfection) | Blocked req rejected at WAF returns **faster** than one reaching backend | **Composite response-differential + timing fitness** → turns binary into an ordered gradient: `blocked-fast < reached-backend(5xx/slow/error) < reflected-neutralized < reflected-intact < executed`. >95% block/pass separation | **No** — this *replaces* the score |

**Why this beats everyone:** GoTestWAF/WAFNinja do no guided search; WAF-A-MoLE
needs a score it won't have on a real WAF. MCTS+CFG+bandit on a timing/differential
gradient gives WAFFEN adaptive search **on pure binary feedback**, plus a learned
WAF model (GOFA-lite) and a structural bypass class (WAFFLED) nothing else has.

---

## Sources
GoTestWAF https://github.com/wallarm/gotestwaf · wafw00f https://github.com/EnableSecurity/wafw00f ·
WAFNinja https://github.com/khalilbijjou/WAFNinja · WhatWaf https://github.com/Ekultek/WhatWaf ·
nowafpls https://github.com/assetnote/nowafpls · go-ftw https://github.com/coreruleset/go-ftw ·
ffuf https://github.com/ffuf/ffuf · wfuzz https://wfuzz.readthedocs.io ·
nuclei https://docs.projectdiscovery.io/templates/protocols/http/fuzzing-overview ·
SQLMap tamper https://github.com/sqlmapproject/sqlmap/tree/master/tamper ·
PayloadsAllTheThings https://github.com/swisskyrepo/PayloadsAllTheThings ·
PortSwigger XSS https://portswigger.net/web-security/cross-site-scripting/cheat-sheet ·
mXSS https://cure53.de/fp170.pdf · HTTP smuggling https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn ·
WAF-A-MoLE https://arxiv.org/abs/2001.01952 · AdvSQLi https://arxiv.org/pdf/2401.02615 ·
AutoSpear https://github.com/luckksdfe/AutoSpear · WAFUzz https://proceedings.mlr.press/v278/mao25a.html ·
GOFA https://www.cs.columbia.edu/~angelos/Papers/2016/bba.pdf · SFADiff https://www.cs.columbia.edu/~angelos/Papers/2016/ccs-sfadiff.pdf ·
WAFFLED https://arxiv.org/html/2503.10846v4 · timing https://0xinfection.xyz/posts/fingerprinting-waf-rules-with-timing-based-side-channel-attacks/ ·
Awesome-WAF https://github.com/0xInfection/Awesome-WAF
