# WAFFEN — Real-target validation (RedEye / juice-shop.redeyes.uz)

Honest record of live testing against the team's own RedEye-protected demo. All
runs are against an authorized target the team owns.

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

## Verdict
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
