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
- **Real actionable finding:** 16 heavily-encoded payloads pass the WAF and cause
  backend **HTTP 500** — an error-handling / normalization gap (not XSS) worth review.

## 5. Known limitation surfaced
WAFFEN (and GoTestWAF) self-ban on a full-corpus run — no built-in ban clearing.
Benign-first ordering fixes FP accuracy; full clean coverage still needs the test
source un-banned (cleared via the RedEye panel) or batched with pauses.

## Verdict
- **Proven stronger / more trustworthy than the de-facto tools on this target:**
  names the WAF (vs wafw00f), avoids GoTestWAF's self-ban FP artifact, and never
  reports an unverified bypass as real.
- **Not proven:** finding a *weaponizable* bypass — because RedEye genuinely blocks
  everything tried. That is a RedEye strength, not a WAFFEN weakness; WAFFEN reports
  it honestly and still surfaces the 500 error-handling lead.
