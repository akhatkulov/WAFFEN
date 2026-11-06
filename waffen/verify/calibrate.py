"""Runtime auto-calibration of the WAF's block/pass signature.

WAFFEN's `Oracle` ships with a *naive* classifier baked in: "HTTP 403 with the
configured `block_signature` substring == BLOCKED, everything else that isn't
down is THROUGH". That assumption is exactly as brittle as every other tool's
(ffuf treats any status as a hit until you tell it `-ac`; wfuzz needs a manual
baseline; wafw00f's `genericdetect` only differentiates on status/Server
header). Real WAFs:

  - block with 200 (soft-block custom error pages), not just 403/406/429/503
  - have an app that legitimately returns 403 for unrelated reasons (auth)
  - sit in front of apps whose own error pages coincidentally resemble a WAF
    block page (same status, similar size) — GoTestWAF calls this the
    **unresolved** bucket and refuses to guess
  - are occasionally *absent* entirely (benign and malicious traffic get
    indistinguishable responses) — wafw00f's whole job is detecting that case

This module learns an *empirical* block/pass fingerprint at the start of a
run by sending known-benign and known-malicious probes (ffuf `-ac` /
wfuzz-baseline style) and clustering the responses, instead of hardcoding
"403 == blocked" anywhere downstream.

Timing is treated as a *secondary, best-effort* signal only (per
`docs/COMPETITIVE_RESEARCH.md` section C / the 0xInfection timing
side-channel research): WAF-layer rejections are often faster than requests
that reach the backend, but shared infra, caching, jitter and network noise
make this unreliable in general. We only ever trust it when the calibration
probes show a *clean, non-overlapping* separation between block-time and
pass-time samples (median ± MAD), and even then it is used only as a
tie-breaker, never as the primary signal.
"""
from __future__ import annotations

import statistics
from dataclasses import dataclass, field

from waffen.core.oracle import Oracle, Response

# ---------------------------------------------------------------------------
# Default calibration probes
# ---------------------------------------------------------------------------

#: Harmless search-term style strings — should always reach the origin on a
#: well-behaved app, WAF or no WAF.
DEFAULT_BENIGN_PROBES = [
    "banana juice",
    "hello world",
    "red shoes size 9",
    "contact support",
    "weather forecast",
    "quarterly report 2024",
]

#: Obvious, textbook attacks any half-decent WAF should block. Deliberately
#: unobfuscated so a competent WAF has no excuse to let them through — if it
#: does, that's a real finding (waf_detected=False), not a calibration bug.
DEFAULT_ATTACK_PROBES = [
    "<script>alert(1)</script>",
    "' OR 1=1-- -",
    "../../../../etc/passwd",
    "UNION SELECT NULL",
    "<img src=x onerror=alert(1)>",
    "1' AND SLEEP(5)-- -",
]


def _take(seq, n):
    seq = list(seq)
    if n <= 0 or n >= len(seq):
        return seq
    return seq[:n]


# ---------------------------------------------------------------------------
# Calibration model
# ---------------------------------------------------------------------------

@dataclass
class _Profile:
    """A learned cluster summary for one response population (block or pass)."""
    codes: set[str] = field(default_factory=set)
    sizes: list[int] = field(default_factory=list)
    times: list[float] = field(default_factory=list)
    markers: set[str] = field(default_factory=set)  # short body substrings seen repeatedly

    @property
    def size_band(self) -> tuple[int, int]:
        if not self.sizes:
            return (0, 0)
        lo, hi = min(self.sizes), max(self.sizes)
        pad = max(int(0.1 * hi), 8)
        return (max(0, lo - pad), hi + pad)

    @property
    def median_time(self) -> float:
        return statistics.median(self.times) if self.times else 0.0

    @property
    def mad_time(self) -> float:
        if not self.times:
            return 0.0
        med = self.median_time
        return statistics.median([abs(t - med) for t in self.times]) or 0.0


def _common_marker(bodies: list[str], min_len: int = 12) -> str:
    """Best-effort: find a substring common to every body in `bodies`.

    Not a true longest-common-substring across the whole set (that's
    overkill here) — just checks whether the single longest candidate
    substring of the shortest body also appears in all the others. Good
    enough to pick up a stable "Request blocked by ..." style marker
    without pulling in extra dependencies.
    """
    bodies = [b for b in bodies if b]
    if len(bodies) < 2:
        return bodies[0][:60] if bodies else ""
    shortest = min(bodies, key=len)
    # try decreasing window sizes over the shortest body, longest-first
    for size in range(min(len(shortest), 120), min_len - 1, -4):
        for start in range(0, len(shortest) - size + 1, 4):
            cand = shortest[start:start + size]
            if cand.strip() and all(cand in b for b in bodies):
                return cand.strip()
    return ""


@dataclass
class Calibration:
    """Learned model of what a WAF-block response looks like vs. a normal pass.

    Fields
    ------
    waf_detected:
        False when benign and malicious probes produced indistinguishable
        responses — i.e. there's nothing to calibrate against.
    block_codes / pass_codes:
        Status codes observed for the attack probes vs. the benign probes.
        Overlap is expected and handled (status alone is rarely decisive).
    block_size_band / benign_profile:
        (lo, hi) body-size bands learned from each cluster, padded ~10%.
    block_marker:
        A representative substring seen across the block responses (e.g. the
        WAF's own error-page copy). Empty string if no stable marker found.
    timing_reliable / block_is_faster / timing_threshold:
        Best-effort timing model. `timing_reliable` is only True when the
        block-time and pass-time samples (by median ± MAD) do not overlap;
        in that case `timing_threshold` sits at the midpoint and
        `block_is_faster` records which side is quicker. Never treat timing
        as authoritative — see module docstring.
    confidence:
        Rough [0, 1] score for how trustworthy this whole calibration is:
        1.0 means clean separation on every signal (status, size, marker,
        timing); it drops as signals go ambiguous or are unavailable.
    """
    waf_detected: bool = False
    block_codes: set[str] = field(default_factory=set)
    pass_codes: set[str] = field(default_factory=set)
    block_size_band: tuple[int, int] = (0, 0)
    benign_size_band: tuple[int, int] = (0, 0)
    block_marker: str = ""
    benign_profile: dict = field(default_factory=dict)  # status/size/time summary
    timing_reliable: bool = False
    block_is_faster: bool | None = None
    timing_threshold: float | None = None
    confidence: float = 0.0
    samples: int = 0

    # -- classification -----------------------------------------------------
    def is_block(self, resp: Response) -> bool:
        return self.classify(resp) == "block"

    def classify(self, resp: Response) -> str:
        """Classify one response as "block" | "pass" | "unresolved".

        Rules (in order):
          1. If the WAF wasn't detected at calibration time, we have no
             learned block fingerprint to match against — everything that
             isn't DOWN is a "pass" (falls back to the oracle's own verdict
             for transport failures).
          2. Strong block match: status in `block_codes` AND (marker present
             in body OR size falls in `block_size_band`). -> "block"
          3. Strong pass match: status in `pass_codes` AND size falls in
             `benign_size_band` AND the block marker is absent. -> "pass"
          4. Ambiguous (e.g. 403 with no marker and a body size squarely in
             the benign band, or a status/size combo seen in both clusters)
             -> "unresolved", unless a reliable timing threshold can break
             the tie.
        """
        code, size, body = resp.code, resp.size, (resp.body or "")

        if resp.verdict == "DOWN":
            return "unresolved"

        if not self.waf_detected:
            return "pass"

        has_marker = bool(self.block_marker) and self.block_marker in body
        in_block_band = self._in_band(size, self.block_size_band)
        in_pass_band = self._in_band(size, self.benign_size_band)

        code_says_block = code in self.block_codes
        code_says_pass = code in self.pass_codes and code not in self.block_codes

        block_match = code_says_block and (has_marker or in_block_band)
        pass_match = code_says_pass and in_pass_band and not has_marker

        if block_match and not pass_match:
            return "block"
        if pass_match and not block_match:
            return "pass"
        if block_match and pass_match:
            # Both fired (overlapping codes/bands) — let the marker decide,
            # then timing, else unresolved.
            if has_marker:
                return "block"
            return self._timing_tiebreak(resp.time, default="unresolved")

        # Neither matched cleanly.
        if code_says_block and not has_marker and not in_block_band:
            # e.g. app itself returns 403 for unrelated reasons (auth, etc.)
            return self._timing_tiebreak(resp.time, default="unresolved")
        if code_says_pass and not in_pass_band:
            return self._timing_tiebreak(resp.time, default="unresolved")

        return self._timing_tiebreak(resp.time, default="unresolved")

    def _timing_tiebreak(self, t: float, default: str) -> str:
        if not self.timing_reliable or self.timing_threshold is None or self.block_is_faster is None:
            return default
        faster = t <= self.timing_threshold
        if faster == self.block_is_faster:
            return "block"
        return "pass"

    @staticmethod
    def _in_band(size: int, band: tuple[int, int]) -> bool:
        lo, hi = band
        return lo <= size <= hi


# ---------------------------------------------------------------------------
# Calibration procedure
# ---------------------------------------------------------------------------

def calibrate(
    oracle: Oracle,
    *,
    benign_samples: list[str] | None = None,
    attack_samples: list[str] | None = None,
    n: int = 6,
) -> Calibration:
    """Probe `oracle` with known-benign + known-malicious payloads and learn
    the WAF's actual block/pass fingerprint (ffuf `-ac` / wfuzz-baseline /
    wafw00f `genericdetect` style), instead of trusting a hardcoded 403 check.

    Parameters
    ----------
    oracle:
        The `Oracle` to probe. Each probe costs one `oracle.send()` call.
    benign_samples / attack_samples:
        Caller overrides for the probe sets. Defaults to
        `DEFAULT_BENIGN_PROBES` / `DEFAULT_ATTACK_PROBES`, trimmed to `n`.
    n:
        How many probes to send per bucket (<=0 or >= len(defaults) sends
        them all).
    """
    benign_samples = _take(benign_samples if benign_samples is not None else DEFAULT_BENIGN_PROBES, n)
    attack_samples = _take(attack_samples if attack_samples is not None else DEFAULT_ATTACK_PROBES, n)

    benign_resps = [oracle.send(p) for p in benign_samples]
    attack_resps = [oracle.send(p) for p in attack_samples]

    pass_profile = _Profile(
        codes={r.code for r in benign_resps},
        sizes=[r.size for r in benign_resps],
        times=[r.time for r in benign_resps],
    )
    block_profile = _Profile(
        codes={r.code for r in attack_resps},
        sizes=[r.size for r in attack_resps],
        times=[r.time for r in attack_resps],
    )

    cal = Calibration(samples=len(benign_resps) + len(attack_resps))
    cal.pass_codes = set(pass_profile.codes)
    cal.block_codes = set(block_profile.codes)
    cal.benign_size_band = pass_profile.size_band
    cal.benign_profile = {
        "codes": sorted(cal.pass_codes),
        "size_band": cal.benign_size_band,
        "median_time": pass_profile.median_time,
    }

    # -- WAF-presence detection --------------------------------------------
    # If the two clusters have the same status codes AND overlapping size
    # bands AND no distinguishing marker, benign and malicious are
    # indistinguishable -> no WAF (or a WAF that isn't acting on these
    # probes at all).
    marker = _common_marker([r.body for r in attack_resps])
    marker_is_distinctive = bool(marker) and not any(marker in (r.body or "") for r in benign_resps)

    codes_distinct = bool(block_profile.codes - pass_profile.codes) or bool(
        pass_profile.codes - block_profile.codes
    )
    bands_distinct = _bands_disjoint(block_profile.size_band, pass_profile.size_band)

    waf_detected = marker_is_distinctive or codes_distinct or bands_distinct
    cal.waf_detected = waf_detected

    if not waf_detected:
        cal.confidence = 0.1
        return cal

    cal.block_marker = marker if marker_is_distinctive else ""
    cal.block_size_band = block_profile.size_band

    # -- timing model --------------------------------------------------------
    if block_profile.times and pass_profile.times:
        b_med, b_mad = block_profile.median_time, block_profile.mad_time
        p_med, p_mad = pass_profile.median_time, pass_profile.mad_time
        # "clean separation" = the MAD-padded ranges don't overlap at all
        b_lo, b_hi = b_med - b_mad, b_med + b_mad
        p_lo, p_hi = p_med - p_mad, p_med + p_mad
        if b_hi < p_lo or p_hi < b_lo:
            cal.timing_reliable = True
            cal.block_is_faster = b_med < p_med
            cal.timing_threshold = (b_med + p_med) / 2.0

    # -- confidence ------------------------------------------------------
    score = 0.0
    if marker_is_distinctive:
        score += 0.4
    if codes_distinct:
        score += 0.3
    if bands_distinct:
        score += 0.2
    if cal.timing_reliable:
        score += 0.1
    cal.confidence = min(1.0, max(score, 0.3))  # waf_detected implies >=0.3

    return cal


def _bands_disjoint(a: tuple[int, int], b: tuple[int, int]) -> bool:
    return a[1] < b[0] or b[1] < a[0]
