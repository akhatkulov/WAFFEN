"""Calibratable gradient scorer for WAF bypass search.

Extracts ~10 normalized features from each response and scores via a weighted
model. Weights start from heuristics (matching the existing gradient_score
shape) and can be refined from labeled calibration samples using logistic
regression — no external dependencies.

Against a scoring-engine WAF like RedEye, a richer, calibrated fitness surface
lets the search engine distinguish payloads that score 0.85 from those that
score 0.99, even though both produce a 403 — response metadata (size, timing,
headers) carries that signal.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field

from ..core.oracle import DOWN, THROUGH, Response

# ---- feature vector -------------------------------------------------------

N_FEATURES = 10

_FEAT_NAMES = [
    "status_bucket",       # 0: 200→1.0, 403→0.0, 5xx→0.5, other→0.3
    "size_delta",          # 1: |resp.size - baseline.size| / max(baseline.size,1), capped 1.0
    "time_delta",          # 2: (resp.time - baseline.time) / max(baseline.time,0.01), capped 1.0
    "status_changed",      # 3: 1.0 if resp.code != baseline.code else 0.0
    "is_5xx",              # 4: 1.0 if 5xx (reached backend)
    "body_sim_block",      # 5: 1.0=completely different from block page, 0.0=identical
    "body_sim_pass",       # 6: 1.0=identical to pass page, 0.0=completely different
    "error_detail",        # 7: 1.0 if backend error strings present
    "redirect_present",    # 8: 1.0 if 3xx
    "size_nonzero",        # 9: 1.0 if size > 0 and differs from block size
]

# default heuristic weights (mimics existing gradient_score shape)
_DEFAULT_WEIGHTS = [
    3.0,   # status_bucket: strong signal
    1.0,   # size_delta: moderate
    1.5,   # time_delta: slower = deeper
    2.0,   # status_changed: strong
    2.0,   # is_5xx: reached backend
    1.0,   # body_sim_block: different from block = good
    1.0,   # body_sim_pass: similar to pass = good
    1.5,   # error_detail: backend errors = payload reached
    0.5,   # redirect_present: weak signal
    0.3,   # size_nonzero: tie-breaker
]
_DEFAULT_BIAS = -3.0


def _clamp(v: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, v))


def _status_bucket(code: str) -> float:
    if not code or code == "000":
        return 0.0
    try:
        c = int(code)
    except ValueError:
        return 0.0
    if 200 <= c < 300:
        return 1.0
    if 300 <= c < 400:
        return 0.6
    if c == 403 or c == 406:
        return 0.0
    if 400 <= c < 500:
        return 0.2
    if 500 <= c < 600:
        return 0.5
    return 0.3


_ERROR_MARKERS = (
    "internal server error", "syntax error", "unexpected", "traceback",
    "exception", "stack trace", "error at", "sqliteexception",
    "sequelizedatabaseerror", "unhandledpromiserejection", "typeerror",
    "referenceerror", "enoent", "near \"", "sqlite3_",
)


def _has_error_detail(body: str) -> float:
    if not body:
        return 0.0
    low = body[:2000].lower()
    return 1.0 if any(m in low for m in _ERROR_MARKERS) else 0.0


def _body_similarity(a: str, b: str) -> float:
    """Quick Jaccard on 4-grams of the first 2000 chars. 0=nothing shared, 1=identical."""
    if not a or not b:
        return 0.0
    sa = a[:2000]
    sb = b[:2000]
    if sa == sb:
        return 1.0
    n = 4
    ga = set(sa[i:i + n] for i in range(len(sa) - n + 1)) if len(sa) >= n else {sa}
    gb = set(sb[i:i + n] for i in range(len(sb) - n + 1)) if len(sb) >= n else {sb}
    if not ga or not gb:
        return 0.0
    inter = len(ga & gb)
    union = len(ga | gb)
    return inter / union if union else 0.0


def extract_features(resp: Response, baseline: Response,
                     block_body: str = "", pass_body: str = "") -> list[float]:
    """Extract N_FEATURES normalized floats from a response relative to baseline."""
    f = [0.0] * N_FEATURES

    f[0] = _status_bucket(resp.code)

    denom_size = max(baseline.size, 1)
    f[1] = _clamp(abs(resp.size - baseline.size) / denom_size)

    denom_time = max(baseline.time, 0.01)
    f[2] = _clamp((resp.time - baseline.time) / denom_time, -1.0, 1.0)
    f[2] = (f[2] + 1.0) / 2.0  # shift to [0,1]

    f[3] = 1.0 if resp.code != baseline.code else 0.0

    f[4] = 1.0 if (len(resp.code) == 3 and resp.code[0] == "5") else 0.0

    if block_body:
        f[5] = 1.0 - _body_similarity(resp.body, block_body)
    else:
        f[5] = 1.0 - _body_similarity(resp.body, baseline.body)

    if pass_body:
        f[6] = _body_similarity(resp.body, pass_body)
    else:
        f[6] = 0.5  # unknown — neutral

    f[7] = _has_error_detail(resp.body)

    try:
        c = int(resp.code)
        f[8] = 1.0 if 300 <= c < 400 else 0.0
    except ValueError:
        f[8] = 0.0

    f[9] = 1.0 if resp.size > 0 and resp.size != baseline.size else 0.0

    return f


# ---- sigmoid / logistic ---------------------------------------------------

def _sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    ez = math.exp(z)
    return ez / (1.0 + ez)


# ---- the scorer ------------------------------------------------------------

@dataclass
class GradientScorer:
    """Calibratable scorer: heuristic weights by default, logistic regression
    after calibrate_weights().

    Usage in search:
        scorer = GradientScorer()
        # optionally: scorer.set_baselines(block_body, pass_body)
        # optionally: scorer.calibrate_weights(block_samples, pass_samples)
        score = scorer.score_response(resp, baseline, chain_len)
    """
    weights: list[float] = field(default_factory=lambda: list(_DEFAULT_WEIGHTS))
    bias: float = _DEFAULT_BIAS
    calibrated: bool = False
    block_body: str = ""
    pass_body: str = ""

    # chain-length penalty (matches existing scoring.py convention)
    chain_penalty: float = 0.15

    def set_baselines(self, block_body: str = "", pass_body: str = ""):
        self.block_body = block_body
        self.pass_body = pass_body

    def features(self, resp: Response, baseline: Response) -> list[float]:
        return extract_features(resp, baseline, self.block_body, self.pass_body)

    def raw_score(self, features: list[float]) -> float:
        """Weighted sum → sigmoid → [0, 1]. Higher = more likely through."""
        z = self.bias + sum(w * f for w, f in zip(self.weights, features))
        return _sigmoid(z)

    def score_response(self, resp: Response, baseline: Response,
                       chain_len: int = 0) -> float:
        """Drop-in replacement for Oracle.score / composite_score / gradient_score.
        Returns a value on the same scale the search engines expect:
        THROUGH → 1e9 (dominates), DOWN → -1, else 0..~10."""
        if resp.verdict == DOWN:
            return -1.0
        if resp.verdict == THROUGH:
            return 1e9 - self.chain_penalty * max(chain_len, 0)

        feats = self.features(resp, baseline)
        raw = self.raw_score(feats)
        # scale sigmoid [0,1] output to ~[0, 8] range to match existing scores
        scaled = raw * 8.0
        scaled -= self.chain_penalty * max(chain_len, 0)
        return scaled

    # ---- logistic regression calibration -----------------------------------

    def calibrate_weights(self, block_samples: list[list[float]],
                          pass_samples: list[list[float]],
                          lr: float = 0.5, iterations: int = 80) -> float:
        """Fit weights via gradient descent on binary cross-entropy.

        block_samples: list of feature vectors from known-BLOCKED responses (label=0)
        pass_samples: list of feature vectors from known-THROUGH responses (label=1)

        Returns final loss. Modifies self.weights and self.bias in place.
        """
        if not block_samples or not pass_samples:
            return float("inf")

        X = block_samples + pass_samples
        y = [0.0] * len(block_samples) + [1.0] * len(pass_samples)
        n = len(X)
        nf = len(self.weights)

        w = list(self.weights)
        b = self.bias
        eps = 1e-8

        for _ in range(iterations):
            dw = [0.0] * nf
            db = 0.0
            loss = 0.0

            for xi, yi in zip(X, y):
                z = b + sum(wj * xj for wj, xj in zip(w, xi))
                p = _sigmoid(z)
                p = max(min(p, 1.0 - eps), eps)
                loss += -(yi * math.log(p) + (1.0 - yi) * math.log(1.0 - p))
                err = p - yi
                for j in range(nf):
                    dw[j] += err * xi[j]
                db += err

            loss /= n
            for j in range(nf):
                w[j] -= lr * dw[j] / n
            b -= lr * db / n

        self.weights = w
        self.bias = b
        self.calibrated = True
        return loss

    def as_dict(self) -> dict:
        return {
            "weights": dict(zip(_FEAT_NAMES, self.weights)),
            "bias": self.bias,
            "calibrated": self.calibrated,
            "n_features": N_FEATURES,
        }


# ---- convenience: adapt an Oracle to use this scorer -----------------------

def patch_oracle_scorer(oracle, scorer: GradientScorer):
    """Monkey-patch an Oracle instance so its .score() uses the GradientScorer.
    Returns the original score method for restoration."""
    original = oracle.score

    def _patched_score(resp, baseline):
        return scorer.score_response(resp, baseline)

    oracle.score = staticmethod(_patched_score)
    return original
