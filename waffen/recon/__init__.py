"""WAF fingerprinting (wafw00f-style) for authorized target reconnaissance.

Sends a benign request and a mildly-malicious probe through the same
curl-based transport used by the rest of WAFFEN (`waffen.core.oracle`) and
matches the responses against a small, extensible table of known WAF
signatures (headers, cookies, body content).
"""
from __future__ import annotations

from .fingerprint import WafGuess, fingerprint, SIGNATURES

__all__ = ["WafGuess", "fingerprint", "SIGNATURES"]
