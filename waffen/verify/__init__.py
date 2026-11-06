"""Semantic verification of THROUGH payloads.

A payload that gets a THROUGH verdict from the oracle only proves it was not
blocked — not that it actually exercises the vulnerability class it was meant
to. This package provides best-effort, class-specific checks that look at the
*content* of the response to decide whether the underlying bug really fired.
"""
from __future__ import annotations

from .verifier import Verification, verify
from .calibrate import Calibration, calibrate

__all__ = ["Verification", "verify", "Calibration", "calibrate"]
