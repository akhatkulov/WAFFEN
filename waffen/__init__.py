"""WAFFEN — a WAF evaluation / bypass-research toolkit for authorized targets.

SDK quick start::

    from waffen import bypass, fingerprint, discover, exploit, fuzz
    result = bypass("https://target.com", path="/search", attack_class="sqli")
"""
__version__ = "2.1.0"

# SDK convenience imports — lazy to avoid heavy import on CLI startup
def __getattr__(name):
    _SDK_NAMES = {"bypass", "fingerprint", "discover", "exploit", "fuzz",
                  "score_probe", "origin", "defend", "report",
                  "BypassResult", "FingerprintResult", "DiscoverResult",
                  "ExploitResult", "FuzzResult", "ScoreProbeResult",
                  "OriginResult", "BypassFinding", "FuzzMatchResult"}
    if name in _SDK_NAMES:
        from . import sdk
        return getattr(sdk, name)
    raise AttributeError(f"module 'waffen' has no attribute {name!r}")
