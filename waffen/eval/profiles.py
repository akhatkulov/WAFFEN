"""Pre-built WAF target profiles for standardized benchmarking."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class WAFProfile:
    key: str
    name: str
    default_url: str
    path: str
    param: str
    block_signature: str
    note: str


WAF_PROFILES: dict[str, WAFProfile] = {
    "crs-pl1": WAFProfile(
        "crs-pl1", "OWASP CRS PL1", "http://localhost:18080",
        "/rest/products/search", "q", "",
        "Local lab, PARANOIA=1 (default)"),
    "crs-pl2": WAFProfile(
        "crs-pl2", "OWASP CRS PL2", "http://localhost:18080",
        "/rest/products/search", "q", "",
        "Local lab, set PARANOIA=2 in docker-compose"),
    "crs-pl3": WAFProfile(
        "crs-pl3", "OWASP CRS PL3", "http://localhost:18080",
        "/rest/products/search", "q", "",
        "Local lab, set PARANOIA=3"),
    "crs-pl4": WAFProfile(
        "crs-pl4", "OWASP CRS PL4", "http://localhost:18080",
        "/rest/products/search", "q", "",
        "Local lab, set PARANOIA=4 (maximum, high FP)"),
    "redeye": WAFProfile(
        "redeye", "RedEye WAF", "https://juice-shop.redeyes.uz",
        "/rest/products/search", "q", "RedEye WAF",
        "RedEye WAF demo instance"),
}


def list_profiles() -> list[WAFProfile]:
    return list(WAF_PROFILES.values())


def get_profile(key: str) -> WAFProfile | None:
    return WAF_PROFILES.get(key.lower())
