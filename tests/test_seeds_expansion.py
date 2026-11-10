"""Guards for the expanded built-in seed corpus (waffen/kb/seeds.py).

The bypass search *mutates* these seeds, so a wider, class-correct seed set
directly widens reach. These tests pin the corpus's invariants after the
expansion: every class carries a meaningful number of non-empty, unique seeds,
the public accessor API is intact, and a spot-check confirms each class's
signature tokens land in the right class (no cross-class mislabeling).
"""
import collections

import pytest

from waffen.kb import seeds as kb_seeds

# A conservative floor: every seed class must carry at least this many seeds.
# (The smallest class after the expansion is well above this.)
MIN_SEEDS_PER_CLASS = 6

# Classes that must exist after the expansion (the original bootstrap set plus
# the newly added, structurally-supported high-value classes).
EXPECTED_CLASSES = {
    # original bootstrap classes
    "XSS Injection", "SQL Injection", "Command Injection", "Directory Traversal",
    "File Inclusion", "SSTI", "NoSQL Injection", "Upload Insecure Files",
    # added classes
    "CRLF Injection", "XXE Injection", "SSRF", "Open Redirect",
    "LDAP Injection", "SSI",
}

# Pre-expansion sizes of the original classes — each must now be strictly larger.
ORIGINAL_SIZES = {
    "XSS Injection": 4,
    "SQL Injection": 4,
    "Command Injection": 4,
    "Directory Traversal": 3,
    "File Inclusion": 3,
    "SSTI": 3,
    "NoSQL Injection": 2,
}

# One or more lowercase substrings that genuinely belong to each class. The
# spot-check requires at least one to appear somewhere in the class's seeds —
# a cheap but effective "is this payload in the right bucket?" assertion.
SIGNATURE_TOKENS = {
    "XSS Injection": ["<script", "onerror", "onload", "javascript:"],
    "SQL Injection": ["union select", "or 1=1", "' or ", " drop ", "--"],
    "Command Injection": ["whoami", "/etc/passwd", "$(", "`"],
    "Directory Traversal": ["../", "/etc/passwd", "..%2f", "win.ini"],
    "File Inclusion": ["php://", "/etc/passwd", "file://", "data://"],
    "SSTI": ["{{", "${", "#{", "*{"],
    "NoSQL Injection": ["$ne", "$gt", "$where", "$regex"],
    "CRLF Injection": ["%0d%0a", "%0a", "set-cookie", "location:"],
    "XXE Injection": ["<!doctype", "<!entity", "system", "&xxe;"],
    "SSRF": ["169.254.169.254", "127.0.0.1", "metadata", "gopher://"],
    "Open Redirect": ["evil", "//", "@"],
    "LDAP Injection": [")(", "uid=", "*)", "objectclass"],
    "SSI": ["<!--#", "exec", "include", "printenv"],
    "Upload Insecure Files": ["php", "phtml", "jsp", "asp"],
}


def _blob(attack_class: str) -> str:
    return "\n".join(kb_seeds.seeds_for(attack_class)).lower()


def test_public_api_intact():
    # the module's public surface the rest of WAFFEN depends on.
    assert isinstance(kb_seeds.SEEDS, dict)
    assert callable(kb_seeds.classes) and callable(kb_seeds.seeds_for)
    assert kb_seeds.classes() == list(kb_seeds.SEEDS.keys())
    assert kb_seeds.seeds_for("does-not-exist") == []


def test_expected_classes_present():
    present = set(kb_seeds.classes())
    missing = EXPECTED_CLASSES - present
    assert not missing, f"missing seed classes after expansion: {sorted(missing)}"


def test_every_class_meets_floor():
    for c in kb_seeds.classes():
        n = len(kb_seeds.seeds_for(c))
        assert n >= MIN_SEEDS_PER_CLASS, (
            f"{c!r} has only {n} seeds (floor is {MIN_SEEDS_PER_CLASS})"
        )


def test_original_classes_were_expanded():
    for c, before in ORIGINAL_SIZES.items():
        after = len(kb_seeds.seeds_for(c))
        assert after > before, f"{c!r} was not expanded ({after} <= original {before})"


def test_no_empty_or_whitespace_seeds():
    for c in kb_seeds.classes():
        for p in kb_seeds.seeds_for(c):
            assert isinstance(p, str), f"{c!r} contains a non-str seed: {p!r}"
            assert p.strip() != "", f"{c!r} contains an empty/whitespace seed: {p!r}"


def test_no_exact_duplicates_within_class():
    for c in kb_seeds.classes():
        payloads = kb_seeds.seeds_for(c)
        dupes = [p for p, n in collections.Counter(payloads).items() if n > 1]
        assert not dupes, f"{c!r} has exact-duplicate seeds: {dupes}"


@pytest.mark.parametrize("attack_class, tokens", sorted(SIGNATURE_TOKENS.items()))
def test_class_signature_tokens_present(attack_class, tokens):
    seeds = kb_seeds.seeds_for(attack_class)
    assert seeds, f"{attack_class!r} unexpectedly has no seeds"
    blob = _blob(attack_class)
    assert any(t in blob for t in tokens), (
        f"{attack_class!r} seeds carry none of its signature tokens {tokens}"
    )


def test_no_obvious_cross_class_mislabeling():
    # A handful of unmistakable negative checks: a class must NOT contain another
    # class's signature (guards against pasting XSS into the SQL list, etc.).
    sql = _blob("SQL Injection")
    assert "<script" not in sql and "onerror=" not in sql
    xss = _blob("XSS Injection")
    assert "union select" not in xss and "/etc/passwd" not in xss
    cmd = _blob("Command Injection")
    assert "<script" not in cmd and "union select" not in cmd
    traversal = _blob("Directory Traversal")
    assert "<script" not in traversal and "union select" not in traversal
