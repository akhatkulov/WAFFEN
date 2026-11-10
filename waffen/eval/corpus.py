"""Harvest attack payloads from a PayloadsAllTheThings-style checkout.

Each top-level directory is treated as an attack class and normalised to one of
WAFFEN's canonical class names (see `DIR_TO_CLASS` / `classify`), so a harvested
corpus lines up with `waffen.kb.seeds` and the per-class routing in
`waffen.kb.inject_map`. `.txt`/`.fuzz`/`.lst`/`.list` files are read one payload
per line; `.md`/`.markdown` files contribute the lines inside fenced code blocks
(the form PayloadsAllTheThings keeps most of its payloads in). Markdown/prose
noise — fences, backtick wrappers, headings/comments and over-long paragraph
lines — is stripped, and payloads are de-duplicated per class. This is the same
corpus model the standalone corpus_runner used, folded into the tool.
"""
from __future__ import annotations

import re
from pathlib import Path

# one payload per line
LIST_EXTS = {".txt", ".fuzz", ".lst", ".list"}
# payloads live inside ``` fenced code blocks (PayloadsAllTheThings READMEs)
DOC_EXTS = {".md", ".markdown"}
# lines longer than this are prose paragraphs / base64 blobs, not payloads
MAX_PAYLOAD_LEN = 4096

# PayloadsAllTheThings top-level directory -> WAFFEN canonical attack class.
# Keys are match-normalised (see `_norm`): lower-cased with punctuation folded to
# spaces, so "Server-Side Template Injection" and "server side template injection"
# both match. Values are the exact class names used by waffen.kb.seeds.classes()
# and waffen.kb.inject_map, so routing/scoring line up.
#
# Grounding (no fabricated classes — every value is a real WAFFEN class):
#   * Folder names: PayloadsAllTheThings repo top-level dirs
#     (github.com/swisskyrepo/PayloadsAllTheThings).
#   * Canonical class names: waffen/kb/seeds.py `SEEDS` keys.
#   * Synonyms: PayloadsAllTheThings READMEs + CWE (cited inline below).
DIR_TO_CLASS: dict[str, str] = {
    # --- PayloadsAllTheThings folder == WAFFEN seeds class (identity) ---
    "xss injection":          "XSS Injection",
    "sql injection":          "SQL Injection",
    "command injection":      "Command Injection",
    "directory traversal":    "Directory Traversal",
    "file inclusion":         "File Inclusion",
    "nosql injection":        "NoSQL Injection",
    "upload insecure files":  "Upload Insecure Files",
    "crlf injection":         "CRLF Injection",
    "xxe injection":          "XXE Injection",
    "open redirect":          "Open Redirect",
    "ldap injection":         "LDAP Injection",
    # --- PayloadsAllTheThings folder -> shortened WAFFEN seeds class ---
    "server side template injection": "SSTI",   # PATT folder; seeds key "SSTI"
    "server side request forgery":    "SSRF",   # PATT folder; seeds key "SSRF"
    "server side include injection":  "SSI",    # PATT folder; seeds key "SSI"
    "server side includes":           "SSI",    # verifier.py "Server Side Includes"
    # --- acronyms / documented synonyms -> canonical class ---
    "ssti":                     "SSTI",
    "ssrf":                     "SSRF",
    "ssi":                      "SSI",
    "xss":                      "XSS Injection",          # CWE-79 Cross-Site Scripting
    "cross site scripting":     "XSS Injection",          # CWE-79
    "sql":                      "SQL Injection",          # CWE-89
    "sqli":                     "SQL Injection",          # CWE-89
    "os command injection":     "Command Injection",      # CWE-78 OS Command Injection
    "path traversal":           "Directory Traversal",    # PATT README: "Path Traversal, also known as Directory Traversal"
    "lfi":                      "File Inclusion",         # PATT File Inclusion README: Local File Inclusion
    "local file inclusion":     "File Inclusion",         # PATT File Inclusion README
    "rfi":                      "File Inclusion",         # PATT File Inclusion README: Remote File Inclusion (RFI)
    "remote file inclusion":    "File Inclusion",         # PATT File Inclusion README
    "nosql":                    "NoSQL Injection",
    "file upload":              "Upload Insecure Files",  # CWE-434 Unrestricted Upload
    "insecure file upload":     "Upload Insecure Files",  # CWE-434
    "unrestricted file upload": "Upload Insecure Files",  # CWE-434
    "crlf":                     "CRLF Injection",         # CWE-113
    "http response splitting":  "CRLF Injection",         # verifier.py "CRLF-injection / HTTP response-splitting"; CWE-113
    "xxe":                      "XXE Injection",          # CWE-611 XML External Entity
    "xml external entity":      "XXE Injection",          # CWE-611
    "open redirects":           "Open Redirect",          # CWE-601
    "open url redirection":     "Open Redirect",          # CWE-601 "URL Redirection to Untrusted Site (Open Redirect)"
    "ldap":                     "LDAP Injection",         # CWE-90
}

# a pure code-fence line: ``` / ~~~ (3+), optionally with an info/language token
_FENCE = re.compile(r"^(?:`{3,}|~{3,})[\w.+-]*$")


def _norm(name: str) -> str:
    """Match-normalise a directory name: lower-case, fold punctuation to spaces."""
    return " ".join("".join(c if c.isalnum() else " " for c in name).split()).lower()


def classify(folder: str) -> str:
    """Map a PayloadsAllTheThings top-level directory to a WAFFEN attack class.

    Unknown folders pass through unchanged, so a corpus laid out with names we
    don't recognise still harvests (its folder name becomes the class label),
    preserving the original one-folder-per-class behaviour.
    """
    return DIR_TO_CLASS.get(_norm(folder), folder)


def _clean(line: str) -> str | None:
    """Clean one raw line into a payload, or None to drop it.

    Drops blank lines, comments / markdown headings (`#...`) and over-long prose
    lines, and unwraps a line fully enclosed in a single pair of backticks.
    Significant trailing whitespace is preserved (e.g. a SQL `-- ` comment), so
    only \\r\\n is stripped from the stored payload.
    """
    probe = line.strip()
    if not probe or probe.startswith("#"):
        return None
    if len(probe) >= 2 and probe[0] == "`" and probe[-1] == "`" and "`" not in probe[1:-1]:
        payload = probe[1:-1]
        if not payload.strip():
            return None
    else:
        payload = line.rstrip("\r\n")
    if len(payload) > MAX_PAYLOAD_LEN:
        return None
    return payload


def _payloads(text: str, markdown: bool):
    """Yield cleaned payload lines from file text.

    For markdown, only the contents of ``` / ~~~ fenced code blocks are yielded
    (prose, tables and headings outside fences are skipped); fence markers
    themselves are always dropped. Fences are a markdown-only concept: list files
    (LIST_EXTS) are read strictly one payload per line, so a wordlist line that
    merely *looks* like a fence is kept, not interpreted away.
    """
    in_fence = False
    for raw in text.splitlines():
        if markdown and _FENCE.match(raw.strip()):
            in_fence = not in_fence
            continue
        if markdown and not in_fence:
            continue
        p = _clean(raw)
        if p is not None:
            yield p


def harvest(root, max_per_class: int = 0) -> dict[str, list[str]]:
    root = Path(root)
    by_cat: dict[str, list[str]] = {}
    seen: dict[str, set[str]] = {}
    # sorted() makes the harvest deterministic (dedup/cap keep the first seen)
    for path in sorted(root.rglob("*")):
        if not path.is_file() or ".git" in path.parts:
            continue
        ext = path.suffix.lower()
        if ext not in LIST_EXTS and ext not in DOC_EXTS:
            continue
        rel = path.relative_to(root).parts
        cat = classify(rel[0]) if rel else "_root"
        s = seen.setdefault(cat, set())
        bucket = by_cat.setdefault(cat, [])
        if max_per_class and len(bucket) >= max_per_class:
            continue
        try:
            text = path.read_text(errors="replace")
        except Exception:
            continue
        for p in _payloads(text, markdown=ext in DOC_EXTS):
            if p in s:
                continue
            if max_per_class and len(bucket) >= max_per_class:
                break
            s.add(p)
            bucket.append(p)
    return by_cat
