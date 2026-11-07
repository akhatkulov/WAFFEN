"""Per-attack-class injection-point routing.

A full-corpus run that sends *every* class through one injection point (e.g. `?q=`)
tests path/upload/config classes at the wrong place — their "coverage" then reads
near-zero as an artifact of the mismatch, not a real WAF gap (a `.php` extension or
`../../etc/passwd` in a search box proves nothing). This map says, per class, where
that class's payloads actually belong, so `--inject auto` routes each one correctly
in a single run.

Each entry gives the inject MODE and sensible default `path`/`param` for that class;
a value of `None` for path/param means "keep whatever the caller configured".
Classes not listed fall back to the caller's base inject (normally `query`).
"""
from __future__ import annotations

# class -> {"inject": mode, "path": str|None, "param": str|None}
INJECT_MAP: dict[str, dict] = {
    # path / traversal / config classes belong in the URL PATH, not a query value
    "Directory Traversal":            {"inject": "rawpath", "path": "/", "param": None},
    "Web Cache Deception":            {"inject": "rawpath", "path": "/", "param": None},
    "Insecure Source Code Management":{"inject": "rawpath", "path": "/", "param": None},
    "Insecure Management Interface":  {"inject": "rawpath", "path": "/", "param": None},
    # file upload is a real multipart upload with a dangerous filename/extension
    "Upload Insecure Files":          {"inject": "upload", "path": "/file-upload", "param": "file"},
    # LFI/RFI is commonly a query parameter that names a resource
    "File Inclusion":                 {"inject": "query", "path": None, "param": "file"},
    # everything else is a value-injection class → the caller's base inject (query by default):
    #   XSS, SQL, Command, SSTI, NoSQL, XXE, CRLF, SSI, LDAP, Open Redirect, API Key Leaks, ...
}


def recommended(attack_class: str) -> dict | None:
    """The routing hint for a class, or None to use the caller's base injection."""
    return INJECT_MAP.get(attack_class)


def effective(base_target, attack_class):
    """Return a Target for this class under `--inject auto`.

    If `base_target.inject != 'auto'`, returns `base_target` unchanged (explicit
    inject always wins). Otherwise applies this class's routing hint, falling back
    to `query` for unlisted classes, and only overriding path/param where the hint
    specifies one (so a user-set --path/--param still carries through when the hint
    leaves it None)."""
    import dataclasses
    if getattr(base_target, "inject", None) != "auto":
        return base_target
    hint = INJECT_MAP.get(attack_class) or {"inject": "query", "path": None, "param": None}
    changes = {"inject": hint["inject"]}
    if hint.get("path"):
        changes["path"] = hint["path"]
    if hint.get("param"):
        changes["param"] = hint["param"]
    return dataclasses.replace(base_target, **changes)
