"""Harvest attack payloads from a PayloadsAllTheThings-style checkout.

Each top-level directory is treated as an attack class; `.txt`/`.fuzz`/`.lst`
files inside it are read one-payload-per-line. This is the same corpus model the
standalone corpus_runner used, folded into the tool.
"""
from __future__ import annotations

from pathlib import Path

LIST_EXTS = {".txt", ".fuzz", ".lst", ".list"}


def harvest(root, max_per_class: int = 0) -> dict[str, list[str]]:
    root = Path(root)
    by_cat: dict[str, list[str]] = {}
    seen: dict[str, set[str]] = {}
    for path in root.rglob("*"):
        if not path.is_file() or ".git" in path.parts:
            continue
        if path.suffix.lower() not in LIST_EXTS:
            continue
        rel = path.relative_to(root).parts
        cat = rel[0] if rel else "_root"
        s = seen.setdefault(cat, set())
        bucket = by_cat.setdefault(cat, [])
        try:
            lines = path.read_text(errors="replace").splitlines()
        except Exception:
            continue
        for line in lines:
            p = line.rstrip("\r\n")
            if not p or p.lstrip().startswith("#") or p in s:
                continue
            if max_per_class and len(bucket) >= max_per_class:
                break
            s.add(p)
            bucket.append(p)
    return by_cat
