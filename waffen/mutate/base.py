"""Mutator primitives.

A Mutator is a named, pure string transform applied to a payload. Mutators are
composed into *chains* by the search engine; each chain is one candidate evasion.

Semantic validity (does the mutated payload still trigger the underlying vuln?)
is best-effort: mutators are grouped by the attack classes they typically keep
valid for, and the search engine prefers mutators whose `classes` include the
target class. Final confirmation that a THROUGH payload is still exploitable is a
separate verification step (see report/ and the --verify roadmap item).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable


@dataclass(frozen=True)
class Mutator:
    name: str
    fn: Callable[[str], str]
    category: str  # "encoder" | "obfuscator"
    desc: str = ""
    # attack classes this mutator usually keeps semantically valid for ("*" = any)
    classes: frozenset[str] = field(default_factory=lambda: frozenset({"*"}))

    def apply(self, payload: str) -> str:
        return self.fn(payload)

    def valid_for(self, attack_class: str) -> bool:
        return "*" in self.classes or attack_class in self.classes


class Registry:
    """Holds all known mutators and lets the engine select a working set."""

    def __init__(self) -> None:
        self._m: dict[str, Mutator] = {}

    def register(self, m: Mutator) -> Mutator:
        if m.name in self._m:
            raise ValueError(f"duplicate mutator: {m.name}")
        self._m[m.name] = m
        return m

    def add(self, name: str, fn: Callable[[str], str], category: str,
            desc: str = "", classes: set[str] | None = None) -> Mutator:
        return self.register(Mutator(
            name=name, fn=fn, category=category, desc=desc,
            classes=frozenset(classes) if classes else frozenset({"*"}),
        ))

    def all(self) -> list[Mutator]:
        return list(self._m.values())

    def get(self, name: str) -> Mutator:
        return self._m[name]

    def select(self, attack_class: str | None = None,
               categories: set[str] | None = None,
               names: set[str] | None = None) -> list[Mutator]:
        out = []
        for m in self._m.values():
            if names is not None and m.name not in names:
                continue
            if categories is not None and m.category not in categories:
                continue
            if attack_class and not m.valid_for(attack_class):
                continue
            out.append(m)
        return out


# the global registry; populated by encoders.py / obfuscators.py on import
REGISTRY = Registry()
