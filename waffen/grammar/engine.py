"""Context-free grammar engine for payload generation.

A Grammar is a dict of rules mapping non-terminal names to lists of
alternatives, where each alternative is a list of symbols (terminals or
non-terminal references).  A terminal is any string NOT present as a rule
key.  Generation expands the start symbol recursively, choosing alternatives
at random, until only terminals remain.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field


@dataclass
class Grammar:
    rules: dict[str, list[list[str]]]
    start: str

    def _is_nonterminal(self, sym: str) -> bool:
        return sym in self.rules

    def _expand(self, symbol: str, depth: int, max_depth: int,
                rng: random.Random, required: set[str] | None = None) -> str:
        if not self._is_nonterminal(symbol):
            return symbol

        alts = self.rules[symbol]
        if depth >= max_depth:
            alts = self._shortest_alternatives(symbol, alts)

        if required:
            preferred = [a for a in alts
                         if any(self._alt_can_reach(a, t) for t in required)]
            if preferred:
                alts = preferred

        alt = rng.choice(alts)
        parts = []
        for sym in alt:
            parts.append(self._expand(sym, depth + 1, max_depth, rng, required))
        return "".join(parts)

    def _shortest_alternatives(self, symbol: str, alts: list[list[str]]) -> list[list[str]]:
        scored = []
        for alt in alts:
            nt_count = sum(1 for s in alt if self._is_nonterminal(s))
            scored.append((nt_count, alt))
        scored.sort(key=lambda x: x[0])
        min_nt = scored[0][0]
        return [a for c, a in scored if c == min_nt]

    def _alt_can_reach(self, alt: list[str], target: str) -> bool:
        for sym in alt:
            if sym == target:
                return True
            if self._is_nonterminal(sym):
                for sub_alt in self.rules[sym]:
                    if any(s == target for s in sub_alt):
                        return True
        return False

    def generate(self, max_depth: int = 10, rng: random.Random | None = None,
                 required: set[str] | None = None) -> str:
        if rng is None:
            rng = random.Random()
        return self._expand(self.start, 0, max_depth, rng, required)

    def generate_n(self, n: int, max_depth: int = 10,
                   seed: int | None = None) -> list[str]:
        rng = random.Random(seed)
        seen: set[str] = set()
        results: list[str] = []
        attempts = 0
        while len(results) < n and attempts < n * 10:
            p = self.generate(max_depth=max_depth, rng=rng)
            if p not in seen:
                seen.add(p)
                results.append(p)
            attempts += 1
        return results

    def generate_targeted(self, required_symbols: set[str],
                          max_depth: int = 12, attempts: int = 50,
                          seed: int | None = None) -> list[str]:
        rng = random.Random(seed)
        results: list[str] = []
        for _ in range(attempts):
            p = self.generate(max_depth=max_depth, rng=rng, required=required_symbols)
            if all(sym in p for sym in required_symbols):
                results.append(p)
        seen: set[str] = set()
        deduped = []
        for r in results:
            if r not in seen:
                seen.add(r)
                deduped.append(r)
        return deduped

    def coverage_generate(self, n: int = 200, max_depth: int = 10,
                          seed: int | None = None) -> list[str]:
        rng = random.Random(seed)
        uncovered = set()
        for name, alts in self.rules.items():
            for i, _ in enumerate(alts):
                uncovered.add((name, i))

        results: list[str] = []
        seen: set[str] = set()
        for _ in range(n * 5):
            if not uncovered and len(results) >= n:
                break
            p, used = self._expand_tracking(self.start, 0, max_depth, rng)
            if p not in seen:
                seen.add(p)
                results.append(p)
                uncovered -= used
        return results[:n]

    def _expand_tracking(self, symbol: str, depth: int, max_depth: int,
                         rng: random.Random) -> tuple[str, set[tuple[str, int]]]:
        if not self._is_nonterminal(symbol):
            return symbol, set()

        alts = self.rules[symbol]
        if depth >= max_depth:
            alts = self._shortest_alternatives(symbol, alts)

        idx = rng.randrange(len(alts))
        alt = alts[idx]
        orig_idx = self.rules[symbol].index(alt) if alt in self.rules[symbol] else idx
        used = {(symbol, orig_idx)}
        parts = []
        for sym in alt:
            text, sub_used = self._expand_tracking(sym, depth + 1, max_depth, rng)
            parts.append(text)
            used |= sub_used
        return "".join(parts), used

    def all_terminals(self) -> set[str]:
        terms: set[str] = set()
        for alts in self.rules.values():
            for alt in alts:
                for sym in alt:
                    if not self._is_nonterminal(sym):
                        terms.add(sym)
        return terms

    def all_nonterminals(self) -> set[str]:
        return set(self.rules.keys())
