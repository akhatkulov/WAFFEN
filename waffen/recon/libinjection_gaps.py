"""Probe a WAF's SQL-token detection for database-specific blind spots.

libinjection (used by ModSecurity, RedEye, and many cloud WAFs) recognises a
fixed set of SQL fingerprints — token sequences that look like injection. Tokens
unique to one SQL dialect (SQLite GLOB, PostgreSQL ILIKE, MySQL RLIKE, …) may be
absent from the table, letting a structurally identical injection through if only
the operator name changes.

This module probes a live WAF with *context templates* — tiny SQL fragments that
carry a single dialect-specific token inside a pattern the WAF should block — and
records which tokens pass. For every gap it finds, it generates seed payloads
that compose only undetected tokens into valid, exploitable SQL.

Non-destructive: every probe carries a benign canary; nothing it sends can
execute against a real backend (the payloads target syntax, not data).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence


# ---- token databases (per-engine) ----------------------------------------

@dataclass(frozen=True)
class Token:
    name: str
    kind: str   # "operator" | "function" | "keyword" | "variable"
    engine: str
    note: str = ""

_SQLITE = [
    Token("GLOB", "operator", "sqlite", "pattern match (like LIKE)"),
    Token("COLLATE", "keyword", "sqlite"),
    Token("MATCH", "operator", "sqlite", "FTS match"),
    Token("ESCAPE", "keyword", "sqlite"),
    Token("ISNULL", "keyword", "sqlite", "postfix IS NULL"),
    Token("NOTNULL", "keyword", "sqlite", "postfix IS NOT NULL"),
    Token("RAISE", "keyword", "sqlite", "RAISE(IGNORE|ABORT|FAIL)"),
    Token("typeof", "function", "sqlite"),
    Token("sqlite_version", "function", "sqlite"),
    Token("hex", "function", "sqlite"),
    Token("unhex", "function", "sqlite"),
    Token("iif", "function", "sqlite", "inline IF (3.32+)"),
    Token("quote", "function", "sqlite"),
    Token("randomblob", "function", "sqlite"),
    Token("zeroblob", "function", "sqlite"),
    Token("unicode", "function", "sqlite"),
    Token("likelihood", "function", "sqlite"),
    Token("likely", "function", "sqlite"),
    Token("unlikely", "function", "sqlite"),
    Token("nullif", "function", "sqlite"),
    Token("instr", "function", "sqlite"),
    Token("replace", "function", "sqlite"),
    Token("substr", "function", "sqlite"),
    Token("group_concat", "function", "sqlite"),
    Token("json_extract", "function", "sqlite"),
    Token("json_each", "function", "sqlite"),
    Token("json_type", "function", "sqlite"),
    Token("total_changes", "function", "sqlite"),
    Token("last_insert_rowid", "function", "sqlite"),
    Token("changes", "function", "sqlite"),
]

_POSTGRESQL = [
    Token("ILIKE", "operator", "postgresql", "case-insensitive LIKE"),
    Token("SIMILAR TO", "operator", "postgresql"),
    Token("~", "operator", "postgresql", "regex match"),
    Token("~*", "operator", "postgresql", "regex match (case-insensitive)"),
    Token("!~", "operator", "postgresql", "regex NOT match"),
    Token("!~*", "operator", "postgresql"),
    Token("::", "operator", "postgresql", "type cast"),
    Token("@>", "operator", "postgresql", "contains"),
    Token("<@", "operator", "postgresql", "contained by"),
    Token("&&", "operator", "postgresql", "overlap"),
    Token("||/", "operator", "postgresql", "cube root"),
    Token("|/", "operator", "postgresql", "square root"),
    Token("#", "operator", "postgresql", "bitwise XOR"),
    Token(">>", "operator", "postgresql", "right shift"),
    Token("<<", "operator", "postgresql", "left shift"),
    Token("ANY", "keyword", "postgresql"),
    Token("ALL", "keyword", "postgresql"),
    Token("SOME", "keyword", "postgresql"),
    Token("LATERAL", "keyword", "postgresql"),
    Token("RETURNING", "keyword", "postgresql"),
    Token("OVERLAPS", "keyword", "postgresql"),
    Token("pg_sleep", "function", "postgresql"),
    Token("generate_series", "function", "postgresql"),
    Token("string_agg", "function", "postgresql"),
    Token("regexp_matches", "function", "postgresql"),
    Token("regexp_replace", "function", "postgresql"),
    Token("xpath", "function", "postgresql"),
    Token("query_to_xml", "function", "postgresql"),
    Token("lo_import", "function", "postgresql"),
    Token("pg_read_file", "function", "postgresql"),
    Token("pg_ls_dir", "function", "postgresql"),
    Token("current_setting", "function", "postgresql"),
    Token("set_config", "function", "postgresql"),
    Token("txid_current", "function", "postgresql"),
]

_MYSQL = [
    Token("RLIKE", "operator", "mysql", "regex match"),
    Token("REGEXP", "operator", "mysql"),
    Token("SOUNDS LIKE", "operator", "mysql"),
    Token("DIV", "operator", "mysql", "integer division"),
    Token("MOD", "operator", "mysql"),
    Token("XOR", "operator", "mysql"),
    Token(":=", "operator", "mysql", "user variable assignment"),
    Token("BENCHMARK", "function", "mysql"),
    Token("LOAD_FILE", "function", "mysql"),
    Token("INTO OUTFILE", "keyword", "mysql"),
    Token("INTO DUMPFILE", "keyword", "mysql"),
    Token("@@version", "variable", "mysql"),
    Token("@@datadir", "variable", "mysql"),
    Token("@@basedir", "variable", "mysql"),
    Token("@@hostname", "variable", "mysql"),
    Token("@@global.version", "variable", "mysql"),
    Token("EXTRACTVALUE", "function", "mysql"),
    Token("UPDATEXML", "function", "mysql"),
    Token("EXP", "function", "mysql"),
    Token("CEIL", "function", "mysql"),
    Token("FLOOR", "function", "mysql"),
    Token("NAME_CONST", "function", "mysql"),
    Token("UUID", "function", "mysql"),
    Token("JSON_EXTRACT", "function", "mysql"),
    Token("AES_ENCRYPT", "function", "mysql"),
    Token("COMPRESS", "function", "mysql"),
    Token("INET_ATON", "function", "mysql"),
]

_MSSQL = [
    Token("WAITFOR", "keyword", "mssql"),
    Token("OPENROWSET", "function", "mssql"),
    Token("OPENDATASOURCE", "function", "mssql"),
    Token("xp_cmdshell", "function", "mssql"),
    Token("sp_configure", "function", "mssql"),
    Token("sp_executesql", "function", "mssql"),
    Token("STUFF", "function", "mssql"),
    Token("STRING_AGG", "function", "mssql"),
    Token("FORMATMESSAGE", "function", "mssql"),
    Token("IIF", "function", "mssql", "inline IF"),
    Token("CHOOSE", "function", "mssql"),
    Token("QUOTENAME", "function", "mssql"),
    Token("SUSER_NAME", "function", "mssql"),
    Token("SYSTEM_USER", "variable", "mssql"),
    Token("IS_SRVROLEMEMBER", "function", "mssql"),
    Token("HAS_DBACCESS", "function", "mssql"),
    Token("DB_NAME", "function", "mssql"),
    Token("HOST_NAME", "function", "mssql"),
    Token("SERVERPROPERTY", "function", "mssql"),
    Token("OBJECT_ID", "function", "mssql"),
]

ALL_TOKENS: dict[str, list[Token]] = {
    "sqlite": _SQLITE,
    "postgresql": _POSTGRESQL,
    "mysql": _MYSQL,
    "mssql": _MSSQL,
}

# ---- context templates ---------------------------------------------------
# Each template places {TOKEN} inside a SQL-like pattern that a WAF with full
# keyword coverage should block. The quote / structure gives libinjection
# enough syntactic context to produce a fingerprint.

_CONTEXT_TEMPLATES: list[tuple[str, str]] = [
    ("op_wildcard",    "' {TOKEN} '*"),
    ("op_value",       "' {TOKEN} 1"),
    ("op_subquery",    "' {TOKEN} (SELECT 1)"),
    ("func_call",      "{TOKEN}(1)"),
    ("func_quote",     "' {TOKEN}(1)"),
    ("binary_op",      "1 {TOKEN} 1"),
    ("postfix",        "' {TOKEN}"),
    ("variable",       "{TOKEN}"),
]


def _templates_for(token: Token) -> list[tuple[str, str]]:
    """Pick the context templates relevant to a token's kind."""
    if token.kind == "operator":
        return [t for t in _CONTEXT_TEMPLATES if t[0] in
                ("op_wildcard", "op_value", "op_subquery", "binary_op")]
    if token.kind == "function":
        return [t for t in _CONTEXT_TEMPLATES if t[0] in
                ("func_call", "func_quote")]
    if token.kind == "variable":
        return [t for t in _CONTEXT_TEMPLATES if t[0] in
                ("variable", "postfix")]
    # keyword — try operator + postfix templates
    return [t for t in _CONTEXT_TEMPLATES if t[0] in
            ("op_wildcard", "op_value", "postfix")]


# ---- probe results -------------------------------------------------------

@dataclass
class TokenProbe:
    token: Token
    template: str        # template name
    payload: str         # exact string sent
    code: str            # HTTP status
    verdict: str         # BLOCKED | THROUGH | DOWN

@dataclass
class GapReport:
    engine: str
    total: int
    blocked: int
    through: int
    down: int
    gaps: list[TokenProbe] = field(default_factory=list)
    seeds: list[str] = field(default_factory=list)


# block/pass classification matching cve_probe's conservative approach
_BLOCK = {"403", "406"}
_PASS = {"200", "201", "202", "204", "301", "302", "303", "307", "308", "404", "422"}


# ---- the hunter -----------------------------------------------------------

class LibinjectionGapHunter:
    """Probe a live WAF for database-specific token blind spots."""

    def __init__(self, target, *, sender=None, engines: Sequence[str] | None = None):
        self.target = target
        self._sender = sender
        self.engines = list(engines) if engines else list(ALL_TOKENS.keys())

    def _oracle(self):
        from ..core.oracle import Oracle
        return Oracle(self.target, sender=self._sender)

    def probe_token(self, token: Token) -> list[TokenProbe]:
        """Send each relevant context template for *token* and record the result."""
        oracle = self._oracle()
        results = []
        for tname, tpl in _templates_for(token):
            payload = tpl.replace("{TOKEN}", token.name)
            resp = oracle.send(payload)
            results.append(TokenProbe(
                token=token, template=tname, payload=payload,
                code=resp.code, verdict=resp.verdict,
            ))
            if resp.verdict == "THROUGH":
                break  # one through is enough to flag this token
        return results

    def scan_engine(self, engine: str) -> GapReport:
        """Probe all tokens for one database engine."""
        tokens = ALL_TOKENS.get(engine, [])
        report = GapReport(engine=engine, total=len(tokens), blocked=0, through=0, down=0)
        for tok in tokens:
            probes = self.probe_token(tok)
            any_through = any(p.verdict == "THROUGH" for p in probes)
            any_block = any(p.verdict == "BLOCKED" for p in probes)
            if any_through:
                report.through += 1
                for p in probes:
                    if p.verdict == "THROUGH":
                        report.gaps.append(p)
            elif any_block:
                report.blocked += 1
            else:
                report.down += 1
        report.seeds = generate_exploit_seeds(engine, report.gaps)
        return report

    def scan_all(self) -> list[GapReport]:
        """Probe all configured database engines."""
        return [self.scan_engine(e) for e in self.engines]


# ---- seed generator -------------------------------------------------------

def _gap_token_names(gaps: list[TokenProbe]) -> set[str]:
    return {g.token.name for g in gaps}


def generate_exploit_seeds(engine: str, gaps: list[TokenProbe]) -> list[str]:
    """Build exploit seed payloads using only undetected tokens.

    Delegates to reconstruct.py's template builders (the single source of
    truth for per-engine exploit templates) and extracts the pattern strings.
    """
    names = _gap_token_names(gaps)
    if not names:
        return []
    try:
        from .reconstruct import _ENGINE_BUILDERS, expand_all
        builder = _ENGINE_BUILDERS.get(engine)
        if builder:
            templates = builder(names)
            return [t.pattern for t in templates]
    except ImportError:
        pass
    return []
