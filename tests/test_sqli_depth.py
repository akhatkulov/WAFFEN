"""SQLi verifier depth: DATA-EXTRACTION confirmation.

The SQL verifier used to stop at "confirmed" (error-signature / boolean-differential
/ UNION-count / time-based blind) — it proved the DB *parsed* the injection but never
returned a value the DB actually *computed*. `_sqli_extract_confirm` adds the stronger,
sqlmap-style signal: inject an arithmetic marker a*b (random factors, like
`_check_ssti`'s product trick) wrapped in '~' delimiters and confirm only when the
DB-evaluated product "~<a*b>~" — which never appears literally in the probe — comes
back, via error-based or UNION-based extraction across MySQL/PostgreSQL/SQLite/MSSQL.

Driven with fake oracles (payload->Response, like tests/test_verifier_hardening.py's
MapOracle) plus an `EvalOracle` that actually *evaluates* the injected arithmetic and
reflects the delimited result — a faithful stand-in for a vulnerable backend's leak.
These tests also lock in that every pre-existing SQL signal still fires with the new,
stronger extraction probe running first in the deep-confirm chain.
"""
from __future__ import annotations

import re

from waffen.core.oracle import Response, Target
from waffen.verify import verifier as V


class MapOracle:
    """Fake oracle mapping a payload string to a canned Response."""
    def __init__(self, mapping, default=None, inject="query"):
        self.mapping = mapping
        self.default = default or Response("THROUGH", "200", 10, 0.0, "ok")
        self.t = Target(base_url="https://t", inject=inject)

    def send(self, payload):
        return self.mapping.get(payload, self.default)


class FuncOracle:
    """Fake oracle computing a Response from the payload — needed where the probe
    carries a random marker the checker generates at call time."""
    def __init__(self, fn, inject="query"):
        self.fn = fn
        self.t = Target(base_url="https://t", inject=inject)
        self.sends = []

    def send(self, payload):
        self.sends.append(payload)
        return self.fn(payload)


class EvalOracle:
    """Fake oracle simulating a SQL-injectable backend that EVALUATES injected
    arithmetic and reflects the DB-computed '~<product>~' marker — the way an
    error-based or UNION extraction leak surfaces a server-computed value. When
    `version` is set it is placed inside the delimiters ("~<product>~<version>~"),
    mimicking the `@@version`/`version()` token the error-based probes also request.
    `reflect=False` models a backend that never evaluates/returns our expression."""
    def __init__(self, reflect=True, version="", inject="query"):
        self.reflect = reflect
        self.version = version
        self.t = Target(base_url="https://t", inject=inject)
        self.sends = []

    def send(self, payload):
        self.sends.append(payload)
        if self.reflect:
            m = re.search(r"\((\d+)\s*\*\s*(\d+)\)", payload)   # the injected a*b
            if m:
                prod = int(m.group(1)) * int(m.group(2))       # the DB "computes" it
                leaked = f"~{prod}~{self.version}~" if self.version else f"~{prod}~"
                return Response("THROUGH", "200", 80, 0.0, f"<tr><td>{leaked}</td></tr>")
        return Response("THROUGH", "200", 40, 0.0, "<html>home</html>")


# ---------------------------------------------------------------------------
# NEW: data-extraction confirmation (the computed value must come back)
# ---------------------------------------------------------------------------
def test_extraction_confirms_when_db_evaluates_arithmetic():
    o = EvalOracle(reflect=True)
    v = V.verify(o, "1' UNION SELECT username FROM users-- -", "SQL Injection")
    assert v.exploitable
    assert v.confidence >= 0.9                       # HIGH confidence: concrete proof
    assert "DATA EXTRACTION" in v.reason
    # the reason quotes a real, self-consistent product, and it is the delimited marker
    m = re.search(r"(\d+)\*(\d+)=(\d+)", v.reason)
    assert m and int(m.group(1)) * int(m.group(2)) == int(m.group(3))
    assert f"~{m.group(3)}~" in v.reason


def test_extraction_not_confirmed_when_marker_absent():
    # backend never evaluates/reflects our arithmetic -> extraction stays silent and
    # the verdict falls through to the existing (not-exploitable) SQL result.
    o = EvalOracle(reflect=False)
    v = V.verify(o, "1' UNION SELECT username FROM users-- -", "SQL Injection")
    assert not v.exploitable


def test_extraction_does_not_false_confirm_on_static_site():
    # a clean THROUGH page that even contains a stray bare number must NOT confirm:
    # the '~<product>~' delimiters guard against coincidental digit matches.
    o = MapOracle({}, default=Response("THROUGH", "200", 120, 0.05, "<html>static 633323</html>"))
    v = V.verify(o, "1' OR 'a'='a", "SQL Injection")
    assert not v.exploitable


def test_extraction_quotes_leaked_version_token():
    o = EvalOracle(reflect=True, version="PostgreSQL 14.2")
    v = V.verify(o, "1' UNION SELECT username FROM users-- -", "SQL Injection")
    assert v.exploitable and v.confidence >= 0.9
    assert "version token" in v.reason and "PostgreSQL" in v.reason


def test_extract_confirm_unit_hits_on_cheap_error_based_first():
    # the error-based channel needs no column count, so a vulnerable backend confirms
    # on the very first probe — proving the step stays cheap/bounded on a real hit.
    o = EvalOracle(reflect=True)
    v = V._sqli_extract_confirm(o, "1' UNION SELECT a-- -", "SQL Injection")
    assert v is not None and v.exploitable and v.confidence == 0.95
    assert len(o.sends) == 1
    assert "error-based" in v.reason


def test_extract_confirm_unit_returns_none_and_stays_bounded_when_silent():
    o = EvalOracle(reflect=False)
    v = V._sqli_extract_confirm(o, "1' UNION SELECT a-- -", "SQL Injection")
    assert v is None
    # bounded: error-based (2 wrappers x 3) + UNION walk (2 x 3 x max_cols=5) = 36, no runaway
    assert len(o.sends) <= 40


def test_extraction_confirms_via_union_channel_when_error_based_suppressed():
    # The error-based oracles above leak on the very first probe, so they never
    # exercise the UNION-based channel to a HIT. This models the exact backend that
    # channel exists for: the app SUPPRESSES DB errors (error-based stays silent) but a
    # balanced UNION SELECT against its 3-column query renders the marker. A hit here
    # proves the UNION column-walk + per-engine concat exprs actually surface a value,
    # not just that the (already-covered) error-based path works.
    def sender(p):
        if "UNION SELECT" not in p.upper():          # error-based probes: errors swallowed
            return Response("THROUGH", "200", 40, 0.0, "<html>home</html>")
        factors = re.findall(r"\((\d+)\s*\*\s*(\d+)\)", p)   # one a*b per UNION column
        if len(factors) == 3:                        # UNION balances only at 3 columns
            prod = int(factors[0][0]) * int(factors[0][1])   # the DB evaluates the arithmetic
            return Response("THROUGH", "200", 90, 0.0, f"<td>~{prod}~</td>")
        return Response("THROUGH", "200", 50, 0.0, "<html>column count mismatch</html>")

    o = FuncOracle(sender)
    v = V.verify(o, "1' OR 'a'='a", "SQL Injection")
    assert v.exploitable and v.confidence == 0.95
    assert "DATA EXTRACTION" in v.reason
    assert "UNION SELECT" in v.reason and "3 column" in v.reason     # the UNION channel fired
    # error-based probes ran first and leaked nothing; a UNION SELECT probe carried the hit
    assert any("UNION SELECT" in s for s in o.sends)
    assert any(k in s for s in o.sends for k in ("EXTRACTVALUE", "CONVERT", "CAST"))


def test_extraction_exception_degrades_to_not_confirmed():
    # if a probe raises mid-extraction, deep-confirm swallows it and the verdict
    # degrades to "not confirmed" — verification must never crash the run.
    class PartialBoom:
        def __init__(self):
            self.t = Target(base_url="https://t")

        def send(self, p):
            if any(k in p for k in ("EXTRACTVALUE", "UPDATEXML", "CONVERT", "CAST", "UNION SELECT")):
                raise RuntimeError("boom during extraction")
            return Response("THROUGH", "200", 10, 0.0, "<html>ok</html>")

    v = V.verify(PartialBoom(), "1' OR 'a'='a", "SQL Injection")
    assert not v.exploitable
    assert v.attack_class == "SQL Injection"


# ---------------------------------------------------------------------------
# Regression: every pre-existing SQL signal still fires with extraction first
# ---------------------------------------------------------------------------
def test_sqli_error_signature_path_still_confirms():
    o = MapOracle({"' OR 1=1-- -": Response("THROUGH", "200", 60, 0.0,
                   "You have an error in your SQL syntax; check the manual")})
    v = V.verify(o, "' OR 1=1-- -", "SQL Injection")
    assert v.exploitable and v.confidence >= 0.8
    assert "error signature" in v.reason.lower()


def test_sqli_boolean_differential_path_still_confirms():
    o = MapOracle({
        "id=1 OR 1=1": Response("THROUGH", "200", 500, 0.0, "<html>" + ("row " * 200) + "</html>"),
        "id=1 OR 1=2": Response("THROUGH", "200", 40, 0.0, "<html>none</html>"),
    })
    v = V.verify(o, "id=1 OR 1=1", "SQL Injection")
    assert v.exploitable
    assert "boolean differential" in v.reason.lower()


def test_existing_union_count_path_survives_extraction():
    # extraction runs first; its probes don't match a "UNION SELECT NULL,.." walk, so
    # the existing UNION column-count confirmation must still fire underneath.
    def sender(p):
        m = re.search(r"UNION SELECT ((?:NULL,?)+)", p, re.I)
        if not m:
            return Response("THROUGH", "200", 100, 0.0, "<html>home</html>")
        ncols = m.group(1).count("NULL")
        if ncols == 3:
            return Response("THROUGH", "200", 500, 0.0, "<html>admin rows</html>")
        return Response("THROUGH", "200", 80, 0.0,
                        "The used SELECT statements have a different number of columns")
    v = V.verify(FuncOracle(sender), "1' OR 'a'='a", "SQL Injection")
    assert v.exploitable
    assert "UNION" in v.reason or "column" in v.reason.lower()


def test_existing_time_based_blind_path_survives_extraction():
    def sender(p):
        m = re.search(r"(?:SLEEP|pg_sleep)\((\d+)\)", p, re.I)
        delay = int(m.group(1)) if m else 0        # a vulnerable backend runs the sleep
        return Response("THROUGH", "200", 100, 0.05 + delay, "<html>ok</html>")
    v = V.verify(FuncOracle(sender), "9 AND 1=1", "SQL Injection")
    assert v.exploitable and "time-based" in v.reason.lower()


def test_static_site_still_not_confirmed_through_whole_chain():
    # every response identical, no errors, no timing jump, no extractable marker
    o = FuncOracle(lambda p: Response("THROUGH", "200", 120, 0.05, "<html>static</html>"))
    v = V.verify(o, "1' OR 'a'='a", "SQL Injection")
    assert not v.exploitable
