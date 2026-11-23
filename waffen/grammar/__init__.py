"""Grammar-guided payload generation — syntactically valid by construction."""
from .engine import Grammar
from .sql import SQL_GRAMMAR
from .xss import XSS_GRAMMAR
from .ssti import SSTI_GRAMMAR

GRAMMARS: dict[str, Grammar] = {
    "sqli": SQL_GRAMMAR,
    "sql": SQL_GRAMMAR,
    "xss": XSS_GRAMMAR,
    "ssti": SSTI_GRAMMAR,
}

__all__ = ["Grammar", "GRAMMARS", "SQL_GRAMMAR", "XSS_GRAMMAR", "SSTI_GRAMMAR"]
