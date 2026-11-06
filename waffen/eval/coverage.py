"""WAF coverage + false-positive scoring (GoTestWAF-style), folded into WAFFEN.

Fires a corpus of attack payloads at a target and measures how many the WAF
blocks (coverage) per attack class, plus a false-positive rate from a benign set.
Classification uses a runtime `Calibration` when supplied (block/pass/unresolved),
otherwise the oracle's naive verdict — so this shares the same "stop assuming
403==blocked" upgrade as the search side.

  coverage% = blocked / (blocked + through)      per class and overall
  fp%       = benign-requests-blocked / benign-total

This is the defensive counterpart to the bypass search: search finds the gaps,
eval scores how wide they are and whether fixes regressed benign traffic.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..core.oracle import Oracle, Target


# GoTestWAF-style split: API-security classes vs classic application-security classes.
API_CLASSES = frozenset({
    "NoSQL Injection", "LDAP Injection", "XXE Injection", "XXE", "Mass Assignment",
    "GraphQL Injection", "GraphQL", "SSRF", "Server Side Request Forgery",
    "gRPC Injection", "SOAP Injection", "XPath Injection", "REST Injection",
})


def class_group(attack_class: str) -> str:
    """Return "api" or "app" for an attack class; unknown classes default to "app"."""
    return "api" if attack_class in API_CLASSES else "app"


@dataclass
class ClassScore:
    blocked: int = 0
    through: int = 0
    unresolved: int = 0
    down: int = 0

    @property
    def resolved(self) -> int:
        return self.blocked + self.through

    @property
    def coverage(self) -> float:
        return (100.0 * self.blocked / self.resolved) if self.resolved else 0.0


@dataclass
class EvalResult:
    target: str = ""
    per_class: dict = field(default_factory=dict)  # class -> ClassScore
    benign_total: int = 0
    benign_blocked: int = 0           # false positives
    through_samples: dict = field(default_factory=dict)  # class -> [payloads that passed]

    @property
    def overall(self) -> ClassScore:
        o = ClassScore()
        for c in self.per_class.values():
            o.blocked += c.blocked; o.through += c.through
            o.unresolved += c.unresolved; o.down += c.down
        return o

    @property
    def fp_rate(self) -> float:
        return (100.0 * self.benign_blocked / self.benign_total) if self.benign_total else 0.0

    def _group(self, group: str) -> ClassScore:
        o = ClassScore()
        for name, c in self.per_class.items():
            if class_group(name) == group:
                o.blocked += c.blocked; o.through += c.through
                o.unresolved += c.unresolved; o.down += c.down
        return o

    @property
    def api_coverage(self) -> float:
        return self._group("api").coverage

    @property
    def app_coverage(self) -> float:
        return self._group("app").coverage

    def as_dict(self) -> dict:
        def grp(g):
            s = self._group(g)
            return {"coverage_pct": round(s.coverage, 1), "blocked": s.blocked, "through": s.through}
        return {
            "api_vs_app": {"api": grp("api"), "app": grp("app")},
            "target": self.target,
            "overall": {"coverage_pct": round(self.overall.coverage, 1),
                        "blocked": self.overall.blocked, "through": self.overall.through,
                        "unresolved": self.overall.unresolved, "down": self.overall.down},
            "false_positive_pct": round(self.fp_rate, 1),
            "benign_blocked": self.benign_blocked, "benign_total": self.benign_total,
            "per_class": {k: {"coverage_pct": round(v.coverage, 1), "blocked": v.blocked,
                              "through": v.through, "unresolved": v.unresolved, "down": v.down}
                          for k, v in self.per_class.items()},
        }


def _classify(resp, calibration):
    if calibration is not None and getattr(calibration, "waf_detected", False):
        try:
            return calibration.classify(resp)  # block|pass|unresolved
        except Exception:
            pass
    # map naive verdict
    return {"BLOCKED": "block", "THROUGH": "pass", "DOWN": "down"}.get(resp.verdict, "pass")


def run_eval(target: Target, cases, *, benign=None, calibration=None, sender=None,
             concurrency: int = 6, delay: float = 0.0, max_through_samples: int = 50,
             on_event=None) -> EvalResult:
    """`cases` = iterable of (attack_class, payload). `benign` = iterable of strings."""
    res = EvalResult(target=target.base_url)
    oracle = Oracle(target, sender=sender)

    # group payloads by class, send per class (concurrently)
    by_cls: dict[str, list[str]] = {}
    for cls, payload in cases:
        by_cls.setdefault(cls, []).append(payload)

    for cls, payloads in by_cls.items():
        score = res.per_class.setdefault(cls, ClassScore())
        samples = res.through_samples.setdefault(cls, [])
        responses = oracle.send_many(payloads, concurrency=concurrency, delay=delay)
        for payload, resp in zip(payloads, responses):
            kind = _classify(resp, calibration)
            if kind == "block":
                score.blocked += 1
            elif kind == "unresolved":
                score.unresolved += 1
            elif kind == "down":
                score.down += 1
            else:  # pass / through = a coverage gap
                score.through += 1
                if len(samples) < max_through_samples:
                    samples.append(payload)
        if on_event:
            on_event("class_done", attack_class=cls, blocked=score.blocked,
                     through=score.through, coverage=round(score.coverage, 1))

    if benign:
        benign = list(benign)
        res.benign_total = len(benign)
        responses = oracle.send_many(benign, concurrency=concurrency, delay=delay)
        for resp in responses:
            if _classify(resp, calibration) == "block":
                res.benign_blocked += 1  # benign blocked == false positive
        if on_event:
            on_event("benign_done", total=res.benign_total, blocked=res.benign_blocked)

    return res
