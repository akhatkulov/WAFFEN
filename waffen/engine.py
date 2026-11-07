"""Orchestration: combine the two bypass axes and (optionally) verify findings.

A full WAFFEN run sweeps:  request-transform  ×  seed  ×  search-strategy.
For each request-transform (HPP, chunked, ... or plain 'identity') and each seed
payload, it runs the chosen search (beam or genetic) over the class-appropriate
mutators, then optionally confirms each discovered THROUGH payload with the
semantic verifier so a bypass means "evaded AND still exploitable", not just
"got a 200".
"""
from __future__ import annotations

from dataclasses import dataclass, field
from types import SimpleNamespace

from .core import transforms as T
from .core.oracle import Oracle, Target
from .kb.inject_map import effective as _effective_target
from .mutate import REGISTRY
from .search.beam import SearchResult, beam_search
from .search.genetic import genetic_search
from .search.bestfirst import best_first_search
from .search.mcts import mcts_search

try:
    from .verify.verifier import verify as _verify
except Exception:  # verifier optional
    _verify = None

try:
    from .verify.calibrate import calibrate as _calibrate
except Exception:  # calibration optional
    _calibrate = None

try:
    from .recon.normalize import learn_normalization as _learn_norm, reorder_mutators as _reorder
except Exception:  # learner optional
    _learn_norm = None
    _reorder = None


@dataclass
class BypassRun:
    transform: str
    attack_class: str
    result: SearchResult
    verifications: dict = field(default_factory=dict)  # payload -> Verification


def _mutators_for(attack_class: str, all_mutators: bool):
    if all_mutators or not attack_class:
        return REGISTRY.all()
    return REGISTRY.select(attack_class=attack_class)


def run_bypass(target: Target, seeds, *, strategy: str = "beam",
               transform_names=None, all_mutators: bool = False,
               width: int = 6, depth: int = 4,
               pop_size: int = 20, generations: int = 8, branch: int = 4,
               iterations: int = 200, rollout_depth: int = 3, delay: float = 0.0,
               max_requests: int = 400, stop_on_first: bool = False,
               timing_threshold: float | None = None, do_calibrate: bool = False,
               do_learn: bool = False, concurrency: int = 1,
               canary_payload: str | None = None, canary_every: int = 25,
               do_verify: bool = False, sender=None, on_event=None) -> list[BypassRun]:
    """Run the full sweep. `seeds` is an iterable of (attack_class, payload)."""
    runs: list[BypassRun] = []
    transforms = T.select(set(transform_names) if transform_names else None)

    for tr in transforms:
        rt = None if tr.name == "identity" else tr
        cal = None
        tt = timing_threshold
        if do_calibrate and _calibrate is not None:
            cal = _calibrate(Oracle(target, sender=sender, request_transform=rt))
            if getattr(cal, "timing_reliable", False):
                tt = getattr(cal, "timing_threshold", None)
            if on_event:
                on_event("calibrated", transform=tr.name,
                         waf_detected=getattr(cal, "waf_detected", None),
                         confidence=getattr(cal, "confidence", None))

        norm_profile = None
        if do_learn and _learn_norm is not None:
            norm_profile = _learn_norm(Oracle(target, sender=sender, request_transform=rt, calibration=cal))
            if on_event:
                on_event("learned", transform=tr.name,
                         blind_to=getattr(norm_profile, "blind_to", None),
                         n_recommended=len(getattr(norm_profile, "recommended_mutators", []) or []))

        for cls, payload in seeds:
            # --inject auto: route each class to its correct injection point
            # (traversal->path, upload->multipart, ...) instead of forcing one.
            eff = _effective_target(target, cls)
            oracle = Oracle(eff, sender=sender, request_transform=rt, calibration=cal, delay=delay,
                            canary_payload=canary_payload, canary_every=canary_every)
            mutators = _mutators_for(cls, all_mutators)
            if norm_profile is not None and _reorder is not None:
                mutators = _reorder(mutators, norm_profile)

            # inline verifier: a THROUGH is confirmed exploitable before it counts
            # as a stop_on_first success, so the search does not halt on a dead bypass.
            verify_fn = None
            if do_verify and _verify is not None:
                def verify_fn(p, _cls=cls, _rt=rt, _eff=eff):  # fresh oracle so verify reqs stay separate
                    return _verify(Oracle(_eff, sender=sender, request_transform=_rt), p, _cls)

            if strategy == "genetic":
                res = genetic_search(
                    oracle, payload, mutators,
                    pop_size=pop_size, generations=generations,
                    max_requests=max_requests, attack_class=cls,
                    stop_on_first=stop_on_first, verify_fn=verify_fn, on_event=on_event,
                    concurrency=concurrency,
                )
            elif strategy == "mcts":
                res = mcts_search(
                    oracle, payload, mutators,
                    iterations=iterations, rollout_depth=rollout_depth,
                    max_requests=max_requests, attack_class=cls,
                    stop_on_first=stop_on_first, timing_threshold=tt,
                    verify_fn=verify_fn, on_event=on_event,
                    concurrency=concurrency,
                )
            elif strategy == "bestfirst":
                res = best_first_search(
                    oracle, payload, mutators,
                    branch=branch, max_requests=max_requests, attack_class=cls,
                    stop_on_first=stop_on_first, timing_threshold=tt,
                    verify_fn=verify_fn, on_event=on_event,
                    concurrency=concurrency,
                )
            else:
                res = beam_search(
                    oracle, payload, mutators,
                    width=width, depth=depth, max_requests=max_requests,
                    attack_class=cls, stop_on_first=stop_on_first,
                    verify_fn=verify_fn, on_event=on_event,
                    concurrency=concurrency,
                )

            # verifications now live on the findings themselves (set inline); expose a
            # payload->record map for the report layer, keeping BypassRun's shape.
            verifs = {}
            for find in res.findings:
                if find.verified is not None:
                    verifs[find.payload] = SimpleNamespace(
                        exploitable=find.verified, confidence=find.confidence)
            # put verified-exploitable findings first in the report order
            res.findings.sort(key=lambda f: (f.verified is not True, len(f.chain), f.payload))
            runs.append(BypassRun(tr.name, cls, res, verifs))
    return runs
