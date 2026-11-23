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
except Exception:  # optional: verifier module not installed/broken
    _verify = None

try:
    from .verify.calibrate import calibrate as _calibrate
except Exception:  # optional: calibration module not installed/broken
    _calibrate = None

try:
    from .recon.normalize import learn_normalization as _learn_norm, reorder_mutators as _reorder
except Exception:  # optional: normalize/learner module not installed/broken
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


def _prefilter_mutators(mutators, seed_payload: str, on_event=None) -> list:
    """Drop mutators that produce no change on the seed — they waste budget."""
    useful = []
    for m in mutators:
        try:
            variant = m.apply(seed_payload)
            if variant and variant != seed_payload and variant.strip():
                useful.append(m)
        except Exception:
            useful.append(m)
    dropped = len(mutators) - len(useful)
    if dropped and on_event:
        on_event("prefilter", original=len(mutators), kept=len(useful), dropped=dropped)
    return useful


def run_bypass(target: Target, seeds, *, strategy: str = "beam",
               transform_names=None, all_mutators: bool = False,
               width: int = 6, depth: int = 4,
               pop_size: int = 20, generations: int = 8, branch: int = 4,
               iterations: int = 200, rollout_depth: int = 3, delay: float = 0.0,
               max_requests: int = 400, stop_on_first: bool = False,
               timing_threshold: float | None = None, do_calibrate: bool = False,
               do_learn: bool = False, concurrency: int = 1,
               canary_payload: str | None = None, canary_every: int = 25,
               do_verify: bool = False, sender=None, transport: str = "curl",
               on_event=None, scorer=None,
               cross_axis: bool = False, cross_axis_budget: int = 200) -> list[BypassRun]:
    """Run the full sweep. `seeds` is an iterable of (attack_class, payload)."""
    runs: list[BypassRun] = []
    transforms = T.select(set(transform_names) if transform_names else None)
    n_transforms = len(transforms)
    seed_list = list(seeds)
    total_runs = n_transforms * len(seed_list)

    import sys as _sys

    def _default_progress(*, depth, max_depth, requests, budget, throughs,
                          best_score, frontier_size):
        label = strategy[:5]
        line = (f"    {label} {depth}/{max_depth} | "
                f"{requests}/{budget} req | "
                f"{throughs} thru | best={best_score:.1f} | "
                f"frontier={frontier_size}")
        _sys.stderr.write(f"\r{line:<72}")
        _sys.stderr.flush()

    progress_fn = _default_progress if on_event else None

    # calibration / normalization probes are class-less, so resolve --inject auto
    # to a concrete mode (query) for them; per-class routing applies to the seeds below.
    from .kb.inject_map import resolve_base as _resolve_base
    probe_target = _resolve_base(target)

    run_idx = 0
    interrupted = False
    for tr_idx, tr in enumerate(transforms):
        if interrupted:
            break
        rt = None if tr.name == "identity" else tr
        cal = None
        tt = timing_threshold
        if do_calibrate and _calibrate is not None:
            cal = _calibrate(Oracle(probe_target, sender=sender, request_transform=rt, transport=transport))
            if getattr(cal, "timing_reliable", False):
                tt = getattr(cal, "timing_threshold", None)
            if on_event:
                on_event("calibrated", transform=tr.name,
                         waf_detected=getattr(cal, "waf_detected", None),
                         confidence=getattr(cal, "confidence", None))

        norm_profile = None
        if do_learn and _learn_norm is not None:
            norm_profile = _learn_norm(Oracle(probe_target, sender=sender, request_transform=rt,
                                               calibration=cal, transport=transport))
            if on_event:
                on_event("learned", transform=tr.name,
                         blind_to=getattr(norm_profile, "blind_to", None),
                         n_recommended=len(getattr(norm_profile, "recommended_mutators", []) or []))

        for cls, payload in seed_list:
            # --inject auto: route each class to its correct injection point
            # (traversal->path, upload->multipart, ...) instead of forcing one.
            eff = _effective_target(target, cls)
            oracle = Oracle(eff, sender=sender, request_transform=rt, calibration=cal, delay=delay,
                            canary_payload=canary_payload, canary_every=canary_every, transport=transport)
            if scorer is not None:
                from .search.gradient import patch_oracle_scorer
                patch_oracle_scorer(oracle, scorer)
            mutators = _mutators_for(cls, all_mutators)
            if norm_profile is not None and _reorder is not None:
                mutators = _reorder(mutators, norm_profile)
            mutators = _prefilter_mutators(mutators, payload, on_event=on_event)

            # inline verifier: a THROUGH is confirmed exploitable before it counts
            # as a stop_on_first success, so the search does not halt on a dead bypass.
            verify_fn = None
            if do_verify and _verify is not None:
                def verify_fn(p, _cls=cls, _rt=rt, _eff=eff):  # fresh oracle so verify reqs stay separate
                    return _verify(Oracle(_eff, sender=sender, request_transform=_rt, transport=transport), p, _cls)

            run_idx += 1
            if on_event:
                _sys.stderr.write(
                    f"\r  [{run_idx}/{total_runs}] transform={tr.name}  "
                    f"seed={payload[:30]!r:<32}\n")
                _sys.stderr.flush()

            try:
                if strategy == "genetic":
                    res = genetic_search(
                        oracle, payload, mutators,
                        pop_size=pop_size, generations=generations,
                        max_requests=max_requests, attack_class=cls,
                        stop_on_first=stop_on_first, verify_fn=verify_fn,
                        on_event=on_event, on_progress=progress_fn,
                        concurrency=concurrency,
                    )
                elif strategy == "mcts":
                    res = mcts_search(
                        oracle, payload, mutators,
                        iterations=iterations, rollout_depth=rollout_depth,
                        max_requests=max_requests, attack_class=cls,
                        stop_on_first=stop_on_first, timing_threshold=tt,
                        verify_fn=verify_fn, on_event=on_event,
                        on_progress=progress_fn, concurrency=concurrency,
                    )
                elif strategy == "bestfirst":
                    res = best_first_search(
                        oracle, payload, mutators,
                        branch=branch, max_requests=max_requests, attack_class=cls,
                        stop_on_first=stop_on_first, timing_threshold=tt,
                        verify_fn=verify_fn, on_event=on_event,
                        on_progress=progress_fn, concurrency=concurrency,
                    )
                else:
                    res = beam_search(
                        oracle, payload, mutators,
                        width=width, depth=depth, max_requests=max_requests,
                        attack_class=cls, stop_on_first=stop_on_first,
                        verify_fn=verify_fn, on_event=on_event,
                        on_progress=progress_fn, concurrency=concurrency,
                    )
            except KeyboardInterrupt:
                _sys.stderr.write("\n  [!] Interrupted — saving partial results\n")
                interrupted = True
                break

            if on_event:
                n_thru = len(res.findings)
                mark = "✓" if n_thru else "―"
                _sys.stderr.write(
                    f"\r  [{run_idx}/{total_runs}] {tr.name}: "
                    f"{n_thru} through ({res.requests} req) {mark}\n")
                _sys.stderr.flush()

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

    if cross_axis and runs:
        try:
            from .search.cross_axis import CrossAxisComposer, CrossAxisConfig
            ca_cfg = CrossAxisConfig(budget=cross_axis_budget)
            composer = CrossAxisComposer(target, config=ca_cfg, sender=sender,
                                        transport=transport)
            ca_result = composer.compose(runs)
            if ca_result.findings:
                ca_search = SearchResult(
                    seed="(cross-axis)",
                    attack_class=ca_result.findings[0].attack_class,
                    findings=[],
                    requests=ca_result.requests,
                )
                for caf in ca_result.findings:
                    from .search.beam import Finding
                    f = Finding(
                        payload=caf.payload, chain=caf.chain + [f"via:{caf.transform}"],
                        code=caf.code, attack_class=caf.attack_class,
                    )
                    ca_search.findings.append(f)
                runs.append(BypassRun(
                    f"cross-axis({ca_result.pairs_tested}t/{ca_result.pairs_skipped}s)",
                    ca_result.findings[0].attack_class, ca_search, {},
                ))
            if on_event:
                on_event("cross_axis", findings=len(ca_result.findings),
                         tested=ca_result.pairs_tested, budget_used=ca_result.requests)
        except Exception as exc:
            import sys
            print(f"  [warn] cross-axis failed: {exc}", file=sys.stderr)

    return runs
