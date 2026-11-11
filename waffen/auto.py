"""WAFFEN auto/wizard mode — guided WAF bypass testing for everyone.

Runs the full pipeline interactively: ask target, fingerprint the WAF,
calibrate block/pass, scan for gaps, then launch the bypass search — all
with clear progress output and no flags to memorize.

Usage:
    waffen auto                 # interactive wizard
    waffen auto --url URL       # skip the URL prompt
    waffen auto --url URL -y    # non-interactive, accept all defaults
"""
from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field
from typing import Optional

from . import ui
from . import __version__
from .core.oracle import Target


# ---- prompt helpers -------------------------------------------------------

def _ask(prompt: str, default: str = "", choices: list[str] | None = None) -> str:
    """Prompt the user. Return default on empty input."""
    suffix = ""
    if choices:
        suffix = f" [{'/'.join(choices)}]"
    if default:
        suffix += f" (default: {default})"
    sys.stdout.write(ui.bold(f"  {prompt}{suffix}: "))
    sys.stdout.flush()
    val = input().strip()
    return val if val else default


def _confirm(prompt: str, default: bool = True) -> bool:
    hint = "Y/n" if default else "y/N"
    sys.stdout.write(ui.bold(f"  {prompt} [{hint}]: "))
    sys.stdout.flush()
    val = input().strip().lower()
    if not val:
        return default
    return val in ("y", "yes", "ha", "da")


def _phase(num: int, title: str, desc: str = ""):
    print()
    print(ui.rule())
    label = ui.bold(ui.green(f"  PHASE {num}"))
    print(f"{label}  {ui.bold(title)}")
    if desc:
        print(ui.gray(f"  {desc}"))
    print()


# ---- auto config ----------------------------------------------------------

@dataclass
class AutoConfig:
    url: str = ""
    path: str = ""
    param: str = "q"
    inject: str = "query"
    method: str = "GET"
    attack_classes: list[str] = field(default_factory=lambda: ["sqli"])
    timeout: int = 10
    tls_verify: bool = False
    cookie: str = ""
    headers: tuple = ()
    strategy: str = "beam"
    max_requests: int = 300
    yes: bool = False       # non-interactive — accept all defaults
    reconstruct: bool = True  # build exploit seeds from recon results
    transport: str = ""
    out: str = ""


# ---- the wizard -----------------------------------------------------------

def run_auto(cfg: AutoConfig) -> int:
    """Run the full auto pipeline."""
    bn = ui.banner(__version__)
    if bn:
        print(bn)

    print(ui.bold("  WAFFEN Auto Mode"))
    print(ui.gray("  Guided WAF bypass testing — just answer a few questions.\n"))

    # ---- Step 1: target URL -----------------------------------------------
    if not cfg.url:
        cfg.url = _ask("Target URL (e.g. https://example.com)")
        if not cfg.url:
            print(ui.red("  URL kiritilmadi. Chiqish."))
            return 2

    if not cfg.url.startswith(("http://", "https://")):
        cfg.url = "https://" + cfg.url

    # ---- Step 2: injection point ------------------------------------------
    if not cfg.yes:
        print()
        print(ui.gray("  WAF test qilish uchun injection point kerak — bu odatda"))
        print(ui.gray("  search, login, yoki API endpoint bo'ladi.\n"))

        cfg.path = _ask("Path (e.g. /search, /api/products)", cfg.path or "/")
        cfg.param = _ask("Parameter nomi", cfg.param or "q")

        inject_choice = _ask("Injection joyi", "query", ["query", "body", "json"])
        cfg.inject = inject_choice

        if cfg.inject in ("body", "json"):
            cfg.method = "POST"
        else:
            cfg.method = _ask("HTTP method", "GET", ["GET", "POST"])

    # ---- Step 3: auth (optional) ------------------------------------------
    if not cfg.yes:
        if _confirm("Autentifikatsiya kerakmi? (cookie/header)", default=False):
            cfg.cookie = _ask("Cookie (e.g. session=abc123)", "")
            hdr = _ask("Custom header (e.g. Authorization: Bearer xxx)", "")
            if hdr:
                cfg.headers = (hdr,)

    # ---- Step 4: what to test ---------------------------------------------
    if not cfg.yes:
        print()
        print(ui.bold("  Nima test qilasiz?"))
        print(ui.gray("  1) SQLi only (tez)"))
        print(ui.gray("  2) XSS only"))
        print(ui.gray("  3) SQLi + XSS"))
        print(ui.gray("  4) Hammasi (SQLi + XSS + SSTI + path + cmd)"))
        choice = _ask("Tanlang", "1", ["1", "2", "3", "4"])
        class_map = {
            "1": ["sqli"],
            "2": ["xss"],
            "3": ["sqli", "xss"],
            "4": ["sqli", "xss", "ssti", "path_traversal", "command_injection"],
        }
        cfg.attack_classes = class_map.get(choice, ["sqli"])

    # ---- Step 5: speed vs thoroughness ------------------------------------
    if not cfg.yes:
        print()
        print(ui.bold("  Tezlik vs chuqurlik:"))
        print(ui.gray("  1) Tez (300 request, ~2 min)"))
        print(ui.gray("  2) O'rta (1000 request, ~5 min)"))
        print(ui.gray("  3) Chuqur (3000 request, ~15 min)"))
        depth = _ask("Tanlang", "1", ["1", "2", "3"])
        depth_map = {"1": 300, "2": 1000, "3": 3000}
        cfg.max_requests = depth_map.get(depth, 300)

    # ---- summary ----------------------------------------------------------
    print()
    print(ui.rule("PLAN"))
    print(f"  {ui.info('Target:     ')} {ui.bold(cfg.url)}{cfg.path}")
    print(f"  {ui.info('Param:      ')} {cfg.param} ({cfg.inject} {cfg.method})")
    print(f"  {ui.info('Classes:    ')} {', '.join(cfg.attack_classes)}")
    print(f"  {ui.info('Budget:     ')} {cfg.max_requests} requests per class")
    if cfg.cookie:
        print(f"  {ui.info('Auth:       ')} cookie set")
    print()

    if not cfg.yes:
        if not _confirm("Boshlashga tayyormisiz?", default=True):
            print(ui.gray("  Bekor qilindi."))
            return 0

    target = Target(
        base_url=cfg.url, path=cfg.path, param=cfg.param,
        inject=cfg.inject, method=cfg.method,
        timeout=cfg.timeout, tls_verify=cfg.tls_verify,
        extra_headers=cfg.headers, cookie=cfg.cookie,
    )

    results = {}

    # ==== PHASE 1: Fingerprint =============================================
    _phase(1, "WAF FINGERPRINT", "WAF turini aniqlash...")

    waf_name = "Unknown"
    try:
        from .recon.fingerprint import fingerprint
        guesses = fingerprint(target)
        if guesses:
            top = guesses[0]
            waf_name = getattr(top, "name", "Unknown")
            conf = getattr(top, "confidence", 0.0)
            print(f"  {ui.green('+')} WAF aniqlandi: {ui.bold(waf_name)} "
                  f"(confidence: {conf:.0%})")
            for g in guesses[1:3]:
                print(f"  {ui.gray('  ')} {getattr(g, 'name', '?')} ({getattr(g, 'confidence', 0):.0%})")
        else:
            print(f"  {ui.yellow('?')} WAF aniqlanmadi (yashirin yoki yo'q)")
    except Exception as e:
        print(f"  {ui.yellow('!')} Fingerprint xato: {e}")

    results["waf"] = waf_name

    # ==== PHASE 2: Calibrate ===============================================
    _phase(2, "CALIBRATE", "WAF block/pass signaturasini o'rganish...")

    calibration = None
    try:
        from .core.oracle import Oracle
        oracle = Oracle(target, transport=cfg.transport)
        from .verify.calibrate import calibrate
        calibration = calibrate(oracle)
        if calibration.waf_detected:
            print(f"  {ui.green('+')} WAF detected: "
                  f"confidence={calibration.confidence:.0%}")
            print(f"  {ui.gray('  ')} block signature: "
                  f"{calibration.signature[:60] if calibration.signature else 'pattern-based'}")
        else:
            print(f"  {ui.yellow('?')} WAF bloklamadi — target ochiq bo'lishi mumkin")
    except Exception as e:
        print(f"  {ui.yellow('!')} Calibrate xato: {e}")

    results["calibration"] = calibration

    # ==== PHASE 3: Score Probe =============================================
    _phase(3, "SCORE THRESHOLD SCAN", "WAF detection chegarasini xaritalash...")

    score_result = None
    try:
        from .recon.score_probe import ScoreProber
        oracle_sp = Oracle(target, transport=cfg.transport)
        if calibration:
            oracle_sp.calibration = calibration
        prober = ScoreProber(oracle_sp)
        score_result = prober.run("sqli")
        detected = [k for k in score_result.keyword_map if k.detected]
        invisible = [k for k in score_result.keyword_map if not k.detected]
        print(f"  {ui.red('X')} Bloklangan tokenlar ({len(detected)}): "
              + ui.gray(", ".join(k.token for k in detected[:15])))
        if invisible:
            print(f"  {ui.green('O')} Invisible tokenlar ({len(invisible)}): "
                  + ui.bold(", ".join(k.token for k in invisible[:15])))
        if score_result.flip_index >= 0:
            flip = score_result.strip_chain[score_result.flip_index]
            print(f"  {ui.green('>')} Threshold boundary: {ui.bold(flip.payload[:50])}")
        results["score_probe"] = {
            "detected": len(detected),
            "invisible": len(invisible),
        }
    except Exception as e:
        print(f"  {ui.yellow('!')} Score probe xato: {e}")

    # ==== PHASE 4: libinjection Gap Scan ===================================
    _phase(4, "LIBINJECTION GAP SCAN", "Database-specific token blind spotlarni qidirish...")

    total_gaps = 0
    try:
        from .recon.libinjection_gaps import LibinjectionGapHunter
        oracle_li = Oracle(target, transport=cfg.transport)
        hunter = LibinjectionGapHunter(target, sender=lambda p: oracle_li.send(p))
        reports = hunter.scan_all()
        for r in reports:
            if r.through > 0:
                print(f"  {ui.green('+')} {ui.bold(r.engine)}: "
                      f"{r.through} gap topildi / {r.total} token")
                for g in r.gaps[:5]:
                    print(f"      {ui.green('GAP')} {g.token.name} ({g.token.kind})")
                total_gaps += r.through
            else:
                print(f"  {ui.gray('-')} {r.engine}: gap yo'q ({r.blocked} blocked)")
        results["libinjection_gaps"] = total_gaps
    except Exception as e:
        print(f"  {ui.yellow('!')} Gap scan xato: {e}")

    # ==== PHASE 4.5: Payload Reconstruction ==================================
    recon_seeds: list[tuple[str, str]] = []
    if cfg.reconstruct and (score_result is not None or total_gaps > 0):
        _phase(5, "PAYLOAD RECONSTRUCTION",
               "Recon natijalaridan exploit template lar qurish...")
        try:
            from .recon.reconstruct import PayloadReconstructor
            reconstructor = PayloadReconstructor()
            if score_result is not None:
                reconstructor.add_score_probe(score_result)
            if 'reports' in dir() and reports:
                reconstructor.add_gap_reports(reports)
            templates = reconstructor.build()
            recon_seeds = reconstructor.seeds()
            if templates:
                print(f"  {ui.green('+')} {len(templates)} template qurildi, "
                      f"{len(recon_seeds)} seed generatsiya qilindi")
                for t in templates[:5]:
                    print(f"      {ui.bold(t.pattern[:50])} "
                          + ui.gray(f"({t.engine}, gaps: {','.join(t.gap_tokens[:3])})"))
                if len(templates) > 5:
                    print(ui.gray(f"      ... va {len(templates)-5} ta yana"))
            else:
                print(f"  {ui.gray('-')} Recon gap topilmadi — reconstruction o'tkazildi")
            results["reconstructed_seeds"] = len(recon_seeds)
        except Exception as e:
            print(f"  {ui.yellow('!')} Reconstruction xato: {e}")

    # ==== PHASE 6: Bypass Search ===========================================
    _phase(6, "BYPASS SEARCH",
           f"Evasion yo'llarini qidirish ({cfg.strategy} strategy, "
           f"{cfg.max_requests} req/class)...")

    from .kb import seeds as kb_seeds
    from .engine import run_bypass
    from .report import results as rpt

    all_runs = []
    for cls in cfg.attack_classes:
        seeds = [(cls, p) for p in kb_seeds.seeds_for(cls)]
        # merge in reconstructed seeds for this class
        seeds.extend((c, p) for c, p in recon_seeds if c == cls)
        if not seeds:
            print(f"  {ui.gray('-')} {cls}: seed yo'q, o'tkazildi")
            continue

        print(f"  {ui.info(cls)} — {len(seeds)} seed bilan search boshlandi...")
        try:
            runs = run_bypass(
                target, seeds,
                strategy=cfg.strategy, max_requests=cfg.max_requests,
                do_calibrate=False, do_learn=True, do_verify=True,
                sender=None, transport=cfg.transport,
                concurrency=1,
            )
            all_runs.extend(runs)

            findings = []
            for run in runs:
                findings.extend(f for f in run.result.findings if f.verified)

            if findings:
                print(f"  {ui.green('!')} {ui.bold(f'{len(findings)} VERIFIED BYPASS topildi!')}")
                for f in findings[:5]:
                    print(f"      {ui.green('BYPASS')} {f.payload[:55]}")
                    if hasattr(f, "transform") and f.transform:
                        print(f"               transform: {f.transform}")
            else:
                through = sum(len(r.result.findings) for r in runs)
                if through:
                    print(f"  {ui.yellow('~')} {through} through topildi, "
                          f"lekin verified exploit yo'q")
                else:
                    print(f"  {ui.gray('-')} bypass topilmadi (WAF bu class da kuchli)")
        except Exception as e:
            print(f"  {ui.red('!')} Search xato: {e}")

    # ==== RESULTS ==========================================================
    print()
    print(ui.rule("NATIJALAR"))

    total_verified = sum(
        1 for run in all_runs
        for f in run.result.findings if f.verified
    )
    total_through = sum(
        len(run.result.findings) for run in all_runs
    )

    print(f"  {ui.info('WAF:           ')} {ui.bold(waf_name)}")
    print(f"  {ui.info('Token gaps:    ')} {total_gaps}")
    print(f"  {ui.info('Through:       ')} {total_through}")
    print(f"  {ui.info('Verified:      ')} {ui.bold(str(total_verified))}")

    if total_verified > 0:
        print()
        print(f"  {ui.green(ui.bold('  WAF BYPASS TOPILDI!'))}")
        print(ui.gray("  Batafsil ko'rish: waffen bypass --target ... --out results.jsonl"))
    elif total_through > 0:
        print()
        print(f"  {ui.yellow('  WAF dan o`tgan payloadlar bor — chuqurroq test kerak')}")
        print(ui.gray("  Qayta sinash: waffen auto --url ... (3-chuqur tanlang)"))
    else:
        print()
        print(f"  {ui.gray('  WAF kuchli — bypass topilmadi')}")
        print(ui.gray("  Lekin: cve-probe va smuggle bilan ham tekshiring"))

    if all_runs:
        rpt.print_engine_summary(all_runs)

    if cfg.out:
        from .report import results as rr
        rr.write_engine_jsonl(all_runs, cfg.out)
        print(f"\n{ui.ok(f'Natijalar yozildi: {cfg.out}')}")

    print()
    print(ui.gray("  Qo'shimcha buyruqlar:"))
    print(ui.gray(f"    waffen cve-probe --target {cfg.url}"))
    print(ui.gray(f"    waffen smuggle --target {cfg.url}"))
    print(ui.gray(f"    waffen score-probe --target {cfg.url} --class sqli"))
    print(ui.gray(f"    waffen libinjection-scan --target {cfg.url}"))
    print()

    return 0 if total_verified == 0 else 1
