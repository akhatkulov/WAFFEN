"""Reproduce the 2026 ModSecurity transformation CVEs as version-differentials:
a VULNERABLE (libmodsecurity 3.0.16) engine beside a PATCHED (3.0.17) one, the SAME
isolation rules (lab/vuln-engine-rules.conf) and the SAME payloads — produced by
WAFFEN's own mutators — so the only variable is the engine version.

Each rule matches the non-SQL token "blockedtoken", so CRS/libinjection never fire;
the rule blocks only if its transformation behaves correctly. See docs/VALIDATION.md
§7.1 (removeComments) and §7.4 (base64DecodeExt).

    docker compose -f lab/modsec-vuln-compose.yml -p waffen-lab-vuln up -d
    .venv/bin/python lab/vuln_repro.py
"""
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, ".")
from waffen.mutate import REGISTRY  # noqa: E402

ENGINES = [("VULNERABLE 3.0.16", 18081), ("PATCHED 3.0.17", 18082)]


def code(port: int, q: str):
    url = f"http://localhost:{port}/rest/products/search?" + urllib.parse.urlencode({"q": q})
    try:
        return urllib.request.urlopen(url, timeout=10).getcode()
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:  # noqa: BLE001
        return f"ERR {e}"


# (cve, seed, baseline-mutator, probe-mutator)
CASES = [
    ("CVE-2026-104259 t:removeComments", "blocked token",
     "sql_between_comment", "sql_adjacent_comment"),
    ("GHSA-4j47-8qcr-jf59 t:base64DecodeExt", "blockedtoken",
     "base64", "base64_malformed_prefix"),
]

all_pass = True
for cve, seed, base_mut, probe_mut in CASES:
    baseline = REGISTRY.get(base_mut).apply(seed)
    probe = REGISTRY.get(probe_mut).apply(seed)
    print(f"\n== {cve} ==")
    print(f"   baseline ({base_mut}): {baseline!r}")
    print(f"   probe    ({probe_mut}): {probe!r}")
    print(f"   {'engine':20} {'baseline':>9} {'probe':>9}")
    res = {}
    for name, port in ENGINES:
        b, p = code(port, baseline), code(port, probe)
        res[name] = (b, p)
        print(f"   {name:20} {str(b):>9} {str(p):>9}")
    vb, vp = res["VULNERABLE 3.0.16"]
    pb, pp = res["PATCHED 3.0.17"]
    baseline_ok = (vb == 403 and pb == 403)   # the rule works (payload caught when well-formed)
    bypass_vuln = (vp == 200)                 # the probe slips the vulnerable engine
    if baseline_ok and bypass_vuln and pp == 403:
        verdict = "VERSION-DIFFERENTIAL: bypasses 3.0.16, blocked by 3.0.17 (fix verified)"
        ok = True
    elif baseline_ok and bypass_vuln and pp == 200:
        verdict = "BLINDS BOTH 3.0.16 AND 3.0.17 (version-independent; not a differential)"
        ok = True
    else:
        verdict = "inconclusive / not reproduced — see codes"
        ok = False
    all_pass = all_pass and ok
    print("   -> " + verdict)

print("\n" + ("ALL PRIMITIVES CONFIRMED (see per-case verdict for differential vs version-independent)"
             if all_pass else "NOT ALL CONFIRMED — see per-case codes above"))
sys.exit(0 if all_pass else 1)
