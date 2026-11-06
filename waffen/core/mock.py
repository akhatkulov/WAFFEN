"""A mock WAF sender for offline testing of the search engine.

Simulates a naive signature WAF: if the (lower-cased) payload still contains any
blocked token, it returns a 403 block; otherwise 200 THROUGH. This lets us verify
that beam search can discover an encoding/obfuscation chain that removes the raw
signature, with no network and no load on a real target.
"""
from __future__ import annotations

from .oracle import Response

DEFAULT_SIGNATURES = [
    "<script", "onerror", "onload", "svg/onload", "javascript:",
    "' or", "\" or", "union select", "or 1=1", "'1'='1", "--",
    "/etc/passwd", "../", "....//", "php://", "169.254.169.254",
    "{{", "${", "<%=", "cat ", "whoami", "$(", "`id`", "| id", "; ",
]

_BLOCK_BODY = ("<!doctype html><title>403 Forbidden — RedEye WAF</title>"
               "Request blocked by RedEye" + "x" * 6000)
_OK_BODY = "<!doctype html><title>Results</title>" + "y" * 1200


def make_mock_sender(signatures=None, block_signature="Request blocked by RedEye"):
    """Simulate a *decent* signature WAF.

    It normalizes the request the way a real WAF does — URL-decodes (twice),
    strips inline /**/ comments and odd whitespace, lowercases — THEN matches
    signatures. So mere URL-encoding does NOT evade it. Genuine gaps remain
    (HTML-entity and full-width-unicode forms are not folded), which is what the
    search must discover — forcing real multi-step behaviour, as on a live WAF.
    """
    import re
    import urllib.parse

    sigs = [s.lower() for s in (signatures or DEFAULT_SIGNATURES)]

    def normalize(payload: str) -> str:
        s = urllib.parse.unquote(urllib.parse.unquote(payload))
        s = s.replace("/**/", " ").replace("\t", " ").replace("\n", " ")
        s = re.sub(r"/\*!?\d*", "", s).replace("*/", "")
        s = re.sub(r"\s+", " ", s)
        return s.lower()

    def sender(payload: str) -> Response:
        norm = normalize(payload)
        if any(sig in norm for sig in sigs):
            return Response("BLOCKED", "403", len(_BLOCK_BODY), 0.05, _BLOCK_BODY)
        return Response("THROUGH", "200", len(_OK_BODY), 0.04, _OK_BODY)

    return sender
