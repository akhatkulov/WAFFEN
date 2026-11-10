#!/usr/bin/env python3
"""Deliberately-vulnerable sink app (stdlib only) to LIVE-validate the verifiers that
are otherwise only unit-tested: Open Redirect, SSI, LDAP, XXE, SSRF.

Each endpoint is crafted to respond exactly as the matching verifier's probe expects,
so `waffen.verify.verifier.verify()` can confirm it end-to-end against a real socket.
For local verifier testing ONLY — it echoes injected input and simulates internal
fetches on purpose. Do not expose it.

    python3 lab/vuln_sinks.py        # serves on 127.0.0.1:18099
"""
import re
import socketserver
import urllib.parse
from http.server import BaseHTTPRequestHandler
from xml.dom import minidom

PORT = 18099
# A fake cloud-metadata credentials blob (matches the SSRF verifier's signatures).
_METADATA = ('{"Code":"Success","Type":"AWS-HMAC","AccessKeyId":"ASIAWFXTEST1234EXMPL",'
             '"SecretAccessKey":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",'
             '"Token":"FQoGZXIvwfxTESTtoken","Expiration":"2035-01-01T00:00:00Z"}')
_META_HOSTS = ("169.254.169.254", "metadata.google.internal", "metadata.azure", "100.100.100.200")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _reply(self, code, body, headers=None):
        b = body.encode("utf-8", "replace")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(b)
        except BrokenPipeError:
            pass

    def do_POST(self):
        self.do_GET()

    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qs(u.query, keep_blank_values=True)

        def g(name):
            return q.get(name, [""])[0]

        # Open Redirect: honor the attacker-supplied URL verbatim in Location.
        if u.path == "/redirect":
            self._reply(302, "redirecting", {"Location": g("to")})
            return

        # SSI: simulate mod_include evaluating `echo $((a*b))` server-side.
        if u.path == "/ssi":
            m = re.search(r"\$\(\((\d+)\s*\*\s*(\d+)\)\)", g("q"))
            self._reply(200, f"page result: {int(m.group(1)) * int(m.group(2))}" if m else "page ok")
            return

        # LDAP: emit a driver error when filter metacharacters are injected.
        if u.path == "/ldap":
            if re.search(r"[*()\\|&=]", g("q")):
                self._reply(200, "Error: javax.naming.directory.InvalidSearchFilterException: "
                                 "invalid filter near ')' [LDAP: error code 87 - Bad search filter]")
            else:
                self._reply(200, "login failed")
            return

        # XXE: parse the submitted XML with internal-entity expansion and reflect it.
        if u.path == "/xxe":
            out = "xml error"
            try:
                doc = minidom.parseString(g("q"))
                node = doc.documentElement.firstChild
                out = node.data if node is not None else ""
            except Exception:
                pass
            self._reply(200, f"parsed document text: {out}")
            return

        # SSRF: simulate the server fetching an internal metadata endpoint.
        if u.path == "/ssrf":
            url = g("url")
            self._reply(200, _METADATA if any(h in url for h in _META_HOSTS)
                        else "fetched: 200 OK (nothing interesting)")
            return

        # Blind/error-SUPPRESSED SQLi: NEVER leaks a SQL error string and returns an
        # identical body for a tautology and its negation (so the error-signature and
        # boolean-differential channels both come up empty) — but it DOES evaluate an
        # injected arithmetic expression server-side and render the delimited marker,
        # which is exactly what the data-extraction verifier channel (0.95) confirms.
        if u.path == "/sqli-blind":
            val = g("q")
            m = re.search(r"\((\d+)\s*\*\s*(\d+)\)", val)
            if m and ("126" in val or "~" in val):            # extraction probe present
                prod = int(m.group(1)) * int(m.group(2))
                self._reply(200, f"results for id: ~{prod}~5.7.44-MariaDB~ end")
            else:
                self._reply(200, "search results: 0 products found")   # same for true & false
            return

        self._reply(200, "vuln sink app")


if __name__ == "__main__":
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(("127.0.0.1", PORT), Handler) as httpd:
        print(f"vuln-sinks listening on 127.0.0.1:{PORT}", flush=True)
        httpd.serve_forever()
