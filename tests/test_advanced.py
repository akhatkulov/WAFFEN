"""Tests for the Phase B "remaining catalog" mutator cluster
(waffen/mutate/advanced.py).

Imports waffen.mutate to trigger registration side effects, then verifies each
new mutator is registered, mutates its representative seed, and is returned by
REGISTRY.select(attack_class=...) for the class(es) it claims to serve.

No pytest: plain functions, run via import-and-call (see tests/test_engine.py).
"""
from waffen.mutate import REGISTRY

SQL_SEED = "' OR 1=1-- -"
UNION_SEED = "UNION SELECT 1 FROM users"
XSS_SEED = "<script>alert(1)</script>"
CMD_SEED = "; cat /etc/passwd"
TRAV_SEED = "../../../../etc/passwd"

# name -> (seed to mutate, attack_class to check REGISTRY.select against)
ADVANCED_MUTATORS = {
    "sql_commaless_mid": (UNION_SEED, "SQL Injection"),
    "sql_commaless_limit": (UNION_SEED, "SQL Injection"),
    "sql_greatest": (UNION_SEED, "SQL Injection"),
    "sql_least": (UNION_SEED, "SQL Injection"),
    "sql_ifnull_variants": (UNION_SEED, "SQL Injection"),
    "sql_concat_ws": (UNION_SEED, "SQL Injection"),
    "sql_0x_to_char": (UNION_SEED, "SQL Injection"),
    "sql_whole_query_versioned": (SQL_SEED, "SQL Injection"),
    "sql_multibyte_quote": (SQL_SEED, "SQL Injection"),
    "sql_backslash_escape_quote": (SQL_SEED, "SQL Injection"),
    "sql_modsecurity_zeroversioned": (UNION_SEED, "SQL Injection"),
    "cmd_var_substring": (CMD_SEED, "Command Injection"),
    "cmd_reverse_exec": (CMD_SEED, "Command Injection"),
    "cmd_base64_exec": (CMD_SEED, "Command Injection"),
    "cmd_quote_noise": (CMD_SEED, "Command Injection"),
    "cmd_backslash_split": (CMD_SEED, "Command Injection"),
    "lfi_more_wrappers": (TRAV_SEED, "File Inclusion"),
    "rfi_remote": (TRAV_SEED, "File Inclusion"),
    "trav_windows_ads": (TRAV_SEED, "Directory Traversal"),
    "trav_16bit_unicode": (TRAV_SEED, "Directory Traversal"),
    "xss_js_rebuild": (XSS_SEED, "XSS Injection"),
    "xss_rare_handlers": (XSS_SEED, "XSS Injection"),
    "uni_line_separators": (SQL_SEED, "SQL Injection"),
}


def test_all_advanced_mutators_registered():
    names = {m.name for m in REGISTRY.all()}
    missing = set(ADVANCED_MUTATORS) - names
    assert not missing, f"missing mutators: {missing}"


def test_each_advanced_mutator_changes_its_seed():
    for name, (seed, _cls) in ADVANCED_MUTATORS.items():
        m = REGISTRY.get(name)
        out = m.apply(seed)
        assert out != seed, f"{name} did not change seed {seed!r}"
        assert isinstance(out, str) and out, f"{name} returned empty/non-str"


def test_each_advanced_mutator_deterministic():
    for name, (seed, _cls) in ADVANCED_MUTATORS.items():
        m = REGISTRY.get(name)
        assert m.apply(seed) == m.apply(seed), f"{name} is not deterministic"


def test_each_advanced_mutator_selectable_for_its_class():
    for name, (_seed, cls) in ADVANCED_MUTATORS.items():
        selected_names = {m.name for m in REGISTRY.select(attack_class=cls)}
        assert name in selected_names, f"{name} not selectable for class {cls!r}"


def test_uni_line_separators_selectable_for_any_class():
    # classes=None -> valid for every attack class, not just SQL
    for cls in ("SQL Injection", "XSS Injection", "Command Injection",
                "Directory Traversal", "File Inclusion", "SSTI", "NoSQL Injection"):
        selected_names = {m.name for m in REGISTRY.select(attack_class=cls)}
        assert "uni_line_separators" in selected_names, cls


def test_sql_commaless_mid_rewrites_commas_away():
    out = REGISTRY.get("sql_commaless_mid").apply("SELECT MID(version(),1,1)")
    assert "," not in out
    assert "MID(version() FROM 1 FOR 1)" in out


def test_sql_commaless_limit_rewrites_commas_away():
    out = REGISTRY.get("sql_commaless_limit").apply("SELECT * FROM users LIMIT 5,10")
    assert out == "SELECT * FROM users LIMIT 10 OFFSET 5"


def test_sql_0x_to_char_reverses_hex_literal():
    out = REGISTRY.get("sql_0x_to_char").apply("SELECT 0x6162")
    assert "0x" not in out
    assert "CHAR(97)" in out and "CHAR(98)" in out


def test_sql_whole_query_versioned_wraps_entire_payload():
    out = REGISTRY.get("sql_whole_query_versioned").apply(SQL_SEED)
    assert out == f"/*!50000{SQL_SEED}*/"


def test_sql_backslash_escape_quote_escapes_every_quote():
    out = REGISTRY.get("sql_backslash_escape_quote").apply("' OR '1'='1")
    assert out.count("\\'") == 4
    assert "'" not in out.replace("\\'", "")


def test_cmd_base64_exec_decodes_back_to_original_command():
    import base64
    out = REGISTRY.get("cmd_base64_exec").apply(CMD_SEED)
    assert "base64 -d|sh" in out
    b64 = out.split("echo ", 1)[1].split("|", 1)[0]
    assert base64.b64decode(b64).decode() == "cat /etc/passwd"


def test_cmd_reverse_exec_reverses_trailing_command():
    out = REGISTRY.get("cmd_reverse_exec").apply(CMD_SEED)
    assert "cat /etc/passwd"[::-1] in out


def test_trav_windows_ads_appends_ads_marker_and_trailing_junk():
    out = REGISTRY.get("trav_windows_ads").apply(TRAV_SEED)
    assert out.startswith(TRAV_SEED)
    assert "::$DATA" in out
    assert out.endswith(" ")


def test_trav_16bit_unicode_removes_raw_separators():
    out = REGISTRY.get("trav_16bit_unicode").apply(TRAV_SEED)
    assert "/" not in out and "." not in out
    assert "%u2215" in out or "%e0%80%af" in out


def test_xss_js_rebuild_hides_literal_alert_call():
    out = REGISTRY.get("xss_js_rebuild").apply(XSS_SEED)
    assert "alert(1)" not in out
    assert "atob(" in out


def test_xss_rare_handlers_swaps_known_handler():
    out = REGISTRY.get("xss_rare_handlers").apply('<img src=x onerror=alert(1)>')
    assert "onerror" not in out
    assert "onanimationstart" in out


def test_uni_line_separators_inserts_js_separators():
    out = REGISTRY.get("uni_line_separators").apply(SQL_SEED)
    assert " " in out or " " in out
    assert " " not in out


def test_registry_total_grew_to_at_least_155():
    assert len(REGISTRY.all()) >= 155


def _run_all():
    tests = [v for k, v in globals().items() if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
    print(f"OK: {len(tests)} test functions passed")


if __name__ == "__main__":
    _run_all()
