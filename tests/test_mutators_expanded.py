"""Tests for the expanded mutation library (sql_tamper, xss_context, path_cmd,
generic_extra). Imports waffen.mutate to trigger registration side effects and
verifies the new mutators behave as advertised: they change a representative
seed for their attack class and are selectable through REGISTRY.select().
"""
from waffen.mutate import REGISTRY

# Richer per-class seeds that exercise every token each mutator looks for
# (keyword, operator, string literal, tag, event handler, separator, etc.).
SQL_SEED = "' OR 'a'='a' UNION SELECT 1 AND 1=1-- -"
XSS_SEED = "<script>alert(1)</script><img src=x onerror=alert(1)> javascript:alert(1)"
TRAVERSAL_SEED = "../../../../etc/passwd"
CMD_SEED = "; cat /etc/passwd"
GENERIC_SEED = "' OR 1=1 AND cat /etc/passwd -- -"

SQL_TAMPER_MUTATORS = [
    "sql_between_comment", "sql_adjacent_comment", "sql_adjacent_comment_keyword",
    "sql_pcre_matchlimit_pad",
    "sql_versioned_comment_mysql", "sql_versioned_comment_generic",
    "sql_keyword_case_random", "sql_space_mysql_comment", "sql_space_vtab", "sql_space_nbsp",
    "sql_space_tab", "sql_space_formfeed", "sql_space_plus", "sql_space_parens",
    "sql_equal_to_like", "sql_equal_to_between", "sql_and_to_ampamp", "sql_or_to_pipepipe",
    "sql_string_char_concat", "sql_string_hex", "sql_string_concat_plus", "sql_string_concat_pipe",
    "sql_nested_parens", "sql_scientific_notation", "sql_backtick_identifiers",
    "sql_double_encode_keyword", "sql_comment_hash_terminator", "sql_comment_multiline_terminator",
    "sql_unionselect_collapse", "sql_quote_doubled",
]

XSS_CONTEXT_MUTATORS = [
    "xss_tag_case_mix", "xss_attr_case_mix", "xss_split_tag_comment", "xss_split_tag_null",
    "xss_split_js_scheme_newline", "xss_alt_event_handler", "xss_event_focus_autofocus",
    "xss_js_scheme_tab", "xss_js_scheme_entity", "xss_js_scheme_newline", "xss_backtick_template",
    "xss_entity_named_angle", "xss_entity_decimal_angle", "xss_entity_hex_padded_angle",
    "xss_data_uri_svg", "xss_svg_onload", "xss_math_vector", "xss_whitespace_slash_tag",
    "xss_whitespace_tab_tag", "xss_whitespace_newline_tag", "xss_whitespace_formfeed_tag",
    "xss_fromcharcode_rebuild", "xss_iframe_srcdoc",
]

PATH_CMD_TRAVERSAL_MUTATORS = [
    "trav_dot_percent", "trav_dot_double_percent", "trav_slash_percent",
    "trav_slash_double_percent", "trav_overlong_utf8", "trav_dotdot_slashslash",
    "trav_dotdot_backslash", "trav_nested_encoded_slash", "trav_mixed_slashes",
    "trav_extra_slashes", "trav_null_byte_suffix", "trav_null_byte_dot_png",
    "trav_question_suffix", "trav_hash_suffix", "trav_absolute_prefix", "trav_unc_prefix",
    "file_wrapper_php_filter", "file_wrapper_data", "file_wrapper_file_scheme", "file_wrapper_zip",
]

PATH_CMD_COMMAND_MUTATORS = [
    "cmd_sep_semicolon", "cmd_sep_pipe", "cmd_sep_double_pipe", "cmd_sep_double_amp",
    "cmd_sep_newline", "cmd_subshell_dollar_paren", "cmd_subshell_backtick", "cmd_ifs_space",
    "cmd_ifs_dollar_brace", "cmd_brace_expansion", "cmd_quote_split_chars", "cmd_env_var_concat",
    "cmd_sep_percent0a",
]

GENERIC_EXTRA_MUTATORS = [
    "triple_url", "mixed_single_double_url", "unicode_nfkc_fold", "zero_width_insert",
    "zero_width_insert_keywords", "overlong_utf8_generic", "tab_injection",
    "crlf_injection_tail", "crlf_inside", "param_pad_leading_zeros", "param_value_padding",
    "whitespace_vtab_generic", "case_swap_extremes",
]


def _assert_all_change(names, seed):
    for name in names:
        m = REGISTRY.get(name)
        out = m.apply(seed)
        assert out != seed, f"{name!r} is a no-op on representative seed {seed!r}"


def test_registry_grew_well_past_80():
    assert len(REGISTRY.all()) >= 80


def test_sql_tamper_mutators_change_seed_and_selectable():
    _assert_all_change(SQL_TAMPER_MUTATORS, SQL_SEED)
    selected = {m.name for m in REGISTRY.select(attack_class="SQL Injection")}
    for name in SQL_TAMPER_MUTATORS:
        assert name in selected, f"{name} not selectable for SQL Injection"


def test_xss_context_mutators_change_seed_and_selectable():
    _assert_all_change(XSS_CONTEXT_MUTATORS, XSS_SEED)
    selected = {m.name for m in REGISTRY.select(attack_class="XSS Injection")}
    for name in XSS_CONTEXT_MUTATORS:
        assert name in selected, f"{name} not selectable for XSS Injection"


def test_path_cmd_traversal_mutators_change_seed_and_selectable():
    _assert_all_change(PATH_CMD_TRAVERSAL_MUTATORS, TRAVERSAL_SEED)
    selected_trav = {m.name for m in REGISTRY.select(attack_class="Directory Traversal")}
    selected_fi = {m.name for m in REGISTRY.select(attack_class="File Inclusion")}
    for name in PATH_CMD_TRAVERSAL_MUTATORS:
        assert name in selected_trav or name in selected_fi, f"{name} not selectable"


def test_path_cmd_command_injection_mutators_change_seed_and_selectable():
    _assert_all_change(PATH_CMD_COMMAND_MUTATORS, CMD_SEED)
    selected = {m.name for m in REGISTRY.select(attack_class="Command Injection")}
    for name in PATH_CMD_COMMAND_MUTATORS:
        assert name in selected, f"{name} not selectable for Command Injection"


def test_generic_extra_mutators_change_seed_and_selectable_for_any_class():
    _assert_all_change(GENERIC_EXTRA_MUTATORS, GENERIC_SEED)
    # generic mutators (classes=None -> "*") must be selectable under every class
    for attack_class in ("SQL Injection", "XSS Injection", "Command Injection",
                         "Directory Traversal", "File Inclusion", "NoSQL Injection"):
        selected = {m.name for m in REGISTRY.select(attack_class=attack_class)}
        for name in GENERIC_EXTRA_MUTATORS:
            assert name in selected, f"{name} not selectable for {attack_class}"


def test_base64_malformed_prefix_mutator():
    import base64 as _b64
    m = REGISTRY.get("base64_malformed_prefix")
    payload = "<script>alert(1)</script>"
    out = m.apply(payload)
    assert out != payload and out.startswith("A==")          # malformed single-char padding group
    assert _b64.b64decode(out[3:]).decode() == payload       # suffix is clean base64 of the payload
    # encoder with classes='*' -> selectable under every attack class
    for cls in ("SQL Injection", "XSS Injection", "Command Injection"):
        assert "base64_malformed_prefix" in {x.name for x in REGISTRY.select(attack_class=cls)}


def test_pcre_matchlimit_pad_mutator():
    m = REGISTRY.get("sql_pcre_matchlimit_pad")
    payload = "' OR 1=1-- -"
    out = m.apply(payload)
    assert out.startswith(payload)                 # payload kept intact at the head
    assert len(out) - len(payload) >= 4096         # substantial filler to trip the step limit
    assert " -- " in out                           # filler neutralised by a trailing SQL comment
    sel_sql = {x.name for x in REGISTRY.select(attack_class="SQL Injection")}
    sel_xss = {x.name for x in REGISTRY.select(attack_class="XSS Injection")}
    assert "sql_pcre_matchlimit_pad" in sel_sql and "sql_pcre_matchlimit_pad" in sel_xss


def test_deterministic_mutators_are_stable_across_calls():
    # no unseeded randomness: applying twice must give the same result
    sample = SQL_TAMPER_MUTATORS[:3] + XSS_CONTEXT_MUTATORS[:3] + GENERIC_EXTRA_MUTATORS[:3]
    seeds = [SQL_SEED, XSS_SEED, GENERIC_SEED]
    for name in sample:
        m = REGISTRY.get(name)
        for seed in seeds:
            assert m.apply(seed) == m.apply(seed)


if __name__ == "__main__":
    import sys
    import types

    mod = sys.modules[__name__]
    failures = []
    for attr_name in dir(mod):
        if attr_name.startswith("test_"):
            fn = getattr(mod, attr_name)
            if isinstance(fn, types.FunctionType):
                try:
                    fn()
                    print(f"PASS {attr_name}")
                except AssertionError as e:
                    failures.append(attr_name)
                    print(f"FAIL {attr_name}: {e}")
    if failures:
        print(f"\n{len(failures)} test(s) failed: {failures}")
        sys.exit(1)
    print("\nAll tests passed.")
