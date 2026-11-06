"""Tests for the Phase B quick-win mutator cluster (waffen/mutate/quickwin.py).

Imports waffen.mutate to trigger registration side effects, then verifies each
new mutator is registered, mutates its representative seed, and is returned by
REGISTRY.select(attack_class=...) for the class(es) it claims to serve.

No pytest: plain functions, run via import-and-call (see tests/test_engine.py).
"""
from waffen.mutate import REGISTRY

SQL_SEED = "' OR 1=1-- -"
UNION_SEED = "UNION SELECT 1"
XSS_SEED = "<script>alert(1)</script>"
CMD_SEED = "; cat /etc/passwd"
TRAV_SEED = "../../../../etc/passwd"
INFO_SCHEMA_SEED = "' UNION SELECT table_name FROM information_schema.tables-- -"

# name -> (seed to mutate, attack_class to check REGISTRY.select against)
QUICKWIN_MUTATORS = {
    "sql_keyword_doubling": (UNION_SEED, "SQL Injection"),
    "percent_u_unicode": (SQL_SEED, "SQL Injection"),
    "sql_intra_keyword_comment": (UNION_SEED, "SQL Injection"),
    "sql_space_to_dash_comment": (SQL_SEED, "SQL Injection"),
    "sql_space_to_hash_comment": (SQL_SEED, "SQL Injection"),
    "sql_information_schema_split": (INFO_SCHEMA_SEED, "SQL Injection"),
    "xss_mxss_noscript": (XSS_SEED, "XSS Injection"),
    "xss_mxss_xmp_style": (XSS_SEED, "XSS Injection"),
    "xss_polyglot": (XSS_SEED, "XSS Injection"),
    "xss_entity_no_semicolon": (XSS_SEED, "XSS Injection"),
    "case_fold_preimage": (XSS_SEED, "XSS Injection"),
    "cmd_wildcard_glob": (CMD_SEED, "Command Injection"),
    "trav_self_referential": (TRAV_SEED, "Directory Traversal"),
    "trav_overlong_3byte_slash": (TRAV_SEED, "Directory Traversal"),
    "xss_utf7_encode": (XSS_SEED, "XSS Injection"),
}


def test_all_quickwin_mutators_registered():
    names = {m.name for m in REGISTRY.all()}
    missing = set(QUICKWIN_MUTATORS) - names
    assert not missing, f"missing mutators: {missing}"


def test_each_quickwin_mutator_changes_its_seed():
    for name, (seed, _cls) in QUICKWIN_MUTATORS.items():
        m = REGISTRY.get(name)
        out = m.apply(seed)
        assert out != seed, f"{name} did not change seed {seed!r}"
        assert isinstance(out, str) and out, f"{name} returned empty/non-str"


def test_each_quickwin_mutator_deterministic():
    for name, (seed, _cls) in QUICKWIN_MUTATORS.items():
        m = REGISTRY.get(name)
        assert m.apply(seed) == m.apply(seed), f"{name} is not deterministic"


def test_each_quickwin_mutator_selectable_for_its_class():
    for name, (_seed, cls) in QUICKWIN_MUTATORS.items():
        selected_names = {m.name for m in REGISTRY.select(attack_class=cls)}
        assert name in selected_names, f"{name} not selectable for class {cls!r}"


def test_case_fold_preimage_selectable_for_any_class():
    # classes=None -> valid for every attack class, not just XSS/SQL
    for cls in ("SQL Injection", "XSS Injection", "Command Injection",
                "Directory Traversal", "File Inclusion", "SSTI", "NoSQL Injection"):
        selected_names = {m.name for m in REGISTRY.select(attack_class=cls)}
        assert "case_fold_preimage" in selected_names, cls


def test_keyword_doubling_reassembles_on_naive_strip():
    out = REGISTRY.get("sql_keyword_doubling").apply("SELECT * FROM users")
    assert out == "SELSELECTECT * FRFROMOM users"
    # naive single-pass removal of the literal keyword reassembles it
    stripped = out.replace("SELECT", "", 1)
    assert "SELECT" in stripped


def test_space_to_dash_and_hash_comment_strip_all_spaces():
    for name, marker in (("sql_space_to_dash_comment", "--"),
                          ("sql_space_to_hash_comment", "#")):
        out = REGISTRY.get(name).apply(SQL_SEED)
        assert " " not in out
        assert marker in out


def test_information_schema_split_breaks_literal_token():
    out = REGISTRY.get("sql_information_schema_split").apply(INFO_SCHEMA_SEED)
    assert "information_schema" not in out
    assert "/**/" in out


def test_cmd_wildcard_glob_obfuscates_cat():
    out = REGISTRY.get("cmd_wildcard_glob").apply(CMD_SEED)
    assert "cat" not in out
    assert "c?t" in out


def test_traversal_self_referential_collapses_after_one_strip():
    out = REGISTRY.get("trav_self_referential").apply(TRAV_SEED)
    assert out != TRAV_SEED
    assert "..././" in out
    # a single non-recursive '../' strip still leaves a real traversal behind
    stripped_once = out.replace("../", "")
    assert "../" in stripped_once


def test_xss_utf7_encode_removes_angle_brackets():
    out = REGISTRY.get("xss_utf7_encode").apply(XSS_SEED)
    assert "<" not in out and ">" not in out
    assert out == "+ADw-script+AD4-alert(1)+ADw-/script+AD4-"


def test_registry_total_grew():
    assert len(REGISTRY.all()) >= 130


def _run_all():
    tests = [v for k, v in globals().items() if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
    print(f"OK: {len(tests)} test functions passed")


if __name__ == "__main__":
    _run_all()
