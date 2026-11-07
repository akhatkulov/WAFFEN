"""Tests for per-class injection routing (kb/inject_map.py) and --inject auto end-to-end."""
from waffen.core.mock import make_mock_sender
from waffen.core.oracle import Target
from waffen.kb.inject_map import effective, recommended
from waffen.eval.dataset import build_dataset


def test_recommended_known_and_unknown():
    assert recommended("Directory Traversal")["inject"] == "rawpath"
    assert recommended("Upload Insecure Files")["inject"] == "upload"
    assert recommended("XSS Injection") is None          # value-injection -> base inject


def test_effective_noop_when_not_auto():
    t = Target(base_url="https://x", inject="query", path="/search", param="q")
    assert effective(t, "Directory Traversal") is t       # explicit inject always wins


def test_effective_routes_traversal_to_path_under_auto():
    t = Target(base_url="https://x", inject="auto", path="/search", param="q")
    eff = effective(t, "Directory Traversal")
    assert eff.inject == "rawpath" and eff.path == "/"
    assert t.inject == "auto"                             # original unchanged (dataclasses.replace)


def test_effective_routes_upload_to_multipart_under_auto():
    t = Target(base_url="https://x", inject="auto")
    eff = effective(t, "Upload Insecure Files")
    assert eff.inject == "upload" and eff.path == "/file-upload" and eff.param == "file"


def test_effective_unlisted_class_falls_back_to_query():
    t = Target(base_url="https://x", inject="auto", path="/search", param="q")
    eff = effective(t, "XSS Injection")
    assert eff.inject == "query" and eff.path == "/search" and eff.param == "q"


def test_dataset_auto_records_log_the_per_class_inject():
    # with --inject auto, each class's records should log the inject point it was
    # actually sent at (traversal->rawpath, upload->upload, xss->query).
    t = Target(base_url="mock://x", inject="auto")
    out = build_dataset(
        t,
        attack_cases=[("Directory Traversal", "../../etc/passwd"),
                      ("Upload Insecure Files", "phtml"),
                      ("XSS Injection", "<script>alert(1)</script>")],
        benign=["banana"],
        sender=make_mock_sender(), concurrency=1,
    )
    inj = {r["attack_class"]: r["inject"] for r in out["records"] if r["label"] == "malicious"}
    assert inj["Directory Traversal"] == "rawpath"
    assert inj["Upload Insecure Files"] == "upload"
    assert inj["XSS Injection"] == "query"
    # benign is logged as a plain query value, not "auto"
    benign_rec = next(r for r in out["records"] if r["label"] == "benign")
    assert benign_rec["inject"] == "query"
