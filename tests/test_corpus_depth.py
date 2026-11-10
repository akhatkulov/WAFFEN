"""Depth tests for the PayloadsAllTheThings harvester (waffen/eval/corpus.py).

The harvester is WAFFEN's answer to a large curated scoring corpus: it reads
PayloadsAllTheThings off disk and maps each folder to a WAFFEN attack class.
These tests pin the strengthened behaviour — broadened directory->class mapping,
markdown/prose-robust payload extraction, de-dup, and the per-class cap — using a
tiny fake corpus built in tmp_path (nothing is fabricated; payloads are read from
the files these tests write).
"""
from waffen.eval.corpus import harvest, classify, DIR_TO_CLASS, MAX_PAYLOAD_LEN
from waffen.kb import seeds as kb_seeds


def _write(root, relpath, text):
    p = root / relpath
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


# ----- directory -> attack-class mapping -----------------------------------

def test_mapping_targets_are_real_waffen_classes():
    # grounding guard: every mapped class must be a real WAFFEN seeds class, so
    # the harvested corpus lines up with scoring/routing and nothing is invented.
    real = set(kb_seeds.classes())
    assert set(DIR_TO_CLASS.values()) <= real, set(DIR_TO_CLASS.values()) - real


def test_classify_normalises_payloadsallthethings_folders():
    # PayloadsAllTheThings folder names that need shortening to WAFFEN classes
    assert classify("Server Side Template Injection") == "SSTI"
    assert classify("Server Side Request Forgery") == "SSRF"
    assert classify("Server Side Include Injection") == "SSI"
    # case / punctuation variants normalise to the same class
    assert classify("server-side request forgery") == "SSRF"
    assert classify("SERVER SIDE TEMPLATE INJECTION") == "SSTI"


def test_classify_documented_synonyms():
    # grounded synonyms (PayloadsAllTheThings READMEs / CWE) fold into one class
    assert classify("Path Traversal") == "Directory Traversal"
    assert classify("LFI") == "File Inclusion"
    assert classify("RFI") == "File Inclusion"
    assert classify("XSS") == "XSS Injection"
    assert classify("SQLi") == "SQL Injection"
    assert classify("File Upload") == "Upload Insecure Files"


def test_classify_identity_and_passthrough_preserved():
    # already-canonical folders are unchanged (preserved behaviour)
    assert classify("XSS Injection") == "XSS Injection"
    assert classify("Open Redirect") == "Open Redirect"
    # unknown folders fall through to their own name (original one-folder==class)
    assert classify("GraphQL Injection") == "GraphQL Injection"
    assert classify("Totally Unknown Thing") == "Totally Unknown Thing"


def test_harvest_maps_new_category_folders(tmp_path):
    _write(tmp_path, "Server Side Template Injection/ssti.txt", "{{7*7}}\n")
    _write(tmp_path, "Server Side Request Forgery/ssrf.txt", "http://169.254.169.254/\n")
    _write(tmp_path, "Server Side Include Injection/ssi.txt", '<!--#exec cmd="id"-->\n')
    _write(tmp_path, "Path Traversal/trav.txt", "../../../../etc/passwd\n")
    _write(tmp_path, "LFI/lfi.txt", "/etc/passwd\n")
    _write(tmp_path, "XSS Injection/xss.txt", "<script>alert(1)</script>\n")
    _write(tmp_path, "GraphQL Injection/gql.txt", "query{__schema{types{name}}}\n")

    by = harvest(tmp_path)
    assert by["SSTI"] == ["{{7*7}}"]
    assert by["SSRF"] == ["http://169.254.169.254/"]
    assert by["SSI"] == ['<!--#exec cmd="id"-->']
    assert by["Directory Traversal"] == ["../../../../etc/passwd"]  # Path Traversal folder
    assert by["File Inclusion"] == ["/etc/passwd"]                  # LFI folder
    assert by["XSS Injection"] == ["<script>alert(1)</script>"]     # identity preserved
    assert by["GraphQL Injection"] == ["query{__schema{types{name}}}"]  # unknown passthrough


def test_two_folders_fold_into_one_class(tmp_path):
    # "Path Traversal" and "Directory Traversal" both -> one WAFFEN class/bucket
    _write(tmp_path, "Directory Traversal/a.txt", "..%2f..%2fetc%2fpasswd\n")
    _write(tmp_path, "Path Traversal/b.txt", "../../../../etc/shadow\n")
    by = harvest(tmp_path)
    assert set(by) == {"Directory Traversal"}
    assert set(by["Directory Traversal"]) == {"..%2f..%2fetc%2fpasswd", "../../../../etc/shadow"}


# ----- markdown / prose-robust extraction -----------------------------------

def test_markdown_fenced_payloads_extracted_noise_stripped(tmp_path):
    md = (
        "# XSS Injection\n"
        "\n"
        "Some prose that describes the payloads and must be ignored.\n"
        "\n"
        "```html\n"
        "<script>alert(1)</script>\n"
        "<img src=x onerror=alert(1)>\n"
        "# an inline comment inside the fence is dropped\n"
        "`alert(document.cookie)`\n"       # backtick-wrapped -> unwrapped
        "```\n"
        "\n"
        "More trailing prose we do not want.\n"
    )
    _write(tmp_path, "XSS Injection/README.md", md)
    got = harvest(tmp_path)["XSS Injection"]

    assert "<script>alert(1)</script>" in got
    assert "<img src=x onerror=alert(1)>" in got
    assert "alert(document.cookie)" in got            # backticks stripped
    # noise is gone
    assert not any("prose" in g for g in got)
    assert "# XSS Injection" not in got
    assert "# an inline comment inside the fence is dropped" not in got
    assert all("`" not in g for g in got)
    assert got == [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "alert(document.cookie)",
    ]


def test_markdown_outside_fence_is_not_harvested(tmp_path):
    # a .md with no code fences contributes no payloads (pure prose is skipped);
    # the bucket may exist but stays empty, matching the original harvester.
    _write(tmp_path, "Open Redirect/notes.md", "# Heading\n\nJust prose, no fences here.\n")
    assert harvest(tmp_path).get("Open Redirect", []) == []


def test_list_files_keep_fence_lookalike_lines(tmp_path):
    # Fences are a markdown-only concept. A flat .txt/.lst wordlist is read one
    # payload per line (LIST_EXTS), so a line that merely looks like a ``` / ~~~
    # fence is a payload and must be kept -- markdown fence-stripping must not leak
    # into list files (regression: it previously swallowed such lines).
    _write(tmp_path, "XSS Injection/wordlist.txt", "```\n<svg onload=alert(1)>\n```js\n")
    assert harvest(tmp_path)["XSS Injection"] == ["```", "<svg onload=alert(1)>", "```js"]


def test_over_long_lines_skipped(tmp_path):
    blob = "A" * (MAX_PAYLOAD_LEN + 10)
    _write(tmp_path, "SQL Injection/s.txt", "' OR 1=1-- -\n" + blob + "\nadmin'--\n")
    got = harvest(tmp_path)["SQL Injection"]
    assert "' OR 1=1-- -" in got
    assert "admin'--" in got
    assert blob not in got
    assert all(len(p) <= MAX_PAYLOAD_LEN for p in got)


def test_comment_lines_and_blanks_skipped(tmp_path):
    # original behaviour preserved: '#' comments and blank lines are dropped
    _write(tmp_path, "SQL Injection/s.txt", "# a comment\n\n   \n' OR '1'='1\n")
    assert harvest(tmp_path)["SQL Injection"] == ["' OR '1'='1"]


def test_significant_trailing_space_preserved(tmp_path):
    # a SQL inline-comment payload needs its trailing space kept
    _write(tmp_path, "SQL Injection/s.txt", "1' OR '1'='1' -- \n")
    assert harvest(tmp_path)["SQL Injection"] == ["1' OR '1'='1' -- "]


# ----- de-dup ----------------------------------------------------------------

def test_dedup_within_and_across_files(tmp_path):
    _write(tmp_path, "SQL Injection/a.txt", "' OR 1=1\n' OR 1=1\nUNION SELECT 1\n")
    _write(tmp_path, "SQL Injection/b.txt", "' OR 1=1\n1=1#\n")
    got = harvest(tmp_path)["SQL Injection"]
    assert got.count("' OR 1=1") == 1                       # de-duped within+across files
    assert set(got) == {"' OR 1=1", "UNION SELECT 1", "1=1#"}


# ----- per-class cap ---------------------------------------------------------

def test_per_class_cap_is_honored(tmp_path):
    payloads = "\n".join(f"p{i}" for i in range(10)) + "\n"
    _write(tmp_path, "XSS Injection/x.txt", payloads)
    assert len(harvest(tmp_path, max_per_class=3)["XSS Injection"]) == 3
    assert len(harvest(tmp_path, max_per_class=0)["XSS Injection"]) == 10   # 0 == no cap
    assert len(harvest(tmp_path)["XSS Injection"]) == 10                    # default no cap


def test_cap_honored_across_multiple_files(tmp_path):
    _write(tmp_path, "XSS Injection/a.txt", "a0\na1\na2\n")
    _write(tmp_path, "XSS Injection/b.txt", "b0\nb1\nb2\n")
    capped = harvest(tmp_path, max_per_class=4)["XSS Injection"]
    assert len(capped) == 4                                 # cap spans files


def test_harvest_returns_plain_dict_of_lists(tmp_path):
    _write(tmp_path, "XSS Injection/x.txt", "<svg onload=alert(1)>\n")
    by = harvest(tmp_path)
    assert isinstance(by, dict)
    assert all(isinstance(k, str) and isinstance(v, list) for k, v in by.items())
