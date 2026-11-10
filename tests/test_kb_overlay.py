"""The KB overlay consumer: kb-update downloads per-class seed files, and seeds.py
now actually merges them into SEEDS at load — the end-to-end piece the self-updating
KB was missing (previously it downloaded bytes nothing consumed)."""
import copy

from waffen.kb import seeds as s


def test_kb_overlay_extends_and_adds_classes(tmp_path, monkeypatch):
    snapshot = copy.deepcopy(s.SEEDS)
    try:
        d = tmp_path / "seeds"
        d.mkdir()
        (d / "SQL Injection.txt").write_text("' custom-kb-payload-1-- -\n# a comment\n\n' custom-kb-payload-2-- -\n")
        (d / "Brand New Class.txt").write_text("novel-kb-payload\n")
        monkeypatch.setenv("WAFFEN_KB_DIR", str(d))

        added = s._load_kb_overlay()
        assert added == 3
        # existing class is EXTENDED, built-in seeds preserved
        assert "' custom-kb-payload-1-- -" in s.seeds_for("SQL Injection")
        assert "' OR 1=1-- -" in s.seeds_for("SQL Injection")          # built-in still there
        # a wholly new class appears
        assert "Brand New Class" in s.classes()
        assert s.seeds_for("Brand New Class") == ["novel-kb-payload"]
        # idempotent: re-loading the same dir adds nothing (dedupe)
        assert s._load_kb_overlay() == 0
    finally:
        s.SEEDS.clear()
        s.SEEDS.update(snapshot)


def test_kb_overlay_noop_without_dir(monkeypatch):
    monkeypatch.setenv("WAFFEN_KB_DIR", "/nonexistent/waffen-kb-xyz")
    assert s._load_kb_overlay() == 0
