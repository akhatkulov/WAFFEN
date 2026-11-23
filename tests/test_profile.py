"""Tests for target profile save/resume."""
import json
import os
import tempfile
from types import SimpleNamespace

import pytest

from waffen.core.profile import TargetProfile


class TestCreate:
    def test_create_basic(self):
        p = TargetProfile.create("https://t.com", "/search", "q")
        assert p.target_url == "https://t.com"
        assert p.path == "/search"
        assert p.param == "q"
        assert p.created
        assert p.updated

    def test_create_defaults(self):
        p = TargetProfile.create("https://t.com")
        assert p.path == "/"
        assert p.param == "q"


class TestReconSetters:
    def test_set_fingerprint(self):
        p = TargetProfile.create("https://t.com")
        p.set_fingerprint({"name": "ModSecurity", "confidence": 0.9})
        assert p.fingerprint["name"] == "ModSecurity"

    def test_set_calibration_dict(self):
        p = TargetProfile.create("https://t.com")
        p.set_calibration({"waf_detected": True, "confidence": 0.9})
        assert p.calibration["waf_detected"] is True

    def test_set_calibration_object(self):
        p = TargetProfile.create("https://t.com")
        cal = SimpleNamespace(waf_detected=True, confidence=0.85, _internal="skip")
        p.set_calibration(cal)
        assert p.calibration["waf_detected"] is True
        assert "_internal" not in p.calibration

    def test_set_score_probe(self):
        p = TargetProfile.create("https://t.com")
        p.set_score_probe("sqli", {"detected": 46, "invisible": 2})
        assert p.has_score_probe("sqli")
        assert not p.has_score_probe("xss")

    def test_set_gap_reports(self):
        p = TargetProfile.create("https://t.com")
        report = SimpleNamespace(engine="sqlite", total=30, through=29, gaps=[])
        p.set_gap_reports([report])
        assert p.has_gap_reports()
        assert "sqlite" in p.gap_reports

    def test_set_cluster_profile_dict(self):
        p = TargetProfile.create("https://t.com")
        p.set_cluster_profile({"n_clusters": 3})
        assert p.cluster_profile["n_clusters"] == 3


class TestSearchState:
    def test_add_findings_dict(self):
        p = TargetProfile.create("https://t.com")
        p.add_findings([{"payload": "' OR 1=1--", "chain": ["base64"]}])
        assert len(p.findings) == 1

    def test_add_findings_object(self):
        p = TargetProfile.create("https://t.com")
        f = SimpleNamespace(payload="' OR 1=1--", chain=["base64"], code="200")
        p.add_findings([f])
        assert len(p.findings) == 1
        assert p.findings[0]["payload"] == "' OR 1=1--"

    def test_add_findings_dedup(self):
        p = TargetProfile.create("https://t.com")
        entry = {"payload": "test", "chain": []}
        p.add_findings([entry, entry])
        assert len(p.findings) == 1

    def test_mark_transform_done(self):
        p = TargetProfile.create("https://t.com")
        p.set_transforms_remaining(["identity", "hpp", "chunked"])
        p.mark_transform_done("identity")
        assert p.is_transform_done("identity")
        assert not p.is_transform_done("hpp")
        assert "identity" not in p.transforms_remaining

    def test_mark_transform_done_idempotent(self):
        p = TargetProfile.create("https://t.com")
        p.mark_transform_done("identity")
        p.mark_transform_done("identity")
        assert p.transforms_completed.count("identity") == 1

    def test_add_requests(self):
        p = TargetProfile.create("https://t.com")
        p.add_requests(100)
        p.add_requests(50)
        assert p.total_requests == 150


class TestSaveLoad:
    def test_roundtrip(self):
        p = TargetProfile.create("https://t.com", "/api", "search")
        p.set_fingerprint({"name": "RedEye"})
        p.set_calibration({"waf_detected": True})
        p.set_score_probe("sqli", {"detected": 46})
        p.add_findings([{"payload": "test"}])
        p.mark_transform_done("identity")
        p.add_requests(200)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            p.save(path)
            loaded = TargetProfile.load(path)

            assert loaded.target_url == "https://t.com"
            assert loaded.path == "/api"
            assert loaded.param == "search"
            assert loaded.fingerprint["name"] == "RedEye"
            assert loaded.calibration["waf_detected"] is True
            assert loaded.has_score_probe("sqli")
            assert len(loaded.findings) == 1
            assert loaded.is_transform_done("identity")
            assert loaded.total_requests == 200
        finally:
            os.unlink(path)

    def test_save_valid_json(self):
        p = TargetProfile.create("https://t.com")
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            p.save(path)
            with open(path) as f:
                data = json.load(f)
            assert data["target_url"] == "https://t.com"
        finally:
            os.unlink(path)

    def test_load_missing_fields(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            json.dump({"target_url": "https://x.com"}, f)
            path = f.name
        try:
            loaded = TargetProfile.load(path)
            assert loaded.target_url == "https://x.com"
            assert loaded.findings == []
            assert loaded.transforms_completed == []
        finally:
            os.unlink(path)


class TestMerge:
    def test_merge_findings(self):
        a = TargetProfile.create("https://t.com")
        a.add_findings([{"payload": "p1"}])

        b = TargetProfile.create("https://t.com")
        b.add_findings([{"payload": "p2"}])

        a.merge(b)
        assert len(a.findings) == 2

    def test_merge_transforms(self):
        a = TargetProfile.create("https://t.com")
        a.mark_transform_done("identity")

        b = TargetProfile.create("https://t.com")
        b.mark_transform_done("hpp")

        a.merge(b)
        assert a.is_transform_done("identity")
        assert a.is_transform_done("hpp")

    def test_merge_recon_no_overwrite_existing(self):
        a = TargetProfile.create("https://t.com")
        a.set_fingerprint({"name": "ModSec"})

        b = TargetProfile.create("https://t.com")
        b.set_fingerprint({"name": "RedEye"})

        a.merge(b)
        assert a.fingerprint["name"] == "ModSec"

    def test_merge_recon_fills_missing(self):
        a = TargetProfile.create("https://t.com")

        b = TargetProfile.create("https://t.com")
        b.set_fingerprint({"name": "RedEye"})

        a.merge(b)
        assert a.fingerprint["name"] == "RedEye"

    def test_merge_requests(self):
        a = TargetProfile.create("https://t.com")
        a.add_requests(100)

        b = TargetProfile.create("https://t.com")
        b.add_requests(50)

        a.merge(b)
        assert a.total_requests == 150

    def test_merge_score_probe(self):
        a = TargetProfile.create("https://t.com")
        a.set_score_probe("sqli", {"detected": 46})

        b = TargetProfile.create("https://t.com")
        b.set_score_probe("xss", {"detected": 10})

        a.merge(b)
        assert a.has_score_probe("sqli")
        assert a.has_score_probe("xss")


class TestQueryHelpers:
    def test_has_calibration(self):
        p = TargetProfile.create("https://t.com")
        assert not p.has_calibration()
        p.set_calibration({"x": 1})
        assert p.has_calibration()

    def test_has_score_probe_any(self):
        p = TargetProfile.create("https://t.com")
        assert not p.has_score_probe()
        p.set_score_probe("sqli", {"x": 1})
        assert p.has_score_probe()

    def test_is_transform_done(self):
        p = TargetProfile.create("https://t.com")
        assert not p.is_transform_done("identity")
        p.mark_transform_done("identity")
        assert p.is_transform_done("identity")


class TestSummary:
    def test_summary_format(self):
        p = TargetProfile.create("https://t.com", "/s", "q")
        p.set_calibration({"x": 1})
        p.add_findings([{"payload": "test"}])
        p.mark_transform_done("identity")
        p.add_requests(42)

        s = p.summary()
        assert "https://t.com" in s
        assert "42" in s
        assert "1 done" in s
        assert "Calibration:  yes" in s
