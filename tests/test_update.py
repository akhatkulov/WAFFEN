"""Tests for waffen/kb/update.py — KB update mechanism."""
import json
import os
import tempfile

from waffen.kb.update import (
    KBSource,
    UpdateCheck,
    UpdateResult,
    _normalize_version,
    _compare_versions,
    _guess_extension,
    _fetch_remote_version,
    check_for_update,
    apply_update,
    load_local_version,
    default_sources,
    check_and_update_all,
    _github_releases_latest_url,
)


# ---- version parsing/comparison ----

class TestNormalizeVersion:
    def test_strips_v_prefix(self):
        assert _normalize_version("v1.2.3") == "1.2.3"
        assert _normalize_version("V1.0") == "1.0"

    def test_strips_whitespace(self):
        assert _normalize_version("  1.2.3  ") == "1.2.3"

    def test_no_prefix(self):
        assert _normalize_version("1.2.3") == "1.2.3"


class TestCompareVersions:
    def test_equal(self):
        assert _compare_versions("1.2.3", "1.2.3") == 0

    def test_less(self):
        assert _compare_versions("1.2.3", "1.2.4") == -1
        assert _compare_versions("1.2.3", "1.3.0") == -1
        assert _compare_versions("1.2.3", "2.0.0") == -1

    def test_greater(self):
        assert _compare_versions("1.2.4", "1.2.3") == 1
        assert _compare_versions("2.0.0", "1.9.9") == 1

    def test_v_prefix(self):
        assert _compare_versions("v1.2.3", "1.2.3") == 0
        assert _compare_versions("v1.2.3", "v1.2.4") == -1

    def test_trailing_zero(self):
        assert _compare_versions("1.2", "1.2.0") == 0
        assert _compare_versions("1", "1.0.0") == 0

    def test_non_numeric_segment(self):
        assert _compare_versions("1.2.alpha", "1.2.beta") == -1
        assert _compare_versions("1.2.beta", "1.2.alpha") == 1
        assert _compare_versions("1.2.alpha", "1.2.alpha") == 0


# ---- extension guessing ----

class TestGuessExtension:
    def test_json(self):
        assert _guess_extension("kb-2.0.0.json") == ".json"

    def test_tar_gz(self):
        assert _guess_extension("source.tar.gz") == ".tar.gz"

    def test_tar_bz2(self):
        assert _guess_extension("source.tar.bz2") == ".tar.bz2"

    def test_url_with_query(self):
        assert _guess_extension("https://example.com/file.zip?token=x") == ".zip"

    def test_no_extension(self):
        assert _guess_extension("noext") == ".bin"

    def test_empty(self):
        assert _guess_extension("") == ".bin"

    def test_url_path(self):
        assert _guess_extension("https://example.com/files/kb-latest.tar.gz") == ".tar.gz"


# ---- fetch_remote_version ----

class TestFetchRemoteVersion:
    def test_github_release(self):
        source = KBSource(name="test", kind="github_release", repo="owner/repo")
        fake = lambda url, timeout: json.dumps({"tag_name": "v1.5.0"}).encode()
        v = _fetch_remote_version(source, fake, 10)
        assert v == "1.5.0"

    def test_manifest(self):
        source = KBSource(name="test", kind="manifest",
                          manifest_url="https://example.com/manifest.json")
        fake = lambda url, timeout: json.dumps({"version": "2.0.0"}).encode()
        v = _fetch_remote_version(source, fake, 10)
        assert v == "2.0.0"

    def test_unknown_kind_raises(self):
        source = KBSource(name="test", kind="ftp")
        try:
            _fetch_remote_version(source, lambda u, t: b"", 10)
            assert False, "should have raised"
        except ValueError as e:
            assert "unknown" in str(e)

    def test_github_no_repo_raises(self):
        source = KBSource(name="test", kind="github_release", repo="")
        try:
            _fetch_remote_version(source, lambda u, t: b"", 10)
            assert False, "should have raised"
        except ValueError:
            pass


# ---- check_for_update ----

class TestCheckForUpdate:
    def test_update_available(self):
        source = KBSource(name="test", kind="manifest",
                          manifest_url="https://example.com/m.json",
                          local_version="1.0.0")
        fake = lambda url, timeout: json.dumps({"version": "2.0.0"}).encode()
        check = check_for_update(source, fetch=fake)
        assert check.update_available is True
        assert check.remote_version == "2.0.0"
        assert check.error is None

    def test_already_up_to_date(self):
        source = KBSource(name="test", kind="manifest",
                          manifest_url="https://example.com/m.json",
                          local_version="2.0.0")
        fake = lambda url, timeout: json.dumps({"version": "2.0.0"}).encode()
        check = check_for_update(source, fetch=fake)
        assert check.update_available is False

    def test_network_error_no_raise(self):
        source = KBSource(name="test", kind="manifest",
                          manifest_url="https://example.com/m.json")
        def boom(url, timeout):
            raise ConnectionError("offline")
        check = check_for_update(source, fetch=boom)
        assert check.update_available is False
        assert check.error is not None
        assert "offline" in check.error


# ---- apply_update ----

class TestApplyUpdate:
    def test_no_op_when_not_available(self):
        source = KBSource(name="test", kind="manifest", manifest_url="x")
        check = UpdateCheck(source_name="test", local_version="1.0",
                            update_available=False)
        result = apply_update(source, check, "/tmp/waffen-test-noop")
        assert result.applied is False
        assert result.error is None

    def test_downloads_and_writes(self):
        source = KBSource(name="test-kb", kind="manifest",
                          manifest_url="https://example.com/m.json",
                          local_version="1.0.0")
        check = UpdateCheck(source_name="test-kb", local_version="1.0.0",
                            remote_version="2.0.0", update_available=True)

        content = b"payload data here"
        manifest = json.dumps({
            "version": "2.0.0",
            "download_url": "https://example.com/kb.json",
        }).encode()

        def fake(url, timeout):
            if "m.json" in url:
                return manifest
            if "kb.json" in url:
                return content
            return content

        with tempfile.TemporaryDirectory() as tmpdir:
            result = apply_update(source, check, tmpdir, fetch=fake)
            assert result.applied is True
            assert result.new_version == "2.0.0"
            assert result.dest_path is not None
            assert os.path.exists(result.dest_path)
            with open(result.dest_path, "rb") as f:
                assert f.read() == content

    def test_download_error_no_raise(self):
        source = KBSource(name="test", kind="manifest",
                          manifest_url="https://example.com/m.json")
        check = UpdateCheck(source_name="test", local_version="1.0",
                            remote_version="2.0", update_available=True)
        def boom(url, timeout):
            raise IOError("download failed")
        result = apply_update(source, check, "/tmp/waffen-noop", fetch=boom)
        assert result.applied is False
        assert "download failed" in result.error


# ---- load_local_version ----

class TestLoadLocalVersion:
    def test_missing_file(self):
        assert load_local_version("/nonexistent/path", "test") == "0.0.0"

    def test_reads_version(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            vfile = os.path.join(tmpdir, "my-kb.version")
            with open(vfile, "w") as f:
                f.write("3.1.4\n")
            assert load_local_version(tmpdir, "my-kb") == "3.1.4"

    def test_empty_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            vfile = os.path.join(tmpdir, "empty.version")
            with open(vfile, "w") as f:
                f.write("")
            assert load_local_version(tmpdir, "empty") == "0.0.0"


# ---- default_sources ----

class TestDefaultSources:
    def test_returns_empty(self):
        assert default_sources() == []


# ---- check_and_update_all ----

class TestCheckAndUpdateAll:
    def test_empty_sources(self):
        results = check_and_update_all([], "/tmp/waffen-noop")
        assert results == []

    def test_mixed_sources(self):
        s1 = KBSource(name="uptodate", kind="manifest",
                       manifest_url="https://example.com/m1.json",
                       local_version="2.0.0")
        s2 = KBSource(name="outdated", kind="manifest",
                       manifest_url="https://example.com/m2.json",
                       local_version="1.0.0")

        def fake(url, timeout):
            if "m1" in url:
                return json.dumps({"version": "2.0.0"}).encode()
            if "m2" in url:
                return json.dumps({"version": "3.0.0",
                                   "download_url": "https://example.com/kb.bin"}).encode()
            return b"binary content"

        with tempfile.TemporaryDirectory() as tmpdir:
            results = check_and_update_all([s1, s2], tmpdir, fetch=fake)
            assert len(results) == 2
            assert results[0].applied is False
            assert results[1].applied is True
            assert results[1].new_version == "3.0.0"


# ---- github url builder ----

class TestGithubUrl:
    def test_format(self):
        url = _github_releases_latest_url("owner/repo")
        assert url == "https://api.github.com/repos/owner/repo/releases/latest"
