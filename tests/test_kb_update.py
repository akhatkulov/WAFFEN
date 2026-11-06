"""Tests for waffen.kb.update — versioned-KB auto-update mechanism (ROADMAP E1).

No real network access anywhere here: every call injects a fake
`fetch(url, timeout) -> bytes`. Any `dest_dir` used is a pytest `tmp_path`,
never a real location on disk.
"""
from __future__ import annotations

import json
import os

from waffen.kb.update import (
    KBSource,
    UpdateCheck,
    apply_update,
    check_and_update_all,
    check_for_update,
    load_local_version,
)

GITHUB_RELEASES_URL = "https://api.github.com/repos/acme/waf-kb/releases/latest"


def _json_bytes(obj) -> bytes:
    return json.dumps(obj).encode("utf-8")


def _fake_fetch(routes: dict):
    """Build a fake `fetch(url, timeout)` serving canned bytes per URL — any
    URL not in `routes` is a test bug, not a real network call."""

    def fetch(url: str, timeout: int) -> bytes:
        if url not in routes:
            raise AssertionError(f"unexpected fetch URL in test: {url}")
        return routes[url]

    return fetch


def _github_source(local_version: str = "1.0.0", repo: str = "acme/waf-kb") -> KBSource:
    return KBSource(name="acme-kb", kind="github_release", repo=repo, local_version=local_version)


def _manifest_source(
    local_version: str = "1.0.0",
    manifest_url: str = "https://example.invalid/manifest.json",
) -> KBSource:
    return KBSource(
        name="acme-manifest-kb", kind="manifest", manifest_url=manifest_url, local_version=local_version
    )


# ---------------------------------------------------------------------------
# check_for_update — github_release
# ---------------------------------------------------------------------------

def test_github_release_update_available():
    source = _github_source(local_version="1.0.0")
    fetch = _fake_fetch({GITHUB_RELEASES_URL: _json_bytes({"tag_name": "v1.2.0", "assets": []})})

    check = check_for_update(source, fetch=fetch)

    assert check.source_name == "acme-kb"
    assert check.local_version == "1.0.0"
    assert check.remote_version == "1.2.0"  # leading 'v' normalized off
    assert check.update_available is True
    assert check.error is None


def test_github_release_same_version_is_no_update():
    source = _github_source(local_version="1.2.0")
    fetch = _fake_fetch({GITHUB_RELEASES_URL: _json_bytes({"tag_name": "v1.2.0", "assets": []})})

    check = check_for_update(source, fetch=fetch)

    assert check.remote_version == "1.2.0"
    assert check.update_available is False
    assert check.error is None


def test_github_release_local_already_newer_is_no_update():
    source = _github_source(local_version="2.0.0")
    fetch = _fake_fetch({GITHUB_RELEASES_URL: _json_bytes({"tag_name": "v1.2.0", "assets": []})})

    check = check_for_update(source, fetch=fetch)

    assert check.update_available is False


# ---------------------------------------------------------------------------
# check_for_update — manifest
# ---------------------------------------------------------------------------

def test_manifest_update_available():
    source = _manifest_source(local_version="1.0.0")
    fetch = _fake_fetch(
        {source.manifest_url: _json_bytes({"version": "2.0.0", "download_url": "https://example.invalid/kb.tar.gz"})}
    )

    check = check_for_update(source, fetch=fetch)

    assert check.remote_version == "2.0.0"
    assert check.update_available is True
    assert check.error is None


def test_manifest_same_version_is_no_update():
    source = _manifest_source(local_version="2.0.0")
    fetch = _fake_fetch(
        {source.manifest_url: _json_bytes({"version": "2.0.0", "download_url": "https://example.invalid/kb.tar.gz"})}
    )

    check = check_for_update(source, fetch=fetch)

    assert check.update_available is False
    assert check.error is None


# ---------------------------------------------------------------------------
# check_for_update — failure handling (must never raise)
# ---------------------------------------------------------------------------

def test_fetch_exception_never_raises_and_sets_error():
    source = _github_source()

    def boom(url: str, timeout: int) -> bytes:
        raise OSError("simulated network failure")

    check = check_for_update(source, fetch=boom)

    assert check.remote_version is None
    assert check.update_available is False
    assert check.error is not None
    assert "simulated network failure" in check.error


def test_malformed_json_never_raises_and_sets_error():
    source = _github_source()
    fetch = _fake_fetch({GITHUB_RELEASES_URL: b"this is not json"})

    check = check_for_update(source, fetch=fetch)

    assert check.update_available is False
    assert check.error is not None


def test_unknown_kind_never_raises_and_sets_error():
    source = KBSource(name="weird", kind="smoke-signal", local_version="1.0.0")

    check = check_for_update(source, fetch=lambda url, timeout: b"{}")

    assert check.update_available is False
    assert check.error is not None


def test_misconfigured_source_missing_repo_never_raises():
    source = KBSource(name="broken", kind="github_release", repo="", local_version="1.0.0")

    check = check_for_update(source, fetch=lambda url, timeout: b"{}")

    assert check.update_available is False
    assert check.error is not None


# ---------------------------------------------------------------------------
# apply_update — no-op path
# ---------------------------------------------------------------------------

def test_apply_update_noop_when_no_update_available(tmp_path):
    source = _github_source(local_version="1.2.0")
    check = UpdateCheck(
        source_name=source.name,
        local_version="1.2.0",
        remote_version="1.2.0",
        update_available=False,
    )
    dest_dir = tmp_path / "kb-state"  # deliberately does not exist yet

    def fetch_must_not_be_called(url: str, timeout: int) -> bytes:
        raise AssertionError("fetch must not be called when update_available is False")

    result = apply_update(source, check, str(dest_dir), fetch=fetch_must_not_be_called)

    assert result.applied is False
    assert result.new_version is None
    assert result.dest_path is None
    assert result.error is None
    assert not dest_dir.exists()  # no filesystem I/O attempted either


# ---------------------------------------------------------------------------
# apply_update — install path
# ---------------------------------------------------------------------------

def test_apply_update_github_release_writes_asset_and_version_file(tmp_path):
    source = _github_source(local_version="1.0.0")
    check = UpdateCheck(
        source_name=source.name, local_version="1.0.0", remote_version="1.2.0", update_available=True
    )
    payload = b"fake-kb-archive-bytes"
    fetch = _fake_fetch(
        {
            GITHUB_RELEASES_URL: _json_bytes(
                {
                    "tag_name": "v1.2.0",
                    "assets": [{"browser_download_url": "https://example.invalid/kb.tar.gz", "name": "kb.tar.gz"}],
                }
            ),
            "https://example.invalid/kb.tar.gz": payload,
        }
    )
    dest_dir = tmp_path / "kb-state"

    result = apply_update(source, check, str(dest_dir), fetch=fetch)

    assert result.applied is True
    assert result.error is None
    assert result.new_version == "1.2.0"
    assert result.dest_path is not None
    assert result.dest_path.endswith(".tar.gz")
    assert os.path.dirname(result.dest_path) == str(dest_dir)

    with open(result.dest_path, "rb") as fh:
        assert fh.read() == payload

    assert load_local_version(str(dest_dir), source.name) == "1.2.0"


def test_apply_update_github_release_falls_back_to_tarball_when_no_assets(tmp_path):
    source = _github_source(local_version="1.0.0")
    check = UpdateCheck(
        source_name=source.name, local_version="1.0.0", remote_version="1.2.0", update_available=True
    )
    payload = b"tarball-bytes"
    fetch = _fake_fetch(
        {
            GITHUB_RELEASES_URL: _json_bytes(
                {
                    "tag_name": "v1.2.0",
                    "assets": [],
                    "tarball_url": "https://example.invalid/tarball/v1.2.0",
                }
            ),
            "https://example.invalid/tarball/v1.2.0": payload,
        }
    )
    dest_dir = tmp_path / "kb-state"

    result = apply_update(source, check, str(dest_dir), fetch=fetch)

    assert result.applied is True
    assert result.dest_path.endswith(".tar.gz")
    with open(result.dest_path, "rb") as fh:
        assert fh.read() == payload


def test_apply_update_manifest_kind_writes_asset_and_version_file(tmp_path):
    source = _manifest_source(local_version="1.0.0")
    check = UpdateCheck(
        source_name=source.name, local_version="1.0.0", remote_version="2.0.0", update_available=True
    )
    payload = b"manifest-kb-bytes"
    fetch = _fake_fetch(
        {
            source.manifest_url: _json_bytes(
                {"version": "2.0.0", "download_url": "https://example.invalid/kb-2.0.0.json"}
            ),
            "https://example.invalid/kb-2.0.0.json": payload,
        }
    )
    dest_dir = tmp_path / "kb-state"

    result = apply_update(source, check, str(dest_dir), fetch=fetch)

    assert result.applied is True
    assert result.new_version == "2.0.0"
    assert result.dest_path.endswith(".json")
    with open(result.dest_path, "rb") as fh:
        assert fh.read() == payload

    assert load_local_version(str(dest_dir), source.name) == "2.0.0"


def test_apply_update_never_raises_on_download_failure(tmp_path):
    source = _github_source(local_version="1.0.0")
    check = UpdateCheck(
        source_name=source.name, local_version="1.0.0", remote_version="1.2.0", update_available=True
    )

    def boom(url: str, timeout: int) -> bytes:
        raise OSError("disk is on fire")

    result = apply_update(source, check, str(tmp_path / "kb-state"), fetch=boom)

    assert result.applied is False
    assert result.error is not None
    assert result.dest_path is None


# ---------------------------------------------------------------------------
# load_local_version
# ---------------------------------------------------------------------------

def test_load_local_version_defaults_when_missing(tmp_path):
    assert load_local_version(str(tmp_path / "nonexistent-dir"), "whatever") == "0.0.0"


def test_load_local_version_roundtrips_after_apply_update(tmp_path):
    source = _manifest_source(local_version="0.0.0")
    check = UpdateCheck(
        source_name=source.name, local_version="0.0.0", remote_version="1.0.0", update_available=True
    )
    fetch = _fake_fetch(
        {
            source.manifest_url: _json_bytes({"version": "1.0.0", "download_url": "https://example.invalid/kb.bin"}),
            "https://example.invalid/kb.bin": b"bytes",
        }
    )
    dest_dir = tmp_path / "kb-state"

    apply_update(source, check, str(dest_dir), fetch=fetch)

    assert load_local_version(str(dest_dir), source.name) == "1.0.0"


# ---------------------------------------------------------------------------
# check_and_update_all
# ---------------------------------------------------------------------------

def test_check_and_update_all_applies_only_the_source_that_needs_it(tmp_path):
    up_to_date = _github_source(local_version="1.2.0")
    up_to_date.name = "up-to-date-source"

    needs_update = _manifest_source(
        local_version="1.0.0", manifest_url="https://example.invalid/needs-update-manifest.json"
    )
    needs_update.name = "needs-update-source"

    fetch = _fake_fetch(
        {
            GITHUB_RELEASES_URL: _json_bytes({"tag_name": "v1.2.0", "assets": []}),
            needs_update.manifest_url: _json_bytes(
                {"version": "2.0.0", "download_url": "https://example.invalid/asset.bin"}
            ),
            "https://example.invalid/asset.bin": b"new-kb-bytes",
        }
    )
    dest_dir = tmp_path / "kb-state"

    results = check_and_update_all([up_to_date, needs_update], str(dest_dir), fetch=fetch)

    by_name = {r.source_name: r for r in results}
    assert set(by_name) == {"up-to-date-source", "needs-update-source"}

    assert by_name["up-to-date-source"].applied is False
    assert by_name["up-to-date-source"].new_version is None

    assert by_name["needs-update-source"].applied is True
    assert by_name["needs-update-source"].new_version == "2.0.0"
    assert load_local_version(str(dest_dir), "needs-update-source") == "2.0.0"

    # the already-up-to-date source must not have had anything written for it
    assert load_local_version(str(dest_dir), "up-to-date-source") == "0.0.0"


def test_check_and_update_all_with_failing_source_is_a_clean_noop(tmp_path):
    broken = _github_source(local_version="1.0.0")
    broken.name = "broken-source"

    def boom(url: str, timeout: int) -> bytes:
        raise OSError("unreachable")

    results = check_and_update_all([broken], str(tmp_path / "kb-state"), fetch=boom)

    assert len(results) == 1
    assert results[0].applied is False
    assert results[0].error is not None
