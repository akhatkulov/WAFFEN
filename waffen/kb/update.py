"""Versioned-KB auto-update mechanism (ROADMAP E1), nuclei-templates style.

The idea (borrowed from `nuclei-templates`' own updater): keep a small local
version stamp per KB "source", compare it against whatever that source's
remote says is latest, and if the remote is newer, download and install an
update into a local KB state directory. Nothing here is specific to WAF
payloads/signatures — it just moves bytes around and tracks a version string.

**Important — there is no real WAFFEN community-KB repository today.** This
module is the generic, pluggable *mechanism* only: a `KBSource` is a plain
description of "where to check" (a GitHub repo's releases, or a bare JSON
manifest URL) and "what we have locally". `default_sources()` therefore
returns an empty list — there is nothing to point at yet, and shipping a
fake/placeholder URL that `waffen kb update` would actually try to hit by
default would violate the "safe no-op until configured" goal. Once a real
community KB exists, a caller (e.g. the future `waffen kb update` CLI
command, or a user's own config) can build a `KBSource` pointing at it and
pass it in here.

Design notes:
  - stdlib only: HTTP via `urllib.request`, no third-party dependency.
  - All network access goes through an injectable `fetch(url, timeout) ->
    bytes` callable so tests never touch the real network.
  - Every public function here is designed to **never raise** on
    network/parsing failure — callers (eventually a CLI command) can just
    check `.error` and move on; a flaky/offline KB source should never crash
    a WAFFEN run.
  - `kb/seeds.py` (the static built-in payload dict) is untouched by this
    module today. The intent is that a future version of `kb/seeds.py` (or
    whatever replaces it) loads its data from the files this module installs
    under a KB state directory — but wiring that up is a separate step.
"""
from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Callable, Optional

#: Injectable network fetch: fetch(url, timeout_seconds) -> response body bytes.
#: Defaults to `_default_fetch` (real `urllib` call); tests pass a fake.
FetchFn = Callable[[str, int], bytes]

_ALLOWED_URL_SCHEMES = ("https", "http")


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class KBSource:
    """One updatable KB source.

    kind:
        "github_release" — latest version is the tag of
        `GET https://api.github.com/repos/<repo>/releases/latest`.
        "manifest" — latest version comes from a plain JSON file at
        `manifest_url` shaped like `{"version": "x.y.z", "download_url": "..."}`.
    repo:
        "owner/name", required (and only used) for kind="github_release".
    manifest_url:
        required (and only used) for kind="manifest".
    local_version:
        The version this source was last updated to. Callers normally fill
        this in from `load_local_version()` rather than hardcoding it.
    """
    name: str
    kind: str
    repo: str = ""
    manifest_url: str = ""
    local_version: str = "0.0.0"


@dataclass
class UpdateCheck:
    """Result of comparing a source's local vs. remote version."""
    source_name: str
    local_version: str
    remote_version: Optional[str] = None
    update_available: bool = False
    error: Optional[str] = None


@dataclass
class UpdateResult:
    """Result of attempting to install an update (or a deliberate no-op)."""
    source_name: str
    applied: bool
    new_version: Optional[str] = None
    dest_path: Optional[str] = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Version parsing / comparison
#
# Deliberately simple — "correct common-case ordering" per the module's
# scope, not a full semver implementation (no prerelease/build-metadata
# precedence rules, etc).
# ---------------------------------------------------------------------------

def _normalize_version(raw: str) -> str:
    v = str(raw).strip()
    if v[:1] in ("v", "V"):
        v = v[1:]
    return v


def _try_int(segment: str) -> Optional[int]:
    try:
        return int(segment)
    except ValueError:
        return None


def _compare_versions(a: str, b: str) -> int:
    """Return -1 / 0 / 1 for a<b / a==b / a>b.

    Strips a leading 'v', splits on '.', compares each dotted segment as an
    int when both sides parse as one, else falls back to a plain string
    compare for that segment. Missing trailing segments are treated as "0"
    (so "1.2" == "1.2.0").
    """
    segs_a = _normalize_version(a).split(".")
    segs_b = _normalize_version(b).split(".")
    for i in range(max(len(segs_a), len(segs_b))):
        sa = segs_a[i] if i < len(segs_a) else "0"
        sb = segs_b[i] if i < len(segs_b) else "0"
        ia, ib = _try_int(sa), _try_int(sb)
        if ia is not None and ib is not None:
            if ia != ib:
                return -1 if ia < ib else 1
            continue
        if sa != sb:
            return -1 if sa < sb else 1
    return 0


# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------

def _default_fetch(url: str, timeout: int = 10) -> bytes:
    """Real network fetch via stdlib `urllib` — the production default.

    Tests must always inject a fake `fetch` instead of exercising this.
    """
    scheme = urllib.parse.urlparse(url).scheme
    if scheme not in _ALLOWED_URL_SCHEMES:
        raise ValueError(f"refusing to fetch unsupported URL scheme: {scheme!r}")
    request = urllib.request.Request(url, headers={"User-Agent": "waffen-kb-updater"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def _github_releases_latest_url(repo: str) -> str:
    return f"https://api.github.com/repos/{repo}/releases/latest"


def _fetch_remote_version(source: KBSource, fetch: FetchFn, timeout: int) -> str:
    """Fetch + parse just the version string for `source`. Raises on failure
    (callers are expected to catch — see `check_for_update`)."""
    if source.kind == "github_release":
        if not source.repo:
            raise ValueError("KBSource.repo is required for kind='github_release'")
        raw = fetch(_github_releases_latest_url(source.repo), timeout)
        data = json.loads(raw)
        return _normalize_version(data["tag_name"])
    if source.kind == "manifest":
        if not source.manifest_url:
            raise ValueError("KBSource.manifest_url is required for kind='manifest'")
        raw = fetch(source.manifest_url, timeout)
        data = json.loads(raw)
        return _normalize_version(data["version"])
    raise ValueError(f"unknown KBSource.kind: {source.kind!r}")


def _resolve_download(source: KBSource, fetch: FetchFn, timeout: int) -> tuple[bytes, str]:
    """Fetch the actual update payload for `source`.

    Returns (content_bytes, filename_hint). Re-fetches the source's metadata
    JSON (release info / manifest) rather than reusing anything from a prior
    `check_for_update` call, since `UpdateCheck` deliberately stays a small,
    serializable summary rather than carrying raw API responses around.
    """
    if source.kind == "github_release":
        if not source.repo:
            raise ValueError("KBSource.repo is required for kind='github_release'")
        raw = fetch(_github_releases_latest_url(source.repo), timeout)
        data = json.loads(raw)
        assets = data.get("assets") or []
        if assets:
            first = assets[0]
            asset_url = first.get("browser_download_url") or first.get("url")
            name_hint = first.get("name") or asset_url or ""
        else:
            # No per-asset upload on the release — fall back to the
            # auto-generated source tarball, which GitHub always serves as
            # gzip regardless of the repo's actual content.
            asset_url = data.get("tarball_url")
            name_hint = "source.tar.gz"
        if not asset_url:
            raise ValueError("release has no downloadable asset or tarball_url")
        return fetch(asset_url, timeout), name_hint

    if source.kind == "manifest":
        if not source.manifest_url:
            raise ValueError("KBSource.manifest_url is required for kind='manifest'")
        raw = fetch(source.manifest_url, timeout)
        data = json.loads(raw)
        download_url = data.get("download_url")
        if not download_url:
            raise ValueError("manifest has no download_url")
        return fetch(download_url, timeout), download_url

    raise ValueError(f"unknown KBSource.kind: {source.kind!r}")


#: Compound extensions to keep intact (checked before the generic last-dot
#: rule, so "kb-payload.tar.gz" -> ".tar.gz", not ".gz").
_COMPOUND_EXTENSIONS = (".tar.gz", ".tar.bz2", ".tar.xz")


def _guess_extension(name_or_url: str) -> str:
    """Best-effort filename extension from an asset name/URL; '.bin' if we
    can't tell. We don't need to be clever, just produce a readable file.

    Uses the *last* dot (not the first) so version numbers embedded in a
    filename (e.g. "kb-2.0.0.json") don't get swallowed into the extension.
    """
    if not name_or_url:
        return ".bin"
    base = name_or_url.split("?", 1)[0].split("#", 1)[0].rsplit("/", 1)[-1]
    lower = base.lower()
    for compound in _COMPOUND_EXTENSIONS:
        if lower.endswith(compound):
            return base[-len(compound):]
    dot = base.rfind(".")
    if 0 < dot < len(base) - 1:
        return base[dot:]
    return ".bin"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_for_update(
    source: KBSource,
    *,
    fetch: Optional[FetchFn] = None,
    timeout: int = 10,
) -> UpdateCheck:
    """Compare `source.local_version` against its remote latest version.

    Never raises: any network/parsing/config error comes back as a
    `remote_version=None, update_available=False, error=<message>` result.
    """
    fetch = fetch or _default_fetch
    try:
        remote_version = _fetch_remote_version(source, fetch, timeout)
    except Exception as exc:  # noqa: BLE001 - deliberately broad, see docstring
        return UpdateCheck(
            source_name=source.name,
            local_version=source.local_version,
            remote_version=None,
            update_available=False,
            error=str(exc),
        )

    update_available = _compare_versions(source.local_version, remote_version) < 0
    return UpdateCheck(
        source_name=source.name,
        local_version=source.local_version,
        remote_version=remote_version,
        update_available=update_available,
        error=None,
    )


def apply_update(
    source: KBSource,
    check: UpdateCheck,
    dest_dir: str,
    *,
    fetch: Optional[FetchFn] = None,
    timeout: int = 10,
) -> UpdateResult:
    """Download and install the update described by `check`, if any.

    No-op (returns `applied=False` without touching the filesystem or the
    network) when `check.update_available` is False. Never raises — any
    failure during download/write comes back as an `UpdateResult` with
    `error` set.
    """
    if not check.update_available:
        return UpdateResult(source_name=source.name, applied=False)

    fetch = fetch or _default_fetch
    try:
        content, name_hint = _resolve_download(source, fetch, timeout)

        new_version = check.remote_version or source.local_version
        os.makedirs(dest_dir, exist_ok=True)

        dest_filename = f"{source.name}-{new_version}{_guess_extension(name_hint)}"
        dest_path = os.path.join(dest_dir, dest_filename)
        with open(dest_path, "wb") as fh:
            fh.write(content)

        _write_version_file(dest_dir, source.name, new_version)

        return UpdateResult(
            source_name=source.name,
            applied=True,
            new_version=new_version,
            dest_path=dest_path,
        )
    except Exception as exc:  # noqa: BLE001 - deliberately broad, see docstring
        return UpdateResult(source_name=source.name, applied=False, error=str(exc))


def _version_file_path(dest_dir: str, source_name: str) -> str:
    return os.path.join(dest_dir, f"{source_name}.version")


def _write_version_file(dest_dir: str, source_name: str, version: str) -> None:
    with open(_version_file_path(dest_dir, source_name), "w", encoding="utf-8") as fh:
        fh.write(version.strip() + "\n")


def load_local_version(dest_dir: str, source_name: str) -> str:
    """Read the locally-installed version for `source_name` from
    `<dest_dir>/<source_name>.version`, or "0.0.0" if it doesn't exist yet
    (never been installed) or can't be read."""
    try:
        with open(_version_file_path(dest_dir, source_name), "r", encoding="utf-8") as fh:
            text = fh.read().strip()
            return text or "0.0.0"
    except OSError:
        return "0.0.0"


def default_sources() -> list[KBSource]:
    """The default list of KB sources `waffen kb update` would check.

    Empty today: there is no real, public WAFFEN community-KB repository to
    point at, and shipping a fake default would make "no-op until
    configured" a lie. Once a real source exists, a caller builds a
    `KBSource` for it and passes that list in explicitly — this function is
    just a convenience, not a requirement.

    # EXAMPLE ONLY (not real, not returned, not active) — the shape a real
    # entry would take once a community KB repo exists:
    #
    #   KBSource(
    #       name="waffen-community-kb",
    #       kind="manifest",
    #       manifest_url="https://example.invalid/waffen-kb/manifest.json",
    #       local_version="0.0.0",
    #   )
    """
    return []


def check_and_update_all(
    sources: list[KBSource],
    dest_dir: str,
    *,
    fetch: Optional[FetchFn] = None,
    timeout: int = 10,
) -> list[UpdateResult]:
    """Check every source and apply whichever updates are available.

    Sources already up to date (or that failed their check) get a no-op
    `UpdateResult` (`applied=False`); the check's error, if any, is carried
    through so callers can still see *why* nothing happened.
    """
    results = []
    for source in sources:
        check = check_for_update(source, fetch=fetch, timeout=timeout)
        if not check.update_available:
            results.append(
                UpdateResult(source_name=source.name, applied=False, error=check.error)
            )
            continue
        results.append(apply_update(source, check, dest_dir, fetch=fetch, timeout=timeout))
    return results
