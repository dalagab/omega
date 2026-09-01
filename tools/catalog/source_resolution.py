"""Resolve and classify public source locations from catalog metadata.

PluginMaster entries frequently omit ``RepoUrl`` even when their package URL points
at a GitHub release, raw file, tagged tree, or archive. This module derives stable
repository identities where the URL structure actually supports that conclusion and
keeps manifests, artifacts, endpoints and ordinary websites as distinct locations.
It never fetches or executes source code itself.
"""
from __future__ import annotations

import hashlib
from pathlib import PurePosixPath
import urllib.parse
from typing import Iterable

KNOWN_FORGE_HOSTS = {
    "bitbucket.org",
    "codeberg.org",
    "git.sr.ht",
    "gitlab.com",
    "www.bitbucket.org",
    "www.codeberg.org",
    "www.gitlab.com",
}
ARTIFACT_SUFFIXES = (
    ".7z", ".dll", ".exe", ".gz", ".nupkg", ".rar", ".tar", ".tar.gz", ".tgz", ".xz", ".zip",
)
MANIFEST_SUFFIXES = (".json", ".json5", ".yaml", ".yml")
NON_REPOSITORY_PATH_MARKERS = {
    "api", "download", "downloads", "install", "installer", "package", "packages", "pluginmaster",
}


def github_repository_url(value: str) -> str:
    """Return a canonical public GitHub repository URL, or an empty string."""
    value = str(value or "").strip()
    if not value:
        return ""
    try:
        parsed = urllib.parse.urlparse(value)
    except ValueError:
        return ""
    host = (parsed.hostname or "").lower()
    parts = [part for part in parsed.path.split("/") if part]
    owner = repo = ""
    if host in {"github.com", "www.github.com", "codeload.github.com"} and len(parts) >= 2:
        owner, repo = parts[0], parts[1]
    elif host == "raw.githubusercontent.com" and len(parts) >= 3:
        owner, repo = parts[0], parts[1]
    elif host == "api.github.com" and len(parts) >= 3 and parts[0].lower() == "repos":
        owner, repo = parts[1], parts[2]
    if not owner or not repo:
        return ""
    repo = repo.removesuffix(".git")
    if not all(part and all(char.isalnum() or char in "-_." for char in part) for part in (owner, repo)):
        return ""
    return f"https://github.com/{owner}/{repo}"


def github_ref_hint(value: str) -> str:
    """Extract a bounded Git ref hint from common GitHub URLs.

    The hint is deliberately advisory. Sigmascope still resolves it through the
    GitHub commits API before reading source, and exact plugin-version tags are tried
    ahead of mutable branch hints.
    """
    value = str(value or "").strip()
    if not github_repository_url(value):
        return ""
    try:
        parsed = urllib.parse.urlparse(value)
    except ValueError:
        return ""
    host = (parsed.hostname or "").lower()
    parts = [urllib.parse.unquote(part) for part in parsed.path.split("/") if part]
    ref = ""
    if host in {"github.com", "www.github.com"} and len(parts) >= 4:
        marker = parts[2].casefold()
        if marker in {"tree", "blob", "raw"}:
            ref = parts[3]
        elif marker == "releases" and len(parts) >= 5 and parts[3].casefold() == "download":
            ref = parts[4]
    elif host == "raw.githubusercontent.com" and len(parts) >= 3:
        ref = parts[2]
    elif host == "codeload.github.com" and len(parts) >= 4 and parts[2].casefold() in {"zip", "tar.gz", "legacy.zip", "legacy.tar.gz"}:
        ref = parts[3]
    elif host == "api.github.com" and len(parts) >= 4 and parts[0].casefold() == "repos":
        query = urllib.parse.parse_qs(parsed.query)
        ref = str((query.get("ref") or [""])[0])
    if not ref:
        return ""
    ref = ref.strip()
    if len(ref) > 256 or any(ord(ch) < 32 for ch in ref):
        return ""
    return ref


def _safe_https(value: str) -> tuple[urllib.parse.SplitResult | None, str]:
    raw = str(value or "").strip()
    if not raw:
        return None, ""
    try:
        parsed = urllib.parse.urlsplit(raw)
    except ValueError:
        return None, raw
    if parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username or parsed.password:
        return None, raw
    return parsed, raw


def _generic_repository_url(parsed: urllib.parse.SplitResult, *, origin: str) -> str:
    path = parsed.path.rstrip("/")
    parts = [part for part in PurePosixPath(path).parts if part != "/"]
    if len(parts) < 2:
        return ""
    lower_path = path.casefold()
    lower_parts = {urllib.parse.unquote(part).casefold() for part in parts}
    if lower_path.endswith(MANIFEST_SUFFIXES + ARTIFACT_SUFFIXES):
        return ""
    if lower_parts & NON_REPOSITORY_PATH_MARKERS:
        return ""
    if lower_path.endswith(("/releases", "/issues", "/pulls", "/wiki")):
        return ""
    explicit_git = path.casefold().endswith(".git")
    host = (parsed.hostname or "").casefold()
    known_forge = host in KNOWN_FORGE_HOSTS or host.startswith("git.")
    explicit_metadata = str(origin or "").casefold() in {"repo-url", "catalog-source", "metadata"}
    if not (explicit_git or known_forge or explicit_metadata):
        return ""
    if explicit_git:
        path = path[:-4]
    authority = host if parsed.port in {None, 443} else f"{host}:{parsed.port}"
    return urllib.parse.urlunsplit(("https", authority, path, "", ""))


def classify_source_location(value: str, *, origin: str = "metadata") -> dict[str, str]:
    """Classify a catalog location without promoting ordinary endpoints to Git repos."""
    parsed, raw = _safe_https(value)
    result = {"url": raw, "kind": "unresolved", "repository": "", "refHint": ""}
    if not raw:
        return result
    github = github_repository_url(raw)
    if github:
        result.update({"kind": "repository", "repository": github, "refHint": github_ref_hint(raw)})
        return result
    if parsed is None:
        return result

    path = urllib.parse.unquote(parsed.path or "")
    lower_path = path.casefold()
    parts = [part.casefold() for part in path.split("/") if part]
    final = parts[-1] if parts else ""
    if lower_path.endswith(MANIFEST_SUFFIXES) or final in {"pluginmaster", "pluginmaster.json", "repo.json", "manifest.json"}:
        result["kind"] = "manifest"
        return result
    if lower_path.endswith(ARTIFACT_SUFFIXES):
        result["kind"] = "artifact"
        return result
    if set(parts) & NON_REPOSITORY_PATH_MARKERS:
        result["kind"] = "artifact" if str(origin or "").casefold().startswith("artifact-") else "endpoint"
        return result

    repository = _generic_repository_url(parsed, origin=origin)
    if repository:
        result.update({"kind": "repository", "repository": repository})
        return result

    if str(origin or "").casefold().startswith("artifact-"):
        result["kind"] = "artifact"
    elif path in {"", "/"}:
        result["kind"] = "website"
    else:
        result["kind"] = "endpoint"
    return result


def public_repository_url(value: str) -> str:
    """Return a stable public HTTPS Git repository candidate from explicit metadata."""
    return classify_source_location(value, origin="metadata")["repository"]


def source_location_records(values: Iterable[tuple[str, str]]) -> list[dict[str, object]]:
    """Return deduplicated location records while retaining non-repository evidence."""
    records: list[dict[str, object]] = []
    by_url: dict[str, dict[str, object]] = {}
    kind_rank = {"unresolved": 0, "website": 1, "endpoint": 2, "artifact": 3, "manifest": 4, "repository": 5}
    for origin, raw in values:
        raw = str(raw or "").strip()
        if not raw:
            continue
        classified = classify_source_location(raw, origin=origin)
        key = raw.casefold()
        record = by_url.get(key)
        if record is None:
            record = {
                "url": raw,
                "kind": classified["kind"],
                "repository": classified["repository"],
                "refHints": [classified["refHint"]] if classified["refHint"] else [],
                "origins": [origin] if origin else [],
            }
            by_url[key] = record
            records.append(record)
            continue
        origins = record.get("origins")
        if isinstance(origins, list) and origin and origin not in origins:
            origins.append(origin)
        hints = record.get("refHints")
        if isinstance(hints, list) and classified["refHint"] and classified["refHint"] not in hints:
            hints.append(classified["refHint"])
        if kind_rank.get(classified["kind"], 0) > kind_rank.get(str(record.get("kind") or ""), 0):
            record["kind"] = classified["kind"]
            record["repository"] = classified["repository"]
    return records


def source_candidate_records(values: Iterable[tuple[str, str]]) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    by_repository: dict[str, dict[str, object]] = {}
    for location in source_location_records(values):
        if location.get("kind") != "repository":
            continue
        candidate = str(location.get("repository") or "")
        if not candidate:
            continue
        key = candidate.casefold()
        record = by_repository.get(key)
        if record is None:
            record = {"repository": candidate, "origins": [], "refHints": [], "urls": []}
            by_repository[key] = record
            records.append(record)
        origins = record["origins"]
        urls = record["urls"]
        hints = record["refHints"]
        for origin in location.get("origins") or []:
            if isinstance(origins, list) and origin and origin not in origins:
                origins.append(origin)
        raw = str(location.get("url") or "")
        if isinstance(urls, list) and raw and raw not in urls:
            urls.append(raw)
        for hint in location.get("refHints") or []:
            if isinstance(hints, list) and hint and hint not in hints:
                hints.append(hint)
    return records


def source_candidates(*values: str) -> list[str]:
    """Return stable, deduplicated public HTTPS Git source candidates."""
    records = source_candidate_records(("metadata", value) for value in values)
    return [str(record["repository"]) for record in records]


def source_override_key(internal_name: str, catalog_source_url: str) -> str:
    """Return a stable key for a plugin/source pair across database rebuilds.

    Numeric SQLite variant IDs are deliberately not used because they are database
    implementation details and can change after a clean rebuild.  A source override
    applies to the plugin identity as published by one PluginMaster feed, regardless
    of the package version currently represented by that row.
    """
    identity = f"{str(internal_name or '').strip().lower()}\n{str(catalog_source_url or '').strip().lower()}"
    return "src-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]
