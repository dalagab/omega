"""Resolve stable public source-repository identities and Git ref hints from catalog metadata.

PluginMaster entries frequently omit ``RepoUrl`` even when their package URL points
at a GitHub release, raw file, tagged tree, or archive.  This module derives
canonical repository identities plus bounded provenance hints; it never fetches or
executes source code itself.
"""
from __future__ import annotations

import hashlib
from pathlib import PurePosixPath
import urllib.parse
from typing import Iterable


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


def public_repository_url(value: str) -> str:
    """Return a stable public HTTPS Git repository candidate from metadata.

    GitHub forms are canonicalised first. Other public Git hosts retain their
    host and repository path, allowing Sigmascope's constrained smart-Git
    fallback to handle GitLab, Gitea, Forgejo, Bitbucket, and self-hosted hosts.
    Artifact and manifest URLs are deliberately excluded for non-GitHub hosts.
    """
    github = github_repository_url(value)
    if github:
        return github
    try:
        parsed = urllib.parse.urlsplit(str(value or "").strip())
    except ValueError:
        return ""
    if parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username or parsed.password:
        return ""
    path = parsed.path.rstrip("/")
    parts = PurePosixPath(path).parts
    if len(parts) < 2 or path.lower().endswith((".zip", ".json", ".dll", ".exe", ".nupkg")):
        return ""
    if path.endswith(".git"):
        path = path[:-4]
    if not path or path.casefold().endswith(("/releases", "/issues", "/pulls", "/wiki")):
        return ""
    authority = parsed.hostname.lower() if parsed.port in {None, 443} else f"{parsed.hostname.lower()}:{parsed.port}"
    return urllib.parse.urlunsplit(("https", authority, path, "", ""))


def source_candidate_records(values: Iterable[tuple[str, str]]) -> list[dict[str, object]]:
    """Return deduplicated source candidates with discovery/ref provenance.

    ``values`` is an ordered sequence of ``(origin, url)`` pairs. Multiple pieces
    of metadata resolving to the same repository are intentionally merged so a
    RepoUrl and artifact URL agreeing on the same origin becomes explicit evidence.
    """
    records: list[dict[str, object]] = []
    by_repository: dict[str, dict[str, object]] = {}
    for origin, raw in values:
        raw = str(raw or "").strip()
        candidate = public_repository_url(raw)
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
        if isinstance(origins, list) and origin and origin not in origins:
            origins.append(origin)
        if isinstance(urls, list) and raw and raw not in urls:
            urls.append(raw)
        hint = github_ref_hint(raw)
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
