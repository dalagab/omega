"""Resolve stable public source-repository identities from catalog metadata.

PluginMaster entries frequently omit ``RepoUrl`` even when their package URL points
at a GitHub release, raw file, or archive.  This module only derives canonical
repository identities; it never fetches source code itself.
"""
from __future__ import annotations

import hashlib
from pathlib import PurePosixPath
import urllib.parse


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


def public_repository_url(value: str) -> str:
    """Return a stable public HTTPS Git repository candidate from metadata.

    GitHub forms are canonicalised first. Other public Git hosts retain their
    host and repository path, allowing the scanner's constrained smart-Git
    fallback to handle GitLab, Gitea, Forgejo, Bitbucket, and self-hosted hosts.
    Artifact and manifest URLs are deliberately excluded.
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


def source_candidates(*values: str) -> list[str]:
    """Return stable, deduplicated public HTTPS Git source candidates."""
    candidates: list[str] = []
    seen: set[str] = set()
    for value in values:
        candidate = public_repository_url(value)
        lowered = candidate.lower()
        if candidate and lowered not in seen:
            candidates.append(candidate)
            seen.add(lowered)
    return candidates


def source_override_key(internal_name: str, catalog_source_url: str) -> str:
    """Return a stable key for a plugin/source pair across database rebuilds.

    Numeric SQLite variant IDs are deliberately not used because they are database
    implementation details and can change after a clean rebuild.  A source override
    applies to the plugin identity as published by one PluginMaster feed, regardless
    of the package version currently represented by that row.
    """
    identity = f"{str(internal_name or '').strip().lower()}\n{str(catalog_source_url or '').strip().lower()}"
    return "src-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]
