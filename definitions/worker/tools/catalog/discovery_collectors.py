#!/usr/bin/env python3
"""Bounded collector implementations for the Omega Discovery component.

These collectors only produce candidate facts.  They never assign canonical IDs, publish Omega
client state, or create security findings.  Network collectors are optional/bounded and every
result retains the collector identity that produced it.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any, Callable
import urllib.parse
import urllib.request

GITHUB_API = "https://api.github.com"
BRAVE_SEARCH_API = "https://api.search.brave.com/res/v1/web/search"
USER_AGENT = "Omega-Discovery/1 (+https://github.com/dalagab/omega)"
MAX_PROJECT_LINKS = 4_000
MAX_REPOSITORIES_PER_RUN = 60
MAX_TREE_ENTRIES = 8_000
MAX_MANIFEST_CANDIDATES = 1_000
MAX_WEB_RESULTS = 120

COLLECTOR_GITHUB = "omega.collector.discovery.github-code-search"
COLLECTOR_PUNI = "omega.collector.discovery.puni-directory"
COLLECTOR_WEB = "omega.collector.discovery.web-search"
COLLECTOR_PROJECT = "omega.collector.discovery.project-page"
COLLECTOR_TREE = "omega.collector.discovery.repository-tree"
COLLECTOR_ISSUES = "omega.collector.discovery.issue-hints"
COLLECTOR_VALIDATOR = "omega.collector.discovery.pluginmaster-validator"

SEARCH_QUERIES = (
    '"DalamudApiLevel" filetype:json',
    '"TestingDalamudApiLevel" filetype:json',
    '"DownloadLinkInstall" "DalamudApiLevel"',
    '"InternalName" "DalamudApiLevel" filetype:json',
    'inurl:pluginmaster.json Dalamud',
    'inurl:repo.json "DalamudApiLevel"',
)

LIKELY_JSON_RE = re.compile(r"(?:^|/)(?:pluginmaster|repo|manifest|plugins?|plogons?|dalamud[^/]*)[^/]*\.json$", re.I)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return default


def _json_value(value: Any, default: Any) -> Any:
    if isinstance(value, type(default)):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, type(default)) else default
        except Exception:
            return default
    return default


def canonical_github_repo(url: str) -> str:
    try:
        parsed = urllib.parse.urlparse(str(url or "").strip())
    except ValueError:
        return ""
    if parsed.scheme.lower() != "https" or (parsed.hostname or "").lower() not in {"github.com", "www.github.com"}:
        return ""
    parts = [urllib.parse.unquote(item) for item in parsed.path.split("/") if item]
    if len(parts) < 2:
        return ""
    owner, repo = parts[0], parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", owner) or not re.fullmatch(r"[A-Za-z0-9_.-]+", repo):
        return ""
    return f"https://github.com/{owner}/{repo}"


def likely_json_url(url: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(str(url or ""))
    except ValueError:
        return False
    return parsed.scheme.lower() == "https" and bool(parsed.hostname) and (
        parsed.path.lower().endswith(".json") and (
            bool(LIKELY_JSON_RE.search(parsed.path))
            or "dalamud" in parsed.path.lower()
            or "plugin" in parsed.path.lower()
            or "repo" in parsed.path.lower()
        )
    )


def _candidate(url: str, collector_id: str, *, discovered_by: str, provider: str = "", source_repo_url: str = "", provenance: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "url": str(url), "provider": provider or urllib.parse.urlparse(str(url)).netloc,
        "kind": "discovered", "discoveredBy": discovered_by,
        "sourceRepoUrl": source_repo_url, "collectorId": collector_id,
        "provenance": dict(provenance or {}),
    }


def _repository_record(repository_url: str, collector_id: str, *, reason: str, source_url: str = "") -> dict[str, Any]:
    canonical = canonical_github_repo(repository_url)
    if not canonical:
        return {}
    parts = canonical.rstrip("/").split("/")
    return {
        "repositoryUrl": canonical, "owner": parts[-2], "repository": parts[-1],
        "reason": reason, "sourceUrl": source_url, "collectorId": collector_id,
    }


def project_page_candidates(catalog_root: Path) -> dict[str, Any]:
    """Reuse already-scraped project/README metadata as discovery seeds without network I/O."""
    index = _read_json(catalog_root / "websites" / "index.json", {}) or {}
    sources: list[dict[str, Any]] = []
    links: list[dict[str, Any]] = []
    repositories: dict[str, dict[str, Any]] = {}
    seen_source: set[str] = set()
    for item in index.get("websites") or []:
        if not isinstance(item, dict) or not item.get("ok"):
            continue
        rel = str(item.get("path") or "")
        payload = _read_json(catalog_root / rel, {}) if rel else {}
        website = payload.get("website") if isinstance(payload, dict) and isinstance(payload.get("website"), dict) else {}
        project_url = str(website.get("url") or item.get("url") or "").strip()
        metadata = _json_value(website.get("metadata_json"), {})
        raw_links = _json_value(metadata.get("rawLinks"), [])
        classified = _json_value(website.get("links_json"), [])
        homepage = str(website.get("homepage") or "").strip()
        candidates: list[tuple[str, str]] = []
        for raw in raw_links:
            if isinstance(raw, str): candidates.append((raw, "raw-project-link"))
        for row in classified:
            if isinstance(row, dict) and str(row.get("url") or ""):
                candidates.append((str(row["url"]), str(row.get("kind") or "classified-project-link")))
        if homepage:
            candidates.append((homepage, "homepage"))
        own_repo = canonical_github_repo(project_url)
        if own_repo:
            repositories.setdefault(own_repo.casefold(), _repository_record(own_repo, COLLECTOR_PROJECT, reason="known-project-repository", source_url=project_url))
        for url, source in candidates:
            if len(links) >= MAX_PROJECT_LINKS:
                break
            if not str(url).startswith("https://"):
                continue
            repo = canonical_github_repo(url)
            candidate_kind = "repository" if repo else ("json" if likely_json_url(url) else "link")
            links.append({
                "projectUrl": project_url, "url": url, "linkKind": source,
                "source": "canonical-project-enrichment", "candidateKind": candidate_kind,
                "collectorId": COLLECTOR_PROJECT,
            })
            if repo:
                repositories.setdefault(repo.casefold(), _repository_record(repo, COLLECTOR_PROJECT, reason="linked-from-project-page", source_url=project_url))
            if likely_json_url(url):
                key = url.rstrip("/").casefold()
                if key not in seen_source:
                    seen_source.add(key)
                    sources.append(_candidate(url, COLLECTOR_PROJECT, discovered_by="project-page-link", source_repo_url=repo or own_repo, provenance={"projectUrl": project_url, "linkKind": source}))
    return {"sources": sources, "projectLinks": links, "repositoryCandidates": [row for row in repositories.values() if row]}


def issue_candidates(issue_hints: dict[str, Any]) -> dict[str, Any]:
    sources: list[dict[str, Any]] = []
    repositories: dict[str, dict[str, Any]] = {}
    for issue in issue_hints.get("issues") or []:
        if not isinstance(issue, dict):
            continue
        number = int(issue.get("number") or 0)
        for url in issue.get("urls") or []:
            url = str(url or "")
            repo = canonical_github_repo(url)
            if repo:
                repositories.setdefault(repo.casefold(), _repository_record(repo, COLLECTOR_ISSUES, reason=f"omega-issue-{number}", source_url=str(issue.get("htmlUrl") or "")))
            if likely_json_url(url):
                sources.append(_candidate(url, COLLECTOR_ISSUES, discovered_by="omega-issue-hint", source_repo_url=repo, provenance={"issue": number, "htmlUrl": str(issue.get("htmlUrl") or "")}))
    return {"sources": sources, "repositoryCandidates": [row for row in repositories.values() if row]}


def _github_json(url: str, token: str, timeout: float = 15.0) -> Any:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": USER_AGENT}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def _rotating_repository_slice(repositories: list[dict[str, Any]], now: datetime | None = None) -> list[dict[str, Any]]:
    rows = sorted((row for row in repositories if row.get("repositoryUrl")), key=lambda x: str(x["repositoryUrl"]).casefold())
    if len(rows) <= MAX_REPOSITORIES_PER_RUN:
        return rows
    instant = now or datetime.now(timezone.utc)
    slot = int(instant.timestamp() // (6 * 3600))
    start = (slot * MAX_REPOSITORIES_PER_RUN) % len(rows)
    return [rows[(start + i) % len(rows)] for i in range(MAX_REPOSITORIES_PER_RUN)]


def repository_tree_candidates(repositories: list[dict[str, Any]], token: str, *, github_json: Callable[[str, str, float], Any] = _github_json, now: datetime | None = None) -> dict[str, Any]:
    sources: list[dict[str, Any]] = []
    manifests: list[dict[str, Any]] = []
    inspected = 0
    errors = 0
    for repository in _rotating_repository_slice(repositories, now):
        repo_url = canonical_github_repo(str(repository.get("repositoryUrl") or ""))
        if not repo_url:
            continue
        owner, repo = repo_url.rstrip("/").split("/")[-2:]
        inspected += 1
        try:
            metadata = github_json(f"{GITHUB_API}/repos/{owner}/{repo}", token, 15.0)
            branch = str(metadata.get("default_branch") or "main") if isinstance(metadata, dict) else "main"
            tree = github_json(f"{GITHUB_API}/repos/{owner}/{repo}/git/trees/{urllib.parse.quote(branch, safe='')}?recursive=1", token, 15.0)
            entries = tree.get("tree") if isinstance(tree, dict) and isinstance(tree.get("tree"), list) else []
        except Exception:
            errors += 1
            continue
        file_count = 0
        for entry in entries[:MAX_TREE_ENTRIES]:
            if not isinstance(entry, dict) or entry.get("type") != "blob":
                continue
            path = str(entry.get("path") or "")
            if not path.lower().endswith(".json") or not LIKELY_JSON_RE.search(path):
                continue
            raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{urllib.parse.quote(branch, safe='')}/{urllib.parse.quote(path, safe='/._-')}"
            file_count += 1
            manifests.append({
                "url": raw_url, "repositoryUrl": repo_url, "path": path,
                "reason": "likely-dalamud-json-filename", "originCollectorId": COLLECTOR_TREE,
                "collectorId": COLLECTOR_TREE,
            })
            sources.append(_candidate(raw_url, COLLECTOR_TREE, discovered_by="repository-tree", provider=f"{owner}/{repo}", source_repo_url=repo_url, provenance={"path": path, "branch": branch}))
            if len(sources) >= MAX_MANIFEST_CANDIDATES:
                break
        repository["candidateFileCount"] = file_count
        if len(sources) >= MAX_MANIFEST_CANDIDATES:
            break
    return {"sources": sources, "manifestCandidates": manifests, "repositoriesInspected": inspected, "repositoryErrors": errors}


def _brave_json(query: str, api_key: str, timeout: float = 15.0) -> Any:
    params = urllib.parse.urlencode({"q": query, "count": 20, "safesearch": "moderate", "search_lang": "en"})
    req = urllib.request.Request(
        f"{BRAVE_SEARCH_API}?{params}",
        headers={"Accept": "application/json", "X-Subscription-Token": api_key, "User-Agent": USER_AGENT},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def web_search_candidates(api_key: str, *, searcher: Callable[[str, str, float], Any] = _brave_json) -> dict[str, Any]:
    if not api_key:
        return {"enabled": False, "queries": 0, "results": 0, "sources": [], "repositoryCandidates": [], "manifestCandidates": []}
    sources: list[dict[str, Any]] = []
    repositories: dict[str, dict[str, Any]] = {}
    manifests: list[dict[str, Any]] = []
    seen: set[str] = set()
    result_count = 0
    for query in SEARCH_QUERIES:
        try:
            doc = searcher(query, api_key, 15.0)
        except Exception:
            continue
        rows = ((doc.get("web") or {}).get("results") if isinstance(doc, dict) else []) or []
        for row in rows:
            if not isinstance(row, dict):
                continue
            url = str(row.get("url") or "").strip()
            key = url.rstrip("/").casefold()
            if not url.startswith("https://") or not key or key in seen:
                continue
            seen.add(key); result_count += 1
            repo = canonical_github_repo(url)
            if repo:
                repositories.setdefault(repo.casefold(), _repository_record(repo, COLLECTOR_WEB, reason="web-search-result", source_url=url))
            if likely_json_url(url):
                sources.append(_candidate(url, COLLECTOR_WEB, discovered_by="web-search", source_repo_url=repo, provenance={"query": query, "title": str(row.get("title") or "")[:300]}))
                manifests.append({"url": url, "repositoryUrl": repo, "path": urllib.parse.urlparse(url).path, "reason": "web-search-result", "originCollectorId": COLLECTOR_WEB, "collectorId": COLLECTOR_WEB})
            if result_count >= MAX_WEB_RESULTS:
                break
        if result_count >= MAX_WEB_RESULTS:
            break
    return {"enabled": True, "queries": len(SEARCH_QUERIES), "results": result_count, "sources": sources, "repositoryCandidates": [row for row in repositories.values() if row], "manifestCandidates": manifests}


def dedupe_sources(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        url = str(row.get("url") or "").rstrip("/")
        key = url.casefold()
        if not url or key in seen:
            continue
        seen.add(key); result.append(row)
    return result
