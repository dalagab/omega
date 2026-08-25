#!/usr/bin/env python3
"""Independent, read-mostly discovery of new Dalamud JSON sources and plugin facts.

This job is deliberately outside the canonical catalog/SigmaScope pipeline.  It may discover and
validate public facts, but it never assigns plugin/source IDs, freezes Definitions, requests scans,
or publishes client data.  The daily catalog builder is the only authority that consumes accepted
facts into the canonical catalog identity model.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import sys
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

import enrich_metadata
import discovery_collectors

SECURITY_DIR = Path(__file__).resolve().parents[1] / "security"
if str(SECURITY_DIR) not in sys.path:
    sys.path.insert(0, str(SECURITY_DIR))
import collector_contracts  # noqa: E402
import component_registry  # noqa: E402

SCHEMA = "omega.catalog-discovery.v1"
SOURCE_SCHEMA = "omega.catalog-discovery.sources.v1"
PLUGIN_FACT_SCHEMA = "omega.catalog-discovery.plugin-facts.v1"
ISSUE_SCHEMA = "omega.catalog-discovery.issue-hints.v1"
MAX_SOURCE_PLUGINS = 5_000
MAX_ISSUES = 200
URL_RE = re.compile(r"https://[^\s<>()\[\]{}]+", re.IGNORECASE)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalize_url(value: str) -> str:
    return str(value or "").strip().rstrip("/")


def public_https_url(url: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(url)
        host = (parsed.hostname or "").lower()
        port = parsed.port or 443
    except ValueError:
        return False
    if parsed.scheme != "https" or not host or parsed.username or parsed.password:
        return False
    if host == "localhost" or host.endswith((".localhost", ".local")):
        return False
    try:
        addresses = {item[4][0].split("%", 1)[0] for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)}
    except (socket.gaierror, OSError):
        return False
    if not addresses:
        return False
    try:
        return all(ipaddress.ip_address(address).is_global for address in addresses)
    except ValueError:
        return False


def read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return default


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def catalog_source_index(catalog_root: Path) -> tuple[set[str], dict[int, str]]:
    payload = read_json(catalog_root / "sources" / "index.json", {}) or {}
    urls: set[str] = set()
    by_id: dict[int, str] = {}
    for row in payload.get("sources") or []:
        if not isinstance(row, dict):
            continue
        url = normalize_url(row.get("url"))
        source_id = int(row.get("sourceId") or 0)
        if url:
            urls.add(url.casefold())
        if source_id > 0 and url:
            by_id[source_id] = url
    return urls, by_id


def catalog_plugin_index(catalog_root: Path) -> dict[str, str]:
    payload = read_json(catalog_root / "plugins" / "index.json", {}) or {}
    result: dict[str, str] = {}
    for row in payload.get("plugins") or []:
        if not isinstance(row, dict):
            continue
        internal = str(row.get("internalName") or "").strip()
        path = str(row.get("path") or "").strip()
        if internal and path:
            result[internal.casefold()] = path
    return result


def _known_variant_facts(
    catalog_root: Path,
    plugin_path: str,
    source_urls: dict[int, str],
) -> set[tuple[str, str]]:
    payload = read_json(catalog_root / plugin_path, {}) or {}
    facts: set[tuple[str, str]] = set()
    for grouped in payload.get("variants") or []:
        if not isinstance(grouped, dict):
            continue
        variant = grouped.get("variant") if isinstance(grouped.get("variant"), dict) else {}
        source_id = int(variant.get("source_id") or 0)
        source_url = normalize_url(source_urls.get(source_id, "")).casefold()
        version = str(variant.get("assembly_version") or "").strip().casefold()
        if source_url:
            facts.add((source_url, version))
    return facts


def extract_urls(text: str) -> list[str]:
    result: list[str] = []
    for raw in URL_RE.findall(str(text or "")):
        url = raw.rstrip(".,;:!?)]}")
        if url.startswith("https://") and url not in result:
            result.append(url)
    return result


def _github_json(url: str, token: str, timeout: float = 15.0) -> Any:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "Omega-Catalog-Discovery/1"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def collect_issue_hints(repository: str, token: str) -> dict[str, Any]:
    if not repository:
        return {"schema": ISSUE_SCHEMA, "issues": [], "trackedUrls": []}
    issues: list[dict[str, Any]] = []
    tracked: set[str] = set()
    page = 1
    while len(issues) < MAX_ISSUES:
        api = f"https://api.github.com/repos/{repository}/issues?state=open&per_page=100&page={page}"
        try:
            rows = _github_json(api, token)
        except Exception:
            break
        if not isinstance(rows, list) or not rows:
            break
        for issue in rows:
            if not isinstance(issue, dict) or issue.get("pull_request"):
                continue
            title = str(issue.get("title") or "")
            body = str(issue.get("body") or "")
            labels = [
                str(item.get("name") or "") if isinstance(item, dict) else str(item or "")
                for item in issue.get("labels") or []
            ]
            relevant = (
                "omega-source-submission" in body
                or "omega-source-followup:" in body
                or title.casefold().startswith("source submission:")
                or any(label.casefold() == "omega-source-followup" for label in labels)
            )
            if not relevant:
                continue
            urls = extract_urls(body)
            comments_url = str(issue.get("comments_url") or "")
            if comments_url and int(issue.get("comments") or 0) > 0:
                try:
                    comments = _github_json(comments_url + "?per_page=100", token)
                    for comment in comments if isinstance(comments, list) else []:
                        if isinstance(comment, dict):
                            urls.extend(extract_urls(str(comment.get("body") or "")))
                except Exception:
                    pass
            deduped: list[str] = []
            for url in urls:
                key = normalize_url(url).casefold()
                if key and key not in {normalize_url(item).casefold() for item in deduped}:
                    deduped.append(url)
                    tracked.add(key)
            issues.append({
                "number": int(issue.get("number") or 0),
                "title": title,
                "labels": labels,
                "urls": deduped,
                "htmlUrl": str(issue.get("html_url") or ""),
            })
            if len(issues) >= MAX_ISSUES:
                break
        if len(rows) < 100:
            break
        page += 1
    return {"schema": ISSUE_SCHEMA, "issues": issues, "trackedUrls": sorted(tracked)}


def _origin_collector(source: dict[str, Any]) -> str:
    explicit = str(source.get("collectorId") or "").strip()
    if explicit in collector_contracts.collector_map():
        return explicit
    discovered = str(source.get("discoveredBy") or "").casefold()
    if "github" in discovered:
        return discovery_collectors.COLLECTOR_GITHUB
    if "puni" in discovered:
        return discovery_collectors.COLLECTOR_PUNI
    if "community" in discovered:
        return "omega.collector.discovery.community-registry"
    if "curated" in discovered or "catalog-data" in discovered:
        return "omega.collector.discovery.curated-registry"
    return discovery_collectors.COLLECTOR_PROJECT


def _dedupe_repository_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        url = str(row.get("repositoryUrl") or "").rstrip("/")
        key = url.casefold()
        if not url or key in seen:
            continue
        seen.add(key); result.append(row)
    return result


def _dedupe_manifest_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        url = str(row.get("url") or "").rstrip("/")
        key = url.casefold()
        if not url or key in seen:
            continue
        seen.add(key); result.append(row)
    return result


def discover(
    candidates: dict[str, Any],
    catalog_root: Path,
    *,
    repository: str = "",
    token: str = "",
    web_search_api_key: str = "",
    fetcher=enrich_metadata.fetch_source,
    issue_hints: dict[str, Any] | None = None,
    collect_additional: bool = True,
) -> dict[str, Any]:
    known_sources, source_urls = catalog_source_index(catalog_root)
    plugin_index = catalog_plugin_index(catalog_root)
    issues = issue_hints if issue_hints is not None else collect_issue_hints(repository, token)
    tracked_urls = {normalize_url(item).casefold() for item in issues.get("trackedUrls") or []}

    # Discovery is a graph of bounded collectors. Existing PluginMaster discovery remains the
    # first input; canonical project pages, issue hints, optional web search and rotating GitHub
    # repository-tree inspection add candidates without acquiring catalog authority.
    base_sources = [dict(row) for row in candidates.get("sources") or [] if isinstance(row, dict)]
    project = {"sources": [], "projectLinks": [], "repositoryCandidates": []}
    issue_graph = {"sources": [], "repositoryCandidates": []}
    web = {"enabled": False, "queries": 0, "results": 0, "sources": [], "repositoryCandidates": [], "manifestCandidates": []}
    tree = {"sources": [], "manifestCandidates": [], "repositoriesInspected": 0, "repositoryErrors": 0}
    if collect_additional:
        project = discovery_collectors.project_page_candidates(catalog_root)
        issue_graph = discovery_collectors.issue_candidates(issues)
        web = discovery_collectors.web_search_candidates(web_search_api_key)
        repositories = _dedupe_repository_rows(
            list(project.get("repositoryCandidates") or [])
            + list(issue_graph.get("repositoryCandidates") or [])
            + list(web.get("repositoryCandidates") or [])
        )
        if token and repositories:
            tree = discovery_collectors.repository_tree_candidates(repositories, token)
    else:
        repositories = []

    all_sources = discovery_collectors.dedupe_sources(
        base_sources
        + list(project.get("sources") or [])
        + list(issue_graph.get("sources") or [])
        + list(web.get("sources") or [])
        + list(tree.get("sources") or [])
    )
    manifest_candidates: list[dict[str, Any]] = []
    for source in base_sources:
        url = str(source.get("url") or "")
        if not url:
            continue
        manifest_candidates.append({
            "url": url, "repositoryUrl": str(source.get("sourceRepoUrl") or ""),
            "path": urllib.parse.urlparse(url).path, "reason": str(source.get("discoveredBy") or "source-discovery"),
            "originCollectorId": _origin_collector(source), "collectorId": _origin_collector(source),
        })
    manifest_candidates.extend(web.get("manifestCandidates") or [])
    manifest_candidates.extend(tree.get("manifestCandidates") or [])
    for row in project.get("sources") or []:
        manifest_candidates.append({
            "url": str(row.get("url") or ""), "repositoryUrl": str(row.get("sourceRepoUrl") or ""),
            "path": urllib.parse.urlparse(str(row.get("url") or "")).path, "reason": "project-page-link",
            "originCollectorId": discovery_collectors.COLLECTOR_PROJECT, "collectorId": discovery_collectors.COLLECTOR_PROJECT,
        })
    for row in issue_graph.get("sources") or []:
        manifest_candidates.append({
            "url": str(row.get("url") or ""), "repositoryUrl": str(row.get("sourceRepoUrl") or ""),
            "path": urllib.parse.urlparse(str(row.get("url") or "")).path, "reason": "omega-issue-hint",
            "originCollectorId": discovery_collectors.COLLECTOR_ISSUES, "collectorId": discovery_collectors.COLLECTOR_ISSUES,
        })
    manifest_candidates = _dedupe_manifest_rows(manifest_candidates)

    validated: list[dict[str, Any]] = []
    enriched_sources: list[dict[str, Any]] = []
    plugin_facts: list[dict[str, Any]] = []
    skipped_known: list[str] = []
    invalid: list[dict[str, Any]] = []
    variant_cache: dict[str, set[tuple[str, str]]] = {}

    seen: set[str] = set()
    for source in all_sources:
        url = normalize_url(source.get("url"))
        key = url.casefold()
        if not url or key in seen:
            continue
        seen.add(key)
        if key in known_sources:
            skipped_known.append(url)
            continue
        if not public_https_url(url):
            invalid.append({"url": url, "reason": "url-policy", "originCollectorId": _origin_collector(source)})
            continue
        result = fetcher(source, timeout=15.0, max_bytes=16 * 1024 * 1024, url_validator=public_https_url)
        count = int(result.get("pluginCount") or 0)
        if not result.get("ok") or count <= 0 or count > MAX_SOURCE_PLUGINS:
            invalid.append({"url": url, "reason": str(result.get("error") or "invalid-pluginmaster")[:300], "pluginCount": count, "originCollectorId": _origin_collector(source)})
            continue

        origin_collector = _origin_collector(source)
        new_plugins = 0
        new_variants = 0
        already_known_facts = 0
        for plugin in result.get("plugins") or []:
            if not isinstance(plugin, dict):
                continue
            internal = str(plugin.get("internalName") or "").strip()
            if not internal:
                continue
            version = str(plugin.get("assemblyVersion") or "").strip()
            plugin_path = plugin_index.get(internal.casefold())
            if not plugin_path:
                classification = "new-plugin"
                new_plugins += 1
            else:
                if plugin_path not in variant_cache:
                    variant_cache[plugin_path] = _known_variant_facts(catalog_root, plugin_path, source_urls)
                if (key, version.casefold()) in variant_cache[plugin_path]:
                    classification = "already-known-fact"
                    already_known_facts += 1
                else:
                    classification = "new-source-variant"
                    new_variants += 1
            if classification != "already-known-fact":
                plugin_facts.append({
                    "classification": classification,
                    "internalName": internal,
                    "name": str(plugin.get("name") or internal),
                    "assemblyVersion": version,
                    "testingAssemblyVersion": str(plugin.get("testingAssemblyVersion") or ""),
                    "dalamudApiLevel": plugin.get("dalamudApiLevel"),
                    "testingDalamudApiLevel": plugin.get("testingDalamudApiLevel"),
                    "sourceUrl": url,
                    "sourceProvider": str(result.get("provider") or source.get("provider") or ""),
                    "repoUrl": str(plugin.get("repoUrl") or ""),
                    "originCollectorId": origin_collector,
                })

        enriched_path = f"enriched/{hashlib.sha256(url.encode('utf-8')).hexdigest()[:24]}.json"
        enriched_sources.append({"path": enriched_path, "source": result})
        validated.append({
            "url": url,
            "provider": str(result.get("provider") or source.get("provider") or ""),
            "kind": str(result.get("kind") or source.get("kind") or "discovered"),
            "discoveredBy": str(result.get("discoveredBy") or source.get("discoveredBy") or ""),
            "sourceRepoUrl": str(result.get("sourceRepoUrl") or source.get("sourceRepoUrl") or ""),
            "resolvedUrl": str(result.get("resolvedUrl") or ""),
            "contentSha256": str(result.get("contentSha256") or ""),
            "etag": str(result.get("etag") or ""),
            "lastModified": str(result.get("lastModified") or ""),
            "pluginCount": count,
            "newPluginFacts": new_plugins,
            "newVariantFacts": new_variants,
            "alreadyKnownFacts": already_known_facts,
            "trackedByOpenIssue": key in tracked_urls,
            "enrichedPath": enriched_path,
            "originCollectorId": origin_collector,
            "validationCollectorId": discovery_collectors.COLLECTOR_VALIDATOR,
        })

    generated = utc_now()
    return {
        "generatedAtUtc": generated,
        "knownSourceCount": len(known_sources),
        "candidateSourceCount": len(seen),
        "knownSourcesSkipped": len(skipped_known),
        "validatedNovelSources": len(validated),
        "invalidNovelSources": len(invalid),
        "newPluginFacts": sum(1 for row in plugin_facts if row["classification"] == "new-plugin"),
        "newVariantFacts": sum(1 for row in plugin_facts if row["classification"] == "new-source-variant"),
        "projectLinksObserved": len(project.get("projectLinks") or []),
        "repositoryCandidates": len(repositories),
        "repositoryTreesInspected": int(tree.get("repositoriesInspected") or 0),
        "repositoryTreeErrors": int(tree.get("repositoryErrors") or 0),
        "webSearchEnabled": bool(web.get("enabled")),
        "webSearchQueries": int(web.get("queries") or 0),
        "webSearchResults": int(web.get("results") or 0),
        "sources": validated,
        "enrichedSources": enriched_sources,
        "pluginFacts": plugin_facts,
        "issues": issues,
        "projectLinks": list(project.get("projectLinks") or []),
        "repositoryCandidateRows": repositories,
        "manifestCandidates": manifest_candidates,
        "skippedKnownSourceUrls": skipped_known,
        "invalidSources": invalid,
    }


def build_observation_bundle(result: dict[str, Any]) -> dict[str, Any]:
    observed_at = str(result.get("generatedAtUtc") or utc_now())
    rows: dict[str, list[dict[str, Any]]] = {
        "catalogSourceCandidates": [], "catalogPluginFacts": [], "catalogProjectLinks": [],
        "catalogRepositoryCandidates": [], "catalogManifestCandidates": [], "catalogIssueHints": [],
    }
    for item in result.get("sources") or []:
        if not isinstance(item, dict):
            continue
        rows["catalogSourceCandidates"].append(collector_contracts.make_row(
            "catalogSourceCandidates", discovery_collectors.COLLECTOR_VALIDATOR, {
                "url": str(item.get("url") or ""), "provider": str(item.get("provider") or ""),
                "kind": str(item.get("kind") or ""), "status": "validated-novel",
                "pluginCount": int(item.get("pluginCount") or 0), "contentSha256": str(item.get("contentSha256") or ""),
                "trackedByOpenIssue": bool(item.get("trackedByOpenIssue")), "discoveredBy": str(item.get("discoveredBy") or ""),
                "sourceRepoUrl": str(item.get("sourceRepoUrl") or ""), "originCollectorId": str(item.get("originCollectorId") or ""),
            }, observed_at=observed_at, provenance={"originCollectorId": str(item.get("originCollectorId") or ""), "enrichedPath": str(item.get("enrichedPath") or "")}
        ))
    for item in result.get("pluginFacts") or []:
        if isinstance(item, dict):
            rows["catalogPluginFacts"].append(collector_contracts.make_row(
                "catalogPluginFacts", discovery_collectors.COLLECTOR_VALIDATOR, dict(item), observed_at=observed_at,
                provenance={"sourceUrl": str(item.get("sourceUrl") or ""), "originCollectorId": str(item.get("originCollectorId") or "")}
            ))
    for item in result.get("projectLinks") or []:
        if isinstance(item, dict):
            values = {key: value for key, value in item.items() if key != "collectorId"}
            rows["catalogProjectLinks"].append(collector_contracts.make_row(
                "catalogProjectLinks", discovery_collectors.COLLECTOR_PROJECT, values, observed_at=observed_at,
                provenance={"projectUrl": str(item.get("projectUrl") or "")}
            ))
    for item in result.get("repositoryCandidateRows") or []:
        if not isinstance(item, dict):
            continue
        collector_id = str(item.get("collectorId") or discovery_collectors.COLLECTOR_PROJECT)
        values = {key: value for key, value in item.items() if key != "collectorId"}
        rows["catalogRepositoryCandidates"].append(collector_contracts.make_row(
            "catalogRepositoryCandidates", collector_id, values, observed_at=observed_at, provenance={"reason": str(item.get("reason") or "")}
        ))
    for item in result.get("manifestCandidates") or []:
        if not isinstance(item, dict):
            continue
        collector_id = str(item.get("collectorId") or item.get("originCollectorId") or discovery_collectors.COLLECTOR_PROJECT)
        if collector_id not in collector_contracts.providers_for("catalogManifestCandidates"):
            collector_id = discovery_collectors.COLLECTOR_PROJECT
        values = {key: value for key, value in item.items() if key != "collectorId"}
        rows["catalogManifestCandidates"].append(collector_contracts.make_row(
            "catalogManifestCandidates", collector_id, values, observed_at=observed_at, provenance={"reason": str(item.get("reason") or "")}
        ))
    for item in result.get("issues", {}).get("issues") or []:
        if isinstance(item, dict):
            rows["catalogIssueHints"].append(collector_contracts.make_row(
                "catalogIssueHints", discovery_collectors.COLLECTOR_ISSUES, dict(item), observed_at=observed_at,
                provenance={"htmlUrl": str(item.get("htmlUrl") or "")}
            ))
    return collector_contracts.build_bundle(rows, generated_at=observed_at)


def write_snapshot(result: dict[str, Any], output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    for item in result.get("enrichedSources") or []:
        if not isinstance(item, dict):
            continue
        rel = str(item.get("path") or "")
        source = item.get("source") if isinstance(item.get("source"), dict) else {}
        if rel and source:
            write_json(output / rel, {
                "schema": "omega.catalog-discovery.enriched-source.v1",
                "generatedAtUtc": result["generatedAtUtc"],
                "source": source,
            })
    sources_doc = {
        "schema": SOURCE_SCHEMA,
        "generatedAtUtc": result["generatedAtUtc"],
        "sources": result["sources"],
    }
    facts_doc = {
        "schema": PLUGIN_FACT_SCHEMA,
        "generatedAtUtc": result["generatedAtUtc"],
        "facts": result["pluginFacts"],
    }
    write_json(output / "source-candidates.json", sources_doc)
    write_json(output / "plugin-facts.json", facts_doc)
    write_json(output / "issues.json", result["issues"])
    observation_bundle = build_observation_bundle(result)
    write_json(output / "observations.json", observation_bundle)
    write_json(output / "collector-registry.json", collector_contracts.build_registry())
    write_json(output / "component-registry.json", component_registry.build_registry())
    index = {
        "schema": SCHEMA,
        "generatedAtUtc": result["generatedAtUtc"],
        "counts": {
            key: int(result.get(key) or 0)
            for key in (
                "knownSourceCount", "candidateSourceCount", "knownSourcesSkipped",
                "validatedNovelSources", "invalidNovelSources", "newPluginFacts", "newVariantFacts",
                "projectLinksObserved", "repositoryCandidates", "repositoryTreesInspected",
                "repositoryTreeErrors", "webSearchQueries", "webSearchResults",
            )
        },
        "files": {
            "sources": "source-candidates.json",
            "pluginFacts": "plugin-facts.json",
            "issues": "issues.json",
            "observations": "observations.json",
            "collectorRegistry": "collector-registry.json",
            "componentRegistry": "component-registry.json",
        },
        "collectorRegistryRevision": collector_contracts.registry_revision(),
        "componentRegistryRevision": component_registry.component_revision(),
        "component": {"id": collector_contracts.DISCOVERY_COMPONENT_ID, "name": collector_contracts.DISCOVERY_COMPONENT_NAME},
        "authority": {
            "catalogIdentity": False,
            "definitions": False,
            "security": False,
            "scanQueue": False,
            "clientPublication": False,
            "purpose": "discovery-only",
            "ruleEvaluation": False,
            "observationRequestExecution": False,
        },
    }
    write_json(output / "index.json", index)


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate only novel catalog/source facts outside the canonical build pipeline")
    ap.add_argument("--candidates", required=True, type=Path)
    ap.add_argument("--catalog-root", required=True, type=Path)
    ap.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    ap.add_argument("--output", required=True, type=Path)
    args = ap.parse_args()
    candidates = read_json(args.candidates, {}) or {}
    result = discover(
        candidates,
        args.catalog_root,
        repository=args.repository,
        token=os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or "",
        web_search_api_key=os.environ.get("BRAVE_SEARCH_API_KEY") or "",
    )
    write_snapshot(result, args.output)
    print(json.dumps({"schema": SCHEMA, "counts": read_json(args.output / "index.json", {}).get("counts", {})}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
