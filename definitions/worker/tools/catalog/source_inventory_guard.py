#!/usr/bin/env python3
"""Fail-closed source-inventory validation for Omega's daily canonical catalog.

The canonical JSON catalog is allowed to retain unreachable sources and their last-known-good
plugin data. What must never happen silently is losing a source definition because discovery,
normalization, publication, or an identity migration truncated the source universe.

This validator proves that:
  * every URL emitted by the current discovery pass exists in canonical JSON;
  * every curated/community source definition exists in both discovery and canonical JSON;
  * every previously canonical source remains present unless an operator explicitly allows removal;
  * explicitly configured feed migrations and redirects observed by the current enrichment pass can
    satisfy those retention checks without treating arbitrary URLs as equivalent;
  * ambiguous alias declarations fail closed;
  * reachability is reported separately and never confused with catalog membership.
"""
from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path
from typing import Any, Iterable

SCHEMA = "omega.catalog-source-inventory.validation.v2"
ALIAS_SCHEMA = "omega.source-url-aliases.v1"


def normalize_url(value: Any) -> str:
    # Preserve the historical comparison contract for existing source inventories. Alias/redirect
    # evidence is deliberately explicit rather than widening generic URL canonicalization here.
    return str(value or "").strip().rstrip("/").casefold()


def read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return default


def configured_urls(path: Path | None) -> set[str]:
    if path is None or not path.is_file():
        return set()
    doc = read_json(path, [])
    return {
        normalized
        for item in (doc if isinstance(doc, list) else [])
        if isinstance(item, dict)
        for normalized in [normalize_url(item.get("url"))]
        if normalized
    }


def raw_source_urls(path: Path) -> tuple[set[str], dict[str, int]]:
    doc = read_json(path, {})
    sources = doc.get("sources") if isinstance(doc, dict) else []
    urls: set[str] = set()
    by_discovery: dict[str, int] = {}
    for item in sources or []:
        if not isinstance(item, dict):
            continue
        url = normalize_url(item.get("url"))
        if not url:
            continue
        urls.add(url)
        key = str(item.get("discoveredBy") or "unknown")
        by_discovery[key] = by_discovery.get(key, 0) + 1
    return urls, by_discovery


def enriched_reachability(path: Path | None) -> tuple[int, int]:
    if path is None or not path.is_file():
        return 0, 0
    doc = read_json(path, {})
    sources = doc.get("sources") if isinstance(doc, dict) else []
    ok = 0
    total = 0
    for item in sources or []:
        if not isinstance(item, dict):
            continue
        if not normalize_url(item.get("url")):
            continue
        total += 1
        if bool(item.get("ok")):
            ok += 1
    return ok, max(0, total - ok)


def catalog_urls(root: Path | None) -> set[str]:
    if root is None or not (root / "sources" / "index.json").is_file():
        return set()
    index = read_json(root / "sources" / "index.json", {})
    return {
        normalized
        for item in (index.get("sources") or [])
        if isinstance(item, dict)
        for normalized in [normalize_url(item.get("url"))]
        if normalized
    }


def _https_url(value: Any) -> str:
    normalized = normalize_url(value)
    return normalized if normalized.startswith("https://") else ""


def configured_alias_edges(path: Path | None) -> tuple[list[tuple[str, str, str]], list[str], list[dict[str, Any]]]:
    """Load explicit feed-URL migration aliases.

    The file is intentionally separate from source-repository/source-code aliases. These identities
    are PluginMaster/feed endpoints. One alias may belong to only one declared canonical group; a
    collision is a configuration error rather than a guess.
    """
    if path is None or not path.is_file():
        return [], [], []
    doc = read_json(path, {})
    if not isinstance(doc, dict) or str(doc.get("schema") or "") != ALIAS_SCHEMA:
        return [], [f"source alias registry must use schema {ALIAS_SCHEMA}"], []
    groups = doc.get("groups") or []
    if not isinstance(groups, list):
        return [], ["source alias registry groups must be a list"], []

    edges: list[tuple[str, str, str]] = []
    errors: list[str] = []
    declarations: list[dict[str, Any]] = []
    owner_by_url: dict[str, str] = {}
    for index, item in enumerate(groups):
        if not isinstance(item, dict):
            errors.append(f"source alias group {index} must be an object")
            continue
        canonical = _https_url(item.get("canonical"))
        if not canonical:
            errors.append(f"source alias group {index} has no valid HTTPS canonical URL")
            continue
        aliases = item.get("aliases") or []
        if not isinstance(aliases, list):
            errors.append(f"source alias group {index} aliases must be a list")
            continue
        reason = str(item.get("reason") or "configured migration").strip()[:512]
        urls = [canonical]
        for alias_value in aliases:
            alias = _https_url(alias_value)
            if not alias:
                errors.append(f"source alias group {index} contains a non-HTTPS/empty alias")
                continue
            urls.append(alias)
        for url in dict.fromkeys(urls):
            owner = owner_by_url.get(url)
            if owner and owner != canonical:
                errors.append(f"source alias URL is ambiguous between canonical groups: {url}")
            else:
                owner_by_url[url] = canonical
        for alias in dict.fromkeys(urls[1:]):
            if alias != canonical:
                edges.append((alias, canonical, "configured_alias"))
        declarations.append({
            "canonical": canonical,
            "aliases": sorted(set(urls[1:])),
            "reason": reason,
        })
    return edges, errors, declarations


def observed_redirect_edges(path: Path | None) -> list[tuple[str, str, str]]:
    """Return only redirects that the current enrichment pass successfully followed.

    No network access happens here. A redirect can affect retention equivalence only when the fetch
    already succeeded and recorded its final HTTPS URL in enriched-sources.json.
    """
    if path is None or not path.is_file():
        return []
    doc = read_json(path, {})
    sources = doc.get("sources") if isinstance(doc, dict) else []
    edges: list[tuple[str, str, str]] = []
    for item in sources or []:
        if not isinstance(item, dict) or not bool(item.get("ok")):
            continue
        source = _https_url(item.get("url"))
        resolved = _https_url(item.get("resolvedUrl") or item.get("finalUrl"))
        if source and resolved and source != resolved:
            edges.append((source, resolved, "observed_redirect"))
    return edges


class UrlEquivalence:
    def __init__(self, edges: Iterable[tuple[str, str, str]]):
        self.parent: dict[str, str] = {}
        self.graph: dict[str, list[tuple[str, str]]] = collections.defaultdict(list)
        for left, right, basis in edges:
            self._union(left, right)
            self.graph[left].append((right, basis))
            self.graph[right].append((left, basis))

    def _find(self, value: str) -> str:
        if value not in self.parent:
            self.parent[value] = value
            return value
        root = value
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[value] != value:
            parent = self.parent[value]
            self.parent[value] = root
            value = parent
        return root

    def _union(self, left: str, right: str) -> None:
        lroot = self._find(left)
        rroot = self._find(right)
        if lroot != rroot:
            # Deterministic representative keeps report output stable.
            low, high = sorted((lroot, rroot))
            self.parent[high] = low

    def key(self, value: str) -> str:
        return self._find(value)

    def path_basis(self, start: str, end: str) -> list[str]:
        if start == end:
            return ["literal"]
        if self.key(start) != self.key(end):
            return []
        queue = collections.deque([(start, [])])
        seen = {start}
        while queue:
            node, bases = queue.popleft()
            for neighbor, basis in self.graph.get(node, []):
                if neighbor in seen:
                    continue
                next_bases = [*bases, basis]
                if neighbor == end:
                    return list(dict.fromkeys(next_bases))
                seen.add(neighbor)
                queue.append((neighbor, next_bases))
        return ["equivalent"]


def _coverage(required: set[str], available: set[str], equivalence: UrlEquivalence) -> tuple[list[str], list[dict[str, Any]], int]:
    available_by_key: dict[str, list[str]] = collections.defaultdict(list)
    for url in sorted(available):
        available_by_key[equivalence.key(url)].append(url)
    missing: list[str] = []
    migrated: list[dict[str, Any]] = []
    literal = 0
    for url in sorted(required):
        if url in available:
            literal += 1
            continue
        matches = available_by_key.get(equivalence.key(url)) or []
        if not matches:
            missing.append(url)
            continue
        chosen = matches[0]
        migrated.append({
            "required": url,
            "satisfiedBy": chosen,
            "basis": equivalence.path_basis(url, chosen),
        })
    return missing, migrated, literal


def validate(
    *,
    raw: Path,
    catalog_root: Path,
    curated: Path | None = None,
    community: Path | None = None,
    enriched: Path | None = None,
    previous_catalog_root: Path | None = None,
    aliases: Path | None = None,
    allow_source_removal: bool = False,
) -> dict[str, Any]:
    raw_urls, by_discovery = raw_source_urls(raw)
    canonical = catalog_urls(catalog_root)
    previous = catalog_urls(previous_catalog_root)
    curated_urls = configured_urls(curated)
    community_urls = configured_urls(community)
    required = curated_urls | community_urls
    reachable, unreachable = enriched_reachability(enriched)

    configured_edges, alias_errors, alias_declarations = configured_alias_edges(aliases)
    redirect_edges = observed_redirect_edges(enriched)
    equivalence = UrlEquivalence([*configured_edges, *redirect_edges])

    # If an observed redirect connects two independently declared canonical groups, the current
    # evidence is ambiguous. Keep the guard fail-closed and require the registry to be reconciled.
    canonical_groups: dict[str, set[str]] = collections.defaultdict(set)
    for declaration in alias_declarations:
        canonical_url = str(declaration.get("canonical") or "")
        if canonical_url:
            canonical_groups[equivalence.key(canonical_url)].add(canonical_url)
    for group in canonical_groups.values():
        if len(group) > 1:
            alias_errors.append("source alias/redirect evidence merges multiple declared canonical groups: " + ", ".join(sorted(group)))

    missing_raw, migrated_raw, literal_raw = _coverage(raw_urls, canonical, equivalence)
    missing_required_from_discovery, migrated_required_discovery, literal_required_discovery = _coverage(required, raw_urls, equivalence)
    missing_required_from_catalog, migrated_required_catalog, literal_required_catalog = _coverage(required, canonical, equivalence)
    lost_previous, migrated_previous, literal_previous = _coverage(previous, canonical, equivalence)

    errors: list[str] = list(dict.fromkeys(alias_errors))
    if missing_raw:
        errors.append(f"canonical catalog omitted {len(missing_raw)} source(s) emitted by discovery")
    if missing_required_from_discovery:
        errors.append(f"discovery omitted {len(missing_required_from_discovery)} curated/community source(s)")
    if missing_required_from_catalog:
        errors.append(f"canonical catalog omitted {len(missing_required_from_catalog)} curated/community source(s)")
    if lost_previous and not allow_source_removal:
        errors.append(f"canonical catalog lost {len(lost_previous)} previously known source(s)")

    return {
        "schema": SCHEMA,
        "ok": not errors,
        "counts": {
            "discovered": len(raw_urls),
            "canonical": len(canonical),
            "previousCanonical": len(previous),
            "curated": len(curated_urls),
            "community": len(community_urls),
            "required": len(required),
            "reachable": reachable,
            "unreachable": unreachable,
            "configuredAliasGroups": len(alias_declarations),
            "observedRedirects": len(redirect_edges),
        },
        "discovery": dict(sorted(by_discovery.items())),
        "coverage": {
            "discoveredInCanonical": len(raw_urls) - len(missing_raw),
            "requiredInDiscovery": len(required) - len(missing_required_from_discovery),
            "requiredInCanonical": len(required) - len(missing_required_from_catalog),
            "previousRetained": len(previous) - len(lost_previous),
            "literalDiscoveredInCanonical": literal_raw,
            "literalRequiredInDiscovery": literal_required_discovery,
            "literalRequiredInCanonical": literal_required_catalog,
            "literalPreviousRetained": literal_previous,
            "equivalentPreviousRetained": len(migrated_previous),
        },
        "equivalence": {
            "configured": alias_declarations,
            "observedRedirects": [
                {"from": left, "to": right, "basis": basis}
                for left, right, basis in sorted(redirect_edges)
            ],
            "discoveredMigrations": migrated_raw[:100],
            "requiredDiscoveryMigrations": migrated_required_discovery[:100],
            "requiredCatalogMigrations": migrated_required_catalog[:100],
            "previousMigrations": migrated_previous[:100],
            "errors": list(dict.fromkeys(alias_errors)),
        },
        "missing": {
            "discoveredFromCanonical": missing_raw[:100],
            "requiredFromDiscovery": missing_required_from_discovery[:100],
            "requiredFromCanonical": missing_required_from_catalog[:100],
            "previousFromCanonical": lost_previous[:100],
            "literalPreviousFromCanonical": sorted(previous - canonical)[:100],
        },
        "allowSourceRemoval": bool(allow_source_removal),
        "errors": errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", type=Path, required=True)
    parser.add_argument("--catalog-root", type=Path, required=True)
    parser.add_argument("--curated", type=Path)
    parser.add_argument("--community", type=Path)
    parser.add_argument("--enriched", type=Path)
    parser.add_argument("--previous-catalog-root", type=Path)
    parser.add_argument("--aliases", type=Path, help="Explicit feed URL migration/alias registry")
    parser.add_argument("--allow-source-removal", action="store_true")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    result = validate(
        raw=args.raw,
        catalog_root=args.catalog_root,
        curated=args.curated,
        community=args.community,
        enriched=args.enriched,
        previous_catalog_root=args.previous_catalog_root,
        aliases=args.aliases,
        allow_source_removal=args.allow_source_removal,
    )
    text = json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
