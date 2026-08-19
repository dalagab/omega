#!/usr/bin/env python3
"""Fail-closed source-inventory validation for Omega's daily canonical catalog.

The canonical JSON catalog is allowed to retain unreachable sources and their last-known-good
plugin data. What must never happen silently is losing a source definition because discovery,
normalization, or publication truncated the source universe.

This validator proves that:
  * every URL emitted by the current discovery pass exists in canonical JSON;
  * every curated/community source definition exists in both discovery and canonical JSON;
  * every previously canonical source remains present unless an operator explicitly allows removal;
  * reachability is reported separately and never confused with catalog membership.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

SCHEMA = "omega.catalog-source-inventory.validation.v1"


def normalize_url(value: Any) -> str:
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


def validate(
    *,
    raw: Path,
    catalog_root: Path,
    curated: Path | None = None,
    community: Path | None = None,
    enriched: Path | None = None,
    previous_catalog_root: Path | None = None,
    allow_source_removal: bool = False,
) -> dict[str, Any]:
    raw_urls, by_discovery = raw_source_urls(raw)
    canonical = catalog_urls(catalog_root)
    previous = catalog_urls(previous_catalog_root)
    curated_urls = configured_urls(curated)
    community_urls = configured_urls(community)
    required = curated_urls | community_urls
    reachable, unreachable = enriched_reachability(enriched)

    missing_raw = sorted(raw_urls - canonical)
    missing_required_from_discovery = sorted(required - raw_urls)
    missing_required_from_catalog = sorted(required - canonical)
    lost_previous = sorted(previous - canonical)

    errors: list[str] = []
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
        },
        "discovery": dict(sorted(by_discovery.items())),
        "coverage": {
            "discoveredInCanonical": len(raw_urls & canonical),
            "requiredInDiscovery": len(required & raw_urls),
            "requiredInCanonical": len(required & canonical),
            "previousRetained": len(previous & canonical),
        },
        "missing": {
            "discoveredFromCanonical": missing_raw[:100],
            "requiredFromDiscovery": missing_required_from_discovery[:100],
            "requiredFromCanonical": missing_required_from_catalog[:100],
            "previousFromCanonical": lost_previous[:100],
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
