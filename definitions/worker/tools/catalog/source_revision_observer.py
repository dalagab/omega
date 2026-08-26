#!/usr/bin/env python3
"""Observe public Git repository HEAD revisions without fetching source bodies.

This daily observer provides the event signal for confidence-40/default-branch source
attributions.  It performs only ref discovery (``git ls-remote --symref HEAD``); no
clone, checkout, tree, blob, submodule, package restore, build or code execution occurs.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from public_git_source import observe_remote_head  # noqa: E402
from source_resolution import source_candidate_records  # noqa: E402

SCHEMA = "omega.source-revision-observations.v1"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def repository_key(repository: str) -> str:
    return "repo-" + hashlib.sha256(str(repository or "").strip().casefold().encode("utf-8")).hexdigest()[:24]


def _read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return default


def catalog_repositories(catalog_root: Path) -> list[str]:
    plugin_index = _read_json(catalog_root / "plugins" / "index.json", {}) or {}
    source_index = _read_json(catalog_root / "sources" / "index.json", {}) or {}
    sources: dict[int, dict[str, Any]] = {}
    for item in source_index.get("sources") or []:
        if not isinstance(item, dict):
            continue
        payload = _read_json(catalog_root / str(item.get("path") or ""), {}) or {}
        source = payload.get("source") if isinstance(payload.get("source"), dict) else {}
        source_id = int(item.get("sourceId") or source.get("source_id") or 0)
        if source_id > 0:
            sources[source_id] = source

    repositories: dict[str, str] = {}
    for item in plugin_index.get("plugins") or []:
        if not isinstance(item, dict) or not item.get("active"):
            continue
        payload = _read_json(catalog_root / str(item.get("path") or ""), {}) or {}
        for grouped in payload.get("variants") or []:
            if not isinstance(grouped, dict):
                continue
            variant = grouped.get("variant") if isinstance(grouped.get("variant"), dict) else {}
            if int(variant.get("active") or 0) != 1:
                continue
            source = sources.get(int(variant.get("source_id") or 0), {})
            records = source_candidate_records((
                ("repo-url", str(variant.get("repo_url") or "")),
                ("catalog-source", str(source.get("source_repo_url") or "")),
                ("artifact-stable", str(variant.get("download_link_install") or "")),
                ("artifact-testing", str(variant.get("download_link_testing") or "")),
            ))
            for record in records:
                repository = str(record.get("repository") or "").strip()
                if repository:
                    repositories.setdefault(repository.casefold(), repository)
    return sorted(repositories.values(), key=str.casefold)


def observe(catalog_root: Path, *, timeout: float = 12.0, concurrency: int = 16) -> dict[str, Any]:
    repositories = catalog_repositories(catalog_root)

    def one(repository: str) -> dict[str, Any]:
        try:
            result = observe_remote_head(repository, timeout=timeout)
            return {
                "repositoryKey": repository_key(repository),
                "repository": repository,
                "status": "observed",
                "defaultRef": str(result.get("defaultRef") or ""),
                "commitSha": str(result.get("commitSha") or "").lower(),
                "error": "",
            }
        except Exception as exc:
            return {
                "repositoryKey": repository_key(repository),
                "repository": repository,
                "status": "failed",
                "defaultRef": "",
                "commitSha": "",
                "error": f"{type(exc).__name__}: {exc}"[:1000],
            }

    workers = min(max(1, int(concurrency)), 32)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        observations = list(pool.map(one, repositories))
    observations.sort(key=lambda item: str(item["repository"]).casefold())
    semantic = {
        "schema": SCHEMA,
        "repositories": [
            {key: item[key] for key in ("repositoryKey", "repository", "status", "defaultRef", "commitSha")}
            for item in observations
        ],
    }
    revision = "source-observations-v1-" + hashlib.sha256(canonical(semantic)).hexdigest()[:16]
    observed = sum(1 for item in observations if item["status"] == "observed" and item["commitSha"])
    return {
        "schema": SCHEMA,
        "revision": revision,
        "generatedAtUtc": utc_now(),
        "counts": {"repositories": len(observations), "observed": observed, "failed": len(observations) - observed},
        "repositories": observations,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=12.0)
    parser.add_argument("--concurrency", type=int, default=16)
    args = parser.parse_args()
    result = observe(args.catalog_root.resolve(), timeout=args.timeout, concurrency=args.concurrency)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"revision": result["revision"], "counts": result["counts"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
