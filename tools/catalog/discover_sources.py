#!/usr/bin/env python3
"""Discover likely Dalamud repository indexes through GitHub code search.

The output is intentionally only a candidate queue. Validation is a separate stage.
Candidate identity is repository/path, while gitBlobSha lets the builder recognize when
GitHub content has changed. The raw URL follows HEAD so a committed candidate does not
become pinned forever to the discovery commit.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

API = "https://api.github.com/search/code"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except FileNotFoundError:
        return default


def load_queries(path: Path) -> list[str]:
    doc = read_json(path, {})
    values = doc.get("queries", []) if isinstance(doc, dict) else []
    return [str(x).strip() for x in values if str(x).strip()]


def load_existing(path: Path) -> dict[tuple[str, str], dict]:
    doc = read_json(path, {})
    result: dict[tuple[str, str], dict] = {}
    for item in doc.get("items", []) if isinstance(doc, dict) else []:
        repo = str(item.get("repository", "")).strip()
        file_path = str(item.get("path", "")).strip()
        if repo and file_path:
            result[(repo.lower(), file_path)] = item
    return result


def request_json(url: str, token: str) -> dict:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "Dalagab-Omega-Catalog-Builder/1",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=45) as response:
        return json.load(response)


def discover(query: str, token: str, max_pages: int, delay: float):
    for page in range(1, max_pages + 1):
        params = urllib.parse.urlencode({"q": query, "per_page": 100, "page": page})
        doc = request_json(f"{API}?{params}", token)
        items = doc.get("items", [])
        if not items:
            break
        for item in items:
            repo = item.get("repository") or {}
            full_name = str(repo.get("full_name", "")).strip()
            path = str(item.get("path", "")).strip()
            if not full_name or not path or not path.lower().endswith(".json"):
                continue
            raw_path = urllib.parse.quote(path, safe="/")
            yield {
                "repository": full_name,
                "path": path,
                "rawUrl": f"https://raw.githubusercontent.com/{full_name}/HEAD/{raw_path}",
                "htmlUrl": str(item.get("html_url", "")),
                "gitBlobSha": str(item.get("sha", "")),
            }
        if len(items) < 100:
            break
        time.sleep(delay)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--queries", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--token-env", default="GITHUB_TOKEN")
    parser.add_argument("--max-pages", type=int, default=10)
    parser.add_argument("--delay", type=float, default=6.5,
                        help="Delay between full GitHub code-search pages; code search is rate-limited.")
    args = parser.parse_args()

    token = os.environ.get(args.token_env, "")
    if not token:
        print(f"warning: {args.token_env} is empty; GitHub code search usually requires authentication", file=sys.stderr)

    queries = load_queries(args.queries)
    if not queries:
        raise SystemExit("No discovery queries configured")

    now = utc_now()
    existing = load_existing(args.output)
    merged = dict(existing)
    errors: list[dict] = []

    for query in queries:
        print(f"search: {query}")
        try:
            for found in discover(query, token, max(1, args.max_pages), max(0.0, args.delay)):
                key = (found["repository"].lower(), found["path"])
                prior = merged.get(key, {})
                found["firstSeenUtc"] = prior.get("firstSeenUtc") or now
                found["lastSeenUtc"] = now
                merged[key] = found
        except Exception as ex:  # discovery failure should not destroy the previous queue
            errors.append({"query": query, "error": str(ex)})
            print(f"warning: query failed: {ex}", file=sys.stderr)
        time.sleep(max(0.0, args.delay))

    items = sorted(merged.values(), key=lambda x: (x["repository"].lower(), x["path"].lower()))
    output = {
        "schemaVersion": 1,
        "generatedAtUtc": now,
        "queries": queries,
        "count": len(items),
        "errors": errors,
        "items": items,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"candidate queue: {len(items)} entries -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
