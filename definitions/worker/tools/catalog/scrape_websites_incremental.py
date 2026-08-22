#!/usr/bin/env python3
"""Incremental website enrichment for Omega.

Uses the previous SQLite catalog as a last-known-good website cache. Repositories
successfully scraped within --max-age-hours are reused without network traffic;
new/stale entries are delegated to scrape_websites.py. Failures are emitted but
will be merged with prior successful metadata by build_sqlite_catalog.py.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sqlite3
import sys
from pathlib import Path

import scrape_websites


def normalize_url(value: str | None) -> str:
    return (value or "").strip().rstrip("/")


def parse_utc(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def load_cache(path: Path | None, max_age_hours: float) -> dict[str, dict]:
    if path is None or not path.exists():
        return {}
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=max_age_hours)
    out: dict[str, dict] = {}
    try:
        db = sqlite3.connect(path)
        db.row_factory = sqlite3.Row
        for row in db.execute("SELECT * FROM websites WHERE ok=1 AND last_success_utc<>''"):
            success = parse_utc(row["last_success_utc"])
            if success is None or success < cutoff:
                continue
            metadata = {}
            try:
                metadata = json.loads(row["metadata_json"] or "{}")
            except Exception:
                metadata = {}
            if not isinstance(metadata, dict):
                metadata = {}
            # Presentation/parser changes must become visible through a real re-scrape rather than
            # silently reinterpreting an old bounded README/description snapshot forever.
            if int(metadata.get("presentationSchemaVersion") or 0) != scrape_websites.PRESENTATION_SCHEMA_VERSION:
                continue
            # Do not reuse presentation cache entries that contain transport/debug
            # diagnostics. They must be re-scraped so stale 404/500 text can never
            # persist as a plugin description.
            if (scrape_websites.looks_like_http_diagnostic(row["description"]) or
                    scrape_websites.looks_like_http_diagnostic(row["readme_excerpt"])):
                continue
            metadata.update({
                "url": row["url"],
                "ok": True,
                "description": row["description"],
                "homepage": row["homepage"],
                "stars": row["stars"],
                "forks": row["forks"],
                "watchers": row["watchers"],
                "language": row["language"],
                "license": row["license"],
                "defaultBranch": row["default_branch"],
                "lastCommit": row["last_commit_utc"],
                "readmeExcerpt": row["readme_excerpt"],
                "cached": True,
            })
            try:
                metadata["topics"] = json.loads(row["topics_json"] or "[]")
            except Exception:
                metadata["topics"] = []
            try:
                metadata["imageUrls"] = json.loads(row["image_urls_json"] or "[]")
            except Exception:
                metadata["imageUrls"] = []
            try:
                metadata["links"] = json.loads(row["links_json"] or "[]") if "links_json" in row.keys() else metadata.get("links", [])
            except Exception:
                metadata["links"] = []
            try:
                metadata["omegaIndex"] = json.loads(row["omega_index_json"] or "{}") if "omega_index_json" in row.keys() else metadata.get("omegaIndex", {})
            except Exception:
                metadata["omegaIndex"] = {}
            metadata["omegaBannerUrl"] = (row["omega_banner_url"] or "") if "omega_banner_url" in row.keys() else str(metadata.get("omegaBannerUrl") or "")
            out[normalize_url(row["url"]).lower()] = metadata
        db.close()
    except Exception:
        return {}
    return out




def load_seed_repo_urls(path: Path | None) -> dict[str, str]:
    """Return active repository/project URLs already known by the seed catalog.

    Manifest feeds that answer HTTP 304 intentionally contribute no plugin payload to
    enriched-sources.json. Their previously-known project URLs still need website-age
    evaluation, otherwise a permanently unchanged manifest would also freeze website
    enrichment forever.
    """
    if path is None or not path.exists():
        return {}
    out: dict[str, str] = {}
    try:
        db = sqlite3.connect(path)
        for (value,) in db.execute(
            "SELECT DISTINCT repo_url FROM plugin_variants "
            "WHERE active=1 AND repo_url IS NOT NULL AND trim(repo_url)<>''"
        ):
            url = normalize_url(value)
            if url:
                out[url.lower()] = url
        db.close()
    except Exception:
        return {}
    return out

def main() -> int:
    ap = argparse.ArgumentParser(description="Incrementally scrape Omega plugin websites")
    ap.add_argument("--input", "-i", default="catalog/enriched-sources.json")
    ap.add_argument("--output", "-o", default="catalog/website-enrichment.json")
    ap.add_argument("--seed-database", default="")
    ap.add_argument("--max-age-hours", type=float, default=168.0)
    ap.add_argument("--concurrency", "-c", type=int, default=4)
    ap.add_argument("--timeout", type=float, default=20.0)
    args = ap.parse_args()

    enriched = json.loads(Path(args.input).read_text(encoding="utf-8-sig"))
    plugins = enriched.get("plugins") or []
    seed_path = Path(args.seed_database) if args.seed_database else None
    cache = load_cache(seed_path, args.max_age_hours)

    # Union current manifest URLs with active URLs from the previous database. A source
    # returning HTTP 304 has no plugin payload in this run, but its website may still
    # have become stale and must remain eligible for re-scraping.
    urls: dict[str, str] = load_seed_repo_urls(seed_path)
    for p in plugins:
        url = normalize_url(p.get("repoUrl"))
        if url:
            urls[url.lower()] = url

    cached_results = {url: cache[key] for key, url in urls.items() if key in cache}
    stale_urls = {key for key in urls if key not in cache}

    # Give the existing scraper only plugins whose websites are stale/new. For URLs
    # known only through the seed DB (because the manifest was 304), add minimal stubs;
    # scrape_all only needs repoUrl to crawl the project page and the builder consumes
    # the resulting repos map independently from the plugin payload.
    scrape_plugins = [p for p in plugins if normalize_url(p.get("repoUrl")).lower() in stale_urls]
    current_url_keys = {normalize_url(p.get("repoUrl")).lower() for p in scrape_plugins}
    for key in sorted(stale_urls):
        if key not in current_url_keys:
            scrape_plugins.append({"repoUrl": urls[key], "internalName": "", "name": ""})
    scrape_input = dict(enriched)
    scrape_input["plugins"] = scrape_plugins
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    scraped = scrape_websites.scrape_all(
        scrape_input,
        token=token,
        concurrency=args.concurrency,
        timeout=args.timeout,
        verbose=True,
    )

    repos = dict(cached_results)
    repos.update(scraped.get("repos") or {})
    enriched_plugins = []
    web_enriched_plugins = []
    for p in plugins:
        copy = dict(p)
        url = normalize_url(copy.get("repoUrl"))
        rec = repos.get(url) or repos.get(url.lower())
        if rec:
            copy["website"] = rec
            copy["webEnriched"] = bool(rec.get("ok"))
        if copy.get("webEnriched"):
            web_enriched_plugins.append(copy)
        enriched_plugins.append(copy)

    out = {
        "metadata": {
            "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
            "pluginCount": len(plugins),
            "cachedRepos": len(cached_results),
            "networkRepos": len(scraped.get("repos") or {}),
            "maxAgeHours": args.max_age_hours,
        },
        "repos": dict(sorted(repos.items(), key=lambda x: x[0].lower())),
        "plugins": enriched_plugins,
        "webEnrichedPlugins": web_enriched_plugins,
    }
    Path(args.output).write_text(json.dumps(out, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.output}: {len(cached_results)} cached website(s), {len(scraped.get('repos') or {})} network scrape(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
