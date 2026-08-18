#!/usr/bin/env python3
"""
enrich_metadata.py — metadata enrichment for the catalog builder.

Reads `raw-sources.json` (output of collect_sources.py), fetches each URL
in parallel, parses the JSON, normalizes the records, and records whether each variant has a complete basic
metadata set. Rich-card/web-enriched presentation is decided later; this pipeline step
does not award Omega's project-page star.

A plugin gets `metadataComplete: true` when ALL of:
  * has a non-empty Punchline (one-line tagline)
  * has a non-empty Description (longer text, ≥ 40 chars)
  * has a non-empty RepoUrl (upstream link)
  * has a non-empty AssemblyVersion (useable build)

The aggregated output is `enriched-sources.json` — a single document the
website enrichment step (`scrape_websites.py`) reads, and which build_sqlite_catalog.py imports
into Omega's canonical SQLite catalog.

Usage:
    python enrich_metadata.py --input catalog/raw-sources.json --output catalog/enriched-sources.json
    python enrich_metadata.py --input -  # read JSON from stdin

Requires: Python 3.8+ (stdlib only).
"""

from __future__ import annotations

from contextlib import closing
import argparse
import hashlib
import json
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path


USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36"
)

# Basic manifest completeness criteria. This is not Omega's UI star.
METADATA_CRITERIA = ("punchline", "description", "repoUrl", "assemblyVersion")
DEFAULT_MAX_SOURCE_BYTES = 64 * 1024 * 1024


class _ValidatingRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject redirect targets before urllib opens them when a validator is supplied."""

    def __init__(self, validator):
        super().__init__()
        self.validator = validator

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not self.validator(newurl):
            raise urllib.error.HTTPError(newurl, code, "Redirect target rejected by URL policy", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


# ---------------------------------------------------------------------------
# HTTP + JSON
# ---------------------------------------------------------------------------

def normalize_url(value: str | None) -> str:
    return (value or "").strip().rstrip("/")


def load_source_cache(path: str | None) -> dict[str, dict]:
    if not path:
        return {}
    db_path = Path(path)
    if not db_path.exists():
        return {}
    out: dict[str, dict] = {}
    try:
        with closing(sqlite3.connect(db_path)) as db:
            db.row_factory = sqlite3.Row
            for row in db.execute("SELECT url,etag,last_modified,content_sha256 FROM sources WHERE url<>''"):
                out[normalize_url(row["url"]).lower()] = dict(row)
    except Exception:
        return {}
    return out


def http_get(
    url: str,
    timeout: float = 20.0,
    conditional: dict | None = None,
    max_bytes: int = DEFAULT_MAX_SOURCE_BYTES,
    url_validator=None,
) -> tuple[int, bytes, dict[str, str]]:
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json, */*;q=0.8"}
    conditional = conditional or {}
    if conditional.get("etag"):
        headers["If-None-Match"] = str(conditional["etag"])
    if conditional.get("last_modified"):
        headers["If-Modified-Since"] = str(conditional["last_modified"])
    if url_validator is not None and not url_validator(url):
        raise ValueError("Source URL rejected by URL policy")
    req = urllib.request.Request(url, headers=headers)
    opener = urllib.request.build_opener(_ValidatingRedirectHandler(url_validator)) if url_validator is not None else None
    try:
        response = opener.open(req, timeout=timeout) if opener is not None else urllib.request.urlopen(req, timeout=timeout)
        with response as resp:
            body = resp.read(max_bytes + 1)
            if len(body) > max_bytes:
                raise ValueError(f"PluginMaster response exceeds {max_bytes} bytes")
            return int(resp.status), body, {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return 304, b"", {k.lower(): v for k, v in exc.headers.items()}
        raise



def _strip_trailing_json_commas(text: str) -> str:
    """Remove commas immediately before ``]`` or ``}`` outside JSON strings.

    Community Dalamud repositories occasionally publish PluginMaster-style feeds with
    trailing commas. Python's standard JSON decoder rejects them, while Dalamud and
    Omega's in-game manifest parser already tolerate them. Keep the relaxation narrow:
    only a comma whose next non-whitespace character closes an array/object is removed.
    """
    out: list[str] = []
    in_string = False
    escaped = False
    length = len(text)

    for index, char in enumerate(text):
        if in_string:
            out.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue

        if char == '"':
            in_string = True
            out.append(char)
            continue

        if char == ",":
            lookahead = index + 1
            while lookahead < length and text[lookahead].isspace():
                lookahead += 1
            if lookahead < length and text[lookahead] in "]}":
                continue

        out.append(char)

    return "".join(out)


def _loads_pluginmaster_json(text: str):
    """Parse a PluginMaster feed, retrying only for trailing-comma tolerance."""
    text = text.removeprefix("\ufeff")
    try:
        return json.loads(text)
    except json.JSONDecodeError as strict_error:
        relaxed = _strip_trailing_json_commas(text)
        if relaxed == text:
            raise strict_error
        return json.loads(relaxed)


def _extract_plugin_list(data):
    """Accept common PluginMaster root wrappers as well as a bare array."""
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if not isinstance(data, dict):
        return None
    for key in ("plugins", "Plugins", "pluginMaster", "PluginMaster", "pluginmaster", "Pluginmaster"):
        value = data.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    for key in ("data", "Data", "result", "Result"):
        value = data.get(key)
        if isinstance(value, dict):
            nested = _extract_plugin_list(value)
            if nested is not None:
                return nested
    if any(key in data for key in ("InternalName", "internalName")):
        return [data]
    return None

def fetch_source(
    source: dict,
    cache: dict[str, dict] | None = None,
    timeout: float = 20.0,
    max_bytes: int = DEFAULT_MAX_SOURCE_BYTES,
    url_validator=None,
) -> dict:
    """Fetch one URL with conditional headers when a previous SQLite state exists."""
    url = source["url"]
    cached = (cache or {}).get(normalize_url(url).lower(), {})
    try:
        status, body, headers = http_get(
            url, timeout=timeout, conditional=cached, max_bytes=max_bytes, url_validator=url_validator
        )
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, ValueError) as exc:
        return _record(source, ok=False, error=f"{type(exc).__name__}: {exc}")
    etag = headers.get("etag") or str(cached.get("etag") or "")
    last_modified = headers.get("last-modified") or str(cached.get("last_modified") or "")
    if status == 304:
        return _record(
            source, ok=True, error=None, notModified=True, etag=etag, lastModified=last_modified,
            contentSha256=str(cached.get("content_sha256") or ""),
        )
    try:
        data = _loads_pluginmaster_json(body.decode("utf-8-sig", errors="replace"))
    except json.JSONDecodeError as exc:
        return _record(source, ok=False, error=f"Non-JSON response: {exc}")
    entries = _extract_plugin_list(data)
    if entries is None:
        return _record(source, ok=False, error=f"Unsupported PluginMaster JSON root: {type(data).__name__}")
    plugins = [_normalize_plugin(p) for p in entries]
    for plugin in plugins:
        plugin["metadataComplete"] = _is_metadata_complete(plugin)
    return _record(
        source, ok=True, error=None, plugins=plugins, pluginCount=len(plugins),
        etag=etag, lastModified=last_modified, contentSha256=hashlib.sha256(body).hexdigest(),
    )


def _record(
    source: dict,
    ok: bool,
    error: str | None,
    plugins: list[dict] | None = None,
    pluginCount: int | None = None,
    *,
    notModified: bool = False,
    etag: str = "",
    lastModified: str = "",
    contentSha256: str = "",
) -> dict:
    return {
        "url": source["url"],
        "provider": source.get("provider"),
        "kind": source.get("kind"),
        "discoveredBy": source.get("discoveredBy"),
        "sourceRepoUrl": source.get("sourceRepoUrl"),
        "ok": ok,
        "notModified": notModified,
        "error": error,
        "etag": etag,
        "lastModified": lastModified,
        "contentSha256": contentSha256,
        "pluginCount": pluginCount if pluginCount is not None else (len(plugins) if plugins else 0),
        "plugins": plugins or [],
    }


def _normalize_plugin(raw: dict) -> dict:
    """Project a raw plugin entry to a stable, minimal record.

    Keeps the case-sensitive field name `dalamudApiLevel` so downstream
    grep across the DB still matches.
    """
    return {
        "author": raw.get("Author"),
        "name": raw.get("Name"),
        "internalName": raw.get("InternalName"),
        "punchline": raw.get("Punchline"),
        "description": raw.get("Description"),
        "changelog": raw.get("Changelog"),
        "tags": raw.get("Tags") or [],
        "categoryTags": raw.get("CategoryTags") or [],
        "dalamudApiLevel": raw.get("DalamudApiLevel"),
        "testingDalamudApiLevel": raw.get("TestingDalamudApiLevel"),
        "assemblyVersion": raw.get("AssemblyVersion"),
        "testingAssemblyVersion": raw.get("TestingAssemblyVersion"),
        "applicableVersion": raw.get("ApplicableVersion"),
        "minimumDalamudVersion": raw.get("MinimumDalamudVersion"),
        "downloadCount": raw.get("DownloadCount"),
        "iconUrl": raw.get("IconUrl"),
        "imageUrls": raw.get("ImageUrls") or [],
        "repoUrl": raw.get("RepoUrl"),
        "downloadLinkInstall": raw.get("DownloadLinkInstall"),
        "downloadLinkUpdate": raw.get("DownloadLinkUpdate"),
        "downloadLinkTesting": raw.get("DownloadLinkTesting"),
        "isHide": raw.get("IsHide"),
        "isTestingExclusive": raw.get("IsTestingExclusive"),
        "lastUpdate": raw.get("LastUpdate"),
        "dip17Channel": raw.get("_Dip17Channel"),
        "rawManifest": raw,
    }


def _is_metadata_complete(plugin: dict) -> bool:
    """Return whether the manifest has enough basic descriptive metadata."""
    for k in METADATA_CRITERIA:
        v = plugin.get(k)
        if v is None:
            return False
        if isinstance(v, str) and not v.strip():
            return False
        if k == "description" and isinstance(v, str) and len(v.strip()) < 40:
            return False
    return True


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def fetch_sources_parallel(sources: list[dict], concurrency: int = 8, timeout: float = 20.0, cache: dict[str, dict] | None = None) -> list[dict]:
    out: list[dict] = []
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = {ex.submit(fetch_source, s, cache, timeout): s for s in sources}
        for fut in as_completed(futures):
            try:
                rec = fut.result()
            except Exception as e:  # defensive
                src = futures[fut]
                rec = _record(src, ok=False, error=f"{type(e).__name__}: {e}")
            out.append(rec)
    # Stable sort: ok first, then by provider
    out.sort(key=lambda r: (not r["ok"], r.get("provider") or ""))
    return out


def enrich(raw_sources_path: str, concurrency: int = 8, timeout: float = 20.0, verbose: bool = True, seed_database: str | None = None) -> dict:
    def log(msg: str) -> None:
        if verbose:
            print(msg, file=sys.stderr)

    started = time.time()
    log(f"Loading raw sources from {raw_sources_path} ...")
    with open(raw_sources_path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    sources = raw.get("sources") or []
    log(f"  -> {len(sources)} source URL(s)")

    log(f"Fetching {len(sources)} source(s) in parallel (concurrency={concurrency}) ...")
    records = fetch_sources_parallel(sources, concurrency=concurrency, timeout=timeout, cache=load_source_cache(seed_database))
    ok = sum(1 for r in records if r["ok"])

    # Flatten plugins + add sourceRepo field
    all_plugins: list[dict] = []
    for r in records:
        for p in r["plugins"]:
            p["sourceUrl"] = r["url"]
            p["sourceProvider"] = r.get("provider")
            all_plugins.append(p)

    complete = [p for p in all_plugins if p.get("metadataComplete")]
    apis: dict[str, int] = {}
    for p in all_plugins:
        v = p.get("dalamudApiLevel")
        if v is not None:
            apis[str(v)] = apis.get(str(v), 0) + 1

    elapsed = time.time() - started
    return {
        "metadata": {
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "elapsedSeconds": round(elapsed, 2),
            "sourceCount": len(sources),
            "sourceOk": ok,
            "sourceFailed": len(sources) - ok,
            "sourceNotModified": sum(1 for r in records if r.get("notModified")),
            "totalPluginCount": len(all_plugins),
            "metadataCompletePluginCount": len(complete),
            "dalamudApiLevelDistribution": apis,
        },
        "sources": records,
        "plugins": all_plugins,
        "metadataCompletePlugins": complete,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Fetch and normalize JSON sources.")
    ap.add_argument("--input", "-i", default="catalog/raw-sources.json",
                    help="Input raw-sources.json (use '-' for stdin; default: %(default)s)")
    ap.add_argument("--output", "-o", default="catalog/enriched-sources.json",
                    help="Output JSON file (use '-' for stdout; default: %(default)s)")
    ap.add_argument("--concurrency", "-c", type=int, default=8, help="Parallel fetchers (default: %(default)s)")
    ap.add_argument("--timeout", type=float, default=20.0, help="Per-request timeout (default: %(default)s)")
    ap.add_argument("--quiet", "-q", action="store_true", help="Suppress progress output")
    ap.add_argument("--seed-database", default="", help="Previous omega-catalog.sqlite for ETag/Last-Modified conditional fetches")
    args = ap.parse_args()

    if args.input == "-":
        raw_text = sys.stdin.read()
        raw_path = None
    else:
        with open(args.input, "r", encoding="utf-8") as f:
            raw_text = f.read()
        raw_path = args.input

    raw = json.loads(raw_text)
    # If the user fed a raw list (just sources), wrap it
    if isinstance(raw, list):
        raw = {"metadata": {}, "sources": raw}

    sources = raw.get("sources") or []

    # Re-implement the orchestration without writing to a file from inside
    def log(msg: str) -> None:
        if not args.quiet:
            print(msg, file=sys.stderr)

    started = time.time()
    log(f"Loaded {len(sources)} source URL(s) from input")
    log(f"Fetching in parallel (concurrency={args.concurrency}) ...")
    records = fetch_sources_parallel(sources, concurrency=args.concurrency, timeout=args.timeout, cache=load_source_cache(args.seed_database))
    ok = sum(1 for r in records if r["ok"])
    log(f"  -> {ok}/{len(sources)} OK")

    all_plugins: list[dict] = []
    for r in records:
        for p in r["plugins"]:
            p["sourceUrl"] = r["url"]
            p["sourceProvider"] = r.get("provider")
            all_plugins.append(p)

    complete = [p for p in all_plugins if p.get("metadataComplete")]
    apis: dict[str, int] = {}
    for p in all_plugins:
        v = p.get("dalamudApiLevel")
        if v is not None:
            apis[str(v)] = apis.get(str(v), 0) + 1

    elapsed = time.time() - started
    out = {
        "metadata": {
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "elapsedSeconds": round(elapsed, 2),
            "sourceCount": len(sources),
            "sourceOk": ok,
            "sourceFailed": len(sources) - ok,
            "sourceNotModified": sum(1 for r in records if r.get("notModified")),
            "totalPluginCount": len(all_plugins),
            "metadataCompletePluginCount": len(complete),
            "dalamudApiLevelDistribution": apis,
        },
        "sources": records,
        "plugins": all_plugins,
        "metadataCompletePlugins": complete,
    }

    text = json.dumps(out, ensure_ascii=False, indent=2, sort_keys=False)
    if args.output == "-":
        sys.stdout.write(text)
        sys.stdout.write("\n")
    else:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
            f.write("\n")
        meta = out["metadata"]
        print(
            f"\nWrote {args.output}: "
            f"{meta['totalPluginCount']} plugins ({meta['metadataCompletePluginCount']} metadata-complete) from "
            f"{meta['sourceOk']}/{meta['sourceCount']} source(s) OK. "
            f"API levels: {meta['dalamudApiLevelDistribution']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
