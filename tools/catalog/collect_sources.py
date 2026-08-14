#!/usr/bin/env python3
"""
collect_sources.py — Stage 1 of the catalog builder.

Discovers every public JSON source on the internet that contains the
case-sensitive string `DalamudApiLevel`, and writes them to a single file
so the next stage can fetch and parse them.

Sources covered:
  * Puni.sh marketplace (auto-discovers all publisher repos from HTML)
  * Curated list of known aggregator repos (goatcorp, ottercorp, AtmoOmen,
    NightmareXIV, Aether-Tools, etc.)
  * GitHub code search for the literal string `DalamudApiLevel` in
    `.json` files (requires GITHUB_TOKEN env var)

Output: a JSON file with a list of {url, provider, kind, discoveredBy}
entries, ready to be fed into enrich_metadata.py.

Re-run anytime; Puni.sh's publisher list is scraped live, and the GitHub
code search picks up new repos as they appear.

Usage:
    python collect_sources.py --output catalog/raw-sources.json
    python collect_sources.py --output -          # stdout
    GITHUB_TOKEN=ghp_... python collect_sources.py  # enables GH search

Requires: Python 3.8+ (stdlib only).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36"
)

# GitHub code search API endpoint. We use the unauthenticated endpoint first;
# if a token is provided, the rate limit is much higher.
GITHUB_CODE_SEARCH = "https://api.github.com/search/code"
GITHUB_API_BASE = "https://api.github.com"

# Curated list of known aggregator JSON files. Add more here as the
# ecosystem grows. Format: (url, provider_label, kind, source_repo_url_or_None)
CURATED_AGGREGATORS = [
    # goatcorp (official, archived)
    ("https://raw.githubusercontent.com/goatcorp/DalamudPlugins/api6/pluginmaster.json", "goatcorp", "aggregator", "https://github.com/goatcorp/DalamudPlugins"),
    ("https://raw.githubusercontent.com/goatcorp/DalamudPlugins/wotsit-1018/pluginmaster.json", "goatcorp", "aggregator", "https://github.com/goatcorp/DalamudPlugins"),
    ("https://raw.githubusercontent.com/goatcorp/DalamudPlugins/wotsit-1019/pluginmaster.json", "goatcorp", "aggregator", "https://github.com/goatcorp/DalamudPlugins"),
    # ottercorp fork (CN, archived)
    ("https://raw.githubusercontent.com/ottercorp/DalamudPlugins/cn-api6/pluginmaster.json", "ottercorp", "aggregator", "https://github.com/ottercorp/DalamudPlugins"),
    # Third-party aggregators
    ("https://raw.githubusercontent.com/AtmoOmen/DalamudPlugins/main/pluginmaster.json", "AtmoOmen", "aggregator", "https://github.com/AtmoOmen/DalamudPlugins"),
    ("https://raw.githubusercontent.com/Nik-Potokar/MyDalamudPlugins/main/pluginmaster.json", "Nik-Potokar", "aggregator", "https://github.com/Nik-Potokar/MyDalamudPlugins"),
    ("https://raw.githubusercontent.com/Nik-Potokar/XIVSlothCombo/main/pluginmaster.json", "XIVSlothCombo", "aggregator", "https://github.com/Nik-Potokar/XIVSlothCombo"),
    ("https://raw.githubusercontent.com/NightmareXIV/MyDalamudPlugins/main/pluginmaster.json", "NightmareXIV", "aggregator", "https://github.com/NightmareXIV/MyDalamudPlugins"),
    ("https://raw.githubusercontent.com/Aether-Tools/DalamudPlugins/main/repo.json", "Aether-Tools", "aggregator", "https://github.com/Aether-Tools/DalamudPlugins"),
    ("https://raw.githubusercontent.com/UnknownX7/DalamudPluginRepo/master/pluginmaster.json", "UnknownX7", "aggregator", "https://github.com/UnknownX7/DalamudPluginRepo"),
    ("https://raw.githubusercontent.com/PFCraft-box/DalamudPlugins/cn-api6/pluginmaster.json", "PFCraft-box", "aggregator", "https://github.com/PFCraft-box/DalamudPlugins"),
    ("https://raw.githubusercontent.com/zhouhuichen741/dalamud-plugins/master/repo.json", "zhouhuichen741", "aggregator", "https://github.com/zhouhuichen741/dalamud-plugins"),
    ("https://raw.githubusercontent.com/LiangYuxuan/dalamud-plugin-cn-fetcher/master/pluginmaster_gh.json", "LiangYuxuan", "aggregator", "https://github.com/LiangYuxuan/dalamud-plugin-cn-fetcher"),
    ("https://raw.githubusercontent.com/ryon5541/dalamud-repo-up/main/ffxiv_custom_repo.json", "ryon5541", "aggregator", "https://github.com/ryon5541/dalamud-repo-up"),
    ("https://raw.githubusercontent.com/ktisis-tools/Ktisis/main/repo.json", "ktisis-tools", "aggregator", "https://github.com/ktisis-tools/Ktisis"),
    ("https://raw.githubusercontent.com/FFXIV-CombatReborn/BossmodReborn/main/manifest.json", "FFXIV-CombatReborn", "aggregator", "https://github.com/FFXIV-CombatReborn/BossmodReborn"),
    ("https://raw.githubusercontent.com/Errerer/DalamudPlugins/main/pluginmaster.json", "Errerer", "aggregator", "https://github.com/Errerer/DalamudPlugins"),
    ("https://raw.githubusercontent.com/aemiliusxiv/DalamudPlugins/main/pluginmaster.json", "aemiliusxiv", "aggregator", "https://github.com/aemiliusxiv/DalamudPlugins"),
    ("https://raw.githubusercontent.com/dodingdaga/DalamudPlugins/main/PuppetMaster.json", "dodingdaga", "aggregator", "https://github.com/dodingdaga/DalamudPlugins"),
    # Penumbra / Glamourer / Mare (Penumbra ecosystem — the in-game mod loader)
    ("https://raw.githubusercontent.com/xivdev/Penumbra/master/repo.json", "xivdev/Penumbra", "aggregator", "https://github.com/xivdev/Penumbra"),
    # Single-plugin aggregator hosts
    ("https://raw.githubusercontent.com/Ottermandias/Penumbra/master/repo.json", "Ottermandias/Penumbra", "aggregator", "https://github.com/Ottermandias/Penumbra"),
    ("https://raw.githubusercontent.com/Ottermandias/Glamourer/main/repo.json", "Ottermandias/Glamourer", "aggregator", "https://github.com/Ottermandias/Glamourer"),
]

# Puni.sh endpoints we always include as base
PUNI_SH = "https://puni.sh"
PUNI_SH_REPOS_INDEX = f"{PUNI_SH}/directory/repositories"


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def http_get(url: str, timeout: float = 15.0, headers: dict[str, str] | None = None) -> bytes:
    hdrs = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def github_get(path: str, token: str | None = None, timeout: float = 15.0) -> dict:
    """GET a GitHub API endpoint. Returns parsed JSON."""
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
    if token:
        hdrs["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(f"{GITHUB_API_BASE}{path}", headers=hdrs)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


# ---------------------------------------------------------------------------
# Source collectors
# ---------------------------------------------------------------------------

# Match: href="/directory/<slug>"   (no further slashes, page is the repositories list)
SLUG_RE = re.compile(r'href="/directory/([A-Za-z0-9._-]+)"')


def collect_punish_publisher_urls() -> list[dict]:
    """Fetch the puni.sh repositories page and extract every publisher slug.

    The page is server-rendered Next.js HTML, so a regex on `href` works
    reliably. We return a list of {url, provider, kind, discoveredBy}.
    """
    html = http_get(PUNI_SH_REPOS_INDEX).decode("utf-8", errors="replace")
    seen: set[str] = set()
    slugs: list[str] = []
    for m in SLUG_RE.finditer(html):
        slug = m.group(1)
        if slug.lower() == "repositories":
            continue
        if slug in seen:
            continue
        seen.add(slug)
        slugs.append(slug)

    out: list[dict] = []
    # The main aggregator (always present, no /repository/ segment)
    out.append({
        "url": f"{PUNI_SH}/api/plugins",
        "provider": "puni.sh-studio",
        "kind": "aggregator",
        "discoveredBy": "puni.sh/directory/repositories",
        "sourceRepoUrl": PUNI_SH,
    })
    for slug in slugs:
        out.append({
            "url": f"{PUNI_SH}/api/repository/{slug}",
            "provider": slug,
            "kind": "aggregator",
            "discoveredBy": "puni.sh/directory/repositories",
            "sourceRepoUrl": PUNI_SH,
        })
    return out


def collect_curated_file(path: str | None) -> list[dict]:
    if not path:
        return []
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []
    out: list[dict] = []
    for item in data if isinstance(data, list) else []:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "").strip()
        if not url.startswith("https://"):
            continue
        out.append({
            "url": url,
            "provider": str(item.get("name") or item.get("id") or urllib.parse.urlparse(url).netloc),
            "kind": "aggregator",
            "discoveredBy": "curated-sources.json",
            "sourceRepoUrl": str(item.get("sourceRepoUrl") or ""),
        })
    return out


def collect_curated_urls() -> list[dict]:
    return [
        {
            "url": url,
            "provider": provider,
            "kind": "aggregator",
            "discoveredBy": "curated-sources.json",
            "sourceRepoUrl": upstream,
        }
        for (url, provider, _kind, upstream) in CURATED_AGGREGATORS
    ]


def collect_github_search_urls(token: str, max_pages: int = 5, per_page: int = 100) -> list[dict]:
    """Use GitHub code search to find any `.json` file containing
    `DalamudApiLevel`. Returns a list of source URLs (raw.githubusercontent.com
    URLs) plus the original blob URLs.

    Rate limit: 30 req/min unauthenticated, 5000/hr authenticated.
    """
    if not token:
        return []
    out: list[dict] = []
    seen_paths: set[str] = set()

    # `in:file` keeps the search tight; we want files that have the literal
    # token, not just any text in a PR/issue/etc. The query uses a quoted
    # string (literal match) and a language filter for JSON.
    query = '"DalamudApiLevel" in:file language:JSON'

    for page in range(1, max_pages + 1):
        try:
            data = github_get(
                f"/search/code?q={urllib.parse.quote(query)}&page={page}&per_page={per_page}",
                token=token,
            )
        except urllib.error.HTTPError as e:
            if e.code == 403:  # rate limit or secondary rate limit
                # Backoff and stop
                break
            if e.code == 422:  # validation failed (e.g. query too short)
                break
            break
        items = data.get("items") or []
        for item in items:
            path = item.get("path") or ""
            repo = item.get("repository") or {}
            full_name = repo.get("full_name") or ""
            default_branch = repo.get("default_branch") or "main"
            if not full_name or not path.endswith(".json"):
                continue
            key = f"{full_name}:{path}"
            if key in seen_paths:
                continue
            seen_paths.add(key)
            raw_url = f"https://raw.githubusercontent.com/{full_name}/{default_branch}/{path}"
            blob_url = item.get("html_url") or f"https://github.com/{full_name}/blob/{default_branch}/{path}"
            out.append({
                "url": raw_url,
                "provider": full_name,
                "kind": "scanned",
                "discoveredBy": "github-code-search",
                "sourceRepoUrl": f"https://github.com/{full_name}",
                "blobUrl": blob_url,
            })
        if len(items) < per_page:
            break  # last page
        # Be nice to rate limits
        time.sleep(1.2)
    return out


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def collect(verbose: bool = True, curated_path: str | None = None) -> dict:
    def log(msg: str) -> None:
        if verbose:
            print(msg, file=sys.stderr)

    started = time.time()
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    github_enabled = bool(token)

    log("[1/3] Collecting Puni.sh publisher URLs ...")
    try:
        punish = collect_punish_publisher_urls()
    except Exception as exc:
        punish = []
        log(f"      Puni.sh discovery unavailable: {type(exc).__name__}: {exc}")
    log(f"      got {len(punish)} puni.sh URL(s)")

    log("[2/3] Loading curated aggregator URLs ...")
    curated = collect_curated_file(curated_path) or collect_curated_urls()
    log(f"      got {len(curated)} curated URL(s)")

    if github_enabled:
        log("[3/3] Searching GitHub for 'DalamudApiLevel' in .json files ...")
        github = collect_github_search_urls(token)
        log(f"      got {len(github)} GitHub result(s)")
    else:
        log("[3/3] Skipping GitHub code search (no GITHUB_TOKEN in env)")
        github = []

    sources = curated + punish + github  # curated first (authoritative order)

    # Dedup by URL
    seen_url: set[str] = set()
    unique: list[dict] = []
    for s in sources:
        if s["url"] in seen_url:
            continue
        seen_url.add(s["url"])
        unique.append(s)
    sources = unique

    elapsed = time.time() - started
    return {
        "metadata": {
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "elapsedSeconds": round(elapsed, 2),
            "githubSearchEnabled": github_enabled,
            "sourceCounts": {
                "curated": len(curated),
                "punish": len(punish),
                "githubSearch": len(github),
                "deduplicated": len(sources),
            },
        },
        "sources": sources,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Collect all known JSON sources containing 'DalamudApiLevel'.")
    ap.add_argument("--output", "-o", default="catalog/raw-sources.json",
                    help="Output JSON file (use '-' for stdout; default: %(default)s)")
    ap.add_argument("--quiet", "-q", action="store_true", help="Suppress progress output")
    ap.add_argument("--curated", default="sources/curated-sources.json", help="Human-maintained curated source list")
    args = ap.parse_args()

    data = collect(verbose=not args.quiet, curated_path=args.curated)
    text = json.dumps(data, ensure_ascii=False, indent=2, sort_keys=False)

    if args.output == "-":
        sys.stdout.write(text)
        sys.stdout.write("\n")
    else:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
            f.write("\n")
        counts = data["metadata"]["sourceCounts"]
        print(
            f"\nWrote {args.output}: "
            f"{counts['deduplicated']} source(s) — "
            f"{counts['curated']} curated, {counts['punish']} puni.sh, {counts['githubSearch']} github-search"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
