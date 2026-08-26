#!/usr/bin/env python3
"""Infer plugin permissions from source code and emit catalog/permissions.json.

For every plugin referenced in `enriched-sources.json` (the output of
enrich_metadata.py), this stage looks at the plugin's GitHub repository
(when available) and scans the .cs source files for references to
sensitive Dalamud APIs. The detected categories are written to
`catalog/permissions.json`, which build_sqlite_catalog.py reads to
populate the `plugin_permissions` table.

Permission categories:
    filesystem — local file reads / writes
    network    — HTTP / TCP / UDP / WebSocket calls
    ipc        — inter-plugin communication (IpcSubscriber / Provider)
    commands   — slash-command registration
    hooks      — code / memory patching (SigScanner, Hook<T>, MemoryHelper)

Status values written to each plugin:
    "analyzed"  — source code was scanned, categories may be empty
    "no-source" — no public GitHub source available
    "declared"  — author added a manifest `Permissions` field, no scan
    "no-signals"— scanned but no permission patterns matched

Output JSON shape:
    {
      "metadata": {...stats...},
      "permissions": {
        "Syncing": {
          "categories": ["filesystem", "network", "commands"],
          "sources":    {"filesystem": ["File.ReadAllText"],
                         "network":    ["new HttpClient"],
                         "commands":   ["CommandManager.AddHandler"]},
          "status":     "analyzed",
          "repoUrl":    "https://github.com/goatcorp/Syncing"
        },
        ...
      }
    }

Usage:
    python tools/catalog/analyze_permissions.py \\
        --enriched-sources catalog/enriched-sources.json \\
        --output catalog/permissions.json

Requires Python 3.8+ (stdlib only).
"""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from pathlib import Path
from typing import Any

GITHUB_API = "https://api.github.com"
GITHUB_RAW = "https://raw.githubusercontent.com"

# ---------------------------------------------------------------------------
# Permission taxonomy
# ---------------------------------------------------------------------------

# Each category is a tuple of compiled regex patterns. The first match
# in a file "tags" the file with that category. A plugin accumulates
# every category any of its .cs files matches.
PERMISSION_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    "filesystem": (
        re.compile(r"\bGetPluginConfigDirectory\b"),
        re.compile(r"\bGetPluginDataDirectory\b"),
        re.compile(r"\bGetPluginResourcePath\b"),
        re.compile(r"\bSystem\.IO\.File\b"),
        re.compile(r"\bSystem\.IO\.Directory\b"),
        re.compile(r"\bFile\.(Open|Read|Write|Create|Delete|Exists|Move|Copy|ReadAllText|WriteAllText|AppendAllText|AppendText|ReadAllBytes|WriteAllBytes)\b"),
        re.compile(r"\bDirectory\.(Create|Move|Delete|GetFiles|GetDirectories|GetCurrentDirectory|SetCurrentDirectory|EnumerateFiles|EnumerateDirectories)\b"),
        re.compile(r"\bnew\s+StreamWriter\b"),
        re.compile(r"\bnew\s+StreamReader\b"),
        re.compile(r"\bnew\s+BinaryWriter\b"),
        re.compile(r"\bnew\s+BinaryReader\b"),
        re.compile(r"\bFile\.CreateText\b"),
        re.compile(r"\bFile\.OpenText\b"),
    ),
    "network": (
        re.compile(r"\bnew\s+HttpClient\b"),
        re.compile(r"\bHttpClientHandler\b"),
        re.compile(r"\bnew\s+WebClient\b"),
        re.compile(r"\bHttpWebRequest\b"),
        re.compile(r"\bFtpWebRequest\b"),
        re.compile(r"\bWebSocket\b"),
        re.compile(r"\bClientWebSocket\b"),
        re.compile(r"\bnew\s+Socket\s*\("),
        re.compile(r"\bTcpClient\b"),
        re.compile(r"\bUdpClient\b"),
        re.compile(r"\bNetworkStream\b"),
    ),
    "ipc": (
        re.compile(r"\bIpcSubscriber\b"),
        re.compile(r"\bIpcProvider\b"),
        re.compile(r"\bIpcMessage\b"),
        re.compile(r"\bGetIpcSubscriber\b"),
        re.compile(r"\bGetIpcProvider\b"),
        re.compile(r"\bGetOrCreateDataChannel\b"),
        re.compile(r"\bSendMessage\s*\("),
    ),
    "commands": (
        re.compile(r"\bCommandManager\.AddHandler\b"),
        re.compile(r"\bCommandManager\.RemoveHandler\b"),
    ),
    "hooks": (
        re.compile(r"\bSigScanner\b"),
        re.compile(r"\bISigScanner\b"),
        re.compile(r"\bMemoryHelper\b"),
        re.compile(r"\bnew\s+Hook\s*<"),
        re.compile(r"\bCreateHook\s*\("),
        re.compile(r"\bEnableHook\s*\("),
        re.compile(r"\bDisableHook\s*\("),
    ),
}

# Display order for the runtime UI (most sensitive first).
PERMISSION_DISPLAY_ORDER: tuple[str, ...] = (
    "hooks",
    "network",
    "filesystem",
    "ipc",
    "commands",
)

PERMISSION_LABELS: dict[str, str] = {
    "filesystem": "Reads or writes local files (config, cache, save data)",
    "network":    "Makes network calls (HTTP / TCP / WebSocket)",
    "ipc":        "Talks to other plugins via Dalamud IPC",
    "commands":   "Registers slash commands",
    "hooks":      "Patches game memory or installs low-level hooks",
}

# ---------------------------------------------------------------------------
# GitHub helpers
# ---------------------------------------------------------------------------

_GITHUB_REPO_RE = re.compile(
    r'^https?://github\.com/([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+?)(?:\.git)?/?$'
)

# Paths we never scan — vendor / build / metadata.
_VENDOR_PATH_PREFIXES: tuple[str, ...] = (
    "bin/", "obj/", ".git/", ".github/", ".vs/", ".idea/", ".vscode/",
    "node_modules/", "packages/", "vendor/", "third_party/", "thirdparty/",
    "Properties/", "Resources/",
)


def _parse_github_repo(url: str) -> tuple[str, str] | None:
    if not url:
        return None
    m = _GITHUB_REPO_RE.match(url.strip())
    if not m:
        return None
    return m.group(1), m.group(2)


def _github_get(path: str, token: str | None, timeout: float = 15.0) -> Any:
    """GET a GitHub API endpoint. Returns parsed JSON."""
    hdrs = {
        "User-Agent": "Dalagab-Omega-Catalog-PermissionAnalyzer/1",
        "Accept": "application/vnd.github+json",
    }
    if token:
        hdrs["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(f"{GITHUB_API}{path}", headers=hdrs)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def _raw_get(url: str, timeout: float = 15.0, max_bytes: int = 256 * 1024) -> str:
    """GET a raw.githubusercontent.com file. Returns "" on any failure."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Dalagab-Omega-Catalog-PermissionAnalyzer/1"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(max_bytes + 1)
        if len(raw) > max_bytes:
            return ""
        return raw.decode("utf-8", errors="replace")
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError, ValueError):
        return ""


# ---------------------------------------------------------------------------
# Tree + per-file scanning
# ---------------------------------------------------------------------------

def _list_tree(owner: str, repo: str, branch: str, token: str | None, timeout: float) -> list[str]:
    """Return the list of .cs file paths in the repo, filtered for vendor noise."""
    try:
        data = _github_get(f"/repos/{owner}/{repo}/git/trees/{branch}?recursive=1", token=token, timeout=timeout)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError, ValueError):
        return []
    paths: list[str] = []
    for item in (data.get("tree") or []):
        if item.get("type") != "blob":
            continue
        path = (item.get("path") or "").strip()
        if not path.endswith(".cs"):
            continue
        if any(path.startswith(pfx) for pfx in _VENDOR_PATH_PREFIXES):
            continue
        paths.append(path)
    return paths


def _scan_text_for_permissions(text: str) -> tuple[set[str], dict[str, set[str]]]:
    """Pattern-match a single file. Returns (categories, sources_by_category)."""
    categories: set[str] = set()
    sources: dict[str, set[str]] = defaultdict(set)
    if not text:
        return categories, sources
    for category, patterns in PERMISSION_PATTERNS.items():
        for pattern in patterns:
            m = pattern.search(text)
            if not m:
                continue
            categories.add(category)
            # Record the first match in each file as the "source" snippet
            # (capped at 60 chars for compactness in the UI).
            sources[category].add(m.group(0)[:60])
            break  # one match per category per file is enough
    return categories, sources


# ---------------------------------------------------------------------------
# Per-repo analysis
# ---------------------------------------------------------------------------

def _analyze_repo(
    owner: str,
    repo: str,
    token: str | None,
    *,
    timeout: float,
    max_files_per_repo: int,
    max_file_bytes: int,
    workers: int,
) -> tuple[set[str], dict[str, set[str]], dict[str, int]]:
    """Analyze one GitHub repo. Returns (categories, sources, stats)."""
    stats = {"filesScanned": 0, "treeTruncated": False}
    categories: set[str] = set()
    sources: dict[str, set[str]] = defaultdict(set)

    branch = ""
    for candidate in ("main", "master"):
        paths = _list_tree(owner, repo, candidate, token=token, timeout=timeout)
        if paths:
            branch = candidate
            break
    if not branch:
        return categories, sources, stats

    if len(paths) > max_files_per_repo:
        stats["treeTruncated"] = True
        paths = paths[:max_files_per_repo]

    # Fetch + scan in parallel
    def _scan_one(path: str) -> tuple[set[str], dict[str, set[str]]]:
        url = f"{GITHUB_RAW}/{owner}/{repo}/{branch}/{path}"
        text = _raw_get(url, timeout=timeout, max_bytes=max_file_bytes)
        return _scan_text_for_permissions(text)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(8, workers))) as ex:
        for cats, srcs in ex.map(_scan_one, paths):
            stats["filesScanned"] += 1
            categories |= cats
            for cat, snips in srcs.items():
                sources[cat] |= snips

    return categories, sources, stats


# ---------------------------------------------------------------------------
# Plugin URL selection
# ---------------------------------------------------------------------------

def _plugin_repo_url(plugin: dict[str, Any]) -> str:
    for key in ("RepoUrl", "repoUrl", "Website", "WebsiteUrl", "Homepage", "HomepageUrl", "ProjectUrl"):
        value = (plugin.get(key) or "").strip()
        if value.startswith(("https://", "http://")):
            return value
    return ""


def _read_manifest_permissions(plugin: dict[str, Any]) -> list[str]:
    """Read a `Permissions` field from a plugin entry (list or comma-string)."""
    declared = plugin.get("Permissions") or plugin.get("permissions")
    if isinstance(declared, list):
        return [str(x).strip() for x in declared if str(x).strip()]
    if isinstance(declared, str) and declared.strip():
        return [x.strip() for x in declared.split(",") if x.strip()]
    return []


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def analyze(
    enriched_doc: dict[str, Any],
    token: str | None,
    *,
    timeout: float = 10.0,
    max_files_per_repo: int = 50,
    max_file_bytes: int = 256 * 1024,
    workers: int = 4,
) -> dict[str, Any]:
    """Walk every plugin in enriched_doc, scan GitHub source, and emit
    a permissions map keyed by InternalName.

    Returns a dict with `metadata` and `permissions` (the on-disk format).
    """
    # 1) Collect every plugin (by InternalName), with their repo URL.
    plugins: dict[str, dict[str, Any]] = {}
    for source in enriched_doc.get("sources") or []:
        if not isinstance(source, dict):
            continue
        for plugin in (source.get("plugins") or []):
            if not isinstance(plugin, dict):
                continue
            internal = (plugin.get("internalName") or plugin.get("InternalName") or "").strip()
            if not internal:
                continue
            entry = plugins.setdefault(internal, {
                "url": _plugin_repo_url(plugin),
                "declared": _read_manifest_permissions(plugin),
            })
            # Prefer non-empty URL over empty
            if not entry["url"]:
                entry["url"] = _plugin_repo_url(plugin)
            # Keep any manifest declarations
            if entry.get("declared") is None or not entry["declared"]:
                d = _read_manifest_permissions(plugin)
                if d:
                    entry["declared"] = d

    # 2) Group by GitHub repo to amortize the tree call.
    repo_to_internals: dict[tuple[str, str], list[str]] = {}
    for internal, info in plugins.items():
        gh = _parse_github_repo(info["url"])
        if gh:
            repo_to_internals.setdefault(gh, []).append(internal)

    # 3) Per-repo analysis.
    repo_results: dict[tuple[str, str], tuple[set[str], dict[str, set[str]], dict[str, int]]] = {}
    if repo_to_internals:
        def _analyze_one(key: tuple[str, str]) -> tuple[tuple[str, str], tuple[set[str], dict[str, set[str]], dict[str, int]]]:
            return key, _analyze_repo(
                key[0], key[1], token,
                timeout=timeout,
                max_files_per_repo=max_files_per_repo,
                max_file_bytes=max_file_bytes,
                workers=workers,
            )
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(8, workers))) as ex:
            for key, result in ex.map(_analyze_one, repo_to_internals):
                repo_results[key] = result

    # 4) Per-plugin output.
    out_permissions: dict[str, dict[str, Any]] = {}
    analyzed = 0
    manifest_declared = 0
    no_source = 0
    files_scanned_total = 0
    repos_truncated = 0
    category_counts: dict[str, int] = defaultdict(int)

    for internal, info in plugins.items():
        declared = info.get("declared") or []
        url = info["url"]
        gh = _parse_github_repo(url)
        repo_result = repo_results.get(gh) if gh else None

        categories: set[str] = set(declared)
        sources: dict[str, set[str]] = {}
        status: str

        if repo_result is not None:
            cats, srcs, stats = repo_result
            files_scanned_total += stats["filesScanned"]
            if stats.get("treeTruncated"):
                repos_truncated += 1
            for cat in cats:
                categories.add(cat)
            for cat, snips in srcs.items():
                sources[cat] |= snips
            status = "analyzed" if cats else "no-signals"
            if not cats and not declared:
                status = "no-signals"
            analyzed += 1
            if declared:
                manifest_declared += 1
        else:
            if declared:
                status = "declared"
                analyzed += 1
                manifest_declared += 1
            else:
                status = "no-source"
                no_source += 1

        # Sort by display order
        ordered = [c for c in PERMISSION_DISPLAY_ORDER if c in categories]
        for c in categories:
            if c not in ordered:
                ordered.append(c)

        for c in ordered:
            category_counts[c] += 1

        out_permissions[internal] = {
            "categories": ordered,
            "sources": {cat: sorted(snips) for cat, snips in sources.items() if cat in ordered},
            "status": status,
            "repoUrl": url,
        }

    return {
        "metadata": {
            "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
            "pluginCount": len(plugins),
            "analyzedCount": analyzed,
            "manifestDeclaredCount": manifest_declared,
            "noSourceCount": no_source,
            "githubReposScanned": len(repo_results),
            "filesScanned": files_scanned_total,
            "reposWithTruncatedTree": repos_truncated,
            "categoryCounts": dict(category_counts),
        },
        "permissions": out_permissions,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Scan plugin source for permission signals.")
    ap.add_argument("--enriched-sources", required=True, type=Path,
                    help="Path to enriched-sources.json (Stage 2 output).")
    ap.add_argument("--output", "-o", default="catalog/permissions.json",
                    help="Output JSON file (use '-' for stdout; default: %(default)s)")
    ap.add_argument("--token-env", default="GITHUB_TOKEN",
                    help="Name of the env var holding the GitHub token (default: GITHUB_TOKEN). "
                         "Set to empty to force unauthenticated access.")
    ap.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout (default: %(default)s)")
    ap.add_argument("--max-files-per-repo", type=int, default=50,
                    help="Cap on .cs files scanned per repo (default: %(default)s)")
    ap.add_argument("--max-file-bytes", type=int, default=256 * 1024,
                    help="Cap on bytes downloaded per file (default: %(default)s)")
    ap.add_argument("--workers", type=int, default=4, help="Parallel raw-file fetchers (default: %(default)s)")
    ap.add_argument("--quiet", "-q", action="store_true", help="Suppress progress output")
    args = ap.parse_args()

    if not args.quiet:
        print(f"Loading {args.enriched_sources} ...", file=sys.stderr)

    with open(args.enriched_sources, "r", encoding="utf-8") as f:
        enriched = json.load(f)

    token: str | None = None
    if args.token_env:
        token = os.environ.get(args.token_env) or os.environ.get("GH_TOKEN")
    if not args.quiet:
        print(f"GitHub token enabled: {bool(token)}", file=sys.stderr)
        if not token:
            print("WARNING: no GitHub token set; file-tree API will hit unauth rate limit (60/hr).",
                  file=sys.stderr)

    if not args.quiet:
        print("Scanning plugin source code ...", file=sys.stderr)

    out = analyze(
        enriched,
        token=token,
        timeout=args.timeout,
        max_files_per_repo=args.max_files_per_repo,
        max_file_bytes=args.max_file_bytes,
        workers=args.workers,
    )

    text = json.dumps(out, ensure_ascii=False, indent=2, sort_keys=False)
    if args.output == "-":
        sys.stdout.write(text)
        sys.stdout.write("\n")
    else:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
            f.write("\n")
        meta = out["metadata"]
        if not args.quiet:
            print(
                f"\nWrote {args.output}: {meta['analyzedCount']}/{meta['pluginCount']} plugin(s) "
                f"analyzed (declared={meta['manifestDeclaredCount']}, "
                f"no-source={meta['noSourceCount']}, "
                f"repos={meta['githubReposScanned']}, "
                f"files={meta['filesScanned']}). "
                f"Categories: {meta['categoryCounts']}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
