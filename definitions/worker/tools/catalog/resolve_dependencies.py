#!/usr/bin/env python3
"""Resolve plugin-to-plugin dependencies and inject them into the catalog.

For every plugin in `db_dir` (the catalog-db/ directory used by
build_catalog.py), this module figures out which other plugins it requires
at install time. The result is written back into the plugin's manifest
as two new fields:

    OmegaDependencies:        ["Penumbra", "Glamourer", "Brio"]   (InternalNames)
    OmegaDependencySources:   {"Penumbra": "override", "Glamourer": "override",
                              "Brio": "override"}

The runtime reads `OmegaDependencies` and uses it to surface a
"you also need X, Y, Z" picker on install.

Sources of truth (priority order):
  1. `overrides_path` (typically sources/plugin-dependencies.json) —
     curated manual map. Authoritative for chains the README scan
     misses (e.g. Syncing needs Penumbra + Glamourer + Brio).
  2. The plugin manifest itself — if a future plugin author declares a
     `Dependencies` or `RequiredPlugins` field we honour it.
  3. README scan — best-effort, looks for natural-language patterns
     like "Requires: Penumbra, Glamourer" in the GitHub repo's README.

Every candidate dependency is cross-referenced against the catalog so
only plugins that actually exist (by Name or InternalName) are kept.
Self-references and unresolvable names are silently dropped. Cycles are
detected and reported but do not block the build.

Public entry point:
    resolve_database_records(db_dir, overrides_path, *, timeout, max_readme_bytes,
                             workers, now_utc) -> dict

Requires Python 3.8+ (stdlib only).
"""
from __future__ import annotations

import concurrent.futures
import datetime as dt
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# Each pattern captures the dependency list in group(1). Case-insensitive.
# Patterns are intentionally narrow — false negatives are fine because
# the manual override file is the source of truth.
README_DEPENDENCY_PATTERNS: tuple[re.Pattern[str], ...] = (
    # "Requires: X, Y, Z"  /  "Dependencies: X, Y, Z"  /  "Prerequisites: X, Y, Z"
    re.compile(
        r'\b(?:requires?|requirements?|dependencies?|prerequisites?|required\s+plugins?)\s*[:\-]\s*'
        r'([^\n\.;]+?)(?:\.|$|\n)',
        re.IGNORECASE,
    ),
    # "You will also need: X, Y, Z"  /  "You'll need: X, Y, Z"
    re.compile(
        r"\byou(?:'ll|\s+will)?\s+(?:also\s+)?need(?:s|ed)?\s*[:\-]?\s*"
        r'([^\n\.;]+?)(?:\.|$|\n)',
        re.IGNORECASE,
    ),
    # "Install X, Y and Z first/too/as well"
    re.compile(
        r'\binstall\s+([^\n\.;]+?)\s+(?:first|too|as\s+well)\b',
        re.IGNORECASE,
    ),
    # "Must also have/install X, Y, Z"
    re.compile(
        r'\bmust\s+(?:also\s+)?(?:have|install)\s+([^\n\.;]+?)(?:\.|$|\n)',
        re.IGNORECASE,
    ),
)

# Splits a captured list like "Penumbra, Glamourer and Brio" into pieces.
_SPLIT_RE = re.compile(r'\s*(?:,|\band\b|\bor\b)\s*', re.IGNORECASE)

# Normalizes a name for matching: lowercase, strip spaces/dashes/underscores/dots.
_NAME_NORMALIZE_RE = re.compile(r'[\s_\-\.]+')

# GitHub URL → (owner, repo) parser.
_GITHUB_REPO_RE = re.compile(
    r'^https?://github\.com/([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+?)(?:\.git)?/?$'
)

# Common README file names we will try.
_README_NAMES: tuple[str, ...] = ("README.md", "README.MD", "readme.md", "README", "Readme.md")

# Most public Dalamud plugins are on `main`; older ones are on `master`.
_README_BRANCHES: tuple[str, ...] = ("main", "master")


# ---------------------------------------------------------------------------
# Manifest parsing (matches site_enrichment)
# ---------------------------------------------------------------------------

def _extract_plugin_array(root: Any) -> list[dict[str, Any]]:
    """Pull the plugin list out of either a list manifest or a {plugins:[...]} dict."""
    if isinstance(root, list):
        return [x for x in root if isinstance(x, dict)]
    if isinstance(root, dict):
        for key, value in root.items():
            if key.lower() in {"plugins", "pluginmaster"} and isinstance(value, list):
                return [x for x in value if isinstance(x, dict)]
    return []


def _internal_name(plugin: dict[str, Any]) -> str:
    return (plugin.get("InternalName") or "").strip()


def _normalize(value: str) -> str:
    return _NAME_NORMALIZE_RE.sub('', value or '').lower()


# ---------------------------------------------------------------------------
# Overrides
# ---------------------------------------------------------------------------

def _load_overrides(path: Path | None) -> dict[str, list[str]]:
    """Load {pluginName: [depName, ...]} from disk. Metadata keys (starting
    with `_`) are ignored. Returns a normalized key map so lookups are
    case-insensitive against either Name or InternalName.
    """
    if path is None or not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            doc = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(doc, dict):
        return {}
    out: dict[str, list[str]] = {}
    for key, value in doc.items():
        if not isinstance(key, str) or key.startswith("_"):
            continue
        if not isinstance(value, list):
            continue
        cleaned = [v for v in value if isinstance(v, str) and v.strip()]
        out[_normalize(key)] = cleaned
    return out


# ---------------------------------------------------------------------------
# Name resolution
# ---------------------------------------------------------------------------

def _resolve_dep_name(raw: str, index: dict[str, str], self_internal: str) -> str | None:
    """Map a free-text dep name (e.g. 'Penumbra') to an InternalName.
    Returns None if the name isn't in the catalog or resolves to self.
    """
    norm = _normalize(raw)
    if not norm:
        return None
    internal = index.get(norm)
    if not internal:
        return None
    if _normalize(internal) == _normalize(self_internal):
        return None
    return internal


def _resolve_dep_list(values: list[str], index: dict[str, str], self_internal: str) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for v in values:
        dep = _resolve_dep_name(v, index, self_internal)
        if not dep:
            continue
        if _normalize(dep) in seen:
            continue
        seen.add(_normalize(dep))
        out.append(dep)
    return out


# ---------------------------------------------------------------------------
# GitHub README scan
# ---------------------------------------------------------------------------

def _parse_github_repo(url: str) -> tuple[str, str] | None:
    if not url:
        return None
    m = _GITHUB_REPO_RE.match(url.strip())
    if not m:
        return None
    return m.group(1), m.group(2)


def _fetch_github_readme(owner: str, repo: str, timeout: float, max_bytes: int) -> str:
    """Try to fetch the README from `main` then `master` and return its text.
    Returns "" on any failure.
    """
    for branch in _README_BRANCHES:
        for name in _README_NAMES:
            url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{name}"
            try:
                req = urllib.request.Request(
                    url,
                    headers={
                        "User-Agent": "Dalagab-Omega-Catalog-DepResolver/1",
                        "Accept": "text/plain;q=0.9, */*;q=0.5",
                    },
                )
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    raw = resp.read(max_bytes + 1)
                if len(raw) > max_bytes:
                    continue  # Try next branch/name
                return raw.decode("utf-8", errors="replace")
            except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError, ValueError):
                continue
    return ""


def _extract_dependencies_from_readme(readme: str) -> list[str]:
    """Scan a README for natural-language dependency mentions."""
    if not readme:
        return []
    candidates: list[str] = []
    for pattern in README_DEPENDENCY_PATTERNS:
        for match in pattern.finditer(readme):
            group = (match.group(1) or "").strip()
            if not group:
                continue
            for part in _SPLIT_RE.split(group):
                part = part.strip(" \t`\"'()[]{}*_")
                if len(part) < 3 or len(part) > 60:
                    continue
                if part.lower() in {
                    "dalamud", "ffxiv", "xivlauncher", "plugin", "plugins",
                    "the", "and", "or", "etc", "latest", "newer",
                }:
                    continue
                candidates.append(part)
    # Dedup preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for c in candidates:
        key = c.lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append(c)
    return unique


# ---------------------------------------------------------------------------
# Cycle detection
# ---------------------------------------------------------------------------

def _find_cycles(deps: dict[str, list[str]]) -> list[list[str]]:
    """Return one representative cycle for every distinct dependency cycle."""
    cycles: list[list[str]] = []
    seen: set[tuple[str, ...]] = set()

    def visit(node: str, path: list[str], on_stack: set[str]) -> None:
        if node in on_stack:
            idx = path.index(node)
            cycle = path[idx:] + [node]
            key = tuple(sorted(set(cycle)))
            if key not in seen:
                seen.add(key)
                cycles.append(cycle)
            return
        on_stack.add(node)
        path.append(node)
        for dep in deps.get(node, []):
            visit(dep, path, on_stack)
        path.pop()
        on_stack.discard(node)

    for node in deps:
        visit(node, [], set())
    return cycles


# ---------------------------------------------------------------------------
# Per-plugin resolution
# ---------------------------------------------------------------------------

def _resolve_for_plugin(
    plugin: dict[str, Any],
    internal: str,
    name: str,
    index: dict[str, str],
    overrides: dict[str, list[str]],
    readme_text: str,
) -> tuple[list[str], dict[str, str], list[tuple[str, str]]]:
    """Compute the final dependency list for a single plugin.

    Returns (resolved_deps, sources_by_dep, unresolved_references).
    """
    sources: dict[str, str] = {}
    final: list[str] = []
    unresolved: list[tuple[str, str]] = []

    # 1) Override file — try InternalName, then Name (both normalized).
    override_entry = overrides.get(_normalize(internal))
    if override_entry is None and name:
        override_entry = overrides.get(_normalize(name))
    if override_entry is not None:
        for raw_name in override_entry:
            dep = _resolve_dep_name(raw_name, index, internal)
            if dep:
                sources[dep] = "override"
                if _normalize(dep) not in {_normalize(x) for x in final}:
                    final.append(dep)
            else:
                unresolved.append((internal, raw_name))
        if final:
            return final, sources, unresolved

    # 2) Manifest-level dependencies (forward-compat).
    manifest_deps = plugin.get("Dependencies") or plugin.get("RequiredPlugins")
    if isinstance(manifest_deps, list):
        for raw in manifest_deps:
            if not isinstance(raw, str) or not raw.strip():
                continue
            dep = _resolve_dep_name(raw, index, internal)
            if dep:
                sources.setdefault(dep, "manifest")
                if _normalize(dep) not in {_normalize(x) for x in final}:
                    final.append(dep)
            else:
                unresolved.append((internal, raw))

    # 3) README scan (only if readme was provided).
    if readme_text:
        readme_candidates = _extract_dependencies_from_readme(readme_text)
        for raw in readme_candidates:
            dep = _resolve_dep_name(raw, index, internal)
            if dep:
                sources.setdefault(dep, "readme")
                if _normalize(dep) not in {_normalize(x) for x in final}:
                    final.append(dep)
            else:
                unresolved.append((internal, raw))

    return final, sources, unresolved


# ---------------------------------------------------------------------------
# Main entry point (used by build_catalog.py)
# ---------------------------------------------------------------------------

def resolve_database_records(
    db_dir: Path,
    overrides_path: Path | None,
    *,
    tolerant_loads,
    sha256_text,
    timeout: float = 10.0,
    max_readme_bytes: int = 64 * 1024,
    workers: int = 4,
    now_utc: str,
) -> dict[str, Any]:
    """Walk every catalog-db/*.json record, resolve plugin dependencies, and
    inject them into each plugin's manifest.

    Args:
        db_dir: path to the catalog-db/ directory produced by build_catalog.py
        overrides_path: path to sources/plugin-dependencies.json (or None)
        tolerant_loads: build_catalog.tolerant_loads (for parsing the manifest)
        sha256_text: build_catalog.sha256_text (for re-hashing the manifest)
        timeout: per-request GitHub README timeout
        max_readme_bytes: max bytes of README to scan per plugin
        workers: parallel GitHub README fetchers
        now_utc: ISO timestamp used in stats

    Returns:
        A stats dict with `pluginCount`, `enrichedPluginCount`, `overrideHits`,
        `manifestHits`, `readmeHits`, `unresolvedReferences`, `circularDependencies`.
    """
    # 1) First pass: load records, build the plugin name index.
    records: list[tuple[Path, dict[str, Any], Any, list[dict[str, Any]]]] = []
    index: dict[str, str] = {}
    for record_path in sorted(db_dir.glob("*.json")):
        try:
            with open(record_path, "r", encoding="utf-8") as f:
                record = json.load(f)
            root = tolerant_loads(str(record.get("ManifestJson", "")))
        except (OSError, json.JSONDecodeError, ValueError):
            continue
        plugins = _extract_plugin_array(root)
        for plugin in plugins:
            internal = _internal_name(plugin)
            name = (plugin.get("Name") or "").strip()
            if internal:
                key = _normalize(internal)
                if key not in index:
                    index[key] = internal
                if name:
                    name_key = _normalize(name)
                    if name_key not in index:
                        index[name_key] = internal
        records.append((record_path, record, root, plugins))

    overrides = _load_overrides(overrides_path)

    # 2) Build the set of GitHub repos whose READMEs we need to scan.
    repo_to_plugin: dict[tuple[str, str], list[tuple[dict[str, Any], str, str]]] = {}
    for _rp, _rec, _root, plugins in records:
        for plugin in plugins:
            internal = _internal_name(plugin)
            if not internal:
                continue
            # Skip if an override already covers this plugin.
            name = (plugin.get("Name") or "").strip()
            if overrides.get(_normalize(internal)) is not None:
                continue
            if name and overrides.get(_normalize(name)) is not None:
                continue
            # No manifest deps either?
            if plugin.get("Dependencies") or plugin.get("RequiredPlugins"):
                continue
            # Look for a GitHub URL on the plugin.
            for field in ("RepoUrl", "Website", "WebsiteUrl", "Homepage", "HomepageUrl", "ProjectUrl"):
                url = (plugin.get(field) or "").strip()
                gh = _parse_github_repo(url)
                if gh:
                    repo_to_plugin.setdefault(gh, []).append((plugin, internal, name))
                    break

    # 3) Fetch each repo's README once and share the result.
    repo_readmes: dict[tuple[str, str], str] = {}
    if repo_to_plugin:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(16, workers))) as ex:
            futures = {
                ex.submit(_fetch_github_readme, owner, repo, timeout, max_readme_bytes): (owner, repo)
                for (owner, repo) in repo_to_plugin
            }
            for fut, key in futures.items():
                try:
                    repo_readmes[key] = fut.result() or ""
                except Exception:
                    repo_readmes[key] = ""

    # 4) Per-plugin resolution + injection.
    enriched = 0
    override_hits = 0
    manifest_hits = 0
    readme_hits = 0
    all_unresolved: list[tuple[str, str]] = []
    final_deps: dict[str, list[str]] = {}

    for record_path, record, root, plugins in records:
        rewritten = False
        for plugin in plugins:
            internal = _internal_name(plugin)
            if not internal:
                continue
            name = (plugin.get("Name") or "").strip()
            readme_text = ""
            for field in ("RepoUrl", "Website", "WebsiteUrl", "Homepage", "HomepageUrl", "ProjectUrl"):
                url = (plugin.get(field) or "").strip()
                gh = _parse_github_repo(url)
                if gh:
                    readme_text = repo_readmes.get(gh, "")
                    break

            deps, sources, unresolved = _resolve_for_plugin(
                plugin=plugin,
                internal=internal,
                name=name,
                index=index,
                overrides=overrides,
                readme_text=readme_text,
            )
            all_unresolved.extend(unresolved)

            # Update counters
            for src in sources.values():
                if src == "override":
                    override_hits += 1
                elif src == "manifest":
                    manifest_hits += 1
                elif src == "readme":
                    readme_hits += 1
                if src == "override" and len(sources) == 1 and not deps:
                    # override listed deps but all were unresolvable
                    pass

            # Inject / clear
            if deps:
                plugin["OmegaDependencies"] = deps
                plugin["OmegaDependencySources"] = sources
                enriched += 1
                final_deps[internal] = deps
                rewritten = True
            else:
                if "OmegaDependencies" in plugin:
                    del plugin["OmegaDependencies"]
                    plugin.pop("OmegaDependencySources", None)
                    rewritten = True

        if rewritten:
            manifest = json.dumps(root, ensure_ascii=False, separators=(",", ":"))
            record["ManifestJson"] = manifest
            record["ContentSha256"] = sha256_text(manifest)
            record["CheckedAtUtc"] = now_utc
            record_path.write_text(
                json.dumps(record, ensure_ascii=False, separators=(",", ":")),
                encoding="utf-8",
            )

    cycles = _find_cycles(final_deps)

    return {
        "pluginCount": sum(len(plugins) for _, _, _, plugins in records),
        "enrichedPluginCount": enriched,
        "overrideHits": override_hits,
        "manifestHits": manifest_hits,
        "readmeHits": readme_hits,
        "githubReposScanned": len(repo_readmes),
        "unresolvedReferences": all_unresolved,
        "circularDependencies": cycles,
    }
