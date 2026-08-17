#!/usr/bin/env python3
"""Collect public OSV vulnerability records for NuGet dependencies observed by Omega."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sqlite3
import time
import urllib.error
import urllib.request
from collections.abc import Iterable
from contextlib import closing
from pathlib import Path


OSV_QUERY_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULNERABILITY_URL = "https://api.osv.dev/v1/vulns/"
OSV_WEB_URL = "https://osv.dev/vulnerability/"
USER_AGENT = "Dalagab-Omega-Advisory-Collector/1.0 (+https://github.com/dalagab/omega)"
QUERY_BATCH_SIZE = 100
MAX_PACKAGES = 2_000
HTTP_ATTEMPTS = 3
NUGET_DEPENDENCY_KINDS = ("nuget", "nuget-lock", "nuget-resolved")


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def observed_nuget_packages(database: Path, max_packages: int) -> list[tuple[str, str]]:
    with closing(sqlite3.connect(database)) as db:
        tables = {str(row[0]) for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {"plugin_security_dependencies", "plugin_security_current"}.issubset(tables):
            # A brand-new catalog has not been through the scanner yet. The first scan can
            # proceed without advisory input; the next run will have observed package data.
            return []
        kind_placeholders = ",".join("?" for _ in NUGET_DEPENDENCY_KINDS)
        rows = db.execute(f"""
            SELECT MIN(d.name) AS name,COALESCE(NULLIF(TRIM(d.resolved_version),''),NULLIF(TRIM(d.version),'')) AS version,COUNT(*) AS uses
              FROM plugin_security_dependencies d
             WHERE lower(d.kind) IN ({kind_placeholders}) AND TRIM(d.name)<>''
               AND COALESCE(NULLIF(TRIM(d.resolved_version),''),NULLIF(TRIM(d.version),''))<>''
               AND EXISTS (
                    SELECT 1 FROM plugin_security_current c
                     WHERE c.scan_id=d.scan_id AND c.status='complete'
               )
             GROUP BY lower(TRIM(d.name)),version
             ORDER BY uses DESC,name COLLATE NOCASE,version COLLATE NOCASE
             LIMIT ?
        """, (*NUGET_DEPENDENCY_KINDS, max(0, min(max_packages, MAX_PACKAGES)))).fetchall()
    return [(str(name), str(version)) for name, version, _uses in rows]


def observed_nuget_index(index_path: Path, max_packages: int) -> list[tuple[str, str]]:
    """Read exact NuGet package/version pairs from the Security Evidence v2 contract.

    Production OSV collection consumes this purpose-built index rather than reaching
    into the mutable SQLite working projection. This makes the advisory boundary
    explicit and independently inspectable.
    """
    document = json.loads(index_path.read_text(encoding="utf-8-sig"))
    if not isinstance(document, dict) or document.get("schema") != "omega.security-evidence.nuget-index.v2":
        raise ValueError(f"unsupported NuGet evidence index: {document.get('schema') if isinstance(document, dict) else type(document).__name__!r}")
    rows = document.get("packages") or []
    if not isinstance(rows, list):
        raise ValueError("NuGet evidence index packages must be a list")
    pairs: dict[tuple[str, str], tuple[str, str, int]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or "").strip()
        version = str(row.get("version") or "").strip()
        if not name or not version:
            continue
        key = (name.casefold(), version)
        observations = max(0, int(row.get("observations") or 0))
        previous = pairs.get(key)
        if previous is None or observations > previous[2]:
            pairs[key] = (name, version, observations)
    ordered = sorted(pairs.values(), key=lambda item: (-item[2], item[0].casefold(), item[1].casefold()))
    limit = max(0, min(int(max_packages), MAX_PACKAGES))
    return [(name, version) for name, version, _observations in ordered[:limit]]


def _request_json(request: urllib.request.Request, timeout: float) -> dict:
    last_error: Exception | None = None
    for attempt in range(HTTP_ATTEMPTS):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            last_error = exc
            if attempt + 1 < HTTP_ATTEMPTS:
                time.sleep(1.5 * (2 ** attempt))
    assert last_error is not None
    raise last_error


def post_json(url: str, payload: dict, timeout: float) -> dict:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        headers={"Accept": "application/json", "Content-Type": "application/json", "User-Agent": USER_AGENT},
        method="POST",
    )
    return _request_json(request, timeout)


def get_json(url: str, timeout: float) -> dict:
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": USER_AGENT})
    return _request_json(request, timeout)


def chunks(values: list[tuple[str, str]], size: int) -> Iterable[list[tuple[str, str]]]:
    for index in range(0, len(values), size):
        yield values[index:index + size]


def osv_ids_for_packages(packages: list[tuple[str, str]], timeout: float) -> dict[tuple[str, str], list[str]]:
    matches: dict[tuple[str, str], list[str]] = {}
    for batch in chunks(packages, QUERY_BATCH_SIZE):
        response = post_json(
            OSV_QUERY_BATCH_URL,
            {"queries": [{"package": {"name": name, "ecosystem": "NuGet"}, "version": version} for name, version in batch]},
            timeout,
        )
        results = response.get("results") if isinstance(response.get("results"), list) else []
        if len(results) != len(batch):
            raise ValueError(f"OSV querybatch returned {len(results)} results for {len(batch)} queries")
        for package, result in zip(batch, results):
            vulnerabilities = result.get("vulns") if isinstance(result, dict) and isinstance(result.get("vulns"), list) else []
            ids = sorted({str(item.get("id") or "").strip() for item in vulnerabilities if isinstance(item, dict) and str(item.get("id") or "").strip()})
            if ids:
                matches[package] = ids
    return matches


def normalize_severity(record: dict, package_name: str) -> str:
    candidates: list[str] = []
    database = record.get("database_specific") if isinstance(record.get("database_specific"), dict) else {}
    candidates.append(str(database.get("severity") or ""))
    for affected in record.get("affected") or []:
        package = affected.get("package") if isinstance(affected, dict) and isinstance(affected.get("package"), dict) else {}
        if str(package.get("name") or "").casefold() != package_name.casefold():
            continue
        ecosystem = affected.get("ecosystem_specific") if isinstance(affected.get("ecosystem_specific"), dict) else {}
        candidates.append(str(ecosystem.get("severity") or ""))
    value = next((candidate.strip().casefold() for candidate in candidates if candidate.strip()), "unknown")
    return {"moderate": "medium", "important": "high"}.get(value, value)


def normalized_advisories(matches: dict[tuple[str, str], list[str]], timeout: float) -> list[dict]:
    details: dict[str, dict] = {}
    for advisory_id in sorted({advisory_id for ids in matches.values() for advisory_id in ids}, key=str.casefold):
        details[advisory_id] = get_json(f"{OSV_VULNERABILITY_URL}{advisory_id}", timeout)

    advisories: list[dict] = []
    for (package, version), ids in sorted(matches.items(), key=lambda item: (item[0][0].casefold(), item[0][1])):
        for advisory_id in ids:
            record = details[advisory_id]
            title = str(record.get("summary") or record.get("id") or advisory_id).splitlines()[0][:500]
            aliases = [str(alias) for alias in record.get("aliases") or [] if str(alias)]
            advisories.append({
                "id": advisory_id,
                "aliases": aliases,
                "componentKind": "nuget",
                "name": package,
                "affectedVersions": [version],
                "severity": normalize_severity(record, package),
                "title": title,
                "url": f"{OSV_WEB_URL}{advisory_id}",
                "source": "OSV",
            })
    return advisories


def collect_packages(packages: list[tuple[str, str]], output: Path, timeout: float = 20.0) -> dict:
    matches = osv_ids_for_packages(packages, timeout) if packages else {}
    advisories = normalized_advisories(matches, timeout) if matches else []
    document = {
        "schema": "omega.public-advisories.v1",
        "generatedAtUtc": utc_now(),
        "source": "OSV",
        "ecosystem": "NuGet",
        "queriedPackages": len(packages),
        "matchedPackages": len(matches),
        "advisories": advisories,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return document


def collect(database: Path, output: Path, timeout: float = 20.0, max_packages: int = MAX_PACKAGES) -> dict:
    """Compatibility collector for archived SQLite evidence and local tooling."""
    return collect_packages(observed_nuget_packages(database, max_packages), output, timeout)


def collect_from_nuget_index(index_path: Path, output: Path, timeout: float = 20.0, max_packages: int = MAX_PACKAGES) -> dict:
    """Production collector for Security Evidence v2."""
    return collect_packages(observed_nuget_index(index_path, max_packages), output, timeout)


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect public OSV advisories for exact NuGet dependencies observed by Omega")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--database", type=Path, help="Compatibility input: SQLite evidence database")
    source.add_argument("--nuget-index", type=Path, help="Security Evidence v2 indexes/nuget.json (production input)")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--max-packages", type=int, default=MAX_PACKAGES)
    args = parser.parse_args()
    selected = args.nuget_index or args.database
    if selected is None or not selected.exists():
        raise SystemExit(f"Advisory input does not exist: {selected}")
    try:
        if args.nuget_index is not None:
            result = collect_from_nuget_index(args.nuget_index, args.output, args.timeout, args.max_packages)
        else:
            result = collect(args.database, args.output, args.timeout, args.max_packages)
    except (OSError, ValueError, urllib.error.URLError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Public advisory collection failed: {type(exc).__name__}: {exc}") from exc
    print(json.dumps({key: result[key] for key in ("queriedPackages", "matchedPackages", "generatedAtUtc")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
