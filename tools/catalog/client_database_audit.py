#!/usr/bin/env python3
"""Report and optionally gate Omega's downloadable client SQLite footprint."""
from __future__ import annotations
import argparse, json, shutil, sqlite3, tempfile, zipfile
from pathlib import Path
from typing import Any

PROHIBITED_TABLES = {
    "manifest_observations", "manifest_source_candidates", "source_repositories", "source_repository_aliases",
    "plugin_identity_aliases", "plugin_tags", "plugin_images", "plugin_search", "websites", "presentation",
    "plugin_security_scans", "plugin_security_findings", "plugin_security_dependencies", "plugin_security_current",
    "artifact_blobs", "artifact_analyses", "source_analyses", "source_revisions", "artifact_source_attributions",
}


def _rows(db: sqlite3.Connection, table: str) -> int:
    try: return int(db.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])
    except sqlite3.Error: return -1


def audit(path: Path) -> dict[str, Any]:
    with sqlite3.connect(path) as db:
        integrity = str(db.execute("PRAGMA integrity_check").fetchone()[0])
        tables = [str(r[0]) for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        usage: dict[str, int] = {}
        index_owners = {str(name): str(table) for name, table in db.execute("SELECT name,tbl_name FROM sqlite_master WHERE type='index'")}
        try:
            for name, size in db.execute("SELECT name,COALESCE(SUM(pgsize),0) FROM dbstat GROUP BY name"):
                owner = index_owners.get(str(name), str(name))
                usage[owner] = usage.get(owner, 0) + int(size or 0)
        except sqlite3.Error:
            pass
        table_rows = {name: _rows(db, name) for name in tables}
        meta = dict(db.execute("SELECT key,value FROM catalog_meta")) if "catalog_meta" in tables else {}
    leaked = sorted(set(tables) & PROHIBITED_TABLES)
    ranked = sorted(({"name": n, "rows": table_rows[n], "bytes": usage.get(n, 0)} for n in tables), key=lambda r: (-r["bytes"], r["name"]))
    return {
        "schema": "omega.client-database-storage-audit.v1",
        "databaseBytes": path.stat().st_size,
        "integrity": integrity,
        "projectionMode": meta.get("client_projection_mode", "legacy/unknown"),
        "marketplaceProjectorVersion": meta.get("marketplace_projector_version", ""),
        "tables": ranked,
        "prohibitedTables": leaked,
    }


def previous_audit(bundle: Path | None) -> dict[str, Any] | None:
    if bundle is None or not bundle.exists(): return None
    with tempfile.TemporaryDirectory(prefix="omega-client-audit-prev-") as td:
        root = Path(td)
        with zipfile.ZipFile(bundle) as zf:
            candidates = [n for n in zf.namelist() if Path(n).name in {"omega-catalog.sqlite", "omega-marketplace.sqlite"}]
            if not candidates: return None
            target = root / "previous.sqlite"
            with zf.open(candidates[0]) as source, target.open("wb") as destination:
                shutil.copyfileobj(source, destination)
        return audit(target)


def previous_size(bundle: Path | None) -> int | None:
    previous = previous_audit(bundle)
    return int(previous["databaseBytes"]) if previous else None


def audit_with_previous(path: Path, bundle: Path | None = None) -> dict[str, Any]:
    result = audit(path)
    previous = previous_audit(bundle)
    prev_bytes = int(previous["databaseBytes"]) if previous else None
    result["previousDatabaseBytes"] = prev_bytes
    result["growthRatio"] = (result["databaseBytes"] / prev_bytes) if prev_bytes else None

    current_tables = {row["name"]: row for row in result["tables"]}
    previous_tables = {row["name"]: row for row in (previous or {}).get("tables", [])}
    deltas: list[dict[str, Any]] = []
    for name in sorted(set(current_tables) | set(previous_tables)):
        current = current_tables.get(name, {"rows": 0, "bytes": 0})
        prior = previous_tables.get(name, {"rows": 0, "bytes": 0})
        current_rows, previous_rows = int(current["rows"]), int(prior["rows"])
        current_bytes, previous_bytes = int(current["bytes"]), int(prior["bytes"])
        deltas.append({
            "name": name,
            "rows": current_rows,
            "previousRows": previous_rows,
            "rowDelta": current_rows - previous_rows,
            "bytes": current_bytes,
            "previousBytes": previous_bytes,
            "byteDelta": current_bytes - previous_bytes,
            "byteGrowthRatio": (current_bytes / previous_bytes) if previous_bytes else None,
        })
    deltas.sort(key=lambda row: (-row["byteDelta"], -row["rowDelta"], row["name"]))
    result["tableDeltas"] = deltas
    result["largestGrowthTables"] = [row for row in deltas if row["byteDelta"] > 0][:10]
    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--database", required=True, type=Path)
    ap.add_argument("--previous-bundle", type=Path)
    ap.add_argument("--report", type=Path)
    ap.add_argument("--max-bytes", type=int, default=0)
    ap.add_argument("--max-growth-ratio", type=float, default=0.0)
    args = ap.parse_args()
    result = audit_with_previous(args.database, args.previous_bundle)
    prev = result["previousDatabaseBytes"]
    failures: list[str] = []
    if result["integrity"].casefold() != "ok": failures.append("integrity_check failed")
    if result["prohibitedTables"]: failures.append("prohibited server-side tables are present")
    if args.max_bytes and result["databaseBytes"] > args.max_bytes: failures.append(f"database exceeds {args.max_bytes} bytes")
    if args.max_growth_ratio and prev and result["databaseBytes"] > prev * args.max_growth_ratio:
        failures.append(f"database grew by more than {args.max_growth_ratio:.2f}x")
    result["ok"] = not failures; result["failures"] = failures
    text = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True); args.report.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0 if result["ok"] else 2

if __name__ == "__main__": raise SystemExit(main())
