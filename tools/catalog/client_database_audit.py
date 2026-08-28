#!/usr/bin/env python3
"""Report and gate Omega's downloadable client SQLite footprint."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sqlite3
import tempfile
import zipfile
from pathlib import Path
from typing import Any

PROHIBITED_TABLES = {
    "manifest_observations", "manifest_source_candidates", "source_repositories", "source_repository_aliases",
    "plugin_identity_aliases", "plugin_tags", "plugin_images", "plugin_search", "websites", "presentation",
    "plugin_security_scans", "plugin_security_findings", "plugin_security_dependencies", "plugin_security_current",
    "artifact_blobs", "artifact_analyses", "source_analyses", "source_revisions", "artifact_source_attributions",
}

# During a clean Security Evidence rebuild the existing runtime rows legitimately get
# larger as their public security_* summary fields are repopulated. The normal 1.20x
# growth gate may be bypassed only when the database itself proves that this is the
# sole material change.
SECURITY_REFILL_GROWTH_TABLES = {"runtime_plugin_variants", "catalog_meta"}


def _rows(db: sqlite3.Connection, table: str) -> int:
    try:
        return int(db.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])
    except sqlite3.Error:
        return -1


def _columns(db: sqlite3.Connection, table: str) -> list[str]:
    try:
        return [str(row[1]) for row in db.execute(f'PRAGMA table_info("{table}")')]
    except sqlite3.Error:
        return []


def _runtime_non_security_digest(db: sqlite3.Connection) -> str:
    """Hash every runtime field except the Evidence-derived security_* projection."""
    columns = _columns(db, "runtime_plugin_variants")
    selected = [name for name in columns if not name.casefold().startswith("security_")]
    if not selected:
        return ""
    quoted = ",".join(f'"{name}"' for name in selected)
    order = '"variant_id"' if "variant_id" in columns else "rowid"
    digest = hashlib.sha256(
        json.dumps(selected, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    )
    for row in db.execute(
        f"SELECT {quoted} FROM runtime_plugin_variants ORDER BY {order}"
    ):
        digest.update(b"\n")
        digest.update(
            json.dumps(
                list(row),
                separators=(",", ":"),
                ensure_ascii=False,
                default=str,
            ).encode("utf-8")
        )
    return digest.hexdigest()


def _security_coverage(db: sqlite3.Connection) -> dict[str, Any]:
    columns = set(_columns(db, "runtime_plugin_variants"))
    if "security_scanned_at_utc" in columns:
        marker = "security_scanned_at_utc"
        predicate = "TRIM(COALESCE(security_scanned_at_utc,''))<>''"
    elif "security_artifact_sha256" in columns:
        marker = "security_artifact_sha256"
        predicate = "TRIM(COALESCE(security_artifact_sha256,''))<>''"
    elif "security_status" in columns:
        marker = "security_status"
        predicate = (
            "lower(TRIM(COALESCE(security_status,''))) "
            "NOT IN ('','unknown','not-scanned','unscanned','pending')"
        )
    else:
        return {"marker": "", "coveredVariants": 0}
    covered = int(
        db.execute(
            f"SELECT COUNT(*) FROM runtime_plugin_variants WHERE {predicate}"
        ).fetchone()[0]
    )
    return {"marker": marker, "coveredVariants": covered}


def audit(path: Path) -> dict[str, Any]:
    with sqlite3.connect(path) as db:
        integrity = str(db.execute("PRAGMA integrity_check").fetchone()[0])
        tables = [
            str(r[0])
            for r in db.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        ]
        usage: dict[str, int] = {}
        index_owners = {
            str(name): str(table)
            for name, table in db.execute(
                "SELECT name,tbl_name FROM sqlite_master WHERE type='index'"
            )
        }
        try:
            for name, size in db.execute(
                "SELECT name,COALESCE(SUM(pgsize),0) FROM dbstat GROUP BY name"
            ):
                owner = index_owners.get(str(name), str(name))
                usage[owner] = usage.get(owner, 0) + int(size or 0)
        except sqlite3.Error:
            pass
        table_rows = {name: _rows(db, name) for name in tables}
        meta = (
            dict(db.execute("SELECT key,value FROM catalog_meta"))
            if "catalog_meta" in tables
            else {}
        )
        runtime_digest = (
            _runtime_non_security_digest(db)
            if "runtime_plugin_variants" in tables
            else ""
        )
        security_coverage = (
            _security_coverage(db)
            if "runtime_plugin_variants" in tables
            else {"marker": "", "coveredVariants": 0}
        )

    leaked = sorted(set(tables) & PROHIBITED_TABLES)
    ranked = sorted(
        (
            {"name": n, "rows": table_rows[n], "bytes": usage.get(n, 0)}
            for n in tables
        ),
        key=lambda r: (-r["bytes"], r["name"]),
    )
    return {
        "schema": "omega.client-database-storage-audit.v1",
        "databaseBytes": path.stat().st_size,
        "integrity": integrity,
        "projectionMode": meta.get("client_projection_mode", "legacy/unknown"),
        "marketplaceProjectorVersion": meta.get("marketplace_projector_version", ""),
        "evidenceRevision": meta.get("evidence_revision", ""),
        "runtimeNonSecurityDigest": runtime_digest,
        "securityCoverage": security_coverage,
        "tables": ranked,
        "prohibitedTables": leaked,
    }


def previous_audit(bundle: Path | None) -> dict[str, Any] | None:
    if bundle is None or not bundle.exists():
        return None
    with tempfile.TemporaryDirectory(prefix="omega-client-audit-prev-") as td:
        root = Path(td)
        with zipfile.ZipFile(bundle) as zf:
            candidates = [
                n
                for n in zf.namelist()
                if Path(n).name in {"omega-catalog.sqlite", "omega-marketplace.sqlite"}
            ]
            if not candidates:
                return None
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
    result["growthRatio"] = (
        result["databaseBytes"] / prev_bytes if prev_bytes else None
    )

    current_tables = {row["name"]: row for row in result["tables"]}
    previous_tables = {
        row["name"]: row for row in (previous or {}).get("tables", [])
    }
    deltas: list[dict[str, Any]] = []
    for name in sorted(set(current_tables) | set(previous_tables)):
        current = current_tables.get(name, {"rows": 0, "bytes": 0})
        prior = previous_tables.get(name, {"rows": 0, "bytes": 0})
        current_rows, previous_rows = int(current["rows"]), int(prior["rows"])
        current_bytes, previous_bytes = int(current["bytes"]), int(prior["bytes"])
        deltas.append(
            {
                "name": name,
                "rows": current_rows,
                "previousRows": previous_rows,
                "rowDelta": current_rows - previous_rows,
                "bytes": current_bytes,
                "previousBytes": previous_bytes,
                "byteDelta": current_bytes - previous_bytes,
                "byteGrowthRatio": (
                    current_bytes / previous_bytes if previous_bytes else None
                ),
            }
        )
    deltas.sort(
        key=lambda row: (-row["byteDelta"], -row["rowDelta"], row["name"])
    )
    result["tableDeltas"] = deltas
    result["largestGrowthTables"] = [
        row for row in deltas if row["byteDelta"] > 0
    ][:10]
    result["previousRuntimeNonSecurityDigest"] = (
        previous or {}
    ).get("runtimeNonSecurityDigest", "")
    result["previousSecurityCoverage"] = (
        previous or {}
    ).get("securityCoverage", {"marker": "", "coveredVariants": 0})
    result["previousEvidenceRevision"] = (previous or {}).get("evidenceRevision", "")
    result["previousProjectionMode"] = (previous or {}).get("projectionMode", "")
    result["previousMarketplaceProjectorVersion"] = (
        previous or {}
    ).get("marketplaceProjectorVersion", "")
    return result


def security_refill_growth_allowance(
    result: dict[str, Any],
) -> tuple[bool, list[str]]:
    """Allow >1.20x growth only when it is proven to be security-summary refill."""
    reasons: list[str] = []

    if result.get("projectionMode") != result.get("previousProjectionMode"):
        reasons.append("projection mode changed")
    if result.get("marketplaceProjectorVersion") != result.get(
        "previousMarketplaceProjectorVersion"
    ):
        reasons.append("marketplace projector version changed")

    current_digest = str(result.get("runtimeNonSecurityDigest") or "")
    previous_digest = str(result.get("previousRuntimeNonSecurityDigest") or "")
    if not current_digest or current_digest != previous_digest:
        reasons.append("non-security runtime projection changed")

    current_coverage = result.get("securityCoverage") or {}
    previous_coverage = result.get("previousSecurityCoverage") or {}
    current_marker = str(current_coverage.get("marker") or "")
    previous_marker = str(previous_coverage.get("marker") or "")
    current_covered = int(current_coverage.get("coveredVariants") or 0)
    previous_covered = int(previous_coverage.get("coveredVariants") or 0)
    if not current_marker or current_marker != previous_marker:
        reasons.append("security coverage marker changed or unavailable")
    if current_covered <= previous_covered:
        reasons.append("security coverage did not increase")

    current_evidence = str(result.get("evidenceRevision") or "")
    previous_evidence = str(result.get("previousEvidenceRevision") or "")
    if not current_evidence or current_evidence == previous_evidence:
        reasons.append("authoritative Evidence revision did not advance")

    table_deltas = result.get("tableDeltas") or []
    changed_row_counts = [
        str(row.get("name") or "")
        for row in table_deltas
        if int(row.get("rowDelta") or 0) != 0
    ]
    if changed_row_counts:
        reasons.append(
            "table row counts changed: " + ", ".join(sorted(changed_row_counts))
        )

    positive_growth = {
        str(row.get("name") or "")
        for row in table_deltas
        if int(row.get("byteDelta") or 0) > 0
    }
    unexpected_growth = sorted(
        positive_growth - SECURITY_REFILL_GROWTH_TABLES
    )
    if unexpected_growth:
        reasons.append(
            "non-security tables grew: " + ", ".join(unexpected_growth)
        )

    runtime_delta = next(
        (
            row
            for row in table_deltas
            if row.get("name") == "runtime_plugin_variants"
        ),
        None,
    )
    if runtime_delta is None:
        reasons.append("runtime_plugin_variants delta unavailable")
    elif int(runtime_delta.get("byteDelta") or 0) <= 0:
        reasons.append("runtime_plugin_variants did not grow")

    return not reasons, reasons


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
    growth_exceeded = bool(
        args.max_growth_ratio
        and prev
        and result["databaseBytes"] > prev * args.max_growth_ratio
    )
    refill_allowed = False
    refill_reasons: list[str] = []
    if growth_exceeded:
        refill_allowed, refill_reasons = security_refill_growth_allowance(result)

    result["growthGate"] = {
        "maxGrowthRatio": args.max_growth_ratio or None,
        "exceeded": growth_exceeded,
        "securityRefillAllowed": refill_allowed,
        "securityRefillRejectionReasons": refill_reasons,
        "securityCoverageDelta": (
            int((result.get("securityCoverage") or {}).get("coveredVariants") or 0)
            - int(
                (result.get("previousSecurityCoverage") or {}).get(
                    "coveredVariants"
                )
                or 0
            )
        ),
    }

    failures: list[str] = []
    if result["integrity"].casefold() != "ok":
        failures.append("integrity_check failed")
    if result["prohibitedTables"]:
        failures.append("prohibited server-side tables are present")
    if args.max_bytes and result["databaseBytes"] > args.max_bytes:
        failures.append(f"database exceeds {args.max_bytes} bytes")
    if growth_exceeded and not refill_allowed:
        failures.append(
            f"database grew by more than {args.max_growth_ratio:.2f}x"
        )

    result["ok"] = not failures
    result["failures"] = failures
    text = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
