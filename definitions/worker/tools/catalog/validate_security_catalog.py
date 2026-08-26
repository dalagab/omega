#!/usr/bin/env python3
"""Validate a security-enriched Omega SQLite catalog and its transport metadata.

This module contains the deterministic validation previously embedded in the GitHub Actions
workflow. Keeping the checks in importable Python makes them reusable from CI and unit tests.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import json
import sqlite3
import zipfile
from pathlib import Path

import security_scan
from catalog_revisions import CATALOG_REVISION_SCHEMA, EVIDENCE_REVISION_SCHEMA, SECURITY_REVISION_SCHEMA, is_valid_evidence_revision

REQUIRED_TABLES = (
    "plugin_security_current",
    "plugin_security_dependencies",
    "plugin_security_ipc_endpoints",
    "plugin_security_ipc_registry",
    "plugin_security_dependency_resolutions",
    "plugin_security_dependency_components",
    "plugin_security_dependency_issues",
    "plugin_security_dependency_advisory_matches",
    "plugin_security_imports",
    "plugin_security_managed_assemblies",
    "plugin_security_managed_symbols",
    "plugin_security_managed_calls",
    "plugin_security_managed_reachability",
    "plugin_security_scan_lineage",
    "plugin_security_dependency_drift",
    "plugin_security_source_artifact_comparisons",
    "plugin_security_permission_candidates",
    "plugin_security_automation_capabilities",
)


def _table_exists(db: sqlite3.Connection, table: str) -> bool:
    return bool(db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone())


def _column_exists(db: sqlite3.Connection, table: str, column: str) -> bool:
    return any(row[1] == column for row in db.execute(f"PRAGMA table_info('{table}')"))


def validate_database(database: Path, report_path: Path | None = None) -> dict:
    with closing(sqlite3.connect(database)) as db:
        integrity = db.execute("PRAGMA integrity_check").fetchone()
        if not integrity or str(integrity[0]).lower() != "ok":
            raise RuntimeError(f"SQLite integrity_check failed: {integrity}")
        missing = [table for table in REQUIRED_TABLES if not _table_exists(db, table)]
        if missing:
            raise RuntimeError(f"missing security tables: {', '.join(missing)}")
        required_columns = (
            ("runtime_plugin_variants", "security_status"),
            ("plugin_security_dependencies", "requirement"),
            ("plugin_security_dependencies", "version_requirement"),
            ("plugin_security_dependencies", "resolved_version"),
            ("plugin_security_dependencies", "relationship"),
            ("plugin_security_dependencies", "relationship_confidence"),
            ("plugin_security_dependencies", "relationship_evidence_json"),
            ("plugin_security_ipc_endpoints", "relationship"),
            ("plugin_security_dependency_resolutions", "relationship"),
            ("plugin_security_dependency_resolutions", "relationship_confidence"),
            ("plugin_security_dependency_components", "version_divergence"),
            ("plugin_security_managed_calls", "target_method_token"),
            ("plugin_security_current", "automation_level"),
            ("plugin_security_current", "automation_capabilities_json"),
            ("runtime_plugin_variants", "security_automation_level"),
            ("runtime_plugin_variants", "security_automation_capabilities_json"),
        )
        for table, column in required_columns:
            if not _column_exists(db, table, column):
                raise RuntimeError(f"missing {table}.{column}")
        current_dependencies = db.execute(
            """
            SELECT COUNT(*)
              FROM plugin_security_dependencies d
              JOIN plugin_security_scans s ON s.scan_id=d.scan_id
              JOIN plugin_security_current c ON c.scan_id=d.scan_id AND c.variant_id=s.variant_id
             WHERE c.status='complete' AND s.status='complete'
            """
        ).fetchone()[0]
        resolution_count = db.execute("SELECT COUNT(*) FROM plugin_security_dependency_resolutions").fetchone()[0]
        if resolution_count != current_dependencies:
            raise RuntimeError(f"dependency projection mismatch: {resolution_count} != {current_dependencies}")
        ipc_registry_duplicates = db.execute("""
            SELECT COUNT(*) FROM (
                SELECT channel,provider_plugin_id,COUNT(*) AS n
                  FROM plugin_security_ipc_registry
                 GROUP BY channel,provider_plugin_id
                HAVING n>1
            )
        """).fetchone()[0]
        if ipc_registry_duplicates:
            raise RuntimeError(f"IPC provider registry contains duplicate channel/provider rows: {ipc_registry_duplicates}")
        invalid_ipc_edges = db.execute("""
            SELECT COUNT(*)
              FROM plugin_security_dependency_resolutions r
             WHERE r.dependency_kind='ipc' AND r.resolution_status='resolved-ipc-provider'
               AND NOT EXISTS (
                   SELECT 1 FROM plugin_security_ipc_registry g
                    WHERE g.channel=r.dependency_name AND g.provider_plugin_id=r.target_plugin_id
               )
        """).fetchone()[0]
        if invalid_ipc_edges:
            raise RuntimeError(f"resolved IPC edges are missing provider registrations: {invalid_ipc_edges}")
        invalid_ipc_relationships = db.execute("""
            SELECT COUNT(*) FROM plugin_security_dependencies
             WHERE kind='ipc' AND TRIM(relationship)<>'' AND lower(relationship) NOT IN ('required','feature','optional','unknown')
        """).fetchone()[0]
        if invalid_ipc_relationships:
            raise RuntimeError(f"invalid IPC dependency relationships: {invalid_ipc_relationships}")
        invalid_ipc_confidence = db.execute("""
            SELECT COUNT(*) FROM plugin_security_dependencies
             WHERE kind='ipc' AND TRIM(relationship_confidence)<>''
               AND lower(replace(replace(relationship_confidence,'-',''),'_','')) NOT IN ('veryhigh','high','medium','low')
        """).fetchone()[0]
        if invalid_ipc_confidence:
            raise RuntimeError(f"invalid IPC relationship confidence values: {invalid_ipc_confidence}")
        for key in (
            "dependency_graph_version",
            "dependency_version_intelligence_version",
            "dependency_history_version",
            "dependency_hardening_version",
        ):
            if db.execute("SELECT COUNT(*) FROM catalog_meta WHERE key=?", (key,)).fetchone()[0] != 1:
                raise RuntimeError(f"missing catalog_meta key: {key}")
        foreign_keys = db.execute("PRAGMA foreign_key_check").fetchall()
        if foreign_keys:
            raise RuntimeError(f"foreign key violations: {len(foreign_keys)}")
        meta = dict(db.execute("SELECT key,value FROM catalog_meta"))
        security_revision = str(meta.get("security_revision_candidate", ""))
        catalog_revision = str(meta.get("catalog_revision_candidate", ""))
        evidence_revision = str(meta.get("evidence_revision_candidate", ""))
        base_revision = str(meta.get("catalog_base_revision", ""))
        if not security_revision.startswith(f"sec-{security_scan.SCANNER_VERSION}-"):
            raise RuntimeError("security revision candidate is missing or stale")
        if not is_valid_evidence_revision(evidence_revision):
            raise RuntimeError("evidence revision candidate is missing or stale")
        if not catalog_revision.startswith("cat-v1-") or not base_revision.startswith("base-v1-"):
            raise RuntimeError("catalog revision candidate metadata is missing")
        if (meta.get("catalog_revision_schema") != CATALOG_REVISION_SCHEMA or
                meta.get("security_revision_schema") != SECURITY_REVISION_SCHEMA or
                meta.get("evidence_revision_schema") != EVIDENCE_REVISION_SCHEMA):
            raise RuntimeError("semantic revision schema metadata is missing or stale")

    result = {
        "integrity": "ok",
        "currentDependencies": int(current_dependencies),
        "dependencyResolutions": int(resolution_count),
        "scannerVersion": security_scan.SCANNER_VERSION,
        "catalogRevisionCandidate": catalog_revision,
        "securityRevision": security_revision,
        "evidenceRevision": evidence_revision,
        "catalogBaseRevision": base_revision,
    }
    if report_path:
        report = json.loads(report_path.read_text(encoding="utf-8"))
        if report.get("scannerVersion") != security_scan.SCANNER_VERSION:
            raise RuntimeError("security report Sigmascope version does not match Sigmascope implementation")
        health = report.get("databaseHealth") or {}
        if str(health.get("integrity", "")).lower() != "ok":
            raise RuntimeError("security report database health is not ok")
        if health.get("currentDependencies") != health.get("dependencyResolutions"):
            raise RuntimeError("security report dependency resolution count does not match current dependencies")
        if int(report.get("batchBudgetSeconds", -1)) < 0:
            raise RuntimeError("security report contains an invalid batch budget")
        revisions = report.get("revisions") or {}
        if (revisions.get("securityRevision") != security_revision or
                revisions.get("catalogRevision") != catalog_revision or
                revisions.get("evidenceRevision") != evidence_revision):
            raise RuntimeError("security report semantic revisions do not match database metadata")
        result["reportedPlugins"] = int(report.get("reportedPluginRows", len(report.get("plugins") or [])))
    return result


def validate_transport(database: Path, bundle: Path, descriptor_path: Path) -> dict:
    descriptor = json.loads(descriptor_path.read_text(encoding="utf-8"))
    catalog_sha = hashlib.sha256(database.read_bytes()).hexdigest()
    bundle_sha = hashlib.sha256(bundle.read_bytes()).hexdigest()
    if catalog_sha != descriptor.get("catalogSha256"):
        raise RuntimeError("catalog SHA-256 does not match descriptor")
    if bundle_sha != descriptor.get("bundleSha256"):
        raise RuntimeError("bundle SHA-256 does not match descriptor")
    with zipfile.ZipFile(bundle) as archive:
        if archive.namelist() != ["omega-catalog.sqlite"]:
            raise RuntimeError("catalog bundle must contain exactly omega-catalog.sqlite")
        if hashlib.sha256(archive.read("omega-catalog.sqlite")).hexdigest() != catalog_sha:
            raise RuntimeError("bundled database does not match extracted database")
    with closing(sqlite3.connect(database)) as db:
        meta = dict(db.execute("SELECT key,value FROM catalog_meta"))
    if descriptor.get("securityRevision") != meta.get("security_revision_candidate"):
        raise RuntimeError("descriptor securityRevision does not match database")
    if descriptor.get("catalogRevisionCandidate") != meta.get("catalog_revision_candidate"):
        raise RuntimeError("descriptor catalogRevisionCandidate does not match database")
    if descriptor.get("evidenceRevision") != meta.get("evidence_revision_candidate"):
        raise RuntimeError("descriptor evidenceRevision does not match database")
    return {"catalogSha256": catalog_sha, "bundleSha256": bundle_sha, "bundleBytes": bundle.stat().st_size}



def validate_scan_ledger(path: Path) -> dict:
    if not path.exists():
        return {"present": False, "entries": 0}
    doc = json.loads(path.read_text(encoding="utf-8"))
    if doc.get("schema") != security_scan.SECURITY_LEDGER_SCHEMA or not isinstance(doc.get("variants"), dict):
        raise RuntimeError("Sigmascope legacy scan-ledger schema is invalid")
    for key, entry in doc["variants"].items():
        if not str(key).isdigit() or not isinstance(entry, dict):
            raise RuntimeError("Sigmascope legacy scan-ledger contains an invalid variant entry")
        if entry.get("status") not in ("complete", "failed"):
            raise RuntimeError("Sigmascope legacy scan-ledger contains an invalid status")
        if not str(entry.get("scannerVersion") or ""):
            raise RuntimeError("Sigmascope legacy scan-ledger entry is missing the legacy scanner_version / Sigmascope version field")
        if not str(entry.get("lastValidatedAtUtc") or ""):
            raise RuntimeError("Sigmascope legacy scan-ledger entry is missing validation time")
    return {"present": True, "entries": len(doc["variants"]), "scannerVersion": str(doc.get("scannerVersion") or "")}

def validate(root: Path) -> dict:
    database = root / "omega-catalog.sqlite"
    bundle = root / "omega-catalog.sqlite.zip"
    descriptor = root / "catalog.json"
    report = root / "security-report.json"
    for path in (database, bundle, descriptor, report):
        if not path.exists():
            raise RuntimeError(f"missing required security catalog file: {path.name}")
    return {
        "database": validate_database(database, report),
        "transport": validate_transport(database, bundle, descriptor),
        "scanLedger": validate_scan_ledger(root / "security-scan-ledger.json"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate an Omega security-enriched catalog")
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(validate(args.root), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
