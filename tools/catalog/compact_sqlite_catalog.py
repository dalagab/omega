#!/usr/bin/env python3
"""Compact Omega's published SQLite catalog without changing the runtime projection.

The security scanner deliberately stores detailed evidence in normalized SQLite tables. Older
scanner versions also embedded that same evidence in large JSON snapshots on both the historical
scan row and the current row. This utility rewrites those redundant JSON snapshots to bounded
summaries, preserves append-only scan history and normalized evidence, vacuums the database into a
new file, rebuilds the transport bundle, updates descriptor hashes, and records an auditable
compaction report.

The utility never removes scan rows, findings, dependency history, normalized dependency evidence,
managed metadata, IL call sites, reachability evidence, source/artifact comparison data, or current
variant security state.
"""

from __future__ import annotations

from contextlib import closing
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import zipfile
from datetime import datetime, timezone
from typing import Any

import build_sqlite_catalog
import security_scan
from catalog_revisions import (
    CATALOG_REVISION_SCHEMA, CHANGELOG_SCHEMA, EVIDENCE_REVISION_SCHEMA, SECURITY_REVISION_SCHEMA,
    append_changelog_if_changed, latest_changelog, read_meta,
)

COMPACTOR_VERSION = "1.2.0"
SUMMARY_SCHEMA = "omega.plugin-security.scan-summary.v1"
MAX_SUMMARY_BYTES = 64 * 1024
DB_FILENAME = "omega-catalog.sqlite"
BUNDLE_FILENAME = "omega-catalog.sqlite.zip"

PRESERVED_TABLES = (
    "plugins",
    "plugin_variants",
    "sources",
    "plugin_security_scans",
    "plugin_security_findings",
    "plugin_security_current",
    "plugin_security_dependencies",
    "plugin_security_ipc_endpoints",
    "plugin_security_ipc_registry",
    "plugin_security_imports",
    "plugin_security_permission_candidates",
    "plugin_security_automation_capabilities",
    "plugin_security_managed_assemblies",
    "plugin_security_managed_symbols",
    "plugin_security_managed_calls",
    "plugin_security_managed_reachability",
    "plugin_security_dependency_resolutions",
    "plugin_security_dependency_components",
    "plugin_security_dependency_issues",
    "plugin_security_dependency_advisory_matches",
    "plugin_security_scan_lineage",
    "plugin_security_dependency_drift",
    "plugin_security_source_artifact_comparisons",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def table_exists(db: sqlite3.Connection, name: str) -> bool:
    row = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone()
    return row is not None


def view_exists(db: sqlite3.Connection, name: str) -> bool:
    row = db.execute("SELECT 1 FROM sqlite_master WHERE type='view' AND name=?", (name,)).fetchone()
    return row is not None


def scalar_count(db: sqlite3.Connection, table: str) -> int:
    return int(db.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])


def preserved_counts(db: sqlite3.Connection) -> dict[str, int]:
    return {table: scalar_count(db, table) for table in PRESERVED_TABLES if table_exists(db, table)}


def runtime_projection_digest(db: sqlite3.Connection) -> str:
    """Hash the complete runtime projection so compaction cannot silently alter client-visible data."""
    if not view_exists(db, "runtime_plugin_variants"):
        raise RuntimeError("runtime_plugin_variants view is missing")
    h = hashlib.sha256()
    cursor = db.execute("SELECT * FROM runtime_plugin_variants ORDER BY variant_id")
    names = [description[0] for description in cursor.description]
    h.update(json.dumps(names, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    for row in cursor:
        h.update(b"\n")
        h.update(json.dumps(list(row), separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8"))
    return h.hexdigest()


def _countish(value: Any) -> int:
    if isinstance(value, (list, tuple, set, dict)):
        return len(value)
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _json_object(text: str | None) -> dict[str, Any]:
    if not text:
        return {}
    try:
        value = json.loads(text)
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def build_compact_summary(row: sqlite3.Row) -> str:
    previous = _json_object(row["report_json"])
    package = previous.get("package") if isinstance(previous.get("package"), dict) else {}
    source = previous.get("source") if isinstance(previous.get("source"), dict) else {}
    intelligence = previous.get("dependencyIntelligence")
    if not isinstance(intelligence, dict):
        intelligence = previous.get("intelligence") if isinstance(previous.get("intelligence"), dict) else {}

    plugin = previous.get("plugin") if isinstance(previous.get("plugin"), dict) else {}
    if not plugin:
        plugin = {
            "internalName": row["internal_name"],
            "name": row["variant_name"],
            "author": row["variant_author"],
            "sourceName": row["source_name"],
        }

    package_summary = {
        "archive": package.get("archive", ""),
        "fileCount": _countish(package.get("fileCount", package.get("files"))),
        "uncompressedBytes": _countish(package.get("uncompressedBytes")),
        "bundledExecutableCount": _countish(package.get("bundledExecutableCount", package.get("bundledExecutables"))),
        "bundledManagedAssemblyCount": _countish(package.get("bundledManagedAssemblyCount", package.get("bundledManagedAssemblies"))),
        "bundledNativeLibraryCount": _countish(package.get("bundledNativeLibraryCount", package.get("bundledNativeLibraries"))),
        "managedMetadataErrorCount": _countish(package.get("managedMetadataErrorCount", package.get("managedMetadataErrors"))),
    }

    coverage = intelligence.get("coverage") if isinstance(intelligence.get("coverage"), dict) else {}
    limits = intelligence.get("limits") if isinstance(intelligence.get("limits"), dict) else {}

    summary = {
        "schema": SUMMARY_SCHEMA,
        "scannerVersion": row["scanner_version"],
        "scannedAtUtc": row["scanned_at_utc"],
        "plugin": plugin,
        "assemblyVersion": row["assembly_version"],
        "artifactChannel": row["artifact_channel"],
        "artifactUrl": row["artifact_url"],
        "artifactSha256": row["artifact_sha256"],
        "status": row["status"],
        "highestSeverity": row["highest_severity"],
        "counts": {
            "informational": int(row["informational_count"] or 0),
            "caution": int(row["caution_count"] or 0),
            "high": int(row["high_count"] or 0),
            "critical": int(row["critical_count"] or 0),
        },
        "source": {
            "available": bool(row["source_available"]),
            "repository": row["source_repository"],
            "commit": row["source_commit"],
            "branch": source.get("branch", ""),
            "treeSha256": source.get("treeSha256", ""),
            "filesScanned": _countish(source.get("filesScanned")),
            "sourceToBinaryVerified": bool(row["source_to_binary_verified"]),
        },
        "package": package_summary,
        "intelligence": {
            "coverage": coverage,
            "limits": limits,
        },
        "error": row["error"],
    }
    encoded = json.dumps(summary, separators=(",", ":"), ensure_ascii=False)
    if len(encoded.encode("utf-8")) > MAX_SUMMARY_BYTES:
        raise RuntimeError(f"scan {row['scan_id']} compact summary exceeded {MAX_SUMMARY_BYTES} bytes")
    return encoded


def migrate_source_schema(db: sqlite3.Connection) -> None:
    """Apply additive scanner/runtime schema migrations before validating a legacy evidence database."""
    security_scan.ensure_schema(db)
    build_sqlite_catalog.create_runtime_view(db)
    db.commit()


def validate_source_database(db: sqlite3.Connection) -> None:
    integrity = db.execute("PRAGMA integrity_check").fetchone()
    if integrity is None or str(integrity[0]).lower() != "ok":
        raise RuntimeError(f"SQLite integrity_check failed before compaction: {integrity}")
    missing = [table for table in PRESERVED_TABLES if not table_exists(db, table)]
    if missing:
        raise RuntimeError(f"catalog is missing required tables: {', '.join(missing)}")
    if not view_exists(db, "runtime_plugin_variants"):
        raise RuntimeError("catalog is missing runtime_plugin_variants")


def compact_reports(db: sqlite3.Connection) -> dict[str, int]:
    before_scans = db.execute("SELECT COALESCE(SUM(LENGTH(report_json)),0), COALESCE(MAX(LENGTH(report_json)),0) FROM plugin_security_scans").fetchone()
    before_current = db.execute("SELECT COALESCE(SUM(LENGTH(report_json)),0), COALESCE(MAX(LENGTH(report_json)),0) FROM plugin_security_current").fetchone()

    rows = db.execute(
        """
        SELECT s.*,
               COALESCE(p.internal_name,'') AS internal_name,
               COALESCE(v.name,'') AS variant_name,
               COALESCE(v.author,'') AS variant_author,
               COALESCE(src.name,'') AS source_name
          FROM plugin_security_scans s
          LEFT JOIN plugins p ON p.plugin_id=s.plugin_id
          LEFT JOIN plugin_variants v ON v.variant_id=s.variant_id
          LEFT JOIN sources src ON src.source_id=s.source_id
         ORDER BY s.scan_id
        """
    ).fetchall()
    for row in rows:
        db.execute(
            "UPDATE plugin_security_scans SET report_json=? WHERE scan_id=?",
            (build_compact_summary(row), int(row["scan_id"])),
        )

    # Keep the current-row JSON contract readable without copying the former multi-megabyte payload.
    db.execute(
        """
        UPDATE plugin_security_current
           SET report_json=COALESCE((SELECT s.report_json FROM plugin_security_scans s WHERE s.scan_id=plugin_security_current.scan_id),'{}')
        """
    )

    after_scans = db.execute("SELECT COALESCE(SUM(LENGTH(report_json)),0), COALESCE(MAX(LENGTH(report_json)),0) FROM plugin_security_scans").fetchone()
    after_current = db.execute("SELECT COALESCE(SUM(LENGTH(report_json)),0), COALESCE(MAX(LENGTH(report_json)),0) FROM plugin_security_current").fetchone()
    return {
        "scanReportBytesBefore": int(before_scans[0] or 0),
        "scanReportMaxBytesBefore": int(before_scans[1] or 0),
        "currentReportBytesBefore": int(before_current[0] or 0),
        "currentReportMaxBytesBefore": int(before_current[1] or 0),
        "scanReportBytesAfter": int(after_scans[0] or 0),
        "scanReportMaxBytesAfter": int(after_scans[1] or 0),
        "currentReportBytesAfter": int(after_current[0] or 0),
        "currentReportMaxBytesAfter": int(after_current[1] or 0),
    }


def update_metadata(db: sqlite3.Connection, compacted_at: str) -> None:
    db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('database_role','security-evidence')")
    db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('database_compactor_version',?)", (COMPACTOR_VERSION,))
    db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('database_compacted_at_utc',?)", (compacted_at,))
    db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('security_report_payload_schema',?)", (SUMMARY_SCHEMA,))


def validate_compacted_database(path: Path, before_counts: dict[str, int], runtime_digest: str) -> dict[str, Any]:
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    try:
        integrity = db.execute("PRAGMA integrity_check").fetchone()
        if integrity is None or str(integrity[0]).lower() != "ok":
            raise RuntimeError(f"SQLite integrity_check failed after compaction: {integrity}")
        violations = db.execute("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise RuntimeError(f"foreign key violations after compaction: {violations[:5]}")
        after_counts = preserved_counts(db)
        if after_counts != before_counts:
            changed = {
                key: {"before": before_counts.get(key), "after": after_counts.get(key)}
                for key in sorted(set(before_counts) | set(after_counts))
                if before_counts.get(key) != after_counts.get(key)
            }
            raise RuntimeError(f"compaction changed preserved row counts: {changed}")
        after_digest = runtime_projection_digest(db)
        if after_digest != runtime_digest:
            raise RuntimeError("compaction changed runtime_plugin_variants projection")
        max_scan = int(db.execute("SELECT COALESCE(MAX(LENGTH(report_json)),0) FROM plugin_security_scans").fetchone()[0])
        max_current = int(db.execute("SELECT COALESCE(MAX(LENGTH(report_json)),0) FROM plugin_security_current").fetchone()[0])
        if max_scan > MAX_SUMMARY_BYTES or max_current > MAX_SUMMARY_BYTES:
            raise RuntimeError("compacted report_json payload exceeds summary ceiling")
        version = db.execute("SELECT value FROM catalog_meta WHERE key='database_compactor_version'").fetchone()
        if version is None or version[0] != COMPACTOR_VERSION:
            raise RuntimeError("compactor metadata is missing")
        return {
            "integrity": "ok",
            "foreignKeyViolations": 0,
            "runtimeProjectionSha256": after_digest,
            "preservedRows": after_counts,
            "maxHistoricalSummaryBytes": max_scan,
            "maxCurrentSummaryBytes": max_current,
        }
    finally:
        db.close()


def write_bundle_and_descriptor(
    database_path: Path,
    descriptor_input: Path,
    output_dir: Path,
    compacted_at: str,
    before_bytes: int,
    revision_result: dict[str, Any],
) -> dict[str, Any]:
    bundle_path = output_dir / BUNDLE_FILENAME
    descriptor_path = output_dir / "catalog.json"
    with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        archive.write(database_path, DB_FILENAME)

    catalog_sha = sha256_file(database_path)
    bundle_sha = sha256_file(bundle_path)
    with closing(sqlite3.connect(database_path)) as descriptor_db:
        scanner_version = read_meta(descriptor_db, "security_scanner_version", "")
    descriptor = json.loads(descriptor_input.read_text(encoding="utf-8"))
    after_bytes = database_path.stat().st_size
    descriptor.update(
        {
            "catalogSha256": catalog_sha,
            "bundleSha256": bundle_sha,
            "size": bundle_path.stat().st_size,
            "databaseBytes": after_bytes,
            "scannerVersion": scanner_version,
            "compactorVersion": COMPACTOR_VERSION,
            "compactedAtUtc": compacted_at,
            "publishedAtUtc": compacted_at,
            "preCompactionDatabaseBytes": before_bytes,
            "compactionSavedBytes": max(0, before_bytes - after_bytes),
            "catalogRevision": revision_result["catalogRevision"],
            "securityRevision": revision_result["securityRevision"],
            "evidenceRevision": revision_result["evidenceRevision"],
            "catalogBaseRevision": revision_result["baseRevision"],
            "catalogRevisionSchema": CATALOG_REVISION_SCHEMA,
            "securityRevisionSchema": SECURITY_REVISION_SCHEMA,
            "evidenceRevisionSchema": EVIDENCE_REVISION_SCHEMA,
            "changelogSchema": CHANGELOG_SCHEMA,
            "catalogRevisionChanged": bool(revision_result["catalogRevisionChanged"]),
            "securityRevisionChanged": bool(revision_result["securityRevisionChanged"]),
            "changeSummary": revision_result["changes"],
            "changelogEntryCount": int(revision_result.get("changelogEntryCount", 0)),
            "latestChangelogAtUtc": str((revision_result.get("latestChangelog") or {}).get("created_at_utc") or ""),
        }
    )
    descriptor.pop("catalogRevisionCandidate", None)
    descriptor_path.write_text(json.dumps(descriptor, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (output_dir / f"{BUNDLE_FILENAME}.sha256").write_text(f"{bundle_sha}  {BUNDLE_FILENAME}\n", encoding="ascii")
    return descriptor


def compact(
    database: Path,
    descriptor: Path,
    output_dir: Path,
    report_path: Path,
    previous_database: Path | None = None,
    previous_descriptor: Path | None = None,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    output_db = output_dir / DB_FILENAME
    output_db.unlink(missing_ok=True)
    before_bytes = database.stat().st_size
    compacted_at = utc_now()

    previous_descriptor_doc: dict[str, Any] = {}
    if previous_descriptor is not None and previous_descriptor.exists():
        previous_descriptor_doc = json.loads(previous_descriptor.read_text(encoding="utf-8"))

    db = sqlite3.connect(database)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA busy_timeout=5000")
    try:
        migrate_source_schema(db)
        validate_source_database(db)
        before_counts = preserved_counts(db)
        runtime_digest = runtime_projection_digest(db)
        db.execute("BEGIN IMMEDIATE")
        payload_metrics = compact_reports(db)
        update_metadata(db, compacted_at)
        revision_result = append_changelog_if_changed(
            db, previous_database, compacted_at, COMPACTOR_VERSION, "catalog-security-refresh"
        )
        db.commit()
        db.execute("ANALYZE")
        db.commit()
        escaped = str(output_db).replace("'", "''")
        db.execute(f"VACUUM INTO '{escaped}'")
    except Exception:
        if db.in_transaction:
            db.rollback()
        raise
    finally:
        db.close()

    validation = validate_compacted_database(output_db, before_counts, runtime_digest)
    with closing(sqlite3.connect(output_db)) as compacted_db:
        changelog_count = scalar_count(compacted_db, "catalog_changelog") if table_exists(compacted_db, "catalog_changelog") else 0
        latest_change = latest_changelog(compacted_db)
    revision_result["changelogEntryCount"] = changelog_count
    revision_result["latestChangelog"] = latest_change
    descriptor_data = write_bundle_and_descriptor(
        output_db, descriptor, output_dir, compacted_at, before_bytes, revision_result
    )
    after_bytes = output_db.stat().st_size
    previous_compactor_version = str(previous_descriptor_doc.get("compactorVersion") or "")
    representation_changed = previous_compactor_version != COMPACTOR_VERSION
    publication_required = bool(
        revision_result["catalogRevisionChanged"] or revision_result["evidenceRevisionChanged"] or representation_changed
    )
    report = {
        "schema": "omega.catalog-compaction.v1",
        "compactorVersion": COMPACTOR_VERSION,
        "compactedAtUtc": compacted_at,
        "databaseBytesBefore": before_bytes,
        "databaseBytesAfter": after_bytes,
        "databaseBytesSaved": max(0, before_bytes - after_bytes),
        "databaseReductionRatio": round((before_bytes - after_bytes) / before_bytes, 6) if before_bytes else 0.0,
        "payload": payload_metrics,
        "validation": validation,
        "revisions": revision_result,
        "publication": {
            "required": publication_required,
            "semanticChanged": bool(revision_result["catalogRevisionChanged"]),
            "securityChanged": bool(revision_result["securityRevisionChanged"]),
            "evidenceChanged": bool(revision_result["evidenceRevisionChanged"]),
            "representationChanged": representation_changed,
            "previousCompactorVersion": previous_compactor_version,
            "currentCompactorVersion": COMPACTOR_VERSION,
        },
        "descriptor": {
            "catalogRevision": descriptor_data["catalogRevision"],
            "securityRevision": descriptor_data["securityRevision"],
            "evidenceRevision": descriptor_data["evidenceRevision"],
            "catalogSha256": descriptor_data["catalogSha256"],
            "bundleSha256": descriptor_data["bundleSha256"],
            "bundleBytes": descriptor_data["size"],
        },
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return report


def build_self_test_database(path: Path) -> None:
    from build_sqlite_catalog import SCHEMA_SQL, create_runtime_view
    from security_scan import ensure_schema

    db = sqlite3.connect(path)
    db.executescript(SCHEMA_SQL)
    ensure_schema(db)
    db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('schema_version','1')")
    db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('schema_name','omega.catalog.sqlite.v1')")
    db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('security_scanner_version','2.0.0')")
    db.execute("INSERT INTO sources(url,name) VALUES('https://example.invalid/repo.json','Fixture source')")
    db.execute("INSERT INTO plugins(internal_name,canonical_name,first_seen_utc,last_seen_utc,active) VALUES('Fixture','Fixture','','',1)")
    db.execute(
        "INSERT INTO plugin_variants(plugin_id,source_id,source_entry_key,name,author,first_seen_utc,last_seen_utc,active) VALUES(1,1,'Fixture','Fixture','Omega','','',1)"
    )
    large_list = [{"kind": "MemberRef", "name": f"Method{i}", "evidence": ["x" * 256]} for i in range(4000)]
    large_report = {
        "schema": "omega.plugin-security.scan.v1",
        "scannerVersion": "2.0.0",
        "plugin": {"internalName": "Fixture", "name": "Fixture", "author": "Omega", "sourceName": "Fixture source"},
        "package": {"archive": "zip", "files": 3000, "uncompressedBytes": 123456, "bundledManagedAssemblies": 3},
        "dependencyIntelligence": {"managedCallSites": large_list, "coverage": {"total": 1, "analyzed": 1}, "limits": {"truncated": True, "droppedByCollection": {"managedCallSites": 50}}},
        "source": {"available": True, "repository": "example/repo", "commit": "abc", "branch": "main", "treeSha256": "def", "filesScanned": 20},
    }
    encoded = json.dumps(large_report, separators=(",", ":"))
    db.execute(
        """INSERT INTO plugin_security_scans(
            scan_id,plugin_id,variant_id,source_id,assembly_version,artifact_channel,artifact_url,artifact_sha256,scanner_version,status,scanned_at_utc,
            highest_severity,informational_count,caution_count,high_count,critical_count,capabilities_json,source_available,source_repository,source_commit,
            source_to_binary_verified,report_json,error)
            VALUES(1,1,1,1,'1.0','stable','https://example.invalid/plugin.zip','abc','2.0.0','complete','2026-01-01T00:00:00Z',
                   'caution',0,1,0,0,'[]',1,'example/repo','abc',0,?, '')""",
        (encoded,),
    )
    db.execute(
        """INSERT INTO plugin_security_current(
            variant_id,scan_id,assembly_version,artifact_channel,artifact_url,artifact_sha256,scanner_version,status,scanned_at_utc,highest_severity,
            informational_count,caution_count,high_count,critical_count,capabilities_json,findings_json,source_available,source_repository,source_commit,
            source_to_binary_verified,report_json,error)
            VALUES(1,1,'1.0','stable','https://example.invalid/plugin.zip','abc','2.0.0','complete','2026-01-01T00:00:00Z','caution',
                   0,1,0,0,'[]','[]',1,'example/repo','abc',0,?, '')""",
        (encoded,),
    )
    db.execute("INSERT INTO plugin_security_findings(scan_id,rule_id,severity,category,title,description,evidence_json) VALUES(1,'fixture','caution','fixture','fixture','fixture','[]')")
    db.execute("INSERT INTO plugin_security_dependencies(scan_id,origin,kind,name,version,status,requirement,evidence_json) VALUES(1,'artifact','assembly','Fixture.Dependency','1.0','observed','required','[]')")
    db.execute("INSERT INTO plugin_security_imports(scan_id,origin,namespace,path) VALUES(1,'artifact','System.IO','Fixture.dll')")
    db.execute("INSERT INTO plugin_security_permission_candidates(scan_id,origin,permission_id,risk,confidence,reason,evidence_json) VALUES(1,'artifact','filesystem','caution','medium','fixture','[]')")
    db.execute("INSERT INTO plugin_security_managed_assemblies(scan_id,origin,path,sha256,assembly_name,assembly_version,parse_status) VALUES(1,'artifact','Fixture.dll','abc','Fixture','1.0','analyzed')")
    db.execute("INSERT INTO plugin_security_managed_symbols(scan_id,origin,path,symbol_kind,declaring_type,name,assembly_name,evidence_json) VALUES(1,'artifact','Fixture.dll','MemberRef','Fixture.Type','Run','Fixture','[]')")
    db.execute("INSERT INTO plugin_security_managed_calls(scan_id,origin,path,source_method_token,source_declaring_type,source_method_name,il_offset,opcode,target_token,target_kind,target_declaring_type,target_name,target_assembly_name,evidence_json) VALUES(1,'artifact','Fixture.dll','0x06000001','Fixture.Type','Run',0,'call','0x0A000001','MemberRef','System.IO.File','Open','System.Runtime','[]')")
    db.execute("INSERT INTO plugin_security_managed_reachability(scan_id,origin,path,root_method_token,root_declaring_type,root_method_name,root_kind,root_confidence,method_token,method_declaring_type,method_name,depth,evidence_json) VALUES(1,'artifact','Fixture.dll','0x06000001','Fixture.Type','Run','lifecycle','high','0x06000001','Fixture.Type','Run',0,'[]')")
    create_runtime_view(db)
    db.commit()
    db.execute("VACUUM")
    db.close()


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="omega-compact-selftest-") as tmp:
        root = Path(tmp)
        source = root / DB_FILENAME
        build_self_test_database(source)
        descriptor = root / "catalog.json"
        descriptor.write_text(
            json.dumps({"schemaVersion": 1, "schema": "omega.catalog.sqlite.v1", "catalogSha256": "", "bundleSha256": "", "size": 0, "databaseBytes": source.stat().st_size}) + "\n",
            encoding="utf-8",
        )
        out = root / "out"
        report = compact(source, descriptor, out, out / "compaction-report.json")
        if report["databaseBytesAfter"] >= report["databaseBytesBefore"]:
            raise RuntimeError("self-test compaction did not reduce database size")
        db = sqlite3.connect(out / DB_FILENAME)
        try:
            if scalar_count(db, "plugin_security_scans") != 1 or scalar_count(db, "plugin_security_managed_calls") != 1:
                raise RuntimeError("self-test lost historical or normalized evidence")
            historical = db.execute("SELECT report_json FROM plugin_security_scans WHERE scan_id=1").fetchone()[0]
            current = db.execute("SELECT report_json FROM plugin_security_current WHERE variant_id=1").fetchone()[0]
            if json.loads(historical).get("schema") != SUMMARY_SCHEMA or current != historical:
                raise RuntimeError("self-test did not preserve compact current/history summary contract")
        finally:
            db.close()
        # A second pass must be safe and keep the compact summary bounded.
        second_descriptor = out / "catalog.json"
        second_out = root / "out2"
        second = compact(
            out / DB_FILENAME, second_descriptor, second_out, second_out / "compaction-report.json",
            previous_database=out / DB_FILENAME, previous_descriptor=second_descriptor,
        )
        if second["payload"]["scanReportMaxBytesAfter"] > MAX_SUMMARY_BYTES:
            raise RuntimeError("self-test second pass exceeded summary ceiling")
        if second["publication"]["required"]:
            raise RuntimeError("self-test unchanged second pass incorrectly requires publication")
        with closing(sqlite3.connect(second_out / DB_FILENAME)) as check_db:
            if scalar_count(check_db, "catalog_changelog") != 1:
                raise RuntimeError("self-test changelog should contain exactly one semantic revision")
    print("Omega SQLite catalog compactor self-test passed.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compact an Omega security-enriched SQLite catalog")
    parser.add_argument("--database", type=Path, help="Path to the extracted omega-catalog.sqlite")
    parser.add_argument("--descriptor", type=Path, help="Path to catalog.json from the same published catalog")
    parser.add_argument("--output-dir", type=Path, help="Directory for compacted database, bundle, descriptor and checksum")
    parser.add_argument("--report", type=Path, help="Path for the compaction report JSON")
    parser.add_argument("--previous-database", type=Path, help="Previously published SQLite catalog for semantic diff/changelog")
    parser.add_argument("--previous-descriptor", type=Path, help="Previously published catalog.json for publication decisions")
    parser.add_argument("--self-test", action="store_true", help="Run an isolated compaction regression fixture")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        self_test()
        return 0
    if not args.database or not args.descriptor or not args.output_dir or not args.report:
        raise SystemExit("--database, --descriptor, --output-dir and --report are required")
    report = compact(args.database, args.descriptor, args.output_dir, args.report, args.previous_database, args.previous_descriptor)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
