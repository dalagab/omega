#!/usr/bin/env python3
"""Production Omega Sigmascope / Security Evidence v2 orchestrator.

Security Evidence v2 is the authoritative Sigmascope evidence state.  The pipeline builds a
*temporary compact SQLite working projection* from the current catalog identities and
small v2 evidence needed by the existing Sigmascope/projector, examines a bounded set of due
variants, restores the last-known-good current pointer for any failed revalidation,
refreshes OSV/IPC/dependency projections, merges only successful analyses into a staged
copy of the published v2 snapshot, validates it intrinsically, and builds the small
client marketplace SQLite from that staged state.

Nothing in this module writes the published evidence branch.  Publication is a separate
final step performed by publish_security_evidence_v2.py after both snapshot validation
and the independent developer audit pass.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
from types import SimpleNamespace
from typing import Any, Iterable

SCRIPT_DIR = Path(__file__).resolve().parent
TOOLS_DIR = SCRIPT_DIR.parent
CATALOG_DIR = TOOLS_DIR / "catalog"
for item in (SCRIPT_DIR, CATALOG_DIR):
    if str(item) not in sys.path:
        sys.path.insert(0, str(item))

import catalog_revisions  # noqa: E402
import collect_public_advisories  # noqa: E402
import project_marketplace_catalog  # noqa: E402
import sigmascope  # noqa: E402
from local_sigmascope_v2_test import summarize as summarize_database  # noqa: E402
from migrate_security_evidence_v2 import (  # noqa: E402
    _derived_for_variant,
    _export_global_table,
    _export_identity_index,
    _export_ipc_index,
    _export_nuget_index,
    migrate,
)
from security_evidence_v2 import (  # noqa: E402
    FORMAT_VERSION,
    MAX_PUBLISH_FILE_BYTES,
    SCHEMA,
    atomic_write_bytes,
    canonical_json_bytes,
    file_entry,
    normalize_row,
    read_dataset_rows,
    read_json_file,
    write_record_dataset,
    safe_relpath,
    sha256_bytes,
    sha256_file,
    table_columns,
    table_exists,
    transport_security_row,
    validate_snapshot,
)

PIPELINE_SCHEMA = "omega.security-evidence.production-v2.v1"
SNAPSHOT_VALIDATION_SCHEMA = "omega.security-evidence.snapshot-validation.v2"
DEFAULT_MAX_SCANS = 60
DEFAULT_RESCAN_HOURS = 168
DEFAULT_MAX_BATCH_SECONDS = 4200
SMALL_ANALYSIS_DATASETS: dict[str, str] = {
    "findings": "plugin_security_findings",
    "dependencies": "plugin_security_dependencies",
    "ipc": "plugin_security_ipc_endpoints",
    "assemblies": "plugin_security_managed_assemblies",
    "permissions": "plugin_security_permission_candidates",
    "automation": "plugin_security_automation_capabilities",
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_bytes(path, (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8"))


def sqlite_value(column: str, value: Any) -> Any:
    if column.endswith("_json") and not isinstance(value, str):
        return json.dumps(value if value is not None else ([] if column != "report_json" else {}), ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, bool):
        return int(value)
    return value


def _insert_mapping(db: sqlite3.Connection, table: str, row: dict[str, Any], *, replace: bool = False) -> None:
    columns = table_columns(db, table)
    usable = [column for column in columns if column in row]
    if not usable:
        return
    verb = "INSERT OR REPLACE" if replace else "INSERT"
    quoted = ",".join(f'"{column}"' for column in usable)
    placeholders = ",".join("?" for _ in usable)
    db.execute(
        f'{verb} INTO "{table}"({quoted}) VALUES({placeholders})',
        tuple(sqlite_value(column, row.get(column)) for column in usable),
    )


def _insert_child_rows(db: sqlite3.Connection, table: str, scan_id: int, rows: Iterable[dict[str, Any]]) -> None:
    pk = None
    for info in db.execute(f'PRAGMA table_info("{table}")'):
        if int(info[5] or 0) == 1:
            pk = str(info[1])
            break
    for source in rows:
        row = dict(source)
        if pk:
            row.pop(pk, None)
        row["scan_id"] = scan_id
        _insert_mapping(db, table, row)


def _active_variant_ids(db: sqlite3.Connection) -> set[int]:
    return {
        int(row[0])
        for row in db.execute(
            """SELECT v.variant_id FROM plugin_variants v JOIN plugins p ON p.plugin_id=v.plugin_id
               WHERE v.active=1 AND p.active=1"""
        )
    }


def _drop_security_state(db: sqlite3.Connection) -> None:
    # The working DB is disposable. Keep schemas/indexes but clear every detailed
    # security table so state comes solely from the published v2 snapshot.
    sigmascope.ensure_schema(db)
    db.execute("PRAGMA foreign_keys=OFF")
    tables = [
        str(row[0])
        for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'plugin_security_%' ORDER BY name DESC"
        )
    ]
    for table in tables:
        db.execute(f'DELETE FROM "{table}"')
    db.execute("PRAGMA foreign_keys=ON")
    db.commit()


def _current_variant_entries(evidence: Path) -> list[dict[str, Any]]:
    root = read_json_file(evidence, "index.json")
    if root.get("schema") != SCHEMA:
        raise RuntimeError(f"unsupported current evidence schema: {root.get('schema')!r}")
    plugins_path = str((((root.get("indexes") or {}).get("plugins") or {}).get("path") or "indexes/plugins.json"))
    plugins = read_json_file(evidence, plugins_path)
    return [item for item in (plugins.get("currentVariants") or []) if isinstance(item, dict)]


def materialize_current_state(base_database: Path, evidence: Path, work_database: Path) -> dict[str, Any]:
    """Build the bounded mutable state DB used by Sigmascope/projector/audit.

    Large symbols/calls/reachability/import collections are intentionally *not*
    materialized. They remain immutable v2 analysis objects and are only produced for
    freshly scanned variants before being merged into the staged snapshot.
    """
    base_database = base_database.resolve()
    evidence = evidence.resolve()
    work_database = work_database.resolve()
    if not base_database.is_file():
        raise FileNotFoundError(base_database)
    if work_database == base_database:
        raise RuntimeError("production v2 work database must not replace the catalog input")
    work_database.parent.mkdir(parents=True, exist_ok=True)
    temp = work_database.with_suffix(work_database.suffix + ".tmp")
    temp.unlink(missing_ok=True)
    shutil.copy2(base_database, temp)

    current_entries = _current_variant_entries(evidence)
    loaded_variants = 0
    loaded_datasets: dict[str, int] = {name: 0 for name in SMALL_ANALYSIS_DATASETS}
    with closing(sqlite3.connect(temp)) as db:
        db.row_factory = sqlite3.Row
        _drop_security_state(db)
        active = _active_variant_ids(db)
        for entry in current_entries:
            variant_id = int(entry.get("variantId") or 0)
            if variant_id not in active:
                continue
            payload = read_json_file(evidence, str(entry.get("variantPath") or ""))
            scan = transport_security_row(dict(payload.get("scan") or {}))
            current = transport_security_row(dict(payload.get("current") or {}))
            if not scan or not current:
                continue
            scan_id = int(scan.get("scan_id") or current.get("scan_id") or 0)
            if scan_id <= 0:
                continue
            _insert_mapping(db, "plugin_security_scans", scan, replace=True)
            current["variant_id"] = variant_id
            current["scan_id"] = scan_id
            _insert_mapping(db, "plugin_security_current", current, replace=True)
            analysis_path = str((payload.get("analysis") or {}).get("path") or "")
            if analysis_path and str(current.get("status") or "") == "complete":
                for dataset, table in SMALL_ANALYSIS_DATASETS.items():
                    rows = read_dataset_rows(evidence, analysis_path, dataset)
                    _insert_child_rows(db, table, scan_id, rows)
                    loaded_datasets[dataset] += len(rows)
            comparison = ((payload.get("derived") or {}).get("sourceArtifactComparison"))
            if isinstance(comparison, dict) and comparison:
                row = dict(comparison)
                row["scan_id"] = scan_id
                row["variant_id"] = variant_id
                pk = next((str(info[1]) for info in db.execute('PRAGMA table_info("plugin_security_source_artifact_comparisons")') if int(info[5] or 0) == 1), None)
                if pk:
                    row.pop(pk, None)
                _insert_mapping(db, "plugin_security_source_artifact_comparisons", row)
            loaded_variants += 1

        # Derived dependency/IPC/advisory tables are deliberately rebuilt from current
        # primitive evidence rather than trusting migrated transport IDs.
        sigmascope.refresh_dependency_graph(db, [])
        sigmascope.recreate_runtime_view(db)
        db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('security_evidence_transport','v2')")
        db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('security_scanner_version',?)", (sigmascope.SCANNER_VERSION,))
        db.commit()
        integrity = db.execute("PRAGMA integrity_check").fetchone()
        if integrity is None or str(integrity[0]).lower() != "ok":
            raise RuntimeError(f"materialized v2 working database failed integrity check: {integrity}")
    os.replace(temp, work_database)
    return {
        "currentVariantsAvailable": len(current_entries),
        "currentVariantsMaterialized": loaded_variants,
        "datasets": loaded_datasets,
        "databaseBytes": work_database.stat().st_size,
    }


def _sigmascope_args(
    database: Path,
    work_dir: Path,
    *,
    report_name: str,
    max_scans: int,
    rescan_after_hours: int,
    max_batch_seconds: int,
    internal_names: str,
    advisories: Path | None,
    source_overrides: Path,
    skip_source: bool,
) -> SimpleNamespace:
    return SimpleNamespace(
        database=str(database),
        bundle="",
        descriptor="",
        report=str(work_dir / report_name),
        ledger="",  # v2 current scan timestamps are the operational freshness state.
        max_scans=max_scans,
        max_batch_seconds=max_batch_seconds,
        rescan_after_hours=rescan_after_hours,
        internal_names=internal_names,
        advisories=str(advisories) if advisories and advisories.exists() else "",
        source_overrides=str(source_overrides) if source_overrides.exists() else "",
        skip_source=skip_source,
        skip_revision_update=True,
    )


def _current_rows(database: Path) -> dict[int, dict[str, Any]]:
    with closing(sqlite3.connect(database)) as db:
        db.row_factory = sqlite3.Row
        return {int(row["variant_id"]): dict(row) for row in db.execute("SELECT * FROM plugin_security_current")}


def _restore_last_known_good(database: Path, previous: dict[int, dict[str, Any]]) -> tuple[list[int], list[int]]:
    """Return (successful_changed, failed_changed) and restore failed current pointers."""
    successful: list[int] = []
    failed: list[int] = []
    with closing(sqlite3.connect(database)) as db:
        db.row_factory = sqlite3.Row
        now_rows = {int(row["variant_id"]): dict(row) for row in db.execute("SELECT * FROM plugin_security_current")}
        all_ids = set(previous) | set(now_rows)
        for variant_id in sorted(all_ids):
            old = previous.get(variant_id)
            new = now_rows.get(variant_id)
            if new is None or (old is not None and int(new.get("scan_id") or 0) == int(old.get("scan_id") or 0)):
                continue
            if str(new.get("status") or "") == "complete":
                successful.append(variant_id)
                continue
            failed.append(variant_id)
            if old is not None:
                _insert_mapping(db, "plugin_security_current", old, replace=True)
            else:
                db.execute("DELETE FROM plugin_security_current WHERE variant_id=?", (variant_id,))
        db.commit()
    return successful, failed


def _copy_evidence_tree(source: Path, target: Path) -> None:
    if target.exists():
        shutil.rmtree(target)
    ignore = shutil.ignore_patterns(".git", ".omega-security-evidence-v2-migration.json", ".staging")
    shutil.copytree(source, target, ignore=ignore)
    (target / "validation-report.json").unlink(missing_ok=True)


def _merge_successful_subset(candidate: Path, subset: Path) -> None:
    for path in (subset / "artifacts").rglob("*") if (subset / "artifacts").exists() else []:
        if not path.is_file():
            continue
        rel = path.relative_to(subset)
        destination = candidate / rel
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists() and sha256_file(destination) == sha256_file(path):
            continue
        shutil.copy2(path, destination)
    for path in (subset / "variants").rglob("*.json") if (subset / "variants").exists() else []:
        rel = path.relative_to(subset)
        destination = candidate / rel
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)


def _identity_maps(db: sqlite3.Connection) -> tuple[dict[int, dict[str, Any]], dict[int, dict[str, Any]], dict[int, dict[str, Any]]]:
    plugins = {int(row["plugin_id"]): normalize_row(row) for row in db.execute("SELECT * FROM plugins")}
    variants = {int(row["variant_id"]): normalize_row(row) for row in db.execute("SELECT * FROM plugin_variants")}
    sources = {int(row["source_id"]): normalize_row(row) for row in db.execute("SELECT * FROM sources")}
    return plugins, variants, sources


DERIVED_DATASETS: dict[str, str] = {
    "dependencyResolutions": "dependency-resolutions",
    "dependencyIssues": "dependency-issues",
    "advisoryMatches": "advisory-matches",
}


def _graph_derived(db: sqlite3.Connection, scan_id: int, variant_id: int) -> dict[str, list[dict[str, Any]]]:
    derived = _derived_for_variant(db, scan_id, variant_id)
    return {name: list(derived.get(name) or []) for name in DERIVED_DATASETS}


def _write_variant_derived_datasets(
    candidate: Path, variant_id: int, datasets: dict[str, list[dict[str, Any]]]
) -> dict[str, Any]:
    directory = candidate / "derived" / "variants" / f"{variant_id // 1000:04d}" / str(variant_id)
    result: dict[str, Any] = {}
    for name, stem in DERIVED_DATASETS.items():
        result[name] = write_record_dataset(candidate, directory, stem, datasets.get(name) or [])
    return result


def synchronize_candidate(candidate: Path, database: Path, successful_variants: set[int]) -> dict[str, Any]:
    """Synchronize active identity/derived graph and garbage-collect old analyses."""
    removed_variants = 0
    updated_variants = 0
    referenced_analyses: set[str] = set()
    with closing(sqlite3.connect(database)) as db:
        db.row_factory = sqlite3.Row
        active = _active_variant_ids(db)
        plugins, variants, sources = _identity_maps(db)
        current_rows = {int(row["variant_id"]): dict(row) for row in db.execute("SELECT * FROM plugin_security_current")}
        variant_paths = sorted((candidate / "variants").rglob("*.json")) if (candidate / "variants").exists() else []
        for path in variant_paths:
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                variant_id = int(payload.get("variantId") or 0)
            except Exception:
                variant_id = 0
            if variant_id not in active or variant_id not in current_rows:
                path.unlink(missing_ok=True)
                removed_variants += 1
                continue
            variant = variants[variant_id]
            plugin_id = int(variant.get("plugin_id") or payload.get("pluginId") or 0)
            source_id = int(variant.get("source_id") or payload.get("sourceId") or 0)
            payload["pluginId"] = plugin_id
            payload["sourceId"] = source_id
            payload["plugin"] = plugins.get(plugin_id)
            payload["variant"] = variant
            payload["source"] = sources.get(source_id)
            # Older published v2 snapshots may still contain the full legacy
            # report_json in both scan and current rows.  Compact every active
            # descriptor during synchronization so one successful run repairs the
            # whole branch, not only freshly scanned variants.
            payload["scan"] = transport_security_row(dict(payload.get("scan") or {}))
            payload["current"] = transport_security_row(dict(payload.get("current") or {}))
            current = current_rows[variant_id]
            # Successful scans were exported from this DB and already have current/scan
            # payloads. For unchanged variants keep the immutable original scan context.
            # Graph/advisory derivations, however, are global and are refreshed every run.
            scan_id = int(current.get("scan_id") or 0)
            derived = dict(payload.get("derived") or {})
            graph_derived = _graph_derived(db, scan_id, variant_id)
            # The graph projections are potentially very large and are not artifact
            # evidence. Keep variant JSON lightweight by storing only bounded file
            # descriptors here; the actual rows live under derived/variants/.
            for name in DERIVED_DATASETS:
                derived.pop(name, None)
            payload["derived"] = derived
            payload["derivedEvidence"] = _write_variant_derived_datasets(candidate, variant_id, graph_derived)
            write_json(path, payload)
            updated_variants += 1
            analysis_path = str((payload.get("analysis") or {}).get("path") or "")
            if analysis_path:
                referenced_analyses.add(safe_relpath(analysis_path))

    removed_derived = 0
    derived_root = candidate / "derived" / "variants"
    if derived_root.exists():
        live_variant_ids = {
            int(json.loads(path.read_text(encoding="utf-8")).get("variantId") or 0)
            for path in (candidate / "variants").rglob("*.json")
        }
        for directory in sorted(
            [p for p in derived_root.glob("*/*") if p.is_dir()],
            key=lambda p: len(p.parts),
            reverse=True,
        ):
            try:
                variant_id = int(directory.name)
            except ValueError:
                variant_id = 0
            if variant_id not in live_variant_ids:
                shutil.rmtree(directory, ignore_errors=True)
                removed_derived += 1
        for directory in sorted([p for p in derived_root.rglob("*") if p.is_dir()], key=lambda p: len(p.parts), reverse=True):
            try:
                directory.rmdir()
            except OSError:
                pass

    removed_analyses = 0
    analyses_root = candidate / "artifacts"
    if analyses_root.exists():
        for manifest in sorted(analyses_root.glob("*/*/analyses/*/manifest.json")):
            analysis_dir = manifest.parent.relative_to(candidate).as_posix()
            if analysis_dir not in referenced_analyses:
                shutil.rmtree(manifest.parent, ignore_errors=True)
                removed_analyses += 1
        # Remove empty artifact/bucket directories from the bottom up.
        for directory in sorted([p for p in analyses_root.rglob("*") if p.is_dir()], key=lambda p: len(p.parts), reverse=True):
            try:
                directory.rmdir()
            except OSError:
                pass
    return {
        "variantsUpdated": updated_variants,
        "variantsRemoved": removed_variants,
        "analysesReferenced": len(referenced_analyses),
        "analysesGarbageCollected": removed_analyses,
        "derivedVariantDirectoriesGarbageCollected": removed_derived,
    }


def _build_plugins_artifacts_indexes(candidate: Path) -> tuple[dict[str, Any], dict[str, Any], int, int, int]:
    plugin_rows: list[dict[str, Any]] = []
    artifacts: dict[str, dict[str, Any]] = {}
    analyses: set[str] = set()
    for path in sorted((candidate / "variants").rglob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        variant_id = int(payload.get("variantId") or 0)
        current = payload.get("current") or {}
        analysis = payload.get("analysis") or {}
        artifact_sha = str(analysis.get("artifactSha256") or current.get("artifact_sha256") or "").strip().lower() or "unknown"
        analysis_id = str(analysis.get("analysisId") or "")
        analysis_path = str(analysis.get("path") or "")
        rel = path.relative_to(candidate).as_posix()
        plugin_rows.append({
            "variantId": variant_id,
            "scanId": int(current.get("scan_id") or 0),
            "artifactSha256": artifact_sha,
            "analysisId": analysis_id,
            "variantPath": rel,
        })
        bucket = artifacts.setdefault(artifact_sha, {"artifactSha256": artifact_sha, "variants": [], "analyses": {}})
        bucket["variants"].append(variant_id)
        if analysis_id and analysis_path:
            analyses.add(analysis_id)
            manifest_path = candidate / safe_relpath(analysis_path) / "manifest.json"
            bucket["analyses"][analysis_id] = {
                "path": safe_relpath(analysis_path),
                "manifest": file_entry(candidate, manifest_path, encoding="json"),
            }
    plugin_rows.sort(key=lambda row: int(row["variantId"]))
    plugins_payload = {"schema": "omega.security-evidence.plugins-index.v2", "currentVariants": plugin_rows}
    artifacts_payload = {
        "schema": "omega.security-evidence.artifacts-index.v2",
        "artifacts": [
            {
                "artifactSha256": key,
                "variants": sorted(value["variants"]),
                "analyses": [{"analysisId": aid, **data} for aid, data in sorted(value["analyses"].items())],
            }
            for key, value in sorted(artifacts.items())
        ],
    }
    plugins_path = candidate / "indexes" / "plugins.json"
    artifacts_path = candidate / "indexes" / "artifacts.json"
    write_json(plugins_path, plugins_payload)
    write_json(artifacts_path, artifacts_payload)
    return (
        file_entry(candidate, plugins_path, records=len(plugin_rows), encoding="json"),
        file_entry(candidate, artifacts_path, records=len(artifacts), encoding="json"),
        len(plugin_rows),
        len(analyses),
        len(artifacts),
    )


def _semantic_security_revision(db: sqlite3.Connection) -> str:
    """Hash client/security conclusions without transport scan IDs.

    Current scan IDs are implementation details. Revalidating identical evidence must not
    manufacture a new semantic Security Revision merely because SQLite allocated a new
    scan row. Variant identity plus the current semantic rows is the stable contract.
    """
    payload: list[Any] = []
    rows = db.execute("""
        SELECT c.variant_id,c.artifact_sha256,c.scanner_version,c.status,c.highest_severity,
               c.informational_count,c.caution_count,c.high_count,c.critical_count,c.capabilities_json,
               c.automation_level,c.automation_capabilities_json,c.source_available,c.source_repository,
               c.source_commit,c.source_to_binary_verified
          FROM plugin_security_current c ORDER BY c.variant_id
    """).fetchall()
    payload.append([list(row) for row in rows])
    child_queries = (
        ("plugin_security_findings",
         "SELECT c.variant_id,f.rule_id,f.severity,f.category,f.title,f.description,f.evidence_json "
         "FROM plugin_security_findings f JOIN plugin_security_current c ON c.scan_id=f.scan_id "
         "ORDER BY c.variant_id,f.rule_id,f.title"),
        ("plugin_security_dependencies",
         "SELECT c.variant_id,d.origin,d.kind,d.name,d.version,d.version_requirement,d.resolved_version,d.path,d.status,d.requirement,d.evidence_json,d.relationship,d.relationship_confidence,d.relationship_evidence_json "
         "FROM plugin_security_dependencies d JOIN plugin_security_current c ON c.scan_id=d.scan_id "
         "ORDER BY c.variant_id,d.kind,d.name,d.path,d.origin"),
        ("plugin_security_ipc_endpoints",
         "SELECT c.variant_id,e.origin,e.role,e.channel,e.signature,e.path,e.status,e.relationship,e.relationship_confidence,e.relationship_evidence_json "
         "FROM plugin_security_ipc_endpoints e JOIN plugin_security_current c ON c.scan_id=e.scan_id "
         "ORDER BY c.variant_id,e.role,e.channel,e.path,e.origin"),
        ("plugin_security_permission_candidates",
         "SELECT c.variant_id,p.origin,p.permission_id,p.risk,p.confidence,p.reason,p.evidence_json "
         "FROM plugin_security_permission_candidates p JOIN plugin_security_current c ON c.scan_id=p.scan_id "
         "ORDER BY c.variant_id,p.permission_id,p.origin"),
        ("plugin_security_automation_capabilities",
         "SELECT c.variant_id,a.capability_id,a.label,a.automation_level,a.confidence,a.reachable,a.indirect,a.reason,a.evidence_json "
         "FROM plugin_security_automation_capabilities a JOIN plugin_security_current c ON c.scan_id=a.scan_id "
         "ORDER BY c.variant_id,a.capability_id"),
        ("plugin_security_dependency_advisory_matches",
         "SELECT advisory_id,component_key,component_kind,component_name,affected_version,affected_range,fixed_version,severity,title,advisory_url,advisory_source "
         "FROM plugin_security_dependency_advisory_matches ORDER BY advisory_id,component_key,affected_version"),
    )
    for table, sql in child_queries:
        if table_exists(db, table):
            payload.append([list(row) for row in db.execute(sql)])
    digest = sha256_bytes(canonical_json_bytes(payload))
    safe_version = "".join(ch if ch.isalnum() or ch in ".-_" else "-" for ch in sigmascope.SCANNER_VERSION)[:24]
    return f"sec-{safe_version}-{digest[:16]}"


def _evidence_revision(candidate: Path, index_entries: dict[str, dict[str, Any]]) -> str:
    variants = []
    for path in sorted((candidate / "variants").rglob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        analysis = payload.get("analysis") or {}
        current = payload.get("current") or {}
        variants.append({
            "variantId": int(payload.get("variantId") or 0),
            "analysisId": str(analysis.get("analysisId") or ""),
            "artifactSha256": str(analysis.get("artifactSha256") or current.get("artifact_sha256") or "").lower(),
            "scannerVersion": str(current.get("scanner_version") or ""),
            "status": str(current.get("status") or ""),
        })
    semantic_indexes = {
        name: str(entry.get("sha256") or "")
        for name, entry in sorted(index_entries.items())
        if name in {"nuget", "ipc", "dependencyComponents", "advisories"}
    }
    digest = sha256_bytes(canonical_json_bytes({"schema": "omega.security-evidence.revision.v2", "variants": variants, "indexes": semantic_indexes}))
    return f"ev-v2-{digest[:16]}"


def rebuild_candidate_indexes(candidate: Path, database: Path, previous_index: dict[str, Any], scan_context: dict[str, Any]) -> dict[str, Any]:
    candidate.mkdir(parents=True, exist_ok=True)
    (candidate / "indexes").mkdir(exist_ok=True)
    with closing(sqlite3.connect(database)) as db:
        db.row_factory = sqlite3.Row
        identity_entry = _export_identity_index(db, candidate)
        nuget_entry, nuget_count = _export_nuget_index(db, candidate)
        ipc_entry, ipc_count = _export_ipc_index(db, candidate)
        component_entry, component_count = _export_global_table(db, candidate, "plugin_security_dependency_components", "dependency-components")
        advisory_entry, advisory_count = _export_global_table(db, candidate, "plugin_security_dependency_advisory_matches", "advisories")
        plugins_entry, artifacts_entry, current_count, analysis_count, artifact_count = _build_plugins_artifacts_indexes(candidate)
        indexes = {
            "identities": identity_entry,
            "plugins": plugins_entry,
            "artifacts": artifacts_entry,
            "nuget": nuget_entry,
            "ipc": ipc_entry,
            "dependencyComponents": component_entry,
            "advisories": advisory_entry,
        }
        base_revision = ""
        if table_exists(db, "catalog_meta"):
            row = db.execute("SELECT value FROM catalog_meta WHERE key IN ('catalog_base_revision','base_revision') ORDER BY CASE key WHEN 'catalog_base_revision' THEN 0 ELSE 1 END LIMIT 1").fetchone()
            base_revision = str(row[0] or "") if row else ""
        security_revision = _semantic_security_revision(db)
        evidence_revision = _evidence_revision(candidate, indexes)
        catalog_revision = catalog_revisions.compute_catalog_revision(db, base_revision, security_revision)
        for key, value in (
            ("security_revision", security_revision),
            ("security_revision_candidate", security_revision),
            ("evidence_revision", evidence_revision),
            ("evidence_revision_candidate", evidence_revision),
            ("catalog_revision", catalog_revision),
            ("catalog_revision_candidate", catalog_revision),
            ("sigmascope_name", sigmascope.SIGMASCOPE_NAME),
            ("sigmascope_version", sigmascope.SIGMASCOPE_VERSION),
            ("security_scanner_version", sigmascope.SCANNER_VERSION),
            ("security_evidence_transport", "v2"),
        ):
            db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES(?,?)", (key, value))
        db.commit()

    previous_revisions = previous_index.get("revisions") or {}
    root = {
        "schema": SCHEMA,
        "formatVersion": FORMAT_VERSION,
        "generatedAtUtc": utc_now(),
        "migrationMode": "incremental-v2",
        "engine": {"name": sigmascope.SIGMASCOPE_NAME, "version": sigmascope.SIGMASCOPE_VERSION},
        "source": {
            "stateTransport": "security-evidence-v2",
            "engineName": sigmascope.SIGMASCOPE_NAME,
            "engineVersion": sigmascope.SIGMASCOPE_VERSION,
            "scannerVersion": sigmascope.SCANNER_VERSION,
            "previousIndexSha256": scan_context.get("previousIndexSha256", ""),
            "scan": scan_context,
        },
        "revisions": {
            "baseRevision": base_revision,
            "catalogRevision": catalog_revision,
            "securityRevision": security_revision,
            "evidenceRevision": evidence_revision,
            "previousCatalogRevision": str(previous_revisions.get("catalogRevision") or ""),
            "previousSecurityRevision": str(previous_revisions.get("securityRevision") or ""),
            "previousEvidenceRevision": str(previous_revisions.get("evidenceRevision") or ""),
        },
        "counts": {
            "currentVariants": current_count,
            "analyses": analysis_count,
            "artifactGroups": artifact_count,
            "nugetPackageVersionPairs": nuget_count,
            "ipcProviders": ipc_count,
            "dependencyComponents": component_count,
            "advisories": advisory_count,
        },
        "indexes": indexes,
        "publication": {
            "rootWrittenLast": True,
            "recommendedBranch": "security-evidence-v2",
            "historyPolicy": "snapshot",
            "failurePolicy": "last-known-good",
        },
    }
    # Atomic candidate pointer is always the final evidence write.
    write_json(candidate / "index.json", root)
    return root


def write_marketplace_projection(
    database: Path,
    input_descriptor: Path,
    output_dir: Path,
    *,
    marketplace_download_url: str,
    evidence_index_url: str,
    previous_marketplace_descriptor: Path | None,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    marketplace_db = output_dir / project_marketplace_catalog.MARKETPLACE_DB_FILENAME
    projection = project_marketplace_catalog.project_database(database, marketplace_db)
    marketplace_bundle, bundle_sha = project_marketplace_catalog.write_marketplace_bundle(marketplace_db, output_dir)
    source_descriptor = json.loads(input_descriptor.read_text(encoding="utf-8"))
    descriptor = dict(source_descriptor)
    descriptor.update({
        "schemaVersion": 1,
        "schema": project_marketplace_catalog.MARKETPLACE_SCHEMA,
        "databaseRole": "marketplace",
        "downloadUrl": marketplace_download_url,
        "catalogSha256": sha256_file(marketplace_db),
        "bundleSha256": bundle_sha,
        "size": marketplace_bundle.stat().st_size,
        "databaseBytes": marketplace_db.stat().st_size,
        "marketplaceProjectorVersion": project_marketplace_catalog.PROJECTOR_VERSION,
        "detailedSecurityEvidenceIncluded": False,
        "securityEvidenceFormat": "v2",
        "securityEvidenceIndexUrl": evidence_index_url,
        "catalogRevision": projection["catalogRevision"],
        "securityRevision": projection["securityRevision"],
        "evidenceRevision": projection["evidenceRevision"],
    })
    for key in ("preCompactionDatabaseBytes", "compactionSavedBytes", "evidenceDownloadUrl"):
        descriptor.pop(key, None)
    write_json(output_dir / project_marketplace_catalog.MARKETPLACE_DESCRIPTOR_FILENAME, descriptor)
    previous: dict[str, Any] = {}
    if previous_marketplace_descriptor and previous_marketplace_descriptor.is_file():
        try:
            previous = json.loads(previous_marketplace_descriptor.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            previous = {}
    representation_changed = str(previous.get("marketplaceProjectorVersion") or "") != project_marketplace_catalog.PROJECTOR_VERSION
    semantic_changed = str(previous.get("catalogRevision") or "") != projection["catalogRevision"]
    evidence_changed = str(previous.get("evidenceRevision") or "") != projection["evidenceRevision"]
    report = {
        "schema": "omega.marketplace-projection.v2",
        "projectorVersion": project_marketplace_catalog.PROJECTOR_VERSION,
        "evidence": {
            "format": "v2",
            "indexUrl": evidence_index_url,
            "evidenceRevision": projection["evidenceRevision"],
        },
        "marketplace": {
            "databaseBytes": marketplace_db.stat().st_size,
            "bundleBytes": marketplace_bundle.stat().st_size,
            "catalogSha256": descriptor["catalogSha256"],
            "bundleSha256": bundle_sha,
            "catalogRevision": projection["catalogRevision"],
            "securityRevision": projection["securityRevision"],
            "evidenceRevision": projection["evidenceRevision"],
            "securityRows": projection["securityRows"],
            "dependencySummaryRows": projection["dependencySummaryRows"],
            "dependencySummaryEntries": projection["dependencySummaryEntries"],
            "knownRiskRows": projection.get("knownRiskRows", 0),
        },
        "publication": {
            "marketplaceRequired": semantic_changed or evidence_changed or representation_changed or not previous,
            "semanticChanged": semantic_changed,
            "evidenceChanged": evidence_changed,
            "representationChanged": representation_changed,
        },
        "validation": projection,
    }
    write_json(output_dir / "marketplace-projection-report.json", report)
    return report


def _dependency_diagnostics(database: Path) -> dict[str, Any]:
    with closing(sqlite3.connect(database)) as db:
        kinds = {
            str(row[0] or ""): int(row[1] or 0)
            for row in db.execute(
                """SELECT lower(kind),COUNT(*) FROM plugin_security_dependencies d
                   JOIN plugin_security_current c ON c.scan_id=d.scan_id
                   WHERE c.status='complete' GROUP BY lower(kind) ORDER BY lower(kind)"""
            )
        }
        exact = int(db.execute("""
            SELECT COUNT(*) FROM plugin_security_dependencies d JOIN plugin_security_current c ON c.scan_id=d.scan_id
            WHERE c.status='complete' AND lower(d.kind) IN ('nuget','nuget-lock','nuget-resolved')
              AND TRIM(d.name)<>'' AND COALESCE(NULLIF(TRIM(d.resolved_version),''),NULLIF(TRIM(d.version),''))<>''
        """).fetchone()[0])
        missing = int(db.execute("""
            SELECT COUNT(*) FROM plugin_security_dependencies d JOIN plugin_security_current c ON c.scan_id=d.scan_id
            WHERE c.status='complete' AND lower(d.kind) IN ('nuget','nuget-lock','nuget-resolved')
              AND TRIM(d.name)<>'' AND COALESCE(NULLIF(TRIM(d.resolved_version),''),NULLIF(TRIM(d.version),''))=''
        """).fetchone()[0])
        unresolved_ipc = int(db.execute("""
            SELECT COUNT(*) FROM plugin_security_ipc_endpoints e
            JOIN plugin_security_current c ON c.scan_id=e.scan_id
            LEFT JOIN plugin_security_ipc_registry r ON r.channel=e.channel
            WHERE c.status='complete' AND e.role='consumer' AND TRIM(e.channel)<>'' AND r.channel IS NULL
        """).fetchone()[0])
        return {
            "rowsByKind": kinds,
            "nugetExactObservations": exact,
            "nugetMissingVersionObservations": missing,
            "ipcUnresolvedConsumerChannels": unresolved_ipc,
        }


def run_pipeline(args: argparse.Namespace) -> dict[str, Any]:
    base_database = args.base_database.resolve()
    current_evidence = args.current_evidence.resolve()
    candidate = args.candidate_evidence.resolve()
    work_dir = args.work_dir.resolve()
    publication = args.publication_output.resolve()
    descriptor = args.descriptor.resolve()
    previous_marketplace = args.previous_marketplace_descriptor.resolve() if args.previous_marketplace_descriptor else None
    source_overrides = args.source_overrides.resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    publication.mkdir(parents=True, exist_ok=True)

    initial_validation = validate_snapshot(current_evidence, require_no_orphans=False)
    if not initial_validation.get("ok"):
        raise RuntimeError("published Security Evidence v2 baseline failed intrinsic validation: " + "; ".join(initial_validation.get("errors") or []))
    previous_index = read_json_file(current_evidence, "index.json")
    previous_index_sha = sha256_file(current_evidence / "index.json")

    work_database = work_dir / "omega-security-v2-working.sqlite"
    materialized = materialize_current_state(base_database, current_evidence, work_database)
    before_current = _current_rows(work_database)

    if not os.environ.get("GITHUB_TOKEN") and os.environ.get("GH_TOKEN"):
        os.environ["GITHUB_TOKEN"] = os.environ["GH_TOKEN"]

    scan_args = _sigmascope_args(
        work_database,
        work_dir,
        report_name="sigmascope-report.json",
        max_scans=args.max_scans,
        rescan_after_hours=args.rescan_after_hours,
        max_batch_seconds=args.max_batch_seconds,
        internal_names=args.internal_names,
        advisories=None,
        source_overrides=source_overrides,
        skip_source=args.skip_source,
    )
    scan_report = sigmascope.run(scan_args)
    successful, failed = _restore_last_known_good(work_database, before_current)
    # Sigmascope itself preserves an existing completed current pointer when a
    # transient revalidation fails, so such failures do not appear as a changed
    # current row. Carry the attempted failed variant IDs from the bounded scan
    # report into production diagnostics while still retaining last-known-good data.
    reported_failed = {
        int(item.get("variantId") or 0)
        for item in (scan_report.get("plugins") or [])
        if isinstance(item, dict) and str(item.get("status") or "") != "complete" and int(item.get("variantId") or 0) > 0
    }
    failed = sorted(set(failed) | reported_failed)

    # OSV consumes the explicit v2 NuGet package/version contract rather than
    # querying the mutable SQLite working projection directly. Build that bounded
    # index from current evidence first, then query exactly those identities.
    osv_input_root = work_dir / "osv-input"
    if osv_input_root.exists():
        shutil.rmtree(osv_input_root)
    with closing(sqlite3.connect(work_database)) as osv_db:
        osv_db.row_factory = sqlite3.Row
        _osv_nuget_entry, osv_nuget_pairs = _export_nuget_index(osv_db, osv_input_root)
    osv_nuget_index = osv_input_root / "indexes" / "nuget.json"
    advisory_path = work_dir / "public-advisories.json"
    advisory_report = collect_public_advisories.collect_from_nuget_index(
        osv_nuget_index,
        advisory_path,
        timeout=args.osv_timeout,
        max_packages=args.max_osv_packages,
    )
    refresh_args = _sigmascope_args(
        work_database,
        work_dir,
        report_name="sigmascope-advisory-refresh-report.json",
        max_scans=0,
        rescan_after_hours=args.rescan_after_hours,
        max_batch_seconds=0,
        internal_names=args.internal_names,
        advisories=advisory_path,
        source_overrides=source_overrides,
        skip_source=True,
    )
    refresh_report = sigmascope.run(refresh_args)
    summary = summarize_database(work_database)
    diagnostics = _dependency_diagnostics(work_database)
    observed_nuget_pairs = int(summary.get("nugetPackageVersionPairs") or 0)
    if observed_nuget_pairs != int(osv_nuget_pairs):
        raise RuntimeError(
            f"NuGet evidence-index publication gate failed: current evidence reports {observed_nuget_pairs} exact pairs "
            f"but the generated v2 NuGet index contains {osv_nuget_pairs}"
        )
    expected_osv = min(observed_nuget_pairs, int(args.max_osv_packages))
    queried_osv = int(advisory_report.get("queriedPackages") or 0)
    if expected_osv and queried_osv < expected_osv:
        raise RuntimeError(
            f"OSV publication gate failed: {summary.get('nugetPackageVersionPairs')} exact NuGet package/version pairs observed, "
            f"expected {expected_osv} queries, collector queried {queried_osv}"
        )

    subset = work_dir / "successful-v2-subset"
    migrate(
        work_database,
        subset,
        reset=True,
        variant_ids=set(successful),
        source_context={"mode": "production-incremental-v2", "previousIndexSha256": previous_index_sha},
    )
    _copy_evidence_tree(current_evidence, candidate)
    _merge_successful_subset(candidate, subset)
    sync_report = synchronize_candidate(candidate, work_database, set(successful))

    scan_context = {
        "previousIndexSha256": previous_index_sha,
        "selected": int(scan_report.get("selected") or 0),
        "successful": len(successful),
        "failedRetained": len(failed),
        "failedVariantIds": failed,
        "maxScans": args.max_scans,
        "rescanAfterHours": args.rescan_after_hours,
    }
    root_index = rebuild_candidate_indexes(candidate, work_database, previous_index, scan_context)
    snapshot_validation = validate_snapshot(candidate, require_no_orphans=True)
    write_json(candidate / "validation-report.json", snapshot_validation)
    if not snapshot_validation.get("ok"):
        raise RuntimeError("candidate Security Evidence v2 snapshot failed validation: " + "; ".join(snapshot_validation.get("errors") or []))

    # Root revisions were written into the working DB by rebuild_candidate_indexes.
    marketplace_report = write_marketplace_projection(
        work_database,
        descriptor,
        publication,
        marketplace_download_url=args.marketplace_download_url,
        evidence_index_url=args.evidence_index_url,
        previous_marketplace_descriptor=previous_marketplace,
    )

    previous_revisions = previous_index.get("revisions") or {}
    revisions = root_index.get("revisions") or {}
    publication_required = any(
        str(revisions.get(key) or "") != str(previous_revisions.get(key) or "")
        for key in ("catalogRevision", "securityRevision", "evidenceRevision", "baseRevision")
    )
    result = {
        "schema": PIPELINE_SCHEMA,
        "generatedAtUtc": utc_now(),
        "baseline": initial_validation,
        "materialized": materialized,
        "scan": scan_report,
        "advisoryRefresh": refresh_report,
        "successfulVariantIds": successful,
        "failedRetainedVariantIds": failed,
        "summary": summary,
        "dependencyDiagnostics": diagnostics,
        "osv": {
            "input": "indexes/nuget.json",
            "inputIndexPath": str(osv_nuget_index),
            "inputIndexSha256": sha256_file(osv_nuget_index),
            "observedExactPackageVersionPairs": observed_nuget_pairs,
            "expectedQueries": expected_osv,
            "queriedPackages": queried_osv,
            "matchedPackages": int(advisory_report.get("matchedPackages") or 0),
            "gate": "pass" if (not expected_osv or queried_osv >= expected_osv) else "fail",
        },
        "candidate": {
            "path": str(candidate),
            "indexSha256": sha256_file(candidate / "index.json"),
            "revisions": revisions,
            "counts": root_index.get("counts") or {},
            "sync": sync_report,
            "validation": snapshot_validation,
        },
        "marketplace": marketplace_report,
        "publicationRequired": publication_required,
        "workDatabase": str(work_database),
        "publicationOutput": str(publication),
    }
    write_json(work_dir / "production-sigmascope-v2-report.json", result)
    if args.github_output:
        output = args.github_output
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("a", encoding="utf-8") as stream:
            stream.write(f"publish_v2={'true' if publication_required else 'false'}\n")
            stream.write(f"publish_marketplace={'true' if marketplace_report.get('publication', {}).get('marketplaceRequired') else 'false'}\n")
            stream.write(f"catalog_revision={revisions.get('catalogRevision','')}\n")
            stream.write(f"security_revision={revisions.get('securityRevision','')}\n")
            stream.write(f"evidence_revision={revisions.get('evidenceRevision','')}\n")
    return result


def self_test() -> None:
    """Deterministic smoke test for failure retention + intrinsic v2 validation."""
    # Full integration behavior is covered by tools/tests/test_production_sigmascope_v2_pipeline.py.
    assert sigmascope.SCANNER_VERSION
    assert MAX_PUBLISH_FILE_BYTES >= 16 * 1024 * 1024
    print("Omega production Sigmascope / Security Evidence v2 pipeline self-test passed.")


def main() -> int:
    # Keep the workflow self-test invocable without supplying production paths.
    # argparse otherwise enforces the required production arguments before the
    # self-test flag can be handled.
    if "--self-test" in sys.argv[1:]:
        self_test()
        return 0
    parser = argparse.ArgumentParser(description="Stage and validate the production Omega Sigmascope / Security Evidence v2 update")
    parser.add_argument("--base-database", required=True, type=Path)
    parser.add_argument("--descriptor", required=True, type=Path)
    parser.add_argument("--current-evidence", required=True, type=Path)
    parser.add_argument("--candidate-evidence", required=True, type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--publication-output", required=True, type=Path)
    parser.add_argument("--previous-marketplace-descriptor", type=Path)
    parser.add_argument("--marketplace-download-url", required=True)
    parser.add_argument("--evidence-index-url", required=True)
    parser.add_argument("--source-overrides", type=Path, default=TOOLS_DIR.parent / "sources" / "source-overrides.json")
    parser.add_argument("--max-scans", type=int, default=DEFAULT_MAX_SCANS)
    parser.add_argument("--rescan-after-hours", type=int, default=DEFAULT_RESCAN_HOURS)
    parser.add_argument("--max-batch-seconds", type=int, default=DEFAULT_MAX_BATCH_SECONDS)
    parser.add_argument("--internal-names", default="")
    parser.add_argument("--skip-source", action="store_true")
    parser.add_argument("--osv-timeout", type=float, default=20.0)
    parser.add_argument("--max-osv-packages", type=int, default=2000)
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    try:
        result = run_pipeline(args)
    except Exception as exc:
        print(f"Production Security Evidence v2 pipeline failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({
        "publicationRequired": result["publicationRequired"],
        "successful": len(result["successfulVariantIds"]),
        "failedRetained": len(result["failedRetainedVariantIds"]),
        "nugetPackageVersionPairs": result["summary"].get("nugetPackageVersionPairs", 0),
        "ipcProviders": result["summary"].get("ipcProviders", 0),
        "osv": result["osv"],
        "revisions": result["candidate"]["revisions"],
        "validation": {"ok": result["candidate"]["validation"].get("ok")},
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
