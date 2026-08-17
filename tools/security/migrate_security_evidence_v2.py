#!/usr/bin/env python3
"""Migrate Omega's v1 detailed SQLite security evidence to v2 shards.

This is intentionally a local/operator tool. It opens the source database read-only,
exports only the *current* security state into content-addressed artifact analyses,
preserves per-variant current/scan/source context, and writes the root index last.
The original SQLite database is never modified or deleted.

Typical use (download current production evidence, migrate, then validate):
    python tools/security/migrate_security_evidence_v2.py \
      --download-current \
      --output security-evidence-v2 \
      --resume \
      --validate

Offline/local database use remains available with ``--database``.

A phase-1 migration is current-state only. Historical v1 scans remain available in the
archived SQLite database while future v2 publications accumulate immutable analyses.
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
from typing import Any, Iterable, Sequence

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from security_evidence_download import default_cache_dir, download_current_database  # noqa: E402
from security_evidence_v2 import (  # noqa: E402
    CORE_DATASETS,
    DEFAULT_CHUNK_BYTES,
    FORMAT_VERSION,
    LARGE_DATASETS,
    NUGET_KINDS,
    SCHEMA,
    TRANSPORT_REPORT_SCHEMA,
    JsonlGzipChunkWriter,
    atomic_write_bytes,
    canonical_json_bytes,
    dataset_record_digest_from_hashes,
    file_entry,
    normalize_row,
    open_ro,
    primary_key_column,
    read_meta,
    sha256_bytes,
    sha256_file,
    table_columns,
    table_exists,
    transport_security_row,
    write_record_dataset,
)

STATE_FILE = ".omega-security-evidence-v2-migration.json"
DERIVED_DATASETS = {
    "dependencyResolutions": "dependency-resolutions",
    "dependencyIssues": "dependency-issues",
    "advisoryMatches": "advisory-matches",
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _write_json(path: Path, value: Any) -> None:
    atomic_write_bytes(path, (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8"))


def _db_signature(db: sqlite3.Connection, path: Path) -> dict[str, Any]:
    meta = read_meta(db)
    current_count = int(db.execute("SELECT COUNT(*) FROM plugin_security_current").fetchone()[0])
    max_scan = int(db.execute("SELECT COALESCE(MAX(scan_id),0) FROM plugin_security_current").fetchone()[0])
    return {
        "databaseBytes": path.stat().st_size,
        "currentScanCount": current_count,
        "maxCurrentScanId": max_scan,
        "baseRevision": meta.get("base_revision", meta.get("catalog_base_revision", "")),
        "catalogRevision": meta.get("catalog_revision", meta.get("catalog_revision_candidate", "")),
        "securityRevision": meta.get("security_revision", ""),
        "evidenceRevision": meta.get("evidence_revision", ""),
        "scannerVersion": meta.get("security_scanner_version", meta.get("scanner_version", "")),
    }


def _load_state(output: Path, signature: dict[str, Any], resume: bool) -> dict[str, Any]:
    path = output / STATE_FILE
    if not resume or not path.exists():
        return {"schema": SCHEMA, "formatVersion": FORMAT_VERSION, "source": signature, "completedVariants": {}}
    state = json.loads(path.read_text(encoding="utf-8"))
    if state.get("source") != signature:
        raise RuntimeError(
            "Migration state belongs to a different SQLite revision. Remove the output directory "
            "or rerun with --reset before resuming."
        )
    state.setdefault("completedVariants", {})
    return state


def _save_state(output: Path, state: dict[str, Any]) -> None:
    state["updatedAtUtc"] = utc_now()
    _write_json(output / STATE_FILE, state)


def _fetch_row(db: sqlite3.Connection, table: str, column: str, value: Any) -> dict[str, Any] | None:
    if not table_exists(db, table):
        return None
    row = db.execute(f'SELECT * FROM "{table}" WHERE "{column}"=?', (value,)).fetchone()
    return normalize_row(row) if row is not None else None


def _fetch_rows(db: sqlite3.Connection, sql: str, params: Sequence[Any] = (), *, exclude: Iterable[str] = ()) -> list[dict[str, Any]]:
    return [normalize_row(row, exclude=exclude) for row in db.execute(sql, params)]


def _semantic_dataset_row(row: sqlite3.Row, table: str, pk: str | None) -> dict[str, Any]:
    exclude = {"scan_id"}
    if pk:
        exclude.add(pk)
    return normalize_row(row, exclude=exclude)


def _export_dataset(
    db: sqlite3.Connection,
    scan_id: int,
    dataset: str,
    table: str,
    pk: str,
    analysis_dir: Path,
    evidence_root: Path,
    *,
    chunk_bytes: int,
) -> dict[str, Any]:
    if not table_exists(db, table):
        return {"records": 0, "recordDigest": sha256_bytes(b""), "files": [], "missingTable": True}

    actual_pk = pk if pk in table_columns(db, table) else primary_key_column(db, table)
    order = f' ORDER BY "{actual_pk}"' if actual_pk else ""
    cursor = db.execute(f'SELECT * FROM "{table}" WHERE scan_id=?{order}', (scan_id,))

    row_hashes: list[str] = []
    rows: list[dict[str, Any]] = []
    total_uncompressed = 0

    if dataset not in LARGE_DATASETS:
        for row in cursor:
            normalized = _semantic_dataset_row(row, table, actual_pk)
            encoded = canonical_json_bytes(normalized)
            row_hashes.append(sha256_bytes(encoded))
            rows.append(normalized)
            total_uncompressed += len(encoded) + 1
        count, record_digest = dataset_record_digest_from_hashes(row_hashes)
        # Human-readable JSON for ordinary evidence; fall back to chunked JSONL when
        # a plugin has an unusually large supposedly-small dataset.
        if total_uncompressed <= min(chunk_bytes, 8 * 1024 * 1024):
            path = analysis_dir / f"{dataset}.json"
            _write_json(path, rows)
            return {
                "records": count,
                "recordDigest": record_digest,
                "files": [file_entry(evidence_root, path, records=count, record_digest=record_digest, encoding="json")],
            }
        # Reuse the normalized rows below through the chunk writer.
        iterable = iter(rows)
    else:
        iterable = None

    writer = JsonlGzipChunkWriter(analysis_dir / "forensics", dataset, target_bytes=chunk_bytes)
    if iterable is not None:
        for normalized in iterable:
            writer.write(normalized)
    else:
        # Re-query because the original cursor was not materialized for large datasets.
        cursor = db.execute(f'SELECT * FROM "{table}" WHERE scan_id=?{order}', (scan_id,))
        for row in cursor:
            normalized = _semantic_dataset_row(row, table, actual_pk)
            encoded = canonical_json_bytes(normalized)
            row_hashes.append(sha256_bytes(encoded))
            writer.write(normalized)
    chunks = writer.close()
    count, record_digest = dataset_record_digest_from_hashes(row_hashes)
    return {
        "records": count,
        "recordDigest": record_digest,
        "files": [file_entry(
            evidence_root,
            analysis_dir / "forensics" / chunk.path,
            records=chunk.records,
            record_digest=chunk.record_digest,
            encoding=chunk.encoding,
        ) for chunk in chunks],
    }


def _analysis_id(artifact_sha: str, scanner_version: str, datasets: dict[str, Any]) -> str:
    semantic = {
        "artifactSha256": artifact_sha.lower(),
        "scannerVersion": scanner_version,
        "datasets": {name: {"records": item["records"], "recordDigest": item["recordDigest"]} for name, item in sorted(datasets.items())},
    }
    return sha256_bytes(canonical_json_bytes(semantic))


def _export_analysis(
    db: sqlite3.Connection,
    scan: dict[str, Any],
    output: Path,
    *,
    chunk_bytes: int,
) -> tuple[str, str, dict[str, Any]]:
    scan_id = int(scan["scan_id"])
    artifact_sha = str(scan.get("artifact_sha256") or "").strip().lower()
    artifact_group = artifact_sha if len(artifact_sha) == 64 else "unknown"
    stage_parent = output / ".staging"
    stage_parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f"scan-{scan_id}-", dir=stage_parent))
    try:
        datasets: dict[str, Any] = {}
        for dataset, table, pk in CORE_DATASETS:
            datasets[dataset] = _export_dataset(
                db, scan_id, dataset, table, pk, stage, output, chunk_bytes=chunk_bytes
            )
        analysis_id = _analysis_id(artifact_group, str(scan.get("scanner_version") or ""), datasets)
        shard = artifact_group[:2] if artifact_group != "unknown" else "unknown"
        target = output / "artifacts" / shard / artifact_group / "analyses" / analysis_id

        semantic_manifest = {
            "schema": "omega.security-evidence.analysis.v2",
            "formatVersion": FORMAT_VERSION,
            "analysisId": analysis_id,
            "artifactSha256": artifact_group,
            "engineName": "Sigmascope",
            "engineVersion": str(scan.get("scanner_version") or ""),
            "scannerVersion": str(scan.get("scanner_version") or ""),
            "datasets": datasets,
        }
        # Paths in staged file entries currently point at .staging. Rebase after moving.
        if target.exists():
            shutil.rmtree(stage)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            os.replace(stage, target)
        # Rebuild file entries against their canonical target paths.
        rebased_datasets: dict[str, Any] = {}
        for dataset, item in datasets.items():
            files = []
            for original in item.get("files") or []:
                filename = Path(str(original["path"])).name
                if str(original.get("encoding")) == "json":
                    actual = target / filename
                else:
                    actual = target / "forensics" / filename
                files.append(file_entry(
                    output,
                    actual,
                    records=int(original.get("records") or 0),
                    record_digest=str(original.get("recordDigest") or ""),
                    encoding=str(original.get("encoding") or ""),
                ))
            rebased_datasets[dataset] = {
                "records": int(item.get("records") or 0),
                "recordDigest": str(item.get("recordDigest") or ""),
                "files": files,
            }
            if item.get("missingTable"):
                rebased_datasets[dataset]["missingTable"] = True
        semantic_manifest["datasets"] = rebased_datasets
        semantic_manifest["recordCount"] = sum(int(item["records"]) for item in rebased_datasets.values())
        semantic_manifest["createdFromScanId"] = scan_id
        _write_json(target / "manifest.json", semantic_manifest)
        return analysis_id, target.relative_to(output).as_posix(), semantic_manifest
    finally:
        if stage.exists():
            shutil.rmtree(stage, ignore_errors=True)


def _derived_for_variant(db: sqlite3.Connection, scan_id: int, variant_id: int) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if table_exists(db, "plugin_security_dependency_resolutions") and table_exists(db, "plugin_security_dependencies"):
        result["dependencyResolutions"] = _fetch_rows(db, """
            SELECT r.* FROM plugin_security_dependency_resolutions r
            JOIN plugin_security_dependencies d ON d.dependency_id=r.dependency_id
            WHERE d.scan_id=? ORDER BY r.dependency_id
        """, (scan_id,))
    else:
        result["dependencyResolutions"] = []
    if table_exists(db, "plugin_security_dependency_issues"):
        result["dependencyIssues"] = _fetch_rows(
            db,
            "SELECT * FROM plugin_security_dependency_issues WHERE scan_id=? ORDER BY issue_id",
            (scan_id,),
        )
    else:
        result["dependencyIssues"] = []
    result["sourceArtifactComparison"] = _fetch_row(db, "plugin_security_source_artifact_comparisons", "scan_id", scan_id)
    result["scanLineage"] = _fetch_row(db, "plugin_security_scan_lineage", "current_scan_id", scan_id)
    if table_exists(db, "plugin_security_dependency_drift"):
        result["dependencyDrift"] = _fetch_rows(
            db,
            "SELECT * FROM plugin_security_dependency_drift WHERE current_scan_id=? ORDER BY drift_id",
            (scan_id,),
        )
    else:
        result["dependencyDrift"] = []
    if table_exists(db, "plugin_security_dependency_advisory_matches") and table_exists(db, "plugin_security_dependency_resolutions"):
        result["advisoryMatches"] = _fetch_rows(db, """
            SELECT DISTINCT a.* FROM plugin_security_dependency_advisory_matches a
            JOIN plugin_security_dependency_resolutions r ON r.component_key=a.component_key
            WHERE r.scan_id=?
            ORDER BY a.advisory_id,a.component_key,a.affected_version,a.affected_range
        """, (scan_id,))
    else:
        result["advisoryMatches"] = []
    return result


def _export_identity_index(db: sqlite3.Connection, output: Path) -> dict[str, Any]:
    payload: dict[str, Any] = {"schema": "omega.security-evidence.identities.v2"}
    for table in ("plugins", "plugin_variants", "sources"):
        if table_exists(db, table):
            pk = primary_key_column(db, table)
            order = f' ORDER BY "{pk}"' if pk else ""
            payload[table] = [normalize_row(row) for row in db.execute(f'SELECT * FROM "{table}"{order}')]
        else:
            payload[table] = []
    path = output / "indexes" / "identities.json"
    _write_json(path, payload)
    return file_entry(output, path, encoding="json")


def _export_nuget_index(db: sqlite3.Connection, output: Path) -> tuple[dict[str, Any], int]:
    packages: list[dict[str, Any]] = []
    if table_exists(db, "plugin_security_dependencies"):
        placeholders = ",".join("?" for _ in NUGET_KINDS)
        rows = db.execute(f"""
            SELECT lower(TRIM(d.name)) AS normalized_name,
                   TRIM(d.name) AS name,
                   COALESCE(NULLIF(TRIM(d.resolved_version),''),NULLIF(TRIM(d.version),'')) AS version,
                   COUNT(DISTINCT c.variant_id) AS variants,
                   COUNT(*) AS observations
              FROM plugin_security_dependencies d
              JOIN plugin_security_current c ON c.scan_id=d.scan_id
             WHERE c.status='complete'
               AND lower(d.kind) IN ({placeholders})
               AND TRIM(d.name)<>''
               AND COALESCE(NULLIF(TRIM(d.resolved_version),''),NULLIF(TRIM(d.version),''))<>''
             GROUP BY lower(TRIM(d.name)), COALESCE(NULLIF(TRIM(d.resolved_version),''),NULLIF(TRIM(d.version),''))
             ORDER BY lower(TRIM(d.name)), version
        """, tuple(NUGET_KINDS))
        packages = [normalize_row(row) for row in rows]
    payload = {
        "schema": "omega.security-evidence.nuget-index.v2",
        "ecosystem": "NuGet",
        "packageVersionPairs": len(packages),
        "packages": packages,
    }
    path = output / "indexes" / "nuget.json"
    _write_json(path, payload)
    return file_entry(output, path, records=len(packages), encoding="json"), len(packages)


def _export_ipc_index(db: sqlite3.Connection, output: Path) -> tuple[dict[str, Any], int]:
    registry = []
    if table_exists(db, "plugin_security_ipc_registry"):
        registry = [normalize_row(row) for row in db.execute(
            "SELECT * FROM plugin_security_ipc_registry ORDER BY channel COLLATE NOCASE,provider_plugin_id"
        )]
    payload = {"schema": "omega.security-evidence.ipc-index.v2", "providers": registry}
    path = output / "indexes" / "ipc.json"
    _write_json(path, payload)
    return file_entry(output, path, records=len(registry), encoding="json"), len(registry)


def _export_global_table(db: sqlite3.Connection, output: Path, table: str, filename: str) -> tuple[dict[str, Any], int]:
    rows: list[dict[str, Any]] = []
    if table_exists(db, table):
        pk = primary_key_column(db, table)
        order = f' ORDER BY "{pk}"' if pk else ""
        rows = [normalize_row(row) for row in db.execute(f'SELECT * FROM "{table}"{order}')]
    payload = {"schema": f"omega.security-evidence.{filename}.v2", "records": rows}
    path = output / "indexes" / f"{filename}.json"
    _write_json(path, payload)
    return file_entry(output, path, records=len(rows), encoding="json"), len(rows)


def migrate(
    database: Path,
    output: Path,
    *,
    resume: bool = False,
    reset: bool = False,
    chunk_bytes: int = DEFAULT_CHUNK_BYTES,
    source_context: dict[str, Any] | None = None,
    variant_ids: set[int] | None = None,
) -> dict[str, Any]:
    database = database.resolve()
    output = output.resolve()
    if not database.is_file():
        raise FileNotFoundError(database)
    if reset and output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)
    (output / "artifacts").mkdir(exist_ok=True)
    (output / "variants").mkdir(exist_ok=True)
    (output / "indexes").mkdir(exist_ok=True)

    with closing(open_ro(database)) as db:
        for required in ("plugin_security_current", "plugin_security_scans", "plugins", "plugin_variants", "sources"):
            if not table_exists(db, required):
                raise RuntimeError(f"source database is missing required table {required}")
        signature = _db_signature(db, database)
        if source_context and str(source_context.get("assetSha256") or "").strip():
            # A downloaded release asset has a strong immutable transport identity.
            # Include it in the resume signature so a replaced publication can never
            # reuse completed variant state merely because DB counts/revisions happen
            # to be equal.
            signature["sourceArchiveSha256"] = str(source_context["assetSha256"]).strip().lower()
        state = _load_state(output, signature, resume)
        # Operator-local source information is kept only in the migration state file,
        # which the publisher excludes from the evidence snapshot. This lets the
        # validator infer the source DB without leaking local paths into index.json.
        state["sourceDatabasePath"] = str(database)
        if source_context:
            state["sourceContext"] = source_context
        _save_state(output, state)
        if variant_ids is None:
            current_rows = list(db.execute("SELECT * FROM plugin_security_current ORDER BY variant_id"))
        else:
            wanted = sorted({int(item) for item in variant_ids})
            if wanted:
                placeholders = ",".join("?" for _ in wanted)
                current_rows = list(db.execute(
                    f"SELECT * FROM plugin_security_current WHERE variant_id IN ({placeholders}) ORDER BY variant_id",
                    tuple(wanted),
                ))
            else:
                current_rows = []
        analysis_paths: dict[str, str] = {}
        artifact_map: dict[str, dict[str, Any]] = {}
        plugin_index: list[dict[str, Any]] = []
        completed = state["completedVariants"]

        for position, current_row in enumerate(current_rows, start=1):
            current = transport_security_row(normalize_row(current_row))
            variant_id = int(current["variant_id"])
            scan_id = int(current["scan_id"])
            key = str(variant_id)
            variant_path = output / "variants" / f"{variant_id // 1000:04d}" / f"{variant_id}.json"
            cached = completed.get(key) or {}
            if resume and int(cached.get("scanId") or -1) == scan_id and variant_path.is_file():
                payload = json.loads(variant_path.read_text(encoding="utf-8"))
                analysis_id = str(payload.get("analysis", {}).get("analysisId") or "")
                analysis_path = str(payload.get("analysis", {}).get("path") or "")
                derived_evidence = payload.get("derivedEvidence") or {}
                has_bounded_derived = all(name in derived_evidence for name in DERIVED_DATASETS)
                has_bounded_reports = all(
                    not isinstance((payload.get(field) or {}).get("report_json"), dict)
                    or str(((payload.get(field) or {}).get("report_json") or {}).get("schema") or "") == TRANSPORT_REPORT_SCHEMA
                    for field in ("scan", "current")
                )
                if analysis_id and (output / analysis_path / "manifest.json").is_file() and has_bounded_derived and has_bounded_reports:
                    analysis_paths[analysis_id] = analysis_path
                    artifact_sha = str(current.get("artifact_sha256") or "").strip().lower() or "unknown"
                    bucket = artifact_map.setdefault(artifact_sha, {"artifactSha256": artifact_sha, "analyses": {}, "variants": []})
                    bucket["analyses"][analysis_id] = {"path": analysis_path, "manifest": file_entry(output, output / analysis_path / "manifest.json", encoding="json")}
                    bucket["variants"].append(variant_id)
                    plugin_index.append({"variantId": variant_id, "scanId": scan_id, "artifactSha256": artifact_sha, "analysisId": analysis_id, "variantPath": variant_path.relative_to(output).as_posix()})
                    print(f"[{position}/{len(current_rows)}] variant {variant_id}: resume", flush=True)
                    continue

            scan_row = db.execute("SELECT * FROM plugin_security_scans WHERE scan_id=?", (scan_id,)).fetchone()
            if scan_row is None:
                raise RuntimeError(f"current variant {variant_id} references missing scan {scan_id}")
            scan = transport_security_row(normalize_row(scan_row))
            plugin_id = int(scan["plugin_id"])
            source_id = int(scan["source_id"])
            plugin = _fetch_row(db, "plugins", "plugin_id", plugin_id)
            variant = _fetch_row(db, "plugin_variants", "variant_id", variant_id)
            source = _fetch_row(db, "sources", "source_id", source_id)

            analysis_id = ""
            analysis_path = ""
            analysis_manifest: dict[str, Any] | None = None
            if str(current.get("status") or "") == "complete":
                analysis_id, analysis_path, analysis_manifest = _export_analysis(
                    db, scan, output, chunk_bytes=chunk_bytes
                )
                analysis_paths[analysis_id] = analysis_path

            derived = _derived_for_variant(db, scan_id, variant_id)
            derived_evidence: dict[str, Any] = {}
            derived_dir = output / "derived" / "variants" / f"{variant_id // 1000:04d}" / str(variant_id)
            for name, stem in DERIVED_DATASETS.items():
                derived_evidence[name] = write_record_dataset(
                    output, derived_dir, stem, list(derived.pop(name, []) or []), chunk_bytes=chunk_bytes
                )
            payload = {
                "schema": "omega.security-evidence.variant.v2",
                "formatVersion": FORMAT_VERSION,
                "variantId": variant_id,
                "pluginId": plugin_id,
                "sourceId": source_id,
                "plugin": plugin,
                "variant": variant,
                "source": source,
                "current": current,
                "scan": scan,
                "analysis": {
                    "analysisId": analysis_id,
                    "path": analysis_path,
                    "artifactSha256": str(current.get("artifact_sha256") or "").strip().lower(),
                    "recordCount": int(analysis_manifest.get("recordCount") or 0) if analysis_manifest else 0,
                },
                "derived": derived,
                "derivedEvidence": derived_evidence,
            }
            _write_json(variant_path, payload)
            artifact_sha = str(current.get("artifact_sha256") or "").strip().lower() or "unknown"
            bucket = artifact_map.setdefault(artifact_sha, {"artifactSha256": artifact_sha, "analyses": {}, "variants": []})
            if analysis_id:
                bucket["analyses"][analysis_id] = {"path": analysis_path, "manifest": file_entry(output, output / analysis_path / "manifest.json", encoding="json")}
            bucket["variants"].append(variant_id)
            plugin_index.append({"variantId": variant_id, "scanId": scan_id, "artifactSha256": artifact_sha, "analysisId": analysis_id, "variantPath": variant_path.relative_to(output).as_posix()})
            completed[key] = {"scanId": scan_id, "variantPath": variant_path.relative_to(output).as_posix(), "analysisId": analysis_id, "analysisPath": analysis_path}
            _save_state(output, state)
            print(f"[{position}/{len(current_rows)}] variant {variant_id}: scan {scan_id} -> {analysis_id[:12] or 'no-analysis'}", flush=True)

        identity_entry = _export_identity_index(db, output)
        nuget_entry, nuget_count = _export_nuget_index(db, output)
        ipc_entry, ipc_count = _export_ipc_index(db, output)
        component_entry, component_count = _export_global_table(db, output, "plugin_security_dependency_components", "dependency-components")
        advisory_entry, advisory_count = _export_global_table(db, output, "plugin_security_dependency_advisory_matches", "advisories")

        plugin_payload = {
            "schema": "omega.security-evidence.plugins-index.v2",
            "currentVariants": plugin_index,
        }
        plugins_path = output / "indexes" / "plugins.json"
        _write_json(plugins_path, plugin_payload)
        plugins_entry = file_entry(output, plugins_path, records=len(plugin_index), encoding="json")

        artifacts_payload = {
            "schema": "omega.security-evidence.artifacts-index.v2",
            "artifacts": [
                {
                    "artifactSha256": key,
                    "variants": sorted(value["variants"]),
                    "analyses": [{"analysisId": aid, **data} for aid, data in sorted(value["analyses"].items())],
                }
                for key, value in sorted(artifact_map.items())
            ],
        }
        artifacts_path = output / "indexes" / "artifacts.json"
        _write_json(artifacts_path, artifacts_payload)
        artifacts_entry = file_entry(output, artifacts_path, records=len(artifact_map), encoding="json")

        meta = read_meta(db)
        root = {
            "schema": SCHEMA,
            "formatVersion": FORMAT_VERSION,
            "generatedAtUtc": utc_now(),
            "migrationMode": "current-state" if variant_ids is None else "incremental-subset",
            "engine": {"name": "Sigmascope", "version": str(signature.get("scannerVersion") or "")},
            "source": {
                **signature,
                "engineName": "Sigmascope",
                "engineVersion": str(signature.get("scannerVersion") or ""),
                "databaseFilename": database.name,
                "databaseBytes": database.stat().st_size,
            },
            "revisions": {
                "baseRevision": meta.get("base_revision", meta.get("catalog_base_revision", "")),
                "catalogRevision": meta.get("catalog_revision", meta.get("catalog_revision_candidate", "")),
                "securityRevision": meta.get("security_revision", ""),
                "evidenceRevision": meta.get("evidence_revision", ""),
            },
            "counts": {
                "currentVariants": len(current_rows),
                "analyses": len(analysis_paths),
                "artifactGroups": len(artifact_map),
                "nugetPackageVersionPairs": nuget_count,
                "ipcProviders": ipc_count,
                "dependencyComponents": component_count,
                "advisories": advisory_count,
            },
            "indexes": {
                "identities": identity_entry,
                "plugins": plugins_entry,
                "artifacts": artifacts_entry,
                "nuget": nuget_entry,
                "ipc": ipc_entry,
                "dependencyComponents": component_entry,
                "advisories": advisory_entry,
            },
            "publication": {
                "rootWrittenLast": True,
                "recommendedBranch": "security-evidence-v2",
                "historyPolicy": "snapshot",
            },
        }
        # index.json is the atomic revision pointer and is deliberately written last.
        _write_json(output / "index.json", root)
        state["complete"] = True
        state["rootIndexSha256"] = sha256_file(output / "index.json")
        _save_state(output, state)
        return root


def _resolve_source_database(
    database: Path | None,
    download_current: bool,
    cache_dir: Path | None,
) -> tuple[Path, dict[str, Any]]:
    if database is not None and download_current:
        raise ValueError("choose either --database or --download-current, not both")
    if database is not None:
        resolved = database.resolve()
        return resolved, {"mode": "local", "databasePath": str(resolved)}
    if not download_current:
        raise ValueError("either --database or --download-current is required")
    downloaded = download_current_database((cache_dir or default_cache_dir()).resolve())
    print(f"Using published v1 evidence database: {downloaded.database}", file=sys.stderr)
    print(f"Published archive SHA-256: {downloaded.asset_sha256}", file=sys.stderr)
    return downloaded.database.resolve(), downloaded.state_context()


def _validate_after_migration(database: Path, output: Path, report_path: Path) -> dict[str, Any]:
    # Import lazily so migration-only use does not pay validator startup cost.
    from validate_security_evidence_v2 import validate  # noqa: WPS433

    report = validate(database, output, quick=False)
    report_path = report_path.resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if report.get("ok") is not True:
        raise RuntimeError(f"Full v1↔v2 parity validation failed; see {report_path}")
    print(
        f"Full parity validation passed: {report.get('checkedVariants', 0)} variants, "
        f"{report.get('checkedAnalyses', 0)} unique analyses.",
        file=sys.stderr,
    )
    print(f"Validation report: {report_path}", file=sys.stderr)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Migrate Omega SQLite security evidence to v2 sharded JSON")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--database", type=Path, help="Local omega-security-evidence.sqlite")
    source.add_argument(
        "--download-current",
        action="store_true",
        help="Download/resume/verify/extract the currently published security-evidence-latest database",
    )
    parser.add_argument("--cache-dir", type=Path, help="Download cache directory (default: user Omega cache)")
    parser.add_argument("--output", required=True, type=Path, help="Output security-evidence-v2 directory")
    parser.add_argument("--resume", action="store_true", help="Resume a prior migration with the same source revision")
    parser.add_argument("--reset", action="store_true", help="Delete the output directory before migrating")
    parser.add_argument("--chunk-mib", type=int, default=16, help="Target compressed JSONL shard size (default: 16 MiB)")
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Run full v1↔v2 parity validation after migration and fail if it disagrees",
    )
    parser.add_argument(
        "--validation-report",
        type=Path,
        help="Validation report path (default with --validate: <output>/validation-report.json)",
    )
    args = parser.parse_args()
    if args.chunk_mib < 1 or args.chunk_mib > 30:
        parser.error("--chunk-mib must be between 1 and 30 MiB")
    try:
        database, source_context = _resolve_source_database(args.database, args.download_current, args.cache_dir)
    except (OSError, RuntimeError, ValueError) as exc:
        parser.error(str(exc))
    root = migrate(
        database,
        args.output,
        resume=args.resume,
        reset=args.reset,
        chunk_bytes=args.chunk_mib * 1024 * 1024,
        source_context=source_context,
    )
    result: dict[str, Any] = {
        "database": str(database),
        "output": str(args.output.resolve()),
        "counts": root["counts"],
        "revisions": root["revisions"],
    }
    if args.validate:
        report_path = (args.validation_report or (args.output / "validation-report.json")).resolve()
        try:
            report = _validate_after_migration(database, args.output.resolve(), report_path)
        except RuntimeError as exc:
            print(json.dumps(result, indent=2))
            print(str(exc), file=sys.stderr)
            return 1
        result["validation"] = {
            "ok": True,
            "mode": report.get("mode"),
            "report": str(report_path),
            "indexSha256": report.get("indexSha256"),
        }
    print(json.dumps(result, indent=2))
    if args.validate:
        print("Migration and full parity validation complete. The snapshot is ready for publication preflight.")
    else:
        print("Migration complete. Run validate_security_evidence_v2.py before publishing, or rerun with --validate.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
