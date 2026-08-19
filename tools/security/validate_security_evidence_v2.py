#!/usr/bin/env python3
"""Validate an Omega security-evidence v2 migration against its v1 SQLite source.

The validator checks transport integrity and semantic parity. By default it validates
all current evidence, including the large managed-symbol/call/reachability datasets.
Use --quick only for iterative development; a migration intended for publication
should pass the default full validation.
"""
from __future__ import annotations

import argparse
from contextlib import closing
from collections import Counter
import gzip
import json
from pathlib import Path
import sqlite3
import sys
from typing import Any, Iterable, Sequence

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from security_evidence_v2 import (  # noqa: E402
    CORE_DATASETS,
    FORMAT_VERSION,
    LARGE_DATASETS,
    MAX_PUBLISH_FILE_BYTES,
    NUGET_KINDS,
    SCHEMA,
    canonical_json_bytes,
    normalize_row,
    open_ro,
    primary_key_column,
    read_meta,
    read_record_dataset,
    row_digest_from_query,
    safe_relpath,
    sha256_bytes,
    sha256_file,
    table_columns,
    table_exists,
    transport_security_row,
    verify_file_entry,
)

QUICK_SKIP = {"symbols", "calls", "reachability"}


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _canonical_counter(rows: Iterable[dict[str, Any]], *, exclude: Iterable[str] = ()) -> Counter[bytes]:
    excluded = set(exclude)
    result: Counter[bytes] = Counter()
    for row in rows:
        normalized = {k: v for k, v in row.items() if k not in excluded}
        result[canonical_json_bytes(normalized)] += 1
    return result


def _compare_exact(label: str, expected: Any, actual: Any, errors: list[str]) -> None:
    if canonical_json_bytes(expected) != canonical_json_bytes(actual):
        errors.append(f"{label} differs between v1 and v2")


def _verify_index_files(root: Path, index: dict[str, Any], errors: list[str]) -> None:
    for name, entry in (index.get("indexes") or {}).items():
        for error in verify_file_entry(root, entry, max_bytes=MAX_PUBLISH_FILE_BYTES):
            errors.append(f"index {name}: {error}")


def _verify_analysis_files(root: Path, manifest: dict[str, Any], errors: list[str]) -> None:
    for dataset, info in (manifest.get("datasets") or {}).items():
        total_records = 0
        for entry in info.get("files") or []:
            for error in verify_file_entry(root, entry, max_bytes=MAX_PUBLISH_FILE_BYTES):
                errors.append(f"analysis {manifest.get('analysisId')} dataset {dataset}: {error}")
            total_records += int(entry.get("records") or 0)
        if int(info.get("records") or 0) != total_records and info.get("files"):
            errors.append(
                f"analysis {manifest.get('analysisId')} dataset {dataset}: file record total {total_records} "
                f"!= dataset records {info.get('records')}"
            )


def _dataset_digest(db: sqlite3.Connection, scan_id: int, table: str, pk_hint: str) -> tuple[int, str]:
    if not table_exists(db, table):
        return 0, sha256_bytes(b"")
    pk = pk_hint if pk_hint in table_columns(db, table) else primary_key_column(db, table)
    exclude = {"scan_id"}
    if pk:
        exclude.add(pk)
    order = f' ORDER BY "{pk}"' if pk else ""
    return row_digest_from_query(db, f'SELECT * FROM "{table}" WHERE scan_id=?{order}', (scan_id,), exclude=exclude)


def _expected_nuget(db: sqlite3.Connection) -> list[dict[str, Any]]:
    if not table_exists(db, "plugin_security_dependencies"):
        return []
    placeholders = ",".join("?" for _ in NUGET_KINDS)
    return [normalize_row(row) for row in db.execute(f"""
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
    """, tuple(NUGET_KINDS))]


def _expected_global_table(db: sqlite3.Connection, table: str) -> list[dict[str, Any]]:
    if not table_exists(db, table):
        return []
    pk = primary_key_column(db, table)
    order = f' ORDER BY "{pk}"' if pk else ""
    return [normalize_row(row) for row in db.execute(f'SELECT * FROM "{table}"{order}')]


def _expected_identity(db: sqlite3.Connection) -> dict[str, Any]:
    payload: dict[str, Any] = {"schema": "omega.security-evidence.identities.v2"}
    for table in ("plugins", "plugin_variants", "sources"):
        payload[table] = _expected_global_table(db, table)
    return payload


def _expected_derived(db: sqlite3.Connection, scan_id: int) -> dict[str, Any]:
    if table_exists(db, "plugin_security_dependency_resolutions") and table_exists(db, "plugin_security_dependencies"):
        resolutions = [normalize_row(row) for row in db.execute("""
            SELECT r.* FROM plugin_security_dependency_resolutions r
            JOIN plugin_security_dependencies d ON d.dependency_id=r.dependency_id
            WHERE d.scan_id=? ORDER BY r.dependency_id
        """, (scan_id,))]
    else:
        resolutions = []
    issues = [normalize_row(row) for row in db.execute(
        "SELECT * FROM plugin_security_dependency_issues WHERE scan_id=? ORDER BY issue_id", (scan_id,)
    )] if table_exists(db, "plugin_security_dependency_issues") else []
    comparison = normalize_row(db.execute(
        "SELECT * FROM plugin_security_source_artifact_comparisons WHERE scan_id=?", (scan_id,)
    ).fetchone()) if table_exists(db, "plugin_security_source_artifact_comparisons") and db.execute(
        "SELECT 1 FROM plugin_security_source_artifact_comparisons WHERE scan_id=?", (scan_id,)
    ).fetchone() else None
    lineage = normalize_row(db.execute(
        "SELECT * FROM plugin_security_scan_lineage WHERE current_scan_id=?", (scan_id,)
    ).fetchone()) if table_exists(db, "plugin_security_scan_lineage") and db.execute(
        "SELECT 1 FROM plugin_security_scan_lineage WHERE current_scan_id=?", (scan_id,)
    ).fetchone() else None
    drift = [normalize_row(row) for row in db.execute(
        "SELECT * FROM plugin_security_dependency_drift WHERE current_scan_id=? ORDER BY drift_id", (scan_id,)
    )] if table_exists(db, "plugin_security_dependency_drift") else []
    advisories = [normalize_row(row) for row in db.execute("""
        SELECT DISTINCT a.* FROM plugin_security_dependency_advisory_matches a
        JOIN plugin_security_dependency_resolutions r ON r.component_key=a.component_key
        WHERE r.scan_id=?
        ORDER BY a.advisory_id,a.component_key,a.affected_version,a.affected_range
    """, (scan_id,))] if table_exists(db, "plugin_security_dependency_advisory_matches") and table_exists(db, "plugin_security_dependency_resolutions") else []
    return {
        "dependencyResolutions": resolutions,
        "dependencyIssues": issues,
        "sourceArtifactComparison": comparison,
        "scanLineage": lineage,
        "dependencyDrift": drift,
        "advisoryMatches": advisories,
    }


def validate(database: Path, evidence: Path, *, quick: bool = False) -> dict[str, Any]:
    database = database.resolve()
    evidence = evidence.resolve()
    errors: list[str] = []
    warnings: list[str] = []
    index_path = evidence / "index.json"
    if not index_path.is_file():
        return {"ok": False, "errors": ["index.json is missing; migration is incomplete"], "warnings": [], "checkedVariants": 0}
    index = _load_json(index_path)
    if index.get("schema") != SCHEMA or int(index.get("formatVersion") or 0) != FORMAT_VERSION:
        errors.append(f"unsupported root schema/version: {index.get('schema')} v{index.get('formatVersion')}")
    _verify_index_files(evidence, index, errors)
    artifacts_entry = (index.get("indexes") or {}).get("artifacts") or {}
    if artifacts_entry.get("path"):
        artifacts_payload = _load_json(evidence / safe_relpath(str(artifacts_entry["path"])))
        for artifact in artifacts_payload.get("artifacts") or []:
            for analysis in artifact.get("analyses") or []:
                manifest_entry = analysis.get("manifest") or {}
                for error in verify_file_entry(evidence, manifest_entry, max_bytes=MAX_PUBLISH_FILE_BYTES):
                    errors.append(f"analysis manifest {analysis.get('analysisId')}: {error}")

    checked_variants = 0
    checked_analyses: set[str] = set()
    with closing(open_ro(database)) as db:
        meta = read_meta(db)
        expected_revisions = {
            "baseRevision": meta.get("base_revision", meta.get("catalog_base_revision", "")),
            "catalogRevision": meta.get("catalog_revision", meta.get("catalog_revision_candidate", "")),
            "securityRevision": meta.get("security_revision", ""),
            "evidenceRevision": meta.get("evidence_revision", ""),
        }
        _compare_exact("root revisions", expected_revisions, index.get("revisions") or {}, errors)
        current_rows = list(db.execute("SELECT * FROM plugin_security_current ORDER BY variant_id"))
        if int((index.get("counts") or {}).get("currentVariants") or -1) != len(current_rows):
            errors.append(f"current variant count differs: v1={len(current_rows)}, v2={(index.get('counts') or {}).get('currentVariants')}")

        for current_row in current_rows:
            current = transport_security_row(normalize_row(current_row))
            variant_id = int(current["variant_id"])
            scan_id = int(current["scan_id"])
            variant_path = evidence / "variants" / f"{variant_id // 1000:04d}" / f"{variant_id}.json"
            if not variant_path.is_file():
                errors.append(f"variant {variant_id}: missing {variant_path.relative_to(evidence)}")
                continue
            payload = _load_json(variant_path)
            checked_variants += 1
            _compare_exact(f"variant {variant_id} current", current, payload.get("current"), errors)
            scan_row = db.execute("SELECT * FROM plugin_security_scans WHERE scan_id=?", (scan_id,)).fetchone()
            if scan_row is None:
                errors.append(f"variant {variant_id}: v1 current scan {scan_id} is missing")
                continue
            scan = transport_security_row(normalize_row(scan_row))
            _compare_exact(f"variant {variant_id} scan", scan, payload.get("scan"), errors)
            plugin = normalize_row(db.execute("SELECT * FROM plugins WHERE plugin_id=?", (scan["plugin_id"],)).fetchone())
            variant = normalize_row(db.execute("SELECT * FROM plugin_variants WHERE variant_id=?", (variant_id,)).fetchone())
            source = normalize_row(db.execute("SELECT * FROM sources WHERE source_id=?", (scan["source_id"],)).fetchone())
            _compare_exact(f"variant {variant_id} plugin identity", plugin, payload.get("plugin"), errors)
            _compare_exact(f"variant {variant_id} variant identity", variant, payload.get("variant"), errors)
            _compare_exact(f"variant {variant_id} source identity", source, payload.get("source"), errors)
            actual_derived = dict(payload.get("derived") or {})
            for name, descriptor in (payload.get("derivedEvidence") or {}).items():
                if name == "sourceAnalysisCache":
                    # Transport cache has no v1 relational equivalent; its intrinsic
                    # identity/digest contract is validated by security_evidence_v2.
                    continue
                if isinstance(descriptor, dict):
                    actual_derived[name] = read_record_dataset(evidence, descriptor)
            _compare_exact(f"variant {variant_id} derived evidence", _expected_derived(db, scan_id), actual_derived, errors)

            if str(current.get("status") or "") != "complete":
                continue
            analysis = payload.get("analysis") or {}
            analysis_path_text = str(analysis.get("path") or "")
            if not analysis_path_text:
                errors.append(f"variant {variant_id}: complete scan has no v2 analysis path")
                continue
            try:
                rel = safe_relpath(analysis_path_text)
            except ValueError as exc:
                errors.append(f"variant {variant_id}: {exc}")
                continue
            manifest_path = evidence / rel / "manifest.json"
            if not manifest_path.is_file():
                errors.append(f"variant {variant_id}: missing analysis manifest {rel}/manifest.json")
                continue
            manifest = _load_json(manifest_path)
            analysis_id = str(manifest.get("analysisId") or "")
            if analysis_id and analysis_id not in checked_analyses:
                _verify_analysis_files(evidence, manifest, errors)
                checked_analyses.add(analysis_id)
            datasets = manifest.get("datasets") or {}
            for dataset, table, pk in CORE_DATASETS:
                if quick and dataset in QUICK_SKIP:
                    continue
                count, digest = _dataset_digest(db, scan_id, table, pk)
                actual = datasets.get(dataset) or {}
                if int(actual.get("records") or 0) != count:
                    errors.append(f"variant {variant_id} dataset {dataset}: v1 rows={count}, v2 rows={actual.get('records')}")
                if str(actual.get("recordDigest") or "") != digest:
                    errors.append(f"variant {variant_id} dataset {dataset}: semantic record digest differs")

        identities_entry = (index.get("indexes") or {}).get("identities") or {}
        identities = _load_json(evidence / safe_relpath(str(identities_entry.get("path") or "")))
        _compare_exact("identity index", _expected_identity(db), identities, errors)

        nuget_entry = (index.get("indexes") or {}).get("nuget") or {}
        nuget = _load_json(evidence / safe_relpath(str(nuget_entry.get("path") or "")))
        _compare_exact("NuGet package/version index", _expected_nuget(db), nuget.get("packages") or [], errors)

        ipc_entry = (index.get("indexes") or {}).get("ipc") or {}
        ipc = _load_json(evidence / safe_relpath(str(ipc_entry.get("path") or "")))
        _compare_exact("IPC provider index", _expected_global_table(db, "plugin_security_ipc_registry"), ipc.get("providers") or [], errors)

        components_entry = (index.get("indexes") or {}).get("dependencyComponents") or {}
        components = _load_json(evidence / safe_relpath(str(components_entry.get("path") or "")))
        _compare_exact("dependency component index", _expected_global_table(db, "plugin_security_dependency_components"), components.get("records") or [], errors)

        advisories_entry = (index.get("indexes") or {}).get("advisories") or {}
        advisories = _load_json(evidence / safe_relpath(str(advisories_entry.get("path") or "")))
        _compare_exact("advisory index", _expected_global_table(db, "plugin_security_dependency_advisory_matches"), advisories.get("records") or [], errors)

    if quick:
        warnings.append("quick mode skipped managed symbols, calls, and reachability semantic parity")
    return {
        "schema": "omega.security-evidence.validation.v2",
        "ok": not errors,
        "mode": "quick" if quick else "full",
        "indexSha256": sha256_file(index_path),
        "evidenceRevision": str((index.get("revisions") or {}).get("evidenceRevision") or ""),
        "checkedVariants": checked_variants,
        "checkedAnalyses": len(checked_analyses),
        "errors": errors,
        "warnings": warnings,
    }



def infer_database_from_migration_state(evidence: Path) -> Path:
    state_path = evidence.resolve() / ".omega-security-evidence-v2-migration.json"
    if not state_path.is_file():
        raise RuntimeError("--database was omitted and the migration state file is unavailable")
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"cannot read migration state {state_path}: {exc}") from exc
    value = str(state.get("sourceDatabasePath") or "").strip()
    if not value:
        value = str((state.get("sourceContext") or {}).get("databasePath") or "").strip()
    if not value:
        raise RuntimeError("migration state does not record the source database path")
    database = Path(value).expanduser().resolve()
    if not database.is_file():
        raise RuntimeError(f"migration source database no longer exists: {database}")
    return database

def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Omega security-evidence v2 against the v1 SQLite database")
    parser.add_argument("--database", type=Path, help="v1 SQLite source; defaults to the migration state source path")
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--quick", action="store_true", help="Skip the three largest forensic dataset digests")
    parser.add_argument("--json", action="store_true", help="Print machine-readable validation JSON")
    parser.add_argument("--report", type=Path, help="Also write the validation report to this path")
    args = parser.parse_args()
    try:
        database = args.database.resolve() if args.database else infer_database_from_migration_state(args.evidence)
    except RuntimeError as exc:
        parser.error(str(exc))
    report = validate(database, args.evidence, quick=args.quick)
    text = json.dumps(report, indent=2, ensure_ascii=False)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(text + "\n", encoding="utf-8")
    if args.json or not report["ok"]:
        print(text)
    else:
        print(
            f"Security evidence v2 parity passed: {report['checkedVariants']} variants, "
            f"{report['checkedAnalyses']} unique analyses ({report['mode']} mode)."
        )
        for warning in report["warnings"]:
            print(f"WARNING: {warning}")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
