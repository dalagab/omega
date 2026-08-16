#!/usr/bin/env python3
"""Project Omega's compacted security evidence database into the small client marketplace catalog.

The evidence database remains the server-side source of truth and contains normalized managed
symbols, IL call sites, reachability, scan history, dependency evidence and source/artifact data.
The marketplace projection intentionally carries only data required by the in-game application:
plugin/source metadata, current security summaries, automation summaries, semantic revisions and
catalog changelog entries.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
import zipfile
from typing import Any

PROJECTOR_VERSION = "1.1.0"
MARKETPLACE_DB_FILENAME = "omega-marketplace.sqlite"
MARKETPLACE_BUNDLE_FILENAME = "omega-marketplace.sqlite.zip"
CLIENT_INTERNAL_DB_FILENAME = "omega-catalog.sqlite"
EVIDENCE_BUNDLE_FILENAME = "omega-security-evidence.sqlite.zip"
EVIDENCE_DESCRIPTOR_FILENAME = "evidence.json"
MARKETPLACE_DESCRIPTOR_FILENAME = "catalog.json"
MARKETPLACE_SCHEMA = "omega.catalog.sqlite.v1"
EVIDENCE_SCHEMA = "omega.security-evidence.sqlite.v1"
DEPENDENCY_SUMMARY_LIMIT = 30

DETAILED_SECURITY_TABLES = (
    "plugin_security_scans",
    "plugin_security_findings",
    "plugin_security_dependencies",
    "plugin_security_imports",
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
    "plugin_security_permission_candidates",
    "plugin_security_automation_capabilities",
    "plugin_security_current",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_meta(db: sqlite3.Connection, key: str, default: str = "") -> str:
    row = db.execute("SELECT value FROM catalog_meta WHERE key=?", (key,)).fetchone()
    return str(row[0]) if row is not None and row[0] is not None else default


def runtime_projection_digest(db: sqlite3.Connection, ignore_columns: set[str] | None = None) -> str:
    cursor = db.execute("SELECT * FROM runtime_plugin_variants ORDER BY variant_id")
    all_names = [description[0] for description in cursor.description or []]
    ignored = {name.casefold() for name in (ignore_columns or set())}
    indices = [index for index, name in enumerate(all_names) if name.casefold() not in ignored]
    names = [all_names[index] for index in indices]
    digest = hashlib.sha256(json.dumps(names, separators=(",", ":")).encode("utf-8"))
    for row in cursor:
        digest.update(b"\n")
        digest.update(json.dumps([row[index] for index in indices], separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8"))
    return digest.hexdigest()


def _dependency_severity(rank: int) -> str:
    return {4: "critical", 3: "high", 2: "medium", 1: "low"}.get(rank, "")


def _dependency_requirement_rank(value: str) -> int:
    return {"required": 5, "soft": 4, "optional": 3, "bundled": 2, "observed": 1}.get(value.casefold(), 0)


def _framework_dependency_identity(name: str) -> tuple[str, str] | None:
    normalized = name.strip().casefold()
    if normalized == "dalamud" or normalized.startswith("dalamud."):
        return "Dalamud", "framework:dalamud"
    if normalized == "ffxivclientstructs" or normalized.startswith("ffxivclientstructs."):
        return "FFXIVClientStructs", "framework:ffxivclientstructs"
    return None


def _dependency_type(kind: str, requirement: str, name: str, target_internal_name: str) -> tuple[str, bool]:
    normalized_kind = kind.strip().casefold()
    normalized_requirement = requirement.strip().casefold()
    if _framework_dependency_identity(name) is not None:
        return "framework", True
    if normalized_kind == "ipc":
        return "ipc", False
    if normalized_kind == "external-plugin" or target_internal_name:
        return {"required": "hard", "soft": "soft", "optional": "optional"}.get(normalized_requirement, "plugin"), False
    if normalized_kind in {"nuget", "nuget-lock"}:
        return "package", False
    if normalized_kind in {"managed-assembly", "managed-assembly-reference", "assembly", "assembly-reference"}:
        return ("bundled-assembly" if normalized_requirement == "bundled" or normalized_kind == "managed-assembly" else "assembly"), False
    if normalized_kind in {"native-import", "native-library"}:
        return "native", False
    if normalized_kind == "project-reference":
        return "project", False
    if normalized_requirement == "bundled":
        return "bundled", False
    return normalized_kind or "component", False


def _dependency_is_presentation_candidate(item: dict[str, Any], source_internal_name: str = "") -> bool:
    """Only relationships to another plugin belong in the marketplace Dependencies panel.

    Framework assemblies, NuGet packages, native libraries and bundled/runtime components remain
    available to the security evidence pipeline, but they are capabilities/components rather than
    user-facing plugin dependencies. IPC is kept because it represents integration with another plugin.
    """
    name = str(item.get("name") or "").strip()
    kind = str(item.get("kind") or "").strip().casefold()
    dep_type = str(item.get("type") or "").strip().casefold()
    target_internal_name = str(item.get("targetInternalName") or "").strip()
    if not name:
        return False

    is_ipc = kind == "ipc" or dep_type == "ipc"
    is_plugin = kind == "external-plugin" or dep_type in {"hard", "soft", "optional", "plugin"} or bool(target_internal_name)
    if not is_ipc and not is_plugin:
        return False

    source = source_internal_name.strip().casefold()
    target = target_internal_name.casefold()
    if source and target and source == target:
        return False
    if source and not target and name.casefold() == source:
        return False
    return True


def build_dependency_summaries(db: sqlite3.Connection) -> dict[int, tuple[int, str]]:
    """Build a bounded, deduplicated UI summary from current dependency evidence.

    The detailed dependency tables stay server-side. Only relationship/type/version/resolution
    status and aggregate warning/advisory indicators are projected to Definitions.
    """
    table_names = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if "plugin_security_dependencies" not in table_names or "plugin_security_current" not in table_names:
        return {}

    resolution_join = "LEFT JOIN plugin_security_dependency_resolutions r ON r.dependency_id=d.dependency_id" if "plugin_security_dependency_resolutions" in table_names else "LEFT JOIN (SELECT NULL dependency_id) r ON 1=0"
    issue_ctes = ""
    issue_joins = ""
    issue_fields = "0 AS dependency_warning_rank,0 AS dependency_warning_count,0 AS component_warning_rank,0 AS component_warning_count"
    if "plugin_security_dependency_issues" in table_names:
        issue_ctes = """
        dependency_issues AS (
            SELECT dependency_id,
                   MAX(CASE lower(severity) WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'caution' THEN 2 WHEN 'low' THEN 1 WHEN 'informational' THEN 1 ELSE 0 END) AS warning_rank,
                   COUNT(*) AS warning_count
              FROM plugin_security_dependency_issues
             WHERE dependency_id IS NOT NULL
             GROUP BY dependency_id
        ),
        component_issues AS (
            SELECT component_key,
                   MAX(CASE lower(severity) WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'caution' THEN 2 WHEN 'low' THEN 1 WHEN 'informational' THEN 1 ELSE 0 END) AS warning_rank,
                   COUNT(*) AS warning_count
              FROM plugin_security_dependency_issues
             WHERE dependency_id IS NULL AND source_variant_id IS NULL AND component_key<>''
             GROUP BY component_key
        ),
        """
        issue_joins = "LEFT JOIN dependency_issues di ON di.dependency_id=d.dependency_id LEFT JOIN component_issues ci ON ci.component_key=COALESCE(r.component_key,'')"
        issue_fields = "COALESCE(di.warning_rank,0) AS dependency_warning_rank,COALESCE(di.warning_count,0) AS dependency_warning_count,COALESCE(ci.warning_rank,0) AS component_warning_rank,COALESCE(ci.warning_count,0) AS component_warning_count"

    advisory_cte = ""
    advisory_join = ""
    advisory_fields = "0 AS advisory_rank,0 AS advisory_count"
    if "plugin_security_dependency_advisory_matches" in table_names:
        advisory_cte = """
        advisories AS (
            SELECT component_key,
                   MAX(CASE lower(severity) WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'caution' THEN 2 WHEN 'moderate' THEN 2 WHEN 'low' THEN 1 WHEN 'informational' THEN 1 ELSE 0 END) AS warning_rank,
                   COUNT(*) AS advisory_count
              FROM plugin_security_dependency_advisory_matches
             WHERE component_key<>''
             GROUP BY component_key
        )
        """
        advisory_join = "LEFT JOIN advisories adv ON adv.component_key=COALESCE(r.component_key,'')"
        advisory_fields = "COALESCE(adv.warning_rank,0) AS advisory_rank,COALESCE(adv.advisory_count,0) AS advisory_count"

    ctes = issue_ctes + advisory_cte
    if ctes.strip().endswith(','):
        ctes = ctes.rstrip().rstrip(',')
    with_clause = f"WITH {ctes}" if ctes.strip() else ""
    query = f"""
        {with_clause}
        SELECT sc.variant_id,d.dependency_id,d.origin,d.kind,d.name,d.version,d.version_requirement,d.resolved_version,d.status,d.requirement,
               COALESCE(r.component_key,'') AS component_key,COALESCE(r.resolution_status,'') AS resolution_status,
               COALESCE(r.version_status,'') AS version_status,COALESCE(r.target_internal_name,'') AS target_internal_name,
               COALESCE(r.target_version,'') AS target_version,{issue_fields},{advisory_fields}
          FROM plugin_security_current sc
          JOIN plugin_security_dependencies d ON d.scan_id=sc.scan_id
          {resolution_join}
          {issue_joins}
          {advisory_join}
         WHERE sc.status='complete'
         ORDER BY sc.variant_id,d.dependency_id
    """

    source_internal_names = {
        int(row[0]): str(row[1] or "")
        for row in db.execute(
            "SELECT pv.variant_id,p.internal_name FROM plugin_variants pv JOIN plugins p ON p.plugin_id=pv.plugin_id"
        )
    } if "plugin_variants" in table_names and "plugins" in table_names else {}

    summaries: dict[int, tuple[int, str]] = {}
    current_variant: int | None = None
    merged: dict[tuple[str, str], dict[str, Any]] = {}

    def flush() -> None:
        nonlocal merged, current_variant
        if current_variant is None:
            return
        source_internal_name = source_internal_names.get(current_variant, "")
        items = [item for item in merged.values() if _dependency_is_presentation_candidate(item, source_internal_name)]
        total = len(items)
        items.sort(key=lambda item: (
            -_dependency_requirement_rank(str(item.get("requirement") or "")),
            -int(item.get("warningRank") or 0),
            0 if item.get("isFramework") else 1,
            0 if item.get("targetInternalName") else 1,
            str(item.get("name") or "").casefold(),
        ))
        projected = []
        for item in items[:DEPENDENCY_SUMMARY_LIMIT]:
            projected.append({
                "name": item["name"], "kind": item["kind"], "type": item["type"], "requirement": item["requirement"],
                "version": item["version"], "versionRequirement": item["versionRequirement"], "resolvedVersion": item["resolvedVersion"],
                "resolutionStatus": item["resolutionStatus"], "versionStatus": item["versionStatus"],
                "targetInternalName": item["targetInternalName"], "targetVersion": item["targetVersion"], "isFramework": item["isFramework"],
                "warningSeverity": _dependency_severity(int(item.get("warningRank") or 0)),
                "warningCount": int(item.get("warningCount") or 0), "advisoryCount": int(item.get("advisoryCount") or 0),
            })
        summaries[current_variant] = (total, json.dumps(projected, separators=(",", ":"), ensure_ascii=False))
        merged = {}

    for row in db.execute(query):
        variant_id = int(row[0])
        if current_variant is None:
            current_variant = variant_id
        elif variant_id != current_variant:
            flush()
            current_variant = variant_id

        kind = str(row[3] or "")
        name = str(row[4] or "").strip()
        requirement = str(row[9] or "observed").strip().casefold() or "observed"
        component_key = str(row[10] or "").strip().casefold()
        target_internal = str(row[13] or "").strip()
        framework_identity = _framework_dependency_identity(name)
        if framework_identity is not None:
            name, component_key = framework_identity
        key = (component_key or f"{kind.casefold()}:{name.casefold()}", target_internal.casefold())
        item = merged.get(key)
        dep_type, is_framework = _dependency_type(kind, requirement, name, target_internal)
        warning_rank = max(int(row[15] or 0), int(row[17] or 0), int(row[19] or 0))
        warning_count = int(row[16] or 0) + int(row[18] or 0)
        advisory_count = int(row[20] or 0)
        if item is None:
            merged[key] = {
                "name": name, "kind": kind, "type": dep_type, "requirement": requirement, "version": str(row[5] or ""),
                "versionRequirement": str(row[6] or ""), "resolvedVersion": str(row[7] or ""),
                "resolutionStatus": str(row[11] or ""), "versionStatus": str(row[12] or ""),
                "targetInternalName": target_internal, "targetVersion": str(row[14] or ""), "isFramework": is_framework,
                "warningRank": warning_rank, "warningCount": warning_count, "advisoryCount": advisory_count,
            }
            continue

        if _dependency_requirement_rank(requirement) > _dependency_requirement_rank(str(item.get("requirement") or "")):
            item["requirement"] = requirement
            item["type"], _ = _dependency_type(kind, requirement, name, target_internal)
        item["isFramework"] = bool(item.get("isFramework")) or is_framework
        item["warningRank"] = max(int(item.get("warningRank") or 0), warning_rank)
        item["warningCount"] = max(int(item.get("warningCount") or 0), warning_count)
        item["advisoryCount"] = max(int(item.get("advisoryCount") or 0), advisory_count)
        for field, value in (("versionRequirement", row[6]), ("resolvedVersion", row[7]), ("resolutionStatus", row[11]),
                             ("versionStatus", row[12]), ("targetInternalName", row[13]), ("targetVersion", row[14])):
            if not item.get(field) and value:
                item[field] = str(value)

    flush()
    return summaries


def create_marketplace_security_current(db: sqlite3.Connection) -> None:
    db.execute("DROP TABLE IF EXISTS marketplace_security_current")
    db.execute(
        """
        CREATE TABLE marketplace_security_current (
            variant_id INTEGER PRIMARY KEY,
            scan_id INTEGER NOT NULL DEFAULT 0,
            assembly_version TEXT NOT NULL DEFAULT '',
            artifact_channel TEXT NOT NULL DEFAULT 'stable',
            artifact_url TEXT NOT NULL DEFAULT '',
            artifact_sha256 TEXT NOT NULL DEFAULT '',
            scanner_version TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT '',
            scanned_at_utc TEXT NOT NULL DEFAULT '',
            highest_severity TEXT NOT NULL DEFAULT 'none',
            informational_count INTEGER NOT NULL DEFAULT 0,
            caution_count INTEGER NOT NULL DEFAULT 0,
            high_count INTEGER NOT NULL DEFAULT 0,
            critical_count INTEGER NOT NULL DEFAULT 0,
            capabilities_json TEXT NOT NULL DEFAULT '[]',
            automation_level TEXT NOT NULL DEFAULT 'none',
            automation_capabilities_json TEXT NOT NULL DEFAULT '[]',
            findings_json TEXT NOT NULL DEFAULT '[]',
            dependencies_json TEXT NOT NULL DEFAULT '[]',
            dependency_total_count INTEGER NOT NULL DEFAULT 0,
            source_available INTEGER NOT NULL DEFAULT 0,
            source_repository TEXT NOT NULL DEFAULT '',
            source_commit TEXT NOT NULL DEFAULT '',
            source_to_binary_verified INTEGER NOT NULL DEFAULT 0,
            error TEXT NOT NULL DEFAULT ''
        )
        """
    )
    columns = {row[1] for row in db.execute("PRAGMA table_info(plugin_security_current)")}
    automation_level = "automation_level" if "automation_level" in columns else "'none'"
    automation_caps = "automation_capabilities_json" if "automation_capabilities_json" in columns else "'[]'"
    db.execute(
        f"""
        INSERT INTO marketplace_security_current(
            variant_id,scan_id,assembly_version,artifact_channel,artifact_url,artifact_sha256,scanner_version,status,
            scanned_at_utc,highest_severity,informational_count,caution_count,high_count,critical_count,capabilities_json,
            automation_level,automation_capabilities_json,findings_json,source_available,source_repository,source_commit,
            source_to_binary_verified,error)
        SELECT variant_id,scan_id,assembly_version,artifact_channel,artifact_url,artifact_sha256,scanner_version,status,
               scanned_at_utc,highest_severity,informational_count,caution_count,high_count,critical_count,capabilities_json,
               {automation_level},{automation_caps},findings_json,source_available,source_repository,source_commit,
               source_to_binary_verified,error
          FROM plugin_security_current
        """
    )
    for variant_id, (total_count, encoded) in build_dependency_summaries(db).items():
        db.execute(
            "UPDATE marketplace_security_current SET dependencies_json=?,dependency_total_count=? WHERE variant_id=?",
            (encoded, total_count, variant_id),
        )


def create_marketplace_runtime_view(db: sqlite3.Connection) -> None:
    db.execute("DROP VIEW IF EXISTS runtime_plugin_variants")
    db.execute(
        """CREATE VIEW runtime_plugin_variants AS
           SELECT
             v.variant_id,p.plugin_id,p.internal_name,v.author,v.name,v.punchline,v.description,v.changelog,
             v.assembly_version,v.testing_assembly_version,v.dalamud_api_level,v.testing_dalamud_api_level,
             v.applicable_version,v.minimum_dalamud_version,v.repo_url,v.download_link_install,v.download_link_update,
             v.download_link_testing,v.icon_url,v.image_urls_json,v.tags_json,v.category_tags_json,v.download_count,
             v.last_update,v.is_hide,v.is_testing_exclusive,v.dip17_channel,s.name AS source_name,s.url AS source_url,
             s.is_official AS source_is_official,COALESCE(w.url,'') AS website_url,COALESCE(w.title,'') AS website_title,
             COALESCE(w.description,'') AS website_description,COALESCE(w.readme_excerpt,'') AS website_readme_excerpt,
             COALESCE(w.image_urls_json,'[]') AS website_image_urls_json,
             CASE WHEN w.website_id IS NOT NULL AND w.ok=1 THEN 1 ELSE 0 END AS website_enriched,
             COALESCE(pr.rich_card,0) AS rich_card,COALESCE(pr.official,0) AS plugin_official,COALESCE(pr.nsfw,0) AS plugin_nsfw,
             COALESCE(pr.richness_score,0) AS richness_score,
             CASE WHEN pr.presentation_variant_id=v.variant_id THEN 1 ELSE 0 END AS is_presentation_variant,
             CASE WHEN pr.preferred_variant_id=v.variant_id THEN 1 ELSE 0 END AS is_preferred_variant,
             COALESCE(sc.status,'') AS security_status,COALESCE(sc.scanned_at_utc,'') AS security_scanned_at_utc,
             COALESCE(sc.artifact_sha256,'') AS security_artifact_sha256,COALESCE(sc.scanner_version,'') AS security_scanner_version,
             COALESCE(sc.highest_severity,'none') AS security_highest_severity,
             COALESCE(sc.informational_count,0) AS security_informational_count,COALESCE(sc.caution_count,0) AS security_caution_count,
             COALESCE(sc.high_count,0) AS security_high_count,COALESCE(sc.critical_count,0) AS security_critical_count,
             COALESCE(sc.capabilities_json,'[]') AS security_capabilities_json,
             COALESCE(sc.automation_level,'none') AS security_automation_level,
             COALESCE(sc.automation_capabilities_json,'[]') AS security_automation_capabilities_json,
             COALESCE(sc.findings_json,'[]') AS security_findings_json,
             COALESCE(sc.dependencies_json,'[]') AS security_dependencies_json,
             COALESCE(sc.dependency_total_count,0) AS security_dependency_total_count,
             COALESCE(sc.source_available,0) AS security_source_available,
             COALESCE(sc.source_repository,'') AS security_source_repository,COALESCE(sc.source_commit,'') AS security_source_commit,
             COALESCE(sc.source_to_binary_verified,0) AS security_source_to_binary_verified,COALESCE(sc.error,'') AS security_error
           FROM plugin_variants v
           JOIN plugins p ON p.plugin_id=v.plugin_id
           JOIN sources s ON s.source_id=v.source_id
           LEFT JOIN websites w ON w.url=v.repo_url COLLATE NOCASE
           LEFT JOIN presentation pr ON pr.plugin_id=p.plugin_id
           LEFT JOIN marketplace_security_current sc ON sc.variant_id=v.variant_id
           WHERE v.active=1 AND p.active=1"""
    )


def project_database(evidence_database: Path, output_database: Path) -> dict[str, Any]:
    output_database.parent.mkdir(parents=True, exist_ok=True)
    output_database.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(prefix="omega-marketplace-project-") as tmp:
        working = Path(tmp) / "working.sqlite"
        shutil.copy2(evidence_database, working)
        db = sqlite3.connect(working)
        db.row_factory = sqlite3.Row
        try:
            before_integrity = db.execute("PRAGMA integrity_check").fetchone()
            if before_integrity is None or str(before_integrity[0]).lower() != "ok":
                raise RuntimeError(f"evidence database integrity check failed: {before_integrity}")
            before_runtime = runtime_projection_digest(db, {"security_dependencies_json", "security_dependency_total_count"})
            current_rows = int(db.execute("SELECT COUNT(*) FROM plugin_security_current").fetchone()[0])
            db.execute("PRAGMA foreign_keys=OFF")
            db.execute("BEGIN IMMEDIATE")
            create_marketplace_security_current(db)
            db.execute("DROP VIEW IF EXISTS runtime_plugin_variants")
            for table in DETAILED_SECURITY_TABLES:
                db.execute(f'DROP TABLE IF EXISTS "{table}"')
            create_marketplace_runtime_view(db)
            db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('database_role','marketplace')")
            db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('marketplace_projector_version',?)", (PROJECTOR_VERSION,))
            db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('detailed_security_evidence_included','0')")
            db.commit()
            after_runtime = runtime_projection_digest(db, {"security_dependencies_json", "security_dependency_total_count"})
            if after_runtime != before_runtime:
                raise RuntimeError("marketplace projection changed runtime_plugin_variants")
            projected_rows = int(db.execute("SELECT COUNT(*) FROM marketplace_security_current").fetchone()[0])
            if projected_rows != current_rows:
                raise RuntimeError("marketplace projection changed current security row count")
            escaped = str(output_database).replace("'", "''")
            db.execute("ANALYZE")
            db.commit()
            db.execute(f"VACUUM INTO '{escaped}'")
        finally:
            db.close()

    with closing(sqlite3.connect(output_database)) as check:
        integrity = check.execute("PRAGMA integrity_check").fetchone()
        if integrity is None or str(integrity[0]).lower() != "ok":
            raise RuntimeError(f"marketplace database integrity check failed: {integrity}")
        remaining = [
            row[0] for row in check.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'plugin_security_%' ORDER BY name"
            )
        ]
        if remaining:
            raise RuntimeError(f"detailed security tables leaked into marketplace database: {remaining}")
        if int(check.execute("SELECT COUNT(*) FROM runtime_plugin_variants").fetchone()[0]) <= 0:
            raise RuntimeError("marketplace database contains no runtime plugin variants")
        evidence_revision = read_meta(check, "evidence_revision")
        return {
            "integrity": "ok",
            "runtimeProjectionSha256": runtime_projection_digest(check, {"security_dependencies_json", "security_dependency_total_count"}),
            "runtimeProjectionWithDependenciesSha256": runtime_projection_digest(check),
            "securityRows": int(check.execute("SELECT COUNT(*) FROM marketplace_security_current").fetchone()[0]),
            "dependencySummaryRows": int(check.execute("SELECT COUNT(*) FROM marketplace_security_current WHERE dependency_total_count>0").fetchone()[0]),
            "dependencySummaryEntries": int(check.execute("SELECT COALESCE(SUM(MIN(dependency_total_count, ?)),0) FROM marketplace_security_current", (DEPENDENCY_SUMMARY_LIMIT,)).fetchone()[0]),
            "evidenceRevision": evidence_revision,
            "catalogRevision": read_meta(check, "catalog_revision"),
            "securityRevision": read_meta(check, "security_revision"),
        }


def write_marketplace_bundle(database: Path, output_dir: Path) -> tuple[Path, str]:
    bundle = output_dir / MARKETPLACE_BUNDLE_FILENAME
    bundle.unlink(missing_ok=True)
    with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        archive.write(database, CLIENT_INTERNAL_DB_FILENAME)
    sha = sha256_file(bundle)
    (output_dir / f"{MARKETPLACE_BUNDLE_FILENAME}.sha256").write_text(
        f"{sha}  {MARKETPLACE_BUNDLE_FILENAME}\n", encoding="ascii"
    )
    return bundle, sha


def copy_evidence_bundle(source_bundle: Path, output_dir: Path) -> tuple[Path, str]:
    target = output_dir / EVIDENCE_BUNDLE_FILENAME
    shutil.copy2(source_bundle, target)
    sha = sha256_file(target)
    (output_dir / f"{EVIDENCE_BUNDLE_FILENAME}.sha256").write_text(
        f"{sha}  {EVIDENCE_BUNDLE_FILENAME}\n", encoding="ascii"
    )
    return target, sha


def project(
    evidence_database: Path,
    evidence_bundle: Path,
    input_descriptor: Path,
    output_dir: Path,
    marketplace_download_url: str,
    evidence_download_url: str,
    previous_marketplace_descriptor: Path | None = None,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    marketplace_db = output_dir / MARKETPLACE_DB_FILENAME
    projection = project_database(evidence_database, marketplace_db)
    marketplace_bundle, marketplace_bundle_sha = write_marketplace_bundle(marketplace_db, output_dir)
    evidence_release_bundle, evidence_bundle_sha = copy_evidence_bundle(evidence_bundle, output_dir)
    evidence_db_sha = sha256_file(evidence_database)

    source_descriptor = json.loads(input_descriptor.read_text(encoding="utf-8"))
    marketplace_descriptor = dict(source_descriptor)
    marketplace_descriptor.update({
        "schemaVersion": 1,
        "schema": MARKETPLACE_SCHEMA,
        "databaseRole": "marketplace",
        "downloadUrl": marketplace_download_url,
        "catalogSha256": sha256_file(marketplace_db),
        "bundleSha256": marketplace_bundle_sha,
        "size": marketplace_bundle.stat().st_size,
        "databaseBytes": marketplace_db.stat().st_size,
        "marketplaceProjectorVersion": PROJECTOR_VERSION,
        "detailedSecurityEvidenceIncluded": False,
        "evidenceRevision": projection["evidenceRevision"],
    })
    for key in ("preCompactionDatabaseBytes", "compactionSavedBytes"):
        marketplace_descriptor.pop(key, None)
    (output_dir / MARKETPLACE_DESCRIPTOR_FILENAME).write_text(
        json.dumps(marketplace_descriptor, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    evidence_descriptor = {
        "schemaVersion": 1,
        "schema": EVIDENCE_SCHEMA,
        "databaseRole": "security-evidence",
        "generatedAtUtc": source_descriptor.get("generatedAtUtc", ""),
        "compactedAtUtc": source_descriptor.get("compactedAtUtc", ""),
        "downloadUrl": evidence_download_url,
        "databaseSha256": evidence_db_sha,
        "bundleSha256": evidence_bundle_sha,
        "size": evidence_release_bundle.stat().st_size,
        "databaseBytes": evidence_database.stat().st_size,
        "catalogRevision": projection["catalogRevision"],
        "securityRevision": projection["securityRevision"],
        "evidenceRevision": projection["evidenceRevision"],
        "scannerVersion": source_descriptor.get("scannerVersion", ""),
        "compactorVersion": source_descriptor.get("compactorVersion", ""),
        "marketplaceProjectorVersion": PROJECTOR_VERSION,
    }
    (output_dir / EVIDENCE_DESCRIPTOR_FILENAME).write_text(
        json.dumps(evidence_descriptor, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    previous = {}
    if previous_marketplace_descriptor is not None and previous_marketplace_descriptor.exists():
        try:
            previous = json.loads(previous_marketplace_descriptor.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            previous = {}
    representation_changed = str(previous.get("marketplaceProjectorVersion") or "") != PROJECTOR_VERSION
    semantic_changed = str(previous.get("catalogRevision") or "") != projection["catalogRevision"]
    evidence_changed = str(previous.get("evidenceRevision") or "") != projection["evidenceRevision"]
    marketplace_required = semantic_changed or evidence_changed or representation_changed or not previous

    report = {
        "schema": "omega.marketplace-projection.v1",
        "projectorVersion": PROJECTOR_VERSION,
        "evidence": {
            "databaseBytes": evidence_database.stat().st_size,
            "bundleBytes": evidence_release_bundle.stat().st_size,
            "databaseSha256": evidence_db_sha,
            "bundleSha256": evidence_bundle_sha,
            "evidenceRevision": projection["evidenceRevision"],
        },
        "marketplace": {
            "databaseBytes": marketplace_db.stat().st_size,
            "bundleBytes": marketplace_bundle.stat().st_size,
            "catalogSha256": marketplace_descriptor["catalogSha256"],
            "bundleSha256": marketplace_bundle_sha,
            "catalogRevision": projection["catalogRevision"],
            "securityRevision": projection["securityRevision"],
            "evidenceRevision": projection["evidenceRevision"],
            "securityRows": projection["securityRows"],
            "dependencySummaryRows": projection["dependencySummaryRows"],
            "dependencySummaryEntries": projection["dependencySummaryEntries"],
        },
        "publication": {
            "marketplaceRequired": marketplace_required,
            "semanticChanged": semantic_changed,
            "evidenceChanged": evidence_changed,
            "representationChanged": representation_changed,
        },
        "validation": projection,
    }
    (output_dir / "marketplace-projection-report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return report


def self_test() -> None:
    from compact_sqlite_catalog import build_self_test_database
    from security_scan import ensure_schema

    with tempfile.TemporaryDirectory(prefix="omega-marketplace-projector-") as tmp:
        root = Path(tmp)
        evidence_db = root / "evidence.sqlite"
        build_self_test_database(evidence_db)
        with closing(sqlite3.connect(evidence_db)) as db:
            ensure_schema(db)
            db.execute("UPDATE plugin_security_dependencies SET kind='external-plugin',name='Fixture.Dependency',requirement='required' WHERE dependency_id=1")
            db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('catalog_revision','cat-v1-0123456789abcdef')")
            db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('security_revision','sec-2.0.0-0123456789abcdef')")
            db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('evidence_revision','ev-v1-0123456789abcdef')")
            db.commit()
        evidence_bundle = root / "source.zip"
        with zipfile.ZipFile(evidence_bundle, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
            zf.write(evidence_db, "omega-catalog.sqlite")
        descriptor = root / "catalog.json"
        descriptor.write_text(json.dumps({"schemaVersion": 1, "schema": MARKETPLACE_SCHEMA, "scannerVersion": "2.0.0"}), encoding="utf-8")
        out = root / "out"
        report = project(
            evidence_db, evidence_bundle, descriptor, out,
            "https://example.invalid/catalog-latest/omega-marketplace.sqlite.zip",
            "https://example.invalid/security-evidence-latest/omega-security-evidence.sqlite.zip",
        )
        if report["marketplace"]["databaseBytes"] >= report["evidence"]["databaseBytes"]:
            raise RuntimeError("marketplace projection did not reduce database size")
        with closing(sqlite3.connect(out / MARKETPLACE_DB_FILENAME)) as db:
            if db.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='plugin_security_managed_calls'").fetchone()[0]:
                raise RuntimeError("managed call evidence leaked into marketplace database")
            if read_meta(db, "evidence_revision") != "ev-v1-0123456789abcdef":
                raise RuntimeError("evidence revision was not preserved in marketplace projection")
            dep_row = db.execute("SELECT security_dependencies_json,security_dependency_total_count FROM runtime_plugin_variants WHERE internal_name='Fixture'").fetchone()
            if dep_row is None or int(dep_row[1] or 0) < 1:
                raise RuntimeError("dependency summary was not projected into the marketplace runtime view")
            dependencies = json.loads(dep_row[0] or "[]")
            if not dependencies or dependencies[0].get("name") != "Fixture.Dependency":
                raise RuntimeError("dependency summary did not preserve the fixture dependency")
        with zipfile.ZipFile(out / MARKETPLACE_BUNDLE_FILENAME) as zf:
            if zf.namelist() != [CLIENT_INTERNAL_DB_FILENAME]:
                raise RuntimeError("marketplace transport must contain exactly the runtime database filename")
    print("Omega marketplace database projector self-test passed.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Project the full Omega security evidence database into the client marketplace database")
    parser.add_argument("--evidence-database", type=Path)
    parser.add_argument("--evidence-bundle", type=Path)
    parser.add_argument("--descriptor", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--marketplace-download-url", default="")
    parser.add_argument("--evidence-download-url", default="")
    parser.add_argument("--previous-marketplace-descriptor", type=Path)
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        self_test()
        return 0
    if not args.evidence_database or not args.evidence_bundle or not args.descriptor or not args.output_dir:
        raise SystemExit("--evidence-database, --evidence-bundle, --descriptor and --output-dir are required")
    report = project(
        args.evidence_database,
        args.evidence_bundle,
        args.descriptor,
        args.output_dir,
        args.marketplace_download_url,
        args.evidence_download_url,
        args.previous_marketplace_descriptor,
    )
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
