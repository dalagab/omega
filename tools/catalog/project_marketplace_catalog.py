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

from source_stability import stable_source_priority
from behavior_consistency import compact_behavior_consistency, compute_behavior_consistency

PROJECTOR_VERSION = "1.9.0"
MARKETPLACE_DB_FILENAME = "omega-marketplace.sqlite"
MARKETPLACE_BUNDLE_FILENAME = "omega-marketplace.sqlite.zip"
CLIENT_INTERNAL_DB_FILENAME = "omega-catalog.sqlite"
EVIDENCE_BUNDLE_FILENAME = "omega-security-evidence.sqlite.zip"
EVIDENCE_DESCRIPTOR_FILENAME = "evidence.json"
MARKETPLACE_DESCRIPTOR_FILENAME = "catalog.json"
MARKETPLACE_SCHEMA = "omega.catalog.sqlite.v1"
EVIDENCE_SCHEMA = "omega.security-evidence.sqlite.v1"
DEPENDENCY_SUMMARY_LIMIT = 30

# The projector is allowed to canonicalize user-facing security fields by exact artifact hash.
# Non-security runtime metadata must remain byte-for-byte equivalent to the evidence database.
ARTIFACT_CANONICAL_RUNTIME_COLUMNS = {
    "security_status", "security_scanned_at_utc", "security_artifact_sha256", "security_scanner_version", "security_highest_severity",
    "security_informational_count", "security_caution_count", "security_high_count", "security_critical_count",
    "security_capabilities_json", "security_automation_level", "security_automation_capabilities_json",
    "security_findings_json", "security_dependencies_json", "security_dependency_total_count",
    "security_known_advisory_count", "security_known_advisory_highest_severity", "security_risk_score",
    "security_source_available", "security_source_repository", "security_source_commit",
    "security_source_attribution_confidence", "security_source_attribution_basis_json", "security_review_coverage_label",
    "security_source_to_binary_verified", "security_developer_profile_status", "security_developer_profile_sha256",
    "security_developer_profile_json", "security_behavior_consistency_json",
    "security_behavior_observed_undeclared_count", "security_behavior_not_expected_observed_count",
    "security_behavior_expected_not_observed_count", "security_behavior_unexplained_destination_count", "security_error",
}

DETAILED_SECURITY_TABLES = (
    "plugin_security_scans",
    "plugin_security_findings",
    "plugin_security_dependencies",
    "plugin_security_ipc_endpoints",
    "plugin_security_ipc_registry",
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
    "artifact_blobs",
    "source_revisions",
    "artifact_source_attributions",
    "artifact_analyses",
    "source_analyses",
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


def _ipc_relationship_rank(value: str) -> int:
    return {"required": 4, "feature": 3, "optional": 2, "unknown": 1}.get(value.casefold(), 0)


def _relationship_confidence_rank(value: str) -> int:
    return {"veryhigh": 4, "high": 3, "medium": 2, "low": 1}.get(value.replace("_", "").replace("-", "").casefold(), 0)


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


def build_dependency_summaries(db: sqlite3.Connection, current_table: str = "plugin_security_current") -> dict[int, tuple[int, str]]:
    """Build a bounded, deduplicated UI summary from current dependency evidence.

    The detailed dependency tables stay server-side. Only relationship/type/version/resolution
    status and aggregate warning/advisory indicators are projected to Definitions.
    """
    table_names = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if "plugin_security_dependencies" not in table_names or current_table not in table_names:
        return {}
    if current_table not in {"plugin_security_current", "marketplace_security_current"}:
        raise ValueError(f"unsupported dependency-current table: {current_table}")

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
            SELECT component_key,affected_version,
                   MAX(CASE lower(severity) WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'caution' THEN 2 WHEN 'moderate' THEN 2 WHEN 'low' THEN 1 WHEN 'informational' THEN 1 ELSE 0 END) AS warning_rank,
                   COUNT(*) AS advisory_count
              FROM plugin_security_dependency_advisory_matches
             WHERE component_key<>''
             GROUP BY component_key,affected_version
        )
        """
        advisory_join = """LEFT JOIN advisories adv
                                 ON adv.component_key=COALESCE(r.component_key,'')
                                AND (TRIM(adv.affected_version)=''
                                     OR lower(TRIM(adv.affected_version))=lower(COALESCE(NULLIF(TRIM(d.resolved_version),''),NULLIF(TRIM(d.version),''))))"""
        advisory_fields = "COALESCE(adv.warning_rank,0) AS advisory_rank,COALESCE(adv.advisory_count,0) AS advisory_count"

    ctes = issue_ctes + advisory_cte
    if ctes.strip().endswith(','):
        ctes = ctes.rstrip().rstrip(',')
    with_clause = f"WITH {ctes}" if ctes.strip() else ""
    dependency_columns = {row[1] for row in db.execute("PRAGMA table_info(plugin_security_dependencies)")}
    relationship_fields = (
        "COALESCE(d.relationship,'') AS relationship,COALESCE(d.relationship_confidence,'') AS relationship_confidence,"
        "COALESCE(d.relationship_evidence_json,'[]') AS relationship_evidence_json"
        if {"relationship", "relationship_confidence", "relationship_evidence_json"}.issubset(dependency_columns)
        else "'' AS relationship,'' AS relationship_confidence,'[]' AS relationship_evidence_json"
    )
    query = f"""
        {with_clause}
        SELECT sc.variant_id,d.dependency_id,d.origin,d.kind,d.name,d.version,d.version_requirement,d.resolved_version,d.status,d.requirement,
               COALESCE(r.component_key,'') AS component_key,COALESCE(r.resolution_status,'') AS resolution_status,
               COALESCE(r.version_status,'') AS version_status,COALESCE(r.target_internal_name,'') AS target_internal_name,
               COALESCE(r.target_version,'') AS target_version,{issue_fields},{advisory_fields},{relationship_fields}
          FROM {current_table} sc
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
            -_ipc_relationship_rank(str(item.get("relationship") or "")),
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
                "relationship": item.get("relationship") or "", "relationshipConfidence": item.get("relationshipConfidence") or "",
                "relationshipReason": item.get("relationshipReason") or "",
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
        relationship = str(row[21] or "").strip().casefold()
        relationship_confidence = str(row[22] or "").strip()
        try:
            relationship_evidence = json.loads(str(row[23] or "[]"))
        except (TypeError, ValueError, json.JSONDecodeError):
            relationship_evidence = []
        relationship_reason = " · ".join(str(x) for x in relationship_evidence[:2] if str(x).strip())[:320]
        if item is None:
            merged[key] = {
                "name": name, "kind": kind, "type": dep_type, "requirement": requirement, "version": str(row[5] or ""),
                "versionRequirement": str(row[6] or ""), "resolvedVersion": str(row[7] or ""),
                "resolutionStatus": str(row[11] or ""), "versionStatus": str(row[12] or ""),
                "targetInternalName": target_internal, "targetVersion": str(row[14] or ""), "isFramework": is_framework,
                "relationship": relationship, "relationshipConfidence": relationship_confidence, "relationshipReason": relationship_reason,
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
        current_relationship = str(item.get("relationship") or "")
        current_confidence = str(item.get("relationshipConfidence") or "")
        if (_ipc_relationship_rank(relationship), _relationship_confidence_rank(relationship_confidence)) > (
            _ipc_relationship_rank(current_relationship), _relationship_confidence_rank(current_confidence)
        ):
            item["relationship"] = relationship
            item["relationshipConfidence"] = relationship_confidence
            item["relationshipReason"] = relationship_reason
        for field, value in (("versionRequirement", row[6]), ("resolvedVersion", row[7]), ("resolutionStatus", row[11]),
                             ("versionStatus", row[12]), ("targetInternalName", row[13]), ("targetVersion", row[14])):
            if not item.get(field) and value:
                item[field] = str(value)

    flush()
    return summaries


def _security_risk_score(informational: int, caution: int, high: int, critical: int, advisory_points: int = 0) -> int:
    """Return Omega's bounded internal risk score.

    The score is intentionally not a safety verdict and is not currently shown numerically in the UI.
    It exists so sorting/filtering can account for both static findings and independently published
    dependency advisories. Known vulnerable dependencies carry extra weight because an external
    advisory confirms a concrete affected component/version rather than only an observed capability.
    """
    base = (max(0, informational) * 1) + (max(0, caution) * 6) + (max(0, high) * 15) + (max(0, critical) * 30)
    return min(100, base + max(0, advisory_points))


def build_advisory_risk_summaries(db: sqlite3.Connection, current_table: str = "marketplace_security_current") -> dict[int, tuple[int, str, int]]:
    """Summarize advisories that affect the exact dependency versions used by each current plugin scan."""
    tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    required = {current_table, "plugin_security_dependencies", "plugin_security_dependency_resolutions", "plugin_security_dependency_advisory_matches"}
    if not required.issubset(tables):
        return {}
    if current_table not in {"plugin_security_current", "marketplace_security_current"}:
        raise ValueError(f"unsupported advisory-current table: {current_table}")

    severity_rank = {"critical": 4, "high": 3, "medium": 2, "caution": 2, "moderate": 2, "low": 1, "informational": 1}
    severity_points = {4: 40, 3: 25, 2: 12, 1: 5, 0: 8}
    by_variant: dict[int, dict[tuple[str, str, str], int]] = {}
    rows = db.execute(f"""
        SELECT sc.variant_id,adv.advisory_id,adv.component_key,adv.affected_version,adv.severity
          FROM {current_table} sc
          JOIN plugin_security_dependencies d ON d.scan_id=sc.scan_id
          JOIN plugin_security_dependency_resolutions r ON r.dependency_id=d.dependency_id
          JOIN plugin_security_dependency_advisory_matches adv
            ON adv.component_key=r.component_key
           AND (TRIM(adv.affected_version)=''
                OR lower(TRIM(adv.affected_version))=lower(COALESCE(NULLIF(TRIM(d.resolved_version),''),NULLIF(TRIM(d.version),''))))
         WHERE sc.status='complete' AND TRIM(adv.advisory_id)<>''
         ORDER BY sc.variant_id,adv.advisory_id,adv.component_key,adv.affected_version
    """).fetchall()
    for row in rows:
        variant_id = int(row[0])
        key = (str(row[1] or '').casefold(), str(row[2] or '').casefold(), str(row[3] or '').casefold())
        rank = severity_rank.get(str(row[4] or '').strip().casefold(), 0)
        bucket = by_variant.setdefault(variant_id, {})
        bucket[key] = max(bucket.get(key, -1), rank)

    summaries: dict[int, tuple[int, str, int]] = {}
    for variant_id, matches in by_variant.items():
        ranks = list(matches.values())
        highest_rank = max(ranks, default=0)
        summaries[variant_id] = (
            len(matches),
            _dependency_severity(highest_rank) or ("unknown" if matches else "none"),
            sum(severity_points.get(rank, 8) for rank in ranks),
        )
    return summaries


def _source_attribution_projection(report_json: str) -> tuple[int, str, str]:
    try:
        report = json.loads(report_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        report = {}
    source = report.get("source") if isinstance(report, dict) and isinstance(report.get("source"), dict) else {}
    attribution = source.get("attribution") if isinstance(source.get("attribution"), dict) else {}
    try:
        confidence = int(attribution.get("confidence") or 0)
    except (TypeError, ValueError):
        confidence = 0
    if confidence not in {0, 40, 70, 95, 100}:
        confidence = 0
    basis = attribution.get("basis") if isinstance(attribution.get("basis"), list) else []
    label = str(attribution.get("coverageLabel") or ({0: "Unresolved", 40: "Current source found", 70: "Version-correlated source", 95: "Commit-pinned source", 100: "Reproducibly verified"}.get(confidence, "Unresolved")))
    return confidence, json.dumps([str(item) for item in basis if str(item)], separators=(",", ":")), label


def refresh_marketplace_source_attribution(db: sqlite3.Connection) -> None:
    rows = db.execute("SELECT variant_id,scan_id FROM marketplace_security_current ORDER BY variant_id").fetchall()
    for variant_id, scan_id in rows:
        scan = db.execute("SELECT report_json FROM plugin_security_scans WHERE scan_id=?", (int(scan_id or 0),)).fetchone()
        confidence, basis_json, label = _source_attribution_projection(str(scan[0] or "{}") if scan else "{}")
        db.execute(
            "UPDATE marketplace_security_current SET source_attribution_confidence=?,source_attribution_basis_json=?,review_coverage_label=? WHERE variant_id=?",
            (confidence, basis_json, label, int(variant_id)),
        )


def refresh_marketplace_developer_profiles(db: sqlite3.Connection) -> None:
    """Project bounded developer-authored `.omega` metadata from the current scan report."""
    rows = db.execute("SELECT variant_id,scan_id FROM marketplace_security_current ORDER BY variant_id").fetchall()
    for variant_id, scan_id in rows:
        scan = db.execute("SELECT report_json FROM plugin_security_scans WHERE scan_id=?", (int(scan_id or 0),)).fetchone()
        if scan is None:
            continue
        try:
            report = json.loads(str(scan[0] or "{}"))
        except (TypeError, ValueError, json.JSONDecodeError):
            report = {}
        source = report.get("source") if isinstance(report, dict) and isinstance(report.get("source"), dict) else {}
        observation = source.get("developerProfile") if isinstance(source.get("developerProfile"), dict) else {}
        status = str(observation.get("status") or "absent")[:32]
        sha256 = str(observation.get("sha256") or "")[:128]
        encoded = json.dumps(observation, ensure_ascii=False, sort_keys=True, separators=(",", ":")) if observation else "{}"
        if len(encoded.encode("utf-8")) > 96 * 1024:
            # The source parser is already bounded; this is a final fail-soft transport guard.
            encoded = json.dumps({
                "schema": "omega.plugin-profile-observation.v1",
                "status": "invalid",
                "valid": False,
                "sha256": sha256,
                "diagnostics": [{"code": "projection-size", "path": "", "message": "developer profile exceeded marketplace projection limit"}],
            }, separators=(",", ":"))
            status = "invalid"
        db.execute(
            "UPDATE marketplace_security_current SET developer_profile_status=?,developer_profile_sha256=?,developer_profile_json=? WHERE variant_id=?",
            (status, sha256, encoded, int(variant_id)),
        )


def refresh_marketplace_behavior_consistency(db: sqlite3.Connection) -> None:
    """Project observation-vs-declaration comparison without changing native findings."""
    rows = db.execute("SELECT variant_id,scan_id FROM marketplace_security_current ORDER BY variant_id").fetchall()
    for variant_id, scan_id in rows:
        scan = db.execute("SELECT report_json FROM plugin_security_scans WHERE scan_id=?", (int(scan_id or 0),)).fetchone()
        if scan is None:
            continue
        try:
            report = json.loads(str(scan[0] or "{}"))
        except (TypeError, ValueError, json.JSONDecodeError):
            report = {}
        try:
            comparison = compact_behavior_consistency(
                report.get("behaviorConsistency") if isinstance(report, dict) and isinstance(report.get("behaviorConsistency"), dict)
                else compute_behavior_consistency(report if isinstance(report, dict) else {})
            )
        except Exception:
            comparison = {}
        summary = comparison.get("summary") if isinstance(comparison.get("summary"), dict) else {}
        encoded = json.dumps(comparison, ensure_ascii=False, sort_keys=True, separators=(",", ":")) if comparison else "{}"
        if len(encoded.encode("utf-8")) > 128 * 1024:
            encoded = json.dumps({
                "schema": "omega.sigmascope.behavior-consistency.v1",
                "profileStatus": "projection-too-large",
                "summary": {key: int(summary.get(key) or 0) for key in (
                    "observedUndeclaredCount", "notExpectedObservedCount", "expectedNotObservedCount", "unexplainedDestinationCount"
                )},
            }, separators=(",", ":"))
        db.execute(
            """UPDATE marketplace_security_current
                  SET behavior_consistency_json=?,behavior_observed_undeclared_count=?,behavior_not_expected_observed_count=?,
                      behavior_expected_not_observed_count=?,behavior_unexplained_destination_count=?
                WHERE variant_id=?""",
            (
                encoded, int(summary.get("observedUndeclaredCount") or 0), int(summary.get("notExpectedObservedCount") or 0),
                int(summary.get("expectedNotObservedCount") or 0), int(summary.get("unexplainedDestinationCount") or 0), int(variant_id),
            ),
        )


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
            known_advisory_count INTEGER NOT NULL DEFAULT 0,
            known_advisory_highest_severity TEXT NOT NULL DEFAULT 'none',
            risk_score INTEGER NOT NULL DEFAULT 0,
            source_available INTEGER NOT NULL DEFAULT 0,
            source_repository TEXT NOT NULL DEFAULT '',
            source_commit TEXT NOT NULL DEFAULT '',
            source_attribution_confidence INTEGER NOT NULL DEFAULT 0,
            source_attribution_basis_json TEXT NOT NULL DEFAULT '[]',
            review_coverage_label TEXT NOT NULL DEFAULT 'Unresolved',
            source_to_binary_verified INTEGER NOT NULL DEFAULT 0,
            developer_profile_status TEXT NOT NULL DEFAULT 'absent',
            developer_profile_sha256 TEXT NOT NULL DEFAULT '',
            developer_profile_json TEXT NOT NULL DEFAULT '{}',
            behavior_consistency_json TEXT NOT NULL DEFAULT '{}',
            behavior_observed_undeclared_count INTEGER NOT NULL DEFAULT 0,
            behavior_not_expected_observed_count INTEGER NOT NULL DEFAULT 0,
            behavior_expected_not_observed_count INTEGER NOT NULL DEFAULT 0,
            behavior_unexplained_destination_count INTEGER NOT NULL DEFAULT 0,
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
    # Recover the artifact/current identity before projecting dependencies so recovered mirrors
    # inherit the exact scan's plugin/IPC dependency summary too.
    backfill_marketplace_security_from_completed_scans(db)
    refresh_marketplace_source_attribution(db)
    refresh_marketplace_developer_profiles(db)
    refresh_marketplace_behavior_consistency(db)
    for variant_id, (total_count, encoded) in build_dependency_summaries(db, "marketplace_security_current").items():
        db.execute(
            "UPDATE marketplace_security_current SET dependencies_json=?,dependency_total_count=? WHERE variant_id=?",
            (encoded, total_count, variant_id),
        )
    advisory_summaries = build_advisory_risk_summaries(db, "marketplace_security_current")
    for variant_id, (advisory_count, advisory_severity, _advisory_points) in advisory_summaries.items():
        db.execute(
            "UPDATE marketplace_security_current SET known_advisory_count=?,known_advisory_highest_severity=? WHERE variant_id=?",
            (advisory_count, advisory_severity, variant_id),
        )

    # Canonicalize only artifact-intrinsic static conclusions. Dependency/advisory
    # projections can legitimately differ until all mirrors have inherited the same
    # resolved original-source evidence; copying one mirror's derived zero counters
    # over another can erase a known advisory. Recompute risk only after the static
    # conclusion has been canonicalized so its score combines canonical static counts
    # with each variant's independently reproduced advisory evidence.
    canonicalize_marketplace_security_by_artifact(db)
    for row in db.execute("SELECT variant_id,informational_count,caution_count,high_count,critical_count FROM marketplace_security_current").fetchall():
        variant_id = int(row[0])
        _advisory_count, _advisory_severity, advisory_points = advisory_summaries.get(variant_id, (0, "none", 0))
        risk_score = _security_risk_score(int(row[1] or 0), int(row[2] or 0), int(row[3] or 0), int(row[4] or 0), advisory_points)
        db.execute("UPDATE marketplace_security_current SET risk_score=? WHERE variant_id=?", (risk_score, variant_id))
    validate_artifact_security_consistency(db)


def _normalized_package_url(value: str) -> str:
    return str(value or "").strip().rstrip("/").casefold()


def _scan_findings_json(db: sqlite3.Connection, scan_id: int, report_json: str) -> str:
    try:
        report = json.loads(report_json or "{}")
        findings = report.get("findings") if isinstance(report, dict) else None
        if isinstance(findings, list):
            return json.dumps(findings, separators=(",", ":"))
    except (TypeError, ValueError, json.JSONDecodeError):
        pass

    rows = db.execute(
        """SELECT rule_id,severity,category,title,description,evidence_json
             FROM plugin_security_findings
            WHERE scan_id=?
            ORDER BY finding_id""",
        (scan_id,),
    ).fetchall()
    findings = []
    for row in rows:
        try:
            evidence = json.loads(str(row["evidence_json"] or "[]"))
        except (TypeError, ValueError, json.JSONDecodeError):
            evidence = []
        findings.append({
            "ruleId": str(row["rule_id"] or ""),
            "severity": str(row["severity"] or ""),
            "category": str(row["category"] or ""),
            "title": str(row["title"] or ""),
            "description": str(row["description"] or ""),
            "evidence": evidence if isinstance(evidence, list) else [],
        })
    return json.dumps(findings, separators=(",", ":"))


def _scan_automation_projection(report_json: str) -> tuple[str, str]:
    try:
        report = json.loads(report_json or "{}")
        automation = report.get("automation") if isinstance(report, dict) else None
        if isinstance(automation, dict):
            level = str(automation.get("level") or "none")
            capabilities = automation.get("capabilities")
            if isinstance(capabilities, list):
                return level, json.dumps(capabilities, separators=(",", ":"))
            return level, "[]"
    except (TypeError, ValueError, json.JSONDecodeError):
        pass
    return "none", "[]"


def backfill_marketplace_security_from_completed_scans(db: sqlite3.Connection) -> dict[str, int]:
    """Recover artifact-based security for variants missing a duplicate current row.

    Security belongs to package bytes, not to a repository-manifest row. Sigmascope keeps immutable
    completed scan history, while `plugin_security_current` is only a convenience pointer per
    variant. If that pointer is absent, the client projection recovers the latest proven artifact
    identity for that variant, or reuses a completed scan for the exact same package URL/version.
    Identical SHA-256 artifacts then share the canonical user-facing result.
    """
    tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if "plugin_security_scans" not in tables:
        return {"historyRecovered": 0, "exactUrlMirrorsRecovered": 0, "artifactDonorCopies": 0}

    current_fields = (
        "scan_id", "assembly_version", "artifact_channel", "artifact_url", "artifact_sha256",
        "scanner_version", "status", "scanned_at_utc", "highest_severity", "informational_count",
        "caution_count", "high_count", "critical_count", "capabilities_json", "automation_level",
        "automation_capabilities_json", "findings_json", "dependencies_json", "dependency_total_count",
        "source_available", "source_repository", "source_commit", "source_to_binary_verified", "error",
    )

    variants = db.execute(
        """SELECT v.variant_id,p.internal_name,v.assembly_version,v.testing_assembly_version,
                  v.download_link_install,v.download_link_update,v.download_link_testing
             FROM plugin_variants v
             JOIN plugins p ON p.plugin_id=v.plugin_id
        LEFT JOIN marketplace_security_current m ON m.variant_id=v.variant_id
            WHERE v.active=1 AND p.active=1 AND m.variant_id IS NULL
            ORDER BY v.variant_id"""
    ).fetchall()

    history_recovered = 0
    url_recovered = 0
    donor_copies = 0

    for variant in variants:
        variant_id = int(variant["variant_id"])
        internal_name = str(variant["internal_name"] or "")
        version_candidates = {
            str(variant["assembly_version"] or "").casefold(),
            str(variant["testing_assembly_version"] or "").casefold(),
        } - {""}

        scan = db.execute(
            """SELECT * FROM plugin_security_scans
                WHERE variant_id=? AND status='complete' AND artifact_sha256<>''
                ORDER BY scanned_at_utc DESC,scan_id DESC LIMIT 1""",
            (variant_id,),
        ).fetchone()
        recovered_from_url = False

        if scan is None:
            package_urls = {
                _normalized_package_url(variant["download_link_install"]),
                _normalized_package_url(variant["download_link_update"]),
                _normalized_package_url(variant["download_link_testing"]),
            } - {""}
            if package_urls:
                candidates = db.execute(
                    """SELECT s.*
                         FROM plugin_security_scans s
                         JOIN plugins p ON p.plugin_id=s.plugin_id
                        WHERE p.internal_name=? COLLATE NOCASE
                          AND s.status='complete' AND s.artifact_sha256<>''
                        ORDER BY s.scanned_at_utc DESC,s.scan_id DESC""",
                    (internal_name,),
                ).fetchall()
                scan = next((row for row in candidates
                             if str(row["assembly_version"] or "").casefold() in version_candidates
                             and _normalized_package_url(row["artifact_url"]) in package_urls), None)
                recovered_from_url = scan is not None

        if scan is None:
            continue

        artifact_hash = str(scan["artifact_sha256"] or "").casefold()
        scan_version = str(scan["assembly_version"] or "").casefold()
        donor = db.execute(
            """SELECT m.*
                 FROM marketplace_security_current m
                 JOIN plugin_variants v ON v.variant_id=m.variant_id
                 JOIN plugins p ON p.plugin_id=v.plugin_id
                WHERE p.internal_name=? COLLATE NOCASE
                  AND lower(m.assembly_version)=?
                  AND lower(m.artifact_sha256)=?
                  AND m.status='complete'
                ORDER BY m.scanned_at_utc DESC,m.scan_id DESC,m.variant_id
                LIMIT 1""",
            (internal_name, scan_version, artifact_hash),
        ).fetchone()

        if donor is not None:
            values = [donor[field] for field in current_fields]
            placeholders = ",".join("?" for _ in range(len(current_fields) + 1))
            db.execute(
                f"INSERT INTO marketplace_security_current(variant_id,{','.join(current_fields)}) VALUES({placeholders})",
                (variant_id, *values),
            )
            donor_copies += 1
        else:
            automation_level, automation_caps = _scan_automation_projection(str(scan["report_json"] or "{}"))
            findings_json = _scan_findings_json(db, int(scan["scan_id"]), str(scan["report_json"] or "{}"))
            db.execute(
                """INSERT INTO marketplace_security_current(
                       variant_id,scan_id,assembly_version,artifact_channel,artifact_url,artifact_sha256,scanner_version,status,
                       scanned_at_utc,highest_severity,informational_count,caution_count,high_count,critical_count,capabilities_json,
                       automation_level,automation_capabilities_json,findings_json,dependencies_json,dependency_total_count,
                       source_available,source_repository,source_commit,source_to_binary_verified,error)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,?,?,?,?,?)""",
                (
                    variant_id,int(scan["scan_id"]),str(scan["assembly_version"] or ""),str(scan["artifact_channel"] or "stable"),
                    str(scan["artifact_url"] or ""),str(scan["artifact_sha256"] or ""),str(scan["scanner_version"] or ""),
                    "complete",str(scan["scanned_at_utc"] or ""),str(scan["highest_severity"] or "none"),
                    int(scan["informational_count"] or 0),int(scan["caution_count"] or 0),int(scan["high_count"] or 0),
                    int(scan["critical_count"] or 0),str(scan["capabilities_json"] or "[]"),automation_level,automation_caps,
                    findings_json,"[]",int(scan["source_available"] or 0),str(scan["source_repository"] or ""),
                    str(scan["source_commit"] or ""),int(scan["source_to_binary_verified"] or 0),str(scan["error"] or ""),
                ),
            )

        if recovered_from_url:
            url_recovered += 1
        else:
            history_recovered += 1

    return {
        "historyRecovered": history_recovered,
        "exactUrlMirrorsRecovered": url_recovered,
        "artifactDonorCopies": donor_copies,
    }


def canonicalize_marketplace_security_by_artifact(db: sqlite3.Connection) -> dict[str, int]:
    """Make one exact artifact hash produce one user-facing security report.

    Detailed source evidence remains untouched in the server-side tables. Only the compact client
    projection is canonicalized, using stable provider priority when several repositories mirror
    the same package bytes.
    """
    rows = db.execute("""
        SELECT m.variant_id,m.assembly_version,m.artifact_sha256,
               p.internal_name,s.name AS source_name,s.url AS source_url,s.is_official
          FROM marketplace_security_current m
          JOIN plugin_variants v ON v.variant_id=m.variant_id
          JOIN plugins p ON p.plugin_id=v.plugin_id
          JOIN sources s ON s.source_id=v.source_id
         WHERE m.status='complete' AND m.artifact_sha256<>''
         ORDER BY p.internal_name COLLATE NOCASE,m.assembly_version COLLATE NOCASE,m.artifact_sha256,m.variant_id
    """).fetchall()
    groups: dict[tuple[str, str, str], list[sqlite3.Row]] = {}
    for row in rows:
        key = (
            str(row["internal_name"] or "").casefold(),
            str(row["assembly_version"] or "").casefold(),
            str(row["artifact_sha256"] or "").casefold(),
        )
        groups.setdefault(key, []).append(row)

    fields = (
        "scanner_version", "status", "highest_severity",
        "informational_count", "caution_count", "high_count", "critical_count", "capabilities_json",
        "automation_level", "automation_capabilities_json", "findings_json",
    )
    updated = 0
    mirrored_groups = 0
    for members in groups.values():
        if len(members) < 2:
            continue
        mirrored_groups += 1
        canonical = min(
            members,
            key=lambda row: (
                stable_source_priority(row["source_name"], row["source_url"], bool(row["is_official"]))
                if stable_source_priority(row["source_name"], row["source_url"], bool(row["is_official"])) is not None
                else 1_000,
                str(row["source_name"] or "").casefold(),
                int(row["variant_id"]),
            ),
        )
        source = db.execute(
            f"SELECT {','.join(fields)} FROM marketplace_security_current WHERE variant_id=?",
            (int(canonical["variant_id"]),),
        ).fetchone()
        if source is None:
            continue
        assignments = ",".join(f"{field}=?" for field in fields)
        values = tuple(source[index] for index in range(len(fields)))
        for member in members:
            variant_id = int(member["variant_id"])
            if variant_id == int(canonical["variant_id"]):
                continue
            db.execute(
                f"UPDATE marketplace_security_current SET {assignments} WHERE variant_id=?",
                (*values, variant_id),
            )
            updated += 1
    return {"mirroredArtifactGroups": mirrored_groups, "canonicalizedVariants": updated}


def validate_artifact_security_consistency(db: sqlite3.Connection) -> None:
    rows = db.execute("""
        SELECT p.internal_name,m.assembly_version,m.artifact_sha256,
               COUNT(DISTINCT (
                   m.status || '|' || m.highest_severity || '|' || m.informational_count || '|' ||
                   m.caution_count || '|' || m.high_count || '|' || m.critical_count || '|' ||
                   m.capabilities_json || '|' || m.automation_level || '|' || m.automation_capabilities_json || '|' ||
                   m.findings_json
               )) AS signatures
          FROM marketplace_security_current m
          JOIN plugin_variants v ON v.variant_id=m.variant_id
          JOIN plugins p ON p.plugin_id=v.plugin_id
         WHERE m.status='complete' AND m.artifact_sha256<>''
         GROUP BY p.internal_name COLLATE NOCASE,m.assembly_version COLLATE NOCASE,m.artifact_sha256 COLLATE NOCASE
        HAVING signatures<>1
    """).fetchall()
    if rows:
        first = rows[0]
        raise RuntimeError(
            "marketplace artifact security canonicalization failed for "
            f"{first[0]} {first[1]} {str(first[2])[:16]}: {first[3]} result signatures"
        )

def create_marketplace_runtime_view(db: sqlite3.Connection) -> None:
    website_columns = {str(row[1]).casefold() for row in db.execute("PRAGMA table_info(websites)")}
    omega_banner_projection = (
        "CASE WHEN w.ok=1 THEN COALESCE(w.omega_banner_url,'') ELSE '' END AS omega_banner_url"
        if "omega_banner_url" in website_columns
        else "'' AS omega_banner_url"
    )
    website_license_projection = (
        "CASE WHEN w.ok=1 THEN COALESCE(w.license,'') ELSE '' END AS website_license"
        if "license" in website_columns
        else "'' AS website_license"
    )
    db.execute("DROP VIEW IF EXISTS runtime_plugin_variants")
    db.execute(
        f"""CREATE VIEW runtime_plugin_variants AS
           SELECT
             v.variant_id,p.plugin_id,p.internal_name,v.author,COALESCE(v.authors_json,'[]') AS authors_json,v.name,v.punchline,v.description,v.changelog,
             v.assembly_version,v.testing_assembly_version,v.dalamud_api_level,v.testing_dalamud_api_level,
             v.applicable_version,v.minimum_dalamud_version,v.repo_url,v.download_link_install,v.download_link_update,
             v.download_link_testing,v.icon_url,v.image_urls_json,v.tags_json,v.category_tags_json,v.download_count,
             v.last_update,v.is_hide,v.is_testing_exclusive,v.dip17_channel,s.name AS source_name,s.url AS source_url,
             s.is_official AS source_is_official,CASE WHEN w.ok=1 THEN COALESCE(w.url,'') ELSE '' END AS website_url,CASE WHEN w.ok=1 THEN COALESCE(w.title,'') ELSE '' END AS website_title,
             CASE WHEN w.ok=1 THEN COALESCE(w.description,'') ELSE '' END AS website_description,CASE WHEN w.ok=1 THEN COALESCE(w.readme_excerpt,'') ELSE '' END AS website_readme_excerpt,
             CASE WHEN w.ok=1 THEN COALESCE(w.image_urls_json,'[]') ELSE '[]' END AS website_image_urls_json,
             CASE WHEN w.ok=1 THEN COALESCE(w.links_json,'[]') ELSE '[]' END AS website_links_json,
             {omega_banner_projection},
             {website_license_projection},
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
             COALESCE(sc.known_advisory_count,0) AS security_known_advisory_count,
             COALESCE(sc.known_advisory_highest_severity,'none') AS security_known_advisory_highest_severity,
             COALESCE(sc.risk_score,0) AS security_risk_score,
             COALESCE(sc.source_available,0) AS security_source_available,
             COALESCE(sc.source_repository,'') AS security_source_repository,COALESCE(sc.source_commit,'') AS security_source_commit,
             COALESCE(sc.source_attribution_confidence,0) AS security_source_attribution_confidence,
             COALESCE(sc.source_attribution_basis_json,'[]') AS security_source_attribution_basis_json,
             COALESCE(sc.review_coverage_label,'Unresolved') AS security_review_coverage_label,
             COALESCE(sc.source_to_binary_verified,0) AS security_source_to_binary_verified,
             COALESCE(sc.developer_profile_status,'absent') AS security_developer_profile_status,
             COALESCE(sc.developer_profile_sha256,'') AS security_developer_profile_sha256,
             COALESCE(sc.developer_profile_json,'{{}}') AS security_developer_profile_json,
             COALESCE(sc.behavior_consistency_json,'{{}}') AS security_behavior_consistency_json,
             COALESCE(sc.behavior_observed_undeclared_count,0) AS security_behavior_observed_undeclared_count,
             COALESCE(sc.behavior_not_expected_observed_count,0) AS security_behavior_not_expected_observed_count,
             COALESCE(sc.behavior_expected_not_observed_count,0) AS security_behavior_expected_not_observed_count,
             COALESCE(sc.behavior_unexplained_destination_count,0) AS security_behavior_unexplained_destination_count,
             COALESCE(sc.error,'') AS security_error
           FROM plugin_variants v
           JOIN plugins p ON p.plugin_id=v.plugin_id
           JOIN sources s ON s.source_id=v.source_id
           LEFT JOIN websites w ON w.url=v.repo_url COLLATE NOCASE
           LEFT JOIN presentation pr ON pr.plugin_id=p.plugin_id
           LEFT JOIN marketplace_security_current sc ON sc.variant_id=v.variant_id
           WHERE v.active=1 AND p.active=1"""
    )


CLIENT_HISTORY_SCHEMA = """
CREATE TABLE catalog_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE sources (
    source_id INTEGER PRIMARY KEY,
    curated_id TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL DEFAULT '',
    url TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    is_official INTEGER NOT NULL DEFAULT 0,
    enabled_by_default INTEGER NOT NULL DEFAULT 1,
    integrate_with_dalamud INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE plugins (
    plugin_id INTEGER PRIMARY KEY,
    internal_name TEXT NOT NULL DEFAULT ''
);
CREATE TABLE plugin_variants (
    variant_id INTEGER PRIMARY KEY,
    plugin_id INTEGER NOT NULL,
    source_id INTEGER NOT NULL,
    assembly_version TEXT NOT NULL DEFAULT '',
    last_update INTEGER NOT NULL DEFAULT 0,
    changelog TEXT NOT NULL DEFAULT '',
    active INTEGER NOT NULL DEFAULT 0,
    last_seen_utc TEXT NOT NULL DEFAULT ''
);
CREATE INDEX ix_client_variants_plugin ON plugin_variants(plugin_id);
CREATE INDEX ix_client_variants_source ON plugin_variants(source_id);
CREATE TABLE plugin_search (
    plugin_id INTEGER PRIMARY KEY,
    internal_name TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL DEFAULT '',
    author TEXT NOT NULL DEFAULT '',
    punchline TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    tags TEXT NOT NULL DEFAULT '',
    website_text TEXT NOT NULL DEFAULT ''
);
CREATE INDEX ix_client_plugin_search_internal_name ON plugin_search(internal_name COLLATE NOCASE);
CREATE INDEX ix_client_plugin_search_name ON plugin_search(name COLLATE NOCASE);
CREATE INDEX ix_client_plugin_search_author ON plugin_search(author COLLATE NOCASE);
"""

# The downloadable Omega database is an explicit client allow-list.  The rich normalized catalog
# and Security Evidence v2 remain authoritative elsewhere; new server-side tables therefore cannot
# silently leak into every user's local database just because the projector started from a richer
# working SQLite file.
CLIENT_ALLOWED_BASE_TABLES = {
    "catalog_meta",
    "sources",
    "plugins",
    "plugin_variants",
    "runtime_plugin_variants",
    "plugin_search",
    "catalog_changelog",
}


def _table_exists(db: sqlite3.Connection, name: str, schema: str = "main") -> bool:
    row = db.execute(
        f"SELECT 1 FROM {schema}.sqlite_master WHERE type='table' AND name=?",
        (name,),
    ).fetchone()
    return row is not None


def _copy_table_schema_and_rows(source: sqlite3.Connection, target: sqlite3.Connection, table: str) -> None:
    """Copy one explicitly allowed table without copying unrelated source schema."""
    row = source.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    if row is None or not str(row[0] or "").strip():
        return
    target.execute(str(row[0]))
    columns = [str(item[1]) for item in source.execute(f'PRAGMA table_info("{table}")')]
    if not columns:
        return
    placeholders = ",".join("?" for _ in columns)
    quoted = ",".join(f'"{name}"' for name in columns)
    cursor = source.execute(f'SELECT {quoted} FROM "{table}"')
    target.executemany(
        f'INSERT INTO "{table}"({quoted}) VALUES({placeholders})',
        cursor,
    )


def _write_fresh_client_database(working: sqlite3.Connection, output_database: Path) -> dict[str, Any]:
    """Materialize a fresh, allow-listed Omega client database from the prepared working snapshot."""
    output_database.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(prefix="omega-marketplace-client-") as td:
        scratch = Path(td) / "client-working.sqlite"
        client = sqlite3.connect(scratch)
        try:
            client.executescript("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;" + CLIENT_HISTORY_SCHEMA)
            # Explicit transfers through ATTACH form the server -> client allow-list.  New
            # server-side tables cannot appear in the downloadable database by accident.
            client.execute("ATTACH DATABASE ? AS server", (str(Path(working.execute("PRAGMA database_list").fetchone()[2])),))
            client.execute("INSERT INTO catalog_meta(key,value) SELECT key,value FROM server.catalog_meta")
            client.execute("""
                INSERT INTO sources(source_id,curated_id,name,url,description,is_official,enabled_by_default,integrate_with_dalamud)
                SELECT source_id,COALESCE(curated_id,''),COALESCE(name,''),COALESCE(url,''),COALESCE(description,''),
                       COALESCE(is_official,0),COALESCE(enabled_by_default,1),COALESCE(integrate_with_dalamud,0)
                  FROM server.sources
            """)
            client.execute("INSERT INTO plugins(plugin_id,internal_name) SELECT plugin_id,internal_name FROM server.plugins")
            # Keep enough historical version/changelog metadata for Omega's existing changelog UI,
            # but never carry raw manifests, scraper state, aliases, source observations or security
            # analysis tables into the client database.
            client.execute("""
                INSERT INTO plugin_variants(variant_id,plugin_id,source_id,assembly_version,last_update,changelog,active,last_seen_utc)
                SELECT variant_id,plugin_id,source_id,COALESCE(assembly_version,''),COALESCE(last_update,0),
                       COALESCE(changelog,''),COALESCE(active,0),COALESCE(last_seen_utc,'')
                  FROM server.plugin_variants
            """)
            # runtime_plugin_variants is the complete current UI projection.  CTAS intentionally
            # freezes the view into a small physical table so none of its server-side backing tables
            # need to be shipped.
            client.execute("CREATE TABLE runtime_plugin_variants AS SELECT * FROM server.runtime_plugin_variants WHERE 0")
            client.execute("INSERT INTO runtime_plugin_variants SELECT * FROM server.runtime_plugin_variants")
            client.execute("CREATE INDEX ix_client_runtime_internal_name ON runtime_plugin_variants(internal_name COLLATE NOCASE)")
            client.execute("CREATE INDEX ix_client_runtime_plugin_id ON runtime_plugin_variants(plugin_id)")
            client.execute("CREATE INDEX ix_client_runtime_source_url ON runtime_plugin_variants(source_url COLLATE NOCASE)")
            if _table_exists(working, "plugin_search"):
                client.execute("""
                    INSERT INTO plugin_search(plugin_id,internal_name,name,author,punchline,description,tags,website_text)
                    SELECT plugin_id,COALESCE(internal_name,''),COALESCE(name,''),COALESCE(author,''),
                           COALESCE(punchline,''),COALESCE(description,''),COALESCE(tags,''),COALESCE(website_text,'')
                      FROM server.plugin_search
                """)

            if _table_exists(working, "catalog_changelog"):
                # The changelog table is small semantic history already consumed by Omega.  Copy its
                # current schema verbatim rather than coupling this projector to every changelog field.
                server_sql = working.execute(
                    "SELECT sql FROM sqlite_master WHERE type='table' AND name='catalog_changelog'"
                ).fetchone()
                if server_sql and str(server_sql[0] or "").strip():
                    client.execute(str(server_sql[0]))
                    cols = [str(row[1]) for row in working.execute("PRAGMA table_info(catalog_changelog)")]
                    quoted = ",".join(f'"{col}"' for col in cols)
                    client.execute(f"INSERT INTO catalog_changelog({quoted}) SELECT {quoted} FROM server.catalog_changelog")

            client.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('database_role','marketplace')")
            client.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('marketplace_projector_version',?)", (PROJECTOR_VERSION,))
            client.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('detailed_security_evidence_included','0')")
            client.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('client_projection_mode','fresh-allowlist-v1')")
            client.execute("ANALYZE")
            client.commit()
            escaped = str(output_database).replace("'", "''")
            client.execute(f"VACUUM INTO '{escaped}'")
        finally:
            client.close()

    with closing(sqlite3.connect(output_database)) as check:
        table_names = {
            str(row[0]) for row in check.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        }
        unexpected = sorted(table_names - CLIENT_ALLOWED_BASE_TABLES)
        if unexpected:
            raise RuntimeError(f"unexpected server-side tables leaked into Omega client database: {unexpected}")
        return {
            "tables": sorted(table_names),
            "bytes": output_database.stat().st_size,
            "mode": "fresh-allowlist-v1",
        }


def project_database(evidence_database: Path, output_database: Path) -> dict[str, Any]:
    output_database.parent.mkdir(parents=True, exist_ok=True)
    output_database.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(prefix="omega-marketplace-project-") as tmp:
        working_path = Path(tmp) / "working.sqlite"
        shutil.copy2(evidence_database, working_path)
        db = sqlite3.connect(working_path)
        db.row_factory = sqlite3.Row
        try:
            before_integrity = db.execute("PRAGMA integrity_check").fetchone()
            if before_integrity is None or str(before_integrity[0]).lower() != "ok":
                raise RuntimeError(f"evidence database integrity check failed: {before_integrity}")
            runtime_columns_before = {description[1].casefold() for description in db.execute("PRAGMA table_info(runtime_plugin_variants)")}
            projection_ignored_columns = set(ARTIFACT_CANONICAL_RUNTIME_COLUMNS)
            if "omega_banner_url" not in runtime_columns_before:
                projection_ignored_columns.add("omega_banner_url")
            before_runtime = runtime_projection_digest(db, projection_ignored_columns)
            current_rows = int(db.execute("SELECT COUNT(*) FROM plugin_security_current").fetchone()[0])
            db.execute("PRAGMA foreign_keys=OFF")
            db.execute("BEGIN IMMEDIATE")
            create_marketplace_security_current(db)
            db.execute("DROP VIEW IF EXISTS runtime_plugin_variants")
            # Do not strip the working snapshot destructively.  It is temporary and server-rich by
            # design; _write_fresh_client_database copies only the explicit client allow-list.
            create_marketplace_runtime_view(db)
            db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('database_role','marketplace')")
            db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('marketplace_projector_version',?)", (PROJECTOR_VERSION,))
            db.execute("INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('detailed_security_evidence_included','0')")
            db.commit()
            after_runtime = runtime_projection_digest(db, projection_ignored_columns)
            if after_runtime != before_runtime:
                raise RuntimeError("marketplace projection changed non-security runtime_plugin_variants metadata")
            projected_rows = int(db.execute("SELECT COUNT(*) FROM marketplace_security_current").fetchone()[0])
            active_variants = int(db.execute(
                "SELECT COUNT(*) FROM plugin_variants v JOIN plugins p ON p.plugin_id=v.plugin_id WHERE v.active=1 AND p.active=1"
            ).fetchone()[0])
            if projected_rows < current_rows:
                raise RuntimeError("marketplace projection lost current security rows")
            if projected_rows > active_variants:
                raise RuntimeError("marketplace projection created security rows for nonexistent active variants")
            fresh = _write_fresh_client_database(db, output_database)
        finally:
            db.close()

    with closing(sqlite3.connect(output_database)) as check:
        integrity = check.execute("PRAGMA integrity_check").fetchone()
        if integrity is None or str(integrity[0]).lower() != "ok":
            raise RuntimeError(f"marketplace database integrity check failed: {integrity}")
        leaked = [
            row[0] for row in check.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND (name LIKE 'plugin_security_%' OR name IN ('manifest_observations','manifest_source_candidates','source_repositories','source_repository_aliases','plugin_identity_aliases','plugin_tags','plugin_images','websites','presentation')) ORDER BY name"
            )
        ]
        if leaked:
            raise RuntimeError(f"server/catalog working tables leaked into marketplace database: {leaked}")
        if int(check.execute("SELECT COUNT(*) FROM runtime_plugin_variants").fetchone()[0]) <= 0:
            raise RuntimeError("marketplace database contains no runtime plugin variants")
        evidence_revision = read_meta(check, "evidence_revision")
        dependency_rows = int(check.execute(
            "SELECT COUNT(*) FROM runtime_plugin_variants WHERE security_dependency_total_count>0"
        ).fetchone()[0])
        dependency_entries = int(check.execute(
            "SELECT COALESCE(SUM(MIN(security_dependency_total_count, ?)),0) FROM runtime_plugin_variants",
            (DEPENDENCY_SUMMARY_LIMIT,),
        ).fetchone()[0])
        known_risk_rows = int(check.execute(
            "SELECT COUNT(*) FROM runtime_plugin_variants WHERE security_known_advisory_count>0"
        ).fetchone()[0])
        return {
            "integrity": "ok",
            "runtimeProjectionSha256": runtime_projection_digest(check, ARTIFACT_CANONICAL_RUNTIME_COLUMNS),
            "runtimeProjectionWithDependenciesSha256": runtime_projection_digest(check),
            "securityRows": projected_rows,
            "dependencySummaryRows": dependency_rows,
            "dependencySummaryEntries": dependency_entries,
            "knownRiskRows": known_risk_rows,
            "evidenceRevision": evidence_revision,
            "catalogRevision": read_meta(check, "catalog_revision"),
            "securityRevision": read_meta(check, "security_revision"),
            "clientProjection": fresh,
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
