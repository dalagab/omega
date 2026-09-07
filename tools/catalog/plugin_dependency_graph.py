#!/usr/bin/env python3
"""Build Omega's normalized plugin-to-plugin dependency graph.

SigmaScope owns observations; this module turns explicit plugin dependency observations
and their current catalog resolution into deterministic package relationships. Unresolved
or ambiguous required declarations remain blocking edges instead of disappearing. IPC,
project references, NuGet, native, framework and bundled components never become package
authority.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any

GRAPH_SCHEMA = "omega.plugin-dependency-graph.v1"
PACKAGE_KINDS = {"external-plugin", "plugin"}
CONFIDENCE_RANK = {"veryhigh": 4, "high": 3, "medium": 2, "low": 1}


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _table_exists(db: sqlite3.Connection, name: str) -> bool:
    return db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (name,),
    ).fetchone() is not None


def _columns(db: sqlite3.Connection, table: str) -> set[str]:
    if not _table_exists(db, table):
        return set()
    return {str(row[1]) for row in db.execute(f'PRAGMA table_info("{table}")')}


def _expr(alias: str, columns: set[str], name: str, fallback: str = "''") -> str:
    return f"COALESCE({alias}.{name},{fallback})" if name in columns else fallback


def _relationship(requirement: str, relationship: str) -> str:
    requirement = requirement.strip().casefold()
    relationship = relationship.strip().casefold()
    if requirement == "required" or relationship == "required":
        return "required"
    if requirement == "soft" or relationship == "feature":
        return "recommended"
    if requirement == "optional" or relationship == "optional":
        return "optional"
    return "observed"


def _confidence_rank(value: str) -> int:
    return CONFIDENCE_RANK.get(value.replace("_", "").replace("-", "").casefold(), 0)


def _install_eligible(provider_plugin_id: int, relationship: str, resolution_status: str, version_status: str) -> bool:
    if provider_plugin_id <= 0 or relationship not in {"required", "recommended", "optional"}:
        return False
    resolution = resolution_status.strip().casefold()
    version = version_status.strip().casefold()
    if any(token in resolution for token in ("missing", "unresolved", "ambiguous", "conflict")):
        return False
    return version != "incompatible"


def build_graph(db: sqlite3.Connection) -> dict[str, Any]:
    required_tables = {
        "plugin_security_dependency_resolutions",
        "plugin_security_current",
        "plugins",
        "plugin_variants",
    }
    if not all(_table_exists(db, table) for table in required_tables):
        return _empty_graph()

    rcols = _columns(db, "plugin_security_dependency_resolutions")
    required = {
        "dependency_id",
        "source_variant_id",
        "source_plugin_id",
        "scan_id",
        "dependency_kind",
        "dependency_name",
        "requirement",
        "resolution_status",
        "target_plugin_id",
        "target_internal_name",
    }
    if not required.issubset(rcols):
        return _empty_graph()

    dcols = _columns(db, "plugin_security_dependencies")
    dependency_join = (
        "LEFT JOIN plugin_security_dependencies d ON d.dependency_id=r.dependency_id"
        if dcols
        else "LEFT JOIN (SELECT NULL AS dependency_id) d ON 1=0"
    )
    origin_expr = _expr("d", dcols, "origin")
    version_requirement_expr = _expr("r", rcols, "version_requirement")
    resolved_version_expr = _expr("r", rcols, "resolved_version")
    relationship_expr = _expr("r", rcols, "relationship")
    relationship_confidence_expr = _expr("r", rcols, "relationship_confidence")
    confidence_expr = _expr("r", rcols, "confidence")
    version_status_expr = _expr("r", rcols, "version_status")
    target_version_expr = _expr("r", rcols, "target_version")

    rows = db.execute(f"""
        SELECT r.source_variant_id,
               r.source_plugin_id,
               COALESCE(cp.internal_name,'') AS consumer_internal_name,
               COALESCE(pv.assembly_version,'') AS consumer_version,
               COALESCE(r.dependency_kind,'') AS dependency_kind,
               COALESCE(r.dependency_name,'') AS dependency_name,
               {version_requirement_expr} AS version_requirement,
               {resolved_version_expr} AS resolved_version,
               COALESCE(r.requirement,'') AS requirement,
               {relationship_expr} AS relationship,
               {relationship_confidence_expr} AS relationship_confidence,
               {confidence_expr} AS confidence,
               COALESCE(r.resolution_status,'') AS resolution_status,
               {version_status_expr} AS version_status,
               COALESCE(r.target_plugin_id,0) AS target_plugin_id,
               COALESCE(r.target_internal_name,'') AS target_internal_name,
               {target_version_expr} AS target_version,
               {origin_expr} AS origin
          FROM plugin_security_dependency_resolutions r
          JOIN plugin_security_current c
            ON c.variant_id=r.source_variant_id
           AND c.scan_id=r.scan_id
           AND c.status='complete'
          LEFT JOIN plugins cp ON cp.plugin_id=r.source_plugin_id
          LEFT JOIN plugin_variants pv ON pv.variant_id=r.source_variant_id
          {dependency_join}
         ORDER BY r.source_variant_id,
                  lower(COALESCE(NULLIF(TRIM(r.target_internal_name),''),r.dependency_name)),
                  r.dependency_id
    """).fetchall()

    merged: dict[tuple[Any, ...], dict[str, Any]] = {}
    for row in rows:
        source_kind = str(row[4] or "").strip().casefold()
        if source_kind not in PACKAGE_KINDS:
            continue
        consumer_internal = str(row[2] or "").strip()
        declared_internal = str(row[5] or "").strip()
        resolved_internal = str(row[15] or "").strip()
        provider_internal = resolved_internal or declared_internal
        if not provider_internal or provider_internal.casefold() == consumer_internal.casefold():
            continue

        relationship = _relationship(str(row[8] or ""), str(row[9] or ""))
        key = (
            int(row[0] or 0),
            provider_internal.casefold(),
            relationship,
            str(row[6] or "").strip(),
        )
        confidence = str(row[10] or row[11] or "").strip()
        edge = {
            "consumerVariantId": int(row[0] or 0),
            "consumerPluginId": int(row[1] or 0),
            "consumerInternalName": consumer_internal,
            "consumerVersion": str(row[3] or ""),
            "providerPluginId": int(row[14] or 0),
            "providerInternalName": provider_internal,
            "relationship": relationship,
            "versionConstraint": str(row[6] or "").strip(),
            "resolvedVersion": str(row[7] or row[16] or "").strip(),
            "resolutionStatus": str(row[12] or "").strip(),
            "versionStatus": str(row[13] or "").strip(),
            "confidence": confidence,
            "sourceKind": source_kind,
            "origins": sorted({str(row[17] or "").strip()} - {""}),
        }
        edge["installEligible"] = _install_eligible(
            edge["providerPluginId"],
            relationship,
            edge["resolutionStatus"],
            edge["versionStatus"],
        )
        previous = merged.get(key)
        if previous is None:
            merged[key] = edge
            continue
        previous["origins"] = sorted(set(previous.get("origins") or []) | set(edge["origins"]))
        if _confidence_rank(edge["confidence"]) > _confidence_rank(str(previous.get("confidence") or "")):
            previous["confidence"] = edge["confidence"]
        if not previous.get("providerPluginId") and edge["providerPluginId"]:
            previous["providerPluginId"] = edge["providerPluginId"]
        previous["installEligible"] = bool(previous.get("installEligible")) or bool(edge["installEligible"])

    edges = sorted(
        merged.values(),
        key=lambda item: (
            int(item["consumerPluginId"]),
            int(item["consumerVariantId"]),
            str(item["providerInternalName"]).casefold(),
            str(item["relationship"]),
            str(item["versionConstraint"]),
        ),
    )
    providers = _providers(edges)
    semantic_edges = [
        {
            key: edge[key]
            for key in (
                "consumerVariantId",
                "consumerPluginId",
                "providerPluginId",
                "providerInternalName",
                "relationship",
                "versionConstraint",
                "resolutionStatus",
                "versionStatus",
                "installEligible",
            )
        }
        for edge in edges
    ]
    revision = f"plugin-deps-v1-{hashlib.sha256(_canonical(semantic_edges)).hexdigest()[:20]}"
    return {
        "schema": GRAPH_SCHEMA,
        "authority": "catalog-package-resolution-projection",
        "dependencyGraphRevision": revision,
        "semantics": {
            "securityEvidenceIsObservationOnly": True,
            "ipcIsPackageDependency": False,
            "projectReferencesArePackageDependencies": False,
            "unresolvedPluginRequirementsRetained": True,
            "providerIdentity": "stable-plugin-id",
            "consumerIdentity": "catalog-variant",
        },
        "counts": {
            "edges": len(edges),
            "providers": len(providers),
            "resolvedEdges": sum(1 for edge in edges if int(edge["providerPluginId"] or 0) > 0),
            "unresolvedEdges": sum(1 for edge in edges if int(edge["providerPluginId"] or 0) <= 0),
            "requiredEdges": sum(1 for edge in edges if edge["relationship"] == "required"),
            "blockedRequiredEdges": sum(1 for edge in edges if edge["relationship"] == "required" and not edge["installEligible"]),
            "installEligibleEdges": sum(1 for edge in edges if edge["installEligible"]),
        },
        "edges": edges,
        "providers": providers,
    }


def _providers(edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    buckets: dict[str, dict[str, Any]] = {}
    for edge in edges:
        provider_plugin_id = int(edge["providerPluginId"] or 0)
        internal_name = str(edge["providerInternalName"])
        if provider_plugin_id <= 0 or not internal_name:
            continue
        key = internal_name.casefold()
        bucket = buckets.setdefault(
            key,
            {
                "providerPluginId": provider_plugin_id,
                "providerInternalName": internal_name,
                "requiredBy": {},
                "recommendedBy": {},
                "optionalBy": {},
            },
        )
        if not bucket["providerPluginId"] and edge["providerPluginId"]:
            bucket["providerPluginId"] = int(edge["providerPluginId"])
        target = {
            "required": "requiredBy",
            "recommended": "recommendedBy",
            "optional": "optionalBy",
        }.get(str(edge["relationship"]))
        if target is None:
            continue
        consumer_key = int(edge["consumerPluginId"] or 0) or -int(edge["consumerVariantId"])
        bucket[target][consumer_key] = {
            "pluginId": int(edge["consumerPluginId"] or 0),
            "internalName": str(edge["consumerInternalName"] or ""),
        }

    result = []
    for bucket in buckets.values():
        required = sorted(bucket.pop("requiredBy").values(), key=lambda x: (x["internalName"].casefold(), x["pluginId"]))
        recommended = sorted(bucket.pop("recommendedBy").values(), key=lambda x: (x["internalName"].casefold(), x["pluginId"]))
        optional = sorted(bucket.pop("optionalBy").values(), key=lambda x: (x["internalName"].casefold(), x["pluginId"]))
        result.append(
            {
                **bucket,
                "requiredByCount": len(required),
                "recommendedByCount": len(recommended),
                "optionalByCount": len(optional),
                "totalDependentPlugins": len(
                    {(x["pluginId"], x["internalName"].casefold()) for x in required + recommended + optional}
                ),
                "requiredBy": required,
            }
        )
    return sorted(result, key=lambda x: (x["providerInternalName"].casefold(), x["providerPluginId"]))


def _empty_graph() -> dict[str, Any]:
    revision = f"plugin-deps-v1-{hashlib.sha256(_canonical([])).hexdigest()[:20]}"
    return {
        "schema": GRAPH_SCHEMA,
        "authority": "catalog-package-resolution-projection",
        "dependencyGraphRevision": revision,
        "semantics": {
            "securityEvidenceIsObservationOnly": True,
            "ipcIsPackageDependency": False,
            "projectReferencesArePackageDependencies": False,
            "unresolvedPluginRequirementsRetained": True,
            "providerIdentity": "stable-plugin-id",
            "consumerIdentity": "catalog-variant",
        },
        "counts": {
            "edges": 0,
            "providers": 0,
            "resolvedEdges": 0,
            "unresolvedEdges": 0,
            "requiredEdges": 0,
            "blockedRequiredEdges": 0,
            "installEligibleEdges": 0,
        },
        "edges": [],
        "providers": [],
    }


def materialize_catalog_tables(db: sqlite3.Connection) -> dict[str, Any]:
    graph = build_graph(db)
    db.execute("DROP TABLE IF EXISTS plugin_dependencies")
    db.execute("DROP TABLE IF EXISTS plugin_dependency_providers")
    db.execute("""
        CREATE TABLE plugin_dependencies (
            consumer_variant_id INTEGER NOT NULL,
            consumer_plugin_id INTEGER NOT NULL,
            consumer_internal_name TEXT NOT NULL,
            consumer_version TEXT NOT NULL,
            provider_plugin_id INTEGER NOT NULL,
            provider_internal_name TEXT NOT NULL,
            relationship TEXT NOT NULL,
            version_constraint TEXT NOT NULL,
            resolved_version TEXT NOT NULL,
            resolution_status TEXT NOT NULL,
            version_status TEXT NOT NULL,
            confidence TEXT NOT NULL,
            source_kind TEXT NOT NULL,
            origins_json TEXT NOT NULL,
            install_eligible INTEGER NOT NULL,
            PRIMARY KEY(consumer_variant_id,provider_internal_name,relationship,version_constraint)
        )
    """)
    db.execute(
        "CREATE INDEX ix_plugin_dependencies_provider ON plugin_dependencies(provider_plugin_id,provider_internal_name)"
    )
    db.execute(
        "CREATE INDEX ix_plugin_dependencies_consumer ON plugin_dependencies(consumer_plugin_id,consumer_variant_id)"
    )
    db.execute("""
        CREATE TABLE plugin_dependency_providers (
            provider_plugin_id INTEGER NOT NULL,
            provider_internal_name TEXT PRIMARY KEY,
            required_by_count INTEGER NOT NULL,
            recommended_by_count INTEGER NOT NULL,
            optional_by_count INTEGER NOT NULL,
            total_dependent_plugins INTEGER NOT NULL
        )
    """)
    for edge in graph["edges"]:
        db.execute(
            "INSERT INTO plugin_dependencies VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                edge["consumerVariantId"],
                edge["consumerPluginId"],
                edge["consumerInternalName"],
                edge["consumerVersion"],
                edge["providerPluginId"],
                edge["providerInternalName"],
                edge["relationship"],
                edge["versionConstraint"],
                edge["resolvedVersion"],
                edge["resolutionStatus"],
                edge["versionStatus"],
                edge["confidence"],
                edge["sourceKind"],
                json.dumps(edge["origins"], separators=(",", ":")),
                int(edge["installEligible"]),
            ),
        )
    for provider in graph["providers"]:
        db.execute(
            "INSERT INTO plugin_dependency_providers VALUES(?,?,?,?,?,?)",
            (
                provider["providerPluginId"],
                provider["providerInternalName"],
                provider["requiredByCount"],
                provider["recommendedByCount"],
                provider["optionalByCount"],
                provider["totalDependentPlugins"],
            ),
        )
    if _table_exists(db, "catalog_meta"):
        db.execute(
            "INSERT OR REPLACE INTO catalog_meta(key,value) VALUES('dependency_graph_revision',?)",
            (graph["dependencyGraphRevision"],),
        )
    return graph
