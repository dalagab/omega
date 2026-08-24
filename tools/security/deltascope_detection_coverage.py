#!/usr/bin/env python3
"""Read-only DeltaScope projection of SigmaScope detection/observation coverage.

The matrix deliberately works from the compact current-variant index and the narrow
analysis revisions published with Security Evidence v2.  It therefore does *not* fetch
one variant descriptor per plugin merely to paint a dashboard.  A complete current scan
at the current narrow analysis revision is treated as evidence that the producer contract
for that observation family is current; exact retained rows remain inspectable lazily in
the Rule/Data collection views.

This module never scans, queues, mutates Definitions, or changes evidence authority.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

import observation_projection
import rule_author_reference

SCHEMA = "omega.deltascope.detection-coverage.v1"


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _int(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value or "").strip().casefold() in {"1", "true", "yes", "on"}


def _rev(source: Mapping[str, Any], *keys: str) -> str:
    for key in keys:
        value = source.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


def _revisions(summary: Mapping[str, Any], context: Mapping[str, Any]) -> dict[str, str]:
    evidence = context.get("evidence") if isinstance(context.get("evidence"), Mapping) else {}
    roots = evidence.get("revisions") if isinstance(evidence.get("revisions"), Mapping) else {}
    source = context.get("source") if isinstance(context.get("source"), Mapping) else {}
    meta = summary.get("meta") if isinstance(summary.get("meta"), Mapping) else {}
    return {
        "evidenceRevision": _rev(roots, "evidenceRevision") or _rev(meta, "evidence_revision", "security_evidence_v2_revision"),
        "definitionsRevision": _rev(roots, "definitionsRevision") or _rev(source, "definitionsRevision") or _rev(meta, "definitions_revision"),
        "artifactAnalysisRevision": _rev(roots, "artifactAnalysisRevision") or _rev(source, "artifactAnalysisRevision") or _rev(meta, "artifact_analysis_revision", "definitions_artifact_analysis_revision"),
        "sourceAnalysisRevision": _rev(roots, "sourceAnalysisRevision") or _rev(source, "sourceAnalysisRevision") or _rev(meta, "source_analysis_revision", "definitions_source_analysis_revision"),
        "sourceObservationRevision": _rev(roots, "sourceObservationRevision") or _rev(meta, "source_observation_revision", "definitions_source_observation_revision"),
        "ruleSetRevision": _rev(roots, "ruleSetRevision") or _rev(meta, "rule_set_revision", "definitions_rule_set_revision"),
        "observationContractRevision": observation_projection.contract_revision(),
    }


def _rule_dependencies(provenance: Mapping[str, Any], repository_library: Mapping[str, Any] | None) -> tuple[dict[str, list[dict[str, Any]]], str]:
    by_collection: dict[str, list[dict[str, Any]]] = {}
    active = provenance.get("activeRules") if isinstance(provenance.get("activeRules"), list) else []
    authority = "published-definitions" if active else "repository-source"
    if active:
        rows = [dict(row) for row in active if isinstance(row, Mapping) and row.get("active", True)]
    else:
        rows = []
        for pack in (repository_library or {}).get("packs") or []:
            if not isinstance(pack, Mapping):
                continue
            pack_id = str(pack.get("packId") or "")
            for rule in pack.get("rules") or []:
                if not isinstance(rule, Mapping):
                    continue
                rows.append({**dict(rule), "packId": pack_id})
    for rule in rows:
        for collection in rule.get("requires") or []:
            name = str(collection or "")
            if not name:
                continue
            by_collection.setdefault(name, []).append({
                "ruleId": str(rule.get("ruleId") or rule.get("id") or ""),
                "packId": str(rule.get("packId") or ""),
                "kind": str(rule.get("kind") or ""),
                "status": str(rule.get("status") or ""),
                "title": str(rule.get("title") or (rule.get("emit") or {}).get("title") or ""),
            })
    for values in by_collection.values():
        values.sort(key=lambda row: (row.get("packId", "").casefold(), row.get("ruleId", "").casefold()))
    return by_collection, authority


def _scope_for(spec: Mapping[str, Any]) -> tuple[str, str, bool]:
    origin = str(spec.get("origin") or "artifact+source")
    if origin == "source":
        return "source-attributable current variants", "sourceAnalysisRevision", True
    if origin == "catalog":
        return "current catalog variants", "artifactAnalysisRevision", False
    # artifact+source means artifact observations are still meaningful without source;
    # source evidence augments the same logical collection when available.
    return "current analyzed variants", "artifactAnalysisRevision", False


def _row_revision(asset: Mapping[str, Any], revision_key: str) -> str:
    if revision_key == "sourceAnalysisRevision":
        return _rev(asset, "source_analysis_revision", "sourceAnalysisRevision")
    return _rev(asset, "artifact_analysis_revision", "artifactAnalysisRevision")


def _asset_identity(asset: Mapping[str, Any], reason: str) -> dict[str, Any]:
    return {
        "variantId": _int(asset.get("variant_id") or asset.get("variantId")),
        "pluginId": _int(asset.get("plugin_id") or asset.get("pluginId")),
        "name": str(asset.get("canonical_name") or asset.get("canonicalName") or asset.get("name") or asset.get("internal_name") or ""),
        "internalName": str(asset.get("internal_name") or asset.get("internalName") or ""),
        "version": str(asset.get("assembly_version") or asset.get("version") or ""),
        "status": str(asset.get("scan_status") or asset.get("scanStatus") or "unscanned"),
        "scannedAtUtc": str(asset.get("scanned_at_utc") or asset.get("scannedAtUtc") or ""),
        "artifactAnalysisRevision": _rev(asset, "artifact_analysis_revision", "artifactAnalysisRevision"),
        "sourceAnalysisRevision": _rev(asset, "source_analysis_revision", "sourceAnalysisRevision"),
        "sourceAvailable": _bool(asset.get("source_available") if asset.get("source_available") is not None else asset.get("source_code_available")),
        "reason": reason,
    }


def _collection_row(
    name: str,
    spec: Mapping[str, Any],
    assets: list[dict[str, Any]],
    revisions: Mapping[str, str],
    rules: list[dict[str, Any]],
) -> dict[str, Any]:
    author = rule_author_reference.COLLECTIONS.get(name) or {}
    scope_label, revision_key, source_conditional = _scope_for(spec)
    target_revision = str(revisions.get(revision_key) or "")
    targets: list[dict[str, Any]] = []
    outside = 0
    for asset in assets:
        source_available = _bool(asset.get("source_available") if asset.get("source_available") is not None else asset.get("source_code_available"))
        if source_conditional and not source_available:
            outside += 1
            continue
        targets.append(asset)

    covered = 0
    stale = 0
    incomplete = 0
    unknown_revision = 0
    gap_rows: list[dict[str, Any]] = []
    observed_times: list[str] = []
    for asset in targets:
        status = str(asset.get("scan_status") or asset.get("scanStatus") or "unscanned").casefold()
        scanned = str(asset.get("scanned_at_utc") or asset.get("scannedAtUtc") or "")
        if scanned:
            observed_times.append(scanned)
        if status != "complete":
            incomplete += 1
            if len(gap_rows) < 80:
                gap_rows.append(_asset_identity(asset, f"analysis status is {status or 'unknown'}"))
            continue
        asset_revision = _row_revision(asset, revision_key)
        if target_revision and not asset_revision:
            unknown_revision += 1
            if len(gap_rows) < 80:
                gap_rows.append(_asset_identity(asset, f"{revision_key} is not retained on the current index row"))
            continue
        if target_revision and asset_revision != target_revision:
            stale += 1
            if len(gap_rows) < 80:
                gap_rows.append(_asset_identity(asset, f"analysis revision {asset_revision or 'unknown'} differs from current {target_revision}"))
            continue
        covered += 1

    target_count = len(targets)
    gap_count = max(0, target_count - covered)
    percent = round((covered / target_count) * 100.0, 1) if target_count else 100.0
    if gap_count == 0:
        status = "healthy"
    elif covered == 0 and target_count:
        status = "blind-spot"
    elif percent < 90:
        status = "degraded"
    else:
        status = "attention"

    origin = str(spec.get("origin") or "")
    special_note = str(author.get("notes") or "")
    if name == "developerProfile":
        special_note = (special_note + " Coverage here measures whether the source-analysis path is current; a developer profile is optional and its absence is not itself a scanner blind spot.").strip()
    elif name == "secondarySecurity":
        special_note = (special_note + " Index-level coverage cannot prove that every optional secondary engine was available; inspect plugin evidence or Operations for engine-specific failures.").strip()

    remediation = "none"
    if incomplete:
        remediation = "complete/retry the current analysis"
    if stale or unknown_revision:
        remediation = "targeted re-analysis at the current narrow analysis revision"
    if source_conditional and gap_count:
        remediation = "source follow-up / source re-analysis"

    display_name = {
        "managedCallSites": "Managed calls",
        "managedReachability": "Managed reachability",
        "nativeImports": "Native imports / PInvoke",
        "networkEndpoints": "Network endpoints",
        "staticPatternMatches": "Static pattern matches",
        "secondarySecurity": "YARA / ClamAV supplemental security",
        "sourceFiles": "Source-file observations",
        "dependencies": "Dependencies",
        "ipcIntegrations": "IPC integrations",
    }.get(name, name)
    return {
        "kind": "observation-collection",
        "collection": name,
        "displayName": display_name,
        "schema": str(spec.get("schema") or ""),
        "semanticClass": str(spec.get("semanticClass") or "observation"),
        "origin": origin,
        "srlEligible": bool(spec.get("srlEligible")),
        "sameRecordSemantics": bool(spec.get("sameRecordSemantics")),
        "backingDataset": str(spec.get("backingDataset") or author.get("dataset") or ""),
        "producer": str(author.get("source") or spec.get("backingDataset") or ""),
        "scope": str(author.get("scope") or "retained observation"),
        "fields": dict(author.get("fields") or {}),
        "notes": special_note,
        "coverageBasis": "current variant index + narrow analysis revision",
        "coverageExactness": "contract-currentness; exact row presence is lazy per plugin",
        "expectedScope": scope_label,
        "revisionKey": revision_key,
        "targetRevision": target_revision,
        "targetVariants": target_count,
        "coveredVariants": covered,
        "gapVariants": gap_count,
        "staleVariants": stale,
        "incompleteVariants": incomplete,
        "unknownRevisionVariants": unknown_revision,
        "outsideScopeVariants": outside,
        "coveragePercent": percent,
        "status": status,
        "remediation": remediation,
        "rescanRequiredForGap": bool(stale or unknown_revision or incomplete),
        "reprojectionSufficientForMissingRawObservation": False,
        "oldestObservedAtUtc": min(observed_times) if observed_times else "",
        "newestObservedAtUtc": max(observed_times) if observed_times else "",
        "ruleCount": len(rules),
        "rules": rules,
        "gapPreview": gap_rows,
        "gapPreviewTruncated": gap_count > len(gap_rows),
    }


def _osv_row(context: Mapping[str, Any]) -> dict[str, Any] | None:
    source = context.get("source") if isinstance(context.get("source"), Mapping) else {}
    osv = source.get("osv") if isinstance(source.get("osv"), Mapping) else {}
    if not osv:
        return None
    expected = _int(osv.get("expectedQueryPackageVersionPairs") or osv.get("inputPackageVersionPairs"))
    queried = _int(osv.get("queriedPackageVersionPairs"))
    gap = max(0, expected - queried)
    percent = round((queried / expected) * 100.0, 1) if expected else 100.0
    return {
        "kind": "advisory-collector",
        "collection": "OSV / NuGet advisories",
        "schema": str(osv.get("schema") or ""),
        "semanticClass": "dependency-advisory",
        "origin": "frozen-definitions",
        "srlEligible": False,
        "backingDataset": "frozen OSV advisory universe",
        "producer": "collect_public_advisories.py",
        "scope": "NuGet package-version pairs in the frozen query universe",
        "fields": {},
        "notes": "This row uses package-version pairs rather than plugin variants. It is an exact collector-universe coverage ratio from the published frozen OSV metadata.",
        "coverageBasis": "published frozen OSV coverage metadata",
        "coverageExactness": "exact query-universe coverage",
        "expectedScope": "NuGet package-version pairs",
        "revisionKey": "advisoryRevision",
        "targetRevision": str(osv.get("advisoryRevision") or source.get("advisoryRevision") or ""),
        "targetVariants": expected,
        "coveredVariants": queried,
        "gapVariants": gap,
        "staleVariants": 0,
        "incompleteVariants": gap,
        "unknownRevisionVariants": 0,
        "outsideScopeVariants": _int(osv.get("notCoveredByFrozenDefinitions")),
        "coveragePercent": percent,
        "status": "healthy" if gap == 0 else "attention" if queried else "blind-spot",
        "remediation": "refresh/freeze advisory Definitions" if gap else "none",
        "rescanRequiredForGap": False,
        "reprojectionSufficientForMissingRawObservation": False,
        "oldestObservedAtUtc": "",
        "newestObservedAtUtc": str(osv.get("generatedAtUtc") or ""),
        "ruleCount": 0,
        "rules": [],
        "gapPreview": [],
        "gapPreviewTruncated": False,
        "unit": "package-version pairs",
    }


def project_detection_coverage(
    inspector: Any,
    *,
    repository_library: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the bounded corpus coverage matrix from current published state."""
    summary = inspector.summary()
    context = inspector.workbench_system_context() if hasattr(inspector, "workbench_system_context") else {
        "evidence": {"revisions": dict(summary.get("revisions") or summary.get("meta") or {})},
        "source": {}, "queue": {"available": False, "summary": {}},
    }
    assets = [dict(row) for row in inspector.list_plugins(limit=2000)]
    provenance = inspector.definition_provenance() if hasattr(inspector, "definition_provenance") else {}
    by_collection, rule_authority = _rule_dependencies(provenance, repository_library)
    revisions = _revisions(summary, context)

    rows = [
        _collection_row(name, spec, assets, revisions, by_collection.get(name, []))
        for name, spec in observation_projection.COLLECTIONS.items()
        if bool(spec.get("srlEligible"))
    ]
    osv = _osv_row(context)
    if osv:
        rows.append(osv)

    rows.sort(key=lambda row: (
        {"blind-spot": 0, "degraded": 1, "attention": 2, "healthy": 3}.get(str(row.get("status") or ""), 4),
        float(row.get("coveragePercent") or 0),
        str(row.get("collection") or "").casefold(),
    ))
    blind = [row for row in rows if str(row.get("status") or "") != "healthy"]
    total_current = len(assets)
    complete = sum(1 for row in assets if str(row.get("scan_status") or row.get("scanStatus") or "").casefold() == "complete")
    artifact_current = sum(
        1 for row in assets
        if str(row.get("scan_status") or row.get("scanStatus") or "").casefold() == "complete"
        and (not revisions["artifactAnalysisRevision"] or _row_revision(row, "artifactAnalysisRevision") == revisions["artifactAnalysisRevision"])
    )
    source_scope = [row for row in assets if _bool(row.get("source_available") if row.get("source_available") is not None else row.get("source_code_available"))]
    source_current = sum(
        1 for row in source_scope
        if str(row.get("scan_status") or row.get("scanStatus") or "").casefold() == "complete"
        and (not revisions["sourceAnalysisRevision"] or _row_revision(row, "sourceAnalysisRevision") == revisions["sourceAnalysisRevision"])
    )
    queue = context.get("queue") if isinstance(context.get("queue"), Mapping) else {}
    queue_summary = queue.get("summary") if isinstance(queue.get("summary"), Mapping) else {}

    return {
        "schema": SCHEMA,
        "readOnly": True,
        "mutationAuthority": "none",
        "policyInput": False,
        "generatedAtUtc": str(context.get("generatedAtUtc") or summary.get("generatedAtUtc") or _now()),
        "coverageMethod": "index-revision-contract-v1",
        "coverageMethodNote": (
            "The matrix deliberately avoids fetching every variant descriptor. A complete current scan at the current narrow analysis revision is treated as current producer-contract coverage. "
            "Exact rows/completeness remain available through per-plugin collection inspection. Empty complete collections are valid negative evidence and are not counted as blind spots."
        ),
        "revisions": revisions,
        "ruleDependencyAuthority": rule_authority,
        "corpus": {
            "currentVariants": total_current,
            "completeCurrentScans": complete,
            "artifactRevisionCurrent": artifact_current,
            "sourceAttributableVariants": len(source_scope),
            "sourceRevisionCurrent": source_current,
            "queuePending": _int((queue_summary.get("states") or {}).get("pending") if isinstance(queue_summary.get("states"), Mapping) else queue_summary.get("pending")),
            "queueRetry": _int((queue_summary.get("states") or {}).get("retry") if isinstance(queue_summary.get("states"), Mapping) else queue_summary.get("retry")),
        },
        "summary": {
            "systems": len(rows),
            "healthy": sum(1 for row in rows if row.get("status") == "healthy"),
            "attention": sum(1 for row in rows if row.get("status") == "attention"),
            "degraded": sum(1 for row in rows if row.get("status") == "degraded"),
            "blindSpots": sum(1 for row in rows if row.get("status") == "blind-spot"),
            "collectionsWithRuleDependencies": sum(1 for row in rows if _int(row.get("ruleCount")) > 0),
            "variantsNotAtCurrentArtifactRevision": max(0, total_current - artifact_current),
            "sourceVariantsNotAtCurrentSourceRevision": max(0, len(source_scope) - source_current),
        },
        "blindSpots": [
            {
                "collection": row.get("collection"), "status": row.get("status"),
                "coveragePercent": row.get("coveragePercent"), "gapVariants": row.get("gapVariants"),
                "remediation": row.get("remediation"), "ruleCount": row.get("ruleCount"),
            }
            for row in blind
        ],
        "collections": rows,
    }
