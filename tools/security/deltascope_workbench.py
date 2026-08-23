#!/usr/bin/env python3
"""Deterministic read-only DeltaScope security-information projections.

These projections are investigator navigation objects only. They never become SigmaScope
findings, queue state, Definitions, or mutable case-management records.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable, Mapping

WORKBENCH_SCHEMA = "omega.deltascope.security-workbench.v1"
INCIDENT_SCHEMA = "omega.deltascope.incident-projection.v1"
EVENT_SCHEMA = "omega.deltascope.event-projection.v1"
INTELLIGENCE_SCHEMA = "omega.deltascope.intelligence-projection.v1"
CASE_SCHEMA = "omega.deltascope.incident-case-projection.v1"
TIMELINE_SCHEMA = "omega.deltascope.security-timeline.v1"
JOURNEY_SCHEMA = "omega.deltascope.asset-journey.v1"

SEVERITY_RANK = {
    "none": 0,
    "informational": 1,
    "low": 1,
    "caution": 2,
    "moderate": 2,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
RANK_SEVERITY = {0: "none", 1: "informational", 2: "caution", 3: "high", 4: "critical"}

# Collections that are useful as investigator timeline events.  The selected-case API
# remains lazy and bounded; this list does not authorize these collections as policy.
TIMELINE_COLLECTIONS = (
    "staticPatternMatches", "networkEndpoints", "nativeImports", "dependencies",
    "ipcIntegrations", "binaryClassifications", "sourceFiles", "secondarySecurity",
    "sourceAttribution", "sourceProvenance", "artifactIdentity", "manifestObservation",
)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _stable_id(prefix: str, payload: dict[str, Any]) -> str:
    return f"{prefix}-{hashlib.sha256(_canonical(payload)).hexdigest()[:20]}"


def _int(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _severity(value: Any) -> str:
    text = str(value or "none").strip().casefold()
    return text if text in SEVERITY_RANK else "none"


def _asset(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "variantId": _int(row.get("variant_id")),
        "pluginId": _int(row.get("plugin_id")),
        "name": str(row.get("canonical_name") or row.get("name") or row.get("internal_name") or ""),
        "internalName": str(row.get("internal_name") or ""),
        "version": str(row.get("assembly_version") or ""),
        "author": str(row.get("author") or ""),
        "sourceName": str(row.get("source_name") or ""),
        "sourceUrl": str(row.get("source_url") or ""),
    }


def _finding_count(row: dict[str, Any]) -> int:
    return sum(_int(row.get(key)) for key in ("critical_count", "high_count", "caution_count", "informational_count"))


def _incident(row: dict[str, Any]) -> dict[str, Any] | None:
    severity = _severity(row.get("highest_severity"))
    rank = SEVERITY_RANK[severity]
    status = str(row.get("scan_status") or "unscanned").strip().casefold()
    advisories = _int(row.get("knownAdvisoryCount"))
    advisory_severity = _severity(row.get("knownAdvisoryHighestSeverity"))
    reasons: list[dict[str, str]] = []
    if rank >= 2:
        reasons.append({"code": "elevated-findings", "label": f"Current static severity is {severity}"})
    if status not in {"complete", "unscanned", ""}:
        reasons.append({"code": "analysis-incomplete", "label": f"Current analysis status is {status}"})
    if advisories:
        reasons.append({"code": "known-advisory", "label": f"{advisories} known dependency advisory match(es)"})
    if not reasons:
        return None
    priority = "urgent" if rank >= 4 else "review" if rank >= 3 else "failed" if status not in {"complete", "unscanned", ""} else "watch"
    effective_rank = max(rank, SEVERITY_RANK[advisory_severity], 2 if status not in {"complete", "unscanned", ""} else 0)
    identity = {
        "variantId": _int(row.get("variant_id")),
        "scanId": _int(row.get("scan_id")),
        "status": status,
        "severity": severity,
        "advisories": advisories,
        "advisorySeverity": advisory_severity,
        "reasons": [item["code"] for item in reasons],
    }
    return {
        "schema": INCIDENT_SCHEMA,
        "incidentId": _stable_id("incident", identity),
        "readOnly": True,
        "mutationAuthority": "none",
        "asset": _asset(row),
        "priority": priority,
        "severity": RANK_SEVERITY[effective_rank],
        "findingCount": _finding_count(row),
        "advisoryCount": advisories,
        "advisoryHighestSeverity": advisory_severity,
        "analysisStatus": status or "unscanned",
        "lastEvidenceUtc": str(row.get("scanned_at_utc") or ""),
        "reasons": reasons,
    }


def _event(row: dict[str, Any]) -> dict[str, Any]:
    status = str(row.get("scan_status") or "unscanned").strip().casefold() or "unscanned"
    severity = _severity(row.get("highest_severity"))
    identity = {
        "variantId": _int(row.get("variant_id")),
        "scanId": _int(row.get("scan_id")),
        "status": status,
        "time": str(row.get("scanned_at_utc") or ""),
        "severity": severity,
    }
    label = "Security analysis completed" if status == "complete" else "No completed analysis" if status == "unscanned" else f"Security analysis {status}"
    return {
        "schema": EVENT_SCHEMA,
        "eventId": _stable_id("event", identity),
        "readOnly": True,
        "mutationAuthority": "none",
        "asset": _asset(row),
        "eventType": "security-analysis",
        "label": label,
        "occurredAtUtc": str(row.get("scanned_at_utc") or ""),
        "analysisStatus": status,
        "severity": severity,
        "scanId": _int(row.get("scan_id")),
    }


def _intelligence(row: dict[str, Any]) -> dict[str, Any] | None:
    count = _int(row.get("knownAdvisoryCount"))
    if not count:
        return None
    highest = _severity(row.get("knownAdvisoryHighestSeverity"))
    identity = {
        "variantId": _int(row.get("variant_id")),
        "scanId": _int(row.get("scan_id")),
        "advisoryCount": count,
        "highest": highest,
    }
    return {
        "schema": INTELLIGENCE_SCHEMA,
        "intelligenceId": _stable_id("intel", identity),
        "readOnly": True,
        "mutationAuthority": "none",
        "asset": _asset(row),
        "kind": "dependency-advisory",
        "advisoryCount": count,
        "highestSeverity": highest,
        "staticSeverity": _severity(row.get("highest_severity")),
        "lastEvidenceUtc": str(row.get("scanned_at_utc") or ""),
    }


def _bounded(value: Any, *, depth: int = 0) -> Any:
    """Return deterministic investigator preview data, never a replacement evidence record."""
    if depth >= 3:
        return "…"
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key in sorted(str(k) for k in value.keys())[:16]:
            result[key] = _bounded(value.get(key), depth=depth + 1)
        if len(value) > 16:
            result["_truncatedFields"] = len(value) - 16
        return result
    if isinstance(value, list):
        result = [_bounded(item, depth=depth + 1) for item in value[:8]]
        if len(value) > 8:
            result.append(f"… {len(value) - 8} more")
        return result
    if isinstance(value, str):
        return value if len(value) <= 400 else value[:397] + "…"
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    return str(value)[:400]


def _finding_rows(detail: Mapping[str, Any]) -> list[dict[str, Any]]:
    researcher = detail.get("researcher") if isinstance(detail.get("researcher"), Mapping) else {}
    source = researcher.get("findings") if isinstance(researcher.get("findings"), list) else detail.get("findings")
    result: list[dict[str, Any]] = []
    for raw in source or []:
        if not isinstance(raw, Mapping):
            continue
        rule_id = str(raw.get("ruleId") or raw.get("rule_id") or "")
        finding_id = str(raw.get("findingId") or raw.get("finding_id") or rule_id)
        evidence = raw.get("evidence") if raw.get("evidence") is not None else raw.get("evidence_json")
        if isinstance(evidence, str):
            try:
                evidence = json.loads(evidence)
            except Exception:
                evidence = [evidence]
        result.append({
            "ruleId": rule_id,
            "findingId": finding_id,
            "severity": _severity(raw.get("severity")),
            "category": str(raw.get("category") or ""),
            "title": str(raw.get("title") or finding_id or rule_id),
            "description": str(raw.get("description") or ""),
            "evidence": _bounded(evidence or []),
        })
    result.sort(key=lambda item: (-SEVERITY_RANK[_severity(item.get("severity"))], item["findingId"], item["ruleId"]))
    return result


def _detail_row(detail: Mapping[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    identity = detail.get("identity") if isinstance(detail.get("identity"), Mapping) else {}
    researcher = detail.get("researcher") if isinstance(detail.get("researcher"), Mapping) else {}
    counts = researcher.get("findingCounts") if isinstance(researcher.get("findingCounts"), Mapping) else {}
    advisory = detail.get("advisorySummary") if isinstance(detail.get("advisorySummary"), Mapping) else {}
    severity = "none"
    for finding in findings:
        if SEVERITY_RANK[_severity(finding.get("severity"))] > SEVERITY_RANK[severity]:
            severity = _severity(finding.get("severity"))
    return {
        **dict(identity),
        "variant_id": _int(identity.get("variant_id") or identity.get("variantId")),
        "scan_id": _int(identity.get("scan_id") or identity.get("scanId")),
        "scan_status": str(identity.get("scan_status") or identity.get("status") or "unscanned"),
        "highest_severity": severity,
        "critical_count": _int(counts.get("critical")),
        "high_count": _int(counts.get("high")),
        "caution_count": _int(counts.get("caution")),
        "informational_count": _int(counts.get("informational")),
        "knownAdvisoryCount": _int(advisory.get("count")),
        "knownAdvisoryHighestSeverity": _severity(advisory.get("highestSeverity")),
        "scanned_at_utc": str(identity.get("scanned_at_utc") or detail.get("lastEvidenceUtc") or ""),
    }


def _observation_label(collection: str, row: Mapping[str, Any]) -> str:
    if collection == "staticPatternMatches":
        return f"Static marker observed: {row.get('pattern') or 'pattern'}"
    if collection == "networkEndpoints":
        return f"Network endpoint observed: {row.get('host') or row.get('url') or row.get('domain') or 'endpoint'}"
    if collection == "nativeImports":
        return f"Native import observed: {row.get('entryPoint') or row.get('name') or row.get('library') or 'native API'}"
    if collection == "dependencies":
        return f"Dependency observed: {row.get('name') or row.get('package') or row.get('id') or 'component'} {row.get('version') or ''}".strip()
    if collection == "ipcIntegrations":
        return f"IPC integration observed: {row.get('name') or row.get('endpoint') or row.get('provider') or 'IPC'}"
    if collection == "binaryClassifications":
        return f"Binary classified: {row.get('path') or row.get('name') or row.get('classification') or 'binary'}"
    if collection == "sourceFiles":
        return f"Source file retained: {row.get('path') or 'source file'}"
    if collection == "sourceAttribution":
        return "Source attribution evidence recorded"
    if collection == "sourceProvenance":
        return "Source provenance evidence recorded"
    if collection == "artifactIdentity":
        return "Artifact identity observed"
    if collection == "manifestObservation":
        return "Plugin manifest observed"
    if collection == "secondarySecurity":
        return "Secondary security-engine evidence recorded"
    return f"{collection} observation recorded"


def _timeline_event(*, variant_id: int, scan_id: int, occurred: str, event_type: str, label: str,
                    severity: str = "none", source: str = "evidence", identity: Mapping[str, Any] | None = None,
                    collection: str = "", record: Any = None, relationship: str = "") -> dict[str, Any]:
    stable = {
        "variantId": variant_id, "scanId": scan_id, "eventType": event_type,
        "collection": collection, "identity": dict(identity or {}), "record": _bounded(record),
    }
    return {
        "schema": EVENT_SCHEMA,
        "eventId": _stable_id("event", stable),
        "readOnly": True,
        "mutationAuthority": "none",
        "variantId": variant_id,
        "scanId": scan_id,
        "eventType": event_type,
        "label": label,
        "severity": _severity(severity),
        "source": source,
        "collection": collection,
        "occurredAtUtc": occurred,
        "timeBasis": "scan-evidence-time" if occurred else "unordered-retained-evidence",
        "relationship": relationship,
        "evidencePreview": _bounded(record) if record is not None else None,
    }


def project_incident_case(
    detail: Mapping[str, Any],
    observation_rows: Mapping[str, Iterable[Mapping[str, Any]]] | None = None,
    rule_projection_state: Mapping[str, Any] | None = None,
    *,
    max_observation_events: int = 250,
) -> dict[str, Any]:
    """Build the selected-asset read-only incident composition and normalized timeline."""
    findings = _finding_rows(detail)
    row = _detail_row(detail, findings)
    asset = _asset(row)
    variant_id = asset["variantId"]
    scan_id = _int(row.get("scan_id"))
    occurred = str(row.get("scanned_at_utc") or "")
    incident = _incident(row)
    researcher = detail.get("researcher") if isinstance(detail.get("researcher"), Mapping) else {}
    signals = [dict(item) for item in researcher.get("signals") or [] if isinstance(item, Mapping)]
    advisories = [dict(item) for item in detail.get("advisories") or [] if isinstance(item, Mapping)]
    projection_state = dict(rule_projection_state or {})

    timeline: list[dict[str, Any]] = []
    timeline.append(_timeline_event(
        variant_id=variant_id, scan_id=scan_id, occurred=occurred, event_type="security-analysis",
        label="Security analysis completed" if str(row.get("scan_status") or "").casefold() == "complete" else f"Security analysis {row.get('scan_status') or 'unscanned'}",
        severity=_severity(row.get("highest_severity")), source="sigmascope",
        identity={"status": str(row.get("scan_status") or ""), "scanId": scan_id},
    ))
    for finding in findings:
        timeline.append(_timeline_event(
            variant_id=variant_id, scan_id=scan_id, occurred=occurred, event_type="finding-projected",
            label=finding.get("title") or finding.get("findingId") or "Finding projected",
            severity=str(finding.get("severity") or "none"), source="legacy-projection",
            identity={"ruleId": finding.get("ruleId"), "findingId": finding.get("findingId")},
            record=finding, relationship="contributes-to-incident",
        ))
    for advisory in advisories:
        advisory_id = str(advisory.get("id") or advisory.get("advisoryId") or advisory.get("ghsaId") or advisory.get("osvId") or "")
        timeline.append(_timeline_event(
            variant_id=variant_id, scan_id=scan_id, occurred=occurred, event_type="intelligence-advisory",
            label=f"Known dependency advisory: {advisory_id or advisory.get('summary') or advisory.get('package') or 'advisory'}",
            severity=str(advisory.get("severity") or "caution"), source="intelligence",
            identity={"advisoryId": advisory_id, "package": advisory.get("package") or advisory.get("name")},
            record=advisory, relationship="enriches-incident",
        ))

    observation_counts: dict[str, int] = {}
    emitted_observations = 0
    for collection in TIMELINE_COLLECTIONS:
        rows = [dict(item) for item in (observation_rows or {}).get(collection, []) if isinstance(item, Mapping)]
        rows.sort(key=lambda item: hashlib.sha256(_canonical(item)).hexdigest())
        observation_counts[collection] = len(rows)
        for observation in rows:
            if emitted_observations >= max(0, int(max_observation_events)):
                break
            timeline.append(_timeline_event(
                variant_id=variant_id, scan_id=scan_id, occurred=occurred, event_type="observation",
                label=_observation_label(collection, observation), severity="none", source="retained-observation",
                collection=collection, identity={"recordDigest": hashlib.sha256(_canonical(observation)).hexdigest()},
                record=observation, relationship="supports-evaluation",
            ))
            emitted_observations += 1
        if emitted_observations >= max(0, int(max_observation_events)):
            break

    projection = projection_state.get("projection") if isinstance(projection_state.get("projection"), Mapping) else {}
    if projection:
        projected_findings = [dict(item) for item in projection.get("findings") or [] if isinstance(item, Mapping)]
        highest = max((_severity(item.get("severity")) for item in projected_findings), key=lambda value: SEVERITY_RANK[value], default="none")
        timeline.append(_timeline_event(
            variant_id=variant_id, scan_id=scan_id, occurred=occurred, event_type="srl-rule-reprojection",
            label=f"SRL reprojection evaluated {len(projection.get('matchedRuleIds') or [])} matched rule(s)",
            severity=highest, source="non-authoritative-srl-projection",
            identity={"projectionRevision": projection.get("projectionRevision"), "ruleSetRevision": projection.get("ruleSetRevision")},
            record={
                "projectionRevision": projection.get("projectionRevision"),
                "ruleSetRevision": projection.get("ruleSetRevision"),
                "matchedRuleIds": projection.get("matchedRuleIds") or [],
                "facts": projection.get("facts") or [],
                "findings": projected_findings,
                "productionWriteBack": bool(projection.get("productionWriteBack")),
            }, relationship="reprojects-retained-observations",
        ))
    request = projection_state.get("reanalysisRequest") if isinstance(projection_state.get("reanalysisRequest"), Mapping) else {}
    if request:
        timeline.append(_timeline_event(
            variant_id=variant_id, scan_id=scan_id, occurred=occurred, event_type="srl-reanalysis-required",
            label=str(request.get("reason") or "SRL reprojection requires additional observations"), severity="caution",
            source="non-authoritative-srl-projection", identity={"ruleSetRevision": request.get("ruleSetRevision")},
            record=request, relationship="requires-observation-refresh",
        ))

    timeline.sort(key=lambda item: (str(item.get("occurredAtUtc") or ""), str(item.get("eventId") or "")), reverse=True)
    truncated = sum(observation_counts.values()) > emitted_observations
    timeline_payload = {
        "schema": TIMELINE_SCHEMA,
        "readOnly": True,
        "mutationAuthority": "none",
        "variantId": variant_id,
        "events": timeline,
        "observationCounts": observation_counts,
        "observationEventsEmitted": emitted_observations,
        "observationEventsTruncated": truncated,
    }
    identity = {
        "variantId": variant_id, "scanId": scan_id,
        "incidentId": str((incident or {}).get("incidentId") or ""),
        "findingIds": [item["findingId"] for item in findings],
        "eventIds": [item["eventId"] for item in timeline],
        "projectionRevision": str(projection.get("projectionRevision") or ""),
        "reanalysisReason": str(request.get("reason") or ""),
    }
    return {
        "schema": CASE_SCHEMA,
        "caseProjectionId": _stable_id("case", identity),
        "readOnly": True,
        "mutationAuthority": "none",
        "authoritativeChangeBoundary": "github-permission-ci-review-normal-pr",
        "asset": asset,
        "incident": incident,
        "contributingFindings": findings,
        "contributingFindingIds": [item["findingId"] for item in findings],
        "contributingSignals": signals,
        "advisories": advisories,
        "ruleProjection": projection_state,
        "timeline": timeline_payload,
    }


def project_workbench(asset_rows: Iterable[dict[str, Any]], summary: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build deterministic read-only workbench navigation objects from asset summaries."""
    assets = [dict(row) for row in asset_rows if isinstance(row, dict) and _int(row.get("variant_id")) > 0]
    assets.sort(key=lambda row: (_int(row.get("variant_id")), _int(row.get("scan_id"))))
    incidents = [item for row in assets if (item := _incident(row)) is not None]
    incidents.sort(key=lambda item: (-SEVERITY_RANK[_severity(item.get("severity"))], str(item.get("lastEvidenceUtc") or ""), str(item.get("incidentId") or "")), reverse=False)
    events = [_event(row) for row in assets]
    events.sort(key=lambda item: (str(item.get("occurredAtUtc") or ""), str(item.get("eventId") or "")), reverse=True)
    intelligence = [item for row in assets if (item := _intelligence(row)) is not None]
    intelligence.sort(key=lambda item: (-SEVERITY_RANK[_severity(item.get("highestSeverity"))], str(item.get("intelligenceId") or "")))
    summary_counts = dict((summary or {}).get("counts") or {}) if isinstance(summary, dict) else {}
    payload_core = {
        "assets": assets,
        "incidents": incidents,
        "events": events,
        "intelligence": intelligence,
        "summaryCounts": summary_counts,
    }
    return {
        "schema": WORKBENCH_SCHEMA,
        "projectionRevision": f"deltascope-workbench-v1-{hashlib.sha256(_canonical(payload_core)).hexdigest()[:20]}",
        "readOnly": True,
        "mutationAuthority": "none",
        "authoritativeChangeBoundary": "github-permission-ci-review-normal-pr",
        "assets": assets,
        "incidents": incidents,
        "events": events,
        "intelligence": intelligence,
        "summaryCounts": summary_counts,
    }

INTELLIGENCE_CATALOG_SCHEMA = "omega.deltascope.intelligence-catalog.v1"
INTELLIGENCE_PIVOT_SCHEMA = "omega.deltascope.intelligence-pivot.v1"
ASSET_RELATIONSHIP_SCHEMA = "omega.deltascope.asset-relationship-projection.v1"


def _relation_key(kind: str, item: Mapping[str, Any]) -> str:
    if kind == "endpoint":
        return str(item.get("endpointKey") or "")
    if kind == "component":
        return str(item.get("componentKey") or "")
    if kind == "advisory":
        return "|".join((
            str(item.get("advisoryId") or ""),
            str(item.get("componentKey") or ""),
            str(item.get("affectedVersion") or ""),
        ))
    return ""


def _relation_variant_ids(kind: str, item: Mapping[str, Any]) -> list[int]:
    if kind == "endpoint":
        values = item.get("variantIds") if isinstance(item.get("variantIds"), list) else []
    elif kind == "component":
        values = [row.get("variantId") for row in item.get("usage") or [] if isinstance(row, Mapping)]
    elif kind == "advisory":
        values = [row.get("variantId") for row in item.get("affectedAssets") or [] if isinstance(row, Mapping)]
    else:
        values = []
    return sorted({_int(value) for value in values if _int(value) > 0})


def _catalog_item(kind: str, item: Mapping[str, Any]) -> dict[str, Any]:
    key = _relation_key(kind, item)
    variant_ids = _relation_variant_ids(kind, item)
    base = {
        "relationshipId": _stable_id(kind, {"key": key}),
        "kind": kind,
        "key": key,
        "variantCount": len(variant_ids),
        "variantIds": variant_ids,
    }
    if kind == "endpoint":
        return {
            **base,
            "label": str(item.get("host") or (item.get("urlSamples") or [""])[0] or key),
            "host": str(item.get("host") or ""),
            "urlSamples": list(item.get("urlSamples") or []),
            "classifications": list(item.get("classifications") or []),
            "purposes": list(item.get("purposes") or []),
            "origins": list(item.get("origins") or []),
            "pluginCount": _int(item.get("pluginCount")),
            "observations": _int(item.get("observations")),
        }
    if kind == "component":
        return {
            **base,
            "label": str(item.get("displayName") or item.get("componentKey") or "component"),
            "componentKey": str(item.get("componentKey") or ""),
            "componentKind": str(item.get("kind") or ""),
            "versions": list(item.get("versions") or []),
            "pluginCount": _int(item.get("pluginCount")),
            "versionDivergence": str(item.get("versionDivergence") or "none"),
        }
    if kind == "advisory":
        return {
            **base,
            "label": str(item.get("title") or item.get("advisoryId") or "advisory"),
            "advisoryId": str(item.get("advisoryId") or ""),
            "componentKey": str(item.get("componentKey") or ""),
            "componentName": str(item.get("componentName") or ""),
            "affectedVersion": str(item.get("affectedVersion") or ""),
            "fixedVersion": str(item.get("fixedVersion") or ""),
            "severity": _severity(item.get("severity")),
            "url": str(item.get("url") or ""),
            "source": str(item.get("source") or ""),
        }
    return base


def project_intelligence_catalog(relationship_index: Mapping[str, Any], *, limit: int = 1000) -> dict[str, Any]:
    """Project the published relationship index into a read-only DeltaScope intelligence catalog."""
    limit = min(5000, max(1, int(limit)))
    endpoints = [_catalog_item("endpoint", item) for item in relationship_index.get("endpoints") or [] if isinstance(item, Mapping)]
    components = [_catalog_item("component", item) for item in relationship_index.get("components") or [] if isinstance(item, Mapping)]
    advisories = [_catalog_item("advisory", item) for item in relationship_index.get("advisories") or [] if isinstance(item, Mapping)]
    endpoints.sort(key=lambda item: (-_int(item.get("variantCount")), str(item.get("label") or "").casefold(), str(item.get("key") or "")))
    components.sort(key=lambda item: (-_int(item.get("variantCount")), str(item.get("label") or "").casefold(), str(item.get("key") or "")))
    advisories.sort(key=lambda item: (-SEVERITY_RANK[_severity(item.get("severity"))], -_int(item.get("variantCount")), str(item.get("advisoryId") or "")))
    core = {
        "relationshipRevision": str(relationship_index.get("relationshipRevision") or ""),
        "endpoints": endpoints[:limit], "components": components[:limit], "advisories": advisories[:limit],
        "counts": dict(relationship_index.get("counts") or {}),
    }
    return {
        "schema": INTELLIGENCE_CATALOG_SCHEMA,
        "projectionRevision": _stable_id("intelligence-catalog", core),
        "readOnly": True,
        "mutationAuthority": "none",
        "policyInput": False,
        "authoritativeChangeBoundary": "github-permission-ci-review-normal-pr",
        **core,
    }


def project_intelligence_pivot(
    relationship_index: Mapping[str, Any], kind: str, key: str, asset_rows: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    """Resolve one endpoint/component/advisory intelligence object to its affected current assets."""
    kind = str(kind or "").strip().casefold()
    source_name = {"endpoint": "endpoints", "component": "components", "advisory": "advisories"}.get(kind)
    if not source_name:
        raise ValueError("intelligence pivot kind must be endpoint, component, or advisory")
    match = None
    for raw in relationship_index.get(source_name) or []:
        if isinstance(raw, Mapping) and _relation_key(kind, raw) == str(key or ""):
            match = raw
            break
    if match is None:
        raise ValueError(f"unknown {kind} intelligence key")
    ids = set(_relation_variant_ids(kind, match))
    assets = [_asset(row) for row in asset_rows if isinstance(row, dict) and _int(row.get("variant_id")) in ids]
    assets.sort(key=lambda item: (str(item.get("name") or "").casefold(), _int(item.get("variantId"))))
    relationship = _catalog_item(kind, match)
    core = {"kind": kind, "key": str(key), "relationship": relationship, "assetVariantIds": [item["variantId"] for item in assets]}
    return {
        "schema": INTELLIGENCE_PIVOT_SCHEMA,
        "pivotId": _stable_id("pivot", core),
        "readOnly": True,
        "mutationAuthority": "none",
        "policyInput": False,
        "authoritativeChangeBoundary": "github-permission-ci-review-normal-pr",
        "relationshipRevision": str(relationship_index.get("relationshipRevision") or ""),
        "relationship": relationship,
        "assets": assets,
    }



def project_asset_journey(
    detail: Mapping[str, Any], observations: Mapping[str, Any] | None = None,
    projection_state: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Reconstruct the evidence-backed path one plugin variant took through Omega security services.

    This is a read-only explanatory projection. A stage is marked complete only when retained
    evidence supports that claim; absent/optional stages remain explicit instead of being invented.
    """
    observations = observations or {}
    projection_state = projection_state or {}
    identity = detail.get("identity") if isinstance(detail.get("identity"), Mapping) else {}
    researcher = detail.get("researcher") if isinstance(detail.get("researcher"), Mapping) else {}
    coverage = detail.get("sourceCoverage") if isinstance(detail.get("sourceCoverage"), Mapping) else {}
    artifact_identity = detail.get("artifactIdentity") if isinstance(detail.get("artifactIdentity"), Mapping) else {}
    manifest = detail.get("manifestObservation") if isinstance(detail.get("manifestObservation"), Mapping) else {}
    package = detail.get("package") if isinstance(detail.get("package"), Mapping) else {}
    source_attr = detail.get("sourceAttribution") if isinstance(detail.get("sourceAttribution"), Mapping) else {}
    source_prov = detail.get("sourceProvenance") if isinstance(detail.get("sourceProvenance"), Mapping) else {}
    secondary = detail.get("secondarySecurity") if isinstance(detail.get("secondarySecurity"), Mapping) else {}
    analysis = detail.get("analysis") if isinstance(detail.get("analysis"), Mapping) else {}
    projection = projection_state.get("projection") if isinstance(projection_state.get("projection"), Mapping) else {}

    variant_id = _int(identity.get("variant_id") or identity.get("variantId"))
    scan_id = _int(identity.get("scan_id") or identity.get("scanId"))
    scan_status = str(identity.get("scan_status") or identity.get("status") or "unscanned").strip().casefold() or "unscanned"
    artifact_sha = str(identity.get("artifact_sha256") or artifact_identity.get("sha256") or artifact_identity.get("artifactSha256") or "").strip().lower()
    artifact_url = str(identity.get("artifact_url") or artifact_identity.get("url") or artifact_identity.get("artifactUrl") or "").strip()
    source_repo = str(coverage.get("repository") or source_prov.get("repository") or identity.get("source_repository") or "").strip()
    source_commit = str(coverage.get("commit") or source_prov.get("commit") or identity.get("source_commit") or "").strip()
    source_available = bool(coverage.get("sourceCodeAvailable")) or bool(source_repo)
    source_verified = bool(coverage.get("sourceToBinaryVerified") or source_prov.get("sourceToBinaryVerified"))
    findings = researcher.get("findings") if isinstance(researcher.get("findings"), list) else detail.get("findings") if isinstance(detail.get("findings"), list) else []
    capabilities = researcher.get("capabilities") if isinstance(researcher.get("capabilities"), list) else []
    endpoints = detail.get("networkEndpoints") if isinstance(detail.get("networkEndpoints"), list) else []
    components = detail.get("componentSummary") if isinstance(detail.get("componentSummary"), Mapping) else {}
    dependencies = detail.get("dependencies") if isinstance(detail.get("dependencies"), list) else []
    engines = secondary.get("engines") if isinstance(secondary.get("engines"), list) else []
    engine_matches = sum(len(item.get("matches") or []) for item in engines if isinstance(item, Mapping))

    obs_counts = {
        str(name): len(rows) for name, rows in observations.items()
        if isinstance(rows, list) and rows
    }

    def stage(key: str, title: str, status: str, summary: str, details: list[str] | None = None, *, evidence: str = "") -> dict[str, Any]:
        values = [str(item) for item in (details or []) if str(item).strip()]
        return {
            "stageId": key, "title": title, "status": status, "summary": summary,
            "details": values[:8], "evidence": evidence,
        }

    stages: list[dict[str, Any]] = []
    source_name = str(identity.get("source_name") or "").strip()
    source_url = str(identity.get("source_url") or "").strip()
    stages.append(stage(
        "catalog-discovery", "Catalog discovery", "complete" if variant_id else "unknown",
        "Plugin variant was discovered and normalized into the Omega catalog." if variant_id else "No catalog identity is retained.",
        [
            f"variant {variant_id}" if variant_id else "",
            f"source: {source_name}" if source_name else "",
            source_url,
            f"version: {identity.get('assembly_version')}" if identity.get("assembly_version") else "",
        ], evidence="variant identity",
    ))
    stages.append(stage(
        "artifact-acquisition", "Acquire installable plugin", "complete" if artifact_sha else ("failed" if scan_status == "failed" else "not-recorded"),
        "Installable artifact was acquired and pinned by SHA-256." if artifact_sha else "No retained artifact identity is available for this variant.",
        [artifact_url, f"sha256: {artifact_sha}" if artifact_sha else "", str(identity.get("artifact_channel") or "")],
        evidence="artifactIdentity",
    ))
    package_seen = bool(manifest) or bool(package)
    stages.append(stage(
        "package-inspection", "Inspect package & manifest", "complete" if package_seen else ("not-recorded" if artifact_sha else "not-run"),
        "Package structure and manifest metadata were retained for static inspection." if package_seen else "No explicit package/manifest observation is retained.",
        [
            f"manifest fields: {len(manifest)}" if manifest else "",
            f"package fields: {len(package)}" if package else "",
        ], evidence="manifestObservation · package",
    ))
    source_details = [source_repo, f"commit: {source_commit}" if source_commit else ""]
    if coverage.get("selectedRef"):
        source_details.append(f"selected ref: {coverage.get('selectedRef')}")
    if source_attr.get("confidence") is not None or coverage.get("attributionConfidence") is not None:
        source_details.append(f"attribution: {source_attr.get('confidence', coverage.get('attributionConfidence', 0))}/100")
    if source_available:
        source_details.append("source ↔ artifact: verified" if source_verified else "source ↔ artifact: not cryptographically verified")
    stages.append(stage(
        "source-attribution", "Retrieve & attribute source", "complete" if source_available else "skipped",
        "Attributed source was retrieved and retained as a separate evidence stream." if source_available else "No attributable source code was found; analysis remained artifact-only.",
        source_details, evidence="sourceAttribution · sourceProvenance",
    ))
    if scan_status == "complete":
        static_status = "complete"
        static_summary = "SigmaScope completed deterministic static analysis of the retained evidence."
    elif scan_status in {"failed", "error"}:
        static_status = "failed"
        static_summary = "SigmaScope analysis did not complete successfully."
    elif scan_id:
        static_status = "partial"
        static_summary = f"SigmaScope analysis is recorded with status {scan_status}."
    else:
        static_status = "not-run"
        static_summary = "No SigmaScope analysis is currently recorded."
    stages.append(stage(
        "sigmascope-static", "SigmaScope static analysis", static_status, static_summary,
        [
            f"scan {scan_id}" if scan_id else "",
            f"scanner: {identity.get('scanner_version')}" if identity.get("scanner_version") else "",
            f"analyzed: {identity.get('scanned_at_utc')}" if identity.get("scanned_at_utc") else "",
            f"findings: {len(findings)}",
            f"capabilities: {len(capabilities)}" if capabilities else "",
        ], evidence="scan report · retained observations",
    ))
    if engines:
        incomplete = [str(item.get("engine") or item.get("name") or "engine") for item in engines if isinstance(item, Mapping) and (item.get("available") is False or str(item.get("status") or "").casefold() not in {"complete", "ready"})]
        sec_status = "partial" if incomplete else "complete"
        sec_summary = f"{len(engines)} secondary engine(s) evaluated the artifact; {engine_matches} match(es) were retained."
        sec_details = [f"{item.get('engine') or item.get('name')}: {item.get('status') or 'unknown'} · {len(item.get('matches') or [])} matches" for item in engines if isinstance(item, Mapping)]
    else:
        sec_status, sec_summary, sec_details = "skipped", "No retained ClamAV/YARA secondary-engine result is present.", []
    stages.append(stage("secondary-engines", "Secondary security engines", sec_status, sec_summary, sec_details, evidence="secondarySecurity"))

    intelligence_total = len(endpoints) + len(dependencies) + sum(obs_counts.values())
    component_count = _int(components.get("count") or components.get("componentCount") or components.get("total")) if components else 0
    intelligence_total += component_count
    intel_details = [f"{name}: {count}" for name, count in sorted(obs_counts.items())[:6]]
    if endpoints:
        intel_details.append(f"network endpoints: {len(endpoints)}")
    if dependencies:
        intel_details.append(f"dependencies: {len(dependencies)}")
    if component_count:
        intel_details.append(f"components: {component_count}")
    stages.append(stage(
        "evidence-normalization", "Normalize observations & intelligence", "complete" if intelligence_total or scan_status == "complete" else "not-recorded",
        "Typed observations were retained for later investigation and rule evaluation." if intelligence_total else "No additional typed-observation preview is retained in this view.",
        intel_details, evidence="Evidence-v2 observation collections",
    ))

    matched_rules = projection.get("matchedRuleIds") if isinstance(projection.get("matchedRuleIds"), list) else []
    projected_findings = projection.get("findings") if isinstance(projection.get("findings"), list) else []
    if projection:
        rule_status = "complete"
        rule_summary = f"Stigma-1/SRL replay projected {len(matched_rules)} matched rule(s) and {len(projected_findings)} finding(s)."
        rule_details = [
            f"rule set: {projection_state.get('ruleSetRevision') or projection.get('ruleSetRevision') or 'unknown'}",
            f"projection: {projection.get('projectionRevision') or projection_state.get('projectionSetRevision') or 'unknown'}",
            "production write-back: enabled" if projection_state.get("productionWriteBack") else "production write-back: disabled",
        ]
    elif projection_state.get("available"):
        rule_status = "skipped"
        rule_summary = "A Stigma-1 projection set is available, but this variant has no retained projection entry."
        rule_details = [f"rule set: {projection_state.get('ruleSetRevision') or 'unknown'}"]
    else:
        rule_status = "not-recorded"
        rule_summary = "No retained Stigma-1/SRL projection sidecar is available for this evidence snapshot."
        rule_details = []
    stages.append(stage("stigma-rules", "Stigma-1 / SRL rules", rule_status, rule_summary, rule_details, evidence="rule-projections"))

    deep_request = projection_state.get("analysisRequest") if isinstance(projection_state.get("analysisRequest"), Mapping) else {}
    reanalysis = projection_state.get("reanalysisRequest") if isinstance(projection_state.get("reanalysisRequest"), Mapping) else {}
    if deep_request:
        deep_status = "requested"
        deep_summary = "A frozen rule requested deeper evidence acquisition for this variant."
        deep_details = [
            f"profile: {deep_request.get('profile') or 'unknown'}",
            f"depth: {deep_request.get('depth') or 'standard'}",
            f"compare with: {deep_request.get('compareWith') or '—'}",
            f"rule: {deep_request.get('ruleId') or '—'}",
            str(deep_request.get("reason") or ""),
        ]
    elif reanalysis:
        deep_status = "needs-evidence"
        deep_summary = "Rule replay requires additional retained observations before exact evaluation is possible."
        deep_details = [str(reanalysis.get("reason") or ""), f"rule set: {reanalysis.get('ruleSetRevision') or 'unknown'}"]
    else:
        deep_status, deep_summary, deep_details = "not-requested", "No deep-scan or targeted reanalysis request is retained for this variant.", []
    stages.append(stage("deep-analysis", "Deep / targeted analysis", deep_status, deep_summary, deep_details, evidence="analysisRequests · reanalysisRequests"))

    publication_details = []
    if analysis.get("path"):
        publication_details.append(f"analysis: {analysis.get('path')}")
    if detail.get("snapshotKind"):
        publication_details.append(f"snapshot: {detail.get('snapshotKind')}")
    if detail.get("lifecycle") and isinstance(detail.get("lifecycle"), Mapping):
        publication_details.append(f"lifecycle: {detail.get('lifecycle', {}).get('state') or 'active'}")
    stages.append(stage(
        "evidence-publication", "Publish Security Evidence v2", "complete" if (scan_id or analysis) else "not-recorded",
        "Immutable/derived evidence was published for downstream consumers and investigation." if (scan_id or analysis) else "No published Evidence-v2 analysis reference is retained.",
        publication_details, evidence="Security Evidence v2",
    ))
    stages.append(stage(
        "deltascope-view", "DeltaScope investigation", "current",
        "You are viewing the read-only reconstruction of this plugin's path through the security system.",
        ["No production mutation authority", "Stages are reconstructed from retained evidence only"], evidence="DeltaScope",
    ))

    core = {
        "variantId": variant_id, "scanId": scan_id,
        "stages": [{k: v for k, v in item.items() if k != "evidence"} for item in stages],
    }
    return {
        "schema": JOURNEY_SCHEMA, "journeyProjectionId": _stable_id("journey", core),
        "readOnly": True, "mutationAuthority": "none",
        "authoritativeChangeBoundary": "github-permission-ci-review-normal-pr",
        "variantId": variant_id, "scanId": scan_id, "asset": _asset(dict(identity)),
        "stageCount": len(stages), "stages": stages,
    }

def project_asset_relationships(
    relationship_index: Mapping[str, Any], variant_id: int, asset_row: Mapping[str, Any],
) -> dict[str, Any]:
    """Build one plugin/variant relationship graph from read-only published ecosystem relationships."""
    variant_id = _int(variant_id)
    if variant_id <= 0:
        raise ValueError("variant_id is required")
    asset = _asset(dict(asset_row))
    endpoints = [_catalog_item("endpoint", item) for item in relationship_index.get("endpoints") or [] if isinstance(item, Mapping) and variant_id in _relation_variant_ids("endpoint", item)]
    components = [_catalog_item("component", item) for item in relationship_index.get("components") or [] if isinstance(item, Mapping) and variant_id in _relation_variant_ids("component", item)]
    advisories = [_catalog_item("advisory", item) for item in relationship_index.get("advisories") or [] if isinstance(item, Mapping) and variant_id in _relation_variant_ids("advisory", item)]
    endpoints.sort(key=lambda item: str(item.get("label") or "").casefold())
    components.sort(key=lambda item: str(item.get("label") or "").casefold())
    advisories.sort(key=lambda item: (-SEVERITY_RANK[_severity(item.get("severity"))], str(item.get("advisoryId") or "")))

    plugin_id = _int(asset_row.get("plugin_id") or asset.get("pluginId"))
    artifact_sha = str(asset_row.get("artifact_sha256") or "").strip().lower()
    source_repo = str(asset_row.get("source_repository") or asset_row.get("source_code_repository") or asset.get("sourceUrl") or "").strip()
    nodes: list[dict[str, Any]] = [
        {"nodeId": f"plugin:{plugin_id}", "kind": "plugin", "label": asset.get("name") or asset.get("internalName") or f"plugin {plugin_id}"},
        {"nodeId": f"variant:{variant_id}", "kind": "variant", "label": asset.get("version") or f"variant {variant_id}"},
    ]
    edges: list[dict[str, Any]] = [{"from": f"plugin:{plugin_id}", "to": f"variant:{variant_id}", "relationship": "has-variant"}]
    if artifact_sha:
        nodes.append({"nodeId": f"artifact:{artifact_sha}", "kind": "artifact", "label": artifact_sha})
        edges.append({"from": f"variant:{variant_id}", "to": f"artifact:{artifact_sha}", "relationship": "analyzed-from-artifact"})
    if source_repo:
        source_id = hashlib.sha256(source_repo.encode("utf-8")).hexdigest()[:20]
        nodes.append({"nodeId": f"source:{source_id}", "kind": "source", "label": source_repo})
        edges.append({"from": f"variant:{variant_id}", "to": f"source:{source_id}", "relationship": "attributed-to-source"})
    for item in components:
        node = f"component:{hashlib.sha256(str(item['key']).encode('utf-8')).hexdigest()[:20]}"
        nodes.append({"nodeId": node, "kind": "component", "label": item.get("label"), "key": item.get("key")})
        edges.append({"from": f"variant:{variant_id}", "to": node, "relationship": "uses-component"})
    for item in endpoints:
        node = f"endpoint:{hashlib.sha256(str(item['key']).encode('utf-8')).hexdigest()[:20]}"
        nodes.append({"nodeId": node, "kind": "endpoint", "label": item.get("label"), "key": item.get("key")})
        edges.append({"from": f"variant:{variant_id}", "to": node, "relationship": "observes-endpoint"})
    for item in advisories:
        node = f"advisory:{hashlib.sha256(str(item['key']).encode('utf-8')).hexdigest()[:20]}"
        nodes.append({"nodeId": node, "kind": "advisory", "label": item.get("advisoryId") or item.get("label"), "key": item.get("key")})
        component_node = f"component:{hashlib.sha256(str(item.get('componentKey') or '').encode('utf-8')).hexdigest()[:20]}"
        if any(n.get("nodeId") == component_node for n in nodes):
            edges.append({"from": node, "to": component_node, "relationship": "affects-component"})
        else:
            edges.append({"from": f"variant:{variant_id}", "to": node, "relationship": "affected-by-advisory"})

    core = {
        "variantId": variant_id, "relationshipRevision": str(relationship_index.get("relationshipRevision") or ""),
        "endpointKeys": [item["key"] for item in endpoints], "componentKeys": [item["key"] for item in components],
        "advisoryKeys": [item["key"] for item in advisories], "nodes": nodes, "edges": edges,
    }
    return {
        "schema": ASSET_RELATIONSHIP_SCHEMA,
        "relationshipProjectionId": _stable_id("asset-rel", core),
        "readOnly": True,
        "mutationAuthority": "none",
        "policyInput": False,
        "authoritativeChangeBoundary": "github-permission-ci-review-normal-pr",
        "asset": asset,
        "relationshipRevision": core["relationshipRevision"],
        "endpoints": endpoints,
        "components": components,
        "advisories": advisories,
        "graph": {"nodes": nodes, "edges": edges},
    }


def relationship_variant_ids(relationship_index: Mapping[str, Any], kind: str, key: str) -> list[int]:
    """Return current variant IDs behind one relationship key for a lazy read-only pivot."""
    kind = str(kind or "").strip().casefold()
    source_name = {"endpoint": "endpoints", "component": "components", "advisory": "advisories"}.get(kind)
    if not source_name:
        raise ValueError("intelligence pivot kind must be endpoint, component, or advisory")
    for item in relationship_index.get(source_name) or []:
        if isinstance(item, Mapping) and _relation_key(kind, item) == str(key or ""):
            return _relation_variant_ids(kind, item)
    raise ValueError(f"unknown {kind} intelligence key")

RULE_CATALOG_SCHEMA = "omega.deltascope.active-rule-catalog.v1"
REPORT_CATALOG_SCHEMA = "omega.deltascope.report-catalog.v1"
SYSTEM_STATUS_SCHEMA = "omega.deltascope.system-status.v1"


def project_rule_catalog(provenance: Mapping[str, Any] | None) -> dict[str, Any]:
    """Project exact frozen Definitions provenance into a read-only active-rule browser."""
    provenance = provenance if isinstance(provenance, Mapping) else {}
    available = bool(provenance.get("available", True) and provenance.get("provenanceRevision"))
    srl = provenance.get("srl") if isinstance(provenance.get("srl"), Mapping) else {}
    definitions = provenance.get("definitions") if isinstance(provenance.get("definitions"), Mapping) else {}
    packs: list[dict[str, Any]] = []
    for raw in provenance.get("packs") or []:
        if not isinstance(raw, Mapping):
            continue
        fixtures = [dict(item) for item in raw.get("fixtures") or [] if isinstance(item, Mapping)]
        rules = [dict(item) for item in raw.get("rules") or [] if isinstance(item, Mapping)]
        review = (raw.get("metadata") or {}).get("review") if isinstance(raw.get("metadata"), Mapping) else {}
        packs.append({
            "packId": str(raw.get("packId") or ""),
            "title": str(raw.get("title") or raw.get("packId") or ""),
            "description": str(raw.get("description") or ""),
            "trustTier": str(raw.get("trustTier") or ""),
            "productionEligible": bool(raw.get("productionEligible")),
            "packRevision": str(raw.get("packRevision") or ""),
            "review": dict(review) if isinstance(review, Mapping) else {},
            "fixtureCount": len(fixtures),
            "fixturesPassed": sum(bool(item.get("passed")) for item in fixtures),
            "fixtures": fixtures,
            "rules": rules,
        })
    packs.sort(key=lambda item: item["packId"])
    rules = [dict(item) for item in provenance.get("activeRules") or [] if isinstance(item, Mapping)]
    rules.sort(key=lambda item: str(item.get("ruleId") or ""))
    parity = srl.get("migrationParity") if isinstance(srl.get("migrationParity"), Mapping) else {}
    core = {
        "available": available,
        "provenanceRevision": str(provenance.get("provenanceRevision") or ""),
        "definitions": dict(definitions),
        "srl": dict(srl),
        "packs": packs,
        "rules": rules,
        "migrationParity": dict(parity),
    }
    return {
        "schema": RULE_CATALOG_SCHEMA,
        "projectionRevision": _stable_id("rule-catalog", core),
        "readOnly": True,
        "mutationAuthority": "none",
        "policyInput": False,
        "authoritativeChangeBoundary": "github-permission-ci-review-normal-pr",
        **core,
    }


def project_reports(
    workbench: Mapping[str, Any] | None,
    summary: Mapping[str, Any] | None,
    system_context: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Create deterministic operational reports without writing report state anywhere."""
    workbench = workbench if isinstance(workbench, Mapping) else {}
    summary = summary if isinstance(summary, Mapping) else {}
    system_context = system_context if isinstance(system_context, Mapping) else {}
    counts = summary.get("counts") if isinstance(summary.get("counts"), Mapping) else {}
    projections = system_context.get("ruleProjections") if isinstance(system_context.get("ruleProjections"), Mapping) else {}
    projection_counts = projections.get("counts") if isinstance(projections.get("counts"), Mapping) else {}
    queue = system_context.get("queue") if isinstance(system_context.get("queue"), Mapping) else {}
    queue_summary = queue.get("summary") if isinstance(queue.get("summary"), Mapping) else {}
    queue_states = queue_summary.get("states") if isinstance(queue_summary.get("states"), Mapping) else {}
    incidents = [item for item in workbench.get("incidents") or [] if isinstance(item, Mapping)]
    assets = [item for item in workbench.get("assets") or [] if isinstance(item, Mapping)]
    reports = [
        {
            "reportId": "coverage",
            "title": "Security coverage",
            "status": "attention" if _int(counts.get("failedScans")) or _int(counts.get("unscannedVariantsPending")) else "ok",
            "metrics": {
                "currentVariants": _int(counts.get("variants") or len(assets)),
                "completeScans": _int(counts.get("completeScans")),
                "failedScans": _int(counts.get("failedScans")),
                "unscannedVariantsPending": _int(counts.get("unscannedVariantsPending")),
                "incidentCount": len(incidents),
                "reviewVariants": _int(counts.get("reviewVariants")),
            },
        },
        {
            "reportId": "srl-reprojection",
            "title": "SRL reprojection readiness",
            "status": "gated" if not bool(projections.get("productionRuleEvaluationEnabled")) else "active",
            "metrics": {
                "checkedVariants": _int(projection_counts.get("checkedVariants")),
                "reprojectedVariants": _int(projection_counts.get("reprojectedVariants")),
                "reanalysisRequiredVariants": _int(projection_counts.get("reanalysisRequiredVariants")),
                "auditErrorVariants": _int(projection_counts.get("auditErrorVariants")),
            },
            "ruleSetRevision": str(projections.get("ruleSetRevision") or ""),
            "projectionSetRevision": str(projections.get("projectionSetRevision") or ""),
            "productionWriteBack": bool(projections.get("productionWriteBack")),
        },
        {
            "reportId": "queue",
            "title": "Analysis queue",
            "status": "attention" if _int(queue_states.get("retry")) else "ok",
            "metrics": {
                "total": _int(queue_summary.get("total")),
                "pending": _int(queue_states.get("pending")),
                "retry": _int(queue_states.get("retry")),
                "complete": _int(queue_states.get("complete")),
                "coveredWorkPending": _int(queue_summary.get("coveredWorkPending")),
            },
        },
    ]
    core = {
        "reports": reports,
        "evidenceRevision": str(((system_context.get("evidence") or {}).get("revisions") or {}).get("evidenceRevision") or ""),
        "generatedAtUtc": str(system_context.get("generatedAtUtc") or summary.get("generatedAtUtc") or ""),
    }
    return {
        "schema": REPORT_CATALOG_SCHEMA,
        "projectionRevision": _stable_id("reports", core),
        "readOnly": True,
        "mutationAuthority": "none",
        "authoritativeChangeBoundary": "github-permission-ci-review-normal-pr",
        **core,
    }


def project_system_status(
    system_context: Mapping[str, Any] | None,
    provenance: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Project revision/pipeline health for DeltaScope System without control-plane actions."""
    context = system_context if isinstance(system_context, Mapping) else {}
    provenance = provenance if isinstance(provenance, Mapping) else {}
    evidence = context.get("evidence") if isinstance(context.get("evidence"), Mapping) else {}
    projections = context.get("ruleProjections") if isinstance(context.get("ruleProjections"), Mapping) else {}
    provenance_meta = context.get("definitionProvenance") if isinstance(context.get("definitionProvenance"), Mapping) else {}
    checks: list[dict[str, Any]] = []

    def check(code: str, label: str, status: str, detail: str) -> None:
        checks.append({"code": code, "label": label, "status": status, "detail": detail})

    check("evidence.root", "Evidence-v2 root", "pass" if evidence.get("schema") == "omega.security-evidence.v2" else "warn", str(evidence.get("schema") or "unavailable"))
    check("definitions.provenance", "Frozen Definitions provenance", "pass" if provenance_meta.get("available") else "warn", str(provenance_meta.get("provenanceRevision") or "not published in this snapshot"))
    check("srl.production", "Production SRL evaluation", "active" if projections.get("productionRuleEvaluationEnabled") else "gated", "enabled" if projections.get("productionRuleEvaluationEnabled") else "disabled pending corpus cutover review")
    check("srl.writeback", "SRL production write-back", "fail" if projections.get("productionWriteBack") else "pass", "must remain disabled during migration")
    check("queue.authority", "Reprojection queue mutation", "fail" if projections.get("queueMutationAuthorized") else "pass", "DeltaScope/reprojection sidecar has no queue authority")
    revisions = evidence.get("revisions") if isinstance(evidence.get("revisions"), Mapping) else {}
    defs = provenance.get("definitions") if isinstance(provenance.get("definitions"), Mapping) else {}
    srl = provenance.get("srl") if isinstance(provenance.get("srl"), Mapping) else {}
    core = {
        "generatedAtUtc": str(context.get("generatedAtUtc") or ""),
        "engine": dict(context.get("engine") or {}) if isinstance(context.get("engine"), Mapping) else {},
        "revisions": {
            "evidenceRevision": str(revisions.get("evidenceRevision") or ""),
            "securityRevision": str(revisions.get("securityRevision") or ""),
            "catalogRevision": str(revisions.get("catalogRevision") or ""),
            "definitionsRevision": str(defs.get("definitionsRevision") or (context.get("source") or {}).get("definitionsRevision") or ""),
            "scannerRevision": str(defs.get("scannerRevision") or ""),
            "artifactAnalysisRevision": str(defs.get("artifactAnalysisRevision") or (context.get("source") or {}).get("artifactAnalysisRevision") or ""),
            "sourceAnalysisRevision": str(defs.get("sourceAnalysisRevision") or (context.get("source") or {}).get("sourceAnalysisRevision") or ""),
            "legacyRuleSetRevision": str(defs.get("legacyRuleSetRevision") or ""),
            "srlRuleSetRevision": str(srl.get("ruleSetRevision") or projections.get("ruleSetRevision") or ""),
            "definitionPackRevision": str(srl.get("definitionPackRevision") or ""),
            "projectionSetRevision": str(projections.get("projectionSetRevision") or ""),
            "relationshipRevision": str((context.get("relationshipIndex") or {}).get("relationshipRevision") or ""),
        },
        "queue": dict(context.get("queue") or {}) if isinstance(context.get("queue"), Mapping) else {},
        "checks": checks,
        "publication": dict(evidence.get("publication") or {}) if isinstance(evidence.get("publication"), Mapping) else {},
    }
    return {
        "schema": SYSTEM_STATUS_SCHEMA,
        "projectionRevision": _stable_id("system", core),
        "readOnly": True,
        "mutationAuthority": "none",
        "authoritativeChangeBoundary": "github-permission-ci-review-normal-pr",
        **core,
    }
