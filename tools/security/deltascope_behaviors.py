#!/usr/bin/env python3
"""Read-only plugin behavior/evidence projection for DeltaScope.

The plugin dossier is organised both by evidence origin (Network, Code & native, Supply)
and by observed behavior.  This module supplies the latter from the same matched-row
lineage projection used by the finding-lineage drawer.  It does not infer runtime behavior,
change findings, or create security authority.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable, Mapping, Sequence

import deltascope_finding_lineage

SCHEMA = "omega.deltascope.plugin-behaviors.v1"
PIVOT_EVIDENCE_SCHEMA = "omega.deltascope.pivot-evidence.v1"
MAX_BEHAVIORS = 120
MAX_ROWS_PER_BEHAVIOR = 16
MAX_PIVOT_ROWS_PER_ASSET = 8


def _text(value: Any) -> str:
    return str(value or "").strip()


def _int(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _stable_id(prefix: str, value: Any) -> str:
    return f"{prefix}-{hashlib.sha256(_canonical(value)).hexdigest()[:20]}"


def _identity(detail: Mapping[str, Any]) -> dict[str, Any]:
    row = detail.get("identity") if isinstance(detail.get("identity"), Mapping) else {}
    return {
        "variantId": _int(row.get("variant_id") or row.get("variantId")),
        "pluginId": _int(row.get("plugin_id") or row.get("pluginId")),
        "name": _text(row.get("canonical_name") or row.get("name") or row.get("internal_name") or row.get("internalName")),
        "internalName": _text(row.get("internal_name") or row.get("internalName")),
        "version": _text(row.get("assembly_version") or row.get("version")),
        "scanId": _int(row.get("scan_id") or row.get("scanId")),
        "scannedAtUtc": _text(row.get("scanned_at_utc") or row.get("scannedAtUtc")),
    }


def _flatten(value: Any) -> list[str]:
    out: list[str] = []
    if isinstance(value, Mapping):
        for key in sorted(value, key=lambda item: str(item)):
            out.extend(_flatten(value.get(key)))
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            out.extend(_flatten(item))
    elif value is not None:
        text = _text(value)
        if text:
            out.append(text)
    return out


def _managed_location(row: Mapping[str, Any]) -> str:
    declaring = _text(row.get("sourceDeclaringType"))
    method = _text(row.get("sourceMethodName"))
    location = ".".join(item for item in (declaring, method) if item)
    offset = row.get("ilOffset")
    if offset not in (None, ""):
        try:
            location += f"+0x{int(offset):x}"
        except (TypeError, ValueError):
            location += f"+{offset}"
    return location


def _observed_value(collection: str, row: Mapping[str, Any], label: str, detail: str) -> str:
    # Put the datum a researcher is looking for first.  Source-location fields are kept
    # separately so a file path / URL / symbol is not buried inside an opaque evidence id.
    ordered_keys = (
        "url", "uri", "endpoint", "host", "literal", "literalValue", "stringValue",
        "value", "pathValue", "externalPath", "targetPath", "operand", "argument",
        "target", "pattern", "evidenceLabel",
    )
    if collection == "managedCallSites":
        target_type = _text(row.get("targetDeclaringType"))
        target_name = _text(row.get("targetName"))
        target = ".".join(item for item in (target_type, target_name) if item)
        # Literal-bearing callsite rows may also publish the actual argument. Prefer it.
        for key in ("argument", "operand", "literal", "literalValue", "stringValue", "value", "pathValue", "url"):
            value = _text(row.get(key))
            if value:
                return value
        if target:
            return target
    if collection == "nativeImports":
        library = _text(row.get("library") or row.get("targetNativeLibrary"))
        entry = _text(row.get("entryPoint") or row.get("targetNativeEntryPoint"))
        value = "!".join(item for item in (library, entry) if item)
        if value:
            return value
    for key in ordered_keys:
        value = row.get(key)
        if isinstance(value, (str, int, float)) and _text(value):
            return _text(value)
    evidence = _flatten(row.get("evidence"))
    if evidence:
        return evidence[0]
    return _text(label) or _text(detail) or collection


def _evidence_kind(collection: str, item_kind: str) -> str:
    if item_kind:
        return item_kind
    return {
        "managedCallSites": "il",
        "staticPatternMatches": "metadata",
        "networkEndpoints": "endpoint",
        "nativeImports": "native",
        "manifestObservation": "manifest",
        "dependencies": "component",
    }.get(collection, collection or "evidence")


def normalize_lineage_evidence(item: Mapping[str, Any], *, finding: Mapping[str, Any], detail: Mapping[str, Any]) -> dict[str, Any]:
    collection = _text(item.get("collection")) or "findingEvidence"
    row = item.get("row") if isinstance(item.get("row"), Mapping) else {}
    row = dict(row) if isinstance(row, Mapping) else {}
    label = _text(item.get("label"))
    detail_text = _text(item.get("detail"))
    location = ""
    if collection == "managedCallSites":
        location = _managed_location(row) or label
    elif collection == "staticPatternMatches":
        location = _text(row.get("path") or row.get("memberPath"))
    elif collection == "nativeImports":
        location = _text(row.get("path") or row.get("assembly") or row.get("sourceAssembly"))
    elif collection == "networkEndpoints":
        location = _text(row.get("path") or row.get("originPath") or row.get("source"))
    else:
        location = _text(row.get("path") or row.get("memberPath") or row.get("sourcePath"))
    value = _observed_value(collection, row, label, detail_text)
    source_line = row.get("sourceLine") or row.get("line") or row.get("lineNumber")
    source_file = _text(row.get("sourceFile") or row.get("file") or row.get("sourcePath"))
    source_coverage = detail.get("sourceCoverage") if isinstance(detail.get("sourceCoverage"), Mapping) else {}
    if source_file and source_line not in (None, ""):
        source_note = f"{source_file}:{source_line}"
    elif source_file:
        source_note = source_file
    elif bool(source_coverage.get("sourceCodeAvailable")):
        source_note = "source available; no exact source line mapped to this retained row"
    else:
        source_note = "not available (artifact-only evidence)"
    rule_id = _text(finding.get("ruleId") or finding.get("rule_id"))
    finding_id = _text(finding.get("findingId") or finding.get("finding_id"))
    evidence_id = _stable_id("behavior-evidence", {
        "collection": collection, "index": item.get("index"), "row": row or item.get("row"),
        "ruleId": rule_id, "findingId": finding_id,
    })
    return {
        "evidenceId": evidence_id,
        "kind": _evidence_kind(collection, _text(item.get("kind"))),
        "collection": collection,
        "index": item.get("index"),
        "location": location,
        "value": value,
        "label": label or value,
        "detail": detail_text,
        "ruleId": rule_id,
        "findingId": finding_id,
        "confidence": _text(finding.get("confidence") or finding.get("confidenceLabel") or "retained"),
        "source": _text(item.get("source")),
        "sourceLocation": source_note,
        "totalRows": _int(item.get("totalRows")),
        "completeness": _text(item.get("completeness")),
        "row": row if row else item.get("row"),
    }


def _finding_rows(detail: Mapping[str, Any]) -> list[dict[str, Any]]:
    researcher = detail.get("researcher") if isinstance(detail.get("researcher"), Mapping) else {}
    return [dict(row) for row in researcher.get("findings") or [] if isinstance(row, Mapping)][:MAX_BEHAVIORS]


def _capability_rows(detail: Mapping[str, Any]) -> list[dict[str, Any]]:
    researcher = detail.get("researcher") if isinstance(detail.get("researcher"), Mapping) else {}
    values: list[dict[str, Any]] = []
    for raw in researcher.get("capabilities") or []:
        if isinstance(raw, Mapping):
            key = _text(raw.get("capabilityId") or raw.get("capability_id") or raw.get("id") or raw.get("name") or raw.get("label"))
            label = _text(raw.get("label") or raw.get("name") or raw.get("capability") or key)
            if key or label:
                values.append({"key": key or label, "label": label or key, "raw": dict(raw)})
        elif _text(raw):
            values.append({"key": _text(raw), "label": _text(raw), "raw": raw})
    for raw in researcher.get("capabilityIds") or []:
        key = _text(raw)
        if key and not any(_text(item.get("key")).casefold() == key.casefold() for item in values):
            values.append({"key": key, "label": key, "raw": raw})
    return values


def _matches_text(value: Any, needle: str) -> bool:
    if not needle:
        return True
    return needle.casefold() in " ".join(_flatten(value)).casefold()


def _behavior_matches_pivot(group: Mapping[str, Any], kind: str, key: str) -> bool:
    kind = _text(kind).casefold()
    key = _text(key)
    if not kind or not key:
        return True
    if kind in {"behavior", "capability"}:
        aliases = {
            _text(group.get("behaviorKey")).casefold(), _text(group.get("ruleId")).casefold(),
            _text(group.get("findingId")).casefold(), _text(group.get("title")).casefold(),
        }
        return key.casefold() in aliases or any(key.casefold() in alias for alias in aliases if alias)
    if kind in {"endpoint", "component", "advisory", "evidence"}:
        return _matches_text(group, key)
    # Family/author pivots describe a relationship rather than one behavior. Keep the full
    # behavior list visible and let the context banner explain the relationship axis.
    return kind in {"family", "author"}


def project_plugin_behaviors(
    detail: Mapping[str, Any], observations: Mapping[str, Sequence[Mapping[str, Any]]], provenance: Mapping[str, Any],
    projection_state: Mapping[str, Any] | None = None, system_context: Mapping[str, Any] | None = None,
    *, pivot_kind: str = "", pivot_key: str = "", pivot_label: str = "",
) -> dict[str, Any]:
    identity = _identity(detail)
    groups: list[dict[str, Any]] = []
    seen_keys: set[str] = set()
    for finding in _finding_rows(detail):
        fid = _text(finding.get("findingId") or finding.get("finding_id"))
        rid = _text(finding.get("ruleId") or finding.get("rule_id"))
        try:
            lineage = deltascope_finding_lineage.project_finding_lineage(
                detail, observations, provenance, projection_state or {}, system_context or {},
                finding_id=fid, rule_id=rid,
            )
            narrative = lineage.get("narrative") if isinstance(lineage.get("narrative"), Mapping) else {}
            found = narrative.get("whatWasFound") if isinstance(narrative.get("whatWasFound"), Mapping) else {}
            triggering = [normalize_lineage_evidence(item, finding=finding, detail=detail) for item in found.get("triggeringEvidence") or [] if isinstance(item, Mapping)]
            trace = narrative.get("whyItWasFound") if isinstance(narrative.get("whyItWasFound"), Mapping) else {}
        except (KeyError, TypeError, ValueError):
            triggering = []
            trace = {}
        behavior_key = rid or fid or _text(finding.get("category")) or _text(finding.get("title"))
        group = {
            "behaviorId": _stable_id("behavior", {"variantId": identity["variantId"], "key": behavior_key, "finding": fid}),
            "behaviorKey": behavior_key,
            "title": _text(finding.get("title") or behavior_key or "Observed behavior"),
            "description": _text(finding.get("description")),
            "severity": _text(finding.get("severity") or "none").casefold(),
            "category": _text(finding.get("category")),
            "ruleId": rid,
            "findingId": fid,
            "ruleRevision": _text(trace.get("ruleRevision")),
            "ruleRelationship": _text(trace.get("relationship")),
            "evidenceRows": triggering[:MAX_ROWS_PER_BEHAVIOR],
            "evidenceRowCount": len(triggering),
            "evidenceMapping": "matched-retained-rows" if triggering else "no-specific-row-mapped",
            "note": "" if triggering else "The behavior/finding is published, but no individual retained observation row was mapped into this projection.",
        }
        group["pivotMatch"] = _behavior_matches_pivot(group, pivot_kind, pivot_key)
        groups.append(group)
        seen_keys.update(item.casefold() for item in (behavior_key, rid, fid, group["title"]) if item)

    # Capabilities may exist without a finding row. Keep those visible instead of implying that
    # absence from the finding list means absence of the capability.
    for cap in _capability_rows(detail):
        key = _text(cap.get("key"))
        label = _text(cap.get("label") or key)
        if not key and not label:
            continue
        if (key and key.casefold() in seen_keys) or (label and label.casefold() in seen_keys):
            continue
        group = {
            "behaviorId": _stable_id("capability", {"variantId": identity["variantId"], "key": key or label}),
            "behaviorKey": key or label,
            "title": label or key,
            "description": "Observed capability published in the current plugin summary.",
            "severity": "none",
            "category": "capability",
            "ruleId": "",
            "findingId": "",
            "ruleRevision": "",
            "ruleRelationship": "capability-summary",
            "evidenceRows": [],
            "evidenceRowCount": 0,
            "evidenceMapping": "collection-or-summary-derived",
            "note": "Capability is present in the compact summary; this snapshot does not publish a specific matched callsite for it.",
            "rawCapability": cap.get("raw"),
        }
        group["pivotMatch"] = _behavior_matches_pivot(group, pivot_kind, pivot_key)
        groups.append(group)

    matched = [group for group in groups if group.get("pivotMatch")]
    return {
        "schema": SCHEMA,
        "readOnly": True,
        "mutationAuthority": "none",
        "policyInput": False,
        "identity": identity,
        "pivotContext": {
            "kind": _text(pivot_kind), "key": _text(pivot_key), "label": _text(pivot_label),
            "active": bool(_text(pivot_kind) and _text(pivot_key)),
            "matchedBehaviors": len(matched), "totalBehaviors": len(groups),
        },
        "behaviors": groups,
        "visibleBehaviors": matched if pivot_kind and pivot_key else groups,
        "counts": {
            "behaviors": len(groups),
            "visible": len(matched if pivot_kind and pivot_key else groups),
            "evidenceRows": sum(_int(group.get("evidenceRowCount")) for group in groups),
        },
        "note": "Behavior evidence is a read-only presentation over retained finding-lineage rows. It does not create new scanner observations or runtime claims.",
    }


def _direct_pivot_rows(detail: Mapping[str, Any], kind: str, key: str) -> list[dict[str, Any]]:
    kind = _text(kind).casefold()
    key_cf = _text(key).casefold()
    result: list[dict[str, Any]] = []
    if kind == "endpoint":
        for row in detail.get("networkEndpoints") or []:
            if not isinstance(row, Mapping) or not _matches_text(row, key_cf):
                continue
            value = _text(row.get("url") or row.get("host") or key)
            result.append({"kind": "endpoint", "collection": "networkEndpoints", "location": _text(row.get("originPath") or row.get("path")), "value": value, "detail": _text(row.get("classification") or row.get("purpose") or "retained endpoint"), "row": dict(row)})
    elif kind == "component":
        summary = detail.get("componentSummary") if isinstance(detail.get("componentSummary"), Mapping) else {}
        if _matches_text(summary, key_cf):
            result.append({
                "kind": "component", "collection": "componentSummary",
                "location": _text((detail.get("identity") or {}).get("internal_name") if isinstance(detail.get("identity"), Mapping) else ""),
                "value": _text(key), "detail": "component/reference relationship retained for this plugin",
                "row": dict(summary),
            })
    elif kind == "advisory":
        for row in detail.get("advisories") or []:
            if not isinstance(row, Mapping) or not _matches_text(row, key_cf):
                continue
            result.append({"kind": "advisory", "collection": "advisories", "location": _text(row.get("component") or row.get("package") or row.get("name")), "value": _text(row.get("advisoryId") or row.get("id") or key), "detail": _text(row.get("summary") or row.get("fixedVersion") or "frozen advisory relationship"), "row": dict(row)})
    elif kind in {"family", "author"}:
        identity = detail.get("identity") if isinstance(detail.get("identity"), Mapping) else {}
        coverage = detail.get("sourceCoverage") if isinstance(detail.get("sourceCoverage"), Mapping) else {}
        value = _text(coverage.get("repository") or identity.get("source_repository") or identity.get("source_url") or key)
        result.append({"kind": "source-lineage" if kind == "family" else "author", "collection": "catalogIdentity", "location": _text(identity.get("internal_name") or identity.get("canonical_name")), "value": value if kind == "family" else _text(identity.get("author") or key), "detail": "catalog/source identity retained for this plugin", "row": {"repository": value, "author": _text(identity.get("author"))}})
    return result[:MAX_PIVOT_ROWS_PER_ASSET]


def project_pivot_asset_evidence(detail: Mapping[str, Any], behavior_projection: Mapping[str, Any], *, kind: str, key: str) -> dict[str, Any]:
    identity = _identity(detail)
    rows: list[dict[str, Any]] = []
    groups = [dict(group) for group in behavior_projection.get("visibleBehaviors") or [] if isinstance(group, Mapping)]
    for group in groups:
        for row in group.get("evidenceRows") or []:
            if isinstance(row, Mapping):
                item = dict(row)
                item["behaviorKey"] = _text(group.get("behaviorKey"))
                item["behaviorTitle"] = _text(group.get("title"))
                item["severity"] = _text(group.get("severity"))
                rows.append(item)
    if not rows:
        rows.extend(_direct_pivot_rows(detail, kind, key))
    return {
        "variantId": identity["variantId"], "pluginId": identity["pluginId"], "name": identity["name"],
        "internalName": identity["internalName"], "version": identity["version"],
        "evidenceRows": rows[:MAX_PIVOT_ROWS_PER_ASSET], "evidenceRowCount": len(rows),
        "behaviorCount": len(groups),
    }
