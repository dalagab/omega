#!/usr/bin/env python3
"""Compare independent SigmaScope observations with developer-provided `.omega` claims.

This module is deliberately a *projection* layer.  It never changes scanner findings,
severity, capability observations, YARA/ClamAV/OSV evidence, or source/artifact
provenance.  It only places already-recorded observations next to bounded developer
claims so DeltaScope/Omega can explain agreement and differences.
"""
from __future__ import annotations

import json
import urllib.parse
from typing import Any, Iterable

from capability_registry import capability_index, legacy_capability_ids, load_registry

SCHEMA = "omega.sigmascope.behavior-consistency.v1"
MAX_CAPABILITY_ROWS = 128
MAX_DESTINATION_ROWS = 128
MAX_EVIDENCE_ITEMS = 8

CAPABILITY_STATES = {
    "expected-observed",
    "observed-undeclared",
    "expected-not-observed",
    "not-expected-observed",
    "not-expected-not-observed",
    "observed-no-profile",
}


def _text(value: Any, limit: int = 2048) -> str:
    text = str(value or "").strip()
    return text if len(text) <= limit else text[: max(0, limit - 1)] + "…"


def _profile_observation(report: dict[str, Any]) -> dict[str, Any]:
    source = report.get("source") if isinstance(report.get("source"), dict) else {}
    observation = source.get("developerProfile") if isinstance(source.get("developerProfile"), dict) else {}
    return observation


def _profile_document(observation: dict[str, Any]) -> dict[str, Any]:
    if not observation or not bool(observation.get("valid")):
        return {}
    profile = observation.get("profile")
    return profile if isinstance(profile, dict) else {}


def _observed_capability_ids(report: dict[str, Any], registry: dict[str, Any]) -> list[str]:
    explicit = report.get("capabilityIds") if isinstance(report.get("capabilityIds"), list) else []
    ids = {str(item or "").strip() for item in explicit if str(item or "").strip()}
    if not ids:
        intelligence = report.get("dependencyIntelligence") if isinstance(report.get("dependencyIntelligence"), dict) else {}
        automation = report.get("automation") if isinstance(report.get("automation"), dict) else {}
        ids.update(legacy_capability_ids(
            list(report.get("capabilities") or []),
            list(intelligence.get("permissionCandidates") or []),
            list(automation.get("capabilities") or []),
            registry,
        ))
    known = capability_index(registry)
    return sorted((item for item in ids if item in known), key=str.casefold)[:MAX_CAPABILITY_ROWS]


def _declared_capabilities(profile: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in profile.get("capabilities") or []:
        if not isinstance(item, dict):
            continue
        capability_id = _text(item.get("id"), 128)
        if not capability_id or capability_id in result:
            continue
        result[capability_id] = item
    return result


def _capability_state(observed: bool, declaration: dict[str, Any] | None, *, profile_available: bool) -> str:
    if declaration is None:
        if not observed:
            return ""
        return "observed-undeclared" if profile_available else "observed-no-profile"
    expected = bool(declaration.get("expected", True))
    if expected and observed:
        return "expected-observed"
    if expected and not observed:
        return "expected-not-observed"
    if not expected and observed:
        return "not-expected-observed"
    return "not-expected-not-observed"


def _is_profile_evidence(endpoint: dict[str, Any]) -> bool:
    """Do not let `.omega` declarations prove their own observed destination.

    Older retained source-analysis rows could have scanned YAML files broadly.  The
    comparison therefore filters developer-profile evidence even if such an endpoint is
    present in historical normalized endpoint records.
    """
    for value in endpoint.get("evidence") or []:
        folded = str(value or "").replace("\\", "/").casefold()
        if ".omega/plugin.yaml" in folded or ".omega/plugin.yml" in folded:
            return True
    return False


def _observed_destinations(report: dict[str, Any]) -> list[dict[str, Any]]:
    intelligence = report.get("dependencyIntelligence") if isinstance(report.get("dependencyIntelligence"), dict) else {}
    by_host: dict[str, dict[str, Any]] = {}
    for endpoint in intelligence.get("networkEndpoints") or []:
        if not isinstance(endpoint, dict) or not bool(endpoint.get("concreteDestinationEvidence")) or _is_profile_evidence(endpoint):
            continue
        host = _text(endpoint.get("host"), 512).casefold().rstrip(".")
        if not host:
            continue
        row = by_host.setdefault(host, {
            "host": host,
            "confidence": "",
            "classifications": set(),
            "originTypes": set(),
            "evidence": [],
        })
        confidence = _text(endpoint.get("confidence"), 32)
        rank = {"Low": 1, "Medium": 2, "High": 3, "VeryHigh": 4}
        if rank.get(confidence, 0) > rank.get(str(row.get("confidence") or ""), 0):
            row["confidence"] = confidence
        classification = _text(endpoint.get("classification"), 128)
        origin_type = _text(endpoint.get("originType"), 64)
        if classification:
            row["classifications"].add(classification)
        if origin_type:
            row["originTypes"].add(origin_type)
        for evidence in endpoint.get("evidence") or []:
            evidence_text = _text(evidence, 1024)
            if evidence_text and evidence_text not in row["evidence"] and len(row["evidence"]) < MAX_EVIDENCE_ITEMS:
                row["evidence"].append(evidence_text)
    result: list[dict[str, Any]] = []
    for host in sorted(by_host, key=str.casefold)[:MAX_DESTINATION_ROWS]:
        row = by_host[host]
        result.append({
            "host": host,
            "confidence": str(row.get("confidence") or ""),
            "classifications": sorted(row["classifications"], key=str.casefold),
            "originTypes": sorted(row["originTypes"], key=str.casefold),
            "evidence": list(row["evidence"]),
        })
    return result


def _service_host(url: str) -> str:
    try:
        return (urllib.parse.urlsplit(str(url or "")).hostname or "").casefold().rstrip(".")
    except ValueError:
        return ""


def _declared_destinations(profile: dict[str, Any]) -> list[dict[str, Any]]:
    by_pattern: dict[str, dict[str, Any]] = {}
    for capability in profile.get("capabilities") or []:
        if not isinstance(capability, dict):
            continue
        capability_id = _text(capability.get("id"), 128)
        reason = _text(capability.get("reason"), 1200)
        for value in capability.get("destinations") or []:
            pattern = _text(value, 253).casefold().rstrip(".")
            if not pattern:
                continue
            row = by_pattern.setdefault(pattern, {"pattern": pattern, "capabilityIds": set(), "serviceIds": set(), "reasons": []})
            if capability_id:
                row["capabilityIds"].add(capability_id)
            if reason and reason not in row["reasons"] and len(row["reasons"]) < MAX_EVIDENCE_ITEMS:
                row["reasons"].append(reason)
    for service in profile.get("services") or []:
        if not isinstance(service, dict):
            continue
        pattern = _service_host(_text(service.get("url"), 2048))
        if not pattern:
            continue
        row = by_pattern.setdefault(pattern, {"pattern": pattern, "capabilityIds": set(), "serviceIds": set(), "reasons": []})
        service_id = _text(service.get("id"), 128)
        purpose = _text(service.get("purpose"), 1200)
        if service_id:
            row["serviceIds"].add(service_id)
        if purpose and purpose not in row["reasons"] and len(row["reasons"]) < MAX_EVIDENCE_ITEMS:
            row["reasons"].append(purpose)
    result: list[dict[str, Any]] = []
    for pattern in sorted(by_pattern, key=str.casefold)[:MAX_DESTINATION_ROWS]:
        row = by_pattern[pattern]
        result.append({
            "pattern": pattern,
            "capabilityIds": sorted(row["capabilityIds"], key=str.casefold),
            "serviceIds": sorted(row["serviceIds"], key=str.casefold),
            "developerReasons": list(row["reasons"]),
        })
    return result


def destination_matches(pattern: str, host: str) -> bool:
    pattern = str(pattern or "").casefold().rstrip(".")
    host = str(host or "").casefold().rstrip(".")
    if not pattern or not host:
        return False
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return bool(suffix and host != suffix and host.endswith("." + suffix))
    return host == pattern


def compute_behavior_consistency(report: dict[str, Any], registry: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build deterministic declaration/observation comparison from retained evidence."""
    report = report if isinstance(report, dict) else {}
    registry = registry or load_registry()
    registry_entries = capability_index(registry)
    observation = _profile_observation(report)
    profile = _profile_document(observation)
    profile_status = _text(observation.get("status"), 32) or ("valid" if profile else "absent")

    observed_ids = _observed_capability_ids(report, registry)
    observed_set = set(observed_ids)
    declared = _declared_capabilities(profile)
    union = sorted(observed_set | set(declared), key=str.casefold)[:MAX_CAPABILITY_ROWS]
    capability_rows: list[dict[str, Any]] = []
    counts = {state: 0 for state in sorted(CAPABILITY_STATES)}
    for capability_id in union:
        declaration = declared.get(capability_id)
        state = _capability_state(capability_id in observed_set, declaration, profile_available=bool(profile))
        if not state:
            continue
        counts[state] += 1
        registry_row = registry_entries.get(capability_id) or {}
        capability_rows.append({
            "id": capability_id,
            "label": _text(registry_row.get("label") or (declaration or {}).get("label") or capability_id, 180),
            "category": _text(registry_row.get("category") or (declaration or {}).get("category"), 64),
            "state": state,
            "observed": capability_id in observed_set,
            "declared": declaration is not None,
            "expected": bool(declaration.get("expected", True)) if declaration is not None else None,
            "required": bool(declaration.get("required")) if declaration is not None else False,
            "developerReason": _text((declaration or {}).get("reason"), 1200),
            "declaredDestinations": sorted({_text(value, 253).casefold().rstrip(".") for value in ((declaration or {}).get("destinations") or []) if _text(value, 253)}),
        })

    declared_destinations = _declared_destinations(profile)
    observed_destinations = _observed_destinations(report)
    explained: list[dict[str, Any]] = []
    unexplained: list[dict[str, Any]] = []
    matched_patterns: set[str] = set()
    observed_without_profile: list[dict[str, Any]] = []
    for observed in observed_destinations:
        if not profile:
            observed_without_profile.append({
                "host": observed["host"],
                "confidence": observed.get("confidence") or "",
                "classifications": list(observed.get("classifications") or []),
                "originTypes": list(observed.get("originTypes") or []),
            })
            continue
        matches = [row for row in declared_destinations if destination_matches(str(row.get("pattern") or ""), str(observed.get("host") or ""))]
        if matches:
            for match in matches:
                matched_patterns.add(str(match.get("pattern") or ""))
            explained.append({
                "host": observed["host"],
                "confidence": observed.get("confidence") or "",
                "matchedPatterns": sorted({str(item.get("pattern") or "") for item in matches}, key=str.casefold),
                "capabilityIds": sorted({value for item in matches for value in (item.get("capabilityIds") or [])}, key=str.casefold),
                "serviceIds": sorted({value for item in matches for value in (item.get("serviceIds") or [])}, key=str.casefold),
            })
        else:
            unexplained.append({
                "host": observed["host"],
                "confidence": observed.get("confidence") or "",
                "classifications": list(observed.get("classifications") or []),
                "originTypes": list(observed.get("originTypes") or []),
            })
    declared_not_observed = [row for row in declared_destinations if str(row.get("pattern") or "") not in matched_patterns]

    endpoint_summary = report.get("dependencyIntelligence") if isinstance(report.get("dependencyIntelligence"), dict) else {}
    endpoint_summary = endpoint_summary.get("endpointSummary") if isinstance(endpoint_summary.get("endpointSummary"), dict) else {}
    summary = {
        "observedCapabilityCount": len(observed_ids),
        "declaredCapabilityCount": len(declared),
        "expectedObservedCount": counts["expected-observed"],
        "observedUndeclaredCount": counts["observed-undeclared"],
        "expectedNotObservedCount": counts["expected-not-observed"],
        "notExpectedObservedCount": counts["not-expected-observed"],
        "notExpectedNotObservedCount": counts["not-expected-not-observed"],
        "observedWithoutProfileCount": counts["observed-no-profile"],
        "declaredDestinationCount": len(declared_destinations),
        "observedConcreteDestinationCount": len(observed_destinations),
        "explainedDestinationCount": len(explained),
        "unexplainedDestinationCount": len(unexplained),
        "observedDestinationWithoutProfileCount": len(observed_without_profile),
        "declaredDestinationNotObservedCount": len(declared_not_observed),
        "destinationsUndetermined": bool(endpoint_summary.get("destinationsUndetermined")),
    }
    return {
        "schema": SCHEMA,
        "capabilityRegistryRevision": _text(registry.get("revision"), 128),
        "profileStatus": profile_status,
        "profileAvailable": bool(profile),
        "developerProfileSha256": _text(observation.get("sha256"), 128),
        "summary": summary,
        "capabilities": capability_rows,
        "destinations": {
            "declared": declared_destinations,
            "observed": observed_destinations,
            "explained": explained,
            "unexplained": unexplained,
            "observedWithoutProfile": observed_without_profile,
            "declaredNotObserved": declared_not_observed,
        },
        "semantics": "Comparison only: developer claims never suppress, downgrade, or prove independent SigmaScope observations.",
    }


def compact_behavior_consistency(value: Any) -> dict[str, Any]:
    """Bound an already-computed comparison for transport/client projection."""
    if not isinstance(value, dict):
        return {}
    summary = value.get("summary") if isinstance(value.get("summary"), dict) else {}
    capabilities = value.get("capabilities") if isinstance(value.get("capabilities"), list) else []
    destinations = value.get("destinations") if isinstance(value.get("destinations"), dict) else {}

    def compact_declared(item: dict[str, Any]) -> dict[str, Any]:
        return {
            "pattern": _text(item.get("pattern"), 253),
            "capabilityIds": [_text(v, 128) for v in (item.get("capabilityIds") or [])[:16]],
            "serviceIds": [_text(v, 128) for v in (item.get("serviceIds") or [])[:16]],
            "developerReasons": [_text(v, 600) for v in (item.get("developerReasons") or [])[:4]],
        }

    def compact_observed(item: dict[str, Any]) -> dict[str, Any]:
        return {
            "host": _text(item.get("host"), 512),
            "confidence": _text(item.get("confidence"), 32),
            "classifications": [_text(v, 128) for v in (item.get("classifications") or [])[:8]],
            "originTypes": [_text(v, 64) for v in (item.get("originTypes") or [])[:8]],
        }

    def compact_explained(item: dict[str, Any]) -> dict[str, Any]:
        return {
            "host": _text(item.get("host"), 512),
            "confidence": _text(item.get("confidence"), 32),
            "matchedPatterns": [_text(v, 253) for v in (item.get("matchedPatterns") or [])[:16]],
            "capabilityIds": [_text(v, 128) for v in (item.get("capabilityIds") or [])[:16]],
            "serviceIds": [_text(v, 128) for v in (item.get("serviceIds") or [])[:16]],
        }

    def compact_unexplained(item: dict[str, Any]) -> dict[str, Any]:
        return compact_observed(item)

    destination_compactors = {
        "declared": compact_declared,
        "observed": compact_observed,
        "explained": compact_explained,
        "unexplained": compact_unexplained,
        "observedWithoutProfile": compact_unexplained,
        "declaredNotObserved": compact_declared,
    }
    compact_destinations: dict[str, list[dict[str, Any]]] = {}
    for key, fn in destination_compactors.items():
        compact_destinations[key] = [fn(item) for item in (destinations.get(key) or [])[:64] if isinstance(item, dict)]

    return {
        "schema": _text(value.get("schema"), 128),
        "capabilityRegistryRevision": _text(value.get("capabilityRegistryRevision"), 128),
        "profileStatus": _text(value.get("profileStatus"), 32),
        "profileAvailable": bool(value.get("profileAvailable")),
        "developerProfileSha256": _text(value.get("developerProfileSha256"), 128),
        "summary": {str(key): (bool(raw) if key == "destinationsUndetermined" else int(raw or 0)) for key, raw in summary.items() if key in {
            "observedCapabilityCount", "declaredCapabilityCount", "expectedObservedCount", "observedUndeclaredCount",
            "expectedNotObservedCount", "notExpectedObservedCount", "notExpectedNotObservedCount", "observedWithoutProfileCount", "declaredDestinationCount",
            "observedConcreteDestinationCount", "explainedDestinationCount", "unexplainedDestinationCount", "observedDestinationWithoutProfileCount",
            "declaredDestinationNotObservedCount", "destinationsUndetermined",
        }},
        "capabilities": [
            {
                "id": _text(item.get("id"), 128), "label": _text(item.get("label"), 180), "category": _text(item.get("category"), 64),
                "state": _text(item.get("state"), 64), "observed": bool(item.get("observed")), "declared": bool(item.get("declared")),
                "expected": item.get("expected") if isinstance(item.get("expected"), bool) else None,
                "required": bool(item.get("required")), "developerReason": _text(item.get("developerReason"), 600),
                "declaredDestinations": [_text(v, 253) for v in (item.get("declaredDestinations") or [])[:16]],
            }
            for item in capabilities[:64] if isinstance(item, dict)
        ],
        "destinations": compact_destinations,
        "semantics": _text(value.get("semantics"), 512),
    }


def refresh_behavior_consistency(report: dict[str, Any], registry: dict[str, Any] | None = None) -> dict[str, Any]:
    comparison = compute_behavior_consistency(report, registry)
    report["behaviorConsistency"] = comparison
    return comparison


def main() -> int:
    import argparse
    from pathlib import Path
    parser = argparse.ArgumentParser(description="Compare SigmaScope observations with a developer .omega profile in a scan report")
    parser.add_argument("report")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    result = compute_behavior_consistency(report)
    print(json.dumps(result, indent=2 if args.json else None, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
