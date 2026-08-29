#!/usr/bin/env python3
"""Publish owner-facing security-system readiness from existing Omega contracts."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any

import collector_contracts
import component_registry
import security_evidence_v2

SCHEMA = "omega.security-system-state.v1"
ALLOWED_STATES = {"operational", "degraded", "experimental", "disabled", "blocked", "incomplete", "planned", "failed", "stale", "unsupported"}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _state_for_component(row: dict[str, Any]) -> str:
    status = str(row.get("status") or "planned")
    return {"active": "operational", "embedded-transition": "incomplete", "external": "blocked", "planned": "planned", "deprecated": "disabled"}.get(status, "incomplete")


def _message(state: str, row: dict[str, Any]) -> str:
    if state == "operational": return "Implemented and available within its declared trust boundary."
    if state == "planned": return "Known capability; implementation or production wiring is not complete."
    if state == "blocked": return "Owned by an external workstream and not launchable from Omega yet."
    if state == "incomplete": return "Partially implemented or still embedded in another component."
    if state == "disabled": return "Present in the architecture but intentionally disabled or deprecated."
    return str(row.get("purpose") or "Readiness requires owner attention.")


def build_state(evidence_root: Path) -> dict[str, Any]:
    components = component_registry.component_map()
    collectors = collector_contracts.collector_map()
    coverage_counts: Counter[str] = Counter()
    component_errors: dict[str, list[dict[str, Any]]] = defaultdict(list)
    variant_count = 0
    for entry, payload in security_evidence_v2.iter_variant_entries(evidence_root):
        variant_count += 1
        coverage = security_evidence_v2.variant_coverage_summary(payload)
        coverage_counts[str(coverage.get("status") or "unknown")] += 1
        current = payload.get("current") if isinstance(payload.get("current"), dict) else {}
        report = current.get("report_json") if isinstance(current.get("report_json"), dict) else {}
        error = str(current.get("error") or report.get("error") or "").strip()
        if error or str(coverage.get("status")) == "failed":
            plugin = payload.get("plugin") if isinstance(payload.get("plugin"), dict) else {}
            component_errors["omega.sigmascope"].append({
                "variantId": int(payload.get("variantId") or 0),
                "plugin": str(plugin.get("canonical_name") or plugin.get("internal_name") or f"Variant {entry.get('variantId', 0)}"),
                "code": "scan-failed",
                "message": (error or "One or more required scan stages failed")[:512],
                "atUtc": str(current.get("scanned_at_utc") or ""),
            })

    by_component: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for collector in collectors.values():
        by_component[str(collector.get("componentId") or "")].append(collector)

    systems: list[dict[str, Any]] = []
    for component_id, component in sorted(components.items()):
        state = _state_for_component(component)
        owned = by_component.get(component_id, [])
        planned = sum(1 for row in owned if str(row.get("status") or "active") == "planned")
        active = len(owned) - planned
        errors = component_errors.get(component_id, [])[:25]
        if errors and state == "operational": state = "degraded"
        systems.append({
            "id": component_id,
            "name": str(component.get("name") or component_id),
            "kind": str(component.get("type") or "component"),
            "state": state,
            "implementationStatus": str(component.get("status") or ""),
            "branch": str(component.get("branch") or ""),
            "message": _message(state, component),
            "collectorCounts": {"active": active, "planned": planned, "total": len(owned)},
            "affectedPlugins": len(errors),
            "recentErrors": errors,
        })
    counts = Counter(str(row["state"]) for row in systems)
    payload = {
        "schema": SCHEMA,
        "generatedAtUtc": utc_now(),
        "componentRegistryRevision": component_registry.component_revision(),
        "collectorRegistryRevision": collector_contracts.registry_revision(),
        "summary": {
            "systems": len(systems),
            "requiringAttention": sum(counts[state] for state in ("degraded", "failed", "blocked", "stale")),
            "incomplete": counts["incomplete"],
            "planned": counts["planned"],
            "operational": counts["operational"],
            "plugins": variant_count,
            "pluginCoverage": dict(sorted(coverage_counts.items())),
        },
        "systems": systems,
        "policy": {
            "noFindingDoesNotImplyCovered": True,
            "plannedIsNotOperational": True,
            "externalIsNotLaunchable": True,
            "errorsAreHighLevelAndBounded": True,
        },
    }
    semantic = dict(payload); semantic.pop("generatedAtUtc", None)
    payload["stateRevision"] = "security-systems-v1-" + hashlib.sha256(json.dumps(semantic, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:20]
    return payload


def materialize(evidence_root: Path) -> dict[str, Any]:
    evidence_root = evidence_root.resolve()
    path = evidence_root / "systems" / "security-systems.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = build_state(evidence_root)
    path.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return {"schema": SCHEMA, **security_evidence_v2.file_entry(evidence_root, path), "stateRevision": payload["stateRevision"], "summary": payload["summary"]}


def main() -> int:
    parser = argparse.ArgumentParser(description="Build owner-facing Omega security-system readiness")
    parser.add_argument("--evidence-root", type=Path, required=True)
    args = parser.parse_args()
    descriptor = materialize(args.evidence_root)
    print(json.dumps(descriptor, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
