#!/usr/bin/env python3
"""First-class Omega platform component registry.

A component is a deployable/trust-boundary unit (SigmaScope, Omega Discovery, Rift,
Rebuilder, Threat Intelligence), not an individual collector.  Collectors belong to a
component and provide typed observations.  The registry is intentionally descriptive:
it may advertise planned or externally managed components, but only components whose
launch contract is both active and dispatchable may be selected by the Analysis Broker.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

REGISTRY_SCHEMA = "omega.component-registry.v1"
COMPONENT_SCHEMA = "omega.component.v1"

_ALLOWED_TYPES = {"control-plane", "catalog", "scanner", "intelligence", "rule-engine", "evidence-store", "workbench", "client"}
_ALLOWED_STATUS = {"active", "embedded-transition", "external", "planned", "deprecated"}
_ALLOWED_LAUNCH_MODES = {"none", "reusable-workflow", "external-contract", "embedded"}


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


_RUNTIME_REGISTRY: dict[str, Any] | None = None

COMPONENTS: tuple[dict[str, Any], ...] = (
    {
        "id": "omega.platform.main",
        "name": "Omega Main Control Plane",
        "type": "control-plane",
        "status": "active",
        "branch": "main",
        "executionClass": "workflow-orchestration",
        "launch": {"mode": "none", "available": False, "brokerDispatchable": False},
        "authority": {"observations": False, "securityFindings": False, "catalogIdentity": False, "dispatch": True},
        "boundary": {"network": "workflow-dependent", "hostileCodeExecution": False, "writesEvidence": False},
        "purpose": "Own thin launchers, scheduling and dispatch policy; security logic remains in component branches.",
    },
    {
        "id": "omega.analysis-dispatcher",
        "name": "Omega Analysis Dispatcher",
        "type": "control-plane",
        "status": "active",
        "branch": "main",
        "executionClass": "queue-claim-and-component-dispatch",
        "launch": {
            "mode": "none", "available": False, "brokerDispatchable": False,
            "mainLauncher": "docs/workflow-callers/analysis-dispatcher-main.yml",
        },
        "authority": {"observations": False, "securityFindings": False, "catalogIdentity": False, "dispatch": True, "queueRequests": False},
        "boundary": {"network": "github-workflow-control-only", "hostileCodeExecution": False, "writesEvidence": False},
        "purpose": "Run a bounded leased worker pool over broker work: atomically reserve eligible items, expose in-flight state to other dispatcher runs, and route only through explicit allow-listed main workflows; it does not choose providers or evaluate rules.",
    },
    {
        "id": "omega.analysis-broker",
        "name": "Omega Analysis Broker",
        "type": "control-plane",
        "status": "active",
        "branch": "sigmascope",
        "executionClass": "observation-request-resolution",
        "launch": {
            "mode": "reusable-workflow", "available": True, "brokerDispatchable": False, "requestMode": "analysis-request-state",
            "workflow": ".github/workflows/analysis-broker.yml",
            "mainLauncher": "docs/workflow-callers/analysis-broker-main.yml",
        },
        "authority": {"observations": False, "securityFindings": False, "catalogIdentity": False, "dispatch": False, "queueRequests": True},
        "boundary": {"network": "git-state-publication-only", "hostileCodeExecution": False, "writesEvidence": False},
        "purpose": "Resolve logical observation requests against component/collector registries, freshness and durable queue state without executing providers.",
    },
    {
        "id": "omega.catalog",
        "name": "Omega Catalog",
        "type": "catalog",
        "status": "active",
        "branch": "sigmascope",
        "executionClass": "canonical-catalog-normalization",
        "launch": {
            "mode": "reusable-workflow", "available": True, "brokerDispatchable": False, "requestMode": "daily-or-manual-canonical-build",
            "workflow": ".github/workflows/catalog-builder.yml",
            "mainLauncher": "external-main-caller",
        },
        "authority": {"observations": False, "securityFindings": False, "catalogIdentity": True, "dispatch": False},
        "boundary": {"network": "bounded-public-catalog-acquisition", "hostileCodeExecution": False, "writesEvidence": False},
        "purpose": "Reconcile discovery/configured/canonical history into authoritative plugin/source/variant identity and client projections.",
    },
    {
        "id": "omega.discovery",
        "name": "Omega Discovery",
        "type": "intelligence",
        "status": "active",
        "branch": "sigmascope",
        "executionClass": "ecosystem-discovery",
        "launch": {
            "mode": "reusable-workflow", "available": True, "brokerDispatchable": True, "requestMode": "full-refresh",
            "workflow": ".github/workflows/catalog-discovery.yml",
            "mainLauncher": ".github/workflows/catalog-discovery-launcher.yml",
            "maxConcurrent": 1,
        },
        "authority": {"observations": True, "securityFindings": False, "catalogIdentity": False, "dispatch": False},
        "boundary": {"network": "public-discovery-only", "hostileCodeExecution": False, "writesEvidence": False},
        "purpose": "Continuously discover provenance-backed public ecosystem facts without canonical catalog authority.",
    },
    {
        "id": "omega.sigmascope",
        "name": "SigmaScope",
        "type": "scanner",
        "status": "active",
        "branch": "sigmascope",
        "executionClass": "static-security-analysis",
        "launch": {
            "mode": "reusable-workflow", "available": True, "brokerDispatchable": True, "requestMode": "generic-analysis-request-v1",
            "workflow": ".github/workflows/sigmascope.yml",
            "mainLauncher": "docs/workflow-callers/analysis-dispatch-sigmascope-main.yml",
            "requestAdapter": "tools/security/sigmascope_request_adapter.py",
            "maxConcurrent": 1,
        },
        "authority": {"observations": True, "securityFindings": False, "catalogIdentity": False, "dispatch": False},
        "boundary": {"network": "bounded-artifact-source-acquisition", "hostileCodeExecution": False, "writesEvidence": True},
        "purpose": "Perform bounded non-executing artifact/source/security analysis and publish retained evidence candidates. Generic broker requests are merged into the canonical scan queue; Evidence-v2 publication remains serialized.",
    },
    {
        "id": "omega.rift",
        "name": "Rift",
        "type": "scanner",
        "status": "external",
        "branch": "rift",
        "executionClass": "isolated-runtime-analysis",
        "launch": {"mode": "external-contract", "available": False, "brokerDispatchable": False, "workflow": "managed-by-rift-workstream"},
        "authority": {"observations": True, "securityFindings": False, "catalogIdentity": False, "dispatch": False},
        "boundary": {"network": "rift-defined", "hostileCodeExecution": True, "writesEvidence": False},
        "purpose": "Provide neutral runtime observations. Implementation and launch wiring are owned by the separate Rift workstream.",
    },
    {
        "id": "omega.threat-intelligence",
        "name": "Omega Threat Intelligence",
        "type": "intelligence",
        "status": "embedded-transition",
        "branch": "sigmascope",
        "executionClass": "live-security-intelligence",
        "launch": {"mode": "embedded", "available": False, "brokerDispatchable": False, "workflow": ".github/workflows/catalog-builder.yml"},
        "authority": {"observations": True, "securityFindings": False, "catalogIdentity": False, "dispatch": False},
        "boundary": {"network": "live-intelligence-lookups", "hostileCodeExecution": False, "writesEvidence": False},
        "purpose": "Target component for time-dependent DNS/reputation/connectivity intelligence; current reputation collection remains embedded during transition.",
    },
    {
        "id": "omega.rebuilder",
        "name": "Omega Build Provenance",
        "type": "scanner",
        "status": "planned",
        "branch": "rebuild",
        "executionClass": "isolated-source-build",
        "launch": {"mode": "none", "available": False, "brokerDispatchable": False},
        "authority": {"observations": True, "securityFindings": False, "catalogIdentity": False, "dispatch": False},
        "boundary": {"network": "constrained-build-dependency-restore", "hostileCodeExecution": False, "sourceBuildExecution": True, "writesEvidence": False},
        "purpose": "Produce reproducible source-to-artifact build proof for exact source/artifact subjects.",
    },
    {
        "id": "omega.stigma-1",
        "name": "Stigma-1",
        "type": "rule-engine",
        "status": "active",
        "branch": "sigmascope",
        "executionClass": "deterministic-rule-evaluation",
        "launch": {"mode": "embedded", "available": False, "brokerDispatchable": False},
        "authority": {"observations": False, "securityFindings": True, "catalogIdentity": False, "dispatch": False},
        "boundary": {"network": "none", "hostileCodeExecution": False, "writesEvidence": False},
        "purpose": "Evaluate deterministic rules over retained typed observations and request additional observation classes without executing collectors.",
    },
    {
        "id": "omega.evidence-v2",
        "name": "Security Evidence v2",
        "type": "evidence-store",
        "status": "active",
        "branch": "security-evidence-v2",
        "executionClass": "immutable-evidence-storage",
        "launch": {"mode": "none", "available": False, "brokerDispatchable": False},
        "authority": {"observations": False, "securityFindings": False, "catalogIdentity": False, "dispatch": False},
        "boundary": {"network": "none", "hostileCodeExecution": False, "writesEvidence": True},
        "purpose": "Retain immutable/current security observations, findings, lineage and analysis state.",
    },
    {
        "id": "omega.client",
        "name": "Omega Client",
        "type": "client",
        "status": "active",
        "branch": "",
        "executionClass": "dalamud-client-consumer",
        "launch": {"mode": "none", "available": False, "brokerDispatchable": False},
        "authority": {"observations": False, "securityFindings": False, "catalogIdentity": False, "dispatch": False},
        "boundary": {"network": "catalog-client-fetch", "hostileCodeExecution": False, "writesEvidence": False},
        "purpose": "Consume compact catalog/security projections for plugin discovery and installation; never re-grade production evidence.",
    },
    {
        "id": "omega.deltascope",
        "name": "DeltaScope",
        "type": "workbench",
        "status": "active",
        "branch": "sigmascope",
        "executionClass": "read-only-research-workbench",
        "launch": {"mode": "reusable-workflow", "available": True, "brokerDispatchable": False, "requestMode": "developer-workbench", "workflow": ".github/workflows/deltascope.yml"},
        "authority": {"observations": False, "securityFindings": False, "catalogIdentity": False, "dispatch": False},
        "boundary": {"network": "operator-research", "hostileCodeExecution": False, "writesEvidence": False},
        "purpose": "Read-only developer/security research and explanation surface; never part of production scan decisions.",
    },
)


_BUNDLED_COMPONENTS = COMPONENTS


def configure_registry(document: Mapping[str, Any] | None) -> None:
    """Use a verified published component registry for this SDK process.

    Passing ``None`` restores the bundled compatibility snapshot.
    """
    global _RUNTIME_REGISTRY, COMPONENTS
    if document is None:
        _RUNTIME_REGISTRY = None
        COMPONENTS = _BUNDLED_COMPONENTS
        return
    if not isinstance(document, Mapping) or str(document.get("schema") or "") != REGISTRY_SCHEMA:
        raise ValueError("unsupported published component registry")
    rows = document.get("components")
    if not isinstance(rows, list):
        raise ValueError("published component registry has no component list")
    validated: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in rows:
        if not isinstance(raw, Mapping):
            raise ValueError("published component registry contains malformed rows")
        row = dict(raw)
        component_id = str(row.get("id") or "")
        if not component_id.startswith("omega.") or component_id in seen:
            raise ValueError(f"published component registry has invalid/duplicate id: {component_id!r}")
        seen.add(component_id)
        validated.append(row)
    COMPONENTS = tuple(validated)
    _RUNTIME_REGISTRY = dict(document)


def validate_component(component: Mapping[str, Any]) -> dict[str, Any]:
    row = dict(component)
    component_id = str(row.get("id") or "")
    if not component_id.startswith("omega."):
        raise ValueError(f"invalid component id: {component_id!r}")
    if str(row.get("type") or "") not in _ALLOWED_TYPES:
        raise ValueError(f"unsupported component type for {component_id}")
    if str(row.get("status") or "") not in _ALLOWED_STATUS:
        raise ValueError(f"unsupported component status for {component_id}")
    launch = row.get("launch") if isinstance(row.get("launch"), Mapping) else {}
    if str(launch.get("mode") or "none") not in _ALLOWED_LAUNCH_MODES:
        raise ValueError(f"unsupported launch mode for {component_id}")
    if bool(launch.get("available")) and str(row.get("status")) != "active":
        raise ValueError(f"non-active component cannot expose an active launcher: {component_id}")
    if bool(launch.get("available")) and str(launch.get("mode")) != "reusable-workflow":
        raise ValueError(f"launchable component must expose a reusable workflow: {component_id}")
    if bool(launch.get("available")) and not str(launch.get("workflow") or ""):
        raise ValueError(f"launchable component must name a workflow: {component_id}")
    if bool(launch.get("brokerDispatchable")) and not bool(launch.get("available")):
        raise ValueError(f"broker-dispatchable component must also be launchable: {component_id}")
    if bool(launch.get("brokerDispatchable")):
        try:
            max_concurrent = int(launch.get("maxConcurrent") or 0)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"broker-dispatchable component maxConcurrent must be an integer: {component_id}") from exc
        if max_concurrent < 1 or max_concurrent > 64:
            raise ValueError(f"broker-dispatchable component maxConcurrent must be 1..64: {component_id}")
    return row


def component_map() -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for raw in COMPONENTS:
        row = dict(raw) if _RUNTIME_REGISTRY is not None else validate_component(raw)
        component_id = str(row.get("id") or "")
        if not component_id.startswith("omega.") or component_id in result:
            raise ValueError(f"duplicate/invalid component id: {component_id!r}")
        result[component_id] = row
    return result


def component_revision() -> str:
    if _RUNTIME_REGISTRY is not None and _RUNTIME_REGISTRY.get("revision"):
        return str(_RUNTIME_REGISTRY.get("revision"))
    semantic = {"schema": REGISTRY_SCHEMA, "components": COMPONENTS}
    return f"component-registry-v1-{_sha(semantic)[:20]}"


def is_launchable(component_id: str) -> bool:
    row = component_map().get(str(component_id or "")) or {}
    launch = row.get("launch") if isinstance(row.get("launch"), Mapping) else {}
    return str(row.get("status") or "") == "active" and bool(launch.get("available"))


def is_dispatchable(component_id: str) -> bool:
    row = component_map().get(str(component_id or "")) or {}
    launch = row.get("launch") if isinstance(row.get("launch"), Mapping) else {}
    return is_launchable(component_id) and bool(launch.get("brokerDispatchable"))


def dispatch_contract(component_id: str) -> dict[str, Any] | None:
    row = component_map().get(str(component_id or ""))
    if row is None:
        return None
    launch = row.get("launch") if isinstance(row.get("launch"), Mapping) else {}
    return {
        "componentId": str(row["id"]),
        "status": str(row.get("status") or ""),
        "branch": str(row.get("branch") or ""),
        "executionClass": str(row.get("executionClass") or ""),
        "launchMode": str(launch.get("mode") or "none"),
        "launchable": is_launchable(str(row["id"])),
        "dispatchable": is_dispatchable(str(row["id"])),
        "requestMode": str(launch.get("requestMode") or ""),
        "workflow": str(launch.get("workflow") or ""),
        "mainLauncher": str(launch.get("mainLauncher") or ""),
        "maxConcurrent": int(launch.get("maxConcurrent") or 0),
    }


def build_registry() -> dict[str, Any]:
    if _RUNTIME_REGISTRY is not None:
        return dict(_RUNTIME_REGISTRY)
    components = component_map()
    return {
        "schema": REGISTRY_SCHEMA,
        "revision": component_revision(),
        "components": [components[key] for key in sorted(components)],
        "byId": {key: components[key] for key in sorted(components)},
        "launchableComponents": [key for key in sorted(components) if is_launchable(key)],
        "dispatchableComponents": [key for key in sorted(components) if is_dispatchable(key)],
        "policy": {
            "componentDefinition": "deployable-or-trust-boundary-unit",
            "collectorDefinition": "typed-observation-provider-owned-by-component",
            "rulesMayDispatch": False,
            "brokerMayExecuteCode": False,
            "dispatcherMayChooseProviders": False,
            "dispatcherMayExecuteQueueWorkflowPath": False,
            "mainOwnsWorkflowLaunch": True,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build/inspect the Omega component registry")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--component", default="")
    args = parser.parse_args()
    if args.component:
        payload: Any = dispatch_contract(args.component)
        if payload is None:
            raise SystemExit(f"unknown component {args.component!r}")
    else:
        payload = build_registry()
    text = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
