#!/usr/bin/env python3
"""Shared first-class collector and typed-observation contracts for Omega.

Collectors acquire facts; they do not create catalog identity or security verdicts.  Stigma-1
rules reference stable logical observation collections, while provenance records which registered
collector supplied each row.  Orchestration may use the provider registry to satisfy a typed
``observationRequest`` but rule evaluation itself performs no collector execution or network I/O.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Iterable, Mapping

import component_registry

REGISTRY_SCHEMA = "omega.collector-registry.v1"
COLLECTOR_SCHEMA = "omega.collector.v1"
OBSERVATION_TYPE_SCHEMA = "omega.collector-observation-type.v1"
BUNDLE_SCHEMA = "omega.collector-observation-bundle.v1"
REQUEST_SCHEMA = "omega.stigma-1.observation-request.v1"
REQUEST_RESULT_SCHEMA = "omega.stigma-1.observation-request-resolution.v1"
DISCOVERY_COMPONENT_ID = "omega.discovery"
DISCOVERY_COMPONENT_NAME = "Omega Discovery"
MAX_ROWS_PER_COLLECTION = 20_000
MAX_BUNDLE_ROWS = 50_000
MAX_PROVENANCE_TEXT = 4096

# Logical observation names deliberately follow the existing SRL collection naming convention.
# They are not Evidence-v2 collections: they are contextual/catalog-intelligence inputs carried by
# an explicit collector observation bundle.
OBSERVATION_TYPES: dict[str, dict[str, Any]] = {
    "catalogSourceCandidates": {
        "schema": "omega.observation.catalog-source-candidate.v1",
        "semanticClass": "catalog-intelligence",
        "ruleEligible": True,
        "authority": "candidate-context-only",
        "fields": {
            "url": "https-url", "provider": "string", "kind": "string", "status": "string",
            "pluginCount": "integer", "contentSha256": "string", "trackedByOpenIssue": "boolean",
            "discoveredBy": "string", "sourceRepoUrl": "string", "originCollectorId": "string",
        },
    },
    "catalogPluginFacts": {
        "schema": "omega.observation.catalog-plugin-fact.v1",
        "semanticClass": "catalog-intelligence",
        "ruleEligible": True,
        "authority": "candidate-context-only",
        "fields": {
            "classification": "string", "internalName": "string", "name": "string",
            "assemblyVersion": "string", "testingAssemblyVersion": "string",
            "dalamudApiLevel": "integer", "testingDalamudApiLevel": "integer",
            "sourceUrl": "https-url", "sourceProvider": "string", "repoUrl": "string",
            "originCollectorId": "string",
        },
    },
    "catalogProjectLinks": {
        "schema": "omega.observation.catalog-project-link.v1",
        "semanticClass": "catalog-intelligence",
        "ruleEligible": True,
        "authority": "context-only",
        "fields": {
            "projectUrl": "https-url", "url": "https-url", "linkKind": "string",
            "source": "string", "candidateKind": "string",
        },
    },
    "catalogRepositoryCandidates": {
        "schema": "omega.observation.catalog-repository-candidate.v1",
        "semanticClass": "catalog-intelligence",
        "ruleEligible": True,
        "authority": "candidate-context-only",
        "fields": {
            "repositoryUrl": "https-url", "owner": "string", "repository": "string",
            "reason": "string", "sourceUrl": "string", "candidateFileCount": "integer",
        },
    },
    "catalogManifestCandidates": {
        "schema": "omega.observation.catalog-manifest-candidate.v1",
        "semanticClass": "catalog-intelligence",
        "ruleEligible": True,
        "authority": "candidate-context-only",
        "fields": {
            "url": "https-url", "repositoryUrl": "string", "path": "string",
            "reason": "string", "originCollectorId": "string",
        },
    },
    "catalogIssueHints": {
        "schema": "omega.observation.catalog-issue-hint.v1",
        "semanticClass": "operator-context",
        "ruleEligible": True,
        "authority": "untrusted-context-only",
        "fields": {
            "number": "integer", "title": "string", "labels": "string[]",
            "urls": "string[]", "htmlUrl": "string",
        },
    },
    "riftRuntimeEvents": {
        "schema": "omega.observation.rift-runtime-event.v1",
        "semanticClass": "runtime-security-observation",
        "ruleEligible": True,
        "authority": "runtime-observation-only",
        "fields": {
            "id": "string", "kind": "string", "phase": "string", "tsOffsetMs": "integer",
            "component": "string", "operation": "string", "target": "string", "outcome": "string",
            "activityId": "string", "parentActivityId": "string", "registrationId": "string",
            "invocation": "integer", "requestId": "string", "variantId": "integer", "artifactSha256": "string",
        },
    },
    "riftRuntimeExercise": {
        "schema": "omega.observation.rift-runtime-exercise.v1",
        "semanticClass": "runtime-security-observation",
        "ruleEligible": True,
        "authority": "runtime-observation-only",
        "fields": {
            "profile": "string", "status": "string", "reason": "string",
            "frameworkTicksRequested": "integer", "registrationsDiscovered": "integer",
            "registrationsExercised": "integer", "registrationsUnexercised": "integer",
            "requestId": "string", "variantId": "integer", "artifactSha256": "string",
        },
    },
    "riftRuntimeBoundary": {
        "schema": "omega.observation.rift-runtime-boundary.v1",
        "semanticClass": "runtime-provenance",
        "ruleEligible": True,
        "authority": "attested-runtime-context-only",
        "fields": {
            "requestId": "string", "variantId": "integer", "artifactSha256": "string",
            "artifactTreeSha256": "string", "entrySha256": "string", "runtimeReportSha256": "string",
            "producer": "string", "producerVersion": "string", "ranAtUtc": "string",
            "network": "string", "seccomp": "string", "boundaryProfile": "string",
            "contractMode": "string", "processExitCode": "integer", "attested": "boolean",
        },
    },
    "riftComponentSecurity": {
        "schema": "omega.observation.rift-component-security.v1",
        "semanticClass": "runtime-component-security-observation",
        "ruleEligible": True,
        "authority": "specialist-observation-only",
        "fields": {
            "component": "string", "version": "string", "kind": "string", "status": "string",
            "advisoryId": "string", "advisoryUrl": "string", "fixedVersion": "string",
            "requestId": "string", "variantId": "integer", "artifactSha256": "string",
        },
    },
    "binarySignatureTrust": {
        "schema": "omega.observation.binary-signature-trust.v1",
        "semanticClass": "static-security-observation",
        "ruleEligible": True,
        "authority": "signature-validation-observation-only",
        "fields": {
            "artifactSha256": "string", "path": "string", "format": "string",
            "signaturePresent": "boolean", "digestValid": "boolean", "chainValid": "boolean",
            "timestampPresent": "boolean", "timestampValid": "boolean", "publisher": "string",
            "issuer": "string", "thumbprint": "string", "validationStatus": "string",
        },
    },
    "sourceArtifactBuildProof": {
        "schema": "omega.observation.source-artifact-build-proof.v1",
        "semanticClass": "build-provenance-observation",
        "ruleEligible": True,
        "authority": "reproducibility-observation-only",
        "fields": {
            "artifactSha256": "string", "sourceRepository": "string", "sourceCommit": "string",
            "builtArtifactSha256": "string", "match": "boolean", "status": "string",
            "toolchain": "string", "environmentDigest": "string", "buildRecipeDigest": "string",
        },
    },
    "endpointDns": {
        "schema": "omega.observation.endpoint-dns.v1",
        "semanticClass": "live-threat-intelligence",
        "ruleEligible": True,
        "authority": "time-bounded-intelligence-only",
        "fields": {"host": "string", "resolvedIps": "string[]", "status": "string", "observedAtUtc": "string", "expiresAtUtc": "string"},
    },
    "endpointReputation": {
        "schema": "omega.observation.endpoint-reputation.v1",
        "semanticClass": "live-threat-intelligence",
        "ruleEligible": True,
        "authority": "time-bounded-intelligence-only",
        "fields": {
            "indicator": "string", "indicatorType": "string", "provider": "string",
            "classification": "string", "confidence": "string", "observedAtUtc": "string", "expiresAtUtc": "string",
        },
    },
    "endpointConnectivity": {
        "schema": "omega.observation.endpoint-connectivity.v1",
        "semanticClass": "live-threat-intelligence",
        "ruleEligible": True,
        "authority": "time-bounded-connectivity-observation-only",
        "fields": {
            "endpoint": "string", "reachable": "boolean", "protocol": "string", "status": "string",
            "observedAtUtc": "string", "expiresAtUtc": "string",
        },
    },
}

FRESHNESS_POLICIES: dict[str, dict[str, Any]] = {
    "catalogSourceCandidates": {"model": "ttl", "ttlSeconds": 21600},
    "catalogPluginFacts": {"model": "ttl", "ttlSeconds": 21600},
    "catalogProjectLinks": {"model": "ttl", "ttlSeconds": 86400},
    "catalogRepositoryCandidates": {"model": "ttl", "ttlSeconds": 21600},
    "catalogManifestCandidates": {"model": "ttl", "ttlSeconds": 21600},
    "catalogIssueHints": {"model": "ttl", "ttlSeconds": 21600},
    "riftRuntimeEvents": {"model": "immutable-with-subject-and-profile"},
    "riftRuntimeExercise": {"model": "immutable-with-subject-and-profile"},
    "riftRuntimeBoundary": {"model": "immutable-with-subject-and-profile"},
    "riftComponentSecurity": {"model": "immutable-with-subject-and-profile"},
    "binarySignatureTrust": {"model": "immutable-with-artifact"},
    "sourceArtifactBuildProof": {"model": "immutable-with-source-and-artifact"},
    "endpointDns": {"model": "ttl", "ttlSeconds": 3600},
    "endpointReputation": {"model": "ttl", "ttlSeconds": 86400},
    "endpointConnectivity": {"model": "ttl", "ttlSeconds": 3600},
}

def freshness_policy(collection: str) -> dict[str, Any]:
    name = str(collection or "")
    if name in FRESHNESS_POLICIES:
        return dict(FRESHNESS_POLICIES[name])
    providers = providers_for(name, include_planned=True)
    if providers and all(str((collector_map().get(item) or {}).get("componentId") or "") == "omega.sigmascope" for item in providers):
        return {"model": "immutable-with-subject"}
    return {"model": "request-scoped"}

# Collector IDs are implementation identities; rules should normally bind to the provided logical
# observation type.  Provider resolution lets orchestration substitute/add collectors later without
# rewriting rules.
COLLECTORS: tuple[dict[str, Any], ...] = (
    {
        "id": "omega.collector.discovery.curated-registry", "version": 1,
        "componentId": DISCOVERY_COMPONENT_ID, "title": "Curated source registry",
        "purpose": "Project human-maintained curated source URLs into the discovery candidate vocabulary.",
        "provides": ["catalogManifestCandidates"], "cadence": "scheduled",
        "authority": "observation-only", "network": False,
    },
    {
        "id": "omega.collector.discovery.community-registry", "version": 1,
        "componentId": DISCOVERY_COMPONENT_ID, "title": "Validated community source registry",
        "purpose": "Project previously validated community source URLs into the discovery candidate vocabulary.",
        "provides": ["catalogManifestCandidates"], "cadence": "scheduled",
        "authority": "observation-only", "network": False,
    },
    {
        "id": "omega.collector.discovery.github-code-search", "version": 1,
        "componentId": DISCOVERY_COMPONENT_ID, "title": "GitHub code search",
        "purpose": "Search indexed public GitHub JSON files for Dalamud manifest signatures.",
        "provides": ["catalogManifestCandidates"], "cadence": "scheduled",
        "authority": "observation-only", "network": True,
    },
    {
        "id": "omega.collector.discovery.puni-directory", "version": 1,
        "componentId": DISCOVERY_COMPONENT_ID, "title": "Puni directory discovery",
        "purpose": "Enumerate public Puni repository feeds from its repository directory.",
        "provides": ["catalogManifestCandidates"], "cadence": "scheduled",
        "authority": "observation-only", "network": True,
    },
    {
        "id": "omega.collector.discovery.web-search", "version": 1,
        "componentId": DISCOVERY_COMPONENT_ID, "title": "Public web search",
        "purpose": "Run a bounded deterministic query set through an explicitly configured web-search API.",
        "provides": ["catalogManifestCandidates", "catalogRepositoryCandidates"], "cadence": "scheduled-optional",
        "authority": "observation-only", "network": True,
    },
    {
        "id": "omega.collector.discovery.project-page", "version": 1,
        "componentId": DISCOVERY_COMPONENT_ID, "title": "Project-page link intelligence",
        "purpose": "Reuse canonical bounded project/README enrichment to discover related JSON feeds and repositories.",
        "provides": ["catalogProjectLinks", "catalogManifestCandidates", "catalogRepositoryCandidates"],
        "cadence": "scheduled", "authority": "observation-only", "network": False,
    },
    {
        "id": "omega.collector.discovery.repository-tree", "version": 1,
        "componentId": DISCOVERY_COMPONENT_ID, "title": "Repository-tree manifest discovery",
        "purpose": "Inspect a bounded public GitHub repository tree for likely Dalamud JSON manifests.",
        "provides": ["catalogManifestCandidates"], "cadence": "scheduled",
        "authority": "observation-only", "network": True,
    },
    {
        "id": "omega.collector.discovery.issue-hints", "version": 1,
        "componentId": DISCOVERY_COMPONENT_ID, "title": "Omega issue source hints",
        "purpose": "Collect source/repository URLs from bounded open Omega source-submission/follow-up issues.",
        "provides": ["catalogIssueHints", "catalogManifestCandidates", "catalogRepositoryCandidates"],
        "cadence": "scheduled", "authority": "observation-only", "network": True,
    },
    {
        "id": "omega.collector.discovery.pluginmaster-validator", "version": 1,
        "componentId": DISCOVERY_COMPONENT_ID, "title": "PluginMaster validator",
        "purpose": "Validate novel public JSON candidates with the production PluginMaster parser and classify new plugin/source facts.",
        "provides": ["catalogSourceCandidates", "catalogPluginFacts"], "cadence": "scheduled",
        "authority": "observation-only", "network": True,
    },
    # Existing security providers are registered here so Stigma-1/DeltaScope can explain provider
    # lineage through one vocabulary. Their actual retained row schemas remain owned by
    # observation_projection.py and are not duplicated in OBSERVATION_TYPES.
    {
        "id": "omega.collector.sigmascope.artifact-static", "version": 1,
        "componentId": "omega.sigmascope", "title": "SigmaScope artifact static analysis",
        "purpose": "Provide retained static artifact observations.",
        "provides": ["managedAssemblies", "managedSymbols", "managedCallSites", "managedReachability", "nativeImports", "networkEndpoints", "staticPatternMatches", "binaryClassifications", "artifactIdentity"],
        "cadence": "event-driven", "authority": "observation-only", "network": False,
    },
    {
        "id": "omega.collector.sigmascope.source-analysis", "version": 1,
        "componentId": "omega.sigmascope", "title": "SigmaScope source analysis",
        "purpose": "Provide retained source/dependency/provenance observations.",
        "provides": ["dependencies", "ipcIntegrations", "namespaceImports", "sourceFiles", "manifestObservation", "sourceAttribution", "sourceProvenance", "developerProfile"],
        "cadence": "event-driven", "authority": "observation-only", "network": True,
    },
    {
        "id": "omega.collector.sigmascope.secondary-security", "version": 1,
        "componentId": "omega.sigmascope", "title": "SigmaScope secondary security engines",
        "purpose": "Provide bounded supplemental YARA/ClamAV hygiene observations.",
        "provides": ["secondarySecurity"], "cadence": "event-driven",
        "authority": "supplemental-observation-only", "network": False,
    },
    {
        "id": "omega.collector.sigmascope.authenticode", "version": 1,
        "componentId": "omega.sigmascope", "title": "SigmaScope Authenticode validation",
        "purpose": "Validate PE Authenticode digest, signer chain and timestamp semantics without executing the binary.",
        "provides": ["binarySignatureTrust"], "cadence": "event-driven",
        "authority": "observation-only", "network": False, "status": "planned",
    },
    {
        "id": "omega.collector.threat-intelligence.endpoints", "version": 1,
        "componentId": "omega.threat-intelligence", "title": "Live endpoint threat intelligence",
        "purpose": "Provide timestamped DNS, reputation and bounded connectivity observations outside static scanning.",
        "provides": ["endpointDns", "endpointReputation", "endpointConnectivity"],
        "cadence": "on-demand-and-scheduled", "authority": "time-bounded-observation-only",
        "network": True, "status": "planned",
    },
    {
        "id": "omega.collector.rebuilder.source-artifact-proof", "version": 1,
        "componentId": "omega.rebuilder", "title": "Source-to-artifact reproducible build proof",
        "purpose": "Build an exact source revision in an isolated provenance worker and compare its output with the distributed artifact.",
        "provides": ["sourceArtifactBuildProof"], "cadence": "on-demand",
        "authority": "build-provenance-observation-only", "network": True, "status": "planned",
    },
    {
        "id": "omega.collector.rift.runtime", "version": 1,
        "componentId": "omega.rift", "title": "Rift runtime observation collector",
        "purpose": "Project trusted Rift runtime reports and supervisor attestations into typed neutral runtime observations.",
        "provides": ["riftRuntimeEvents", "riftRuntimeExercise", "riftRuntimeBoundary", "riftComponentSecurity"],
        "cadence": "event-driven", "authority": "runtime-observation-only",
        "network": False, "status": "active",
    },
)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def collector_map() -> dict[str, dict[str, Any]]:
    components = component_registry.component_map()
    result: dict[str, dict[str, Any]] = {}
    for item in COLLECTORS:
        row = dict(item)
        collector_id = str(row.get("id") or "")
        component_id = str(row.get("componentId") or "")
        if not collector_id.startswith("omega.collector."):
            raise ValueError(f"invalid collector id: {collector_id!r}")
        if component_id not in components:
            raise ValueError(f"collector {collector_id} references unknown component {component_id!r}")
        if collector_id in result:
            raise ValueError(f"duplicate collector id: {collector_id}")
        result[collector_id] = row
    return result


def providers_for(collection: str, *, include_planned: bool = False) -> list[str]:
    wanted = str(collection or "")
    result: list[str] = []
    for item in COLLECTORS:
        if wanted not in (item.get("provides") or []):
            continue
        if str(item.get("status") or "active") == "planned" and not include_planned:
            continue
        result.append(str(item["id"]))
    return sorted(result)


def srl_field_registry() -> dict[str, dict[str, str]]:
    return {
        name: {str(field): str(kind) for field, kind in (spec.get("fields") or {}).items()}
        for name, spec in OBSERVATION_TYPES.items() if bool(spec.get("ruleEligible"))
    }


def registry_revision() -> str:
    semantic = {"schema": REGISTRY_SCHEMA, "componentRegistryRevision": component_registry.component_revision(), "observationTypes": OBSERVATION_TYPES, "freshness": FRESHNESS_POLICIES, "collectors": COLLECTORS}
    return f"collector-registry-v1-{_sha(semantic)[:20]}"


def build_registry() -> dict[str, Any]:
    components = component_registry.component_map()
    component_summaries = {
        component_id: {
            "name": str(row.get("name") or component_id),
            "role": str(row.get("executionClass") or row.get("type") or ""),
            "authority": dict(row.get("authority") or {}),
            "status": str(row.get("status") or ""),
            "branch": str(row.get("branch") or ""),
            "launchable": component_registry.is_launchable(component_id),
            "dispatchable": component_registry.is_dispatchable(component_id),
        }
        for component_id, row in sorted(components.items())
    }
    observation_types = {
        name: {**dict(spec), "freshness": freshness_policy(name)}
        for name, spec in sorted(OBSERVATION_TYPES.items())
    }
    return {
        "schema": REGISTRY_SCHEMA,
        "revision": registry_revision(),
        "componentRegistry": {
            "schema": component_registry.REGISTRY_SCHEMA,
            "revision": component_registry.component_revision(),
        },
        "components": component_summaries,
        "observationTypes": observation_types,
        "collectors": [dict(item) for item in COLLECTORS],
        "providers": {name: providers_for(name, include_planned=True) for name in sorted(OBSERVATION_TYPES)},
        "ruleBinding": "logical-observation-type",
        "implementationBindingForbidden": True,
    }


def _clean_provenance(value: Mapping[str, Any] | None) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, raw in (value or {}).items():
        key = str(key)
        if isinstance(raw, (str, int, float, bool)) or raw is None:
            result[key] = str(raw)[:MAX_PROVENANCE_TEXT] if isinstance(raw, str) else raw
        elif isinstance(raw, list):
            result[key] = [str(item)[:MAX_PROVENANCE_TEXT] for item in raw[:64]]
    return result


def make_row(collection: str, collector_id: str, values: Mapping[str, Any], *, observed_at: str = "", provenance: Mapping[str, Any] | None = None) -> dict[str, Any]:
    collection = str(collection or "")
    collector_id = str(collector_id or "")
    if collection not in OBSERVATION_TYPES:
        raise ValueError(f"unknown collector observation type: {collection}")
    collector = collector_map().get(collector_id)
    if collector is None:
        raise ValueError(f"unknown collector id: {collector_id}")
    if collection not in (collector.get("provides") or []):
        raise ValueError(f"collector {collector_id} does not provide {collection}")
    row = dict(values)
    row["_collector"] = {
        "id": collector_id,
        "version": int(collector.get("version") or 0),
        "componentId": str(collector.get("componentId") or ""),
        "observedAtUtc": observed_at or utc_now(),
    }
    cleaned = _clean_provenance(provenance)
    if cleaned:
        row["_provenance"] = cleaned
    return row


def build_bundle(collection_rows: Mapping[str, Iterable[Mapping[str, Any]]], *, generated_at: str = "", component_id: str = "") -> dict[str, Any]:
    collections: dict[str, Any] = {}
    total = 0
    for name in sorted(collection_rows):
        if name not in OBSERVATION_TYPES:
            raise ValueError(f"unknown collector observation type: {name}")
        rows = [dict(row) for row in collection_rows[name] if isinstance(row, Mapping)]
        if len(rows) > MAX_ROWS_PER_COLLECTION:
            raise ValueError(f"collector collection {name} exceeds {MAX_ROWS_PER_COLLECTION} rows")
        total += len(rows)
        if total > MAX_BUNDLE_ROWS:
            raise ValueError(f"collector observation bundle exceeds {MAX_BUNDLE_ROWS} rows")
        provider_ids: set[str] = set()
        provider_components: set[str] = set()
        for row in rows:
            meta = row.get("_collector") if isinstance(row.get("_collector"), Mapping) else {}
            collector_id = str(meta.get("id") or "")
            if collector_id not in providers_for(name):
                raise ValueError(f"row in {name} has unregistered provider {collector_id!r}")
            provider_ids.add(collector_id)
            provider_components.add(str(meta.get("componentId") or ""))
        if component_id and any(value and value != component_id for value in provider_components):
            raise ValueError(f"collector bundle component {component_id!r} does not match row providers {sorted(provider_components)!r}")
        collections[name] = {
            "schema": OBSERVATION_TYPES[name]["schema"],
            "semanticClass": OBSERVATION_TYPES[name]["semanticClass"],
            "authority": OBSERVATION_TYPES[name]["authority"],
            "completeness": "retained-snapshot",
            "records": len(rows),
            "providers": sorted(provider_ids),
            "recordDigest": _sha(rows),
            "rows": rows,
        }
    return {
        "schema": BUNDLE_SCHEMA,
        "registryRevision": registry_revision(),
        "componentId": component_id or (
            next((str((row.get("_collector") or {}).get("componentId") or "") for descriptor in collections.values() for row in descriptor.get("rows", []) if isinstance(row, Mapping)), "")
            or DISCOVERY_COMPONENT_ID
        ),
        "generatedAtUtc": generated_at or utc_now(),
        "records": total,
        "collections": collections,
    }


def rows_from_bundle(bundle: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
    if str(bundle.get("schema") or "") != BUNDLE_SCHEMA:
        raise ValueError(f"collector bundle schema must be {BUNDLE_SCHEMA}")
    result: dict[str, list[dict[str, Any]]] = {}
    for name, descriptor in (bundle.get("collections") or {}).items():
        if name not in OBSERVATION_TYPES or not isinstance(descriptor, Mapping):
            continue
        rows = descriptor.get("rows") if isinstance(descriptor.get("rows"), list) else []
        result[str(name)] = [dict(row) for row in rows if isinstance(row, Mapping)]
    return result


def bundle_contract(bundle: Mapping[str, Any]) -> dict[str, Any]:
    """Project a collector bundle into the generic contract shape consumed by Stigma-1 replay gates."""
    collections: dict[str, Any] = {}
    for name, descriptor in (bundle.get("collections") or {}).items():
        if name not in OBSERVATION_TYPES or not isinstance(descriptor, Mapping):
            continue
        collections[str(name)] = {
            "collectionSchema": str(descriptor.get("schema") or OBSERVATION_TYPES[name]["schema"]),
            "records": int(descriptor.get("records") or 0),
            "recordDigest": str(descriptor.get("recordDigest") or ""),
            "completeness": str(descriptor.get("completeness") or "retained-snapshot"),
            "providers": list(descriptor.get("providers") or []),
        }
    return {
        "schema": BUNDLE_SCHEMA,
        "contractRevision": str(bundle.get("registryRevision") or registry_revision()),
        "collections": collections,
    }


def replay_audit(contract: Mapping[str, Any], required_collections: Iterable[str]) -> dict[str, Any]:
    available = contract.get("collections") if isinstance(contract.get("collections"), Mapping) else {}
    required = sorted({str(item) for item in required_collections if str(item) in OBSERVATION_TYPES})
    missing: list[str] = []
    incomplete: list[str] = []
    for name in required:
        item = available.get(name) if isinstance(available.get(name), Mapping) else None
        if item is None:
            missing.append(name)
        elif str(item.get("completeness") or "") not in {"retained", "retained-snapshot", "complete"}:
            incomplete.append(name)
    return {
        "requiredCollections": required,
        "reusable": not missing and not incomplete,
        "missingCollections": missing,
        "incompleteCollections": incomplete,
    }


def compile_observation_request(value: Any) -> dict[str, Any] | None:
    if value in (None, {}, ""):
        return None
    if not isinstance(value, Mapping):
        raise ValueError("observationRequest must be a mapping")
    allowed = {"schema", "collection", "reason", "priority"}
    extras = sorted(str(key) for key in value if str(key) not in allowed)
    if extras:
        raise ValueError(f"observationRequest contains unsupported fields: {extras}")
    if value.get("schema") not in (None, "", REQUEST_SCHEMA):
        raise ValueError(f"observationRequest schema must be {REQUEST_SCHEMA}")
    collection = str(value.get("collection") or "").strip()
    if collection not in OBSERVATION_TYPES or not bool(OBSERVATION_TYPES[collection].get("ruleEligible")):
        raise ValueError(f"observationRequest collection is not a registered rule-eligible collector observation: {collection!r}")
    reason = str(value.get("reason") or "").strip()
    if not reason or len(reason) > 500:
        raise ValueError("observationRequest.reason must be 1..500 characters")
    try:
        priority = int(value.get("priority") or 500)
    except (TypeError, ValueError) as exc:
        raise ValueError("observationRequest.priority must be an integer") from exc
    if priority < 0 or priority > 1000:
        raise ValueError("observationRequest.priority must be between 0 and 1000")
    return {"schema": REQUEST_SCHEMA, "collection": collection, "reason": reason, "priority": priority}


def resolve_observation_request(request: Mapping[str, Any]) -> dict[str, Any]:
    compiled = compile_observation_request(request)
    if compiled is None:
        raise ValueError("observation request is empty")
    providers = providers_for(compiled["collection"])
    all_providers = providers_for(compiled["collection"], include_planned=True)
    collectors = collector_map()
    provider_components = sorted({str((collectors.get(item) or {}).get("componentId") or "") for item in providers if item})
    dispatchable_components = [item for item in provider_components if component_registry.is_dispatchable(item)]
    return {
        "schema": REQUEST_RESULT_SCHEMA,
        **compiled,
        "providerCandidates": providers,
        "plannedProviderCandidates": sorted(set(all_providers) - set(providers)),
        "providerComponents": provider_components,
        "dispatchableComponents": dispatchable_components,
        "freshness": freshness_policy(compiled["collection"]),
        "satisfiable": bool(providers),
        "dispatchable": bool(dispatchable_components),
        "executionAuthority": "orchestrator-only",
        "controlPlaneAuthority": "main",
    }
