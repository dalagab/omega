"""Static DeltaScope rule-author data reference.

SRL v1 compilation/evaluation is implemented in ``srl.py`` for local/DeltaScope use,
and Definition Pack v1 freezing is implemented; the first reviewed primitive fact producers and compound correlations now have enforced migration parity plus retained-Evidence replay tooling, while production projection remains disabled pending compatible 2.15 corpus replay/cutover approval.
This module is the typed evidence vocabulary shared with that compiler.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

CATALOG_DIR = Path(__file__).resolve().parents[1] / "catalog"
if str(CATALOG_DIR) not in sys.path:
    sys.path.insert(0, str(CATALOG_DIR))
from capability_registry import load_registry  # noqa: E402
import observation_projection  # noqa: E402
import collector_contracts  # noqa: E402

SCHEMA = "omega.deltascope.rule-author-reference.v1"

SECURITY_COLLECTIONS: dict[str, dict[str, Any]] = {
    "managedCallSites": {
        "dataset": "calls",
        "source": "plugin_security_managed_calls",
        "scope": "immutable normalized observation",
        "fields": {
            "origin": "string", "path": "string", "sourceMethodToken": "string", "sourceDeclaringType": "string",
            "sourceMethodName": "string", "ilOffset": "integer", "opcode": "string", "targetToken": "string",
            "targetKind": "string", "targetDeclaringType": "string", "targetName": "string", "targetAssemblyName": "string",
            "targetNativeLibrary": "string", "targetNativeEntryPoint": "string", "targetMethodToken": "string", "evidence": "string[]",
        },
        "notes": "Same-record matching is required: fields in one selector must come from the same call row.",
    },
    "managedReachability": {
        "dataset": "reachability",
        "source": "plugin_security_managed_reachability",
        "scope": "immutable normalized observation",
        "fields": {"origin": "string", "path": "string", "methodToken": "string", "depth": "integer", "rootMethodToken": "string", "evidence": "string[]"},
    },
    "binaryClassifications": {
        "dataset": "binaryClassifications",
        "source": "dependencyIntelligence.binaryClassifications",
        "scope": "immutable normalized artifact binary-format observation",
        "fields": {
            "path": "string", "filename": "string", "format": "string", "kind": "string",
            "role": "string", "architecture": "string", "bitness": "integer", "sha256": "string",
            "bytesExamined": "integer", "managedCliHeader": "boolean", "sectionCount": "integer",
            "writableExecutableSections": "string[]", "highEntropySections": "string[]",
            "importLibraryCount": "integer", "importFunctionCount": "integer",
        },
        "notes": "Format/structure observation only. PE certificate-table presence is not Authenticode trust; use binarySignatureTrust for platform signature validation.",
    },
    "nativeImports": {
        "dataset": "nativeImports",
        "source": "dependencyIntelligence.nativeImports (retained as a Phase-4 observation dataset); managed-call native targets remain a second concrete source",
        "scope": "immutable normalized observation",
        "fields": {"origin": "string", "path": "string", "library": "string", "entryPoint": "string", "evidence": "string[]"},
    },
    "permissionCandidates": {
        "dataset": "permissions",
        "source": "plugin_security_permission_candidates",
        "scope": "derived capability candidate; useful for migration, not the final SRL observation boundary",
        "fields": {"origin": "string", "permissionId": "capability-id", "risk": "string", "confidence": "string", "reason": "string", "evidence": "string[]"},
    },
    "automationCapabilities": {
        "dataset": "automation",
        "source": "plugin_security_automation_capabilities",
        "scope": "derived automation capability",
        "fields": {"capabilityId": "capability-id", "label": "string", "automationLevel": "string", "confidence": "string", "reachable": "boolean", "indirect": "boolean", "reason": "string", "evidence": "string[]"},
    },
    "dependencies": {
        "dataset": "dependencies",
        "source": "plugin_security_dependencies",
        "scope": "immutable normalized observation",
        "fields": {"origin": "string", "kind": "string", "name": "string", "version": "string", "versionRequirement": "string", "resolvedVersion": "string", "path": "string", "status": "string", "requirement": "string", "relationship": "string", "relationshipConfidence": "string", "evidence": "string[]"},
    },
    "ipcIntegrations": {
        "dataset": "ipc",
        "source": "plugin_security_ipc_endpoints",
        "scope": "immutable normalized observation",
        "fields": {"origin": "string", "role": "string", "channel": "string", "signature": "string", "path": "string", "status": "string", "relationship": "string", "relationshipConfidence": "string", "evidence": "string[]"},
    },
    "networkEndpoints": {
        "dataset": "compact scan report / endpoint summary",
        "source": "dependencyIntelligence.networkEndpoints",
        "scope": "normalized endpoint observation",
        "fields": {
            "url": "string", "host": "string", "origin": "string", "originType": "string",
            "classification": "string", "purpose": "string", "confidence": "string",
            "concreteDestinationEvidence": "boolean", "evidence": "string[]",
            "resolvedIps": "string[]", "threatIntelMatched": "boolean", "threatIntelActive": "boolean",
            "threatIntelRisk": "string", "threatIntelCategories": "string[]", "threatIntelSources": "string[]",
            "threatIntelIndicatorIds": "string[]", "threatIntelRevision": "string",
        },
        "notes": "The endpoint observation is immutable plugin evidence. threatIntel* and resolvedIps are deterministic frozen-Definitions enrichment over that retained endpoint. A daily threat-intelligence change can therefore be SRL-reprojected without reopening the plugin artifact.",
    },
    "staticPatternMatches": {
        "dataset": "staticPatternMatches",
        "source": "dependencyIntelligence.staticPatternMatches",
        "scope": "immutable normalized literal-pattern observation",
        "fields": {"origin": "string", "pattern": "string", "evidenceLabel": "string", "evidence": "string[]"},
        "notes": "Low-level case-insensitive literal presence only. Rows intentionally carry no legacy rule ID, capability, severity or finding conclusion; changing the producer vocabulary is an analysis-semantic change and may require targeted re-analysis.",
    },
    "sourceBuildProjects": {
        "dataset": "sourceBuildProjects",
        "source": "source.dependencyIntelligence.sourceBuildProjects",
        "scope": "immutable selected source-build project observation",
        "fields": {
            "origin": "string", "path": "string", "role": "string", "sdk": "string",
            "targetFrameworks": "string[]", "runtimeIdentifiers": "string[]", "outputType": "string",
            "assemblyName": "string", "rootNamespace": "string", "langVersion": "string", "nullable": "string",
            "allowUnsafeBlocks": "boolean", "publishAot": "boolean", "selfContained": "boolean",
            "publishTrimmed": "boolean", "publishReadyToRun": "boolean", "useWpf": "boolean",
            "useWindowsForms": "boolean", "packageReferenceCount": "integer", "projectReferenceCount": "integer",
            "importCount": "integer", "conditionalItemCount": "integer",
        },
        "notes": "Developer-authored build configuration only; it does not prove how a distributed artifact was built.",
    },
    "sourceBuildEdges": {
        "dataset": "sourceBuildEdges",
        "source": "source.dependencyIntelligence.sourceBuildEdges",
        "scope": "immutable selected source-build graph edge",
        "fields": {
            "origin": "string", "fromProject": "string", "toProject": "string", "condition": "string",
            "privateAssets": "string", "referenceOutputAssembly": "boolean",
        },
    },
    "sourceBuildInputs": {
        "dataset": "sourceBuildInputs",
        "source": "source.dependencyIntelligence.sourceBuildInputs",
        "scope": "immutable source-build input identity",
        "fields": {"origin": "string", "path": "string", "kind": "string", "role": "string", "sha256": "string", "bytes": "integer"},
    },
    "sourceBuildEnvironment": {
        "dataset": "sourceBuildEnvironment",
        "source": "source.dependencyIntelligence.sourceBuildEnvironment",
        "scope": "developer-authored toolchain/build-policy context",
        "fields": {
            "origin": "string", "path": "string", "kind": "string", "sdkVersion": "string", "rollForward": "string",
            "allowPrerelease": "boolean", "packageSources": "string[]",
            "managePackageVersionsCentrally": "boolean", "restoreLockedMode": "boolean",
        },
        "notes": "Context only; package sources and SDK declarations do not establish build provenance by themselves.",
    },
    "sourceDependencyDeclarations": {
        "dataset": "sourceDependencyDeclarations",
        "source": "source.dependencyIntelligence.sourceDependencyDeclarations",
        "scope": "immutable source dependency declaration/lock observation",
        "fields": {
            "origin": "string", "sourceKind": "string", "path": "string", "projectPath": "string",
            "targetFramework": "string", "kind": "string", "name": "string", "versionExpression": "string",
            "resolvedVersion": "string", "contentHash": "string", "condition": "string", "privateAssets": "string",
            "includeAssets": "string", "excludeAssets": "string", "aliases": "string",
            "direct": "boolean", "transitive": "boolean",
        },
    },
    "sourceReleaseWorkflows": {
        "dataset": "sourceReleaseWorkflows",
        "source": "source.dependencyIntelligence.sourceReleaseWorkflows",
        "scope": "bounded developer-authored CI/release construction context",
        "fields": {
            "origin": "string", "path": "string", "name": "string", "triggers": "string[]", "jobs": "string[]",
            "runners": "string[]", "actions": "string[]", "dotnetVerbs": "string[]", "dotnetTargets": "string[]",
            "uploadsArtifacts": "boolean", "downloadsArtifacts": "boolean", "publishesRelease": "boolean",
            "truncated": "boolean", "sha256": "string", "bytes": "integer", "identityMatched": "boolean",
        },
        "notes": "A workflow is source context, not proof that a published plugin artifact came from that workflow.",
    },
    "sourceAttribution": {
        "dataset": "compact scan report",
        "source": "source.attribution",
        "scope": "provenance evidence",
        "fields": {"confidence": "integer", "coverageLabel": "string", "basis": "string[]"},
    },
    "sourceProvenance": {
        "dataset": "compact scan report",
        "source": "source.provenance",
        "scope": "provenance evidence",
        "fields": {"selectedRef": "string", "selectedRefKind": "string", "identityMatched": "boolean", "versionMatched": "boolean", "manifestRepositoryMatched": "boolean", "artifactOriginMatched": "boolean", "sourceToBinaryVerified": "boolean", "reproducibleSourceToArtifact": "boolean"},
    },
    "developerProfile": {
        "dataset": "compact scan report",
        "source": "source.developerProfile.profile",
        "scope": "untrusted developer declaration; consistency rules only",
        "fields": {
            "profile.tagline": "string", "profile.description": "string", "capabilities[].id": "capability-id",
            "capabilities[].expected": "boolean", "capabilities[].required": "boolean", "capabilities[].reason": "string",
            "capabilities[].destinations": "string[]", "services[].url": "https-url", "services[].purpose": "string",
            "nativeComponents[].name": "string", "ipc[].plugin": "string", "ipc[].channel": "string",
        },
        "notes": "Developer declarations never suppress or downgrade scanner evidence.",
    },
    "behaviorConsistency": {
        "dataset": "compact scan report / marketplace projection",
        "source": "behaviorConsistency",
        "scope": "derived developer-claim vs independent-observation comparison; presentation/research only",
        "fields": {
            "summary.observedUndeclaredCount": "integer", "summary.notExpectedObservedCount": "integer",
            "summary.expectedNotObservedCount": "integer", "summary.unexplainedDestinationCount": "integer",
            "capabilities[].id": "capability-id", "capabilities[].state": "string",
            "destinations.explained[].host": "string", "destinations.unexplained[].host": "string",
        },
        "notes": "Do not author production SRL rules against behaviorConsistency itself: it is already a derived projection. Author consistency rules from immutable observations plus developerProfile to avoid recursive conclusions.",
    },
    "secondarySecurity": {
        "dataset": "compact scan report",
        "source": "secondarySecurity",
        "scope": "supplemental hygiene evidence",
        "fields": {"engines[].engine": "string", "engines[].status": "string", "engines[].matches": "object[]", "matchCount": "integer"},
        "notes": "YARA/ClamAV remain separate engines; SRL should correlate their bounded results only when policy permits.",
    },
}


def _collector_authoring_collections() -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for name, spec in collector_contracts.OBSERVATION_TYPES.items():
        result[name] = {
            "dataset": "collector observation bundle",
            "source": ", ".join(collector_contracts.providers_for(name, include_planned=True)),
            "scope": str(spec.get("semanticClass") or "collector observation"),
            "fields": dict(spec.get("fields") or {}),
            "notes": "Rules bind to this logical observation type, not to a collector implementation. Provider provenance is retained on each row.",
            "authority": str(spec.get("authority") or "context-only"),
            "providers": collector_contracts.providers_for(name, include_planned=True),
        }
    return result


COLLECTIONS: dict[str, dict[str, Any]] = {**SECURITY_COLLECTIONS, **_collector_authoring_collections()}


def build_reference() -> dict[str, Any]:
    registry = load_registry()
    return {
        "schema": SCHEMA,
        "status": "srl-v1-phase7-static-observation-replay-production-disabled",
        "productionRuleEvaluationEnabled": False,
        "warning": "DeltaScope can compile/evaluate SRL v1 locally and Daily Definitions freezes reviewed Definition Packs. Fourteen reviewed literal-backed primitive fact producers and two compound correlations now have exhaustive legacy parity plus retained-Evidence replay tooling, but production SRL projection remains gated until compatible 2.15 observations have been collected and corpus replay/cutover review succeeds. Candidate YAML cannot affect production evidence.",
        "sameRecordSemantics": True,
        "observationBoundary": observation_projection.build_schema_reference(),
        "capabilityRegistry": {
            "schema": registry.get("schema"),
            "revision": registry.get("revision"),
            "categories": registry.get("categories"),
            "capabilities": registry.get("capabilities"),
        },
        "collections": COLLECTIONS,
        "collectorRegistry": collector_contracts.build_registry(),
        "ruleCollectorBinding": "logical observation type; collector implementation IDs are provenance/provider-resolution only",
        "implementedOperators": ["equals", "equals-ci", "in", "in-ci", "contains", "contains-ci", "starts-with", "starts-with-ci", "ends-with", "ends-with-ci", "exists", "missing", "gt", "gte", "lt", "lte", "all", "any", "not", "count"],
        "plannedOperators": ["equals", "equals-ci", "in", "in-ci", "contains", "contains-ci", "starts-with", "starts-with-ci", "ends-with", "ends-with-ci", "exists", "missing", "gt", "gte", "lt", "lte", "all", "any", "not", "count"],
        "forbiddenRuleActions": ["execute code", "open arbitrary files", "network requests", "spawn processes", "raw SQL", "environment access", "developer-authority override"],
    }


def to_json() -> str:
    return json.dumps(build_reference(), indent=2, ensure_ascii=False, sort_keys=True)
