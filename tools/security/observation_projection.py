"""SigmaScope observation/projection contract helpers.

Phase 4 deliberately separates *retained evidence inputs* from conclusions produced by
SigmaScope's current rule/evaluation code.  The physical Security Evidence v2 layout is
kept backward compatible: historical analyses may still contain projection datasets
beside observations, but the semantic contract labels which collections are eligible as
future SRL inputs and which are derived/current conclusions.

No plugin bytes are opened by this module.  It only classifies and fingerprints already
retained normalized rows/report data, so it can be used to adapt historical 2.14
Evidence-v2 without rescanning a plugin.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable

import collector_contracts

OBSERVATION_CONTRACT_SCHEMA = "omega.sigmascope.observation-contract.v1"
OBSERVATION_COLLECTION_SCHEMA = "omega.sigmascope.observation-collection.v1"
PROJECTION_CONTRACT_SCHEMA = "omega.sigmascope.projection-contract.v1"
REPLAY_AUDIT_SCHEMA = "omega.sigmascope.projection-replay-audit.v1"

# Stable logical collection names. ``backingDataset`` is the current Evidence-v2
# physical name where one exists.  Future transports may move bytes without changing
# these logical contracts.
COLLECTIONS: dict[str, dict[str, Any]] = {
    "dependencies": {
        "schema": "omega.sigmascope.observation.dependencies.v1", "backingDataset": "dependencies",
        "semanticClass": "observation", "srlEligible": True, "origin": "artifact+source",
    },
    "ipcIntegrations": {
        "schema": "omega.sigmascope.observation.ipc.v1", "backingDataset": "ipc",
        "semanticClass": "observation", "srlEligible": True, "origin": "artifact+source",
    },
    "namespaceImports": {
        "schema": "omega.sigmascope.observation.namespace-imports.v1", "backingDataset": "imports",
        "semanticClass": "observation", "srlEligible": True, "origin": "artifact+source",
    },
    "managedAssemblies": {
        "schema": "omega.sigmascope.observation.managed-assemblies.v1", "backingDataset": "assemblies",
        "semanticClass": "observation", "srlEligible": True, "origin": "artifact+source",
    },
    "managedSymbols": {
        "schema": "omega.sigmascope.observation.managed-symbols.v1", "backingDataset": "symbols",
        "semanticClass": "observation", "srlEligible": True, "origin": "artifact+source",
    },
    "managedCallSites": {
        "schema": "omega.sigmascope.observation.managed-calls.v1", "backingDataset": "calls",
        "semanticClass": "observation", "srlEligible": True, "origin": "artifact+source",
        "sameRecordSemantics": True,
    },
    "managedReachability": {
        "schema": "omega.sigmascope.observation.managed-reachability.v1", "backingDataset": "reachability",
        "semanticClass": "observation", "srlEligible": True, "origin": "artifact+source",
    },
    "nativeImports": {
        "schema": "omega.sigmascope.observation.native-imports.v1", "backingDataset": "nativeImports",
        "semanticClass": "observation", "srlEligible": True, "origin": "artifact+source",
    },
    "networkEndpoints": {
        "schema": "omega.sigmascope.observation.network-endpoints.v1", "backingDataset": "networkEndpoints",
        "semanticClass": "observation", "srlEligible": True, "origin": "artifact+source",
    },
    "staticPatternMatches": {
        "schema": "omega.sigmascope.observation.static-pattern-matches.v1", "backingDataset": "staticPatternMatches",
        "semanticClass": "observation", "srlEligible": True, "origin": "artifact+source",
        "sameRecordSemantics": True,
    },
    "sourceFiles": {
        "schema": "omega.sigmascope.observation.source-files.v1", "backingDataset": "sourceFiles",
        "semanticClass": "observation", "srlEligible": True, "origin": "source",
    },
    "sourceBuildProjects": {
        "schema": "omega.sigmascope.observation.source-build-project.v1", "backingDataset": "sourceBuildProjects",
        "semanticClass": "source-build-observation", "srlEligible": True, "origin": "source",
    },
    "sourceBuildEdges": {
        "schema": "omega.sigmascope.observation.source-build-edge.v1", "backingDataset": "sourceBuildEdges",
        "semanticClass": "source-build-observation", "srlEligible": True, "origin": "source",
    },
    "sourceBuildInputs": {
        "schema": "omega.sigmascope.observation.source-build-input.v1", "backingDataset": "sourceBuildInputs",
        "semanticClass": "source-build-provenance", "srlEligible": True, "origin": "source",
    },
    "sourceBuildEnvironment": {
        "schema": "omega.sigmascope.observation.source-build-environment.v1", "backingDataset": "sourceBuildEnvironment",
        "semanticClass": "source-build-context", "srlEligible": True, "origin": "source",
        "authority": "developer-source-context-only",
    },
    "sourceDependencyDeclarations": {
        "schema": "omega.sigmascope.observation.source-dependency-declaration.v1", "backingDataset": "sourceDependencyDeclarations",
        "semanticClass": "source-dependency-observation", "srlEligible": True, "origin": "source",
    },
    "sourceReleaseWorkflows": {
        "schema": "omega.sigmascope.observation.source-release-workflow.v1", "backingDataset": "sourceReleaseWorkflows",
        "semanticClass": "source-build-context", "srlEligible": True, "origin": "source",
        "authority": "developer-source-context-only",
    },
    "sourceOperations": {
        "schema": "omega.sigmascope.observation.source-operation.v1", "backingDataset": "sourceOperations",
        "semanticClass": "source-behavior-observation", "srlEligible": True, "origin": "source", "sameRecordSemantics": True,
    },
    "sourceFlowEdges": {
        "schema": "omega.sigmascope.observation.source-flow-edge.v1", "backingDataset": "sourceFlowEdges",
        "semanticClass": "source-behavior-observation", "srlEligible": True, "origin": "source", "sameRecordSemantics": True,
    },
    "sourceTriggers": {
        "schema": "omega.sigmascope.observation.source-trigger.v1", "backingDataset": "sourceTriggers",
        "semanticClass": "source-behavior-observation", "srlEligible": True, "origin": "source", "sameRecordSemantics": True,
    },
    "sourceConditions": {
        "schema": "omega.sigmascope.observation.source-condition.v1", "backingDataset": "sourceConditions",
        "semanticClass": "source-behavior-observation", "srlEligible": True, "origin": "source", "sameRecordSemantics": True,
    },
    "sourceDataFlow": {
        "schema": "omega.sigmascope.observation.source-data-flow.v1", "backingDataset": "sourceDataFlow",
        "semanticClass": "source-behavior-observation", "srlEligible": True, "origin": "source", "sameRecordSemantics": True,
    },
    "binaryClassifications": {
        "schema": "omega.sigmascope.observation.binary-classifications.v1", "backingDataset": "binaryClassifications",
        "semanticClass": "observation", "srlEligible": True, "origin": "artifact",
    },
    "artifactIdentity": {
        "schema": "omega.sigmascope.observation.artifact-identity.v1", "backingDataset": "artifactIdentity",
        "semanticClass": "provenance", "srlEligible": True, "origin": "artifact",
    },
    "manifestObservation": {
        "schema": "omega.sigmascope.observation.manifest.v1", "backingDataset": "manifestObservation",
        "semanticClass": "provenance", "srlEligible": True, "origin": "catalog",
    },
    "sourceAttribution": {
        "schema": "omega.sigmascope.observation.source-attribution.v1", "backingDataset": "sourceAttribution",
        "semanticClass": "provenance", "srlEligible": True, "origin": "source",
    },
    "sourceProvenance": {
        "schema": "omega.sigmascope.observation.source-provenance.v1", "backingDataset": "sourceProvenance",
        "semanticClass": "provenance", "srlEligible": True, "origin": "source",
    },
    "developerProfile": {
        "schema": "omega.sigmascope.input.developer-profile.v1", "backingDataset": "developerProfile",
        "semanticClass": "developer-claim", "srlEligible": True, "origin": "source",
        "authority": "untrusted-context-only",
    },
    "secondarySecurity": {
        "schema": "omega.sigmascope.observation.secondary-security.v1", "backingDataset": "secondarySecurity",
        "semanticClass": "hygiene-evidence", "srlEligible": True, "origin": "artifact",
        "authority": "supplemental-only",
    },
}

# Datasets retained for historical compatibility but explicitly *not* valid raw SRL
# observation inputs. New rules must use the underlying observation collections.
PROJECTION_DATASETS: dict[str, dict[str, Any]] = {
    "findings": {"schema": "omega.sigmascope.projection.findings.v1", "semanticClass": "projection", "srlEligible": False},
    "permissions": {"schema": "omega.sigmascope.projection.permission-candidates.v1", "semanticClass": "projection", "srlEligible": False},
    "automation": {"schema": "omega.sigmascope.projection.automation.v1", "semanticClass": "projection", "srlEligible": False},
}


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _record_digest(rows: Iterable[dict[str, Any]]) -> tuple[int, str]:
    hashes = sorted(_sha(dict(row)) for row in rows)
    digest = hashlib.sha256()
    for item in hashes:
        digest.update(item.encode("ascii"))
        digest.update(b"\n")
    return len(hashes), digest.hexdigest()


def contract_revision() -> str:
    semantic = {
        "schema": OBSERVATION_CONTRACT_SCHEMA,
        "collections": COLLECTIONS,
        "projectionDatasets": PROJECTION_DATASETS,
    }
    return f"observations-v1-{_sha(semantic)[:16]}"


def compatible_contract_revision(value: Any) -> bool:
    """Return whether a declared v1 observation contract can be replay-audited.

    The revision fingerprints the *registry available when the evidence was written*,
    not the immutable observation bytes themselves.  Additive collection-registry
    growth therefore must not retroactively corrupt older Evidence-v2 rows.  A v1
    declaration is accepted here only as a compatibility envelope; every declared
    collection is still validated below against the current schema/eligibility
    contract, its retained descriptor/digest and the immutable analysis manifest.

    Incompatible semantic changes must advance the contract schema/version rather than
    silently reusing the v1 revision prefix.
    """
    revision = str(value or "")
    prefix = "observations-v1-"
    if not revision.startswith(prefix):
        return False
    suffix = revision[len(prefix):]
    return len(suffix) == 16 and all(char in "0123456789abcdef" for char in suffix)


def projection_contract_revision() -> str:
    semantic = {"schema": PROJECTION_CONTRACT_SCHEMA, "projectionDatasets": PROJECTION_DATASETS}
    return f"projection-contract-v1-{_sha(semantic)[:16]}"


def annotate_analysis_datasets(datasets: dict[str, Any]) -> dict[str, Any]:
    """Add semantic collection metadata without changing records/digests."""
    result: dict[str, Any] = {}
    by_backing = {str(spec["backingDataset"]): (name, spec) for name, spec in COLLECTIONS.items()}
    for dataset_name, descriptor in sorted((datasets or {}).items()):
        item = dict(descriptor or {}) if isinstance(descriptor, dict) else {}
        logical = by_backing.get(str(dataset_name))
        projection = PROJECTION_DATASETS.get(str(dataset_name))
        if logical:
            logical_name, spec = logical
            item.update({
                "collection": logical_name,
                "collectionSchema": spec["schema"],
                "semanticClass": spec["semanticClass"],
                "srlEligible": bool(spec.get("srlEligible")),
            })
            if spec.get("sameRecordSemantics"):
                item["sameRecordSemantics"] = True
        elif projection:
            item.update({
                "collectionSchema": projection["schema"],
                "semanticClass": projection["semanticClass"],
                "srlEligible": False,
            })
        else:
            item.update({"semanticClass": "transport-compatibility", "srlEligible": False})
        result[str(dataset_name)] = item
    return result


def analysis_observation_contract(datasets: dict[str, Any]) -> dict[str, Any]:
    annotated = annotate_analysis_datasets(datasets)
    collections: dict[str, Any] = {}
    for dataset_name, descriptor in annotated.items():
        logical = str(descriptor.get("collection") or "")
        if not logical:
            continue
        collections[logical] = {
            "schema": OBSERVATION_COLLECTION_SCHEMA,
            "collectionSchema": str(descriptor.get("collectionSchema") or ""),
            "backingDataset": dataset_name,
            "records": int(descriptor.get("records") or 0),
            "recordDigest": str(descriptor.get("recordDigest") or ""),
            "semanticClass": str(descriptor.get("semanticClass") or "observation"),
            "srlEligible": bool(descriptor.get("srlEligible")),
            "completeness": "retained",
        }
    digest_payload = [
        {"collection": name, "records": item["records"], "recordDigest": item["recordDigest"], "schema": item["collectionSchema"]}
        for name, item in sorted(collections.items())
    ]
    return {
        "schema": OBSERVATION_CONTRACT_SCHEMA,
        "contractRevision": contract_revision(),
        "observationDigest": f"obs-{_sha(digest_payload)}",
        "collections": collections,
    }


def _report(report_or_row: dict[str, Any]) -> dict[str, Any]:
    value: Any = report_or_row.get("report_json") if isinstance(report_or_row, dict) and "report_json" in report_or_row else report_or_row
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except Exception:
            value = {}
    return value if isinstance(value, dict) else {}


def report_observation_rows(report_or_row: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Extract observation/input rows that historically existed only inside report_json.

    This function intentionally excludes findings, capability projections, automation
    conclusions, endpoint/component summaries, and behaviorConsistency.
    """
    report = _report(report_or_row)
    intelligence = report.get("dependencyIntelligence") if isinstance(report.get("dependencyIntelligence"), dict) else {}
    source = report.get("source") if isinstance(report.get("source"), dict) else {}
    source_intel = source.get("dependencyIntelligence") if isinstance(source.get("dependencyIntelligence"), dict) else {}
    source_build = source_intel.get("sourceBuildIntelligence") if isinstance(source_intel.get("sourceBuildIntelligence"), dict) else {}
    source_behavior = source_intel.get("sourceBehavior") if isinstance(source_intel.get("sourceBehavior"), dict) else {}
    package = report.get("package") if isinstance(report.get("package"), dict) else {}

    profile = source.get("developerProfile") if isinstance(source.get("developerProfile"), dict) else {}
    attribution = source.get("attribution") if isinstance(source.get("attribution"), dict) else {}
    provenance = source.get("provenance") if isinstance(source.get("provenance"), dict) else {}
    secondary = report.get("secondarySecurity") if isinstance(report.get("secondarySecurity"), dict) else {}
    artifact_identity = report.get("artifactIdentity") if isinstance(report.get("artifactIdentity"), dict) else {}
    manifest = report.get("manifestObservation") if isinstance(report.get("manifestObservation"), dict) else {}

    rows: dict[str, list[dict[str, Any]]] = {
        "nativeImports": [dict(item) for item in intelligence.get("nativeImports") or [] if isinstance(item, dict)],
        "networkEndpoints": [dict(item) for item in intelligence.get("networkEndpoints") or [] if isinstance(item, dict)],
        "staticPatternMatches": [dict(item) for item in intelligence.get("staticPatternMatches") or [] if isinstance(item, dict)],
        "sourceFiles": [dict(item) for item in source_intel.get("sourceFiles") or intelligence.get("sourceFiles") or [] if isinstance(item, dict)],
        "sourceOperations": [dict(item) for item in source_behavior.get("operations") or [] if isinstance(item, dict)],
        "sourceFlowEdges": [dict(item) for item in source_behavior.get("flowEdges") or [] if isinstance(item, dict)],
        "sourceTriggers": [dict(item) for item in source_behavior.get("triggers") or [] if isinstance(item, dict)],
        "sourceConditions": [dict(item) for item in source_behavior.get("conditions") or [] if isinstance(item, dict)],
        "sourceDataFlow": [dict(item) for item in source_behavior.get("dataFlow") or [] if isinstance(item, dict)],
        "sourceBuildProjects": [dict(item) for item in source_build.get("projects") or [] if isinstance(item, dict)],
        "sourceBuildEdges": [dict(item) for item in source_build.get("edges") or [] if isinstance(item, dict)],
        "sourceBuildInputs": [dict(item) for item in source_build.get("inputs") or [] if isinstance(item, dict)],
        "sourceBuildEnvironment": [dict(item) for item in source_build.get("environment") or [] if isinstance(item, dict)],
        "sourceDependencyDeclarations": [dict(item) for item in source_build.get("dependencies") or [] if isinstance(item, dict)],
        "sourceReleaseWorkflows": [dict(item) for item in source_build.get("releaseWorkflows") or [] if isinstance(item, dict)],
        "binaryClassifications": [dict(item) for item in package.get("binaryClassifications") or [] if isinstance(item, dict)],
        "developerProfile": [dict(profile)] if profile else [],
        "sourceAttribution": [dict(attribution)] if attribution else [],
        "sourceProvenance": [dict(provenance)] if provenance else [],
        "secondarySecurity": [dict(secondary)] if secondary else [],
        "artifactIdentity": [dict(artifact_identity)] if artifact_identity else [],
        "manifestObservation": [dict(manifest)] if manifest else [],
    }
    return rows


def report_collection_complete(report_or_row: dict[str, Any], collection_name: str) -> bool:
    """Return whether an empty report-only collection is explicitly complete.

    Historical reports did not retain static pattern observations at all.  New scans
    carry a provider contract marker even when the match set is empty, allowing the
    Evidence-v2 exporter to distinguish a complete negative result from missing legacy
    evidence without consulting any current finding projection.
    """
    report = _report(report_or_row)
    intelligence = report.get("dependencyIntelligence") if isinstance(report.get("dependencyIntelligence"), dict) else {}
    if collection_name == "staticPatternMatches":
        return int(intelligence.get("staticPatternMatchContractVersion") or 0) == 1
    if collection_name in {
        "sourceBuildProjects", "sourceBuildEdges", "sourceBuildInputs", "sourceBuildEnvironment",
        "sourceDependencyDeclarations", "sourceReleaseWorkflows",
    }:
        source = report.get("source") if isinstance(report.get("source"), dict) else {}
        source_intel = source.get("dependencyIntelligence") if isinstance(source.get("dependencyIntelligence"), dict) else {}
        source_build = source_intel.get("sourceBuildIntelligence") if isinstance(source_intel.get("sourceBuildIntelligence"), dict) else {}
        return int(source_build.get("contractVersion") or 0) == 1
    if collection_name in {
        "sourceOperations", "sourceFlowEdges", "sourceTriggers", "sourceConditions", "sourceDataFlow",
    }:
        source = report.get("source") if isinstance(report.get("source"), dict) else {}
        source_intel = source.get("dependencyIntelligence") if isinstance(source.get("dependencyIntelligence"), dict) else {}
        source_behavior = source_intel.get("sourceBehavior") if isinstance(source_intel.get("sourceBehavior"), dict) else {}
        return int(source_behavior.get("contractVersion") or 0) == 1
    return False


def compact_report_compatibility_collections(report_or_row: dict[str, Any]) -> dict[str, Any]:
    """Describe replay inputs recoverable from historical compact report transport.

    The compact transport intentionally bounds some collections (notably endpoints), so
    these adapters are marked ``bounded-transport`` rather than pretending they are a
    complete immutable observation dataset.
    """
    report = _report(report_or_row)
    intelligence = report.get("intelligence") if isinstance(report.get("intelligence"), dict) else {}
    source = report.get("source") if isinstance(report.get("source"), dict) else {}
    mapping: dict[str, list[dict[str, Any]]] = {
        "networkEndpoints": [dict(item) for item in intelligence.get("networkEndpoints") or [] if isinstance(item, dict)],
        "developerProfile": [dict(source.get("developerProfile"))] if isinstance(source.get("developerProfile"), dict) and source.get("developerProfile") else [],
        "sourceAttribution": [dict(source.get("attribution"))] if isinstance(source.get("attribution"), dict) and source.get("attribution") else [],
        "sourceProvenance": [dict(source.get("provenance"))] if isinstance(source.get("provenance"), dict) and source.get("provenance") else [],
        "secondarySecurity": [dict(report.get("secondarySecurity"))] if isinstance(report.get("secondarySecurity"), dict) and report.get("secondarySecurity") else [],
        "artifactIdentity": [dict(report.get("artifactIdentity"))] if isinstance(report.get("artifactIdentity"), dict) and report.get("artifactIdentity") else [],
        "manifestObservation": [dict(report.get("manifestObservation"))] if isinstance(report.get("manifestObservation"), dict) and report.get("manifestObservation") else [],
    }
    result: dict[str, Any] = {}
    for name, rows in mapping.items():
        if not rows:
            continue
        count, digest = _record_digest(rows)
        spec = COLLECTIONS[name]
        result[name] = {
            "schema": OBSERVATION_COLLECTION_SCHEMA,
            "collectionSchema": spec["schema"],
            "backingDataset": "compact-report",
            "records": count,
            "recordDigest": digest,
            "semanticClass": spec["semanticClass"],
            "srlEligible": bool(spec.get("srlEligible")),
            "completeness": "bounded-transport" if name == "networkEndpoints" else "retained-summary",
        }
    return result


def build_variant_observation_contract(analysis_manifest: dict[str, Any] | None, report_or_row: dict[str, Any]) -> dict[str, Any]:
    datasets = (analysis_manifest or {}).get("datasets") if isinstance((analysis_manifest or {}).get("datasets"), dict) else {}
    base = analysis_observation_contract(datasets)
    collections = dict(base.get("collections") or {})
    for name, descriptor in compact_report_compatibility_collections(report_or_row).items():
        # A full retained observation dataset always wins over compact compatibility.
        if name not in collections:
            collections[name] = descriptor
    report = _report(report_or_row)
    provenance = report.get("scanProvenance") if isinstance(report.get("scanProvenance"), dict) else {}
    digest_payload = [
        {"collection": name, "records": int(item.get("records") or 0), "recordDigest": str(item.get("recordDigest") or ""), "schema": str(item.get("collectionSchema") or ""), "completeness": str(item.get("completeness") or "")}
        for name, item in sorted(collections.items())
    ]
    missing = sorted(name for name, spec in COLLECTIONS.items() if bool(spec.get("srlEligible")) and name not in collections)
    return {
        "schema": OBSERVATION_CONTRACT_SCHEMA,
        "contractRevision": contract_revision(),
        "observationDigest": f"obs-{_sha(digest_payload)}",
        "providerRevisions": {
            "artifactAnalysisRevision": str(report.get("artifactAnalysisRevision") or provenance.get("artifactAnalysisRevision") or ""),
            "sourceAnalysisRevision": str(report.get("sourceAnalysisRevision") or provenance.get("sourceAnalysisRevision") or ""),
        },
        "collections": collections,
        "missingCollections": missing,
        "legacyCompatibility": bool((analysis_manifest or {}).get("observationContract") is None),
    }


def _projection_rows(report: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    findings = [dict(item) for item in report.get("findings") or [] if isinstance(item, dict)]
    capability_ids = [{"id": str(item)} for item in report.get("capabilityIds") or [] if str(item or "")]
    automation = report.get("automation") if isinstance(report.get("automation"), dict) else {}
    automation_rows = [dict(item) for item in automation.get("capabilities") or [] if isinstance(item, dict)]
    behavior = report.get("behaviorConsistency") if isinstance(report.get("behaviorConsistency"), dict) else {}
    behavior_rows = [dict(behavior)] if behavior else []
    return {"findings": findings, "capabilityIds": capability_ids, "automation": automation_rows, "behaviorConsistency": behavior_rows}


def projection_revision(report_or_row: dict[str, Any]) -> str:
    report = _report(report_or_row)
    provenance = report.get("scanProvenance") if isinstance(report.get("scanProvenance"), dict) else {}
    evaluator = {
        "schema": PROJECTION_CONTRACT_SCHEMA,
        "contractRevision": projection_contract_revision(),
        "ruleSetRevision": str(provenance.get("ruleSetRevision") or ""),
        "capabilityRegistryRevision": str(report.get("capabilityRegistryRevision") or ""),
        # Legacy reports may not contain a rule-set identity. Scanner version is only
        # a compatibility fallback and is never presented as an analysis semantic.
        "legacyScannerFallback": "" if provenance.get("ruleSetRevision") else str(report.get("scannerVersion") or report.get("engineVersion") or ""),
    }
    return f"projection-v1-{_sha(evaluator)[:16]}"


def build_projection_descriptor(analysis_manifest: dict[str, Any] | None, report_or_row: dict[str, Any]) -> dict[str, Any]:
    report = _report(report_or_row)
    rows = _projection_rows(report)
    outputs: dict[str, Any] = {}
    for name, items in rows.items():
        count, digest = _record_digest(items)
        outputs[name] = {"records": count, "recordDigest": digest}
    datasets = (analysis_manifest or {}).get("datasets") if isinstance((analysis_manifest or {}).get("datasets"), dict) else {}
    if isinstance(datasets.get("findings"), dict):
        outputs["findings"] = {
            "records": int(datasets["findings"].get("records") or 0),
            "recordDigest": str(datasets["findings"].get("recordDigest") or ""),
            "backingDataset": "findings",
        }
    provenance = report.get("scanProvenance") if isinstance(report.get("scanProvenance"), dict) else {}
    return {
        "schema": PROJECTION_CONTRACT_SCHEMA,
        "contractRevision": projection_contract_revision(),
        "projectionRevision": projection_revision(report),
        "ruleSetRevision": str(provenance.get("ruleSetRevision") or ""),
        "capabilityRegistryRevision": str(report.get("capabilityRegistryRevision") or ""),
        "outputs": outputs,
        "recursiveInputsForbidden": ["findings", "permissionCandidates", "automationCapabilities", "behaviorConsistency"],
    }


def replay_audit(observation_contract: dict[str, Any], required_collections: Iterable[str]) -> dict[str, Any]:
    available = observation_contract.get("collections") if isinstance(observation_contract.get("collections"), dict) else {}
    required = sorted({str(item) for item in required_collections if str(item)})
    missing: list[str] = []
    bounded: list[str] = []
    forbidden: list[str] = []
    for name in required:
        spec = COLLECTIONS.get(name)
        if spec is None or not bool(spec.get("srlEligible")):
            forbidden.append(name)
            continue
        item = available.get(name) if isinstance(available.get(name), dict) else None
        if item is None:
            missing.append(name)
        elif str(item.get("completeness") or "") == "bounded-transport":
            bounded.append(name)
    reusable = not missing and not forbidden and not bounded
    return {
        "schema": REPLAY_AUDIT_SCHEMA,
        "observationContractRevision": str(observation_contract.get("contractRevision") or ""),
        "requiredCollections": required,
        "reusableWithoutRescan": reusable,
        "missingCollections": missing,
        "boundedCompatibilityCollections": bounded,
        "forbiddenDerivedInputs": forbidden,
        "rescanRequired": not reusable,
        "reason": "compatible retained observations" if reusable else (
            "required collection is absent from retained evidence" if missing else
            "historical compact transport is insufficient for exact replay" if bounded else
            "rule requested a derived/non-observation input"
        ),
    }


def build_schema_reference() -> dict[str, Any]:
    return {
        "schema": "omega.deltascope.observation-reference.v1",
        "observationContractSchema": OBSERVATION_CONTRACT_SCHEMA,
        "observationContractRevision": contract_revision(),
        "projectionContractSchema": PROJECTION_CONTRACT_SCHEMA,
        "projectionContractRevision": projection_contract_revision(),
        "collections": COLLECTIONS,
        "legacyProjectionDatasets": PROJECTION_DATASETS,
        "rules": {
            "srlMayReadOnlyEligibleCollections": True,
            "derivedProjectionMayNotBeRecursiveInput": True,
            "historicalBoundedTransportRequiresTargetedRescanForExactRules": True,
        },
    }


def validation_errors(variant_payload: dict[str, Any], analysis_manifest: dict[str, Any] | None = None) -> list[str]:
    """Validate optional Phase-4 contracts without making historical v2 snapshots invalid."""
    errors: list[str] = []
    observations = variant_payload.get("observations") if isinstance(variant_payload.get("observations"), dict) else None
    projection = variant_payload.get("projection") if isinstance(variant_payload.get("projection"), dict) else None
    current = variant_payload.get("current") if isinstance(variant_payload.get("current"), dict) else {}
    scan = variant_payload.get("scan") if isinstance(variant_payload.get("scan"), dict) else {}
    report = current.get("report_json") if isinstance(current.get("report_json"), dict) else {}
    if not report and isinstance(scan.get("report_json"), dict):
        report = scan.get("report_json") or {}
    if observations is not None:
        if str(observations.get("schema") or "") != OBSERVATION_CONTRACT_SCHEMA:
            errors.append("observation contract schema is invalid")
        if not compatible_contract_revision(observations.get("contractRevision")):
            errors.append("observation contract revision is invalid")
        expected = build_variant_observation_contract(analysis_manifest or {}, report)
        expected_collections = expected.get("collections") if isinstance(expected.get("collections"), dict) else {}
        declared = observations.get("collections") if isinstance(observations.get("collections"), dict) else {}

        # Core SigmaScope observations remain reproducible from the retained immutable
        # analysis/report data.  External collector observations may extend the contract,
        # but can never replace or mutate one of these core descriptors.
        for name, expected_item in expected_collections.items():
            item = declared.get(name)
            if not isinstance(item, dict):
                errors.append(f"observation contract is missing core collection {name}")
                continue
            for field in ("schema", "collectionSchema", "backingDataset", "records", "recordDigest", "semanticClass", "srlEligible", "completeness"):
                if item.get(field) != expected_item.get(field):
                    errors.append(f"observation core collection {name} {field} mismatch")

        for name, item in declared.items():
            if not isinstance(item, dict):
                errors.append(f"observation collection {name} is malformed")
                continue
            spec = COLLECTIONS.get(str(name))
            if spec is not None:
                if str(item.get("collectionSchema") or "") != str(spec.get("schema") or ""):
                    errors.append(f"observation collection {name} schema mismatch")
                if bool(item.get("srlEligible")) != bool(spec.get("srlEligible")):
                    errors.append(f"observation collection {name} SRL eligibility mismatch")
                continue

            external_spec = collector_contracts.OBSERVATION_TYPES.get(str(name))
            if external_spec is None:
                errors.append(f"observation contract contains unknown collection {name}")
                continue
            if str(item.get("schema") or "") != OBSERVATION_COLLECTION_SCHEMA:
                errors.append(f"external observation collection {name} descriptor schema mismatch")
            if str(item.get("collectionSchema") or "") != str(external_spec.get("schema") or ""):
                errors.append(f"external observation collection {name} schema mismatch")
            if bool(item.get("srlEligible")) != bool(external_spec.get("ruleEligible")):
                errors.append(f"external observation collection {name} SRL eligibility mismatch")
            if str(item.get("semanticClass") or "") != str(external_spec.get("semanticClass") or ""):
                errors.append(f"external observation collection {name} semantic class mismatch")
            if str(item.get("backingDataset") or "") != "collector-result":
                errors.append(f"external observation collection {name} must use collector-result backing")
            if str(item.get("completeness") or "") not in {"retained-snapshot", "partial"}:
                errors.append(f"external observation collection {name} completeness is invalid")
            if int(item.get("records") or 0) < 0 or not str(item.get("recordDigest") or ""):
                errors.append(f"external observation collection {name} record identity is invalid")
            if not str(item.get("collectorId") or "") or not str(item.get("resultRevision") or "") or not str(item.get("resultPath") or ""):
                errors.append(f"external observation collection {name} collector-result linkage is incomplete")
            else:
                provider = collector_contracts.collector_map().get(str(item.get("collectorId") or ""))
                if not provider or str(name) not in [str(value) for value in provider.get("provides") or []]:
                    errors.append(f"external observation collection {name} collector is not a registered provider")

        digest_payload = [
            {
                "collection": name,
                "records": int(item.get("records") or 0),
                "recordDigest": str(item.get("recordDigest") or ""),
                "schema": str(item.get("collectionSchema") or ""),
                "completeness": str(item.get("completeness") or ""),
            }
            for name, item in sorted(declared.items()) if isinstance(item, dict)
        ]
        if str(observations.get("observationDigest") or "") != f"obs-{_sha(digest_payload)}":
            errors.append("observation contract digest is not reproducible")
    if projection is not None:
        if str(projection.get("schema") or "") != PROJECTION_CONTRACT_SCHEMA:
            errors.append("projection contract schema is invalid")
        if str(projection.get("contractRevision") or "") != projection_contract_revision():
            errors.append("projection contract revision is invalid")
        expected_projection = build_projection_descriptor(analysis_manifest or {}, report)
        if str(projection.get("projectionRevision") or "") != str(expected_projection.get("projectionRevision") or ""):
            errors.append("projection revision is not reproducible")
        if projection.get("recursiveInputsForbidden") != expected_projection.get("recursiveInputsForbidden"):
            errors.append("projection recursive-input boundary is invalid")
    return errors
