#!/usr/bin/env python3
"""Shared primitives for Omega security-evidence v2.

The v2 format is intentionally transport-oriented rather than query-oriented:
small JSON manifests/indexes describe the current graph while large forensic
collections are emitted as deterministic gzip-compressed JSON Lines shards.
The published root index is written last and acts as the atomic revision pointer.
"""
from __future__ import annotations

from dataclasses import dataclass
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import sqlite3
import sys
import tempfile
import urllib.parse
from typing import Any, Iterable, Iterator, Sequence


CATALOG_DIR = Path(__file__).resolve().parents[1] / "catalog"
if str(CATALOG_DIR) not in sys.path:
    sys.path.insert(0, str(CATALOG_DIR))
from artifact_source_model import (  # noqa: E402
    ATTRIBUTION_SCHEMA, MANIFEST_OBSERVATION_SCHEMA, attribution_invariant_errors, manifest_observation_key,
)

SCHEMA = "omega.security-evidence.v2"
FORMAT_VERSION = 2
DEFAULT_CHUNK_BYTES = 16 * 1024 * 1024
MAX_PUBLISH_FILE_BYTES = 32 * 1024 * 1024
DEFAULT_INLINE_DATASET_BYTES = 4 * 1024 * 1024
JSON_COLUMNS_SUFFIX = "_json"
NUGET_KINDS = ("nuget", "nuget-lock", "nuget-resolved")

TRANSPORT_REPORT_SCHEMA = "omega.security-evidence.scan-summary.v2"
MAX_TRANSPORT_REPORT_BYTES = 256 * 1024


def _bounded_text(value: Any, limit: int = 4096) -> str:
    text = str(value or "")
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)] + "…"


def _countish_transport(value: Any) -> int:
    if isinstance(value, (list, tuple, set, dict)):
        return len(value)
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def compact_report_for_transport(row: dict[str, Any]) -> dict[str, Any]:
    """Return a bounded summary for legacy ``report_json`` transport.

    The original scanner report duplicates normalized Evidence v2 tables and can be
    tens of MiB.  Variant descriptors only need the small compatibility fields still
    consumed by incremental scanning, source follow-ups and legacy projections.  The
    detailed findings/dependencies/calls/symbols remain in their dedicated v2 datasets.
    """
    raw = row.get("report_json")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except Exception:
            raw = {}
    report = raw if isinstance(raw, dict) else {}

    source = report.get("source") if isinstance(report.get("source"), dict) else {}
    source_provenance = source.get("provenance") if isinstance(source.get("provenance"), dict) else {}
    source_attribution = source.get("attribution") if isinstance(source.get("attribution"), dict) else {}
    source_candidates = source.get("candidates") if isinstance(source.get("candidates"), list) else []
    source_intel = source.get("dependencyIntelligence") if isinstance(source.get("dependencyIntelligence"), dict) else {}
    source_fingerprints = source_intel.get("fingerprints") if isinstance(source_intel.get("fingerprints"), dict) else {}
    package = report.get("package") if isinstance(report.get("package"), dict) else {}
    artifact_identity = report.get("artifactIdentity") if isinstance(report.get("artifactIdentity"), dict) else {}
    manifest_observation = report.get("manifestObservation") if isinstance(report.get("manifestObservation"), dict) else {}
    secondary_security = report.get("secondarySecurity") if isinstance(report.get("secondarySecurity"), dict) else {}
    automation = report.get("automation") if isinstance(report.get("automation"), dict) else {}
    intelligence = report.get("dependencyIntelligence") if isinstance(report.get("dependencyIntelligence"), dict) else {}
    if not intelligence and isinstance(report.get("intelligence"), dict):
        intelligence = report.get("intelligence")
    scan_provenance = report.get("scanProvenance") if isinstance(report.get("scanProvenance"), dict) else {}

    capabilities = automation.get("capabilities") if isinstance(automation.get("capabilities"), list) else []
    compact_caps: list[Any] = []
    for item in capabilities[:128]:
        if isinstance(item, dict):
            compact_caps.append({
                key: item.get(key)
                for key in ("id", "capabilityId", "label", "level", "automationLevel", "confidence", "reachable", "indirect")
                if key in item
            })
        elif isinstance(item, (str, int, float, bool)):
            compact_caps.append(item)

    report_counts_raw = report.get("counts") if isinstance(report.get("counts"), dict) else {}
    report_counts = {
        "informational": int(report_counts_raw.get("informational") or 0),
        "caution": int(report_counts_raw.get("caution") or 0),
        "high": int(report_counts_raw.get("high") or 0),
        "critical": int(report_counts_raw.get("critical") or 0),
    }
    row_counts = {
        "informational": int(row.get("informational_count") or 0),
        "caution": int(row.get("caution_count") or 0),
        "high": int(row.get("high_count") or 0),
        "critical": int(row.get("critical_count") or 0),
    }
    # Early v2 descriptors could carry zeroed current summary columns while the
    # immutable scan report and normalized findings still contained the real static
    # conclusion.  Preserve a non-empty legacy report conclusion when the row is the
    # known empty/stale shape; otherwise current row values remain authoritative so
    # intentional derived current-projection findings are not lost.
    counts = report_counts if not any(row_counts.values()) and any(report_counts.values()) else row_counts
    row_highest = str(row.get("highest_severity") or "none").strip().casefold()
    report_highest = str(report.get("highestSeverity") or "none").strip().casefold()
    highest = report_highest if row_highest in {"", "none"} and report_highest not in {"", "none"} else (row_highest or "none")
    top_capabilities = report.get("capabilities") if isinstance(report.get("capabilities"), list) else []
    compact_top_capabilities = [
        item for item in top_capabilities[:128]
        if isinstance(item, (str, int, float, bool))
    ]
    endpoint_records = intelligence.get("networkEndpoints") if isinstance(intelligence.get("networkEndpoints"), list) else []
    compact_endpoints: list[dict[str, str]] = []
    for endpoint in endpoint_records[:48]:
        if not isinstance(endpoint, dict):
            continue
        compact_endpoint = {
            "url": _bounded_text(endpoint.get("url"), 2048),
            "host": _bounded_text(endpoint.get("host"), 512),
            "origin": _bounded_text(endpoint.get("origin"), 64),
            "classification": _bounded_text(endpoint.get("classification"), 128),
            "purpose": _bounded_text(endpoint.get("purpose"), 512),
        }
        if "originType" in endpoint:
            compact_endpoint["originType"] = _bounded_text(endpoint.get("originType"), 64)
        if "confidence" in endpoint:
            compact_endpoint["confidence"] = _bounded_text(endpoint.get("confidence"), 32)
        if "concreteDestinationEvidence" in endpoint:
            compact_endpoint["concreteDestinationEvidence"] = bool(endpoint.get("concreteDestinationEvidence"))
        compact_endpoints.append(compact_endpoint)

    endpoint_summary_raw = intelligence.get("endpointSummary") if isinstance(intelligence.get("endpointSummary"), dict) else {}
    component_summary_raw = intelligence.get("componentSummary") if isinstance(intelligence.get("componentSummary"), dict) else {}
    compact_endpoint_summary = {
        "schema": _bounded_text(endpoint_summary_raw.get("schema"), 128),
        "networkCapabilityObserved": bool(endpoint_summary_raw.get("networkCapabilityObserved")),
        "literalCount": _countish_transport(endpoint_summary_raw.get("literalCount")),
        "concreteDestinationCount": _countish_transport(endpoint_summary_raw.get("concreteDestinationCount")),
        "hostCount": _countish_transport(endpoint_summary_raw.get("hostCount")),
        "destinationsUndetermined": bool(endpoint_summary_raw.get("destinationsUndetermined")),
        "hosts": [
            {
                "host": _bounded_text(item.get("host"), 512),
                "literalCount": _countish_transport(item.get("literalCount")),
                "concreteCount": _countish_transport(item.get("concreteCount")),
                "confidence": _bounded_text(item.get("confidence"), 32),
                "classifications": [_bounded_text(v, 128) for v in (item.get("classifications") or [])[:8]],
                "originTypes": [_bounded_text(v, 64) for v in (item.get("originTypes") or [])[:8]],
            }
            for item in (endpoint_summary_raw.get("hosts") or [])[:24] if isinstance(item, dict)
        ],
    } if endpoint_summary_raw else {}
    compact_component_summary = {
        "schema": _bounded_text(component_summary_raw.get("schema"), 128),
        "dependencyCount": _countish_transport(component_summary_raw.get("dependencyCount")),
        "families": component_summary_raw.get("families") if isinstance(component_summary_raw.get("families"), dict) else {},
        "requirements": component_summary_raw.get("requirements") if isinstance(component_summary_raw.get("requirements"), dict) else {},
        "exactVersionObservedCount": _countish_transport(component_summary_raw.get("exactVersionObservedCount")),
        "versionUnknownCount": _countish_transport(component_summary_raw.get("versionUnknownCount")),
        "nativeRelationshipCounts": component_summary_raw.get("nativeRelationshipCounts") if isinstance(component_summary_raw.get("nativeRelationshipCounts"), dict) else {},
        "pluginRelationships": [
            {key: _bounded_text(item.get(key), 512) for key in ("kind", "name", "requirement", "relationship", "confidence", "versionRequirement", "origin")}
            for item in (component_summary_raw.get("pluginRelationships") or [])[:24] if isinstance(item, dict)
        ],
        "nativeRelationships": [
            {
                **{key: _bounded_text(item.get(key), 1024) for key in ("consumerPath", "library", "entryPoint", "managedName", "disposition", "confidence", "targetPath")},
                "directManagedCallObserved": bool(item.get("directManagedCallObserved")),
                "directManagedCallCount": _countish_transport(item.get("directManagedCallCount")),
            }
            for item in (component_summary_raw.get("nativeRelationships") or [])[:24] if isinstance(item, dict)
        ],
        "fingerprint": _bounded_text(component_summary_raw.get("fingerprint"), 128),
    } if component_summary_raw else {}

    summary = {
        "schema": TRANSPORT_REPORT_SCHEMA,
        "engineVersion": str(report.get("engineVersion") or ""),
        "scannerVersion": str(row.get("scanner_version") or report.get("scannerVersion") or ""),
        "scanProvenance": {
            key: scan_provenance.get(key)
            for key in (
                "schema", "catalogRevision", "catalogIdentityEpoch", "definitionsRevision", "scannerRevision", "scannerBundleSha256", "definitionsSourceCommit", "artifactAnalysisRevision", "sourceAnalysisRevision", "sourceObservationRevision", "ruleSetRevision",
                "queueSeedRevision", "queueKey", "workType", "targetFingerprint", "primaryReason", "baselineSecurityRebuild",
                "reasons", "attemptId", "attemptNumber", "variantId", "observedSourceRepository", "observedSourceCommit", "observedSourceRef",
            )
            if key in scan_provenance
        },
        "scannedAtUtc": str(row.get("scanned_at_utc") or report.get("scannedAtUtc") or ""),
        "workType": str(report.get("workType") or scan_provenance.get("workType") or ""),
        "artifactIdentityContractVersion": int(report.get("artifactIdentityContractVersion") or 0),
        "manifestObservationContractVersion": int(report.get("manifestObservationContractVersion") or 0),
        "sourceAttributionContractVersion": int(report.get("sourceAttributionContractVersion") or 0),
        "secondarySecurityContractVersion": int(report.get("secondarySecurityContractVersion") or 0),
        "artifactAnalysisRevision": str(report.get("artifactAnalysisRevision") or scan_provenance.get("artifactAnalysisRevision") or scan_provenance.get("ruleSetRevision") or ""),
        "artifactAnalysisReused": bool(report.get("artifactAnalysisReused")),
        "artifactAnalysisRepresentativeScanId": int(report.get("artifactAnalysisRepresentativeScanId") or 0),
        "sourceAnalysisRevision": str(report.get("sourceAnalysisRevision") or ""),
        "sourceAnalysisReused": bool(report.get("sourceAnalysisReused")),
        "sourceAnalysisRepresentativeScanId": int(report.get("sourceAnalysisRepresentativeScanId") or 0),
        "artifactBytes": int(report.get("artifactBytes") or 0),
        "artifactIdentity": {
            "schema": _bounded_text(artifact_identity.get("schema"), 128),
            "artifactSha256": _bounded_text(artifact_identity.get("artifactSha256"), 128),
            "artifactBytes": int(artifact_identity.get("artifactBytes") or report.get("artifactBytes") or 0),
            "resolvedArtifactUrl": _bounded_text(artifact_identity.get("resolvedArtifactUrl") or report.get("resolvedArtifactUrl"), 8192),
            "catalogAssemblyVersion": _bounded_text(artifact_identity.get("catalogAssemblyVersion"), 512),
            "artifactAssemblyVersion": _bounded_text(artifact_identity.get("artifactAssemblyVersion"), 512),
            "manifestPath": _bounded_text(artifact_identity.get("manifestPath"), 2048),
            "manifestInternalName": _bounded_text(artifact_identity.get("manifestInternalName"), 512),
            "manifestRepositoryUrl": _bounded_text(artifact_identity.get("manifestRepositoryUrl"), 8192),
            "versionMatchesCatalog": bool(artifact_identity.get("versionMatchesCatalog")),
        },
        "manifestObservation": {
            "schema": _bounded_text(manifest_observation.get("schema"), 128),
            "observationKey": _bounded_text(manifest_observation.get("observationKey"), 128),
            "observationId": int(manifest_observation.get("observationId") or 0),
            "variantId": int(manifest_observation.get("variantId") or 0),
            "channel": _bounded_text(manifest_observation.get("channel"), 64),
            "internalName": _bounded_text(manifest_observation.get("internalName"), 512),
            "manifestVersion": _bounded_text(manifest_observation.get("manifestVersion"), 512),
            "downloadUrl": _bounded_text(manifest_observation.get("downloadUrl"), 8192),
            "repositoryUrl": _bounded_text(manifest_observation.get("repositoryUrl"), 8192),
        },
        "status": str(row.get("status") or report.get("status") or ""),
        "highestSeverity": highest,
        "counts": counts,
        "capabilities": compact_top_capabilities,
        "source": {
            "available": bool(row.get("source_available") or source.get("available") or False),
            "repository": _bounded_text(row.get("source_repository") or source.get("repository") or "", 8192),
            "commit": _bounded_text(row.get("source_commit") or source.get("commit") or "", 512),
            "branch": _bounded_text(source.get("branch"), 512),
            "treeSha256": _bounded_text(source.get("treeSha256"), 128),
            "candidates": [_bounded_text(item, 8192) for item in source_candidates[:16] if str(item or "")],
            "attribution": {
                "schema": str(source_attribution.get("schema") or "omega.artifact-source-attribution.v1"),
                "confidence": int(source_attribution.get("confidence") or 0),
                "coverageLabel": _bounded_text(source_attribution.get("coverageLabel"), 256),
                "basis": [str(item) for item in (source_attribution.get("basis") or [])[:16] if str(item)],
            },
            "provenance": {
                key: source_provenance.get(key)
                for key in (
                    "schema", "confidence", "requestedAssemblyVersion", "selectedRef", "selectedRefKind",
                    "manifestPath", "manifestInternalName", "manifestAssemblyVersion", "manifestRepoUrl",
                    "identityMatched", "versionMatched", "manifestRepositoryMatched", "artifactOriginMatched",
                    "repoUrlMatched", "originMatched", "artifactPinnedCommit", "reproducibleSourceToArtifact", "sourceToBinaryVerified", "inheritedViaArtifact",
                    "inheritedArtifactSha256", "inheritedFromVariantId", "distributionSource",
                )
                if key in source_provenance
            },
            "error": _bounded_text(source.get("error"), 8192),
            "dependencyIntelligence": {
                "fingerprints": {
                    "relevantSourceSha256": _bounded_text(source_fingerprints.get("relevantSourceSha256"), 128),
                }
            },
        },
        "secondarySecurity": ({
            "schema": _bounded_text(secondary_security.get("schema"), 128),
            "artifactSha256": _bounded_text(secondary_security.get("artifactSha256"), 128),
            "semantics": _bounded_text(secondary_security.get("semantics"), 128),
            "matchCount": int(secondary_security.get("matchCount") or 0),
            "engines": [
                {
                    "schema": _bounded_text(item.get("schema"), 128),
                    "engine": _bounded_text(item.get("engine"), 64),
                    "status": _bounded_text(item.get("status"), 64),
                    "available": bool(item.get("available")),
                    "enabled": bool(item.get("enabled")),
                    "revision": _bounded_text(item.get("revision"), 256),
                    "version": _bounded_text(item.get("version"), 512),
                    "policyRevision": _bounded_text(item.get("policyRevision"), 256),
                    "executableIdentity": ({
                        "schema": _bounded_text((item.get("executableIdentity") or {}).get("schema"), 128),
                        "command": _bounded_text((item.get("executableIdentity") or {}).get("command"), 128),
                        "expectedSha256": _bounded_text((item.get("executableIdentity") or {}).get("expectedSha256"), 128),
                        "expectedBytes": int((item.get("executableIdentity") or {}).get("expectedBytes") or 0),
                        "expectedVersion": _bounded_text((item.get("executableIdentity") or {}).get("expectedVersion"), 512),
                        "actualSha256": _bounded_text((item.get("executableIdentity") or {}).get("actualSha256"), 128),
                        "actualBytes": int((item.get("executableIdentity") or {}).get("actualBytes") or 0),
                        "actualVersion": _bounded_text((item.get("executableIdentity") or {}).get("actualVersion"), 512),
                        "available": bool((item.get("executableIdentity") or {}).get("available")),
                        "verified": bool((item.get("executableIdentity") or {}).get("verified")),
                        "error": _bounded_text((item.get("executableIdentity") or {}).get("error"), 2048),
                    } if isinstance(item.get("executableIdentity"), dict) and item.get("executableIdentity") else {}),
                    "matches": [
                        {
                            "kind": _bounded_text(match.get("kind"), 64),
                            "value": _bounded_text(match.get("value"), 2048),
                            "rule": _bounded_text(match.get("rule"), 256),
                            "provenance": ({
                                "kind": _bounded_text((match.get("provenance") or {}).get("kind"), 128),
                                "source": _bounded_text((match.get("provenance") or {}).get("source"), 1024),
                            } if isinstance(match.get("provenance"), dict) and match.get("provenance") else {}),
                            "license": _bounded_text(match.get("license"), 256),
                            "falsePositiveExpectation": _bounded_text(match.get("falsePositiveExpectation"), 64),
                            "scope": _bounded_text(match.get("scope"), 1024),
                        }
                        for match in (item.get("matches") or [])[:256] if isinstance(match, dict)
                    ],
                    "error": _bounded_text(item.get("error"), 4096),
                }
                for item in (secondary_security.get("engines") or [])[:8] if isinstance(item, dict)
            ],
        } if secondary_security else {}),
        "package": {
            "archive": _bounded_text(package.get("archive"), 2048),
            "fileCount": _countish_transport(package.get("fileCount") or package.get("files")),
            "uncompressedBytes": _countish_transport(package.get("uncompressedBytes")),
            "bundledExecutableCount": _countish_transport(package.get("bundledExecutableCount") or package.get("bundledExecutables")),
            "bundledManagedAssemblyCount": _countish_transport(package.get("bundledManagedAssemblyCount") or package.get("bundledManagedAssemblies")),
            "bundledNativeLibraryCount": _countish_transport(package.get("bundledNativeLibraryCount") or package.get("bundledNativeLibraries")),
        },
        "automation": {
            "level": str(automation.get("level") or row.get("automation_level") or "none"),
            "capabilities": compact_caps,
        },
        "intelligence": {
            "coverage": intelligence.get("coverage") if isinstance(intelligence.get("coverage"), dict) else {},
            "limits": intelligence.get("limits") if isinstance(intelligence.get("limits"), dict) else {},
            "networkEndpoints": compact_endpoints,
            "endpointSummary": compact_endpoint_summary,
            "componentSummary": compact_component_summary,
        },
        "error": _bounded_text(row.get("error") or report.get("error") or "", 8192),
    }
    encoded = canonical_json_bytes(summary)
    if len(encoded) > MAX_TRANSPORT_REPORT_BYTES:
        # Coverage/limits are informational compatibility data.  Preserve the fields
        # required by incremental/source workflows first, then drop these optional
        # maps rather than ever allowing a legacy report to inflate a variant file.
        summary["intelligence"] = {"coverage": {}, "limits": {}, "networkEndpoints": [], "endpointSummary": compact_endpoint_summary, "componentSummary": compact_component_summary}
        encoded = canonical_json_bytes(summary)
    if len(encoded) > MAX_TRANSPORT_REPORT_BYTES:
        summary["automation"]["capabilities"] = []
        encoded = canonical_json_bytes(summary)
    if len(encoded) > MAX_TRANSPORT_REPORT_BYTES:
        raise ValueError(f"transport report summary exceeds {MAX_TRANSPORT_REPORT_BYTES} bytes")
    return summary


def transport_security_row(row: dict[str, Any]) -> dict[str, Any]:
    """Normalize a scan/current row for bounded Evidence v2 transport."""
    result = dict(row)
    if "report_json" in result:
        result["report_json"] = compact_report_for_transport(result)
    return result

# Core evidence is tied to one scan. Primary keys and scan_id are transport
# identities, not semantic evidence, so they are excluded from record digests.
CORE_DATASETS: tuple[tuple[str, str, str], ...] = (
    ("findings", "plugin_security_findings", "finding_id"),
    ("dependencies", "plugin_security_dependencies", "dependency_id"),
    ("ipc", "plugin_security_ipc_endpoints", "ipc_endpoint_id"),
    ("imports", "plugin_security_imports", "import_id"),
    ("assemblies", "plugin_security_managed_assemblies", "managed_assembly_id"),
    ("symbols", "plugin_security_managed_symbols", "managed_symbol_id"),
    ("calls", "plugin_security_managed_calls", "managed_call_id"),
    ("reachability", "plugin_security_managed_reachability", "reachability_id"),
    ("permissions", "plugin_security_permission_candidates", "candidate_id"),
    ("automation", "plugin_security_automation_capabilities", "automation_capability_id"),
)

LARGE_DATASETS = {"imports", "symbols", "calls", "reachability"}


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_value(key: str, value: Any) -> Any:
    if value is None:
        return None
    if key.endswith(JSON_COLUMNS_SUFFIX) and isinstance(value, str):
        text = value.strip()
        if not text:
            return [] if text == "" else value
        try:
            return json.loads(text)
        except Exception:
            # Preserve malformed legacy evidence exactly instead of inventing data.
            return value
    return value


def variant_index_summary(
    payload: dict[str, Any], *, lifecycle_contract_version: int | None = None
) -> dict[str, Any]:
    """Return the small identity/current projection used by the online Developer View.

    The summary intentionally contains no detailed findings, calls, symbols or source text.
    Those remain in the variant/analysis graph and are fetched lazily by developers.

    ``lifecycle_contract_version`` is deliberately explicit for validation. Published
    pre-lifecycle snapshots used the same plugins index schema but did not contain the
    lifecycle summary keys introduced by lifecycle contract v1.  When omitted, infer
    the contract from the descriptor so legacy migration paths keep their historical
    shape while lifecycle-aware production descriptors get the v1 fields.
    """
    plugin = payload.get("plugin") if isinstance(payload.get("plugin"), dict) else {}
    variant = payload.get("variant") if isinstance(payload.get("variant"), dict) else {}
    source = payload.get("source") if isinstance(payload.get("source"), dict) else {}
    current = payload.get("current") if isinstance(payload.get("current"), dict) else {}
    report = current.get("report_json") if isinstance(current.get("report_json"), dict) else {}
    report_source = report.get("source") if isinstance(report.get("source"), dict) else {}
    provenance = report_source.get("provenance") if isinstance(report_source.get("provenance"), dict) else {}
    attribution = report_source.get("attribution") if isinstance(report_source.get("attribution"), dict) else {}
    scan_provenance = report.get("scanProvenance") if isinstance(report.get("scanProvenance"), dict) else {}
    lifecycle = payload.get("lifecycle") if isinstance(payload.get("lifecycle"), dict) else {}
    if lifecycle_contract_version is None:
        lifecycle_contract_version = (
            1 if str(lifecycle.get("schema") or "") == "omega.security-evidence.variant-lifecycle.v1" else 0
        )
    if lifecycle_contract_version not in {0, 1}:
        raise ValueError(f"unsupported lifecycle summary contract: {lifecycle_contract_version}")
    summary = {
        "plugin_id": int(payload.get("pluginId") or plugin.get("plugin_id") or variant.get("plugin_id") or 0),
        "source_id": int(payload.get("sourceId") or source.get("source_id") or variant.get("source_id") or 0),
        "internal_name": str(plugin.get("internal_name") or ""),
        "canonical_name": str(plugin.get("canonical_name") or variant.get("name") or plugin.get("internal_name") or ""),
        "name": str(variant.get("name") or plugin.get("canonical_name") or plugin.get("internal_name") or ""),
        "author": str(variant.get("author") or ""),
        "assembly_version": str(variant.get("assembly_version") or current.get("assembly_version") or ""),
        "source_name": str(source.get("name") or ""),
        "source_url": str(source.get("url") or ""),
        "source_provider": str(source.get("provider") or ""),
        "scan_id": int(current.get("scan_id") or 0),
        "scanner_version": str(current.get("scanner_version") or ""),
        "scan_status": str(current.get("status") or "unscanned"),
        "scanned_at_utc": str(current.get("scanned_at_utc") or ""),
        "highest_severity": str(current.get("highest_severity") or "none"),
        "informational_count": int(current.get("informational_count") or 0),
        "caution_count": int(current.get("caution_count") or 0),
        "high_count": int(current.get("high_count") or 0),
        "critical_count": int(current.get("critical_count") or 0),
        "automation_level": str(current.get("automation_level") or "none"),
        "artifact_sha256": str(current.get("artifact_sha256") or "").strip().lower(),
        "source_available": int(current.get("source_available") or 0),
        "source_repository": str(current.get("source_repository") or ""),
        "source_commit": str(current.get("source_commit") or ""),
        "source_provenance_confidence": str(provenance.get("confidence") or ""),
        "source_attribution_confidence": int(attribution.get("confidence") or 0),
        "source_attribution_basis": list(attribution.get("basis") or []),
        "source_coverage_label": str(attribution.get("coverageLabel") or "Unresolved"),
        "source_identity_matched": bool(provenance.get("identityMatched")),
        "source_version_matched": bool(provenance.get("versionMatched")),
        "source_artifact_origin_matched": bool(provenance.get("artifactOriginMatched")),
        "source_selected_ref": str(provenance.get("selectedRef") or ""),
        "catalog_revision": str(scan_provenance.get("catalogRevision") or ""),
        "definitions_revision": str(scan_provenance.get("definitionsRevision") or ""),
        "definitions_source_commit": str(scan_provenance.get("definitionsSourceCommit") or ""),
        "scanner_revision": str(scan_provenance.get("scannerRevision") or ""),
        "scanner_bundle_sha256": str(scan_provenance.get("scannerBundleSha256") or ""),
        "artifact_analysis_revision": str(report.get("artifactAnalysisRevision") or scan_provenance.get("artifactAnalysisRevision") or ""),
        "source_analysis_revision": str(report.get("sourceAnalysisRevision") or scan_provenance.get("sourceAnalysisRevision") or ""),
        "source_observation_revision": str(scan_provenance.get("sourceObservationRevision") or ""),
        "rule_set_revision": str(scan_provenance.get("ruleSetRevision") or ""),
        "scan_queue_reason": str(scan_provenance.get("primaryReason") or ""),
        "scan_queue_seed_revision": str(scan_provenance.get("queueSeedRevision") or ""),
    }
    if lifecycle_contract_version == 1:
        summary.update({
            "lifecycle_state": str(lifecycle.get("state") or "active"),
            "lifecycle_reason": str(lifecycle.get("reason") or ""),
            "lifecycle_terminal": bool(lifecycle.get("terminal")),
        })
    return summary


def normalize_row(row: sqlite3.Row | dict[str, Any], *, exclude: Iterable[str] = ()) -> dict[str, Any]:
    excluded = set(exclude)
    source = dict(row)
    return {key: normalize_value(key, value) for key, value in source.items() if key not in excluded}


def table_exists(db: sqlite3.Connection, name: str) -> bool:
    return db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


def table_columns(db: sqlite3.Connection, name: str) -> list[str]:
    if not table_exists(db, name):
        return []
    return [str(row[1]) for row in db.execute(f'PRAGMA table_info("{name}")')]


def primary_key_column(db: sqlite3.Connection, table: str) -> str | None:
    rows = list(db.execute(f'PRAGMA table_info("{table}")'))
    for row in rows:
        if int(row[5] or 0) == 1:
            return str(row[1])
    return None


def read_meta(db: sqlite3.Connection) -> dict[str, str]:
    if not table_exists(db, "catalog_meta"):
        return {}
    return {str(row[0]): str(row[1]) for row in db.execute("SELECT key,value FROM catalog_meta ORDER BY key")}


def open_ro(path: Path) -> sqlite3.Connection:
    resolved = path.resolve()
    uri = "file:" + urllib.parse.quote(str(resolved).replace("\\", "/"), safe="/:_") + "?mode=ro"
    db = sqlite3.connect(uri, uri=True)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA query_only=ON")
    return db


def safe_relpath(path: str) -> str:
    pure = PurePosixPath(path.replace("\\", "/"))
    if pure.is_absolute() or ".." in pure.parts:
        raise ValueError(f"unsafe evidence path: {path!r}")
    return pure.as_posix()


def atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def write_json(path: Path, value: Any, *, pretty: bool = True) -> dict[str, Any]:
    if pretty:
        data = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    else:
        data = canonical_json_bytes(value) + b"\n"
    atomic_write_bytes(path, data)
    return {"path": path.name, "bytes": len(data), "sha256": sha256_bytes(data), "encoding": "json"}


def dataset_record_digest(rows: Iterable[dict[str, Any]]) -> tuple[int, str]:
    row_hashes: list[str] = []
    count = 0
    for row in rows:
        row_hashes.append(sha256_bytes(canonical_json_bytes(row)))
        count += 1
    row_hashes.sort()
    digest = hashlib.sha256()
    for item in row_hashes:
        digest.update(item.encode("ascii"))
        digest.update(b"\n")
    return count, digest.hexdigest()


@dataclass
class ChunkResult:
    path: str
    bytes: int
    sha256: str
    records: int
    record_digest: str
    encoding: str = "jsonl+gzip"

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "bytes": self.bytes,
            "sha256": self.sha256,
            "records": self.records,
            "recordDigest": self.record_digest,
            "encoding": self.encoding,
        }


class JsonlGzipChunkWriter:
    """Deterministic bounded gzip JSONL writer.

    gzip mtime is fixed at zero so repeated migrations of identical evidence
    produce byte-identical shards. Chunks roll after the compressed file crosses
    the target size; the hard publish ceiling is checked separately.
    """

    def __init__(self, directory: Path, stem: str, *, target_bytes: int = DEFAULT_CHUNK_BYTES):
        self.directory = directory
        self.stem = stem
        self.target_bytes = max(1024 * 1024, int(target_bytes))
        self.directory.mkdir(parents=True, exist_ok=True)
        self._index = 0
        self._raw = None
        self._gzip = None
        self._path: Path | None = None
        self._records = 0
        self._row_hashes: list[str] = []
        self.results: list[ChunkResult] = []

    def _open(self) -> None:
        self._index += 1
        self._path = self.directory / f"{self.stem}-{self._index:04d}.jsonl.gz"
        self._raw = self._path.open("wb")
        self._gzip = gzip.GzipFile(filename="", mode="wb", fileobj=self._raw, compresslevel=6, mtime=0)
        self._records = 0
        self._row_hashes = []

    def _finish(self) -> None:
        if self._gzip is None or self._raw is None or self._path is None:
            return
        self._gzip.close()
        self._raw.close()
        count, digest = dataset_record_digest_from_hashes(self._row_hashes)
        size = self._path.stat().st_size
        self.results.append(ChunkResult(
            path=self._path.name,
            bytes=size,
            sha256=sha256_file(self._path),
            records=count,
            record_digest=digest,
        ))
        self._gzip = None
        self._raw = None
        self._path = None
        self._records = 0
        self._row_hashes = []

    def write(self, row: dict[str, Any]) -> None:
        if self._gzip is None:
            self._open()
        data = canonical_json_bytes(row) + b"\n"
        self._gzip.write(data)
        self._records += 1
        self._row_hashes.append(sha256_bytes(canonical_json_bytes(row)))
        # Flush before measuring compressed position. This is slightly more CPU
        # intensive but keeps shard size bounded for GitHub branch publication.
        self._gzip.flush()
        if self._raw.tell() >= self.target_bytes and self._records > 0:
            self._finish()

    def close(self) -> list[ChunkResult]:
        self._finish()
        return self.results


def dataset_record_digest_from_hashes(row_hashes: Sequence[str]) -> tuple[int, str]:
    ordered = sorted(row_hashes)
    digest = hashlib.sha256()
    for item in ordered:
        digest.update(item.encode("ascii"))
        digest.update(b"\n")
    return len(ordered), digest.hexdigest()


def combine_chunk_record_digests(chunks: Sequence[ChunkResult]) -> tuple[int, str]:
    # Chunk-level record digests cannot be combined into the same multiset digest
    # as all rows, so callers that need an overall digest should track row hashes
    # separately. This helper is only a transport fingerprint.
    payload = [{"records": c.records, "recordDigest": c.record_digest} for c in chunks]
    return sum(c.records for c in chunks), sha256_bytes(canonical_json_bytes(payload))


def file_entry(root: Path, path: Path, *, records: int | None = None, record_digest: str | None = None, encoding: str | None = None) -> dict[str, Any]:
    rel = path.relative_to(root).as_posix()
    result: dict[str, Any] = {
        "path": rel,
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }
    if records is not None:
        result["records"] = int(records)
    if record_digest:
        result["recordDigest"] = record_digest
    if encoding:
        result["encoding"] = encoding
    return result


def verify_file_entry(root: Path, entry: dict[str, Any], *, max_bytes: int | None = None) -> list[str]:
    errors: list[str] = []
    try:
        rel = safe_relpath(str(entry.get("path") or ""))
    except ValueError as exc:
        return [str(exc)]
    path = root / rel
    if not path.is_file():
        return [f"missing file: {rel}"]
    actual_size = path.stat().st_size
    expected_size = int(entry.get("bytes") or -1)
    if actual_size != expected_size:
        errors.append(f"size mismatch for {rel}: manifest={expected_size}, actual={actual_size}")
    if max_bytes is not None and actual_size > max_bytes:
        errors.append(f"file exceeds {max_bytes} byte ceiling: {rel} ({actual_size} bytes)")
    expected_hash = str(entry.get("sha256") or "").lower()
    actual_hash = sha256_file(path)
    if expected_hash != actual_hash:
        errors.append(f"sha256 mismatch for {rel}: manifest={expected_hash}, actual={actual_hash}")
    return errors


def write_record_dataset(
    root: Path,
    directory: Path,
    stem: str,
    rows: Iterable[dict[str, Any]],
    *,
    chunk_bytes: int = DEFAULT_CHUNK_BYTES,
    inline_bytes: int = DEFAULT_INLINE_DATASET_BYTES,
) -> dict[str, Any]:
    """Write a bounded record collection as JSON or deterministic JSONL+gzip shards.

    This is used for evidence that belongs to a current variant but is not part of the
    immutable artifact analysis (for example dependency resolution and OSV projection
    rows).  The descriptor has the same records/digest/files shape as an analysis
    dataset so intrinsic validation can use one contract for both.
    """
    root = root.resolve()
    directory = directory.resolve()
    if directory != root and root not in directory.parents:
        raise ValueError(f"record dataset directory escaped evidence root: {directory}")
    directory.mkdir(parents=True, exist_ok=True)
    safe_stem = "".join(ch if ch.isalnum() or ch in "-_." else "-" for ch in stem).strip(".-") or "records"

    # Remove the previous transport representation for this logical dataset before
    # replacing it, otherwise a JSON -> JSONL transition would leave orphan files.
    for old in directory.glob(f"{safe_stem}*"):
        if old.is_file() and (old.name == f"{safe_stem}.json" or old.name.startswith(f"{safe_stem}-")):
            old.unlink()

    materialized: list[dict[str, Any]] = []
    row_hashes: list[str] = []
    total_uncompressed = 0
    for row in rows:
        normalized = dict(row)
        encoded = canonical_json_bytes(normalized)
        materialized.append(normalized)
        row_hashes.append(sha256_bytes(encoded))
        total_uncompressed += len(encoded) + 1
    count, digest = dataset_record_digest_from_hashes(row_hashes)

    if total_uncompressed <= max(0, int(inline_bytes)):
        path = directory / f"{safe_stem}.json"
        write_json(path, materialized)
        return {
            "records": count,
            "recordDigest": digest,
            "files": [file_entry(root, path, records=count, record_digest=digest, encoding="json")],
        }

    writer = JsonlGzipChunkWriter(directory, safe_stem, target_bytes=chunk_bytes)
    for row in materialized:
        writer.write(row)
    chunks = writer.close()
    return {
        "records": count,
        "recordDigest": digest,
        "files": [
            file_entry(
                root,
                directory / chunk.path,
                records=chunk.records,
                record_digest=chunk.record_digest,
                encoding=chunk.encoding,
            )
            for chunk in chunks
        ],
    }


def read_record_dataset(root: Path, descriptor: dict[str, Any]) -> list[dict[str, Any]]:
    """Read a generic v2 records/digest/files descriptor.

    Hash/size verification remains the validator's job; this helper intentionally only
    performs safe-path parsing and decoding so callers can reconstruct semantic rows.
    """
    rows: list[dict[str, Any]] = []
    for file_info in descriptor.get("files") or []:
        if not isinstance(file_info, dict):
            continue
        rel = safe_relpath(str(file_info.get("path") or ""))
        path = root.resolve() / rel
        encoding = str(file_info.get("encoding") or "")
        if encoding == "json":
            value = json.loads(path.read_text(encoding="utf-8"))
            values = value if isinstance(value, list) else [value]
            rows.extend(item for item in values if isinstance(item, dict))
        elif encoding == "jsonl+gzip":
            with gzip.open(path, "rt", encoding="utf-8") as stream:
                for line in stream:
                    if not line.strip():
                        continue
                    value = json.loads(line)
                    if isinstance(value, dict):
                        rows.append(value)
        else:
            raise ValueError(f"unsupported record dataset encoding: {encoding!r}")
    return rows


def row_digest_from_query(db: sqlite3.Connection, sql: str, params: Sequence[Any], *, exclude: Iterable[str]) -> tuple[int, str]:
    row_hashes: list[str] = []
    count = 0
    for row in db.execute(sql, params):
        normalized = normalize_row(row, exclude=exclude)
        row_hashes.append(sha256_bytes(canonical_json_bytes(normalized)))
        count += 1
    return dataset_record_digest_from_hashes(row_hashes)


def read_json_file(root: Path, relative: str) -> Any:
    rel = safe_relpath(relative)
    path = (root / rel).resolve()
    resolved_root = root.resolve()
    if path != resolved_root and resolved_root not in path.parents:
        raise ValueError(f"evidence path escaped root: {relative!r}")
    if not path.is_file():
        raise FileNotFoundError(path)
    return json.loads(path.read_text(encoding="utf-8"))


def read_dataset_rows(root: Path, analysis_path: str, dataset: str) -> list[dict[str, Any]]:
    """Read one v2 analysis dataset and verify its declared files while doing so."""
    manifest = read_json_file(root, f"{safe_relpath(analysis_path)}/manifest.json")
    item = ((manifest.get("datasets") or {}).get(dataset) or {}) if isinstance(manifest, dict) else {}
    rows: list[dict[str, Any]] = []
    for entry in item.get("files") or []:
        errors = verify_file_entry(root, entry, max_bytes=MAX_PUBLISH_FILE_BYTES)
        if errors:
            raise ValueError("; ".join(errors))
        rel = safe_relpath(str(entry.get("path") or ""))
        path = root / rel
        encoding = str(entry.get("encoding") or "")
        if encoding == "json":
            value = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(value, list):
                rows.extend(item for item in value if isinstance(item, dict))
            elif isinstance(value, dict):
                rows.append(value)
        elif encoding == "jsonl+gzip":
            with gzip.open(path, "rt", encoding="utf-8") as stream:
                for line in stream:
                    if not line.strip():
                        continue
                    value = json.loads(line)
                    if isinstance(value, dict):
                        rows.append(value)
        else:
            raise ValueError(f"unsupported v2 evidence encoding {encoding!r} for {rel}")
    return rows


def iter_variant_entries(root: Path) -> Iterator[tuple[dict[str, Any], dict[str, Any]]]:
    index = read_json_file(root, "index.json")
    if index.get("schema") != SCHEMA:
        raise ValueError(f"unsupported evidence schema: {index.get('schema')!r}")
    plugins_entry = ((index.get("indexes") or {}).get("plugins") or {})
    plugins = read_json_file(root, str(plugins_entry.get("path") or "indexes/plugins.json"))
    for entry in plugins.get("currentVariants") or []:
        if not isinstance(entry, dict):
            continue
        payload = read_json_file(root, str(entry.get("variantPath") or ""))
        yield entry, payload



def _scanner_version_at_least(value: Any, minimum: tuple[int, int, int]) -> bool:
    parts = []
    for item in str(value or "").split(".")[:3]:
        try:
            parts.append(int(item))
        except ValueError:
            parts.append(0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3]) >= minimum


def _validate_identity_contract(variant_id: int, payload: dict[str, Any], errors: list[str]) -> None:
    current = payload.get("current") if isinstance(payload.get("current"), dict) else {}
    report = current.get("report_json") if isinstance(current.get("report_json"), dict) else {}
    artifact_sha = str(current.get("artifact_sha256") or report.get("artifactSha256") or "").strip().lower()

    artifact_contract = int(report.get("artifactIdentityContractVersion") or 0)
    manifest_contract = int(report.get("manifestObservationContractVersion") or 0)
    attribution_contract = int(report.get("sourceAttributionContractVersion") or 0)
    secondary_contract = int(report.get("secondarySecurityContractVersion") or 0)
    for label, value in (("artifact identity", artifact_contract), ("manifest observation", manifest_contract),
                         ("source attribution", attribution_contract)):
        if value not in {0, 1}:
            errors.append(f"variant {variant_id} declares unsupported {label} contract version {value}")
    if secondary_contract not in {0, 1, 2}:
        errors.append(f"variant {variant_id} declares unsupported secondary security contract version {secondary_contract}")

    if artifact_contract == 1:
        identity = report.get("artifactIdentity") if isinstance(report.get("artifactIdentity"), dict) else {}
        if str(identity.get("schema") or "") != "omega.sigmascope.artifact-identity.v1":
            errors.append(f"variant {variant_id} lacks the v2.10 artifact identity contract")
        if str(identity.get("artifactSha256") or "").strip().lower() != artifact_sha:
            errors.append(f"variant {variant_id} artifact identity hash differs from current artifact hash")
        if int(identity.get("artifactBytes") or 0) <= 0:
            errors.append(f"variant {variant_id} artifact identity lacks package byte identity")

    if manifest_contract == 1:
        observation = report.get("manifestObservation") if isinstance(report.get("manifestObservation"), dict) else {}
        if str(observation.get("schema") or "") != MANIFEST_OBSERVATION_SCHEMA:
            errors.append(f"variant {variant_id} lacks the manifest observation contract")
        else:
            if int(observation.get("variantId") or 0) != variant_id:
                errors.append(f"variant {variant_id} manifest observation points at another variant")
            expected_key = manifest_observation_key(
                variant_id, str(observation.get("channel") or ""), str(observation.get("internalName") or ""),
                str(observation.get("manifestVersion") or ""), str(observation.get("downloadUrl") or ""),
                str(observation.get("repositoryUrl") or ""),
            )
            if str(observation.get("observationKey") or "") != expected_key:
                errors.append(f"variant {variant_id} manifest observation key is not derivable from its fields")
            if str(observation.get("channel") or "") != str(current.get("artifact_channel") or ""):
                errors.append(f"variant {variant_id} manifest observation channel differs from selected artifact channel")
            if str(observation.get("downloadUrl") or "") != str(current.get("artifact_url") or ""):
                errors.append(f"variant {variant_id} manifest observation URL differs from selected artifact URL")
            if str(observation.get("manifestVersion") or "") != str(current.get("assembly_version") or ""):
                errors.append(f"variant {variant_id} manifest observation version differs from selected assembly version")

    if attribution_contract == 1:
        source = report.get("source") if isinstance(report.get("source"), dict) else {}
        attribution = source.get("attribution") if isinstance(source.get("attribution"), dict) else {}
        if str(attribution.get("schema") or "") != ATTRIBUTION_SCHEMA:
            errors.append(f"variant {variant_id} lacks the artifact/source attribution contract")
        else:
            for error in attribution_invariant_errors(source, attribution):
                errors.append(f"variant {variant_id} source attribution: {error}")

    if secondary_contract in {1, 2}:
        secondary = report.get("secondarySecurity") if isinstance(report.get("secondarySecurity"), dict) else {}
        if str(secondary.get("schema") or "") != "omega.sigmascope.secondary-security.v1":
            errors.append(f"variant {variant_id} secondary security schema is unsupported")
        if str(secondary.get("artifactSha256") or "").strip().lower() != artifact_sha:
            errors.append(f"variant {variant_id} secondary security evidence targets another artifact")
        if str(secondary.get("semantics") or "") != "supplemental-evidence-only":
            errors.append(f"variant {variant_id} secondary security evidence has unsafe semantics")
        allowed_status = {"disabled", "unavailable", "complete", "failed"}
        engines = secondary.get("engines") if isinstance(secondary.get("engines"), list) else []
        for engine in engines:
            if not isinstance(engine, dict):
                errors.append(f"variant {variant_id} secondary security engine entry is malformed")
                continue
            if str(engine.get("engine") or "") not in {"yara", "clamav"}:
                errors.append(f"variant {variant_id} secondary security engine is unsupported")
            if str(engine.get("status") or "") not in allowed_status:
                errors.append(f"variant {variant_id} secondary security engine status is unsupported")
            if secondary_contract == 2 and bool(engine.get("enabled")) and str(engine.get("status") or "") == "complete":
                identity = engine.get("executableIdentity") if isinstance(engine.get("executableIdentity"), dict) else {}
                if not bool(identity.get("verified")):
                    errors.append(f"variant {variant_id} completed secondary security engine lacks verified executable identity")
                expected_sha = str(identity.get("expectedSha256") or "").strip().lower()
                actual_sha = str(identity.get("actualSha256") or "").strip().lower()
                if len(expected_sha) != 64 or expected_sha != actual_sha:
                    errors.append(f"variant {variant_id} completed secondary security engine executable hash identity is invalid")


def validate_snapshot(root: Path, *, require_no_orphans: bool = True) -> dict[str, Any]:
    """Validate a published/staged v2 tree without requiring the retired v1 SQLite DB.

    This is the production incremental publication gate. It verifies the atomic root,
    every declared index, every current variant pointer, every analysis manifest and
    shard hash/size, the v2 file-size ceiling, and the root counts. It intentionally
    does not attempt to prove semantic parity with the archived v1 database; that was
    the one-time migration gate.
    """
    root = root.resolve()
    errors: list[str] = []
    warnings: list[str] = []
    index_path = root / "index.json"
    if not index_path.is_file():
        return {
            "schema": "omega.security-evidence.snapshot-validation.v2",
            "ok": False,
            "mode": "intrinsic",
            "errors": ["index.json is missing"],
            "warnings": [],
        }
    try:
        index = json.loads(index_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "schema": "omega.security-evidence.snapshot-validation.v2",
            "ok": False,
            "mode": "intrinsic",
            "errors": [f"index.json is unreadable: {type(exc).__name__}: {exc}"],
            "warnings": [],
        }
    if index.get("schema") != SCHEMA or int(index.get("formatVersion") or 0) != FORMAT_VERSION:
        errors.append(f"unexpected root schema/version: {index.get('schema')!r}/{index.get('formatVersion')!r}")

    scanner_queue = index.get("scannerQueue") or {}
    if scanner_queue:
        if not isinstance(scanner_queue, dict):
            errors.append("scannerQueue descriptor is not an object")
        else:
            errors.extend(f"scannerQueue: {item}" for item in verify_file_entry(root, scanner_queue, max_bytes=MAX_PUBLISH_FILE_BYTES))
            try:
                queue_doc = read_json_file(root, str(scanner_queue.get("path") or ""))
                if queue_doc.get("schema") not in {
                    "omega.sigmascope.queue-state.v1",
                    "omega.sigmascope.queue-state.v2",
                }:
                    errors.append("scannerQueue payload has an unsupported schema")
            except Exception as exc:
                errors.append(f"scannerQueue unreadable: {type(exc).__name__}: {exc}")

    indexes = index.get("indexes") or {}
    for name, entry in sorted(indexes.items()):
        if not isinstance(entry, dict):
            errors.append(f"index entry {name!r} is not an object")
            continue
        errors.extend(f"index {name}: {item}" for item in verify_file_entry(root, entry, max_bytes=MAX_PUBLISH_FILE_BYTES))

    plugin_entries: list[dict[str, Any]] = []
    terminal_entries: list[dict[str, Any]] = []
    historical_entries: list[dict[str, Any]] = []
    lifecycle_contract = 0
    try:
        plugins_path = str((indexes.get("plugins") or {}).get("path") or "")
        plugins = read_json_file(root, plugins_path)
        plugin_entries = [item for item in (plugins.get("currentVariants") or []) if isinstance(item, dict)]
        terminal_entries = [item for item in (plugins.get("terminalVariants") or []) if isinstance(item, dict)]
        historical_entries = [item for item in (plugins.get("historicalSnapshots") or []) if isinstance(item, dict)]
        lifecycle_contract = int(plugins.get("lifecycleContractVersion") or 0)
        if lifecycle_contract not in {0, 1}:
            errors.append(f"plugins index lifecycle contract is unsupported: {lifecycle_contract}")
    except Exception as exc:  # validation should aggregate rather than abort
        errors.append(f"plugins index unreadable: {type(exc).__name__}: {exc}")

    artifact_index_groups: dict[str, dict[str, Any]] = {}
    try:
        artifacts_path = str((indexes.get("artifacts") or {}).get("path") or "")
        artifacts_index = read_json_file(root, artifacts_path)
        for item in artifacts_index.get("artifacts") or []:
            if not isinstance(item, dict):
                errors.append("artifacts index contains a non-object entry")
                continue
            artifact_key = str(item.get("artifactSha256") or "").strip().lower() or "unknown"
            if artifact_key in artifact_index_groups:
                errors.append(f"duplicate artifact group {artifact_key}")
                continue
            artifact_index_groups[artifact_key] = item
    except Exception as exc:
        errors.append(f"artifacts index unreadable: {type(exc).__name__}: {exc}")

    variant_ids: set[int] = set()
    analysis_ids: set[str] = set()
    referenced_analysis_paths: set[str] = set()
    referenced_files: set[str] = {"index.json"}
    for entry in indexes.values():
        if isinstance(entry, dict) and entry.get("path"):
            try:
                referenced_files.add(safe_relpath(str(entry["path"])))
            except ValueError:
                pass

    def validate_record_descriptor(label: str, dataset: dict[str, Any]) -> None:
        declared_records = int(dataset.get("records") or 0)
        file_records = 0
        row_hashes: list[str] = []
        for file_info in dataset.get("files") or []:
            if not isinstance(file_info, dict):
                errors.append(f"{label}: malformed file entry")
                continue
            errors.extend(f"{label}: {item}" for item in verify_file_entry(root, file_info, max_bytes=MAX_PUBLISH_FILE_BYTES))
            try:
                rel = safe_relpath(str(file_info.get("path") or ""))
                referenced_files.add(rel)
                path = root / rel
                encoding = str(file_info.get("encoding") or "")
                if encoding == "json":
                    value = json.loads(path.read_text(encoding="utf-8"))
                    rows = value if isinstance(value, list) else [value]
                    rows = [row for row in rows if isinstance(row, dict)]
                    for row in rows:
                        row_hashes.append(sha256_bytes(canonical_json_bytes(row)))
                    file_records += len(rows)
                elif encoding == "jsonl+gzip":
                    with gzip.open(path, "rt", encoding="utf-8") as stream:
                        for line in stream:
                            if not line.strip():
                                continue
                            row = json.loads(line)
                            if isinstance(row, dict):
                                row_hashes.append(sha256_bytes(canonical_json_bytes(row)))
                                file_records += 1
                else:
                    errors.append(f"{label}: unsupported encoding {encoding!r}")
            except Exception as exc:
                errors.append(f"{label}: cannot read records: {type(exc).__name__}: {exc}")
        count, digest = dataset_record_digest_from_hashes(row_hashes)
        if count != declared_records or file_records != declared_records:
            errors.append(f"{label}: record count mismatch declared={declared_records}, read={count}")
        if str(dataset.get("recordDigest") or "") != digest:
            errors.append(f"{label}: semantic record digest mismatch")

    for entry in plugin_entries:
        try:
            variant_id = int(entry.get("variantId") or 0)
            if variant_id <= 0:
                raise ValueError("variantId is missing/invalid")
            if variant_id in variant_ids:
                errors.append(f"duplicate current variant {variant_id}")
                continue
            variant_ids.add(variant_id)
            variant_path = safe_relpath(str(entry.get("variantPath") or ""))
            referenced_files.add(variant_path)
            payload = read_json_file(root, variant_path)
            if int(payload.get("variantId") or 0) != variant_id:
                errors.append(f"variant {variant_id} identity mismatch in {variant_path}")
            declared_variant_sha = str(entry.get("variantSha256") or "").strip().lower()
            if declared_variant_sha and declared_variant_sha != sha256_file(root / variant_path):
                errors.append(f"variant {variant_id} plugins index descriptor SHA mismatch")
            declared_summary = entry.get("summary")
            expected_summary = variant_index_summary(
                payload, lifecycle_contract_version=lifecycle_contract
            )
            if declared_summary is not None and declared_summary != expected_summary:
                errors.append(f"variant {variant_id} plugins index summary mismatch")
            if lifecycle_contract == 1:
                lifecycle = payload.get("lifecycle") if isinstance(payload.get("lifecycle"), dict) else {}
                if str(lifecycle.get("schema") or "") != "omega.security-evidence.variant-lifecycle.v1":
                    errors.append(f"variant {variant_id} active lifecycle schema is invalid")
                if str(lifecycle.get("state") or "") != "active":
                    errors.append(f"variant {variant_id} current descriptor lifecycle state is not active")
                if bool(lifecycle.get("terminal")):
                    errors.append(f"variant {variant_id} current descriptor is incorrectly terminal")
                if lifecycle.get("rescanEligible") is False:
                    errors.append(f"variant {variant_id} current descriptor is not rescan eligible")
            current = payload.get("current") or {}
            report = current.get("report_json") if isinstance(current.get("report_json"), dict) else {}
            _validate_identity_contract(variant_id, payload, errors)
            report_source = report.get("source") if isinstance(report.get("source"), dict) else {}
            attribution = report_source.get("attribution") if isinstance(report_source.get("attribution"), dict) else {}
            if attribution:
                try:
                    confidence = int(attribution.get("confidence") or 0)
                except (TypeError, ValueError):
                    confidence = -1
                if confidence not in {0, 40, 70, 95, 100}:
                    errors.append(f"variant {variant_id} source attribution has unsupported confidence {confidence}")
                basis = attribution.get("basis")
                if basis is not None and (not isinstance(basis, list) or any(not isinstance(item, str) for item in basis)):
                    errors.append(f"variant {variant_id} source attribution basis is malformed")
                if confidence == 100 and (not isinstance(basis, list) or "reproducible_build" not in basis):
                    errors.append(f"variant {variant_id} confidence 100 lacks reproducible source-to-artifact proof basis")
                if confidence == 95 and (not isinstance(basis, list) or "pinned_commit" not in basis):
                    errors.append(f"variant {variant_id} confidence 95 lacks pinned commit basis")
            analysis = payload.get("analysis") or {}
            analysis_id = str(analysis.get("analysisId") or "")
            analysis_path = str(analysis.get("path") or "")
            artifact_sha = str(analysis.get("artifactSha256") or current.get("artifact_sha256") or "").lower().strip()
            artifact_key = str(entry.get("artifactSha256") or artifact_sha or "").lower().strip() or "unknown"
            group = artifact_index_groups.get(artifact_key)
            if group is None:
                errors.append(f"variant {variant_id} references missing artifact group {artifact_key}")
            elif variant_id not in {int(value) for value in (group.get("variants") or []) if str(value).isdigit()}:
                errors.append(f"variant {variant_id} is missing from artifact group {artifact_key}")
            derived_evidence = payload.get("derivedEvidence") or {}
            if not isinstance(derived_evidence, dict):
                errors.append(f"variant {variant_id} derivedEvidence is not an object")
            else:
                for dataset_name, dataset in sorted(derived_evidence.items()):
                    if not isinstance(dataset, dict):
                        errors.append(f"variant {variant_id} derived dataset {dataset_name} is not an object")
                        continue
                    validate_record_descriptor(f"variant {variant_id}/derived/{dataset_name}", dataset)
                    if dataset_name == "sourceAnalysisCache":
                        try:
                            cache_rows = read_record_dataset(root, dataset)
                            if len(cache_rows) > 1:
                                errors.append(f"variant {variant_id} source-analysis cache has more than one record")
                            for cache in cache_rows:
                                if str(cache.get("schema") or "") != "omega.security-evidence.source-analysis-cache.v1":
                                    errors.append(f"variant {variant_id} source-analysis cache schema is invalid")
                                    continue
                                payload_value = cache.get("analysisPayload") if isinstance(cache.get("analysisPayload"), dict) else {}
                                payload_sha = sha256_bytes(canonical_json_bytes(payload_value))
                                if str(cache.get("analysisPayloadSha256") or "").lower() != payload_sha:
                                    errors.append(f"variant {variant_id} source-analysis cache payload digest mismatch")
                                if str(payload_value.get("schema") or "") != "omega.sigmascope.source-analysis.v1" or not bool(payload_value.get("analysisComplete")):
                                    errors.append(f"variant {variant_id} source-analysis cache is incomplete")
                                if str(cache.get("sourceRevisionKey") or "") != str(payload_value.get("sourceRevisionKey") or ""):
                                    errors.append(f"variant {variant_id} source-analysis cache revision identity mismatch")
                                if str(cache.get("sourceRootPath") or "") != str(payload_value.get("sourceRootPath") or ""):
                                    errors.append(f"variant {variant_id} source-analysis cache root identity mismatch")
                                if not str(cache.get("sourceAnalysisRevision") or ""):
                                    errors.append(f"variant {variant_id} source-analysis cache lacks analysis revision")
                        except Exception as exc:
                            errors.append(f"variant {variant_id} source-analysis cache cannot be read: {type(exc).__name__}: {exc}")

            if str(current.get("status") or "") == "complete":
                if not analysis_id or not analysis_path:
                    errors.append(f"variant {variant_id} is complete but has no analysis pointer")
                    continue
                if str(entry.get("analysisId") or "") != analysis_id:
                    errors.append(f"variant {variant_id} plugins index analysisId mismatch")
                if str(entry.get("artifactSha256") or "").lower().strip() != artifact_sha:
                    errors.append(f"variant {variant_id} plugins index artifact SHA mismatch")
                analysis_ids.add(analysis_id)
                analysis_path = safe_relpath(analysis_path)
                referenced_analysis_paths.add(analysis_path)
                manifest_rel = f"{analysis_path}/manifest.json"
                referenced_files.add(manifest_rel)
                manifest = read_json_file(root, manifest_rel)
                if group is not None:
                    group_analysis_ids = {str(item.get("analysisId") or "") for item in (group.get("analyses") or []) if isinstance(item, dict)}
                    if analysis_id not in group_analysis_ids:
                        errors.append(f"analysis {analysis_id} is missing from artifact group {artifact_key}")
                if str(manifest.get("analysisId") or "") != analysis_id:
                    errors.append(f"analysis manifest ID mismatch for variant {variant_id}: {analysis_path}")
                if str(manifest.get("artifactSha256") or "").lower().strip() != artifact_sha:
                    errors.append(f"analysis artifact SHA mismatch for variant {variant_id}: {analysis_path}")
                for dataset_name, dataset in sorted((manifest.get("datasets") or {}).items()):
                    if not isinstance(dataset, dict):
                        errors.append(f"analysis {analysis_id} dataset {dataset_name} is not an object")
                        continue
                    declared_records = int(dataset.get("records") or 0)
                    file_records = 0
                    row_hashes: list[str] = []
                    for file_info in dataset.get("files") or []:
                        if not isinstance(file_info, dict):
                            errors.append(f"analysis {analysis_id} dataset {dataset_name} has malformed file entry")
                            continue
                        errors.extend(
                            f"analysis {analysis_id}/{dataset_name}: {item}"
                            for item in verify_file_entry(root, file_info, max_bytes=MAX_PUBLISH_FILE_BYTES)
                        )
                        try:
                            rel = safe_relpath(str(file_info.get("path") or ""))
                            referenced_files.add(rel)
                            path = root / rel
                            encoding = str(file_info.get("encoding") or "")
                            if encoding == "json":
                                value = json.loads(path.read_text(encoding="utf-8"))
                                rows = value if isinstance(value, list) else [value]
                                rows = [row for row in rows if isinstance(row, dict)]
                                for row in rows:
                                    row_hashes.append(sha256_bytes(canonical_json_bytes(row)))
                                file_records += len(rows)
                            elif encoding == "jsonl+gzip":
                                with gzip.open(path, "rt", encoding="utf-8") as stream:
                                    for line in stream:
                                        if not line.strip():
                                            continue
                                        row = json.loads(line)
                                        if isinstance(row, dict):
                                            row_hashes.append(sha256_bytes(canonical_json_bytes(row)))
                                            file_records += 1
                            else:
                                errors.append(f"analysis {analysis_id}/{dataset_name}: unsupported encoding {encoding!r}")
                        except Exception as exc:
                            errors.append(f"analysis {analysis_id}/{dataset_name}: cannot read records: {type(exc).__name__}: {exc}")
                    count, digest = dataset_record_digest_from_hashes(row_hashes)
                    if count != declared_records or file_records != declared_records:
                        errors.append(
                            f"analysis {analysis_id}/{dataset_name}: record count mismatch declared={declared_records}, read={count}"
                        )
                    if str(dataset.get("recordDigest") or "") != digest:
                        errors.append(f"analysis {analysis_id}/{dataset_name}: semantic record digest mismatch")
        except Exception as exc:
            errors.append(f"current variant entry invalid: {type(exc).__name__}: {exc}")

    if lifecycle_contract == 1:
        # New lifecycle-aware snapshots are investigation/history state only. They
        # must never masquerade as active queue candidates, but their immutable
        # artifact analyses remain fully hash/digest validated and referenced.
        for collection_name, expected_state, entries in (
            ("terminalVariants", "retired", terminal_entries),
            ("historicalSnapshots", "superseded", historical_entries),
        ):
            seen_snapshot_paths: set[str] = set()
            for entry in entries:
                try:
                    variant_id = int(entry.get("variantId") or 0)
                    if variant_id <= 0:
                        raise ValueError("variantId is missing/invalid")
                    variant_path = safe_relpath(str(entry.get("variantPath") or ""))
                    if variant_path in seen_snapshot_paths:
                        errors.append(f"duplicate {collection_name} path {variant_path}")
                        continue
                    seen_snapshot_paths.add(variant_path)
                    referenced_files.add(variant_path)
                    payload = read_json_file(root, variant_path)
                    if int(payload.get("variantId") or 0) != variant_id:
                        errors.append(f"{collection_name} variant {variant_id} identity mismatch in {variant_path}")
                    declared_variant_sha = str(entry.get("variantSha256") or "").strip().lower()
                    if not declared_variant_sha or declared_variant_sha != sha256_file(root / variant_path):
                        errors.append(f"{collection_name} variant {variant_id} descriptor SHA mismatch")
                    if entry.get("summary") != variant_index_summary(
                        payload, lifecycle_contract_version=1
                    ):
                        errors.append(f"{collection_name} variant {variant_id} summary mismatch")
                    lifecycle = payload.get("lifecycle") if isinstance(payload.get("lifecycle"), dict) else {}
                    if str(lifecycle.get("schema") or "") != "omega.security-evidence.variant-lifecycle.v1":
                        errors.append(f"{collection_name} variant {variant_id} lifecycle schema is invalid")
                    if str(lifecycle.get("state") or "") != expected_state:
                        errors.append(f"{collection_name} variant {variant_id} lifecycle state is not {expected_state}")
                    if not bool(lifecycle.get("terminal")) or bool(lifecycle.get("rescanEligible", True)):
                        errors.append(f"{collection_name} variant {variant_id} is not terminal/non-rescannable")
                    if payload.get("derivedEvidence"):
                        errors.append(f"{collection_name} variant {variant_id} retains mutable derivedEvidence")

                    current = payload.get("current") if isinstance(payload.get("current"), dict) else {}
                    analysis = payload.get("analysis") if isinstance(payload.get("analysis"), dict) else {}
                    artifact_sha = str(analysis.get("artifactSha256") or current.get("artifact_sha256") or "").strip().lower()
                    artifact_key = str(entry.get("artifactSha256") or artifact_sha or "").strip().lower() or "unknown"
                    group = artifact_index_groups.get(artifact_key)
                    if group is None:
                        errors.append(f"{collection_name} variant {variant_id} references missing artifact group {artifact_key}")
                    analysis_id = str(analysis.get("analysisId") or "")
                    analysis_path = str(analysis.get("path") or "")
                    if str(current.get("status") or "") == "complete":
                        if not analysis_id or not analysis_path:
                            errors.append(f"{collection_name} variant {variant_id} is complete but has no analysis pointer")
                            continue
                        if str(entry.get("analysisId") or "") != analysis_id:
                            errors.append(f"{collection_name} variant {variant_id} analysisId mismatch")
                        if str(entry.get("artifactSha256") or "").strip().lower() != artifact_sha:
                            errors.append(f"{collection_name} variant {variant_id} artifact SHA mismatch")
                        analysis_ids.add(analysis_id)
                        analysis_rel = safe_relpath(analysis_path)
                        referenced_analysis_paths.add(analysis_rel)
                        manifest_rel = f"{analysis_rel}/manifest.json"
                        referenced_files.add(manifest_rel)
                        manifest = read_json_file(root, manifest_rel)
                        if str(manifest.get("analysisId") or "") != analysis_id:
                            errors.append(f"{collection_name} analysis manifest ID mismatch for variant {variant_id}")
                        if str(manifest.get("artifactSha256") or "").strip().lower() != artifact_sha:
                            errors.append(f"{collection_name} analysis artifact SHA mismatch for variant {variant_id}")
                        if group is not None:
                            group_analysis_ids = {
                                str(item.get("analysisId") or "")
                                for item in (group.get("analyses") or []) if isinstance(item, dict)
                            }
                            if analysis_id not in group_analysis_ids:
                                errors.append(f"{collection_name} analysis {analysis_id} is missing from artifact group {artifact_key}")
                        for dataset_name, dataset in sorted((manifest.get("datasets") or {}).items()):
                            if not isinstance(dataset, dict):
                                errors.append(f"{collection_name} analysis {analysis_id} dataset {dataset_name} is malformed")
                                continue
                            declared_records = int(dataset.get("records") or 0)
                            row_hashes: list[str] = []
                            file_records = 0
                            for file_info in dataset.get("files") or []:
                                if not isinstance(file_info, dict):
                                    errors.append(f"{collection_name} analysis {analysis_id}/{dataset_name} has malformed file entry")
                                    continue
                                errors.extend(
                                    f"{collection_name} analysis {analysis_id}/{dataset_name}: {item}"
                                    for item in verify_file_entry(root, file_info, max_bytes=MAX_PUBLISH_FILE_BYTES)
                                )
                                rel = safe_relpath(str(file_info.get("path") or ""))
                                referenced_files.add(rel)
                                data_path = root / rel
                                encoding = str(file_info.get("encoding") or "")
                                if encoding == "json":
                                    value = json.loads(data_path.read_text(encoding="utf-8"))
                                    rows = value if isinstance(value, list) else [value]
                                    rows = [row for row in rows if isinstance(row, dict)]
                                    row_hashes.extend(sha256_bytes(canonical_json_bytes(row)) for row in rows)
                                    file_records += len(rows)
                                elif encoding == "jsonl+gzip":
                                    with gzip.open(data_path, "rt", encoding="utf-8") as stream:
                                        for line in stream:
                                            if not line.strip():
                                                continue
                                            row = json.loads(line)
                                            if isinstance(row, dict):
                                                row_hashes.append(sha256_bytes(canonical_json_bytes(row)))
                                                file_records += 1
                                else:
                                    errors.append(f"{collection_name} analysis {analysis_id}/{dataset_name}: unsupported encoding {encoding!r}")
                            count, digest_value = dataset_record_digest_from_hashes(row_hashes)
                            if count != declared_records or file_records != declared_records:
                                errors.append(f"{collection_name} analysis {analysis_id}/{dataset_name}: record count mismatch")
                            if str(dataset.get("recordDigest") or "") != digest_value:
                                errors.append(f"{collection_name} analysis {analysis_id}/{dataset_name}: semantic record digest mismatch")
                except Exception as exc:
                    errors.append(f"{collection_name} entry invalid: {type(exc).__name__}: {exc}")

    counts = index.get("counts") or {}
    expected_counts = {
        "currentVariants": len(variant_ids),
        "terminalVariants": len(terminal_entries) if lifecycle_contract == 1 else int(counts.get("terminalVariants") or 0),
        "historicalSnapshots": len(historical_entries) if lifecycle_contract == 1 else int(counts.get("historicalSnapshots") or 0),
        "analyses": len(analysis_ids),
        "artifactGroups": len(artifact_index_groups),
    }
    for key, actual in expected_counts.items():
        if int(counts.get(key) or 0) != actual:
            errors.append(f"root count mismatch {key}: index={counts.get(key)!r}, actual={actual}")

    # Every published file must be bounded. Orphan analysis objects are rejected for
    # production snapshots so repeated bounded scans cannot regrow branch storage.
    all_files: set[str] = set()
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if rel.startswith(".git/") or rel.startswith(".staging/") or path.name == ".omega-security-evidence-v2-migration.json":
            continue
        all_files.add(rel)
        if path.stat().st_size > MAX_PUBLISH_FILE_BYTES:
            errors.append(f"published file exceeds {MAX_PUBLISH_FILE_BYTES} byte ceiling: {rel}")
    if require_no_orphans:
        for path in sorted(all_files):
            if path.startswith("artifacts/") and path.endswith("/manifest.json"):
                analysis_dir = path.rsplit("/", 1)[0]
                if analysis_dir not in referenced_analysis_paths:
                    errors.append(f"orphan analysis object is still published: {analysis_dir}")
            if path.startswith("derived/") and path not in referenced_files:
                errors.append(f"orphan derived evidence file is still published: {path}")

    return {
        "schema": "omega.security-evidence.snapshot-validation.v2",
        "ok": not errors,
        "mode": "intrinsic",
        "indexSha256": sha256_file(index_path),
        "evidenceRevision": str((index.get("revisions") or {}).get("evidenceRevision") or ""),
        "checkedVariants": len(variant_ids),
        "checkedAnalyses": len(analysis_ids),
        "errors": errors,
        "warnings": warnings,
    }
