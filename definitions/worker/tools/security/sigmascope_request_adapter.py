#!/usr/bin/env python3
"""Adapt generic Omega analysis requests into SigmaScope's canonical scan queue.

This is deliberately an adapter, not a second scanner queue. The Analysis Broker owns
logical observation requests; SigmaScope continues to own its existing event-driven
queue state and Evidence-v2 publication semantics. A broker-dispatched request is
bound to one exact active variant and merged into the corresponding canonical
artifact/source queue item so satisfying the broker request also advances normal
SigmaScope queue state instead of creating duplicate work.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import sqlite3
import sys
from typing import Any, Mapping

SCRIPT_DIR = Path(__file__).resolve().parent
CATALOG_DIR = SCRIPT_DIR.parent / "catalog"
for item in (SCRIPT_DIR, CATALOG_DIR):
    if str(item) not in sys.path:
        sys.path.insert(0, str(item))

import analysis_broker  # noqa: E402
import collector_contracts  # noqa: E402
import observation_projection  # noqa: E402
import scan_queue  # noqa: E402

TARGET_SCHEMA = "omega.sigmascope.analysis-target.v1"
VERIFICATION_SCHEMA = "omega.sigmascope.analysis-request-verification.v1"
COMPONENT_ID = "omega.sigmascope"
MAX_REQUEST_LINKS_PER_QUEUE_ITEM = 16

_ARTIFACT_COLLECTORS = {
    "omega.collector.sigmascope.artifact-static",
    "omega.collector.sigmascope.secondary-security",
}
_SOURCE_COLLECTORS = {"omega.collector.sigmascope.source-analysis"}
_SPECIAL_COLLECTORS = {
    "omega.collector.sigmascope.authenticode": "authenticode",
    "omega.collector.sigmascope.native-structure": "native-structure",
}


def _json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON payload must be an object: {path}")
    return value


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def _provider_contract(observation: str) -> tuple[str, list[str]]:
    providers = []
    for collector_id in collector_contracts.providers_for(observation, include_planned=False):
        collector = collector_contracts.collector_map().get(collector_id) or {}
        if str(collector.get("componentId") or "") == COMPONENT_ID:
            providers.append(collector_id)
    if not providers:
        raise ValueError(f"observation {observation!r} has no active SigmaScope provider")
    work_types: set[str] = set()
    for collector_id in providers:
        if collector_id in _ARTIFACT_COLLECTORS:
            work_types.add("artifact")
        elif collector_id in _SOURCE_COLLECTORS:
            work_types.add("source")
        elif collector_id in _SPECIAL_COLLECTORS:
            work_types.add(_SPECIAL_COLLECTORS[collector_id])
        else:
            raise ValueError(f"SigmaScope provider has no request-adapter work mapping: {collector_id}")
    if len(work_types) != 1:
        raise ValueError(f"observation {observation!r} maps ambiguously to SigmaScope work types: {sorted(work_types)}")
    return next(iter(work_types)), sorted(providers)


def compile_sigmascope_request(value: Mapping[str, Any]) -> dict[str, Any]:
    request = analysis_broker.compile_request(value)
    work_type, providers = _provider_contract(str(request.get("observation") or ""))
    subject = request.get("subject") if isinstance(request.get("subject"), Mapping) else {}
    if int(subject.get("variantId") or 0) <= 0 and not str(subject.get("artifactSha256") or ""):
        raise ValueError("SigmaScope generic requests require subject.variantId or an already-observed artifactSha256")
    return {**request, "sigmascopeWorkType": work_type, "sigmascopeProviders": providers}


def _variant_query(db: sqlite3.Connection, where: str, params: tuple[Any, ...]) -> list[sqlite3.Row]:
    columns = {str(row[1]).casefold() for row in db.execute("PRAGMA table_info(plugin_variants)")}
    update_projection = "v.download_link_update" if "download_link_update" in columns else "'' AS download_link_update"
    return db.execute(f"""
        SELECT v.variant_id,v.plugin_id,v.source_id,p.internal_name,v.name,v.assembly_version,v.testing_assembly_version,
               v.download_link_install,{update_projection},v.download_link_testing,v.repo_url,
               s.name AS source_name,s.source_repo_url,sc.*
          FROM plugin_variants v
          JOIN plugins p ON p.plugin_id=v.plugin_id
          JOIN sources s ON s.source_id=v.source_id
          LEFT JOIN plugin_security_current sc ON sc.variant_id=v.variant_id
         WHERE v.active=1 AND p.active=1 AND ({where})
         ORDER BY v.variant_id
    """, params).fetchall()


def _resolve_variant(db: sqlite3.Connection, request: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any] | None]:
    subject = request.get("subject") if isinstance(request.get("subject"), Mapping) else {}
    variant_id = int(subject.get("variantId") or 0)
    artifact_sha = str(subject.get("artifactSha256") or "").strip().lower()
    if variant_id > 0:
        rows = _variant_query(db, "v.variant_id=?", (variant_id,))
    elif artifact_sha:
        rows = _variant_query(db, "lower(COALESCE(sc.artifact_sha256,''))=?", (artifact_sha,))
    else:
        rows = []
    if not rows:
        raise ValueError("SigmaScope request subject does not resolve to an active canonical variant")
    if len(rows) > 1:
        raise ValueError("SigmaScope request subject resolves to multiple active variants; provide subject.variantId")
    row = rows[0]
    stable = str(row["download_link_install"] or "").strip()
    testing = str(row["download_link_testing"] or "").strip()
    if not stable and not testing:
        raise ValueError("resolved SigmaScope variant has no installable artifact URL")
    variant = {
        "variantId": int(row["variant_id"]),
        "pluginId": int(row["plugin_id"]),
        "sourceId": int(row["source_id"]),
        "internalName": str(row["internal_name"] or ""),
        "name": str(row["name"] or ""),
        "sourceName": str(row["source_name"] or ""),
        "assemblyVersion": str(row["assembly_version"] or "") if stable else str(row["testing_assembly_version"] or row["assembly_version"] or ""),
        "artifactChannel": "stable" if stable else "testing",
        "artifactUrl": stable or testing,
        "repositoryUrl": str(row["repo_url"] or ""),
        "sourceRepositoryUrl": str(row["source_repo_url"] or ""),
    }
    current = dict(row) if row["scan_id"] is not None else None
    if artifact_sha:
        current_sha = str((current or {}).get("artifact_sha256") or "").strip().lower()
        if not current_sha:
            raise ValueError("artifactSha256 subjects must already be bound to the variant in retained Evidence-v2")
        if current_sha != artifact_sha:
            raise ValueError(f"artifactSha256 does not match the retained variant artifact: {artifact_sha} != {current_sha}")
    requested_plugin = int(subject.get("pluginId") or 0)
    if requested_plugin and requested_plugin != int(variant["pluginId"]):
        raise ValueError("subject.pluginId does not match the resolved variant")
    return variant, current


def _request_link(request: Mapping[str, Any], work_item_id: str) -> dict[str, Any]:
    return {
        "requestId": str(request.get("requestId") or ""),
        "workItemId": str(work_item_id or ""),
        "observation": str(request.get("observation") or ""),
        "reason": str(request.get("reason") or "")[:1000],
        "priority": int(request.get("priority") or 0),
        "requestedBy": copy.deepcopy(dict(request.get("requestedBy") or {})),
        "subjectKey": str(request.get("subjectKey") or ""),
    }


def _merge_request_metadata(item: dict[str, Any], request: Mapping[str, Any], work_item_id: str) -> None:
    observation = str(request.get("observation") or "")
    collections = {str(value) for value in item.get("requiredObservationCollections") or [] if str(value)}
    collections.add(observation)
    item["requiredObservationCollections"] = sorted(collections)
    links = [dict(value) for value in item.get("analysisRequests") or [] if isinstance(value, Mapping)]
    link = _request_link(request, work_item_id)
    links = [value for value in links if str(value.get("requestId") or "") != link["requestId"]]
    links.append(link)
    item["analysisRequests"] = links[-MAX_REQUEST_LINKS_PER_QUEUE_ITEM:]
    reasons = [str(value) for value in item.get("reasons") or [] if str(value)]
    if "analysis_observation_requested" not in reasons:
        reasons.append("analysis_observation_requested")
    reasons = sorted(set(reasons), key=lambda reason: (-scan_queue.REASON_PRIORITIES.get(reason, 0), reason))
    item["reasons"] = reasons
    item["primaryReason"] = reasons[0] if reasons else ""
    item["priority"] = max(int(item.get("priority") or 0), int(request.get("priority") or 0), scan_queue.REASON_PRIORITIES["analysis_observation_requested"])
    # A brokered hard dependency always means this target must be attempted again even
    # when a prior queue entry for the same frozen target was marked complete.
    item["state"] = "pending"
    item["nextEligibleAtUtc"] = ""
    item["lastAttemptStatus"] = ""
    item["lastError"] = ""


def enqueue_request(
    queue_state: dict[str, Any], db: sqlite3.Connection, request_value: Mapping[str, Any], *,
    work_item_id: str = "", definitions_root: Path | None = None,
) -> dict[str, Any]:
    request = compile_sigmascope_request(request_value)
    work_type = str(request["sigmascopeWorkType"])
    if work_type not in {"artifact", "source"}:
        raise ValueError(f"SigmaScope work type {work_type!r} is handled by a dedicated collector lane, not the canonical scan queue")
    variant, current = _resolve_variant(db, request)
    generated_at = scan_queue.utc_now()
    if work_type == "source":
        if not current or str(current.get("status") or "") != "complete":
            raise ValueError("source observation request requires a completed artifact scan prerequisite")
        observations = scan_queue.source_observations(definitions_root) if definitions_root is not None else {}
        candidate = scan_queue._source_queue_item(
            variant, current, ["analysis_observation_requested"],
            catalog_revision=str(queue_state.get("catalogRevision") or ""),
            catalog_identity_epoch=str(queue_state.get("catalogIdentityEpoch") or ""),
            definitions_revision=str(queue_state.get("definitionsRevision") or ""),
            scanner_revision=str(queue_state.get("scannerRevision") or ""),
            source_analysis_revision=str(queue_state.get("sourceAnalysisRevision") or ""),
            rule_set_revision=str(queue_state.get("ruleSetRevision") or ""),
            generated_at=generated_at, observations=observations,
            priority_override=int(request.get("priority") or 0),
        )
    else:
        candidate = scan_queue._queue_item(
            variant, current, ["analysis_observation_requested"],
            catalog_revision=str(queue_state.get("catalogRevision") or ""),
            catalog_identity_epoch=str(queue_state.get("catalogIdentityEpoch") or ""),
            definitions_revision=str(queue_state.get("definitionsRevision") or ""),
            scanner_revision=str(queue_state.get("scannerRevision") or ""),
            artifact_analysis_revision=str(queue_state.get("artifactAnalysisRevision") or ""),
            rule_set_revision=str(queue_state.get("ruleSetRevision") or ""),
            generated_at=generated_at,
        )
    key = str(candidate["queueKey"])
    existing = (queue_state.get("items") or {}).get(key)
    if isinstance(existing, dict) and str(existing.get("targetFingerprint") or "") == str(candidate.get("targetFingerprint") or ""):
        item = existing
    else:
        item = candidate
        item.update({
            "dynamic": True, "attemptCount": 0, "recentAttempts": [], "state": "pending",
            "nextEligibleAtUtc": "", "lastAttemptStatus": "", "lastError": "",
        })
        queue_state.setdefault("items", {})[key] = item
    _merge_request_metadata(item, request, work_item_id)
    queue_state["updatedAtUtc"] = generated_at
    return {
        "schema": TARGET_SCHEMA,
        "requestId": str(request["requestId"]),
        "workItemId": str(work_item_id or ""),
        "componentId": COMPONENT_ID,
        "observation": str(request["observation"]),
        "providers": list(request["sigmascopeProviders"]),
        "workType": work_type,
        "queueKey": key,
        "variantId": int(variant["variantId"]),
        "pluginId": int(variant["pluginId"]),
        "artifactSha256": str((current or {}).get("artifact_sha256") or "").strip().lower(),
        "subjectKey": str(request.get("subjectKey") or ""),
        "freshness": copy.deepcopy(dict(request.get("freshness") or {})),
    }


def verify_target(evidence_root: Path, target: Mapping[str, Any]) -> dict[str, Any]:
    if str(target.get("schema") or "") != TARGET_SCHEMA:
        raise ValueError(f"analysis target schema must be {TARGET_SCHEMA}")
    variant_id = int(target.get("variantId") or 0)
    observation = str(target.get("observation") or "")
    variant_path = evidence_root / "variants" / f"{variant_id // 1000:04d}" / f"{variant_id}.json"
    if not variant_path.is_file():
        raise ValueError(f"candidate Evidence-v2 has no variant {variant_id}")
    variant = _json(variant_path)
    observations = variant.get("observations") if isinstance(variant.get("observations"), Mapping) else {}
    collections = observations.get("collections") if isinstance(observations.get("collections"), Mapping) else {}
    descriptor = collections.get(observation) if isinstance(collections.get(observation), Mapping) else None
    if descriptor is None:
        raise ValueError(f"requested SigmaScope observation {observation!r} is absent from candidate Evidence-v2 variant {variant_id}")
    completeness = str(descriptor.get("completeness") or "")
    if completeness not in {"retained", "retained-snapshot", "complete"}:
        raise ValueError(f"requested SigmaScope observation {observation!r} is not retained-complete: {completeness!r}")
    return {
        "schema": VERIFICATION_SCHEMA,
        "ok": True,
        "requestId": str(target.get("requestId") or ""),
        "workItemId": str(target.get("workItemId") or ""),
        "variantId": variant_id,
        "observation": observation,
        "completeness": completeness,
        "records": int(descriptor.get("records") or 0),
        "recordDigest": str(descriptor.get("recordDigest") or ""),
        "observationContractRevision": str(observations.get("contractRevision") or observation_projection.contract_revision()),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Adapt/verify generic broker work for SigmaScope without creating a second scanner queue")
    sub = parser.add_subparsers(dest="command", required=True)
    p_verify = sub.add_parser("verify")
    p_verify.add_argument("--evidence-root", type=Path, required=True)
    p_verify.add_argument("--target", type=Path, required=True)
    p_verify.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.command == "verify":
        result = verify_target(args.evidence_root, _json(args.target))
        if args.output:
            _write(args.output, result)
        else:
            print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
        return 0
    raise AssertionError(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
