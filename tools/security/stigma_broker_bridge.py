#!/usr/bin/env python3
"""Idempotently feed production Stigma-1 dependencies into the Analysis Broker.

The bridge consumes deterministic rule-projection request sidecars already published with
Security Evidence v2. It never evaluates rules itself and never executes components. Typed
``observationRequest`` rows become generic ``omega.analysis-request.v1`` records. Legacy
reprojection gaps (missing retained SigmaScope observation collections) are translated to the
same generic request contract when a registered provider exists.

The request id is stable for rule/ruleset + observation + exact current variant/artifact. This
makes repeated reconciliation safe: one unresolved dependency maps to one logical broker item.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

import analysis_broker
import collector_contracts
import security_evidence_v2

SCHEMA = "omega.stigma-analysis-broker-bridge.v1"
MAX_REQUESTS = 50_000


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON payload must be an object: {path}")
    return value


def _variant_subjects(evidence_root: Path) -> dict[int, dict[str, Any]]:
    result: dict[int, dict[str, Any]] = {}
    for entry, payload in security_evidence_v2.iter_variant_entries(evidence_root):
        current = payload.get("current") if isinstance(payload.get("current"), Mapping) else {}
        variant_id = int(payload.get("variantId") or entry.get("variantId") or 0)
        if variant_id <= 0:
            continue
        artifact_sha = str(current.get("artifact_sha256") or "").strip().lower()
        subject: dict[str, Any] = {"type": "variant", "variantId": variant_id}
        if artifact_sha:
            subject["artifactSha256"] = artifact_sha
        result[variant_id] = subject
    return result


def _stable_request_id(kind: str, *, observation: str, subject: Mapping[str, Any], rule_id: str = "", rule_revision: str = "", rule_set_revision: str = "") -> str:
    semantic = {
        "kind": kind,
        "observation": observation,
        "subjectKey": analysis_broker.subject_key(subject),
        "ruleId": rule_id,
        "ruleRevision": rule_revision,
        "ruleSetRevision": rule_set_revision,
    }
    return f"stigma-{kind}-{_sha(semantic)[:28]}"


def _observation_analysis_request(raw: Mapping[str, Any], subject: Mapping[str, Any], *, requested_at: str, projection_revision: str) -> dict[str, Any]:
    request = analysis_broker.from_observation_request(raw, subject, requested_at=requested_at, evaluation_id=projection_revision)
    request["requestId"] = _stable_request_id(
        "observation", observation=str(request.get("observation") or ""), subject=subject,
        rule_id=str(raw.get("ruleId") or ""), rule_revision=str(raw.get("ruleRevision") or ""),
        rule_set_revision=str(raw.get("ruleSetRevision") or ""),
    )
    return analysis_broker.compile_request(request)


def _reanalysis_requests(raw: Mapping[str, Any], subject: Mapping[str, Any], *, requested_at: str, projection_revision: str) -> list[dict[str, Any]]:
    rule_set_revision = str(raw.get("ruleSetRevision") or "")
    collections = sorted({
        str(item) for key in ("missingCollections", "boundedCompatibilityCollections")
        for item in (raw.get(key) or []) if str(item)
    })
    result: list[dict[str, Any]] = []
    for observation in collections:
        if not collector_contracts.providers_for(observation, include_planned=True):
            continue
        request_id = _stable_request_id(
            "reanalysis", observation=observation, subject=subject, rule_set_revision=rule_set_revision,
        )
        result.append(analysis_broker.compile_request({
            "requestId": request_id,
            "observation": observation,
            "subject": dict(subject),
            "reason": str(raw.get("reason") or f"Stigma-1 requires retained {observation} evidence")[:1000],
            "priority": 850,
            "requestedBy": {
                "componentId": "omega.stigma-1",
                "ruleRevision": rule_set_revision,
                "evaluationId": projection_revision,
            },
            "requestedAtUtc": requested_at,
        }))
    return result


def _load_request_docs(projection_root: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    index = _json(projection_root / "index.json")
    obs_descriptor = index.get("observationRequests") if isinstance(index.get("observationRequests"), Mapping) else {}
    re_descriptor = index.get("reanalysisRequests") if isinstance(index.get("reanalysisRequests"), Mapping) else {}
    observation_doc = _json(projection_root / str(obs_descriptor.get("path") or "observation-requests.json")) if obs_descriptor or (projection_root / "observation-requests.json").is_file() else {"requests": []}
    reanalysis_doc = _json(projection_root / str(re_descriptor.get("path") or "reanalysis-requests.json")) if re_descriptor or (projection_root / "reanalysis-requests.json").is_file() else {"requests": []}
    return index, observation_doc, reanalysis_doc


def reconcile(
    state: Mapping[str, Any], *, projection_root: Path, evidence_root: Path,
    inventory: Mapping[str, Any] | None = None, now: str = "",
) -> tuple[dict[str, Any], dict[str, Any]]:
    projection_root = projection_root.resolve()
    evidence_root = evidence_root.resolve()
    projection_index, observation_doc, reanalysis_doc = _load_request_docs(projection_root)
    if not bool(projection_index.get("observationRequestBrokerMutationAuthorized")):
        report = {
            "schema": SCHEMA,
            "atUtc": now or analysis_broker.utc_now(),
            "projectionSetRevision": str(projection_index.get("projectionSetRevision") or ""),
            "ruleSetRevision": str(projection_index.get("ruleSetRevision") or ""),
            "candidateRequests": 0, "enqueued": 0, "deduplicated": 0, "reused": 0, "dispatchable": 0,
            "skipped": [], "requests": [],
            "stateRevision": str(state.get("stateRevision") or analysis_broker.state_revision(state)),
            "reason": "projection set does not authorize Analysis Broker request mutation",
            "authority": {"ruleEvaluation": False, "componentExecution": False, "brokerQueueMutation": False, "securityFindings": False},
        }
        return dict(state), report
    subjects = _variant_subjects(evidence_root)
    requested_at = now or analysis_broker.utc_now()
    projection_revision = str(projection_index.get("projectionSetRevision") or "")
    requests: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []

    for raw in observation_doc.get("requests") or []:
        if not isinstance(raw, Mapping):
            continue
        variant_id = int(raw.get("variantId") or 0)
        subject = subjects.get(variant_id)
        if subject is None:
            skipped.append({"kind": "observation", "variantId": variant_id, "reason": "variant-not-current"})
            continue
        requested_artifact = str(raw.get("artifactSha256") or "").strip().lower()
        current_artifact = str(subject.get("artifactSha256") or "")
        if requested_artifact and current_artifact and requested_artifact != current_artifact:
            skipped.append({"kind": "observation", "variantId": variant_id, "reason": "artifact-superseded"})
            continue
        requests.append(_observation_analysis_request(raw, subject, requested_at=requested_at, projection_revision=projection_revision))

    for raw in reanalysis_doc.get("requests") or []:
        if not isinstance(raw, Mapping):
            continue
        variant_id = int(raw.get("variantId") or 0)
        subject = subjects.get(variant_id)
        if subject is None:
            skipped.append({"kind": "reanalysis", "variantId": variant_id, "reason": "variant-not-current"})
            continue
        translated = _reanalysis_requests(raw, subject, requested_at=requested_at, projection_revision=projection_revision)
        if not translated and (raw.get("missingCollections") or raw.get("boundedCompatibilityCollections")):
            skipped.append({"kind": "reanalysis", "variantId": variant_id, "reason": "no-registered-provider"})
        requests.extend(translated)

    unique: dict[str, dict[str, Any]] = {}
    for request in requests:
        unique[str(request["requestId"])] = request
    requests = [unique[key] for key in sorted(unique)]
    if len(requests) > MAX_REQUESTS:
        raise ValueError(f"Stigma broker bridge exceeds {MAX_REQUESTS} requests")

    updated = dict(state)
    results: list[dict[str, Any]] = []
    for request in requests:
        updated, resolution = analysis_broker.enqueue(updated, request, now=requested_at, inventory=inventory)
        results.append({
            "requestId": str(request.get("requestId") or ""),
            "observation": str(request.get("observation") or ""),
            "subjectKey": str(request.get("subjectKey") or ""),
            "enqueued": bool(resolution.get("enqueued")),
            "deduplicated": bool(resolution.get("deduplicated")),
            "reused": bool(resolution.get("reused")),
            "dispatchable": bool(resolution.get("dispatchable")),
            "reuseSatisfied": bool(resolution.get("reuseSatisfied")),
            "workItemIds": list(resolution.get("workItemIds") or []),
        })

    report = {
        "schema": SCHEMA,
        "atUtc": requested_at,
        "projectionSetRevision": projection_revision,
        "ruleSetRevision": str(projection_index.get("ruleSetRevision") or ""),
        "candidateRequests": len(requests),
        "enqueued": sum(1 for item in results if item["enqueued"]),
        "deduplicated": sum(1 for item in results if item["deduplicated"]),
        "reused": sum(1 for item in results if item["reused"] or item["reuseSatisfied"]),
        "dispatchable": sum(1 for item in results if item["dispatchable"]),
        "skipped": skipped,
        "requests": results,
        "stateRevision": str(updated.get("stateRevision") or analysis_broker.state_revision(updated)),
        "authority": {
            "ruleEvaluation": False,
            "componentExecution": False,
            "brokerQueueMutation": True,
            "securityFindings": False,
        },
    }
    return updated, report


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Reconcile retained production Stigma dependencies into Analysis Broker state")
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--projection-root", required=True, type=Path)
    parser.add_argument("--evidence-root", required=True, type=Path)
    parser.add_argument("--inventory", type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    state = _json(args.state) if args.state.is_file() else analysis_broker.empty_state()
    inventory = _json(args.inventory) if args.inventory and args.inventory.is_file() else None
    updated, report = reconcile(state, projection_root=args.projection_root, evidence_root=args.evidence_root, inventory=inventory)
    _write(args.state, updated)
    _write(args.report, report)
    print(json.dumps({"schema": SCHEMA, "candidateRequests": report["candidateRequests"], "enqueued": report["enqueued"], "reused": report["reused"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
