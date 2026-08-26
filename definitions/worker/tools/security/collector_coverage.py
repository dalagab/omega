#!/usr/bin/env python3
"""Reconcile neutral collector coverage goals into the Omega Analysis Broker.

Coverage policy is intentionally separate from SRL findings.  It answers only which
registered observation would improve retained evidence for an already-observed subject.
The broker still owns deduplication, freshness/reuse, provider resolution, leasing and
execution.  This module never downloads artifacts, runs collectors, or writes Evidence-v2.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

try:
    from . import analysis_broker, collector_contracts, security_evidence_v2
except ImportError:
    import analysis_broker  # type: ignore
    import collector_contracts  # type: ignore
    import security_evidence_v2  # type: ignore

SCHEMA = "omega.collector-coverage-reconciliation.v1"
POLICY_SCHEMA = "omega.collector-coverage-policy.v1"
MAX_CANDIDATES = 10_000

POLICIES: tuple[dict[str, Any], ...] = (
    {
        "id": "native-pe-authenticode-v1",
        "observation": "binarySignatureTrust",
        "sourceCollection": "binaryClassifications",
        "match": {"format": "pe", "kind": "native-pe"},
        "priority": 450,
        "reason": "Collect Windows Authenticode trust observations for an exact artifact that contains a retained native PE classification.",
        "scope": "native-pe-artifacts-only",
        "authority": "coverage-request-only",
    },
    {
        "id": "native-elf-structure-v1",
        "observation": "elfBinaryStructure",
        "sourceCollection": "binaryClassifications",
        "match": {"format": "elf", "kind": "native-elf"},
        "priority": 425,
        "reason": "Collect bounded ELF dependency, loader, symbol and hardening structure for an exact artifact that contains a retained native ELF classification.",
        "scope": "native-elf-artifacts-only",
        "authority": "coverage-request-only",
    },
    {
        "id": "native-macho-structure-v1",
        "observation": "machOBinaryStructure",
        "sourceCollection": "binaryClassifications",
        "match": {"kind": "native-mach-o"},
        "priority": 425,
        "reason": "Collect bounded Mach-O dependency, load-command, signing-presence and hardening structure for an exact artifact that contains a retained native Mach-O classification.",
        "scope": "native-mach-o-artifacts-only",
        "authority": "coverage-request-only",
    },
)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def policy_revision() -> str:
    return "collector-coverage-v1-" + _sha({"schema": POLICY_SCHEMA, "policies": POLICIES})[:20]


def _artifact_sha(payload: Mapping[str, Any]) -> str:
    analysis = payload.get("analysis") if isinstance(payload.get("analysis"), Mapping) else {}
    current = payload.get("current") if isinstance(payload.get("current"), Mapping) else {}
    return str(analysis.get("artifactSha256") or current.get("artifact_sha256") or "").strip().lower()


def _binary_rows(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    current = payload.get("current") if isinstance(payload.get("current"), Mapping) else {}
    scan = payload.get("scan") if isinstance(payload.get("scan"), Mapping) else {}
    report = current.get("report_json") if isinstance(current.get("report_json"), Mapping) else {}
    if not report and isinstance(scan.get("report_json"), Mapping):
        report = scan.get("report_json") or {}
    package = report.get("dependencyIntelligence") if isinstance(report.get("dependencyIntelligence"), Mapping) else {}
    return [dict(row) for row in package.get("binaryClassifications") or [] if isinstance(row, Mapping)]


def _matches(row: Mapping[str, Any], wanted: Mapping[str, Any]) -> bool:
    return all(str(row.get(key) or "").casefold() == str(value or "").casefold() for key, value in wanted.items())


def candidate_requests(evidence_root: Path, *, requested_at: str = "") -> list[dict[str, Any]]:
    requests: list[dict[str, Any]] = []
    revision = policy_revision()
    at = requested_at or analysis_broker.utc_now()
    for _entry, payload in security_evidence_v2.iter_variant_entries(evidence_root.resolve()):
        variant_id = int(payload.get("variantId") or 0)
        artifact_sha = _artifact_sha(payload)
        if variant_id <= 0 or len(artifact_sha) != 64:
            continue
        rows = _binary_rows(payload)
        if not rows:
            continue
        subject = {"type": "variant", "variantId": variant_id, "artifactSha256": artifact_sha}
        for policy in POLICIES:
            observation = str(policy["observation"])
            if not collector_contracts.providers_for(observation, include_planned=False):
                continue
            if not any(_matches(row, policy.get("match") or {}) for row in rows):
                continue
            semantic = {
                "policyRevision": revision,
                "policyId": str(policy["id"]),
                "observation": observation,
                "subjectKey": analysis_broker.subject_key(subject),
            }
            request = analysis_broker.compile_request({
                "requestId": "coverage-" + _sha(semantic)[:28],
                "observation": observation,
                "subject": subject,
                "reason": str(policy["reason"]),
                "priority": int(policy["priority"]),
                "requestedBy": {
                    "componentId": "omega.analysis-broker",
                    "policyRevision": revision,
                    "policyId": str(policy["id"]),
                },
                "requestedAtUtc": at,
            })
            requests.append(request)
            if len(requests) > MAX_CANDIDATES:
                raise ValueError(f"collector coverage exceeds {MAX_CANDIDATES} candidate requests")
    unique = {str(item["requestId"]): item for item in requests}
    return [unique[key] for key in sorted(unique)]


def reconcile(
    state: Mapping[str, Any], *, evidence_root: Path, inventory: Mapping[str, Any] | None = None, now: str = "",
) -> tuple[dict[str, Any], dict[str, Any]]:
    at = now or analysis_broker.utc_now()
    requests = candidate_requests(evidence_root, requested_at=at)
    updated = dict(state)
    rows: list[dict[str, Any]] = []
    for request in requests:
        updated, resolution = analysis_broker.enqueue(updated, request, now=at, inventory=inventory)
        rows.append({
            "requestId": str(request.get("requestId") or ""),
            "observation": str(request.get("observation") or ""),
            "subjectKey": str(request.get("subjectKey") or ""),
            "enqueued": bool(resolution.get("enqueued")),
            "deduplicated": bool(resolution.get("deduplicated")),
            "reuseSatisfied": bool(resolution.get("reuseSatisfied")),
            "dispatchable": bool(resolution.get("dispatchable")),
            "workItemIds": list(resolution.get("workItemIds") or []),
        })
    report = {
        "schema": SCHEMA,
        "atUtc": at,
        "policyRevision": policy_revision(),
        "candidateRequests": len(requests),
        "enqueued": sum(1 for row in rows if row["enqueued"]),
        "deduplicated": sum(1 for row in rows if row["deduplicated"]),
        "reused": sum(1 for row in rows if row["reuseSatisfied"]),
        "dispatchable": sum(1 for row in rows if row["dispatchable"]),
        "requests": rows,
        "stateRevision": str(updated.get("stateRevision") or analysis_broker.state_revision(updated)),
        "authority": {
            "coveragePolicy": True,
            "brokerQueueMutation": True,
            "componentExecution": False,
            "ruleEvaluation": False,
            "securityFindings": False,
            "evidenceWrite": False,
        },
    }
    return updated, report


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Reconcile neutral collector coverage into the Analysis Broker")
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--inventory", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    state = _load(args.state) if args.state.is_file() else analysis_broker.empty_state()
    inventory = _load(args.inventory) if args.inventory and args.inventory.is_file() else None
    updated, report = reconcile(state, evidence_root=args.evidence_root, inventory=inventory)
    _write(args.state, updated)
    _write(args.report, report)
    print(json.dumps({"schema": SCHEMA, "candidateRequests": report["candidateRequests"], "enqueued": report["enqueued"], "reused": report["reused"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
