#!/usr/bin/env python3
"""Validate delivered SigmaScope drain bundles against an exact drain plan."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

SCHEMA = "omega.sigmascope-drain-bundle-intake.v1"
PLAN_SCHEMA = "omega.sigmascope-parallel-drain-plan.v1"
SLOT_SUMMARY_SCHEMA = "omega.sigmascope-worker-slot-summary.v1"


def _read_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _atomic_write_json(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _planned_assignments(plan: dict[str, Any], expected: int) -> dict[str, dict[str, Any]]:
    if plan.get("schema") != PLAN_SCHEMA:
        raise ValueError("drain plan schema is invalid")
    assignments = [item for item in plan.get("assignments") or [] if isinstance(item, dict)]
    if len(assignments) != expected:
        raise ValueError("drain plan assignment cardinality is invalid")
    by_key: dict[str, dict[str, Any]] = {}
    for item in assignments:
        key = str(item.get("queueKey") or "")
        if not key:
            raise ValueError("drain plan assignment has no queue key")
        if key in by_key:
            raise ValueError("drain plan assignment uniqueness is invalid")
        by_key[key] = item
    return by_key


def _validate_bundle(path: Path, planned: dict[str, dict[str, Any]]) -> str:
    document = _read_object(path)
    work = document.get("work") if isinstance(document.get("work"), dict) else {}
    key = str(work.get("queueKey") or "")
    if not key:
        raise ValueError(f"result bundle has no queue key: {path}")
    expected = planned.get(key)
    if expected is None:
        raise ValueError(f"result bundles are outside the exact drain plan: {key}")
    for field in ("workType", "variantId", "targetFingerprint"):
        actual = work.get(field)
        wanted = expected.get(field)
        if str(actual) != str(wanted):
            raise ValueError(f"result bundle {key} has mismatched {field}: {actual!r} != {wanted!r}")
    return key


def _slot_summaries(root: Path, plan_revision: str, planned_keys: set[str]) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    if not root.exists():
        return summaries
    for path in sorted(root.rglob("slot-summary.json")):
        summary = _read_object(path)
        if summary.get("schema") != SLOT_SUMMARY_SCHEMA:
            raise ValueError(f"worker slot summary schema is invalid: {path}")
        if str(summary.get("planRevision") or "") != plan_revision:
            raise ValueError(f"worker slot summary plan revision mismatch: {path}")
        keys = [str(key) for key in summary.get("plannedQueueKeys") or []]
        outside = sorted(set(keys) - planned_keys)
        if outside:
            raise ValueError(f"worker slot summary includes unplanned queue keys: {outside}")
        summaries.append({
            "slot": int(summary.get("slot") or 0),
            "lane": str(summary.get("lane") or ""),
            "bundleCount": int(summary.get("bundleCount") or 0),
            "plannedQueueKeys": keys,
            "bundledQueueKeys": [str(key) for key in summary.get("bundledQueueKeys") or []],
            "unprocessedQueueKeys": [str(key) for key in summary.get("unprocessedQueueKeys") or []],
            "unbundledSelectedQueueKeys": [str(key) for key in summary.get("unbundledSelectedQueueKeys") or []],
            "stoppedByBatchBudget": bool(summary.get("stoppedByBatchBudget")),
        })
    return summaries


def build_intake(
    *,
    plan_path: Path,
    artifacts_root: Path,
    expected_assignments: int,
    workers_result: str,
    output: Path,
) -> dict[str, Any]:
    plan = _read_object(plan_path)
    planned = _planned_assignments(plan, expected_assignments)
    bundle_paths = sorted(artifacts_root.rglob("bundle.json")) if artifacts_root.exists() else []
    if not bundle_paths:
        raise ValueError("no finalized SigmaScope result bundles were delivered")

    delivered = [_validate_bundle(path, planned) for path in bundle_paths]
    duplicates = sorted({key for key in delivered if delivered.count(key) > 1})
    if duplicates:
        raise ValueError(f"duplicate delivered queue keys: {duplicates}")
    if len(delivered) > expected_assignments:
        raise ValueError(f"received {len(delivered)} bundles for {expected_assignments} planned assignments")

    delivered_set = set(delivered)
    missing = [key for key in planned if key not in delivered_set]
    document = {
        "schema": SCHEMA,
        "authority": "operational-result-intake-only",
        "planRevision": str(plan.get("planRevision") or ""),
        "workersResult": str(workers_result or ""),
        "plannedCount": expected_assignments,
        "receivedCount": len(delivered),
        "missingCount": len(missing),
        "receivedQueueKeys": delivered,
        "missingQueueKeys": missing,
        "slotSummaries": _slot_summaries(artifacts_root, str(plan.get("planRevision") or ""), set(planned)),
    }
    _atomic_write_json(output, document)
    return document


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--artifacts-root", required=True, type=Path)
    parser.add_argument("--expected-assignments", required=True, type=int)
    parser.add_argument("--workers-result", default="")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    intake = build_intake(
        plan_path=args.plan,
        artifacts_root=args.artifacts_root,
        expected_assignments=args.expected_assignments,
        workers_result=args.workers_result,
        output=args.output,
    )
    print(
        f"Accepted {intake['receivedCount']}/{intake['plannedCount']} exact result bundles; "
        f"{intake['missingCount']} planned key(s) remain pending/retryable."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
