#!/usr/bin/env python3
"""Plan one read-only production SigmaScope parallel drain wave.

The planner never leases or publishes work. It synchronizes the immutable catalog
queue seed with the currently published Security Evidence v2 queue state, applies the
existing coverage-first selector, and partitions exact persistent queue keys into a
bounded worker matrix. Every worker starts from the same Evidence head; only the
serialized merger may combine and publish their result bundles.
"""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
CATALOG_TOOLS = REPO_ROOT / "tools" / "catalog"
if str(CATALOG_TOOLS) not in sys.path:
    sys.path.insert(0, str(CATALOG_TOOLS))

import scan_queue  # noqa: E402

SCHEMA = "omega.sigmascope-parallel-drain-plan.v1"
MAX_WORKERS = 8
MAX_ITEMS_PER_WORKER = 16
MAX_ASSIGNMENTS = 64
PARALLEL_WORK_TYPES = {"artifact", "source"}


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _index_revision(evidence_root: Path) -> tuple[str, str]:
    index = _read(evidence_root / "index.json")
    revisions = index.get("revisions") if isinstance(index.get("revisions"), dict) else {}
    return (
        str(revisions.get("evidenceRevision") or ""),
        str(revisions.get("catalogIdentityEpoch") or index.get("catalogIdentityEpoch") or ""),
    )


def _synchronized_state(seed: dict[str, Any], evidence_root: Path, *, now: dt.datetime | None) -> dict[str, Any]:
    previous = scan_queue.load_state(evidence_root / "scanner-queue.json")
    previous = previous if isinstance(previous, dict) else {}
    seed_epoch = str(seed.get("catalogIdentityEpoch") or "")
    previous_epoch = str(previous.get("catalogIdentityEpoch") or "")
    if previous_epoch and seed_epoch and previous_epoch != seed_epoch:
        previous = {}
    return scan_queue.sync_state(seed, previous, now=now)


def build(
    seed_path: Path,
    evidence_root: Path,
    *,
    workers: int = 4,
    items_per_worker: int = 10,
    wave: int = 1,
    output: Path,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    seed = _read(seed_path)
    if seed.get("schema") != scan_queue.SEED_SCHEMA:
        raise ValueError("unsupported frozen SigmaScope queue seed")

    workers = max(1, min(int(workers), MAX_WORKERS))
    items_per_worker = max(1, min(int(items_per_worker), MAX_ITEMS_PER_WORKER))
    capacity = min(workers * items_per_worker, MAX_ASSIGNMENTS)

    evidence_root = evidence_root.resolve()
    evidence_revision, evidence_epoch = _index_revision(evidence_root)
    state = _synchronized_state(seed, evidence_root, now=now)
    summary_before = scan_queue.state_summary(state)

    assignments: list[dict[str, Any]] = []
    blocked_reason = ""
    serial_fallback_required = False
    slots: list[dict[str, Any]] = [
        {"slot": slot, "lane": "mixed" if workers == 1 else ("updates" if slot % 2 == 0 else "baseline"), "queueKeys": [], "assignmentCount": 0}
        for slot in range(workers)
    ]

    while len(assignments) < capacity:
        ordinal = len(assignments)
        slot = slots[ordinal % workers]
        # A single runner alternates within the batch; one-item waves alternate
        # by wave number too, so neither lane can starve the other.
        preference = slot["lane"] if workers > 1 else ("updates" if (ordinal + max(1, wave) - 1) % 2 == 0 else "baseline")
        item = scan_queue.select_next(state, now=now, preferred_lane=preference)
        if item is None:
            break

        queue_key = str(item.get("queueKey") or "")
        work_type = str(item.get("workType") or "")
        variant_id = int(item.get("variantId") or 0)

        if not queue_key:
            raise ValueError("SigmaScope selector returned an item without queueKey")
        if work_type == "advisory" or variant_id <= 0:
            blocked_reason = "global-or-nonvariant-work-requires-serialized-worker"
            serial_fallback_required = True
            break
        if work_type not in PARALLEL_WORK_TYPES:
            blocked_reason = f"unsupported-parallel-work-type:{work_type}"
            serial_fallback_required = True
            break

        assignments.append({
            "queueKey": queue_key,
            "workType": work_type,
            "variantId": variant_id,
            "internalName": str(item.get("internalName") or ""),
            "sourceName": str(item.get("sourceName") or ""),
            "targetFingerprint": str(item.get("targetFingerprint") or ""),
            "priority": int(item.get("priority") or 0),
            "primaryReason": str(item.get("primaryReason") or ""),
            "selectionLane": int(scan_queue._selection_lane(item)),
            "workerLane": preference,
            "releaseUpdate": scan_queue.plugin_coverage.is_release_update(item),
        })
        slot["queueKeys"].append(queue_key)
        slot["assignmentCount"] += 1

        # This is a local planning copy only. Marking selected keys complete prevents
        # duplicate selection inside the wave without creating a persistent lease.
        state_item = (state.get("items") or {}).get(queue_key)
        if isinstance(state_item, dict):
            state_item["state"] = "complete"

    active_slots = [slot for slot in slots if slot["queueKeys"]]

    probe = copy.deepcopy(state)
    next_item = scan_queue.select_next(probe, now=now)
    more_parallel_eligible = False
    if isinstance(next_item, dict):
        next_work_type = str(next_item.get("workType") or "")
        next_variant_id = int(next_item.get("variantId") or 0)
        more_parallel_eligible = next_work_type in PARALLEL_WORK_TYPES and next_variant_id > 0
        if not more_parallel_eligible and not serial_fallback_required:
            serial_fallback_required = True
            blocked_reason = (
                "global-or-nonvariant-work-requires-serialized-worker"
                if next_work_type == "advisory" or next_variant_id <= 0
                else f"unsupported-parallel-work-type:{next_work_type}"
            )

    semantic = {
        "schema": SCHEMA,
        "authority": "read-only-production-drain-planning",
        "queueSeedRevision": str(seed.get("queueSeedRevision") or ""),
        "catalogRevision": str(seed.get("catalogRevision") or ""),
        "catalogIdentityEpoch": str(seed.get("catalogIdentityEpoch") or ""),
        "evidenceRevision": evidence_revision,
        "evidenceCatalogIdentityEpoch": evidence_epoch,
        "baselineSecurityRebuild": bool(seed.get("baselineSecurityRebuild")),
        "selectionPolicy": str(seed.get("selectionPolicy") or ""),
        "workerAllocationPolicy": "release-and-baseline-lanes-v1",
        "wave": max(1, wave),
        "workers": workers,
        "itemsPerWorker": items_per_worker,
        "capacity": capacity,
        "assignments": assignments,
        "matrix": {"include": active_slots},
        "assignmentCount": len(assignments),
        "activeWorkerCount": len(active_slots),
        "moreParallelEligible": more_parallel_eligible,
        "serialFallbackRequired": serial_fallback_required,
        "blockedReason": blocked_reason,
        "queueSummaryBefore": summary_before,
    }
    digest = hashlib.sha256(_canonical(semantic)).hexdigest()
    document = {**semantic, "planRevision": f"sigmascope-drain-plan-v1-{digest[:20]}"}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return document


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--queue-seed", required=True, type=Path)
    parser.add_argument("--evidence-root", required=True, type=Path)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--items-per-worker", type=int, default=10)
    parser.add_argument("--wave", type=int, default=1)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = build(
        args.queue_seed,
        args.evidence_root,
        workers=args.workers,
        items_per_worker=args.items_per_worker,
        wave=args.wave,
        output=args.output,
    )
    print(json.dumps({
        "planRevision": result["planRevision"],
        "assignmentCount": result["assignmentCount"],
        "activeWorkerCount": result["activeWorkerCount"],
        "moreParallelEligible": result["moreParallelEligible"],
        "serialFallbackRequired": result["serialFallbackRequired"],
        "blockedReason": result["blockedReason"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
