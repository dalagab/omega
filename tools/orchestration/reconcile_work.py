#!/usr/bin/env python3
"""Reconcile, settle and lease cadence-driven Omega security work.

The reconciler owns queue mutation.  Workers receive an exact durable lease, publish a
lease-bound omega.work-result.v1 on a lane-specific branch, and never mutate queues.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import sys
from typing import Any, Mapping

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import work_queue  # noqa: E402
import work_result  # noqa: E402

SECURITY = HERE.parent / "security"
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))
import component_registry  # noqa: E402

POLICY_SCHEMA = "omega.orchestration-policy.v1"
INDEX_SCHEMA = "omega.work-state.v1"
DISPATCH_SCHEMA = "omega.work-dispatch-plan.v1"


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _sha_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _parse_utc(value: str) -> datetime:
    text = str(value or "").replace("Z", "+00:00")
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _bucket(now: datetime, cadence: int) -> str:
    seconds = int(now.timestamp())
    start = seconds - (seconds % cadence)
    return datetime.fromtimestamp(start, tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _clean_consumer(row: Mapping[str, Any], queue_id: str) -> dict[str, Any]:
    consumer = row.get("consumer") if isinstance(row.get("consumer"), Mapping) else {}
    implemented = bool(consumer.get("implemented", False))
    if not implemented:
        return {"implemented": False}
    owner = str(consumer.get("leaseOwner") or "").strip()
    workflow = str(consumer.get("workflow") or "").strip()
    result_branch = str(consumer.get("resultBranch") or "").strip()
    lease_seconds = int(consumer.get("leaseSeconds") or 1800)
    if not owner or not workflow or not result_branch:
        raise ValueError(f"implemented queue {queue_id} requires leaseOwner/workflow/resultBranch")
    if not workflow.endswith(".yml") or "/" in workflow or "\\" in workflow:
        raise ValueError(f"queue {queue_id} has invalid workflow name")
    if lease_seconds < 300 or lease_seconds > 86_400:
        raise ValueError(f"queue {queue_id} leaseSeconds out of range")
    return {
        "implemented": True,
        "leaseOwner": owner,
        "workflow": workflow,
        "resultBranch": result_branch,
        "leaseSeconds": lease_seconds,
    }


def validate_policy(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or str(value.get("schema") or "") != POLICY_SCHEMA:
        raise ValueError(f"policy schema must be {POLICY_SCHEMA}")
    rows = value.get("queues") if isinstance(value.get("queues"), list) else []
    if not rows:
        raise ValueError("orchestration policy has no queues")
    seen: set[str] = set(); queues: list[dict[str, Any]] = []
    components = component_registry.component_map()
    for row in rows:
        if not isinstance(row, Mapping):
            raise ValueError("policy queue row must be an object")
        queue_id = str(row.get("queueId") or "").strip()
        component = str(row.get("component") or "").strip()
        kind = str(row.get("kind") or "").strip()
        if not queue_id or not component or not kind:
            raise ValueError("policy queue requires queueId/component/kind")
        if component not in components:
            raise ValueError(f"policy queue {queue_id} references unknown component: {component}")
        if queue_id in seen:
            raise ValueError(f"duplicate policy queueId: {queue_id}")
        seen.add(queue_id)
        cadence = int(row.get("cadenceSeconds") or 0)
        if cadence < 3600 or cadence > 31_536_000:
            raise ValueError(f"queue {queue_id} cadenceSeconds out of range")
        priority = int(row.get("priority") or 0)
        if priority < 0 or priority > 1000:
            raise ValueError(f"queue {queue_id} priority out of range")
        subject = row.get("subject") if isinstance(row.get("subject"), Mapping) else {}
        reason = row.get("reason") if isinstance(row.get("reason"), list) else [row.get("reason")]
        queues.append({
            "queueId": queue_id, "component": component, "kind": kind,
            "cadenceSeconds": cadence, "priority": priority, "subject": dict(subject),
            "reason": reason, "consumer": _clean_consumer(row, queue_id),
            "prerequisites": [str(item).strip() for item in (row.get("prerequisites") or []) if str(item).strip()],
        })
    known = {row["queueId"] for row in queues}
    for row in queues:
        unknown = [item for item in row["prerequisites"] if item not in known]
        if unknown:
            raise ValueError(f"queue {row['queueId']} has unknown prerequisites: {unknown}")
        if row["queueId"] in row["prerequisites"]:
            raise ValueError(f"queue {row['queueId']} cannot depend on itself")
    return {"schema": POLICY_SCHEMA, "version": int(value.get("version") or 1), "queues": queues}


def _queue_path(root: Path, queue_id: str) -> Path:
    return root / "queues" / f"{queue_id}.json"


def _load_previous_queue(root: Path | None, queue_id: str, component: str, now: str) -> dict[str, Any]:
    if root is not None:
        path = _queue_path(root, queue_id)
        if path.is_file():
            queue = work_queue.validate_queue(json.loads(path.read_text(encoding="utf-8")))
            if queue["component"] != component:
                raise ValueError(f"previous queue {queue_id} changed component")
            return queue
    return work_queue.new_queue(queue_id, component, now=now)


def _leased_item(queue: Mapping[str, Any]) -> dict[str, Any] | None:
    leased = [dict(item) for item in queue.get("items") or [] if isinstance(item, Mapping) and str(item.get("state") or "") == "leased"]
    if len(leased) > 1:
        raise ValueError(f"queue {queue.get('queueId')} has more than one active lease")
    return leased[0] if leased else None


def _settle_lane_result(queue: Mapping[str, Any], spec: Mapping[str, Any], results_root: Path | None,
                        now: str) -> tuple[dict[str, Any], bool]:
    consumer = spec["consumer"]
    if not consumer.get("implemented") or results_root is None:
        return dict(queue), False
    current = _leased_item(queue)
    if current is None:
        return dict(queue), False
    lane_root = results_root / spec["queueId"]
    result_path = lane_root / "result.json"
    if not result_path.is_file():
        return dict(queue), False
    try:
        header = json.loads(result_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"{spec['queueId']} result header unreadable: {type(exc).__name__}: {exc}") from exc
    # A lane branch normally still contains the previous completed cadence while a new
    # cadence is leased. That stale result is harmless and must not block reconciliation.
    if str(header.get("workId") or "") != current["workId"]:
        return dict(queue), False
    lease = current.get("lease") or {}
    result = work_result.validate_result(
        lane_root,
        expected_queue_id=spec["queueId"],
        expected_work_id=current["workId"],
        expected_owner=str(consumer["leaseOwner"]),
        expected_claim_token=str(lease.get("claimToken") or ""),
    )
    settled, _ = work_queue.settle(
        queue,
        work_id=current["workId"],
        claim_token=str(lease.get("claimToken") or ""),
        outcome=result["outcome"],
        reason=result.get("reason") or "",
        result_revision=result["resultRevision"],
        result_sha256=_sha_file(result_path),
        retry_after_seconds=int(result.get("retryAfterSeconds") or 0),
        now=now,
    )
    return settled, True


def reconcile(*, policy: Mapping[str, Any], previous_root: Path | None, output_root: Path,
              results_root: Path | None = None, now: str = "") -> dict[str, Any]:
    policy_value = validate_policy(policy)
    at = now or work_queue.utc_now(); at_dt = _parse_utc(at)
    if output_root.exists():
        shutil.rmtree(output_root)
    (output_root / "queues").mkdir(parents=True, exist_ok=True)
    descriptors: list[dict[str, Any]] = []
    dispatches: list[dict[str, Any]] = []
    processed_queues: dict[str, dict[str, Any]] = {}
    created_total = 0; recovered_total = 0; settled_total = 0; claimed_total = 0
    for spec in policy_value["queues"]:
        queue = _load_previous_queue(previous_root, spec["queueId"], spec["component"], at)
        queue, settled = _settle_lane_result(queue, spec, results_root, at)
        settled_total += int(settled)
        queue, recovered = work_queue.recover_expired(queue, now=at)
        recovered_total += recovered
        bucket = _bucket(at_dt, spec["cadenceSeconds"])
        required_revision = f"cadence-v1-{_sha({'queueId': spec['queueId'], 'bucket': bucket, 'seconds': spec['cadenceSeconds']})[:20]}"
        queue, _item, created = work_queue.enqueue(
            queue,
            kind=spec["kind"],
            subject=spec["subject"],
            reason=spec["reason"],
            priority=spec["priority"],
            required_revision=required_revision,
            now=at,
        )
        created_total += int(created)
        consumer = spec["consumer"]
        claim = None
        prerequisites_ready = True
        for prerequisite in spec.get("prerequisites") or []:
            dependency = processed_queues.get(prerequisite)
            if dependency is None:
                raise ValueError(f"queue {spec['queueId']} prerequisite {prerequisite} must appear earlier in policy")
            dep_items = list(dependency.get("items") or [])
            if not dep_items or sorted(dep_items, key=lambda row: (row.get("createdAtUtc", ""), row.get("workId", "")))[-1].get("state") != "completed":
                prerequisites_ready = False
                break
        if consumer.get("implemented") and prerequisites_ready and _leased_item(queue) is None:
            queue, claim = work_queue.claim(
                queue, owner=consumer["leaseOwner"], lease_seconds=int(consumer["leaseSeconds"]), now=at,
            )
        if claim is not None:
            claimed_total += 1
            dispatches.append({
                "queueId": spec["queueId"],
                "workflow": consumer["workflow"],
                "resultBranch": consumer["resultBranch"],
                "leaseOwner": consumer["leaseOwner"],
                "workId": claim["workId"],
                "claimToken": claim["lease"]["claimToken"],
                "requiredRevision": claim["requiredRevision"],
            })
        processed_queues[spec["queueId"]] = queue
        path = _queue_path(output_root, spec["queueId"])
        path.write_text(json.dumps(queue, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        active = _leased_item(queue)
        descriptors.append({
            "queueId": queue["queueId"],
            "component": queue["component"],
            "path": str(path.relative_to(output_root)).replace("\\", "/"),
            "queueRevision": queue["queueRevision"],
            "counts": queue["counts"],
            "cadenceSeconds": spec["cadenceSeconds"],
            "currentCadenceBucketUtc": bucket,
            "consumerImplemented": bool(consumer.get("implemented")),
            "resultBranch": str(consumer.get("resultBranch") or ""),
            "activeLeaseWorkId": str((active or {}).get("workId") or ""),
        })
    semantic = {"schema": INDEX_SCHEMA, "policyVersion": policy_value["version"], "queues": descriptors}
    index = {
        **semantic,
        "generatedAtUtc": at,
        "workStateRevision": f"work-state-v1-{_sha(semantic)[:20]}",
        "createdWorkItems": created_total,
        "settledWorkItems": settled_total,
        "claimedWorkItems": claimed_total,
        "recoveredExpiredLeases": recovered_total,
        "publicationAuthority": "orchestration-only",
        "securityAuthority": False,
        "clientDatabaseBuildRequested": False,
    }
    dispatch = {
        "schema": DISPATCH_SCHEMA,
        "generatedAtUtc": at,
        "workStateRevision": index["workStateRevision"],
        "dispatches": dispatches,
    }
    (output_root / "index.json").write_text(json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output_root / "dispatch.json").write_text(json.dumps(dispatch, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return index


def validate_work_state(root: Path) -> dict[str, Any]:
    index = json.loads((root / "index.json").read_text(encoding="utf-8"))
    if not isinstance(index, Mapping) or str(index.get("schema") or "") != INDEX_SCHEMA:
        raise ValueError(f"work state schema must be {INDEX_SCHEMA}")
    descriptors = index.get("queues") if isinstance(index.get("queues"), list) else []
    rebuilt: list[dict[str, Any]] = []
    for row in descriptors:
        if not isinstance(row, Mapping):
            raise ValueError("work state queue descriptor must be an object")
        rel = str(row.get("path") or "")
        path = root / rel
        queue = work_queue.validate_queue(json.loads(path.read_text(encoding="utf-8")))
        if queue["queueId"] != str(row.get("queueId") or "") or queue["queueRevision"] != str(row.get("queueRevision") or ""):
            raise ValueError("work state queue descriptor does not match queue file")
        rebuilt.append(dict(row))
    semantic = {"schema": INDEX_SCHEMA, "policyVersion": int(index.get("policyVersion") or 0), "queues": rebuilt}
    expected = f"work-state-v1-{_sha(semantic)[:20]}"
    if expected != str(index.get("workStateRevision") or ""):
        raise ValueError("workStateRevision does not match work state")
    if index.get("securityAuthority") is not False or index.get("clientDatabaseBuildRequested") is not False:
        raise ValueError("work state violates orchestration-only boundary")
    return dict(index)


def main() -> int:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd")
    reconcile_parser = sub.add_parser("reconcile")
    reconcile_parser.add_argument("--policy", type=Path, required=True)
    reconcile_parser.add_argument("--previous-root", type=Path)
    reconcile_parser.add_argument("--results-root", type=Path)
    reconcile_parser.add_argument("--output", type=Path, required=True)
    reconcile_parser.add_argument("--now", default="")
    validate_parser = sub.add_parser("validate")
    validate_parser.add_argument("--root", type=Path, required=True)
    # Backward-compatible pre-subcommand form used by the Phase-1 workflow.
    p.add_argument("--policy", type=Path)
    p.add_argument("--previous-root", type=Path)
    p.add_argument("--results-root", type=Path)
    p.add_argument("--output", type=Path)
    p.add_argument("--now", default="")
    args = p.parse_args()
    if args.cmd == "validate":
        result = validate_work_state(args.root)
        print(json.dumps({"ok": True, "workStateRevision": result["workStateRevision"]}, indent=2))
        return 0
    policy_path = getattr(args, "policy", None)
    output = getattr(args, "output", None)
    if policy_path is None or output is None:
        p.error("--policy and --output are required")
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    previous_root = getattr(args, "previous_root", None)
    previous = previous_root if previous_root and (previous_root / "index.json").is_file() else None
    results_root = getattr(args, "results_root", None)
    result = reconcile(policy=policy, previous_root=previous, results_root=results_root, output_root=output, now=getattr(args, "now", ""))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
