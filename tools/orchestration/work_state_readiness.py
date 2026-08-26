#!/usr/bin/env python3
"""Evaluate whether durable collector work state is ready for a catalog freeze.

This is orchestration-only state.  It does not create security findings or publication
authority.  The catalog freeze still performs the authoritative result/revision/hash
validation with freeze_inputs.py once this readiness gate passes.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Mapping

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import reconcile_work  # noqa: E402
import work_queue  # noqa: E402

READY = 0
WAITING = 10
TERMINAL = 20


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _latest(queue: Mapping[str, Any]) -> dict[str, Any] | None:
    items = [dict(row) for row in queue.get("items") or [] if isinstance(row, Mapping)]
    if not items:
        return None
    items.sort(key=lambda row: (str(row.get("createdAtUtc") or ""), str(row.get("workId") or "")))
    return items[-1]


def evaluate(*, work_state: Path, policy_path: Path) -> tuple[int, dict[str, Any]]:
    state = reconcile_work.validate_work_state(work_state)
    policy = reconcile_work.validate_policy(_read_json(policy_path))
    descriptors = {
        str(row.get("queueId") or ""): row
        for row in state.get("queues") or []
        if isinstance(row, Mapping)
    }
    rows: list[dict[str, Any]] = []
    terminal = False
    waiting = False
    for spec in policy["queues"]:
        if not spec["consumer"].get("implemented"):
            continue
        queue_id = spec["queueId"]
        descriptor = descriptors.get(queue_id)
        if descriptor is None:
            rows.append({"queueId": queue_id, "state": "missing"})
            waiting = True
            continue
        queue_path = work_state / str(descriptor.get("path") or "")
        if not queue_path.is_file():
            rows.append({"queueId": queue_id, "state": "missing"})
            waiting = True
            continue
        queue = work_queue.validate_queue(_read_json(queue_path))
        item = _latest(queue)
        if item is None:
            rows.append({"queueId": queue_id, "state": "empty"})
            waiting = True
            continue
        item_state = str(item.get("state") or "")
        row = {
            "queueId": queue_id,
            "state": item_state,
            "workId": str(item.get("workId") or ""),
            "requiredRevision": str(item.get("requiredRevision") or ""),
        }
        settlement = item.get("settlement") if isinstance(item.get("settlement"), Mapping) else {}
        if settlement:
            row["outcome"] = str(settlement.get("outcome") or "")
            row["reason"] = str(settlement.get("reason") or "")
        rows.append(row)
        if item_state == "completed":
            continue
        if item_state in {"blocked", "terminal"}:
            terminal = True
        else:
            waiting = True

    result = {
        "schema": "omega.work-state-readiness.v1",
        "workStateRevision": state["workStateRevision"],
        "ready": not terminal and not waiting and bool(rows),
        "terminal": terminal,
        "queues": sorted(rows, key=lambda row: row["queueId"]),
    }
    if terminal:
        return TERMINAL, result
    if waiting or not rows:
        return WAITING, result
    return READY, result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--work-state", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    code, result = evaluate(work_state=args.work_state, policy_path=args.policy)
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    print(text, end="")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
