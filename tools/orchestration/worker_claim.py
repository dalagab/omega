#!/usr/bin/env python3
"""Validate an exact queue lease before a worker performs collection."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import work_queue


def _parse(value: str) -> datetime:
    text = value.replace("Z", "+00:00")
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def validate_claim(*, work_state: Path, queue_id: str, work_id: str, owner: str, claim_token: str) -> dict:
    queue_path = work_state / "queues" / f"{queue_id}.json"
    queue = work_queue.validate_queue(json.loads(queue_path.read_text(encoding="utf-8")))
    item = next((row for row in queue["items"] if row["workId"] == work_id), None)
    if item is None:
        raise ValueError("dispatched workId is not present in queue")
    if item["state"] != "leased" or not item.get("lease"):
        raise ValueError("dispatched work item is not leased")
    lease = item["lease"]
    if lease["owner"] != owner:
        raise ValueError("dispatched lease owner mismatch")
    if lease["claimToken"] != claim_token:
        raise ValueError("dispatched claim token mismatch")
    if _parse(lease["expiresAtUtc"]) <= datetime.now(timezone.utc):
        raise ValueError("dispatched work lease has expired")
    return item


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--work-state", type=Path, required=True)
    p.add_argument("--queue-id", required=True)
    p.add_argument("--work-id", required=True)
    p.add_argument("--owner", required=True)
    p.add_argument("--claim-token", required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    item = validate_claim(work_state=args.work_state, queue_id=args.queue_id, work_id=args.work_id, owner=args.owner, claim_token=args.claim_token)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(item, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"ok": True, "workId": item["workId"], "expiresAtUtc": item["lease"]["expiresAtUtc"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
