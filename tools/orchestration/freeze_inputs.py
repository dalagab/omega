#!/usr/bin/env python3
"""Fail-closed validation of settled orchestration lane inputs at catalog freeze time."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
from typing import Any

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import reconcile_work
import work_queue
import work_result


def _latest(queue: dict[str, Any]) -> dict[str, Any]:
    items = list(queue.get("items") or [])
    if not items:
        raise ValueError(f"queue {queue.get('queueId')} has no work history")
    items.sort(key=lambda row: (str(row.get("createdAtUtc") or ""), str(row.get("workId") or "")))
    return items[-1]


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def validate_freeze_inputs(*, work_state: Path, policy_path: Path, lanes_root: Path, catalog_root: Path) -> dict[str, Any]:
    state = reconcile_work.validate_work_state(work_state)
    policy = reconcile_work.validate_policy(_read_json(policy_path))
    catalog_index = _read_json(catalog_root / "index.json")
    catalog_revision = str(catalog_index.get("catalogRevision") or "")
    if not catalog_revision:
        raise ValueError("current catalog has no catalogRevision")
    lane_rows: list[dict[str, Any]] = []
    by_queue = {str(row.get("queueId") or ""): row for row in state.get("queues") or [] if isinstance(row, dict)}
    for spec in policy["queues"]:
        consumer = spec["consumer"]
        if not consumer.get("implemented"):
            continue
        descriptor = by_queue.get(spec["queueId"])
        if descriptor is None:
            raise ValueError(f"work state lacks required queue {spec['queueId']}")
        queue = work_queue.validate_queue(_read_json(work_state / str(descriptor["path"])))
        item = _latest(queue)
        if item["state"] != "completed":
            raise ValueError(f"required queue {spec['queueId']} latest work is {item['state']}, not completed")
        settlement = item.get("settlement") or {}
        lane_root = lanes_root / spec["queueId"]
        result = work_result.validate_result(lane_root, expected_queue_id=spec["queueId"], expected_work_id=item["workId"])
        if result["resultRevision"] != str(settlement.get("resultRevision") or ""):
            raise ValueError(f"required queue {spec['queueId']} result revision is not the settled result")
        import hashlib
        h = hashlib.sha256((lane_root / "result.json").read_bytes()).hexdigest()
        if h != str(settlement.get("resultSha256") or ""):
            raise ValueError(f"required queue {spec['queueId']} result SHA-256 is not the settled result")
        lane_rows.append({
            "queueId": spec["queueId"], "workId": item["workId"],
            "resultRevision": result["resultRevision"], "payloadRevision": result.get("payloadRevision") or "",
        })
    # Catalog-bound working-state lanes must have been derived from the catalog we are
    # freezing forward from. Discovery itself may discover beyond that catalog; enrichment
    # and source-head state must explicitly identify this base identity.
    for queue_id in ("catalog-enrichment", "catalog-scrape", "source-head-observation"):
        provenance = _read_json(lanes_root / queue_id / "provenance.json")
        if str(provenance.get("baseCatalogRevision") or "") != catalog_revision:
            raise ValueError(f"{queue_id} was not collected against current catalog revision {catalog_revision}")
    discovery_result = work_result.validate_result(lanes_root / "catalog-discovery", expected_queue_id="catalog-discovery")
    enrichment_provenance = _read_json(lanes_root / "catalog-enrichment" / "provenance.json")
    if str(enrichment_provenance.get("discoveryResultRevision") or "") != discovery_result["resultRevision"]:
        raise ValueError("catalog enrichment did not consume the settled discovery result")
    enrichment_result = work_result.validate_result(lanes_root / "catalog-enrichment", expected_queue_id="catalog-enrichment")
    scrape_provenance = _read_json(lanes_root / "catalog-scrape" / "provenance.json")
    if str(scrape_provenance.get("enrichmentResultRevision") or "") != enrichment_result["resultRevision"]:
        raise ValueError("website scraper did not consume the settled enrichment result")
    result = {
        "schema": "omega.catalog-freeze-inputs.v1",
        "workStateRevision": state["workStateRevision"],
        "baseCatalogRevision": catalog_revision,
        "lanes": sorted(lane_rows, key=lambda row: row["queueId"]),
    }
    return result


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--work-state", type=Path, required=True)
    p.add_argument("--policy", type=Path, required=True)
    p.add_argument("--lanes-root", type=Path, required=True)
    p.add_argument("--catalog-root", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    result = validate_freeze_inputs(work_state=args.work_state, policy_path=args.policy, lanes_root=args.lanes_root, catalog_root=args.catalog_root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
