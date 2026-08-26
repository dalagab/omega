#!/usr/bin/env python3
"""Generic durable work queue contracts for SigmaScope-side orchestration.

This module owns orchestration state only. It is deliberately not Evidence-v2 and it does
not execute collectors. Workers claim bounded items, perform work elsewhere, then settle
claims back into this state.
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping

QUEUE_SCHEMA = "omega.work-queue.v1"
ITEM_SCHEMA = "omega.work-item.v1"
LEASE_SCHEMA = "omega.work-lease.v1"
MAX_ITEMS = 20_000
MAX_REASON = 512
MAX_RESULT_TEXT = 2048
STATES = {"pending", "leased", "completed", "blocked", "terminal"}
CLAIMABLE_STATES = {"pending"}
SHA_RE = re.compile(r"^[0-9a-f]{64}$")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_utc(value: str) -> datetime:
    text = str(value or "").strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _clean_text(value: Any, name: str, *, maximum: int = 256, required: bool = True) -> str:
    text = str(value or "").strip()
    if required and not text:
        raise ValueError(f"{name} is required")
    if len(text) > maximum:
        raise ValueError(f"{name} exceeds {maximum} characters")
    return text


def _clean_subject(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("work subject must be an object")
    if len(value) > 24:
        raise ValueError("work subject has too many fields")
    result: dict[str, Any] = {}
    for raw_key, raw_value in value.items():
        key = _clean_text(raw_key, "subject key", maximum=64)
        if isinstance(raw_value, bool) or raw_value is None:
            result[key] = raw_value
        elif isinstance(raw_value, int):
            result[key] = raw_value
        elif isinstance(raw_value, str):
            result[key] = _clean_text(raw_value, f"subject.{key}", maximum=2048, required=False)
        else:
            raise ValueError(f"subject.{key} must be scalar")
    if not result:
        raise ValueError("work subject must not be empty")
    return result


def _clean_reason(value: Any) -> list[str]:
    raw = value if isinstance(value, list) else [value]
    reasons: list[str] = []
    for item in raw:
        text = _clean_text(item, "reason", maximum=MAX_REASON, required=False)
        if text and text not in reasons:
            reasons.append(text)
    if not reasons:
        raise ValueError("at least one work reason is required")
    if len(reasons) > 16:
        raise ValueError("too many work reasons")
    return reasons


def _priority(value: Any) -> int:
    if isinstance(value, bool):
        raise ValueError("priority must be an integer")
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("priority must be an integer") from exc
    if result < 0 or result > 1000:
        raise ValueError("priority must be between 0 and 1000")
    return result


def work_identity(*, component: str, kind: str, subject: Mapping[str, Any], required_revision: str) -> str:
    semantic = {
        "component": _clean_text(component, "component", maximum=256),
        "kind": _clean_text(kind, "kind", maximum=128),
        "subject": _clean_subject(subject),
        "requiredRevision": _clean_text(required_revision, "requiredRevision", maximum=256),
    }
    return f"work-v1-{_sha(semantic)[:28]}"


def new_queue(queue_id: str, component: str, *, now: str = "") -> dict[str, Any]:
    at = now or utc_now()
    payload = {
        "schema": QUEUE_SCHEMA,
        "queueId": _clean_text(queue_id, "queueId", maximum=128),
        "component": _clean_text(component, "component", maximum=256),
        "createdAtUtc": at,
        "updatedAtUtc": at,
        "items": [],
    }
    return stamp_queue(payload)


def _semantic_queue(queue: Mapping[str, Any]) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    for raw in queue.get("items") or []:
        item = dict(raw)
        items.append(item)
    return {
        "schema": QUEUE_SCHEMA,
        "queueId": queue.get("queueId"),
        "component": queue.get("component"),
        "items": items,
    }


def stamp_queue(queue: dict[str, Any]) -> dict[str, Any]:
    queue["queueRevision"] = f"work-queue-v1-{_sha(_semantic_queue(queue))[:20]}"
    counts = {state: 0 for state in sorted(STATES)}
    for item in queue.get("items") or []:
        state = str(item.get("state") or "")
        if state in counts:
            counts[state] += 1
    queue["counts"] = counts
    return queue


def validate_item(value: Mapping[str, Any], *, queue_component: str = "") -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("work item must be an object")
    if str(value.get("schema") or ITEM_SCHEMA) != ITEM_SCHEMA:
        raise ValueError(f"work item schema must be {ITEM_SCHEMA}")
    component = _clean_text(value.get("component") or queue_component, "component", maximum=256)
    if queue_component and component != queue_component:
        raise ValueError("work item component does not match queue component")
    kind = _clean_text(value.get("kind"), "kind", maximum=128)
    subject = _clean_subject(value.get("subject") if isinstance(value.get("subject"), Mapping) else {})
    required_revision = _clean_text(value.get("requiredRevision"), "requiredRevision", maximum=256)
    expected_id = work_identity(component=component, kind=kind, subject=subject, required_revision=required_revision)
    work_id = _clean_text(value.get("workId") or expected_id, "workId", maximum=128)
    if work_id != expected_id:
        raise ValueError("workId does not match canonical work identity")
    state = _clean_text(value.get("state") or "pending", "state", maximum=32)
    if state not in STATES:
        raise ValueError(f"unsupported work item state: {state}")
    attempts = int(value.get("attempts") or 0)
    if attempts < 0 or attempts > 1000:
        raise ValueError("attempts out of range")
    created = _clean_text(value.get("createdAtUtc") or utc_now(), "createdAtUtc", maximum=64)
    updated = _clean_text(value.get("updatedAtUtc") or created, "updatedAtUtc", maximum=64)
    _parse_utc(created); _parse_utc(updated)
    not_before = _clean_text(value.get("notBeforeUtc") or created, "notBeforeUtc", maximum=64)
    _parse_utc(not_before)
    result = {
        "schema": ITEM_SCHEMA,
        "workId": work_id,
        "component": component,
        "kind": kind,
        "subject": subject,
        "reason": _clean_reason(value.get("reason") or []),
        "priority": _priority(value.get("priority", 500)),
        "requiredRevision": required_revision,
        "state": state,
        "attempts": attempts,
        "notBeforeUtc": not_before,
        "createdAtUtc": created,
        "updatedAtUtc": updated,
    }
    lease = value.get("lease")
    if lease is not None:
        if not isinstance(lease, Mapping):
            raise ValueError("lease must be an object or null")
        if str(lease.get("schema") or LEASE_SCHEMA) != LEASE_SCHEMA:
            raise ValueError("invalid lease schema")
        cleaned_lease = {
            "schema": LEASE_SCHEMA,
            "owner": _clean_text(lease.get("owner"), "lease.owner", maximum=256),
            "claimToken": _clean_text(lease.get("claimToken"), "lease.claimToken", maximum=128),
            "claimedAtUtc": _clean_text(lease.get("claimedAtUtc"), "lease.claimedAtUtc", maximum=64),
            "expiresAtUtc": _clean_text(lease.get("expiresAtUtc"), "lease.expiresAtUtc", maximum=64),
        }
        _parse_utc(cleaned_lease["claimedAtUtc"]); _parse_utc(cleaned_lease["expiresAtUtc"])
        result["lease"] = cleaned_lease
    else:
        result["lease"] = None
    settlement = value.get("settlement")
    if settlement is not None:
        if not isinstance(settlement, Mapping):
            raise ValueError("settlement must be an object or null")
        cleaned_settlement: dict[str, Any] = {}
        for key in ("outcome", "reason", "resultRevision", "resultSha256", "settledAtUtc"):
            text = _clean_text(settlement.get(key), f"settlement.{key}", maximum=MAX_RESULT_TEXT, required=False)
            if text:
                cleaned_settlement[key] = text
        if cleaned_settlement.get("resultSha256") and not SHA_RE.fullmatch(cleaned_settlement["resultSha256"].lower()):
            raise ValueError("settlement.resultSha256 must be SHA-256")
        result["settlement"] = cleaned_settlement or None
    else:
        result["settlement"] = None
    if state == "leased" and result["lease"] is None:
        raise ValueError("leased work item requires lease")
    if state != "leased" and result["lease"] is not None:
        raise ValueError("only leased work items may carry a lease")
    return result


def validate_queue(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("work queue must be an object")
    if str(value.get("schema") or "") != QUEUE_SCHEMA:
        raise ValueError(f"work queue schema must be {QUEUE_SCHEMA}")
    queue_id = _clean_text(value.get("queueId"), "queueId", maximum=128)
    component = _clean_text(value.get("component"), "component", maximum=256)
    items_raw = value.get("items") if isinstance(value.get("items"), list) else []
    if len(items_raw) > MAX_ITEMS:
        raise ValueError(f"work queue exceeds {MAX_ITEMS} items")
    items = [validate_item(item, queue_component=component) for item in items_raw]
    ids = [item["workId"] for item in items]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate workId in queue")
    result = {
        "schema": QUEUE_SCHEMA,
        "queueId": queue_id,
        "component": component,
        "createdAtUtc": _clean_text(value.get("createdAtUtc") or utc_now(), "createdAtUtc", maximum=64),
        "updatedAtUtc": _clean_text(value.get("updatedAtUtc") or utc_now(), "updatedAtUtc", maximum=64),
        "items": items,
    }
    _parse_utc(result["createdAtUtc"]); _parse_utc(result["updatedAtUtc"])
    stamp_queue(result)
    declared = str(value.get("queueRevision") or "")
    if declared and declared != result["queueRevision"]:
        raise ValueError("queueRevision does not match queue contents")
    return result


def enqueue(queue: Mapping[str, Any], *, kind: str, subject: Mapping[str, Any], reason: Any,
            priority: int, required_revision: str, now: str = "") -> tuple[dict[str, Any], dict[str, Any], bool]:
    payload = validate_queue(queue)
    at = now or utc_now()
    work_id = work_identity(component=payload["component"], kind=kind, subject=subject, required_revision=required_revision)
    for item in payload["items"]:
        if item["workId"] == work_id:
            return payload, item, False
    item = validate_item({
        "schema": ITEM_SCHEMA,
        "workId": work_id,
        "component": payload["component"],
        "kind": kind,
        "subject": dict(subject),
        "reason": reason,
        "priority": priority,
        "requiredRevision": required_revision,
        "state": "pending",
        "attempts": 0,
        "notBeforeUtc": at,
        "createdAtUtc": at,
        "updatedAtUtc": at,
        "lease": None,
        "settlement": None,
    }, queue_component=payload["component"])
    payload["items"].append(item)
    if len(payload["items"]) > MAX_ITEMS:
        raise ValueError(f"work queue exceeds {MAX_ITEMS} items")
    payload["updatedAtUtc"] = at
    stamp_queue(payload)
    return payload, item, True


def recover_expired(queue: Mapping[str, Any], *, now: str = "") -> tuple[dict[str, Any], int]:
    payload = validate_queue(queue)
    at = now or utc_now(); at_dt = _parse_utc(at)
    recovered = 0
    for item in payload["items"]:
        if item["state"] != "leased" or not item.get("lease"):
            continue
        if _parse_utc(item["lease"]["expiresAtUtc"]) <= at_dt:
            item["state"] = "pending"
            item["lease"] = None
            item["updatedAtUtc"] = at
            item["notBeforeUtc"] = at
            item["settlement"] = {"outcome": "lease-expired", "settledAtUtc": at}
            recovered += 1
    if recovered:
        payload["updatedAtUtc"] = at
        stamp_queue(payload)
    return payload, recovered


def claim(queue: Mapping[str, Any], *, owner: str, lease_seconds: int = 1800, now: str = "") -> tuple[dict[str, Any], dict[str, Any] | None]:
    payload, _ = recover_expired(queue, now=now)
    at = now or utc_now(); at_dt = _parse_utc(at)
    owner = _clean_text(owner, "owner", maximum=256)
    lease_seconds = int(lease_seconds)
    if lease_seconds < 60 or lease_seconds > 86_400:
        raise ValueError("lease_seconds must be between 60 and 86400")
    candidates = [
        item for item in payload["items"]
        if item["state"] in CLAIMABLE_STATES and _parse_utc(item["notBeforeUtc"]) <= at_dt
    ]
    candidates.sort(key=lambda item: (-int(item["priority"]), item["createdAtUtc"], item["workId"]))
    if not candidates:
        return payload, None
    item = candidates[0]
    attempt = int(item["attempts"]) + 1
    token = f"claim-v1-{_sha({'workId': item['workId'], 'owner': owner, 'attempt': attempt, 'at': at})[:28]}"
    item["state"] = "leased"
    item["attempts"] = attempt
    item["updatedAtUtc"] = at
    item["settlement"] = None
    item["lease"] = {
        "schema": LEASE_SCHEMA,
        "owner": owner,
        "claimToken": token,
        "claimedAtUtc": at,
        "expiresAtUtc": (at_dt + timedelta(seconds=lease_seconds)).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    payload["updatedAtUtc"] = at
    stamp_queue(payload)
    return payload, copy.deepcopy(item)


def settle(queue: Mapping[str, Any], *, work_id: str, claim_token: str, outcome: str,
           reason: str = "", result_revision: str = "", result_sha256: str = "",
           retry_after_seconds: int = 0, now: str = "") -> tuple[dict[str, Any], dict[str, Any]]:
    payload = validate_queue(queue)
    at = now or utc_now(); at_dt = _parse_utc(at)
    outcome = _clean_text(outcome, "outcome", maximum=32)
    if outcome not in {"complete", "retry", "blocked", "terminal"}:
        raise ValueError("outcome must be complete/retry/blocked/terminal")
    target = next((item for item in payload["items"] if item["workId"] == work_id), None)
    if target is None:
        raise ValueError("unknown workId")
    if target["state"] != "leased" or not target.get("lease"):
        raise ValueError("work item is not leased")
    if target["lease"]["claimToken"] != claim_token:
        raise ValueError("claim token mismatch")
    state = {"complete": "completed", "retry": "pending", "blocked": "blocked", "terminal": "terminal"}[outcome]
    target["state"] = state
    target["lease"] = None
    target["updatedAtUtc"] = at
    if outcome == "retry":
        retry_after_seconds = int(retry_after_seconds)
        if retry_after_seconds < 0 or retry_after_seconds > 604_800:
            raise ValueError("retry_after_seconds out of range")
        target["notBeforeUtc"] = (at_dt + timedelta(seconds=retry_after_seconds)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    settlement: dict[str, Any] = {"outcome": outcome, "settledAtUtc": at}
    if reason:
        settlement["reason"] = _clean_text(reason, "settlement.reason", maximum=MAX_RESULT_TEXT)
    if result_revision:
        settlement["resultRevision"] = _clean_text(result_revision, "settlement.resultRevision", maximum=256)
    if result_sha256:
        normalized = str(result_sha256).lower()
        if not SHA_RE.fullmatch(normalized):
            raise ValueError("result_sha256 must be lowercase SHA-256")
        settlement["resultSha256"] = normalized
    target["settlement"] = settlement
    payload["updatedAtUtc"] = at
    stamp_queue(payload)
    return payload, copy.deepcopy(target)


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("validate"); p.add_argument("--input", type=Path, required=True)
    p = sub.add_parser("init"); p.add_argument("--queue-id", required=True); p.add_argument("--component", required=True); p.add_argument("--output", type=Path, required=True)
    p = sub.add_parser("claim"); p.add_argument("--input", type=Path, required=True); p.add_argument("--output", type=Path, required=True); p.add_argument("--owner", required=True); p.add_argument("--lease-seconds", type=int, default=1800)
    p = sub.add_parser("settle"); p.add_argument("--input", type=Path, required=True); p.add_argument("--output", type=Path, required=True); p.add_argument("--work-id", required=True); p.add_argument("--claim-token", required=True); p.add_argument("--outcome", choices=["complete", "retry", "blocked", "terminal"], required=True); p.add_argument("--reason", default=""); p.add_argument("--result-revision", default=""); p.add_argument("--result-sha256", default=""); p.add_argument("--retry-after-seconds", type=int, default=0)
    args = parser.parse_args()
    if args.cmd == "validate":
        value = validate_queue(_load(args.input)); print(json.dumps({"ok": True, "queueId": value["queueId"], "queueRevision": value["queueRevision"], "counts": value["counts"]}, indent=2)); return 0
    if args.cmd == "init":
        value = new_queue(args.queue_id, args.component); _write(args.output, value); print(json.dumps({"output": str(args.output), "queueRevision": value["queueRevision"]}, indent=2)); return 0
    if args.cmd == "claim":
        value, item = claim(_load(args.input), owner=args.owner, lease_seconds=args.lease_seconds); _write(args.output, value); print(json.dumps({"claimed": bool(item), "item": item}, indent=2)); return 0
    if args.cmd == "settle":
        value, item = settle(_load(args.input), work_id=args.work_id, claim_token=args.claim_token, outcome=args.outcome, reason=args.reason, result_revision=args.result_revision, result_sha256=args.result_sha256, retry_after_seconds=args.retry_after_seconds); _write(args.output, value); print(json.dumps({"settled": True, "item": item}, indent=2)); return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
