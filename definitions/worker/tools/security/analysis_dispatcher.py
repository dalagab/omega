#!/usr/bin/env python3
"""Queue-claim/settlement runner for Omega's Analysis Broker.

The dispatcher is intentionally small.  The Analysis Broker decides what observation is
needed and which component is eligible; this module only claims the next currently
*dispatchable* queued work item, issues a bounded lease, and later settles that exact
claim.  It never invokes GitHub Actions or scanner code itself.  A thin workflow on the
``main`` branch maps the claimed ``componentId`` to an allow-listed reusable workflow.

A claim token is a concurrency/idempotency guard, not a secret.  Expired claims are
requeued up to a bounded attempt limit so a cancelled runner cannot strand work forever.
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

import analysis_broker
import collector_contracts
import component_registry

CLAIM_SCHEMA = "omega.analysis-dispatch-claim.v1"
SETTLEMENT_SCHEMA = "omega.analysis-dispatch-settlement.v1"
RECOVERY_SCHEMA = "omega.analysis-dispatch-recovery.v1"
BATCH_SCHEMA = "omega.analysis-dispatch-batch.v1"
DEFAULT_LEASE_SECONDS = 3600
MAX_LEASE_SECONDS = 6 * 3600
DEFAULT_MAX_ATTEMPTS = 3
MAX_ATTEMPTS = 10


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _parse_utc(value: str) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _now(value: str = "") -> tuple[str, datetime]:
    parsed = _parse_utc(value)
    if parsed is None:
        parsed = datetime.now(timezone.utc).replace(microsecond=0)
    return _format_utc(parsed), parsed


def _bounded_int(value: Any, *, default: int, minimum: int, maximum: int, name: str) -> int:
    try:
        parsed = int(value if value is not None else default)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if parsed < minimum or parsed > maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return parsed


def _current_dispatch(item: Mapping[str, Any]) -> tuple[dict[str, Any] | None, str]:
    """Re-resolve the queued item's launch contract against *current* registries."""
    component_id = str(item.get("componentId") or "")
    observation = str(item.get("observation") or "")
    if not component_id:
        return None, "work item has no component"
    launch = component_registry.dispatch_contract(component_id)
    if not launch or not bool(launch.get("dispatchable")):
        return None, "component is not currently broker-dispatchable"
    if str(launch.get("launchMode") or "") != "reusable-workflow":
        return None, "component does not expose a reusable-workflow dispatch contract"
    if not str(launch.get("workflow") or ""):
        return None, "component dispatch contract has no workflow"

    providers = set(collector_contracts.providers_for(observation, include_planned=False))
    collector_map = collector_contracts.collector_map()
    retained = []
    for collector_id in item.get("collectors") or []:
        collector_id = str(collector_id or "")
        collector = collector_map.get(collector_id) or {}
        if (collector_id in providers and str(collector.get("status") or "active") == "active" and
                str(collector.get("componentId") or "") == component_id):
            retained.append(collector_id)
    if not retained:
        return None, "queued collectors no longer provide the requested observation from this component"
    resolved = dict(launch)
    resolved["collectors"] = sorted(set(retained))
    return resolved, ""


def _request_from_item(item: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": analysis_broker.ANALYSIS_REQUEST_SCHEMA,
        "requestId": str(item.get("requestId") or ""),
        "observation": str(item.get("observation") or ""),
        "subject": copy.deepcopy(item.get("subject") or {}),
        "subjectKey": str(item.get("subjectKey") or ""),
        "reason": str(item.get("reason") or ""),
        "priority": int(item.get("priority") or 0),
        "requestedBy": copy.deepcopy(item.get("requestedBy") or {}),
        "freshness": copy.deepcopy(item.get("freshness") or {}),
    }


def recover_expired_claims(
    state: Mapping[str, Any], *, now: str = "", max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> tuple[dict[str, Any], dict[str, Any]]:
    payload = analysis_broker._validate_state(state)  # same subsystem; mutation authority remains broker-state only
    at, at_dt = _now(now)
    limit = _bounded_int(max_attempts, default=DEFAULT_MAX_ATTEMPTS, minimum=1, maximum=MAX_ATTEMPTS, name="max_attempts")
    recovered: list[str] = []
    exhausted: list[str] = []
    for item in payload["items"]:
        if str(item.get("state") or "") != "running":
            continue
        claim = item.get("claim") if isinstance(item.get("claim"), Mapping) else None
        if not claim or str(claim.get("schema") or "") != CLAIM_SCHEMA:
            # Preserve legacy/manual running work: only dispatcher-owned leases are recoverable here.
            continue
        expiry = _parse_utc(str(claim.get("expiresAtUtc") or ""))
        if expiry is None or expiry > at_dt:
            continue
        attempts = int(item.get("attempts") or 0)
        old_claim = dict(claim)
        item.pop("claim", None)
        item["updatedAtUtc"] = at
        if attempts < limit:
            item["state"] = "queued"
            item["result"] = {
                "dispatcherRecovery": "lease-expired-requeued",
                "expiredClaim": {
                    "dispatcherId": str(old_claim.get("dispatcherId") or ""),
                    "claimedAtUtc": str(old_claim.get("claimedAtUtc") or ""),
                    "expiresAtUtc": str(old_claim.get("expiresAtUtc") or ""),
                },
            }
            payload["events"].append(analysis_broker._event(
                "dispatcher-lease-expired:requeued", item, at=at,
                detail={"attempts": attempts, "maxAttempts": limit},
            ))
            recovered.append(str(item.get("workItemId") or ""))
        else:
            item["state"] = "failed"
            item["result"] = {
                "dispatcherRecovery": "lease-expired-attempts-exhausted",
                "attempts": attempts,
                "maxAttempts": limit,
            }
            payload["events"].append(analysis_broker._event(
                "dispatcher-lease-expired:failed", item, at=at,
                detail={"attempts": attempts, "maxAttempts": limit},
            ))
            exhausted.append(str(item.get("workItemId") or ""))
    payload["events"] = payload["events"][-analysis_broker.MAX_EVENTS:]
    if recovered or exhausted:
        payload["updatedAtUtc"] = at
        analysis_broker._stamp_state(payload)
    return payload, {
        "schema": RECOVERY_SCHEMA,
        "atUtc": at,
        "requeued": recovered,
        "failed": exhausted,
        "maxAttempts": limit,
    }


def claim_next(
    state: Mapping[str, Any], *, dispatcher_id: str, now: str = "",
    lease_seconds: int = DEFAULT_LEASE_SECONDS, max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    allowed_components: set[str] | None = None,
) -> tuple[dict[str, Any], dict[str, Any] | None, dict[str, Any]]:
    dispatcher = str(dispatcher_id or "").strip()
    if not dispatcher or len(dispatcher) > 256:
        raise ValueError("dispatcher_id must be 1..256 characters")
    lease = _bounded_int(lease_seconds, default=DEFAULT_LEASE_SECONDS, minimum=60, maximum=MAX_LEASE_SECONDS, name="lease_seconds")
    limit = _bounded_int(max_attempts, default=DEFAULT_MAX_ATTEMPTS, minimum=1, maximum=MAX_ATTEMPTS, name="max_attempts")
    payload, recovery = recover_expired_claims(state, now=now, max_attempts=limit)
    at, at_dt = _now(now)

    candidates = [item for item in payload["items"] if str(item.get("state") or "") == "queued"]
    candidates.sort(key=lambda item: (-int(item.get("priority") or 0), str(item.get("createdAtUtc") or ""), str(item.get("workItemId") or "")))
    selected: dict[str, Any] | None = None
    launch: dict[str, Any] | None = None
    active_by_component = active_claims_by_component(payload, now=at)
    for item in candidates:
        component_id = str(item.get("componentId") or "")
        if allowed_components is not None and component_id not in allowed_components:
            continue
        resolved, _reason = _current_dispatch(item)
        if resolved is None:
            continue
        component_limit = int(resolved.get("maxConcurrent") or 1)
        if active_by_component.get(component_id, 0) >= component_limit:
            continue
        selected = item
        launch = resolved
        break
    if selected is None or launch is None:
        return payload, None, recovery

    attempts = int(selected.get("attempts") or 0)
    if attempts >= limit:
        # A queued item at/over the bound should not be dispatched again. Fail it explicitly.
        selected["state"] = "failed"
        selected["updatedAtUtc"] = at
        selected["result"] = {"dispatcherFailure": "attempts-exhausted-before-claim", "attempts": attempts, "maxAttempts": limit}
        payload["events"].append(analysis_broker._event(
            "dispatcher-attempts-exhausted", selected, at=at,
            detail={"attempts": attempts, "maxAttempts": limit},
        ))
        payload["events"] = payload["events"][-analysis_broker.MAX_EVENTS:]
        payload["updatedAtUtc"] = at
        analysis_broker._stamp_state(payload)
        # Continue recursively once, now that the exhausted item is terminal.
        return claim_next(payload, dispatcher_id=dispatcher, now=at, lease_seconds=lease, max_attempts=limit, allowed_components=allowed_components)

    next_attempt = attempts + 1
    expires = _format_utc(at_dt + timedelta(seconds=lease))
    token_basis = {
        "stateRevision": str(payload.get("stateRevision") or ""),
        "workItemId": str(selected.get("workItemId") or ""),
        "dispatcherId": dispatcher,
        "claimedAtUtc": at,
        "attempt": next_attempt,
    }
    claim_token = f"claim-{_sha(token_basis)[:32]}"
    claim = {
        "schema": CLAIM_SCHEMA,
        "workItemId": str(selected.get("workItemId") or ""),
        "requestId": str(selected.get("requestId") or ""),
        "dispatcherId": dispatcher,
        "claimToken": claim_token,
        "claimedAtUtc": at,
        "expiresAtUtc": expires,
        "attempt": next_attempt,
        "maxAttempts": limit,
        "componentId": str(selected.get("componentId") or ""),
        "observation": str(selected.get("observation") or ""),
        "launch": launch,
        "request": _request_from_item(selected),
        "componentRegistryRevision": component_registry.component_revision(),
        "collectorRegistryRevision": collector_contracts.registry_revision(),
    }
    selected["state"] = "running"
    selected["attempts"] = next_attempt
    selected["updatedAtUtc"] = at
    selected["launch"] = dict(launch)
    selected["claim"] = {key: copy.deepcopy(value) for key, value in claim.items() if key != "request"}
    payload["events"].append(analysis_broker._event(
        "dispatcher-claimed", selected, at=at,
        detail={"dispatcherId": dispatcher, "claimToken": claim_token, "expiresAtUtc": expires, "attempt": next_attempt},
    ))
    payload["events"] = payload["events"][-analysis_broker.MAX_EVENTS:]
    payload["updatedAtUtc"] = at
    analysis_broker._stamp_state(payload)
    return payload, claim, recovery



def active_claims_by_component(state: Mapping[str, Any], *, now: str = "") -> dict[str, int]:
    payload = analysis_broker._validate_state(state)
    _, at_dt = _now(now)
    counts: dict[str, int] = {}
    for item in payload["items"]:
        if str(item.get("state") or "") != "running":
            continue
        claim = item.get("claim") if isinstance(item.get("claim"), Mapping) else None
        if not claim or str(claim.get("schema") or "") != CLAIM_SCHEMA:
            continue
        expiry = _parse_utc(str(claim.get("expiresAtUtc") or ""))
        if expiry is None or expiry <= at_dt:
            continue
        component_id = str(item.get("componentId") or "")
        if component_id:
            counts[component_id] = counts.get(component_id, 0) + 1
    return counts


def active_claim_count(state: Mapping[str, Any], *, now: str = "") -> int:
    return sum(active_claims_by_component(state, now=now).values())


def claim_batch(
    state: Mapping[str, Any], *, dispatcher_id: str, now: str = "",
    lease_seconds: int = DEFAULT_LEASE_SECONDS, max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    max_claims: int = 4, max_in_flight: int = 4, allowed_components: set[str] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Atomically reserve several independent work items up to global capacity.

    The persisted running leases are the concurrency signal. A second dispatcher can run
    immediately after this one: it sees these claims as in-flight and can reserve only
    remaining capacity, so different GitHub jobs may execute in parallel without double
    dispatching the same work item.
    """
    claim_limit = _bounded_int(max_claims, default=4, minimum=1, maximum=32, name="max_claims")
    in_flight_limit = _bounded_int(max_in_flight, default=4, minimum=1, maximum=64, name="max_in_flight")
    payload, recovery = recover_expired_claims(state, now=now, max_attempts=max_attempts)
    at, _ = _now(now)
    active_before = active_claim_count(payload, now=at)
    capacity = max(0, in_flight_limit - active_before)
    wanted = min(claim_limit, capacity)
    claims: list[dict[str, Any]] = []
    for slot in range(wanted):
        payload, claim, _ = claim_next(
            payload, dispatcher_id=f"{dispatcher_id}:slot-{slot + 1}", now=at,
            lease_seconds=lease_seconds, max_attempts=max_attempts, allowed_components=allowed_components,
        )
        if claim is None:
            break
        claims.append(claim)
    batch = {
        "schema": BATCH_SCHEMA,
        "atUtc": at,
        "dispatcherId": str(dispatcher_id),
        "maxClaims": claim_limit,
        "maxInFlight": in_flight_limit,
        "activeBefore": active_before,
        "claimedCount": len(claims),
        "activeAfter": active_before + len(claims),
        "claims": claims,
        "stateRevision": str(payload.get("stateRevision") or ""),
        "allowedComponents": sorted(allowed_components) if allowed_components is not None else [],
    }
    return payload, batch, recovery

def settle_claim(
    state: Mapping[str, Any], *, work_item_id: str, claim_token: str, outcome: str,
    now: str = "", result_detail: Mapping[str, Any] | None = None,
    retry_failed: bool = True, max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> tuple[dict[str, Any], dict[str, Any]]:
    payload = analysis_broker._validate_state(state)
    at, _ = _now(now)
    limit = _bounded_int(max_attempts, default=DEFAULT_MAX_ATTEMPTS, minimum=1, maximum=MAX_ATTEMPTS, name="max_attempts")
    normalized_outcome = str(outcome or "").strip().lower()
    if normalized_outcome not in {"completed", "failed", "cancelled"}:
        raise ValueError("outcome must be completed, failed, or cancelled")
    target = next((item for item in payload["items"] if str(item.get("workItemId") or "") == str(work_item_id)), None)
    if target is None:
        raise ValueError(f"unknown work item: {work_item_id}")
    if str(target.get("state") or "") != "running":
        raise ValueError(f"work item is not running: {work_item_id}")
    claim = target.get("claim") if isinstance(target.get("claim"), Mapping) else {}
    if str(claim.get("schema") or "") != CLAIM_SCHEMA:
        raise ValueError("running work item has no dispatcher claim")
    if str(claim.get("claimToken") or "") != str(claim_token or ""):
        raise ValueError("dispatcher claim token mismatch")

    attempts = int(target.get("attempts") or 0)
    detail = dict(result_detail or {})
    detail.setdefault("dispatcherOutcome", normalized_outcome)
    detail.setdefault("attempt", attempts)
    detail.setdefault("claimToken", str(claim_token))
    target.pop("claim", None)
    target["updatedAtUtc"] = at

    final_state = normalized_outcome
    event = f"dispatcher-settled:{normalized_outcome}"
    if normalized_outcome == "failed" and retry_failed and attempts < limit:
        final_state = "queued"
        detail["retryScheduled"] = True
        detail["maxAttempts"] = limit
        event = "dispatcher-settled:failed-requeued"
    target["state"] = final_state
    target["result"] = detail
    payload["events"].append(analysis_broker._event(event, target, at=at, detail=detail))
    payload["events"] = payload["events"][-analysis_broker.MAX_EVENTS:]
    payload["updatedAtUtc"] = at
    analysis_broker._stamp_state(payload)
    settlement = {
        "schema": SETTLEMENT_SCHEMA,
        "atUtc": at,
        "workItemId": str(work_item_id),
        "requestId": str(target.get("requestId") or ""),
        "componentId": str(target.get("componentId") or ""),
        "outcome": normalized_outcome,
        "state": final_state,
        "attempt": attempts,
        "retryScheduled": final_state == "queued",
        "stateRevision": str(payload.get("stateRevision") or ""),
    }
    return payload, settlement


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON object expected: {path}")
    return value


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def _append_github_output(path: Path, values: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        for key, raw in values.items():
            value = str(raw).replace("\r", " ").replace("\n", " ")
            stream.write(f"{key}={value}\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Claim and settle Omega Analysis Broker queue work without executing components")
    sub = parser.add_subparsers(dest="command", required=True)

    p_claim = sub.add_parser("claim")
    p_claim.add_argument("--state", type=Path, required=True)
    p_claim.add_argument("--dispatcher-id", required=True)
    p_claim.add_argument("--lease-seconds", type=int, default=DEFAULT_LEASE_SECONDS)
    p_claim.add_argument("--max-attempts", type=int, default=DEFAULT_MAX_ATTEMPTS)
    p_claim.add_argument("--claim-output", type=Path)
    p_claim.add_argument("--recovery-output", type=Path)
    p_claim.add_argument("--github-output", type=Path)

    p_batch = sub.add_parser("claim-batch")
    p_batch.add_argument("--state", type=Path, required=True)
    p_batch.add_argument("--dispatcher-id", required=True)
    p_batch.add_argument("--lease-seconds", type=int, default=DEFAULT_LEASE_SECONDS)
    p_batch.add_argument("--max-attempts", type=int, default=DEFAULT_MAX_ATTEMPTS)
    p_batch.add_argument("--max-claims", type=int, default=4)
    p_batch.add_argument("--max-in-flight", type=int, default=4)
    p_batch.add_argument("--allowed-components", default="", help="Comma-separated main-side allow-list; empty means all registered dispatchable components")
    p_batch.add_argument("--batch-output", type=Path)
    p_batch.add_argument("--recovery-output", type=Path)
    p_batch.add_argument("--github-output", type=Path)

    p_settle = sub.add_parser("settle")
    p_settle.add_argument("--state", type=Path, required=True)
    p_settle.add_argument("--work-item", required=True)
    p_settle.add_argument("--claim-token", required=True)
    p_settle.add_argument("--outcome", choices=("completed", "failed", "cancelled"), required=True)
    p_settle.add_argument("--result-json", default="{}")
    p_settle.add_argument("--no-retry", action="store_true")
    p_settle.add_argument("--max-attempts", type=int, default=DEFAULT_MAX_ATTEMPTS)
    p_settle.add_argument("--settlement-output", type=Path)

    p_recover = sub.add_parser("recover")
    p_recover.add_argument("--state", type=Path, required=True)
    p_recover.add_argument("--max-attempts", type=int, default=DEFAULT_MAX_ATTEMPTS)
    p_recover.add_argument("--recovery-output", type=Path)

    args = parser.parse_args()
    state = _read_json(args.state)
    if args.command == "claim":
        updated, claim, recovery = claim_next(
            state, dispatcher_id=args.dispatcher_id,
            lease_seconds=args.lease_seconds, max_attempts=args.max_attempts,
        )
        _write_json(args.state, updated)
        if args.claim_output:
            _write_json(args.claim_output, claim or {})
        if args.recovery_output:
            _write_json(args.recovery_output, recovery)
        if args.github_output:
            _append_github_output(args.github_output, {
                "has_work": "true" if claim else "false",
                "work_item_id": (claim or {}).get("workItemId", ""),
                "request_id": (claim or {}).get("requestId", ""),
                "component_id": (claim or {}).get("componentId", ""),
                "observation": (claim or {}).get("observation", ""),
                "claim_token": (claim or {}).get("claimToken", ""),
                "expires_at_utc": (claim or {}).get("expiresAtUtc", ""),
                "request_mode": ((claim or {}).get("launch") or {}).get("requestMode", ""),
                "workflow": ((claim or {}).get("launch") or {}).get("workflow", ""),
            })
        if not args.claim_output:
            print(json.dumps(claim or {}, ensure_ascii=False, sort_keys=True, indent=2))
        return 0

    if args.command == "claim-batch":
        allowed = {item.strip() for item in str(args.allowed_components or "").split(",") if item.strip()} or None
        updated, batch, recovery = claim_batch(
            state, dispatcher_id=args.dispatcher_id, lease_seconds=args.lease_seconds,
            max_attempts=args.max_attempts, max_claims=args.max_claims, max_in_flight=args.max_in_flight,
            allowed_components=allowed,
        )
        _write_json(args.state, updated)
        if args.batch_output:
            _write_json(args.batch_output, batch)
        if args.recovery_output:
            _write_json(args.recovery_output, recovery)
        if args.github_output:
            _append_github_output(args.github_output, {
                "has_work": "true" if batch["claims"] else "false",
                "claimed_count": batch["claimedCount"],
                "active_before": batch["activeBefore"],
                "active_after": batch["activeAfter"],
                "claims_json": json.dumps(batch["claims"], ensure_ascii=False, sort_keys=True, separators=(",", ":")),
            })
        if not args.batch_output:
            print(json.dumps(batch, ensure_ascii=False, sort_keys=True, indent=2))
        return 0

    if args.command == "settle":
        try:
            detail = json.loads(args.result_json)
        except json.JSONDecodeError as exc:
            raise ValueError(f"--result-json is invalid JSON: {exc}") from exc
        if not isinstance(detail, dict):
            raise ValueError("--result-json must be a JSON object")
        updated, settlement = settle_claim(
            state, work_item_id=args.work_item, claim_token=args.claim_token,
            outcome=args.outcome, result_detail=detail,
            retry_failed=not args.no_retry, max_attempts=args.max_attempts,
        )
        _write_json(args.state, updated)
        if args.settlement_output:
            _write_json(args.settlement_output, settlement)
        else:
            print(json.dumps(settlement, ensure_ascii=False, sort_keys=True, indent=2))
        return 0

    if args.command == "recover":
        updated, recovery = recover_expired_claims(state, max_attempts=args.max_attempts)
        _write_json(args.state, updated)
        if args.recovery_output:
            _write_json(args.recovery_output, recovery)
        else:
            print(json.dumps(recovery, ensure_ascii=False, sort_keys=True, indent=2))
        return 0
    raise AssertionError(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
