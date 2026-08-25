#!/usr/bin/env python3
"""Generic non-executing Analysis Broker contracts for Omega.

Stigma-1 may request a logical observation type.  This module turns that request into a
subject-bound ``omega.analysis-request.v1``, resolves registered collector/component providers,
and maintains durable orchestration state.  It deliberately never invokes GitHub Actions,
performs network I/O, or executes scanner code: thin launchers on ``main`` own dispatch.
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone, timedelta
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from . import collector_contracts, component_registry

ANALYSIS_REQUEST_SCHEMA = "omega.analysis-request.v1"
RESOLUTION_SCHEMA = "omega.analysis-request-resolution.v1"
WORK_ITEM_SCHEMA = "omega.analysis-work-item.v1"
STATE_SCHEMA = "omega.analysis-broker-state.v1"
EVENT_SCHEMA = "omega.analysis-broker-event.v1"
INVENTORY_SCHEMA = "omega.observation-inventory.v1"

MAX_REASON = 1000
MAX_EVENTS = 10_000
MAX_ITEMS = 20_000
MAX_INVENTORY_RECORDS = 500_000
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
STATES = {"requested", "queued", "running", "completed", "failed", "expired", "superseded", "cancelled"}
TERMINAL_STATES = {"completed", "failed", "expired", "superseded", "cancelled"}
TRANSITIONS = {
    "requested": {"queued", "cancelled", "expired", "superseded"},
    "queued": {"running", "cancelled", "expired", "superseded"},
    "running": {"completed", "failed", "cancelled"},
    "failed": {"queued", "superseded"},
    "completed": set(), "expired": set(), "superseded": set(), "cancelled": set(),
}

# Discovery observations normally aggregate multiple collectors belonging to one component.
# Security/runtime/provenance observations normally need one provider implementation.
_PROVIDER_STRATEGY = {
    "catalogSourceCandidates": "aggregate",
    "catalogPluginFacts": "aggregate",
    "catalogProjectLinks": "aggregate",
    "catalogRepositoryCandidates": "aggregate",
    "catalogManifestCandidates": "aggregate",
    "catalogIssueHints": "aggregate",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _require_int(value: Any, name: str, *, minimum: int = 0, maximum: int | None = None) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if result < minimum or (maximum is not None and result > maximum):
        raise ValueError(f"{name} is out of range")
    return result


def _clean_subject(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("analysis request subject must be a mapping")
    allowed = {"type", "pluginId", "variantId", "artifactSha256", "sourceRepository", "sourceCommit", "endpoint", "profile", "assemblyVersion", "channel"}
    extras = sorted(set(value) - allowed)
    if extras:
        raise ValueError(f"analysis request subject contains unsupported fields: {extras}")
    subject_type = str(value.get("type") or "")
    if subject_type not in {"catalog", "plugin", "variant", "artifact", "source", "endpoint"}:
        raise ValueError("analysis request subject.type must be catalog/plugin/variant/artifact/source/endpoint")
    result: dict[str, Any] = {"type": subject_type}
    for name in ("pluginId", "variantId"):
        if name in value and value.get(name) is not None:
            result[name] = _require_int(value.get(name), f"subject.{name}", minimum=1)
    artifact_sha = str(value.get("artifactSha256") or "").lower()
    if artifact_sha:
        if not SHA256_RE.fullmatch(artifact_sha):
            raise ValueError("subject.artifactSha256 must be a lowercase SHA-256")
        result["artifactSha256"] = artifact_sha
    for name in ("sourceRepository", "sourceCommit", "endpoint", "profile", "assemblyVersion", "channel"):
        text = str(value.get(name) or "").strip()
        if text:
            if len(text) > 2048:
                raise ValueError(f"subject.{name} is too long")
            result[name] = text
    required = {
        "plugin": "pluginId", "variant": "variantId", "artifact": "artifactSha256",
        "source": "sourceRepository", "endpoint": "endpoint",
    }.get(subject_type)
    if required and required not in result:
        raise ValueError(f"subject.type={subject_type} requires subject.{required}")
    return result


def subject_key(subject: Mapping[str, Any]) -> str:
    return f"subject-v1-{_sha(_clean_subject(subject))[:24]}"


def freshness_policy(observation: str) -> dict[str, Any]:
    return collector_contracts.freshness_policy(str(observation or ""))


def provider_strategy(observation: str) -> str:
    return _PROVIDER_STRATEGY.get(str(observation or ""), "single")


def compile_request(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("analysis request must be a mapping")
    allowed = {"schema", "requestId", "observation", "subject", "subjectKey", "reason", "priority", "requestedBy", "requestedAtUtc", "freshness"}
    extras = sorted(set(value) - allowed)
    if extras:
        raise ValueError(f"analysis request contains unsupported fields: {extras}")
    if "collectorId" in value or "componentId" in value:
        raise ValueError("analysis requests may not bind collector/component implementations")
    schema = str(value.get("schema") or ANALYSIS_REQUEST_SCHEMA)
    if schema != ANALYSIS_REQUEST_SCHEMA:
        raise ValueError(f"analysis request schema must be {ANALYSIS_REQUEST_SCHEMA}")
    observation = str(value.get("observation") or "")
    if not collector_contracts.providers_for(observation, include_planned=True):
        raise ValueError(f"analysis request observation has no registered provider: {observation!r}")
    subject = _clean_subject(value.get("subject") if isinstance(value.get("subject"), Mapping) else {})
    reason = str(value.get("reason") or "").strip()
    if not reason or len(reason) > MAX_REASON:
        raise ValueError(f"analysis request reason must be 1..{MAX_REASON} characters")
    priority = _require_int(value.get("priority", 500), "analysis request priority", minimum=0, maximum=1000)
    requested_by_raw = value.get("requestedBy") if isinstance(value.get("requestedBy"), Mapping) else {}
    requested_by = {
        key: str(requested_by_raw.get(key) or "")[:256]
        for key in ("componentId", "ruleId", "ruleRevision", "evaluationId")
        if str(requested_by_raw.get(key) or "")
    }
    if requested_by.get("componentId") and requested_by["componentId"] not in component_registry.component_map():
        raise ValueError(f"analysis request requestedBy.componentId is unknown: {requested_by['componentId']!r}")
    requested_at = str(value.get("requestedAtUtc") or utc_now())
    freshness_raw = value.get("freshness") if isinstance(value.get("freshness"), Mapping) else {}
    base_policy = freshness_policy(observation)
    allow_reuse = bool(freshness_raw.get("allowReuse", True))
    freshness: dict[str, Any] = {"allowReuse": allow_reuse, **base_policy}
    if "maxAgeSeconds" in freshness_raw:
        freshness["maxAgeSeconds"] = _require_int(freshness_raw.get("maxAgeSeconds"), "freshness.maxAgeSeconds", minimum=0, maximum=31_536_000)
    semantic = {
        "schema": ANALYSIS_REQUEST_SCHEMA, "observation": observation, "subject": subject,
        "reason": reason, "priority": priority, "requestedBy": requested_by,
        "requestedAtUtc": requested_at, "freshness": freshness,
    }
    request_id = str(value.get("requestId") or "").strip()
    if request_id:
        if len(request_id) > 256 or not re.fullmatch(r"[A-Za-z0-9._:-]+", request_id):
            raise ValueError("analysis request requestId is invalid")
    else:
        request_id = f"analysis-{_sha(semantic)[:28]}"
    computed_subject_key = subject_key(subject)
    declared_subject_key = str(value.get("subjectKey") or "").strip()
    if declared_subject_key and declared_subject_key != computed_subject_key:
        raise ValueError("analysis request subjectKey does not match the canonical subject")
    return {**semantic, "requestId": request_id, "subjectKey": computed_subject_key}


def from_observation_request(observation_request: Mapping[str, Any], subject: Mapping[str, Any], *, requested_at: str = "", evaluation_id: str = "") -> dict[str, Any]:
    # Stigma may hand the broker either the raw rule request or its enriched provider
    # resolution.  Recompile only the logical fields so stale/implementation-specific
    # provider metadata can never cross the broker boundary as an instruction.
    logical = {
        "collection": str(observation_request.get("collection") or ""),
        "reason": str(observation_request.get("reason") or ""),
        "priority": observation_request.get("priority", 500),
    }
    compiled = collector_contracts.compile_observation_request(logical)
    if compiled is None:
        raise ValueError("observation request is empty")
    requested_by = {
        "componentId": "omega.stigma-1",
        "ruleId": str(observation_request.get("ruleId") or ""),
        "ruleRevision": str(observation_request.get("ruleRevision") or ""),
        "evaluationId": evaluation_id,
    }
    return compile_request({
        "observation": compiled["collection"], "subject": dict(subject), "reason": compiled["reason"],
        "priority": compiled["priority"], "requestedBy": requested_by,
        "requestedAtUtc": requested_at or utc_now(),
    })


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


def validate_inventory(value: Mapping[str, Any] | None) -> dict[str, Any]:
    if value is None:
        return {"schema": INVENTORY_SCHEMA, "records": []}
    if not isinstance(value, Mapping) or str(value.get("schema") or "") != INVENTORY_SCHEMA:
        raise ValueError(f"observation inventory schema must be {INVENTORY_SCHEMA}")
    rows = value.get("records")
    if not isinstance(rows, list) or len(rows) > MAX_INVENTORY_RECORDS:
        raise ValueError("observation inventory records must be a bounded array")
    clean: list[dict[str, Any]] = []
    for raw in rows:
        if not isinstance(raw, Mapping):
            continue
        observation = str(raw.get("observation") or "")
        subject_key_value = str(raw.get("subjectKey") or "")
        if not observation or not subject_key_value:
            continue
        row = {
            "observation": observation, "subjectKey": subject_key_value,
            "observedAtUtc": str(raw.get("observedAtUtc") or ""),
            "expiresAtUtc": str(raw.get("expiresAtUtc") or ""),
            "collectorId": str(raw.get("collectorId") or ""),
            "componentId": str(raw.get("componentId") or ""),
            "reference": str(raw.get("reference") or "")[:2048],
            "recordDigest": str(raw.get("recordDigest") or "")[:256],
        }
        clean.append(row)
    return {"schema": INVENTORY_SCHEMA, "records": clean}


def reusable_observations(request: Mapping[str, Any], inventory: Mapping[str, Any] | None, *, now: str = "") -> list[dict[str, Any]]:
    compiled = dict(request) if str(request.get("schema") or "") == ANALYSIS_REQUEST_SCHEMA and str(request.get("subjectKey") or "") else compile_request(request)
    if not bool((compiled.get("freshness") or {}).get("allowReuse", True)):
        return []
    inv = validate_inventory(inventory)
    policy = compiled.get("freshness") if isinstance(compiled.get("freshness"), Mapping) else {}
    model = str(policy.get("model") or "request-scoped")
    now_dt = _parse_utc(now or utc_now()) or datetime.now(timezone.utc)
    result: list[dict[str, Any]] = []
    for row in inv["records"]:
        if row["observation"] != compiled["observation"] or row["subjectKey"] != compiled["subjectKey"]:
            continue
        valid = False
        if model.startswith("immutable-"):
            valid = True
        elif model == "ttl":
            observed = _parse_utc(row.get("observedAtUtc") or "")
            explicit_expiry = _parse_utc(row.get("expiresAtUtc") or "")
            ttl_seconds = int(policy.get("ttlSeconds") or policy.get("maxAgeSeconds") or 0)
            expiry = explicit_expiry or (observed + timedelta(seconds=ttl_seconds) if observed and ttl_seconds > 0 else None)
            valid = bool(expiry and expiry > now_dt)
        elif model == "request-scoped":
            valid = False
        if valid:
            result.append(dict(row))
    result.sort(key=lambda row: (str(row.get("observedAtUtc") or ""), str(row.get("recordDigest") or "")), reverse=True)
    return result


def resolve_request(value: Mapping[str, Any], *, inventory: Mapping[str, Any] | None = None, now: str = "") -> dict[str, Any]:
    request = compile_request(value)
    reusable = reusable_observations(request, inventory, now=now)
    collectors = collector_contracts.collector_map()
    components = component_registry.component_map()
    provider_ids = collector_contracts.providers_for(request["observation"], include_planned=True)
    candidates: list[dict[str, Any]] = []
    for collector_id in provider_ids:
        collector = collectors.get(collector_id) or {}
        component_id = str(collector.get("componentId") or "")
        component = components.get(component_id) or {}
        collector_status = str(collector.get("status") or "active")
        component_status = str(component.get("status") or "unknown")
        dispatch = component_registry.dispatch_contract(component_id) or {}
        active_provider = collector_status == "active" and component_status in {"active", "external", "embedded-transition"}
        dispatchable = active_provider and bool(dispatch.get("dispatchable"))
        candidates.append({
            "collectorId": collector_id,
            "collectorStatus": collector_status,
            "componentId": component_id,
            "componentStatus": component_status,
            "activeProvider": active_provider,
            "dispatchable": dispatchable,
            "launch": dispatch,
        })
    candidates.sort(key=lambda row: (not bool(row["activeProvider"]), not bool(row["dispatchable"]), str(row["componentId"]), str(row["collectorId"])))
    active = [row for row in candidates if row["activeProvider"]]
    dispatchable = [row for row in candidates if row["dispatchable"]]
    strategy = provider_strategy(request["observation"])
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in dispatchable:
        grouped.setdefault(str(row["componentId"]), []).append(row)
    plans: list[dict[str, Any]] = []
    for component_id in sorted(grouped):
        rows = grouped[component_id]
        plans.append({
            "componentId": component_id,
            "collectors": sorted(str(row["collectorId"]) for row in rows),
            "launch": rows[0]["launch"],
        })
        if strategy == "single":
            break
    if reusable:
        plans = []
    return {
        "schema": RESOLUTION_SCHEMA,
        "request": request,
        "providerStrategy": strategy,
        "providerCandidates": candidates,
        "activeProviderCount": len(active),
        "dispatchableProviderCount": len(dispatchable),
        "reuseSatisfied": bool(reusable),
        "reuseCandidates": reusable,
        "satisfied": bool(reusable) or bool(active),
        "satisfiable": bool(active),
        "needsDispatch": not bool(reusable),
        "dispatchable": bool(plans),
        "dispatchPlan": plans,
        "executionAuthority": "main-control-plane-only",
        "brokerExecutesComponents": False,
        "componentRegistryRevision": component_registry.component_revision(),
        "collectorRegistryRevision": collector_contracts.registry_revision(),
    }


def state_revision(state: Mapping[str, Any]) -> str:
    semantic = {
        "schema": STATE_SCHEMA,
        "items": state.get("items") if isinstance(state.get("items"), list) else [],
        "events": state.get("events") if isinstance(state.get("events"), list) else [],
    }
    return f"analysis-broker-state-v1-{_sha(semantic)[:20]}"


def _stamp_state(state: dict[str, Any]) -> dict[str, Any]:
    state["stateRevision"] = state_revision(state)
    return state


def empty_state(*, now: str = "") -> dict[str, Any]:
    return _stamp_state({"schema": STATE_SCHEMA, "updatedAtUtc": now or utc_now(), "items": [], "events": []})


def _validate_state(state: Mapping[str, Any]) -> dict[str, Any]:
    if str(state.get("schema") or "") != STATE_SCHEMA:
        raise ValueError(f"broker state schema must be {STATE_SCHEMA}")
    result = copy.deepcopy(dict(state))
    if not isinstance(result.get("items"), list) or not isinstance(result.get("events"), list):
        raise ValueError("broker state items/events must be arrays")
    if len(result["items"]) > MAX_ITEMS or len(result["events"]) > MAX_EVENTS:
        raise ValueError("broker state exceeds bounded item/event limits")
    declared = str(result.get("stateRevision") or "")
    if declared and declared != state_revision(result):
        raise ValueError("broker state revision does not match content")
    return result


def _event(event: str, item: Mapping[str, Any], *, at: str, detail: Mapping[str, Any] | None = None) -> dict[str, Any]:
    return {
        "schema": EVENT_SCHEMA, "atUtc": at, "event": event,
        "workItemId": str(item.get("workItemId") or ""), "requestId": str(item.get("requestId") or ""),
        "componentId": str(item.get("componentId") or ""), "detail": dict(detail or {}),
    }


def enqueue(state: Mapping[str, Any], request_value: Mapping[str, Any], *, now: str = "", inventory: Mapping[str, Any] | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    result = _validate_state(state)
    at = now or utc_now()
    resolution = resolve_request(request_value, inventory=inventory, now=at)
    request = resolution["request"]
    existing = [item for item in result["items"] if str(item.get("requestId") or "") == request["requestId"] and str(item.get("state") or "") not in TERMINAL_STATES]
    if existing:
        return result, {**resolution, "enqueued": False, "deduplicated": True, "workItemIds": [str(item.get("workItemId") or "") for item in existing]}
    terminal_existing = [item for item in result["items"] if str(item.get("requestId") or "") == request["requestId"] and str(item.get("state") or "") in TERMINAL_STATES]
    if terminal_existing:
        # requestId is the logical idempotency key. A production bridge may see the same
        # Stigma dependency on every reprojection; do not append a duplicate terminal work
        # item merely because the current inventory has not caught up yet. Failed/cancelled
        # requests are explicitly requeued through the broker lifecycle, not recreated.
        return result, {
            **resolution, "enqueued": False, "deduplicated": True,
            "reused": bool(resolution.get("reuseSatisfied")),
            "terminal": True,
            "workItemIds": [str(item.get("workItemId") or "") for item in terminal_existing],
        }
    if resolution.get("reuseSatisfied"):
        reuse = dict((resolution.get("reuseCandidates") or [{}])[0])
        component_id = str(reuse.get("componentId") or "")
        work_id = f"work-{_sha({'requestId': request['requestId'], 'reuse': reuse.get('recordDigest','')})[:28]}"
        item = {
            "schema": WORK_ITEM_SCHEMA, "workItemId": work_id, "requestId": request["requestId"],
            "observation": request["observation"], "subject": request["subject"], "subjectKey": request["subjectKey"],
            "componentId": component_id, "collectors": [str(reuse.get("collectorId") or "")] if reuse.get("collectorId") else [],
            "launch": {}, "priority": int(request["priority"]), "reason": request["reason"],
            "requestedBy": dict(request.get("requestedBy") or {}), "freshness": dict(request.get("freshness") or {}),
            "state": "completed", "attempts": 0, "createdAtUtc": at, "updatedAtUtc": at,
            "result": {"reusedObservation": reuse},
        }
        result["items"].append(item)
        result["events"].append(_event("reused-observation", item, at=at, detail={"reference": reuse.get("reference", "")}))
        result["events"] = result["events"][-MAX_EVENTS:]
        result["updatedAtUtc"] = at
        _stamp_state(result)
        return result, {**resolution, "enqueued": False, "deduplicated": False, "reused": True, "workItemIds": [work_id]}
    plans = list(resolution.get("dispatchPlan") or [])
    if not plans:
        plans = [{"componentId": "", "collectors": [], "launch": {}}]
    new_ids: list[str] = []
    for index, plan in enumerate(plans):
        component_id = str(plan.get("componentId") or "")
        initial_state = "queued" if component_id else "requested"
        work_id = f"work-{_sha({'requestId': request['requestId'], 'componentId': component_id, 'index': index})[:28]}"
        item = {
            "schema": WORK_ITEM_SCHEMA,
            "workItemId": work_id,
            "requestId": request["requestId"],
            "observation": request["observation"],
            "subject": request["subject"],
            "subjectKey": request["subjectKey"],
            "componentId": component_id,
            "collectors": list(plan.get("collectors") or []),
            "launch": dict(plan.get("launch") or {}),
            "priority": int(request["priority"]),
            "reason": request["reason"],
            "requestedBy": dict(request.get("requestedBy") or {}),
            "freshness": dict(request.get("freshness") or {}),
            "state": initial_state,
            "attempts": 0,
            "createdAtUtc": at,
            "updatedAtUtc": at,
            "result": {},
        }
        result["items"].append(item)
        result["events"].append(_event("enqueued" if initial_state == "queued" else "awaiting-provider", item, at=at, detail={"dispatchable": bool(component_id)}))
        new_ids.append(work_id)
    result["events"] = result["events"][-MAX_EVENTS:]
    result["updatedAtUtc"] = at
    _stamp_state(result)
    return result, {**resolution, "enqueued": True, "deduplicated": False, "workItemIds": new_ids}


def select_next(state: Mapping[str, Any]) -> dict[str, Any] | None:
    result = _validate_state(state)
    queued = [dict(item) for item in result["items"] if str(item.get("state") or "") == "queued"]
    queued.sort(key=lambda item: (-int(item.get("priority") or 0), str(item.get("createdAtUtc") or ""), str(item.get("workItemId") or "")))
    return queued[0] if queued else None


def transition(state: Mapping[str, Any], work_item_id: str, new_state: str, *, now: str = "", result_detail: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if new_state not in STATES:
        raise ValueError(f"unsupported broker state: {new_state}")
    payload = _validate_state(state)
    at = now or utc_now()
    target: dict[str, Any] | None = None
    for item in payload["items"]:
        if str(item.get("workItemId") or "") == str(work_item_id):
            target = item
            break
    if target is None:
        raise ValueError(f"unknown work item: {work_item_id}")
    old_state = str(target.get("state") or "")
    if new_state not in TRANSITIONS.get(old_state, set()):
        raise ValueError(f"invalid broker transition {old_state} -> {new_state}")
    target["state"] = new_state
    target["updatedAtUtc"] = at
    if new_state == "running":
        target["attempts"] = int(target.get("attempts") or 0) + 1
    if result_detail:
        target["result"] = dict(result_detail)
    payload["events"].append(_event(f"state:{old_state}->{new_state}", target, at=at, detail=result_detail))
    payload["events"] = payload["events"][-MAX_EVENTS:]
    payload["updatedAtUtc"] = at
    _stamp_state(payload)
    return payload


def summary(state: Mapping[str, Any]) -> dict[str, Any]:
    payload = _validate_state(state)
    counts = {state_name: 0 for state_name in sorted(STATES)}
    by_component: dict[str, int] = {}
    for item in payload["items"]:
        state_name = str(item.get("state") or "")
        if state_name in counts:
            counts[state_name] += 1
        component_id = str(item.get("componentId") or "unresolved") or "unresolved"
        if state_name not in TERMINAL_STATES:
            by_component[component_id] = by_component.get(component_id, 0) + 1
    return {
        "schema": "omega.analysis-broker-summary.v1",
        "updatedAtUtc": str(payload.get("updatedAtUtc") or ""),
        "stateRevision": str(payload.get("stateRevision") or state_revision(payload)),
        "items": len(payload["items"]), "events": len(payload["events"]),
        "states": counts, "activeByComponent": {key: by_component[key] for key in sorted(by_component)},
        "next": select_next(payload),
    }


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _request_input(path: Path | None, inline: str) -> dict[str, Any]:
    if path is not None:
        value = _read_json(path)
    else:
        try:
            value = json.loads(inline)
        except json.JSONDecodeError as exc:
            raise ValueError(f"inline analysis request is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("analysis request JSON must be an object")
    return value


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Resolve and persist generic Omega analysis requests without executing components")
    sub = parser.add_subparsers(dest="command", required=True)
    p_resolve = sub.add_parser("resolve")
    resolve_group = p_resolve.add_mutually_exclusive_group(required=True)
    resolve_group.add_argument("--request", type=Path)
    resolve_group.add_argument("--request-json", default="")
    p_resolve.add_argument("--output", type=Path)
    p_resolve.add_argument("--inventory", type=Path)
    p_init = sub.add_parser("init")
    p_init.add_argument("--state", type=Path, required=True)
    p_enqueue = sub.add_parser("enqueue")
    p_enqueue.add_argument("--state", type=Path, required=True)
    enqueue_group = p_enqueue.add_mutually_exclusive_group(required=True)
    enqueue_group.add_argument("--request", type=Path)
    enqueue_group.add_argument("--request-json", default="")
    p_enqueue.add_argument("--resolution-output", type=Path)
    p_enqueue.add_argument("--inventory", type=Path)
    p_select = sub.add_parser("select")
    p_select.add_argument("--state", type=Path, required=True)
    p_transition = sub.add_parser("transition")
    p_transition.add_argument("--state", type=Path, required=True)
    p_transition.add_argument("--work-item", required=True)
    p_transition.add_argument("--to", required=True, choices=sorted(STATES))
    p_summary = sub.add_parser("summary")
    p_summary.add_argument("--state", type=Path, required=True)
    args = parser.parse_args()

    if args.command == "resolve":
        inventory = _read_json(args.inventory) if args.inventory else None
        payload = resolve_request(_request_input(args.request, args.request_json), inventory=inventory)
        if args.output:
            _write_json(args.output, payload)
        else:
            print(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2))
        return 0
    if args.command == "init":
        _write_json(args.state, empty_state())
        return 0
    if args.command == "enqueue":
        state = _read_json(args.state) if args.state.exists() else empty_state()
        inventory = _read_json(args.inventory) if args.inventory else None
        updated, resolution = enqueue(state, _request_input(args.request, args.request_json), inventory=inventory)
        _write_json(args.state, updated)
        if args.resolution_output:
            _write_json(args.resolution_output, resolution)
        else:
            print(json.dumps(resolution, ensure_ascii=False, sort_keys=True, indent=2))
        return 0
    if args.command == "select":
        selected = select_next(_read_json(args.state))
        print(json.dumps(selected or {}, ensure_ascii=False, sort_keys=True, indent=2))
        return 0
    if args.command == "transition":
        updated = transition(_read_json(args.state), args.work_item, args.to)
        _write_json(args.state, updated)
        return 0
    if args.command == "summary":
        print(json.dumps(summary(_read_json(args.state)), ensure_ascii=False, sort_keys=True, indent=2))
        return 0
    raise AssertionError(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
