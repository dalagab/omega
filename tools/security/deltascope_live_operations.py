"""Adaptive authenticated GitHub Actions live acquisition for DeltaScope.

The browser never receives a GitHub credential. When GitHub access is connected, the
local DeltaScope backend may maintain a bounded, rate-limit-aware live snapshot of active
runs, jobs and runner observations. Public/unauthenticated mode remains explicit-snapshot
only and performs no live GitHub API polling.

Repository self-hosted runner inventory is opportunistic: job-level runner observations
remain useful when the credential cannot read the repository runner inventory.
"""
from __future__ import annotations

import datetime as dt
import json
import math
import threading
import time
from typing import Any, Mapping
import urllib.error
import urllib.parse
import urllib.request

import deltascope_operations
import omega_actions_telemetry

LIVE_SCHEMA = "omega.deltascope.live-operations.v1"
LIVE_CAPABILITY_SCHEMA = "omega.deltascope.github-live-capabilities.v1"
LIVE_RATE_SCHEMA = "omega.deltascope.github-rate-limit.v1"
RUNNER_DASHBOARD_SCHEMA = "omega.deltascope.runner-dashboard.v1"
WORKER_ROLE_SCHEMA = "omega.deltascope.worker-role-observation.v1"
JOB_TELEMETRY_SCHEMA = "omega.deltascope.job-telemetry.v1"
TELEMETRY_VIEW_SCHEMA = "omega.deltascope.actions-telemetry-view.v1"
LIVE_ACTIVITY_SCHEMA = "omega.deltascope.live-activity.v1"

FOREGROUND_POLL_SECONDS = 15
BACKGROUND_POLL_SECONDS = 60
RUNNER_INVENTORY_SECONDS = 60
FORCE_MIN_SECONDS = 5
FAILURE_RETRY_SECONDS = 30
MAX_ACTIVE_RUNS = 6
MAX_LIVE_JOBS = 200
LOW_RATE_REMAINING = 1000
VERY_LOW_RATE_REMAINING = 500
TELEMETRY_LOG_SECONDS = 30
MAX_TELEMETRY_JOBS = 4
MAX_TELEMETRY_LOG_BYTES = 256 * 1024


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _header(headers: Any, name: str) -> str:
    if headers is None:
        return ""
    try:
        value = headers.get(name)
        if value is None:
            value = headers.get(name.lower())
        return str(value or "")
    except Exception:
        return ""


def _rate_snapshot(headers: Any) -> dict[str, Any]:
    limit = _int(_header(headers, "X-RateLimit-Limit"))
    remaining = _int(_header(headers, "X-RateLimit-Remaining"))
    used = _int(_header(headers, "X-RateLimit-Used"))
    reset_epoch = _int(_header(headers, "X-RateLimit-Reset"))
    reset_at = ""
    if reset_epoch > 0:
        try:
            reset_at = dt.datetime.fromtimestamp(reset_epoch, tz=dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        except (OverflowError, OSError, ValueError):
            reset_at = ""
    return {
        "schema": LIVE_RATE_SCHEMA,
        "limit": limit,
        "remaining": remaining,
        "used": used,
        "resource": _header(headers, "X-RateLimit-Resource"),
        "resetEpoch": reset_epoch,
        "resetAtUtc": reset_at,
        "retryAfterSeconds": _int(_header(headers, "Retry-After")),
    }


def _capability(available: bool | None, *, observed: bool, source: str, detail: str = "") -> dict[str, Any]:
    return {"available": available, "observed": bool(observed), "source": source, "detail": str(detail or "")}


def _empty_capabilities(authenticated: bool) -> dict[str, Any]:
    return {
        "schema": LIVE_CAPABILITY_SCHEMA,
        "authenticated": authenticated,
        "actionsRead": _capability(None if authenticated else False, observed=False, source="not-probed"),
        "jobsRead": _capability(None if authenticated else False, observed=False, source="not-probed"),
        "jobLogsRead": _capability(
            True if authenticated else False,
            observed=False,
            source="active-job-telemetry-or-on-demand" if authenticated else "not-authenticated",
            detail="Active jobs may fetch bounded telemetry markers; full raw logs remain lazy/on-demand in Workflow Center.",
        ),
        "runnerInventoryRead": _capability(None if authenticated else False, observed=False, source="not-probed"),
        "workflowDispatch": _capability(
            True if authenticated else False,
            observed=False,
            source="connected-token" if authenticated else "not-authenticated",
            detail="Actual dispatch remains explicitly confirmed by the existing Workflow Center.",
        ),
        "runControl": _capability(
            True if authenticated else False,
            observed=False,
            source="connected-token" if authenticated else "not-authenticated",
            detail="Cancel/rerun remains explicitly confirmed by the existing Workflow Center.",
        ),
    }


def _ensure_state(client: Any) -> None:
    with client._lock:
        if not hasattr(client, "_live_cache"):
            client._live_cache = None
            client._live_cached_at = 0.0
            client._live_last_attempt_at = 0.0
            client._live_fetch_lock = threading.Lock()
            client._live_rate_limit = {
                "schema": LIVE_RATE_SCHEMA,
                "limit": 0,
                "remaining": 0,
                "used": 0,
                "resource": "",
                "resetEpoch": 0,
                "resetAtUtc": "",
                "retryAfterSeconds": 0,
            }
            client._live_backoff_until = 0.0
            client._live_runner_inventory = []
            client._live_runner_inventory_at = 0.0
            client._live_runner_inventory_error = ""
            client._live_runner_inventory_observed = False
            client._live_telemetry_cache = {}
        if not hasattr(client, "_live_last_attempt_utc"):
            client._live_last_attempt_utc = ""
            client._live_last_success_utc = ""
            client._live_last_error = ""
            client._live_last_error_utc = ""
            client._live_backoff_reason = ""


def _reset_state(client: Any) -> None:
    _ensure_state(client)
    with client._lock:
        client._live_cache = None
        client._live_cached_at = 0.0
        client._live_last_attempt_at = 0.0
        client._live_last_attempt_utc = ""
        client._live_last_success_utc = ""
        client._live_last_error = ""
        client._live_last_error_utc = ""
        client._live_backoff_reason = ""
        client._live_rate_limit = {
            "schema": LIVE_RATE_SCHEMA,
            "limit": 0,
            "remaining": 0,
            "used": 0,
            "resource": "",
            "resetEpoch": 0,
            "resetAtUtc": "",
            "retryAfterSeconds": 0,
        }
        client._live_backoff_until = 0.0
        client._live_runner_inventory = []
        client._live_runner_inventory_at = 0.0
        client._live_runner_inventory_error = ""
        client._live_runner_inventory_observed = False
        client._live_telemetry_cache = {}


def _record_rate(client: Any, headers: Any) -> None:
    rate = _rate_snapshot(headers)
    if not any(rate.get(key) for key in ("limit", "remaining", "used", "resetEpoch", "retryAfterSeconds")):
        return
    now = time.monotonic()
    retry = _int(rate.get("retryAfterSeconds"))
    with client._lock:
        client._live_rate_limit = rate
        if retry > 0:
            client._live_backoff_until = max(client._live_backoff_until, now + retry)
            client._live_backoff_reason = f"GitHub requested a {retry}-second retry delay."
        elif rate.get("limit") and rate.get("remaining") == 0:
            client._live_backoff_until = max(client._live_backoff_until, now + FAILURE_RETRY_SECONDS)
            client._live_backoff_reason = "GitHub API rate budget is exhausted; acquisition is delayed until a later bounded retry."


def _live_request_json(client: Any, url: str, *, timeout: float = 6.0, maximum: int = deltascope_operations.MAX_RESPONSE_BYTES) -> Mapping[str, Any]:
    request = urllib.request.Request(url, headers=client._headers())
    try:
        with client._opener(request, timeout=timeout) as response:
            _record_rate(client, getattr(response, "headers", None))
            raw = response.read(maximum + 1)
    except urllib.error.HTTPError as exc:
        _record_rate(client, getattr(exc, "headers", None))
        raise
    if len(raw) > maximum:
        raise RuntimeError("GitHub live operations response exceeded the DeltaScope safety bound")
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, Mapping):
        raise RuntimeError("GitHub live operations response was not an object")
    return payload



def _live_request_text(
    client: Any,
    url: str,
    *,
    timeout: float = 6.0,
    maximum: int = MAX_TELEMETRY_LOG_BYTES,
) -> str:
    request = urllib.request.Request(url, headers=client._headers(accept="text/plain"))
    try:
        with client._opener(request, timeout=timeout) as response:
            _record_rate(client, getattr(response, "headers", None))
            raw = response.read(maximum + 1)
    except urllib.error.HTTPError as exc:
        _record_rate(client, getattr(exc, "headers", None))
        raise
    if len(raw) > maximum:
        raw = raw[:maximum]
    return raw.decode("utf-8", "replace")


def _job_telemetry(client: Any, job: Mapping[str, Any], *, force: bool = False) -> dict[str, Any]:
    """Acquire only the bounded marker-bearing log preview for one active job."""
    _ensure_state(client)
    job_id = _int(job.get("jobId"))
    if job_id <= 0:
        return {
            "schema": JOB_TELEMETRY_SCHEMA, "available": False, "jobId": 0,
            "eventCount": 0, "events": [], "error": "jobId unavailable",
        }
    now = time.monotonic()
    with client._lock:
        cached = client._live_telemetry_cache.get(job_id)
    if (
        not force
        and isinstance(cached, tuple)
        and len(cached) == 2
        and now - float(cached[0] or 0.0) < TELEMETRY_LOG_SECONDS
        and isinstance(cached[1], Mapping)
    ):
        result = dict(cached[1])
        result["servedFromCache"] = True
        return result

    repository = urllib.parse.quote(client.repository, safe="/")
    url = f"https://api.github.com/repos/{repository}/actions/jobs/{job_id}/logs"
    try:
        text = _live_request_text(client, url)
        parsed = omega_actions_telemetry.parse_log(text)
        result = {
            "schema": JOB_TELEMETRY_SCHEMA,
            "available": True,
            "jobId": job_id,
            "contract": omega_actions_telemetry.SCHEMA,
            "source": "github-actions-job-log",
            "fetchedAtUtc": _utc_now(),
            "eventCount": _int(parsed.get("eventCount")),
            "invalidCount": _int(parsed.get("invalidCount")),
            "truncated": bool(parsed.get("truncated")),
            "events": [dict(row) for row in parsed.get("events") or [] if isinstance(row, Mapping)],
            "readOnly": True,
            "mutationAuthority": "none",
        }
    except Exception as exc:
        # Telemetry is an optional enrichment layer. A log endpoint can be temporarily
        # unavailable for running jobs or forbidden by token scope without breaking the
        # authoritative Actions run/job snapshot.
        result = {
            "schema": JOB_TELEMETRY_SCHEMA,
            "available": False,
            "jobId": job_id,
            "contract": omega_actions_telemetry.SCHEMA,
            "source": "github-actions-job-log",
            "fetchedAtUtc": _utc_now(),
            "eventCount": 0,
            "invalidCount": 0,
            "truncated": False,
            "events": [],
            "error": str(exc)[:512],
            "readOnly": True,
            "mutationAuthority": "none",
        }
    with client._lock:
        client._live_telemetry_cache[job_id] = (time.monotonic(), dict(result))
    return result


def _telemetry_worker_role(job: Mapping[str, Any], telemetry: Mapping[str, Any]) -> dict[str, Any] | None:
    events = [dict(row) for row in telemetry.get("events") or [] if isinstance(row, Mapping)]
    if not events:
        return None
    latest = events[-1]
    worker = latest.get("worker") if isinstance(latest.get("worker"), Mapping) else {}
    inferred = _worker_role(job)
    role_id = str(worker.get("roleId") or latest.get("component") or inferred.get("roleId") or "workflow-worker")
    label = str(worker.get("label") or inferred.get("label") or role_id)
    state = str(worker.get("state") or latest.get("state") or latest.get("stage") or latest.get("event") or "running")
    return {
        "schema": WORKER_ROLE_SCHEMA,
        "roleId": role_id,
        "label": label,
        "state": state,
        "currentStep": dict(job.get("currentStep") or {}),
        "source": "omega-actions-telemetry",
        "inferred": False,
        "workerPublished": True,
        "authoritative": False,
        "authority": "github-actions-job-log-self-report",
        "telemetryEvent": latest,
        "note": "Worker activity is explicitly self-reported through omega.actions.telemetry.v1. It is operational context, not Security Evidence authority.",
    }


def _enrich_jobs_with_telemetry(client: Any, jobs: list[dict[str, Any]]) -> dict[str, Any]:
    attempted = 0
    successful = 0
    telemetry_jobs = 0
    invalid = 0
    recent: list[dict[str, Any]] = []
    errors: list[str] = []
    for job in jobs:
        if str(job.get("state") or "") != "running":
            continue
        if attempted >= MAX_TELEMETRY_JOBS:
            job["telemetry"] = {
                "schema": JOB_TELEMETRY_SCHEMA, "available": False, "deferred": True,
                "jobId": _int(job.get("jobId")), "eventCount": 0, "events": [],
                "error": "bounded live telemetry job limit reached",
            }
            continue
        attempted += 1
        projection = _job_telemetry(client, job)
        job["telemetry"] = projection
        if projection.get("available"):
            successful += 1
        invalid += _int(projection.get("invalidCount"))
        events = [dict(row) for row in projection.get("events") or [] if isinstance(row, Mapping)]
        if events:
            telemetry_jobs += 1
            explicit = _telemetry_worker_role(job, projection)
            if explicit:
                job["workerRole"] = explicit
            latest = events[-1]
            job["latestTelemetry"] = latest
            job["telemetryEventCount"] = len(events)
            for event in events:
                recent.append({
                    **event,
                    "runId": _int(job.get("runId")),
                    "runNumber": _int(job.get("runNumber")),
                    "jobId": _int(job.get("jobId")),
                    "jobName": str(job.get("name") or ""),
                    "runnerId": _int(job.get("runnerId")),
                    "runnerName": str(job.get("runnerName") or ""),
                    "workflow": str(job.get("workflow") or ""),
                    "workflowPath": str(job.get("workflowPath") or ""),
                })
        elif projection.get("error"):
            errors.append(f"job {_int(job.get('jobId'))}: {str(projection.get('error'))[:180]}")
    recent.sort(key=lambda row: (
        str(row.get("emittedAtUtc") or ""),
        _int(row.get("runId")),
        _int(row.get("jobId")),
    ), reverse=True)
    recent = recent[: omega_actions_telemetry.MAX_EVENTS]
    return {
        "schema": TELEMETRY_VIEW_SCHEMA,
        "available": bool(recent),
        "contract": omega_actions_telemetry.SCHEMA,
        "marker": omega_actions_telemetry.MARKER.rstrip(),
        "source": "bounded-active-job-logs",
        "attemptedJobs": attempted,
        "successfulLogJobs": successful,
        "telemetryJobs": telemetry_jobs,
        "eventCount": len(recent),
        "invalidCount": invalid,
        "recentEvents": recent,
        "warnings": errors[:8],
        "readOnly": True,
        "mutationAuthority": "none",
        "securityAuthority": False,
    }


def _job_state(job: Mapping[str, Any]) -> str:
    status = str(job.get("status") or "").casefold()
    conclusion = str(job.get("conclusion") or "").casefold()
    if status in deltascope_operations.RUNNING_STATES:
        return "running"
    if conclusion in deltascope_operations.FAIL_CONCLUSIONS:
        return "failed"
    if conclusion in deltascope_operations.WARN_CONCLUSIONS:
        return "warning"
    if conclusion == "success":
        return "healthy"
    return "unknown"


def _safe_url(value: Any) -> str:
    text = str(value or "")
    return text if text.startswith("https://github.com/") else ""



def _current_step(steps: list[Mapping[str, Any]]) -> dict[str, Any]:
    running = [dict(step) for step in steps if str(step.get("status") or "").casefold() in deltascope_operations.RUNNING_STATES]
    if running:
        running.sort(key=lambda row: _int(row.get("number")))
        return running[0]
    completed = [dict(step) for step in steps if str(step.get("status") or "").casefold() == "completed"]
    if completed:
        completed.sort(key=lambda row: _int(row.get("number")), reverse=True)
        return completed[0]
    return {}


def _worker_role(job: Mapping[str, Any]) -> dict[str, Any]:
    """Infer an operator-facing Omega worker role from GitHub job metadata only."""
    text = " ".join([
        str(job.get("componentId") or ""), str(job.get("component") or ""),
        str(job.get("workflow") or ""), str(job.get("name") or ""),
        " ".join(str(value) for value in (job.get("labels") or [])),
    ]).casefold()
    roles = (
        (("sigmascope",), "sigmascope", "SigmaScope worker"),
        (("stigma",), "stigma-1", "Stigma-1 worker"),
        (("srl",), "srl", "SRL worker"),
        (("rift",), "rift", "Rift worker"),
        (("analysis-broker",), "analysis-broker", "Analysis broker"),
        (("analysis-dispatch", "dispatcher"), "analysis-dispatcher", "Analysis dispatcher"),
        (("publish", "publisher"), "publisher", "Evidence publisher"),
        (("catalog",), "catalog", "Catalog worker"),
        (("discovery",), "discovery", "Discovery worker"),
    )
    role_id = str(job.get("componentId") or "").strip().casefold() or "workflow-worker"
    role_label = str(job.get("component") or "").strip() or "Workflow worker"
    for needles, candidate_id, candidate_label in roles:
        if any(needle in text for needle in needles):
            role_id, role_label = candidate_id, candidate_label
            break
    current = _current_step([step for step in (job.get("steps") or []) if isinstance(step, Mapping)])
    stage_text = f"{current.get('name') or ''} {job.get('name') or ''}".casefold()
    if "scan" in stage_text or "analy" in stage_text: worker_state = "scanning"
    elif "merge" in stage_text: worker_state = "merging"
    elif "publish" in stage_text: worker_state = "publishing"
    elif any(token in stage_text for token in ("queue", "claim", "lease")): worker_state = "claiming"
    elif any(token in stage_text for token in ("acquire", "download", "checkout")): worker_state = "acquiring"
    elif any(token in stage_text for token in ("verify", "test", "validate")): worker_state = "verifying"
    elif "wait" in stage_text: worker_state = "waiting"
    elif str(job.get("state") or "") == "running": worker_state = "running"
    else: worker_state = str(job.get("state") or "unknown")
    return {
        "schema": WORKER_ROLE_SCHEMA, "roleId": role_id, "label": role_label,
        "state": worker_state, "currentStep": dict(current),
        "source": "github-job-metadata-inference", "inferred": True, "authoritative": False,
        "note": "Runner infrastructure state is separate. This worker role is inferred from GitHub job metadata until structured Omega action telemetry is published.",
    }

def _normalize_job(raw: Mapping[str, Any], run: Mapping[str, Any]) -> dict[str, Any]:
    steps = []
    for raw_step in raw.get("steps") or []:
        if not isinstance(raw_step, Mapping):
            continue
        steps.append({
            "number": _int(raw_step.get("number")),
            "name": str(raw_step.get("name") or ""),
            "status": str(raw_step.get("status") or ""),
            "conclusion": str(raw_step.get("conclusion") or ""),
            "startedAtUtc": str(raw_step.get("started_at") or ""),
            "completedAtUtc": str(raw_step.get("completed_at") or ""),
        })
    result = {
        "jobId": _int(raw.get("id")),
        "runId": _int(run.get("runId")),
        "runNumber": _int(run.get("runNumber")),
        "componentId": str(run.get("componentId") or ""),
        "component": str(run.get("component") or ""),
        "workflow": str(run.get("workflow") or ""),
        "workflowPath": str(run.get("workflowPath") or ""),
        "branch": str(run.get("branch") or ""),
        "sha": str(run.get("sha") or ""),
        "name": str(raw.get("name") or ""),
        "status": str(raw.get("status") or ""),
        "conclusion": str(raw.get("conclusion") or ""),
        "state": _job_state(raw),
        "startedAtUtc": str(raw.get("started_at") or ""),
        "completedAtUtc": str(raw.get("completed_at") or ""),
        "runnerId": _int(raw.get("runner_id")),
        "runnerName": str(raw.get("runner_name") or ""),
        "runnerGroupId": _int(raw.get("runner_group_id")),
        "runnerGroupName": str(raw.get("runner_group_name") or ""),
        "labels": [str(value) for value in (raw.get("labels") or []) if str(value)],
        "url": _safe_url(raw.get("html_url")),
        "steps": steps,
        "currentStep": _current_step(steps),
        "readOnly": True,
    }
    result["workerRole"] = _worker_role(result)
    return result


def _request_live_jobs(client: Any, run: Mapping[str, Any]) -> list[dict[str, Any]]:
    repository = urllib.parse.quote(client.repository, safe="/")
    url = f"https://api.github.com/repos/{repository}/actions/runs/{_int(run.get('runId'))}/jobs?per_page=100"
    payload = _live_request_json(client, url)
    rows = payload.get("jobs")
    if not isinstance(rows, list):
        raise RuntimeError("GitHub live job response has no jobs list")
    return [_normalize_job(row, run) for row in rows if isinstance(row, Mapping)]


def _normalize_runner_inventory(raw: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "runnerId": _int(raw.get("id")),
        "runnerName": str(raw.get("name") or ""),
        "os": str(raw.get("os") or ""),
        "status": str(raw.get("status") or "unknown"),
        "busy": bool(raw.get("busy")),
        "ephemeral": bool(raw.get("ephemeral")) if "ephemeral" in raw else None,
        "version": str(raw.get("version") or ""),
        "labels": [
            str(row.get("name") or "") if isinstance(row, Mapping) else str(row)
            for row in (raw.get("labels") or [])
            if (str(row.get("name") or "") if isinstance(row, Mapping) else str(row))
        ],
        "source": "repository-runner-inventory",
        "readOnly": True,
    }


def _runner_inventory(client: Any, *, force: bool = False) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    _ensure_state(client)
    now = time.monotonic()
    with client._lock:
        cached = [dict(row) for row in client._live_runner_inventory]
        age = now - client._live_runner_inventory_at
        observed = bool(client._live_runner_inventory_observed)
        error = str(client._live_runner_inventory_error or "")
    if not force and observed and age < RUNNER_INVENTORY_SECONDS:
        return cached, _capability(not bool(error), observed=True, source="repository-runner-inventory", detail=error)

    repository = urllib.parse.quote(client.repository, safe="/")
    url = f"https://api.github.com/repos/{repository}/actions/runners?per_page=100"
    try:
        payload = _live_request_json(client, url)
        rows = payload.get("runners")
        if not isinstance(rows, list):
            raise RuntimeError("GitHub runner inventory response has no runners list")
        inventory = [_normalize_runner_inventory(row) for row in rows if isinstance(row, Mapping)]
        with client._lock:
            client._live_runner_inventory = [dict(row) for row in inventory]
            client._live_runner_inventory_at = now
            client._live_runner_inventory_error = ""
            client._live_runner_inventory_observed = True
        return inventory, _capability(True, observed=True, source="repository-runner-inventory")
    except urllib.error.HTTPError as exc:
        if int(getattr(exc, "code", 0) or 0) not in {403, 404}:
            raise
        detail = f"repository runner inventory unavailable ({int(exc.code)}); job-level runner observations remain available"
    except (OSError, ValueError, RuntimeError, urllib.error.URLError, json.JSONDecodeError) as exc:
        detail = str(exc)
    with client._lock:
        client._live_runner_inventory_at = now
        client._live_runner_inventory_error = detail
        client._live_runner_inventory_observed = True
    return cached, _capability(False, observed=True, source="repository-runner-inventory", detail=detail)


def _merge_runners(inventory: list[Mapping[str, Any]], jobs: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    by_key: dict[tuple[int, str], dict[str, Any]] = {}
    for raw in inventory:
        row = dict(raw)
        key = (_int(row.get("runnerId")), str(row.get("runnerName") or "").casefold())
        row["activeJobs"] = []
        row["runnerGroups"] = []
        by_key[key] = row
    for job in jobs:
        runner_id = _int(job.get("runnerId"))
        runner_name = str(job.get("runnerName") or "")
        if runner_id <= 0 and not runner_name:
            continue
        key = (runner_id, runner_name.casefold())
        row = by_key.get(key)
        if row is None:
            row = {
                "runnerId": runner_id,
                "runnerName": runner_name,
                "os": "",
                "status": "observed",
                "busy": str(job.get("state") or "") == "running",
                "ephemeral": None,
                "version": "",
                "labels": list(job.get("labels") or []),
                "source": "job-observation",
                "readOnly": True,
                "activeJobs": [],
                "runnerGroups": [],
            }
            by_key[key] = row
        row["busy"] = bool(row.get("busy")) or str(job.get("state") or "") == "running"
        group_name = str(job.get("runnerGroupName") or "").strip()
        if group_name and group_name not in row["runnerGroups"]:
            row["runnerGroups"].append(group_name)
        row["activeJobs"].append({
            "jobId": _int(job.get("jobId")),
            "runId": _int(job.get("runId")),
            "runNumber": _int(job.get("runNumber")),
            "componentId": str(job.get("componentId") or ""),
            "component": str(job.get("component") or ""),
            "workflow": str(job.get("workflow") or ""),
            "workflowPath": str(job.get("workflowPath") or ""),
            "branch": str(job.get("branch") or ""),
            "sha": str(job.get("sha") or ""),
            "name": str(job.get("name") or ""),
            "state": str(job.get("state") or ""),
            "startedAtUtc": str(job.get("startedAtUtc") or ""),
            "currentStep": dict(job.get("currentStep") or {}),
            "workerRole": dict(job.get("workerRole") or {}),
            "latestTelemetry": dict(job.get("latestTelemetry") or {}),
            "telemetryEventCount": _int(job.get("telemetryEventCount")),
            "url": str(job.get("url") or ""),
        })
    rows = list(by_key.values())
    rows.sort(key=lambda row: (
        not bool(row.get("busy")),
        str(row.get("status") or "") != "online",
        str(row.get("runnerName") or "").casefold(),
        _int(row.get("runnerId")),
    ))
    return rows




def project_actions_telemetry(
    client: Any,
    *,
    foreground: bool = True,
    force: bool = False,
) -> dict[str, Any]:
    live = live_status(client, foreground=foreground, force=force)
    result = dict(live.get("telemetry") or {})
    result.update({
        "schema": TELEMETRY_VIEW_SCHEMA,
        "repository": str(live.get("repository") or getattr(client, "repository", "")),
        "fetchedAtUtc": str(live.get("fetchedAtUtc") or ""),
        "live": bool(live.get("live")),
        "authenticated": bool(live.get("authenticated")),
        "nextPollSeconds": _int(live.get("nextPollSeconds")) or BACKGROUND_POLL_SECONDS,
        "servedFromCache": bool(live.get("servedFromCache")),
        "stale": bool(live.get("stale")),
        "rateLimit": dict(live.get("rateLimit") or {}),
        "readOnly": True,
        "mutationAuthority": "none",
        "securityAuthority": False,
    })
    return result



def _activity_subject(event: Mapping[str, Any], job: Mapping[str, Any]) -> dict[str, Any]:
    subject = event.get("subject") if isinstance(event.get("subject"), Mapping) else {}
    return {
        "pluginId": _int(subject.get("pluginId")),
        "variantId": _int(subject.get("variantId")),
        "internalName": str(subject.get("internalName") or ""),
        "version": str(subject.get("version") or ""),
        "workType": str(subject.get("workType") or ""),
        "sourceName": str(subject.get("sourceName") or ""),
        "fallback": str(job.get("name") or job.get("workflow") or ""),
    }


def project_live_activity(
    client: Any,
    *,
    foreground: bool = True,
    force: bool = False,
) -> dict[str, Any]:
    """Project the live Actions snapshot into current work + an operator event timeline.

    This is a presentation projection over the same cached live snapshot.  It never
    performs an independent GitHub acquisition cycle and never upgrades operational
    self-reports into Security Evidence authority.
    """
    live = live_status(client, foreground=foreground, force=force)
    telemetry = live.get("telemetry") if isinstance(live.get("telemetry"), Mapping) else {}
    events = [
        dict(row) for row in telemetry.get("recentEvents") or []
        if isinstance(row, Mapping)
    ]
    jobs = [
        dict(row) for row in live.get("jobs") or []
        if isinstance(row, Mapping) and str(row.get("state") or "") == "running"
    ]

    current_work: list[dict[str, Any]] = []
    represented_runs: set[int] = set()
    for job in jobs:
        run_id = _int(job.get("runId"))
        represented_runs.add(run_id)
        event = (
            dict(job.get("latestTelemetry"))
            if isinstance(job.get("latestTelemetry"), Mapping)
            else {}
        )
        role = (
            dict(job.get("workerRole"))
            if isinstance(job.get("workerRole"), Mapping)
            else {}
        )
        current_step = (
            dict(job.get("currentStep"))
            if isinstance(job.get("currentStep"), Mapping)
            else {}
        )
        explicit = bool(event)
        state = str(
            role.get("state")
            or event.get("state")
            or event.get("stage")
            or current_step.get("name")
            or job.get("state")
            or "running"
        )
        current_work.append({
            "kind": "job",
            "runId": run_id,
            "runNumber": _int(job.get("runNumber")),
            "jobId": _int(job.get("jobId")),
            "workflow": str(job.get("workflow") or ""),
            "workflowPath": str(job.get("workflowPath") or ""),
            "jobName": str(job.get("name") or ""),
            "runnerId": _int(job.get("runnerId")),
            "runnerName": str(job.get("runnerName") or ""),
            "workerRole": role,
            "state": state,
            "telemetrySource": "structured" if explicit else "inferred",
            "event": str(event.get("event") or ""),
            "stage": str(event.get("stage") or current_step.get("name") or ""),
            "subject": _activity_subject(event, job),
            "queue": dict(event.get("queue") or {}) if isinstance(event.get("queue"), Mapping) else {},
            "progress": dict(event.get("progress") or {}) if isinstance(event.get("progress"), Mapping) else {},
            "publication": dict(event.get("publication") or {}) if isinstance(event.get("publication"), Mapping) else {},
            "result": dict(event.get("result") or {}) if isinstance(event.get("result"), Mapping) else {},
            "currentStep": current_step,
            "startedAtUtc": str(job.get("startedAtUtc") or ""),
            "url": str(job.get("url") or ""),
            "readOnly": True,
        })

    for run in live.get("activeRuns") or []:
        if not isinstance(run, Mapping):
            continue
        run_id = _int(run.get("runId"))
        if run_id in represented_runs:
            continue
        current_work.append({
            "kind": "run",
            "runId": run_id,
            "runNumber": _int(run.get("runNumber")),
            "jobId": 0,
            "workflow": str(run.get("workflow") or ""),
            "workflowPath": str(run.get("workflowPath") or ""),
            "jobName": "",
            "runnerId": 0,
            "runnerName": "",
            "workerRole": {},
            "state": str(run.get("status") or run.get("state") or "running"),
            "telemetrySource": "actions-run",
            "event": "",
            "stage": "",
            "subject": {"pluginId": 0, "variantId": 0, "internalName": "", "version": "", "workType": "", "sourceName": "", "fallback": str(run.get("title") or run.get("workflow") or "")},
            "queue": {},
            "progress": {},
            "publication": {},
            "result": {},
            "currentStep": {},
            "startedAtUtc": str(run.get("createdAtUtc") or ""),
            "url": str(run.get("url") or ""),
            "readOnly": True,
        })

    current_work.sort(key=lambda row: (
        0 if row.get("telemetrySource") == "structured" else 1,
        str(row.get("startedAtUtc") or ""),
        _int(row.get("runId")),
        _int(row.get("jobId")),
    ))

    latest_queue = next((
        dict(event) for event in events
        if str(event.get("event") or "").startswith("queue.")
    ), {})
    latest_publication = next((
        dict(event) for event in events
        if str(event.get("event") or "").startswith("publication.")
    ), {})
    latest_scan = next((
        dict(event) for event in events
        if str(event.get("event") or "").startswith(("scan.", "source.", "analysis."))
    ), {})

    return {
        "schema": LIVE_ACTIVITY_SCHEMA,
        "available": bool(live.get("available")),
        "live": bool(live.get("live")),
        "authenticated": bool(live.get("authenticated")),
        "repository": str(live.get("repository") or getattr(client, "repository", "")),
        "fetchedAtUtc": str(live.get("fetchedAtUtc") or ""),
        "nextPollSeconds": _int(live.get("nextPollSeconds")) or BACKGROUND_POLL_SECONDS,
        "servedFromCache": bool(live.get("servedFromCache")),
        "stale": bool(live.get("stale")),
        "counts": {
            "currentWork": len(current_work),
            "activeRuns": _int((live.get("counts") or {}).get("activeRuns")),
            "jobs": _int((live.get("counts") or {}).get("jobs")),
            "runners": _int((live.get("counts") or {}).get("runners")),
            "busyRunners": _int((live.get("counts") or {}).get("busyRunners")),
            "telemetryEvents": len(events),
            "telemetryJobs": _int((live.get("counts") or {}).get("telemetryJobs")),
        },
        "currentWork": current_work,
        "timeline": events,
        "latest": {
            "queue": latest_queue,
            "scan": latest_scan,
            "publication": latest_publication,
        },
        "rateLimit": dict(live.get("rateLimit") or {}),
        "capabilities": dict(live.get("capabilities") or {}),
        "readOnly": True,
        "mutationAuthority": "none",
        "securityAuthority": False,
        "semanticBoundary": {
            "actionsRunJobState": "github-actions-operational-state",
            "structuredTelemetry": "worker-self-report-operational-context",
            "securityEvidence": "not-derived-from-live-operations",
            "rawLogsReturned": False,
        },
    }


def project_runner_dashboard(client: Any, *, foreground: bool = True, force: bool = False) -> dict[str, Any]:
    """Project runner infrastructure separately from Omega worker-role observations."""
    live = live_status(client, foreground=foreground, force=force)
    rows: list[dict[str, Any]] = []
    for raw in live.get("runners") or []:
        if not isinstance(raw, Mapping): continue
        runner = dict(raw); source = str(runner.get("source") or ""); status = str(runner.get("status") or "unknown").casefold(); inventory_backed = source == "repository-runner-inventory"
        observed_online: bool | None = (status == "online") if inventory_backed else None
        workers = [dict(job) for job in (runner.get("activeJobs") or []) if isinstance(job, Mapping)]
        rows.append({
            "runnerId": _int(runner.get("runnerId")), "runnerName": str(runner.get("runnerName") or ""),
            "infrastructure": {
                "status": status or "unknown", "busy": bool(runner.get("busy")), "os": str(runner.get("os") or ""),
                "version": str(runner.get("version") or ""), "ephemeral": runner.get("ephemeral"),
                "labels": list(runner.get("labels") or []), "groups": list(runner.get("runnerGroups") or []),
                "source": source or "unknown", "inventoryBacked": inventory_backed, "onlineObserved": observed_online,
                "authority": "github-actions-runner-state",
            },
            "workers": workers, "workerCount": len(workers), "readOnly": True, "mutationAuthority": "none",
        })
    rows.sort(key=lambda row: (not bool((row.get("infrastructure") or {}).get("busy")), (row.get("infrastructure") or {}).get("status") != "online", str(row.get("runnerName") or "").casefold(), _int(row.get("runnerId"))))
    online=sum(1 for row in rows if (row.get("infrastructure") or {}).get("onlineObserved") is True)
    offline=sum(1 for row in rows if (row.get("infrastructure") or {}).get("onlineObserved") is False)
    observed_only=sum(1 for row in rows if (row.get("infrastructure") or {}).get("onlineObserved") is None)
    busy=sum(1 for row in rows if bool((row.get("infrastructure") or {}).get("busy")))
    worker_count=sum(_int(row.get("workerCount")) for row in rows)
    runner_cap=(live.get("capabilities") or {}).get("runnerInventoryRead") or {}
    if not live.get("authenticated"):
        message="Connect GitHub access to enable live runner and worker correlation."
    elif runner_cap.get("available") is True:
        message="Runner infrastructure state comes from GitHub runner inventory; Omega worker roles are correlated separately from active jobs."
    else:
        message="Runner inventory is not available to this credential. Active jobs still provide bounded runner observations without claiming online/offline infrastructure state."
    return {
        "schema": RUNNER_DASHBOARD_SCHEMA, "available": bool(live.get("available")), "live": bool(live.get("live")),
        "authenticated": bool(live.get("authenticated")), "repository": str(live.get("repository") or getattr(client,"repository","")),
        "fetchedAtUtc": str(live.get("fetchedAtUtc") or ""), "nextPollSeconds": _int(live.get("nextPollSeconds")) or BACKGROUND_POLL_SECONDS,
        "servedFromCache": bool(live.get("servedFromCache")), "stale": bool(live.get("stale")),
        "rateLimit": dict(live.get("rateLimit") or {}), "capabilities": dict(live.get("capabilities") or {}),
        "counts": {"runners":len(rows),"online":online,"offline":offline,"observedOnly":observed_only,"busy":busy,"idle":max(0,len(rows)-busy),"workers":worker_count},
        "runners": rows, "message": message,
        "semanticBoundary": {"runnerIsInfrastructure":True,"workerIsExecutionRole":True,"workerRoleMayBeInferredWhenTelemetryMissing":True,"structuredTelemetryOverridesInference":True,"runnerStatusNeverDerivedFromWorkerRole":True},
        "readOnly": True, "mutationAuthority": "none",
    }

def _base_interval(client: Any, foreground: bool) -> int:
    interval = FOREGROUND_POLL_SECONDS if foreground else BACKGROUND_POLL_SECONDS
    with client._lock:
        rate = dict(client._live_rate_limit or {})
        backoff = max(0.0, float(client._live_backoff_until or 0.0) - time.monotonic())
    remaining = _int(rate.get("remaining"))
    limit = _int(rate.get("limit"))
    if limit > 0 and remaining <= VERY_LOW_RATE_REMAINING:
        interval = max(interval, 60)
    elif limit > 0 and remaining <= LOW_RATE_REMAINING:
        interval = max(interval, 30)
    if backoff > 0:
        interval = max(interval, int(math.ceil(backoff)))
    return interval


def _live_unavailable(client: Any, *, foreground: bool, reason: str = "") -> dict[str, Any]:
    authenticated = bool(getattr(client, "token", ""))
    return {
        "schema": LIVE_SCHEMA,
        "available": False,
        "live": False,
        "authenticated": authenticated,
        "readOnly": True,
        "mutationAuthority": "none",
        "repository": client.repository,
        "fetchedAtUtc": "",
        "cachePolicy": "adaptive-authenticated-live" if authenticated else "explicit-public-snapshot",
        "foreground": bool(foreground),
        "nextPollSeconds": BACKGROUND_POLL_SECONDS if not authenticated else _base_interval(client, foreground),
        "counts": {"activeRuns": 0, "queuedRuns": 0, "jobs": 0, "runners": 0, "busyRunners": 0, "telemetryEvents": 0, "telemetryJobs": 0},
        "activeRuns": [],
        "queuedRuns": [],
        "jobs": [],
        "runners": [],
        "telemetry": {"schema": TELEMETRY_VIEW_SCHEMA, "available": False, "contract": omega_actions_telemetry.SCHEMA, "eventCount": 0, "telemetryJobs": 0, "recentEvents": [], "securityAuthority": False},
        "capabilities": _empty_capabilities(authenticated),
        "rateLimit": dict(getattr(client, "_live_rate_limit", {}) or {}),
        "access": client.access_status(),
        "error": reason or ("Connect GitHub access to enable live Actions telemetry." if not authenticated else ""),
    }


def _acquire_live(client: Any, *, foreground: bool) -> dict[str, Any]:
    repository = urllib.parse.quote(client.repository, safe="/")
    runs_url = f"https://api.github.com/repos/{repository}/actions/runs?per_page={deltascope_operations.MAX_RUNS}"
    payload = _live_request_json(client, runs_url)
    raw_runs = payload.get("workflow_runs")
    if not isinstance(raw_runs, list):
        raise RuntimeError("GitHub live Actions response has no workflow_runs list")

    normalized = [
        deltascope_operations.normalize_run(row)
        for row in raw_runs[:deltascope_operations.MAX_RUNS]
        if isinstance(row, Mapping)
    ]
    normalized.sort(key=lambda row: (str(row.get("createdAtUtc") or ""), _int(row.get("runId"))), reverse=True)
    active = [row for row in normalized if str(row.get("state") or "") == "running"]
    queued = [row for row in active if str(row.get("status") or "").casefold() in {"queued", "requested", "waiting", "pending"}]
    execution = [row for row in active if str(row.get("status") or "").casefold() == "in_progress"][:MAX_ACTIVE_RUNS]

    capabilities = _empty_capabilities(True)
    capabilities["actionsRead"] = _capability(True, observed=True, source="actions-runs")

    jobs: list[dict[str, Any]] = []
    job_errors: list[str] = []
    for run in execution:
        try:
            rows = _request_live_jobs(client, run)
            jobs.extend(rows[: max(0, MAX_LIVE_JOBS - len(jobs))])
        except (OSError, ValueError, RuntimeError, urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as exc:
            job_errors.append(f"run {_int(run.get('runId'))}: {exc}")
        if len(jobs) >= MAX_LIVE_JOBS:
            break
    jobs_available: bool | None = None if not execution else True if jobs else False
    capabilities["jobsRead"] = _capability(
        jobs_available,
        observed=bool(execution),
        source="active-run-jobs" if execution else "no-active-job-probe",
        detail="; ".join(job_errors[:4]),
    )

    telemetry = _enrich_jobs_with_telemetry(client, jobs)
    if telemetry.get("attemptedJobs"):
        capabilities["jobLogsRead"] = _capability(
            bool(telemetry.get("successfulLogJobs")),
            observed=True,
            source="bounded-active-job-telemetry",
            detail="; ".join(str(row) for row in telemetry.get("warnings") or [])[:512],
        )

    inventory, runner_capability = _runner_inventory(client)
    capabilities["runnerInventoryRead"] = runner_capability
    runners = _merge_runners(inventory, jobs)

    with client._lock:
        rate = dict(client._live_rate_limit or {})
    interval = _base_interval(client, foreground)
    return {
        "schema": LIVE_SCHEMA,
        "available": True,
        "live": True,
        "authenticated": True,
        "readOnly": True,
        "mutationAuthority": "none",
        "repository": client.repository,
        "fetchedAtUtc": _utc_now(),
        "cachePolicy": "adaptive-authenticated-live",
        "foreground": bool(foreground),
        "nextPollSeconds": interval,
        "counts": {
            "activeRuns": len(active),
            "queuedRuns": len(queued),
            "jobs": len(jobs),
            "runners": len(runners),
            "busyRunners": sum(1 for row in runners if bool(row.get("busy"))),
            "telemetryEvents": _int(telemetry.get("eventCount")),
            "telemetryJobs": _int(telemetry.get("telemetryJobs")),
        },
        "activeRuns": active[:20],
        "queuedRuns": queued[:20],
        "jobs": jobs,
        "runners": runners,
        "telemetry": telemetry,
        "capabilities": capabilities,
        "rateLimit": rate,
        "access": client.access_status(),
        "warnings": job_errors[:8],
    }


def _failure_backoff_reason(exc: Exception, rate: Mapping[str, Any]) -> str:
    code = int(getattr(exc, "code", 0) or 0)
    if code == 401:
        return "GitHub rejected the credential (401); the token may be invalid, expired, or no longer authorized for this repository."
    if code == 403 and _int(rate.get("limit")) > 0 and _int(rate.get("remaining")) == 0:
        return "GitHub denied the read because the API rate budget is exhausted (403)."
    if code == 403:
        return "GitHub denied the bounded Actions read (403); the connected credential may not have access to this repository resource."
    if code == 404:
        return "GitHub did not expose the requested Actions resource (404) to this credential."
    return f"Live GitHub acquisition failed; the next bounded retry is delayed by {FAILURE_RETRY_SECONDS} seconds."


def live_status(client: Any, *, foreground: bool = True, force: bool = False) -> dict[str, Any]:
    _ensure_state(client)
    if not getattr(client, "token", ""):
        return _live_unavailable(client, foreground=foreground)

    now = time.monotonic()
    desired = _base_interval(client, foreground)
    with client._lock:
        cached = dict(client._live_cache) if isinstance(client._live_cache, Mapping) else None
        cached_at = float(client._live_cached_at or 0.0)
        last_attempt = float(client._live_last_attempt_at or 0.0)
        backoff_until = float(client._live_backoff_until or 0.0)
    if cached and not force and now - cached_at < desired:
        cached["foreground"] = bool(foreground)
        cached["nextPollSeconds"] = max(1, int(math.ceil(desired - (now - cached_at))))
        cached["servedFromCache"] = True
        return cached
    if force and now - last_attempt < FORCE_MIN_SECONDS and cached:
        cached["foreground"] = bool(foreground)
        cached["nextPollSeconds"] = max(1, int(math.ceil(FORCE_MIN_SECONDS - (now - last_attempt))))
        cached["servedFromCache"] = True
        cached["forceThrottled"] = True
        return cached
    if backoff_until > now and cached:
        cached["foreground"] = bool(foreground)
        cached["nextPollSeconds"] = max(1, int(math.ceil(backoff_until - now)))
        cached["servedFromCache"] = True
        cached["rateLimited"] = True
        return cached

    fetch_lock = client._live_fetch_lock
    with fetch_lock:
        now = time.monotonic()
        with client._lock:
            cached = dict(client._live_cache) if isinstance(client._live_cache, Mapping) else None
            cached_at = float(client._live_cached_at or 0.0)
            client._live_last_attempt_at = now
            client._live_last_attempt_utc = _utc_now()
        if cached and not force and now - cached_at < desired:
            cached["servedFromCache"] = True
            cached["nextPollSeconds"] = max(1, int(math.ceil(desired - (now - cached_at))))
            return cached
        try:
            result = _acquire_live(client, foreground=foreground)
        except (OSError, ValueError, RuntimeError, urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as exc:
            failure = str(exc)[:500]
            with client._lock:
                client._live_backoff_until = max(client._live_backoff_until, time.monotonic() + FAILURE_RETRY_SECONDS)
                rate = dict(client._live_rate_limit or {})
                client._live_last_error = failure
                client._live_last_error_utc = _utc_now()
                client._live_backoff_reason = _failure_backoff_reason(exc, rate)
            if cached:
                cached["stale"] = True
                cached["servedFromCache"] = True
                cached["error"] = failure
                cached["rateLimit"] = rate
                cached["nextPollSeconds"] = _base_interval(client, foreground)
                return cached
            result = _live_unavailable(client, foreground=foreground, reason=failure)
            result["stale"] = False
        else:
            with client._lock:
                client._live_last_success_utc = str(result.get("fetchedAtUtc") or _utc_now())
                client._live_last_error = ""
                client._live_last_error_utc = ""
                if float(client._live_backoff_until or 0.0) <= time.monotonic():
                    client._live_backoff_reason = ""
        with client._lock:
            client._live_cache = dict(result)
            client._live_cached_at = time.monotonic()
        return result


def _install_client_extensions(cls: Any) -> None:
    if getattr(cls, "_deltascope_live_operations_installed", False):
        return
    original_configure = cls.configure_token

    def configure_token(self: Any, token: object, *, remember: bool = True) -> dict[str, Any]:
        result = original_configure(self, token, remember=remember)
        _reset_state(self)
        return result

    cls.configure_token = configure_token
    cls.live_status = live_status
    cls.runner_dashboard = project_runner_dashboard
    cls.actions_telemetry = project_actions_telemetry
    cls.live_activity = project_live_activity
    cls._deltascope_live_operations_installed = True


_RUNNER_VIEW = r'''
<section id="workbench-runners" class="workspace-view" data-workbench-view="runners">
  <div class="runner-dashboard-head">
    <div><div class="eyebrow">GITHUB RUNNERS · OMEGA WORKERS</div><h1>Runner Dashboard</h1><p>Infrastructure runner state and the Omega worker roles executing on it are intentionally shown as separate facts.</p></div>
    <div class="runner-dashboard-actions"><span id="runnerDashboardSnapshot" class="muted small">Live snapshot not loaded</span><button id="runnerDashboardRefresh">Refresh live state</button></div>
  </div>
  <div id="runnerDashboardStats" class="runner-dashboard-stats"></div>
  <div class="runner-dashboard-toolbar"><input id="runnerDashboardSearch" placeholder="Search runner, group, label, workflow or worker…" autocomplete="off"><select id="runnerDashboardState"><option value="">All runners</option><option value="busy">Busy</option><option value="idle">Idle</option><option value="online">Online</option><option value="offline">Offline</option><option value="observed">Observed from jobs</option></select></div>
  <div id="runnerDashboardNotice" class="runner-dashboard-notice"></div>
  <div id="runnerDashboardGrid" class="runner-dashboard-grid"><div class="workspace-empty">Loading live runner state…</div></div>
</section>
'''

_LIVE_CSS = r'''
.workflow-live-strip{display:grid;grid-template-columns:minmax(180px,.8fr) repeat(4,minmax(90px,.45fr)) minmax(170px,.7fr);gap:1px;background:#c6c6c6;border:1px solid #c6c6c6;margin-top:10px}.workflow-live-cell{background:#fff;padding:9px 11px;min-width:0}.workflow-live-cell span{display:block;font-size:9px;color:#6f6f6f;text-transform:uppercase;letter-spacing:.04em}.workflow-live-cell b{display:block;margin-top:2px;font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.workflow-live-cell.live b{color:#198038}.workflow-live-cell.offline b{color:#6f6f6f}.workflow-live-runners{display:flex;gap:5px;flex-wrap:wrap;margin-top:7px}.workflow-live-runner{border:1px solid #c6c6c6;padding:3px 6px;font-size:10px;background:#fff}.workflow-live-runner.busy{border-color:#0f62fe;background:#edf5ff}.workflow-live-warning{padding:7px 10px;background:#fff1f1;border-left:4px solid #da1e28;font-size:10px;margin-top:6px}
#workbench-runners{gap:12px;overflow:auto}.runner-dashboard-head{display:flex;align-items:flex-end;justify-content:space-between;gap:20px}.runner-dashboard-head h1{margin:2px 0 4px;font-size:27px}.runner-dashboard-head p{margin:0;color:#525252;max-width:780px}.runner-dashboard-actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.runner-dashboard-stats{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:1px;background:#c6c6c6;border:1px solid #c6c6c6}.runner-stat{background:#fff;padding:11px 13px}.runner-stat b{display:block;font-size:22px;font-weight:400}.runner-stat span{display:block;color:#525252;font-size:10px;text-transform:uppercase}.runner-dashboard-toolbar{display:grid;grid-template-columns:minmax(0,1fr) 190px;gap:8px}.runner-dashboard-toolbar input,.runner-dashboard-toolbar select{background:#fff!important;color:#161616!important;border:1px solid #8d8d8d!important}.runner-dashboard-notice{padding:10px 12px;border-left:4px solid #0f62fe;background:#edf5ff;color:#393939}.runner-dashboard-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(330px,1fr));gap:10px}.runner-card{border:1px solid #c6c6c6;background:#fff;min-width:0}.runner-card.busy{border-color:#0f62fe;box-shadow:inset 4px 0 #0f62fe}.runner-card.offline{border-color:#8d8d8d}.runner-card-head{display:flex;justify-content:space-between;gap:10px;padding:13px 14px;border-bottom:1px solid #e0e0e0}.runner-card-head h2{margin:2px 0 0;font-size:17px;overflow-wrap:anywhere}.runner-card-badges{display:flex;gap:5px;align-items:flex-start;flex-wrap:wrap;justify-content:flex-end}.runner-state-badge{font-size:9px;border:1px solid #8d8d8d;padding:2px 5px;text-transform:uppercase}.runner-state-badge.online{border-color:#24a148;color:#198038}.runner-state-badge.offline{border-color:#da1e28;color:#a2191f}.runner-state-badge.observed{border-color:#8d8d8d;color:#525252}.runner-state-badge.busy{border-color:#0f62fe;color:#0043ce;background:#edf5ff}.runner-infra{padding:11px 14px;border-bottom:1px solid #e0e0e0}.runner-section-label{font-size:9px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:#525252;margin-bottom:7px}.runner-facts{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.runner-fact span{display:block;font-size:9px;color:#6f6f6f;text-transform:uppercase}.runner-fact b{display:block;font-size:11px;overflow-wrap:anywhere}.runner-labels{display:flex;gap:4px;flex-wrap:wrap;margin-top:8px}.runner-label{font-size:9px;padding:2px 5px;background:#f4f4f4;border:1px solid #e0e0e0}.runner-workers{padding:11px 14px}.runner-worker{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px;padding:9px 0;border-top:1px solid #e0e0e0}.runner-worker:first-of-type{border-top:0}.runner-worker-role{font-weight:600}.runner-worker-meta{font-size:10px;color:#525252;margin-top:2px}.runner-worker-step{font-size:10px;margin-top:4px}.runner-worker button{align-self:center;white-space:nowrap}.runner-no-worker{font-size:11px;color:#6f6f6f;padding:5px 0}.runner-boundary{font-size:10px;color:#525252;margin-top:8px;padding:8px;background:#f4f4f4}
.live-activity-panel{margin:12px 0;border-top:3px solid #0f62fe}.live-activity-panel .panelhead{align-items:flex-start}.live-activity-summary{display:flex;gap:6px;flex-wrap:wrap}.live-activity-summary .pill{font-size:9px}.live-current-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:8px;padding:0 14px 12px}.live-current-card{border:1px solid #c6c6c6;background:#fff;padding:11px;min-width:0}.live-current-card.structured{box-shadow:inset 4px 0 #24a148}.live-current-card.inferred{box-shadow:inset 4px 0 #8d8d8d}.live-current-card h3{margin:2px 0 5px;font-size:15px;overflow-wrap:anywhere}.live-current-meta{font-size:10px;color:#525252;line-height:1.45}.live-current-state{font-size:10px;font-weight:700;text-transform:uppercase}.live-current-subject{margin-top:7px;font-size:11px}.live-current-progress{margin-top:7px;font-size:10px}.live-current-progress-bar{height:4px;background:#e0e0e0;margin-top:4px;overflow:hidden}.live-current-progress-bar span{display:block;height:100%;background:#0f62fe}.live-current-actions{margin-top:8px}.live-timeline{padding:0 14px 12px}.live-event{border-top:1px solid #e0e0e0;padding:8px 0}.live-event:first-child{border-top:0}.live-event summary{cursor:pointer;display:grid;grid-template-columns:150px minmax(0,1fr) auto;gap:9px;align-items:center}.live-event-time{font-family:Consolas,monospace;font-size:10px;color:#525252}.live-event-name{font-weight:600;overflow-wrap:anywhere}.live-event-context{font-size:10px;color:#525252}.live-event pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:260px;overflow:auto;background:#161616;color:#f4f4f4;padding:9px;font-size:10px}.workflow-live-events{margin-top:8px;border:1px solid #c6c6c6;background:#fff}.workflow-live-events>summary{padding:8px 10px;font-weight:600;cursor:pointer}.workflow-live-events-body{padding:0 10px 8px}.live-activity-empty{padding:12px 14px;color:#6f6f6f}.live-latest-strip{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:1px;background:#e0e0e0;margin:0 14px 12px}.live-latest-item{background:#f4f4f4;padding:8px}.live-latest-item span{display:block;font-size:9px;text-transform:uppercase;color:#6f6f6f}.live-latest-item b{display:block;margin-top:2px;font-size:11px;overflow-wrap:anywhere}@media(max-width:1100px){.runner-dashboard-stats{grid-template-columns:repeat(3,1fr)}.live-event summary{grid-template-columns:110px minmax(0,1fr)}}@media(max-width:1000px){.workflow-live-strip{grid-template-columns:repeat(3,minmax(0,1fr))}}@media(max-width:650px){.workflow-live-strip{grid-template-columns:1fr 1fr}.live-latest-strip{grid-template-columns:1fr}.live-event summary{grid-template-columns:1fr}.runner-dashboard-head{align-items:flex-start;flex-direction:column}.runner-dashboard-stats{grid-template-columns:1fr 1fr}.runner-dashboard-toolbar{grid-template-columns:1fr}.runner-dashboard-grid{grid-template-columns:1fr}}
'''

_LIVE_JS = r'''
setTimeout(function(){
 if(window.__deltascopeLiveOperationsInstalled)return;window.__deltascopeLiveOperationsInstalled=true;
 var style=document.createElement('style');style.textContent=__LIVE_CSS__;document.head.appendChild(style);
 var operate=(perspectiveConfig.operations?.groups||[]).find(group=>group.label==='Operate');if(operate&&!operate.items.some(item=>item.view==='runners')){var workflowIndex=operate.items.findIndex(item=>item.view==='workflows');operate.items.splice(workflowIndex>=0?workflowIndex+1:2,0,{label:'Runners',mark:'R',view:'runners'})}contextualDocumentationFallback.runners={doc:'github-workflows',label:'Runner dashboard docs'};if(currentPerspective==='operations')renderPerspectiveNav();
 var timer=0,inFlight=false,last=null,lastRunner=null,lastActivity=null,runnerSearch='',runnerState='';
 function liveHost(){var view=document.getElementById('workbench-workflows');if(!view)return null;var host=document.getElementById('workflowLiveOperations');if(host)return host;host=document.createElement('div');host.id='workflowLiveOperations';var head=view.querySelector('.workflow-center-head');if(head)head.insertAdjacentElement('afterend',host);return host}
 function capText(cap){if(!cap)return'unknown';if(cap.available===true)return'yes';if(cap.available===false)return'no';return'not observed'}
 function renderLive(r){last=r;var host=liveHost();if(!host)return;var c=r.counts||{},rate=r.rateLimit||{},caps=r.capabilities||{},remaining=rate.limit?`${fmt(rate.remaining||0)} / ${fmt(rate.limit||0)}`:'not reported',mode=r.live?'LIVE':r.authenticated?'WAITING':'NOT CONNECTED';host.innerHTML=`<div class=workflow-live-strip><div class="workflow-live-cell ${r.live?'live':'offline'}"><span>GitHub telemetry</span><b>${esc(mode)}</b></div><div class=workflow-live-cell><span>Active runs</span><b>${fmt(c.activeRuns||0)}</b></div><div class=workflow-live-cell><span>Jobs / telemetry</span><b>${fmt(c.jobs||0)} · ${fmt(c.telemetryEvents||0)} events</b></div><div class=workflow-live-cell><span>Runners</span><b>${fmt(c.runners||0)} · ${fmt(c.busyRunners||0)} busy</b></div><div class=workflow-live-cell><span>Rate remaining</span><b>${esc(remaining)}</b></div><div class=workflow-live-cell><span>Capabilities</span><b>jobs ${esc(capText(caps.jobsRead))} · runners ${esc(capText(caps.runnerInventoryRead))}</b></div></div>${(r.runners||[]).length?`<div class=workflow-live-runners>${r.runners.slice(0,12).map(x=>`<span class="workflow-live-runner ${x.busy?'busy':''}" title="${esc((x.activeJobs||[]).map(j=>`${j.workflow} · ${j.name}`).join(' | '))}">${esc(x.runnerName||`runner ${x.runnerId||'?'}`)} · ${x.busy?'BUSY':esc(x.status||'observed')}</span>`).join('')}</div>`:''}${r.error?`<div class=workflow-live-warning>${esc(r.error)}</div>`:''}`;var snap=document.getElementById('workflowCenterSnapshot');if(snap&&r.live)snap.textContent=`Live · ${esc(r.fetchedAtUtc||'')}`}
 function infraState(r){var i=r.infrastructure||{};if(i.onlineObserved===true)return'online';if(i.onlineObserved===false)return'offline';return'observed'}
 function runnerRows(){var q=runnerSearch.toLowerCase();return (lastRunner?.runners||[]).filter(r=>{var i=r.infrastructure||{},state=infraState(r),busy=!!i.busy;if(runnerState==='busy'&&!busy)return false;if(runnerState==='idle'&&busy)return false;if(['online','offline','observed'].includes(runnerState)&&state!==runnerState)return false;if(!q)return true;var text=[r.runnerName,i.os,i.version,(i.labels||[]).join(' '),(i.groups||[]).join(' '),(r.workers||[]).map(w=>`${w.workflow} ${w.name} ${w.workerRole?.label||''} ${w.workerRole?.state||''} ${w.currentStep?.name||''}`).join(' ')].join(' ').toLowerCase();return text.includes(q)})}
 function renderRunnerStats(){var host=$('runnerDashboardStats'),c=lastRunner?.counts||{};if(!host)return;host.innerHTML=`<div class=runner-stat><b>${fmt(c.runners||0)}</b><span>runners</span></div><div class=runner-stat><b>${fmt(c.online||0)}</b><span>online</span></div><div class=runner-stat><b>${fmt(c.offline||0)}</b><span>offline</span></div><div class=runner-stat><b>${fmt(c.observedOnly||0)}</b><span>job-observed</span></div><div class=runner-stat><b>${fmt(c.busy||0)}</b><span>busy</span></div><div class=runner-stat><b>${fmt(c.workers||0)}</b><span>Omega workers</span></div>`}
 function workerHtml(w){var role=w.workerRole||{},step=w.currentStep||{},tele=w.latestTelemetry||role.telemetryEvent||{},subject=tele.subject||{},queue=tele.queue||{},progress=tele.progress||{},label=role.label||w.component||'Workflow worker',state=role.state||w.state||'unknown',source=role.inferred===false?'TELEMETRY':'INFERRED',subjectText=subject.internalName?`${subject.internalName}${subject.version?` · ${subject.version}`:''}${subject.workType?` · ${subject.workType}`:''}`:'',progressText=progress.total?`${fmt(progress.current||0)} / ${fmt(progress.total)} ${esc(progress.unit||'')}`:queue.remaining!==undefined?`${fmt(queue.remaining)} queue remaining`:'';return `<div class=runner-worker><div><div class=runner-worker-role>${esc(label)} · ${esc(String(state).toUpperCase())} <span class=runner-label>${source}</span></div><div class=runner-worker-meta>${esc(w.workflow||'workflow')} · run #${fmt(w.runNumber||0)} · ${esc(w.name||'job')}</div>${tele.event?`<div class=runner-worker-step><b>${esc(tele.event)}</b>${tele.stage?` · ${esc(tele.stage)}`:''}</div>`:step.name?`<div class=runner-worker-step><b>Stage:</b> ${esc(step.name)} · ${esc(step.status||step.conclusion||'')}</div>`:''}${subjectText?`<div class=runner-worker-step><b>Subject:</b> ${esc(subjectText)}</div>`:''}${progressText?`<div class=runner-worker-step><b>Progress:</b> ${progressText}</div>`:''}<div class="muted tiny">${esc(role.note||'Worker role inferred from GitHub job metadata.')}</div></div><button data-runner-open-job="${String(w.runId||0)}" data-runner-workflow="${esc(w.workflow||'')}" data-runner-workflow-path="${esc(w.workflowPath||'')}">Open run</button></div>`}
 function runnerCard(r){var i=r.infrastructure||{},state=infraState(r),workers=r.workers||[],groups=(i.groups||[]).join(', ')||'—',version=i.version||'not reported',os=i.os||'not reported';return `<article class="runner-card ${i.busy?'busy':''} ${state==='offline'?'offline':''}"><div class=runner-card-head><div><div class=eyebrow>GITHUB RUNNER</div><h2>${esc(r.runnerName||`Runner ${r.runnerId||'?'}`)}</h2></div><div class=runner-card-badges><span class="runner-state-badge ${state}">${esc(state)}</span><span class="runner-state-badge ${i.busy?'busy':''}">${i.busy?'busy':'idle'}</span></div></div><div class=runner-infra><div class=runner-section-label>Infrastructure state</div><div class=runner-facts><div class=runner-fact><span>OS</span><b>${esc(os)}</b></div><div class=runner-fact><span>Version</span><b>${esc(version)}</b></div><div class=runner-fact><span>Runner group</span><b>${esc(groups)}</b></div><div class=runner-fact><span>State source</span><b>${esc(i.source||'unknown')}</b></div></div>${(i.labels||[]).length?`<div class=runner-labels>${i.labels.map(x=>`<span class=runner-label>${esc(x)}</span>`).join('')}</div>`:''}<div class=runner-boundary>${i.inventoryBacked?'ONLINE/OFFLINE comes from GitHub runner inventory.':'This runner was observed through an active job. DeltaScope intentionally does not infer ONLINE/OFFLINE from the worker job.'}</div></div><div class=runner-workers><div class=runner-section-label>Omega worker activity</div>${workers.length?workers.map(workerHtml).join(''):'<div class=runner-no-worker>No Omega worker is currently correlated with this runner.</div>'}</div></article>`}
 function renderRunnerDashboard(r){lastRunner=r;renderRunnerStats();var notice=$('runnerDashboardNotice'),grid=$('runnerDashboardGrid'),snap=$('runnerDashboardSnapshot');if(notice)notice.textContent=r.message||'';if(snap)snap.textContent=r.fetchedAtUtc?`${r.live?'Live':'Snapshot'} · ${r.fetchedAtUtc}`:'Live snapshot not loaded';if(!grid)return;var rows=runnerRows();grid.innerHTML=rows.map(runnerCard).join('')||'<div class=workspace-empty>No runners match the current filter.</div>';grid.querySelectorAll('[data-runner-open-job]').forEach(button=>button.addEventListener('click',()=>openWorkflowRun({runId:Number(button.dataset.runnerOpenJob||0),workflow:button.dataset.runnerWorkflow||'',workflowPath:button.dataset.runnerWorkflowPath||''})))}
 async function openWorkflowRun(job){var item=(perspectiveConfig.operations?.groups||[]).flatMap(group=>group.items||[]).find(candidate=>candidate.view==='workflows');if(item&&typeof navigatePerspective==='function')navigatePerspective(item);else if(typeof setWorkbenchView==='function')setWorkbenchView('workflows');var wantedPath=String(job.workflowPath||'').replace(/\\/g,'/').split('/').pop().toLowerCase(),wantedName=String(job.workflow||'').toLowerCase();for(var tries=0;tries<24;tries++){await new Promise(resolve=>setTimeout(resolve,100));var buttons=[...document.querySelectorAll('#workflowCenterList [data-workflow-id]')],match=buttons.find(b=>{var path=String(b.querySelector('.workflow-list-path')?.textContent||'').toLowerCase(),name=String(b.querySelector('.workflow-list-name')?.textContent||'').toLowerCase();return(wantedPath&&path===wantedPath)||(wantedName&&name===wantedName)});if(match){match.click();break}}for(var tries=0;tries<24;tries++){await new Promise(resolve=>setTimeout(resolve,100));var run=document.querySelector(`#workflowCenterRunList [data-wc-run="${String(job.runId||0)}"]`);if(run){run.click();return}}}
 function activitySubjectText(row){var s=row.subject||{},fallback=s.fallback||row.jobName||row.workflow||'active work';return s.internalName?`${s.internalName}${s.version?` · ${s.version}`:''}${s.workType?` · ${s.workType}`:''}`:fallback}
 function activityProgress(row){var p=row.progress||{},q=row.queue||{};if(Number(p.total||0)>0){var current=Number(p.current||0),total=Number(p.total||0),pct=Math.max(0,Math.min(100,Number(p.percent??(current*100/total))));return {text:`${fmt(current)} / ${fmt(total)} ${p.unit||''}`.trim(),percent:pct}}if(q.remaining!==undefined&&q.remaining!==null)return{text:`${fmt(q.remaining)} queue remaining`,percent:null};return{text:'',percent:null}}
 function activityPanel(){var operations=$('operationsDashboard');if(!operations)return null;var host=$('liveOperationsActivity');if(host)return host;host=document.createElement('section');host.id='liveOperationsActivity';host.className='panel live-activity-panel';var grid=operations.querySelector('.dashboard-grid');if(grid)grid.insertAdjacentElement('beforebegin',host);else operations.appendChild(host);return host}
 function workflowEventsHost(){var liveHostNode=$('workflowLiveOperations');if(!liveHostNode)return null;var host=$('workflowLiveEvents');if(host)return host;host=document.createElement('details');host.id='workflowLiveEvents';host.className='workflow-live-events';host.innerHTML='<summary>Live Omega event timeline</summary><div class=workflow-live-events-body></div>';liveHostNode.insertAdjacentElement('afterend',host);return host}
 function activityEventHtml(e,compact){var subject=e.subject||{},subjectText=subject.internalName?`${subject.internalName}${subject.version?` · ${subject.version}`:''}`:'',queue=e.queue||{},progress=e.progress||{},context=[e.runnerName,e.jobName,subjectText,queue.remaining!==undefined?`${fmt(queue.remaining)} remaining`:'',progress.total?`${fmt(progress.current||0)}/${fmt(progress.total)} ${progress.unit||''}`:''].filter(Boolean).join(' · ');return `<details class=live-event><summary><span class=live-event-time>${esc(e.emittedAtUtc||'')}</span><span><span class=live-event-name>${esc(e.event||'event')}${e.stage?` · ${esc(e.stage)}`:''}</span>${context?`<span class=live-event-context>${esc(context)}</span>`:''}</span>${e.runId?`<button type=button data-live-open-run="${Number(e.runId||0)}" data-live-workflow="${esc(e.workflow||'')}" data-live-workflow-path="${esc(e.workflowPath||'')}">Open run & logs</button>`:''}</summary>${compact?'':`<pre>${esc(JSON.stringify(e,null,2))}</pre>`}</details>`}
 function wireLiveRunLinks(host){host?.querySelectorAll?.('[data-live-open-run]').forEach(button=>button.addEventListener('click',event=>{event.preventDefault();event.stopPropagation();openWorkflowRun({runId:Number(button.dataset.liveOpenRun||0),workflow:button.dataset.liveWorkflow||'',workflowPath:button.dataset.liveWorkflowPath||''})}))}
 function currentWorkHtml(row){var role=row.workerRole||{},progress=activityProgress(row),subject=activitySubjectText(row),source=row.telemetrySource==='structured'?'TELEMETRY':row.telemetrySource==='inferred'?'INFERRED':'ACTIONS',state=row.state||row.stage||'running';return `<article class="live-current-card ${row.telemetrySource==='structured'?'structured':'inferred'}"><div class=eyebrow>${esc(source)} · ${esc(row.runnerName||'runner pending')}</div><h3>${esc(subject)}</h3><div class=live-current-state>${esc(state)}</div><div class=live-current-meta>${esc(role.label||row.workflow||'workflow')} · run #${fmt(row.runNumber||0)}${row.jobName?` · ${esc(row.jobName)}`:''}</div>${row.event?`<div class=live-current-subject><b>${esc(row.event)}</b>${row.stage?` · ${esc(row.stage)}`:''}</div>`:''}${progress.text?`<div class=live-current-progress>${esc(progress.text)}${progress.percent!==null?`<div class=live-current-progress-bar><span style="width:${Math.max(0,Math.min(100,progress.percent))}%"></span></div>`:''}</div>`:''}<div class=live-current-actions>${row.runId?`<button type=button data-live-open-run="${Number(row.runId||0)}" data-live-workflow="${esc(row.workflow||'')}" data-live-workflow-path="${esc(row.workflowPath||'')}">Open run & logs</button>`:''}</div></article>`}
 function latestItem(label,e){if(!e||!e.event)return `<div class=live-latest-item><span>${esc(label)}</span><b>no structured event yet</b></div>`;var subject=e.subject||{},detail=subject.internalName||e.stage||e.message||e.event;return `<div class=live-latest-item><span>${esc(label)}</span><b>${esc(detail)}</b><div class="muted tiny">${esc(e.event||'')}</div></div>`}
 function renderActivity(a){lastActivity=a;var panel=activityPanel(),current=a.currentWork||[],timeline=a.timeline||[],latest=a.latest||{},c=a.counts||{};if(panel){panel.innerHTML=`<div class=panelhead><div><h2>Live Omega activity</h2><div class="muted small">Actions, workers, queue subjects and publication progress from the authenticated live snapshot. Structured events win over inferred job-stage labels.</div></div><div class=live-activity-summary><span class=pill>${fmt(c.currentWork||0)} current</span><span class=pill>${fmt(c.telemetryEvents||0)} events</span><span class=pill>${fmt(c.busyRunners||0)} busy runners</span></div></div><div class=live-latest-strip>${latestItem('Queue',latest.queue)}${latestItem('Scan / analysis',latest.scan)}${latestItem('Publication',latest.publication)}</div>${current.length?`<div class=live-current-grid>${current.map(currentWorkHtml).join('')}</div>`:'<div class=live-activity-empty>No active Actions work is currently visible to this credential.</div>'}<div class=panelhead><div><h3>Recent structured events</h3><div class="muted small">Expand an event for its sanitized payload; open the run for the existing Workflow Center log drill-down.</div></div><span class="muted small">${esc(a.fetchedAtUtc||'')}</span></div><div class=live-timeline>${timeline.length?timeline.slice(0,16).map(e=>activityEventHtml(e,false)).join(''):'<div class=live-activity-empty>No omega.actions.telemetry.v1 events are visible yet.</div>'}</div>`;wireLiveRunLinks(panel)}
 var workflowHost=workflowEventsHost();if(workflowHost){var body=workflowHost.querySelector('.workflow-live-events-body');if(body)body.innerHTML=timeline.length?timeline.slice(0,8).map(e=>activityEventHtml(e,true)).join(''):'<div class=live-activity-empty>No structured events are visible yet.</div>';wireLiveRunLinks(workflowHost)}}
 function relevantForeground(){var view=String(window.currentWorkbenchView||currentWorkbenchView||'');return document.visibilityState==='visible'&&['workflows','runners','dashboard','ops-evidence','ops-gates'].includes(view)}
 function schedule(seconds){clearTimeout(timer);timer=setTimeout(()=>poll(false),Math.max(5000,Number(seconds||60)*1000))}
 async function poll(force){if(inFlight){schedule(5);return}inFlight=true;try{var foreground=relevantForeground(),view=String(window.currentWorkbenchView||currentWorkbenchView||''),r=await api(`/api/operations/live?foreground=${foreground?'1':'0'}${force?'&force=1':''}`),next=r.nextPollSeconds||60;renderLive(r);if(view==='runners'){var rd=await api(`/api/operations/runners?foreground=${foreground?'1':'0'}`);renderRunnerDashboard(rd);next=rd.nextPollSeconds||next}if(view==='dashboard'||view==='workflows'){var activity=await api(`/api/operations/activity?foreground=${foreground?'1':'0'}`);renderActivity(activity);next=activity.nextPollSeconds||next}schedule(next)}catch(e){var host=liveHost();if(host)host.innerHTML=`<div class=workflow-live-warning>Live GitHub telemetry unavailable: ${esc(e.message)}</div>`;var grid=$('runnerDashboardGrid');if(grid&&String(window.currentWorkbenchView||currentWorkbenchView||'')==='runners')grid.innerHTML=`<div class=workflow-live-warning>Runner dashboard unavailable: ${esc(e.message)}</div>`;var activityHost=$('liveOperationsActivity');if(activityHost)activityHost.innerHTML=`<div class=workflow-live-warning>Live Omega activity unavailable: ${esc(e.message)}</div>`;schedule(60)}finally{inFlight=false}}
 document.addEventListener('visibilitychange',()=>{if(last?.authenticated)poll(false)});var refresh=document.getElementById('workflowCenterRefresh');refresh?.addEventListener('click',()=>setTimeout(()=>poll(true),400));$('runnerDashboardRefresh')?.addEventListener('click',()=>poll(true));$('runnerDashboardSearch')?.addEventListener('input',event=>{runnerSearch=String(event.target.value||'');if(lastRunner)renderRunnerDashboard(lastRunner)});$('runnerDashboardState')?.addEventListener('change',event=>{runnerState=String(event.target.value||'');if(lastRunner)renderRunnerDashboard(lastRunner)});var setWorkbenchViewBaseLive=setWorkbenchView;setWorkbenchView=function(name){setWorkbenchViewBaseLive(name);if(['runners','dashboard','workflows'].includes(name))poll(false)};poll(false);
},0);
'''


def _patch_html(html: str) -> str:
    text = str(html)
    if 'id="workbench-runners"' not in text:
        marker = "</main>"
        index = text.rfind(marker)
        if index >= 0:
            text = text[:index] + _RUNNER_VIEW + text[index:]
    if "__deltascopeLiveOperationsInstalled" in text:
        return text
    script = _LIVE_JS.replace("__LIVE_CSS__", json.dumps(_LIVE_CSS))
    marker = "</script>"
    index = text.rfind(marker)
    if index < 0:
        raise RuntimeError("DeltaScope HTML script boundary was not found")
    return text[:index] + "\n" + script + "\n" + text[index:]


def install() -> None:
    """Install live acquisition after the existing Workflow Center routes/UI."""
    import developer_view

    if getattr(developer_view, "_deltascope_live_operations_installed", False):
        return
    _install_client_extensions(deltascope_operations.GitHubOperationsClient)
    developer_view.HTML = _patch_html(developer_view.HTML)
    original_get = developer_view.AppHandler.do_GET

    def patched_get(self: Any) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path not in {"/api/operations/live", "/api/operations/runners", "/api/operations/telemetry", "/api/operations/activity"}:
            return original_get(self)
        try:
            client = getattr(self, "operations_client", None)
            if client is None:
                return self.json_response({
                    "schema": RUNNER_DASHBOARD_SCHEMA if parsed.path.endswith("/runners") else TELEMETRY_VIEW_SCHEMA if parsed.path.endswith("/telemetry") else LIVE_ACTIVITY_SCHEMA if parsed.path.endswith("/activity") else LIVE_SCHEMA,
                    "available": False,
                    "live": False,
                    "authenticated": False,
                    "readOnly": True,
                    "mutationAuthority": "none",
                    "error": "GitHub operations are disabled",
                })
            query = urllib.parse.parse_qs(parsed.query)
            foreground = str((query.get("foreground") or ["1"])[0]).casefold() not in {"0", "false", "no"}
            force = str((query.get("force") or ["0"])[0]).casefold() in {"1", "true", "yes"}
            if parsed.path.endswith("/runners"):
                return self.json_response(client.runner_dashboard(foreground=foreground, force=force))
            if parsed.path.endswith("/telemetry"):
                return self.json_response(client.actions_telemetry(foreground=foreground, force=force))
            if parsed.path.endswith("/activity"):
                return self.json_response(client.live_activity(foreground=foreground, force=force))
            return self.json_response(client.live_status(foreground=foreground, force=force))
        except Exception as exc:
            return self.json_response({"error": str(exc)}, 500)

    developer_view.AppHandler.do_GET = patched_get
    developer_view._deltascope_live_operations_installed = True
