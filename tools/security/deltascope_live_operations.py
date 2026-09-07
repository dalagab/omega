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

LIVE_SCHEMA = "omega.deltascope.live-operations.v1"
LIVE_CAPABILITY_SCHEMA = "omega.deltascope.github-live-capabilities.v1"
LIVE_RATE_SCHEMA = "omega.deltascope.github-rate-limit.v1"
RUNNER_DASHBOARD_SCHEMA = "omega.deltascope.runner-dashboard.v1"
WORKER_ROLE_SCHEMA = "omega.deltascope.worker-role-observation.v1"

FOREGROUND_POLL_SECONDS = 15
BACKGROUND_POLL_SECONDS = 60
RUNNER_INVENTORY_SECONDS = 60
FORCE_MIN_SECONDS = 5
FAILURE_RETRY_SECONDS = 30
MAX_ACTIVE_RUNS = 6
MAX_LIVE_JOBS = 200
LOW_RATE_REMAINING = 1000
VERY_LOW_RATE_REMAINING = 500


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
            source="on-demand-existing-workflow-center" if authenticated else "not-authenticated",
            detail="Raw job logs remain lazy/on-demand; live mode does not continuously download them.",
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


def _reset_state(client: Any) -> None:
    _ensure_state(client)
    with client._lock:
        client._live_cache = None
        client._live_cached_at = 0.0
        client._live_last_attempt_at = 0.0
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
        elif rate.get("limit") and rate.get("remaining") == 0:
            client._live_backoff_until = max(client._live_backoff_until, now + FAILURE_RETRY_SECONDS)


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
        "semanticBoundary": {"runnerIsInfrastructure":True,"workerIsExecutionRole":True,"workerRoleIsInferredUntilStructuredTelemetry":True,"runnerStatusNeverDerivedFromWorkerRole":True},
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
        "counts": {"activeRuns": 0, "queuedRuns": 0, "jobs": 0, "runners": 0, "busyRunners": 0},
        "activeRuns": [],
        "queuedRuns": [],
        "jobs": [],
        "runners": [],
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
        },
        "activeRuns": active[:20],
        "queuedRuns": queued[:20],
        "jobs": jobs,
        "runners": runners,
        "capabilities": capabilities,
        "rateLimit": rate,
        "access": client.access_status(),
        "warnings": job_errors[:8],
    }


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
        if cached and not force and now - cached_at < desired:
            cached["servedFromCache"] = True
            cached["nextPollSeconds"] = max(1, int(math.ceil(desired - (now - cached_at))))
            return cached
        try:
            result = _acquire_live(client, foreground=foreground)
        except (OSError, ValueError, RuntimeError, urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as exc:
            with client._lock:
                client._live_backoff_until = max(client._live_backoff_until, time.monotonic() + FAILURE_RETRY_SECONDS)
                rate = dict(client._live_rate_limit or {})
            if cached:
                cached["stale"] = True
                cached["servedFromCache"] = True
                cached["error"] = str(exc)
                cached["rateLimit"] = rate
                cached["nextPollSeconds"] = _base_interval(client, foreground)
                return cached
            result = _live_unavailable(client, foreground=foreground, reason=str(exc))
            result["stale"] = False
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
#workbench-runners{gap:12px;overflow:auto}.runner-dashboard-head{display:flex;align-items:flex-end;justify-content:space-between;gap:20px}.runner-dashboard-head h1{margin:2px 0 4px;font-size:27px}.runner-dashboard-head p{margin:0;color:#525252;max-width:780px}.runner-dashboard-actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.runner-dashboard-stats{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:1px;background:#c6c6c6;border:1px solid #c6c6c6}.runner-stat{background:#fff;padding:11px 13px}.runner-stat b{display:block;font-size:22px;font-weight:400}.runner-stat span{display:block;color:#525252;font-size:10px;text-transform:uppercase}.runner-dashboard-toolbar{display:grid;grid-template-columns:minmax(0,1fr) 190px;gap:8px}.runner-dashboard-toolbar input,.runner-dashboard-toolbar select{background:#fff!important;color:#161616!important;border:1px solid #8d8d8d!important}.runner-dashboard-notice{padding:10px 12px;border-left:4px solid #0f62fe;background:#edf5ff;color:#393939}.runner-dashboard-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(330px,1fr));gap:10px}.runner-card{border:1px solid #c6c6c6;background:#fff;min-width:0}.runner-card.busy{border-color:#0f62fe;box-shadow:inset 4px 0 #0f62fe}.runner-card.offline{border-color:#8d8d8d}.runner-card-head{display:flex;justify-content:space-between;gap:10px;padding:13px 14px;border-bottom:1px solid #e0e0e0}.runner-card-head h2{margin:2px 0 0;font-size:17px;overflow-wrap:anywhere}.runner-card-badges{display:flex;gap:5px;align-items:flex-start;flex-wrap:wrap;justify-content:flex-end}.runner-state-badge{font-size:9px;border:1px solid #8d8d8d;padding:2px 5px;text-transform:uppercase}.runner-state-badge.online{border-color:#24a148;color:#198038}.runner-state-badge.offline{border-color:#da1e28;color:#a2191f}.runner-state-badge.observed{border-color:#8d8d8d;color:#525252}.runner-state-badge.busy{border-color:#0f62fe;color:#0043ce;background:#edf5ff}.runner-infra{padding:11px 14px;border-bottom:1px solid #e0e0e0}.runner-section-label{font-size:9px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:#525252;margin-bottom:7px}.runner-facts{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.runner-fact span{display:block;font-size:9px;color:#6f6f6f;text-transform:uppercase}.runner-fact b{display:block;font-size:11px;overflow-wrap:anywhere}.runner-labels{display:flex;gap:4px;flex-wrap:wrap;margin-top:8px}.runner-label{font-size:9px;padding:2px 5px;background:#f4f4f4;border:1px solid #e0e0e0}.runner-workers{padding:11px 14px}.runner-worker{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px;padding:9px 0;border-top:1px solid #e0e0e0}.runner-worker:first-of-type{border-top:0}.runner-worker-role{font-weight:600}.runner-worker-meta{font-size:10px;color:#525252;margin-top:2px}.runner-worker-step{font-size:10px;margin-top:4px}.runner-worker button{align-self:center;white-space:nowrap}.runner-no-worker{font-size:11px;color:#6f6f6f;padding:5px 0}.runner-boundary{font-size:10px;color:#525252;margin-top:8px;padding:8px;background:#f4f4f4}@media(max-width:1100px){.runner-dashboard-stats{grid-template-columns:repeat(3,1fr)}}@media(max-width:1000px){.workflow-live-strip{grid-template-columns:repeat(3,minmax(0,1fr))}}@media(max-width:650px){.workflow-live-strip{grid-template-columns:1fr 1fr}.runner-dashboard-head{align-items:flex-start;flex-direction:column}.runner-dashboard-stats{grid-template-columns:1fr 1fr}.runner-dashboard-toolbar{grid-template-columns:1fr}.runner-dashboard-grid{grid-template-columns:1fr}}
'''

_LIVE_JS = r'''
setTimeout(function(){
 if(window.__deltascopeLiveOperationsInstalled)return;window.__deltascopeLiveOperationsInstalled=true;
 var style=document.createElement('style');style.textContent=__LIVE_CSS__;document.head.appendChild(style);
 var operate=(perspectiveConfig.operations?.groups||[]).find(group=>group.label==='Operate');if(operate&&!operate.items.some(item=>item.view==='runners')){var workflowIndex=operate.items.findIndex(item=>item.view==='workflows');operate.items.splice(workflowIndex>=0?workflowIndex+1:2,0,{label:'Runners',mark:'R',view:'runners'})}contextualDocumentationFallback.runners={doc:'github-workflows',label:'Runner dashboard docs'};if(currentPerspective==='operations')renderPerspectiveNav();
 var timer=0,inFlight=false,last=null,lastRunner=null,runnerSearch='',runnerState='';
 function liveHost(){var view=document.getElementById('workbench-workflows');if(!view)return null;var host=document.getElementById('workflowLiveOperations');if(host)return host;host=document.createElement('div');host.id='workflowLiveOperations';var head=view.querySelector('.workflow-center-head');if(head)head.insertAdjacentElement('afterend',host);return host}
 function capText(cap){if(!cap)return'unknown';if(cap.available===true)return'yes';if(cap.available===false)return'no';return'not observed'}
 function renderLive(r){last=r;var host=liveHost();if(!host)return;var c=r.counts||{},rate=r.rateLimit||{},caps=r.capabilities||{},remaining=rate.limit?`${fmt(rate.remaining||0)} / ${fmt(rate.limit||0)}`:'not reported',mode=r.live?'LIVE':r.authenticated?'WAITING':'NOT CONNECTED';host.innerHTML=`<div class=workflow-live-strip><div class="workflow-live-cell ${r.live?'live':'offline'}"><span>GitHub telemetry</span><b>${esc(mode)}</b></div><div class=workflow-live-cell><span>Active runs</span><b>${fmt(c.activeRuns||0)}</b></div><div class=workflow-live-cell><span>Jobs</span><b>${fmt(c.jobs||0)}</b></div><div class=workflow-live-cell><span>Runners</span><b>${fmt(c.runners||0)} · ${fmt(c.busyRunners||0)} busy</b></div><div class=workflow-live-cell><span>Rate remaining</span><b>${esc(remaining)}</b></div><div class=workflow-live-cell><span>Capabilities</span><b>jobs ${esc(capText(caps.jobsRead))} · runners ${esc(capText(caps.runnerInventoryRead))}</b></div></div>${(r.runners||[]).length?`<div class=workflow-live-runners>${r.runners.slice(0,12).map(x=>`<span class="workflow-live-runner ${x.busy?'busy':''}" title="${esc((x.activeJobs||[]).map(j=>`${j.workflow} · ${j.name}`).join(' | '))}">${esc(x.runnerName||`runner ${x.runnerId||'?'}`)} · ${x.busy?'BUSY':esc(x.status||'observed')}</span>`).join('')}</div>`:''}${r.error?`<div class=workflow-live-warning>${esc(r.error)}</div>`:''}`;var snap=document.getElementById('workflowCenterSnapshot');if(snap&&r.live)snap.textContent=`Live · ${esc(r.fetchedAtUtc||'')}`}
 function infraState(r){var i=r.infrastructure||{};if(i.onlineObserved===true)return'online';if(i.onlineObserved===false)return'offline';return'observed'}
 function runnerRows(){var q=runnerSearch.toLowerCase();return (lastRunner?.runners||[]).filter(r=>{var i=r.infrastructure||{},state=infraState(r),busy=!!i.busy;if(runnerState==='busy'&&!busy)return false;if(runnerState==='idle'&&busy)return false;if(['online','offline','observed'].includes(runnerState)&&state!==runnerState)return false;if(!q)return true;var text=[r.runnerName,i.os,i.version,(i.labels||[]).join(' '),(i.groups||[]).join(' '),(r.workers||[]).map(w=>`${w.workflow} ${w.name} ${w.workerRole?.label||''} ${w.workerRole?.state||''} ${w.currentStep?.name||''}`).join(' ')].join(' ').toLowerCase();return text.includes(q)})}
 function renderRunnerStats(){var host=$('runnerDashboardStats'),c=lastRunner?.counts||{};if(!host)return;host.innerHTML=`<div class=runner-stat><b>${fmt(c.runners||0)}</b><span>runners</span></div><div class=runner-stat><b>${fmt(c.online||0)}</b><span>online</span></div><div class=runner-stat><b>${fmt(c.offline||0)}</b><span>offline</span></div><div class=runner-stat><b>${fmt(c.observedOnly||0)}</b><span>job-observed</span></div><div class=runner-stat><b>${fmt(c.busy||0)}</b><span>busy</span></div><div class=runner-stat><b>${fmt(c.workers||0)}</b><span>Omega workers</span></div>`}
 function workerHtml(w){var role=w.workerRole||{},step=w.currentStep||{},label=role.label||w.component||'Workflow worker',state=role.state||w.state||'unknown';return `<div class=runner-worker><div><div class=runner-worker-role>${esc(label)} · ${esc(String(state).toUpperCase())}</div><div class=runner-worker-meta>${esc(w.workflow||'workflow')} · run #${fmt(w.runNumber||0)} · ${esc(w.name||'job')}</div>${step.name?`<div class=runner-worker-step><b>Stage:</b> ${esc(step.name)} · ${esc(step.status||step.conclusion||'')}</div>`:''}<div class="muted tiny">${esc(role.note||'Worker role inferred from GitHub job metadata.')}</div></div><button data-runner-open-job="${String(w.runId||0)}" data-runner-workflow="${esc(w.workflow||'')}" data-runner-workflow-path="${esc(w.workflowPath||'')}">Open run</button></div>`}
 function runnerCard(r){var i=r.infrastructure||{},state=infraState(r),workers=r.workers||[],groups=(i.groups||[]).join(', ')||'—',version=i.version||'not reported',os=i.os||'not reported';return `<article class="runner-card ${i.busy?'busy':''} ${state==='offline'?'offline':''}"><div class=runner-card-head><div><div class=eyebrow>GITHUB RUNNER</div><h2>${esc(r.runnerName||`Runner ${r.runnerId||'?'}`)}</h2></div><div class=runner-card-badges><span class="runner-state-badge ${state}">${esc(state)}</span><span class="runner-state-badge ${i.busy?'busy':''}">${i.busy?'busy':'idle'}</span></div></div><div class=runner-infra><div class=runner-section-label>Infrastructure state</div><div class=runner-facts><div class=runner-fact><span>OS</span><b>${esc(os)}</b></div><div class=runner-fact><span>Version</span><b>${esc(version)}</b></div><div class=runner-fact><span>Runner group</span><b>${esc(groups)}</b></div><div class=runner-fact><span>State source</span><b>${esc(i.source||'unknown')}</b></div></div>${(i.labels||[]).length?`<div class=runner-labels>${i.labels.map(x=>`<span class=runner-label>${esc(x)}</span>`).join('')}</div>`:''}<div class=runner-boundary>${i.inventoryBacked?'ONLINE/OFFLINE comes from GitHub runner inventory.':'This runner was observed through an active job. DeltaScope intentionally does not infer ONLINE/OFFLINE from the worker job.'}</div></div><div class=runner-workers><div class=runner-section-label>Omega worker activity</div>${workers.length?workers.map(workerHtml).join(''):'<div class=runner-no-worker>No Omega worker is currently correlated with this runner.</div>'}</div></article>`}
 function renderRunnerDashboard(r){lastRunner=r;renderRunnerStats();var notice=$('runnerDashboardNotice'),grid=$('runnerDashboardGrid'),snap=$('runnerDashboardSnapshot');if(notice)notice.textContent=r.message||'';if(snap)snap.textContent=r.fetchedAtUtc?`${r.live?'Live':'Snapshot'} · ${r.fetchedAtUtc}`:'Live snapshot not loaded';if(!grid)return;var rows=runnerRows();grid.innerHTML=rows.map(runnerCard).join('')||'<div class=workspace-empty>No runners match the current filter.</div>';grid.querySelectorAll('[data-runner-open-job]').forEach(button=>button.addEventListener('click',()=>openWorkflowRun({runId:Number(button.dataset.runnerOpenJob||0),workflow:button.dataset.runnerWorkflow||'',workflowPath:button.dataset.runnerWorkflowPath||''})))}
 async function openWorkflowRun(job){var item=(perspectiveConfig.operations?.groups||[]).flatMap(group=>group.items||[]).find(candidate=>candidate.view==='workflows');if(item&&typeof navigatePerspective==='function')navigatePerspective(item);else if(typeof setWorkbenchView==='function')setWorkbenchView('workflows');var wantedPath=String(job.workflowPath||'').replace(/\\/g,'/').split('/').pop().toLowerCase(),wantedName=String(job.workflow||'').toLowerCase();for(var tries=0;tries<24;tries++){await new Promise(resolve=>setTimeout(resolve,100));var buttons=[...document.querySelectorAll('#workflowCenterList [data-workflow-id]')],match=buttons.find(b=>{var path=String(b.querySelector('.workflow-list-path')?.textContent||'').toLowerCase(),name=String(b.querySelector('.workflow-list-name')?.textContent||'').toLowerCase();return(wantedPath&&path===wantedPath)||(wantedName&&name===wantedName)});if(match){match.click();break}}for(var tries=0;tries<24;tries++){await new Promise(resolve=>setTimeout(resolve,100));var run=document.querySelector(`#workflowCenterRunList [data-wc-run="${String(job.runId||0)}"]`);if(run){run.click();return}}}
 function relevantForeground(){var view=String(window.currentWorkbenchView||currentWorkbenchView||'');return document.visibilityState==='visible'&&['workflows','runners','dashboard','ops-evidence','ops-gates'].includes(view)}
 function schedule(seconds){clearTimeout(timer);timer=setTimeout(()=>poll(false),Math.max(5000,Number(seconds||60)*1000))}
 async function poll(force){if(inFlight){schedule(5);return}inFlight=true;try{var foreground=relevantForeground(),r=await api(`/api/operations/live?foreground=${foreground?'1':'0'}${force?'&force=1':''}`);renderLive(r);if(String(window.currentWorkbenchView||currentWorkbenchView||'')==='runners'){var rd=await api(`/api/operations/runners?foreground=${foreground?'1':'0'}`);renderRunnerDashboard(rd);schedule(rd.nextPollSeconds||r.nextPollSeconds||60)}else{schedule(r.nextPollSeconds||60)}}catch(e){var host=liveHost();if(host)host.innerHTML=`<div class=workflow-live-warning>Live GitHub telemetry unavailable: ${esc(e.message)}</div>`;var grid=$('runnerDashboardGrid');if(grid&&String(window.currentWorkbenchView||currentWorkbenchView||'')==='runners')grid.innerHTML=`<div class=workflow-live-warning>Runner dashboard unavailable: ${esc(e.message)}</div>`;schedule(60)}finally{inFlight=false}}
 document.addEventListener('visibilitychange',()=>{if(last?.authenticated)poll(false)});var refresh=document.getElementById('workflowCenterRefresh');refresh?.addEventListener('click',()=>setTimeout(()=>poll(true),400));$('runnerDashboardRefresh')?.addEventListener('click',()=>poll(true));$('runnerDashboardSearch')?.addEventListener('input',event=>{runnerSearch=String(event.target.value||'');if(lastRunner)renderRunnerDashboard(lastRunner)});$('runnerDashboardState')?.addEventListener('change',event=>{runnerState=String(event.target.value||'');if(lastRunner)renderRunnerDashboard(lastRunner)});var setWorkbenchViewBaseLive=setWorkbenchView;setWorkbenchView=function(name){setWorkbenchViewBaseLive(name);if(name==='runners')poll(false)};poll(false);
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
        if parsed.path not in {"/api/operations/live", "/api/operations/runners"}:
            return original_get(self)
        try:
            client = getattr(self, "operations_client", None)
            if client is None:
                return self.json_response({
                    "schema": RUNNER_DASHBOARD_SCHEMA if parsed.path.endswith("/runners") else LIVE_SCHEMA,
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
            return self.json_response(client.live_status(foreground=foreground, force=force))
        except Exception as exc:
            return self.json_response({"error": str(exc)}, 500)

    developer_view.AppHandler.do_GET = patched_get
    developer_view._deltascope_live_operations_installed = True
