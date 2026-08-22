#!/usr/bin/env python3
"""Bounded, read-only operational status projection for DeltaScope.

The module reads public GitHub Actions metadata only. It never starts, cancels, retries,
or mutates workflows. A short in-memory cache keeps the dashboard useful without turning
DeltaScope into a GitHub polling service.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Mapping

SCHEMA = "omega.deltascope.operations.v1"
DEFAULT_REPOSITORY = "dalagab/omega"
DEFAULT_TTL_SECONDS = 60
MAX_RUNS = 50
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
RUNNING_STATES = {"queued", "in_progress", "requested", "waiting", "pending"}
FAIL_CONCLUSIONS = {"failure", "timed_out", "action_required", "startup_failure"}
WARN_CONCLUSIONS = {"cancelled", "neutral", "stale"}
EXPECTED_COMPONENTS: tuple[tuple[str, str], ...] = (
    ("sigmascope", "SigmaScope"),
    ("omega-builds", "Omega builds"),
    ("catalog-definitions", "Catalog / Definitions"),
    ("deltascope", "DeltaScope"),
    ("stigma-1", "Stigma-1"),
    ("deep-scan", "Deep Scan"),
    ("security-regression", "Security regression"),
    ("source-intake", "Source intake"),
)


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _component(path: str, name: str, branch: str) -> tuple[str, str]:
    key = f"{path} {name}".casefold()
    if "sigmascope.yml" in key or "sigmascope continuous" in key:
        return "sigmascope", "SigmaScope"
    if "catalog-builder.yml" in key or "catalog snapshot" in key:
        return "catalog-definitions", "Catalog / Definitions"
    if "deltascope.yml" in key or "deltascope developer" in key:
        return "deltascope", "DeltaScope"
    if "deep-scan.yml" in key or "deep scan" in key:
        return "deep-scan", "Deep Scan"
    if "regression-tests.yml" in key or "security services regression" in key:
        return "security-regression", "Security regression"
    if "srl-cutover" in key or "rule-candidates" in key or "stigma" in key or " srl " in f" {key} ":
        return "stigma-1", "Stigma-1"
    if "source-submissions" in key or "source submissions" in key:
        return "source-intake", "Source intake"
    if "catalog-compaction" in key:
        return "legacy-compactor", "Legacy compactor"
    # The main branch contains client/build workflows that are intentionally not copied
    # into the security branch. Keep them visible rather than dropping unknown workflows.
    if branch == "main" or "omega" in key:
        return "omega-builds", "Omega builds"
    return "other", name or "Other workflow"


def _state(run: Mapping[str, Any]) -> tuple[str, str]:
    status = str(run.get("status") or "").casefold()
    conclusion = str(run.get("conclusion") or "").casefold()
    if status in RUNNING_STATES:
        return "running", status
    if conclusion in FAIL_CONCLUSIONS:
        return "failed", conclusion
    if conclusion in WARN_CONCLUSIONS:
        return "warning", conclusion
    if conclusion == "success":
        return "healthy", conclusion
    if conclusion in {"skipped"}:
        return "idle", conclusion
    return "unknown", conclusion or status or "unknown"


def normalize_run(run: Mapping[str, Any]) -> dict[str, Any]:
    path = str(run.get("path") or "")
    name = str(run.get("name") or "")
    branch = str(run.get("head_branch") or "")
    component_id, component = _component(path, name, branch)
    state, detail = _state(run)
    display = str(run.get("display_title") or name or "Workflow run")
    raw_url = str(run.get("html_url") or "")
    url = raw_url if raw_url.startswith("https://github.com/") else ""
    return {
        "runId": int(run.get("id") or 0),
        "runNumber": int(run.get("run_number") or 0),
        "attempt": int(run.get("run_attempt") or 1),
        "componentId": component_id,
        "component": component,
        "workflow": name,
        "workflowPath": path,
        "title": display,
        "event": str(run.get("event") or ""),
        "branch": branch,
        "sha": str(run.get("head_sha") or ""),
        "status": str(run.get("status") or ""),
        "conclusion": str(run.get("conclusion") or ""),
        "state": state,
        "stateDetail": detail,
        "createdAtUtc": str(run.get("created_at") or ""),
        "updatedAtUtc": str(run.get("updated_at") or ""),
        "url": url,
        "readOnly": True,
    }


def project_runs(repository: str, runs: list[Mapping[str, Any]], *, fetched_at_utc: str = "", source: str = "github-actions-public-api") -> dict[str, Any]:
    normalized = [normalize_run(run) for run in runs[:MAX_RUNS] if isinstance(run, Mapping)]
    normalized.sort(key=lambda row: (row["createdAtUtc"], row["runId"]), reverse=True)

    latest_by_component: dict[str, dict[str, Any]] = {}
    running_by_component: dict[str, list[dict[str, Any]]] = {}
    for run in normalized:
        component_id = str(run["componentId"])
        latest_by_component.setdefault(component_id, run)
        if run["state"] == "running":
            running_by_component.setdefault(component_id, []).append(run)

    components: list[dict[str, Any]] = []
    expected = dict(EXPECTED_COMPONENTS)
    component_ids = list(expected) + [key for key in latest_by_component if key not in expected]
    for component_id in component_ids:
        latest = latest_by_component.get(component_id)
        running = running_by_component.get(component_id) or []
        effective = running[0] if running else latest
        components.append({
            "componentId": component_id,
            "component": str((effective or {}).get("component") or (latest or {}).get("component") or expected.get(component_id) or component_id),
            "state": "running" if running else str((latest or {}).get("state") or "unknown"),
            "stateDetail": str((effective or {}).get("stateDetail") or ("not observed in recent Actions history" if latest is None else "")),
            "runningCount": len(running),
            "latestRun": latest,
            "activeRun": effective if running else None,
            "observed": latest is not None,
            "readOnly": True,
        })
    order = {"sigmascope": 0, "omega-builds": 1, "catalog-definitions": 2, "deltascope": 3, "stigma-1": 4, "deep-scan": 5, "security-regression": 6, "source-intake": 7, "legacy-compactor": 8, "other": 9}
    components.sort(key=lambda row: (order.get(str(row.get("componentId")), 50), str(row.get("component") or "").casefold()))

    return {
        "schema": SCHEMA,
        "available": True,
        "readOnly": True,
        "mutationAuthority": "none",
        "source": source,
        "repository": repository,
        "fetchedAtUtc": fetched_at_utc or _utc_now(),
        "actionsRunning": sum(1 for run in normalized if run["state"] == "running"),
        "recentFailureCount": sum(1 for run in normalized[:20] if run["state"] == "failed"),
        "components": components,
        "events": normalized,
    }


class GitHubOperationsClient:
    """Small fail-soft GitHub Actions reader with a process-local TTL cache."""

    def __init__(
        self,
        repository: str = DEFAULT_REPOSITORY,
        *,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        token: str | None = None,
        opener: Callable[..., Any] | None = None,
    ) -> None:
        repository = str(repository or DEFAULT_REPOSITORY).strip()
        if not repository or repository.count("/") != 1 or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_." for ch in repository.replace("/", "")):
            raise ValueError("GitHub repository must use owner/name syntax")
        self.repository = repository
        self.ttl_seconds = max(10, min(900, int(ttl_seconds or DEFAULT_TTL_SECONDS)))
        self.token = token if token is not None else (os.environ.get("OMEGA_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or "")
        self._opener = opener or urllib.request.urlopen
        self._lock = threading.RLock()
        self._cached_at = 0.0
        self._cache: dict[str, Any] | None = None

    def _request_runs(self) -> list[Mapping[str, Any]]:
        url = f"https://api.github.com/repos/{urllib.parse.quote(self.repository, safe='/')}/actions/runs?per_page={MAX_RUNS}"
        headers = {
            "User-Agent": "Omega-DeltaScope/4.6",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(url, headers=headers)
        with self._opener(request, timeout=6) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise RuntimeError("GitHub Actions response exceeded the DeltaScope safety bound")
        payload = json.loads(raw.decode("utf-8"))
        if not isinstance(payload, Mapping):
            raise RuntimeError("GitHub Actions response was not an object")
        runs = payload.get("workflow_runs")
        if not isinstance(runs, list):
            raise RuntimeError("GitHub Actions response has no workflow_runs list")
        return [run for run in runs if isinstance(run, Mapping)]

    def status(self, *, refresh: bool = False) -> dict[str, Any]:
        now = time.monotonic()
        with self._lock:
            if not refresh and self._cache is not None and now - self._cached_at < self.ttl_seconds:
                return dict(self._cache)
        try:
            payload = project_runs(self.repository, self._request_runs())
        except (OSError, ValueError, RuntimeError, urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as exc:
            payload = {
                "schema": SCHEMA,
                "available": False,
                "readOnly": True,
                "mutationAuthority": "none",
                "source": "github-actions-public-api",
                "repository": self.repository,
                "fetchedAtUtc": _utc_now(),
                "actionsRunning": 0,
                "recentFailureCount": 0,
                "components": [],
                "events": [],
                "error": str(exc),
            }
        with self._lock:
            self._cache = dict(payload)
            self._cached_at = now
        return payload
