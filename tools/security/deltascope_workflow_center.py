#!/usr/bin/env python3
"""DeltaScope GitHub Workflow Center.

This module turns the existing bounded GitHub Actions acquisition client into an
operator-facing control-plane projection.  Page navigation is snapshot-only:
selecting workflows/runs never performs network I/O.  Acquisition and mutations
are explicit actions.

The module deliberately does not become security authority.  It can inspect
GitHub workflow state and, with a locally connected credential plus explicit
confirmation, invoke GitHub Actions controls (dispatch/cancel/rerun).  Those
external actions never modify Evidence-v2, Definitions, Stigma-1 conclusions or
SigmaScope queue state directly.
"""
from __future__ import annotations

import json
import threading
import urllib.parse
from dataclasses import dataclass
from typing import Any, Iterable, Mapping


WORKFLOW_CENTER_SCHEMA = "omega.deltascope.workflow-center.v1"
WORKFLOW_DETAIL_SCHEMA = "omega.deltascope.workflow-detail.v1"
RUN_ACTION_SCHEMA = "omega.deltascope.workflow-run-action.v1"
MAX_CENTER_WORKFLOWS = 150
MAX_DETAIL_HISTORY = 8


@dataclass(frozen=True)
class WorkflowFamily:
    id: str
    label: str
    purpose: str
    operator_question: str
    tokens: tuple[str, ...]


_FAMILIES: tuple[WorkflowFamily, ...] = (
    WorkflowFamily(
        "scanning", "Security scanning",
        "Acquire and analyze plugin/security observations.",
        "What is being scanned, what evidence is being produced, and is a worker blocked?",
        ("sigmascope", "deep-scan", "secondary-security", "authenticode", "native-structure"),
    ),
    WorkflowFamily(
        "orchestration", "Security orchestration",
        "Lease, route, reconcile and publish bounded security work.",
        "Is work moving through the broker/dispatcher/publisher lanes without getting stranded?",
        ("analysis-broker", "analysis-dispatch", "security-orchestration", "security-reconcile", "parallel-publish", "phase4"),
    ),
    WorkflowFamily(
        "catalog", "Catalog & discovery",
        "Discover, scrape, enrich, freeze and publish catalog/Definitions inputs.",
        "Is the input catalog current, complete and frozen consistently for downstream workers?",
        ("catalog-", "discovery", "enrichment", "scrape", "source-head"),
    ),
    WorkflowFamily(
        "intelligence", "Intelligence & intake",
        "Acquire external advisories, threat intelligence and submitted source facts.",
        "Are external inputs fresh and did intake validate before becoming a candidate fact?",
        ("osv", "threat-intelligence", "source-submission", "source-intake"),
    ),
    WorkflowFamily(
        "rules", "Rules & Stigma-1",
        "Validate rule candidates, replay retained observations and guard production cutover.",
        "Are rule changes valid and are interpretation/write-back gates still respected?",
        ("rule-candidate", "srl", "stigma"),
    ),
    WorkflowFamily(
        "verification", "Verification",
        "Run regression, readiness and consistency checks around the security platform.",
        "What failed verification, and is the failure blocking publication or only advisory?",
        ("regression", "readiness", "audit", "test"),
    ),
    WorkflowFamily(
        "rift", "Rift",
        "Move bounded Rift runtime evidence through the published ingestion contract.",
        "Was runtime evidence produced by the expected Rift contract and ingested without crossing authority boundaries?",
        ("rift",),
    ),
)

_FALLBACK_FAMILY = WorkflowFamily(
    "other", "Other workflows",
    "Repository workflow not yet classified by the DeltaScope Operations projection.",
    "What contract does this workflow own and should it be assigned to a known operational family?",
    (),
)


_PURPOSE_HINTS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("sigmascope-parallel-worker",), "Execute one bounded SigmaScope worker assignment."),
    (("sigmascope-parallel-publish",), "Merge and publish parallel SigmaScope worker results behind publication gates."),
    (("sigmascope-parallel-shadow",), "Exercise the parallel SigmaScope path without production publication authority."),
    (("sigmascope",), "Run bounded SigmaScope scanning against frozen catalog/Definitions inputs."),
    (("deep-scan",), "Execute approved bounded deep-analysis requests from the durable deep-scan queue."),
    (("analysis-broker",), "Project analysis demand into durable broker work without performing the analysis itself."),
    (("analysis-dispatcher", "analysis-dispatch"), "Claim and route broker work to a compatible analysis provider."),
    (("catalog-discovery",), "Discover novel ecosystem/source facts without making them catalog authority."),
    (("catalog-builder",), "Build/publish canonical catalog state from validated inputs."),
    (("catalog-freeze",), "Freeze catalog and Definitions identities for deterministic workers."),
    (("source-submissions",), "Validate and persist a submitted public PluginMaster source."),
    (("rift-evidence-ingest",), "Import broker-bound Rift runtime observations into a candidate Evidence-v2 snapshot."),
    (("rule-candidates",), "Validate and review Stigma-1/SRL rule candidates through the normal CI contract."),
    (("security-reconcile",), "Reconcile durable security work and publication state."),
    (("threat-intelligence",), "Acquire/freeze URL, domain and IP threat-intelligence observations."),
    (("osv",), "Acquire/freeze public vulnerability advisory intelligence."),
    (("regression",), "Run platform/security regression checks before relying on changed code or contracts."),
)


def _text(value: Any) -> str:
    return str(value or "").strip()


def _workflow_filename(path: str) -> str:
    return _text(path).replace("\\", "/").rsplit("/", 1)[-1]


def classify_workflow(path: str, name: str) -> WorkflowFamily:
    key = f"{_text(path)} {_text(name)}".casefold()
    for family in _FAMILIES:
        if any(token in key for token in family.tokens):
            return family
    return _FALLBACK_FAMILY


def purpose_for(path: str, name: str, family: WorkflowFamily) -> str:
    key = f"{_text(path)} {_text(name)}".casefold()
    for tokens, purpose in _PURPOSE_HINTS:
        if all(token in key for token in tokens):
            return purpose
    return family.purpose


def _state_rank(state: str) -> int:
    return {"failed": 0, "running": 1, "warning": 2, "unknown": 3, "idle": 4, "healthy": 5}.get(_text(state).casefold(), 6)


def _matching_events(events: Iterable[Mapping[str, Any]], workflow: Mapping[str, Any]) -> list[dict[str, Any]]:
    path = _text(workflow.get("path")).replace("\\", "/").casefold()
    filename = _workflow_filename(path).casefold()
    name = _text(workflow.get("name")).casefold()
    rows: list[dict[str, Any]] = []
    for raw in events:
        event = dict(raw)
        event_path = _text(event.get("workflowPath")).replace("\\", "/").casefold()
        event_file = _workflow_filename(event_path).casefold()
        event_name = _text(event.get("workflow")).casefold()
        if (path and event_path == path) or (filename and event_file == filename) or (name and event_name == name):
            rows.append(event)
    rows.sort(key=lambda row: (_text(row.get("createdAtUtc")), int(row.get("runId") or 0)), reverse=True)
    return rows


def _cached_history(client: Any, workflow_file: str) -> dict[str, Any] | None:
    filename = _workflow_filename(workflow_file)
    best: tuple[float, dict[str, Any]] | None = None
    with getattr(client, "_lock", threading.RLock()):
        cache = dict(getattr(client, "_workflow_cache", {}) or {})
    for key, cached in cache.items():
        if not isinstance(key, tuple) or not key or key[0] != filename:
            continue
        if not isinstance(cached, tuple) or len(cached) != 2 or not isinstance(cached[1], Mapping):
            continue
        payload = dict(cached[1])
        if payload.get("schema") != "omega.deltascope.workflow-history.v1":
            continue
        stamp = float(cached[0] or 0.0)
        if best is None or stamp > best[0]:
            best = (stamp, payload)
    return dict(best[1]) if best else None


def _cached_form(client: Any, workflow_id: int, preferred_ref: str = "") -> dict[str, Any] | None:
    matches: list[tuple[float, dict[str, Any]]] = []
    with getattr(client, "_lock", threading.RLock()):
        cache = dict(getattr(client, "_workflow_cache", {}) or {})
    for key, cached in cache.items():
        if not isinstance(key, tuple) or len(key) < 3 or key[0] != "workflow-form":
            continue
        if int(key[1] or 0) != int(workflow_id):
            continue
        if not isinstance(cached, tuple) or len(cached) != 2 or not isinstance(cached[1], Mapping):
            continue
        payload = dict(cached[1])
        if preferred_ref and _text(payload.get("ref")) == preferred_ref:
            return payload
        matches.append((float(cached[0] or 0.0), payload))
    matches.sort(key=lambda item: item[0], reverse=True)
    return dict(matches[0][1]) if matches else None


def _workflow_row(client: Any, workflow: Mapping[str, Any], events: list[Mapping[str, Any]]) -> dict[str, Any]:
    workflow_id = int(workflow.get("id") or 0)
    path = _text(workflow.get("path"))
    name = _text(workflow.get("name")) or "Workflow"
    family = classify_workflow(path, name)
    related = _matching_events(events, workflow)
    latest = related[0] if related else {}
    active = next((row for row in related if _text(row.get("state")).casefold() == "running"), None)
    failures = [row for row in related[:10] if _text(row.get("state")).casefold() == "failed"]
    preferred_ref = _text((active or latest).get("branch")) or "main"
    history = _cached_history(client, _workflow_filename(path))
    form = _cached_form(client, workflow_id, preferred_ref)
    state = _text((active or latest).get("state")) or "unknown"
    return {
        "workflowId": workflow_id,
        "name": name,
        "path": path,
        "filename": _workflow_filename(path),
        "state": state,
        "stateDetail": _text((active or latest).get("stateDetail")) or ("No run in the acquired global Actions window" if not related else ""),
        "githubState": _text(workflow.get("state")) or "unknown",
        "url": _text(workflow.get("url")),
        "familyId": family.id,
        "family": family.label,
        "purpose": purpose_for(path, name, family),
        "operatorQuestion": family.operator_question,
        "preferredRef": preferred_ref,
        "runningCount": sum(1 for row in related if _text(row.get("state")).casefold() == "running"),
        "recentFailureCount": len(failures),
        "latestRun": dict(latest),
        "activeRun": dict(active) if active else None,
        "recentRuns": [dict(row) for row in related[:8]],
        "detailLoaded": bool(history),
        "detailFetchedAtUtc": _text((history or {}).get("fetchedAtUtc")),
        "dispatchDefinitionLoaded": bool(form),
        "dispatchable": bool((form or {}).get("dispatchable")),
        "dispatchRef": _text((form or {}).get("ref")) or preferred_ref,
        "dispatchInputs": list((form or {}).get("inputs") or []),
    }


def project_workflow_center(client: Any) -> dict[str, Any]:
    """Build the Workflow Center from already-acquired snapshots only."""
    inventory = client.workflows(refresh=False)
    operations = client.status(refresh=False)
    workflows = inventory.get("workflows") if isinstance(inventory.get("workflows"), list) else []
    events = operations.get("events") if isinstance(operations.get("events"), list) else []
    rows = [_workflow_row(client, workflow, events) for workflow in workflows[:MAX_CENTER_WORKFLOWS] if isinstance(workflow, Mapping)]
    rows.sort(key=lambda row: (str(row["family"]).casefold(), _state_rank(str(row["state"])), str(row["name"]).casefold()))
    families: dict[str, dict[str, Any]] = {}
    for row in rows:
        bucket = families.setdefault(row["familyId"], {
            "familyId": row["familyId"], "label": row["family"], "workflowCount": 0,
            "runningCount": 0, "failureCount": 0,
        })
        bucket["workflowCount"] += 1
        bucket["runningCount"] += int(row["runningCount"] or 0)
        bucket["failureCount"] += 1 if row["state"] == "failed" else 0
    access = client.access_status()
    return {
        "schema": WORKFLOW_CENTER_SCHEMA,
        "available": bool(inventory.get("available")),
        "repository": _text(getattr(client, "repository", "")),
        "fetchedAtUtc": _text(inventory.get("fetchedAtUtc")) or _text(operations.get("fetchedAtUtc")),
        "snapshotLoaded": bool(inventory.get("available")) or bool(operations.get("available")),
        "navigationRefresh": False,
        "cachePolicy": "explicit-refresh",
        "workflowCount": len(rows),
        "runningCount": sum(int(row["runningCount"] or 0) for row in rows),
        "recentFailureCount": sum(1 for row in rows if row["state"] == "failed"),
        "detailLoadedCount": sum(1 for row in rows if row["detailLoaded"]),
        "families": sorted(families.values(), key=lambda row: str(row["label"]).casefold()),
        "workflows": rows,
        "access": {
            "tokenConfigured": bool(access.get("tokenConfigured")),
            "dispatchAvailable": bool(access.get("dispatchAvailable")),
            "statusMode": _text(access.get("statusMode")),
            "tokenSource": _text(access.get("tokenSource")),
        },
        "error": _text(inventory.get("error")) if not inventory.get("available") else "",
    }


def _find_workflow(center: Mapping[str, Any], workflow_id: int) -> dict[str, Any]:
    for row in center.get("workflows") or []:
        if isinstance(row, Mapping) and int(row.get("workflowId") or 0) == int(workflow_id):
            return dict(row)
    raise ValueError("workflow is not present in the acquired GitHub workflow snapshot")


def _history_for_ui(history: Mapping[str, Any] | None) -> dict[str, Any]:
    if not history:
        return {"available": False, "runs": [], "fetchedAtUtc": "", "snapshotLoaded": False}
    return {
        "available": bool(history.get("available")),
        "runs": [dict(row) for row in (history.get("runs") or []) if isinstance(row, Mapping)],
        "fetchedAtUtc": _text(history.get("fetchedAtUtc")),
        "snapshotLoaded": bool(history.get("available")),
        "error": _text(history.get("error")),
    }


def workflow_detail_snapshot(client: Any, workflow_id: int) -> dict[str, Any]:
    center = project_workflow_center(client)
    workflow = _find_workflow(center, workflow_id)
    history = _cached_history(client, workflow["filename"])
    form = _cached_form(client, workflow_id, workflow.get("preferredRef") or "")
    return {
        "schema": WORKFLOW_DETAIL_SCHEMA,
        "repository": center.get("repository"),
        "workflow": workflow,
        "history": _history_for_ui(history),
        "form": dict(form) if form else {
            "available": False, "dispatchable": False, "inputs": [],
            "snapshotLoaded": False,
            "error": "Workflow definition has not been acquired for this ref yet.",
        },
        "access": center.get("access") or {},
        "navigationRefresh": False,
    }


def acquire_workflow_detail(client: Any, workflow_id: int, ref: str, *, history_limit: int = 6, include_logs: bool = True) -> dict[str, Any]:
    """Explicitly acquire one workflow definition and bounded run/job/log detail."""
    center = project_workflow_center(client)
    workflow = _find_workflow(center, workflow_id)
    branch = _text(ref) or _text(workflow.get("preferredRef")) or "main"
    if len(branch) > 255 or any(ch in branch for ch in "\r\n"):
        raise ValueError("ref must be a bounded branch or tag name")
    limit = max(1, min(int(history_limit or 6), MAX_DETAIL_HISTORY))
    form = client.workflow_dispatch_form(workflow_id, branch, refresh=True)
    history = client.workflow_history(
        workflow["filename"], limit=limit, include_logs=bool(include_logs),
        log_job_names=None, log_run_limit=2 if include_logs else 0, refresh=True,
    )
    # Reproject after acquisition so detailLoaded/dispatchability fields reflect this action.
    result = workflow_detail_snapshot(client, workflow_id)
    result["form"] = dict(form)
    result["history"] = _history_for_ui(history)
    result["acquired"] = True
    result["acquisitionPolicy"] = "explicit-selected-workflow"
    return result


def _known_run_ids(client: Any) -> set[int]:
    ids: set[int] = set()
    operations = client.status(refresh=False)
    for row in operations.get("events") or []:
        if isinstance(row, Mapping):
            ids.add(int(row.get("runId") or 0))
    with getattr(client, "_lock", threading.RLock()):
        cache = dict(getattr(client, "_workflow_cache", {}) or {})
    for _key, cached in cache.items():
        if not isinstance(cached, tuple) or len(cached) != 2 or not isinstance(cached[1], Mapping):
            continue
        if cached[1].get("schema") != "omega.deltascope.workflow-history.v1":
            continue
        for run in cached[1].get("runs") or []:
            if isinstance(run, Mapping):
                ids.add(int(run.get("runId") or 0))
    ids.discard(0)
    return ids


def run_action(client: Any, run_id: int, action: str, confirmation: str) -> dict[str, Any]:
    """Apply a bounded GitHub Actions run control with explicit confirmation."""
    if not getattr(client, "token", ""):
        raise ValueError("connect GitHub workflow access before controlling a run")
    run_id = int(run_id or 0)
    if run_id <= 0 or run_id not in _known_run_ids(client):
        raise ValueError("run is not present in the acquired DeltaScope GitHub snapshot")
    action_key = _text(action).casefold()
    mapping = {
        "cancel": ("cancel", "CANCEL"),
        "rerun": ("rerun", "RERUN"),
        "rerun-failed": ("rerun-failed-jobs", "RERUN"),
    }
    if action_key not in mapping:
        raise ValueError("run action must be cancel, rerun, or rerun-failed")
    endpoint, required = mapping[action_key]
    if _text(confirmation) != required:
        raise ValueError(f"type {required} to confirm this GitHub run action")
    url = (
        f"https://api.github.com/repos/{urllib.parse.quote(client.repository, safe='/')}"
        f"/actions/runs/{run_id}/{endpoint}"
    )
    status, _payload = client._request(url, method="POST", body=None)
    accepted = status in {200, 201, 202, 204}
    return {
        "schema": RUN_ACTION_SCHEMA,
        "accepted": accepted,
        "status": status,
        "repository": client.repository,
        "runId": run_id,
        "action": action_key,
        "snapshotStale": True,
        "notice": "GitHub accepted the action. DeltaScope keeps the current snapshot until you explicitly reacquire workflow details or refresh GitHub data.",
        "readOnly": False,
        "mutationAuthority": "github-actions-run-control",
    }


_WORKFLOW_VIEW = r'''
<section id="workbench-workflows" class="workspace-view" data-workbench-view="workflows">
  <div class="workflow-center-head">
    <div><div class="eyebrow">GITHUB ACTIONS · LOCAL CONTROL PLANE</div><h1>Workflow Center</h1><p>Inspect, acquire and explicitly control GitHub workflows without turning page navigation into GitHub polling.</p></div>
    <div class="workflow-center-head-actions"><span id="workflowCenterSnapshot" class="muted small">Snapshot not loaded</span><button id="workflowCenterRefresh">Refresh GitHub snapshot</button></div>
  </div>
  <div id="workflowCenterStats" class="workflow-center-stats"></div>
  <div class="workflow-center-layout">
    <aside class="panel workflow-catalog-panel">
      <div class="workflow-catalog-search"><input id="workflowCenterSearch" placeholder="Search workflows…" autocomplete="off"><select id="workflowCenterFamily"><option value="">All families</option></select></div>
      <div id="workflowCenterList" class="workflow-center-list"><div class="workspace-empty">Loading acquired workflow inventory…</div></div>
    </aside>
    <section id="workflowCenterMain" class="panel workflow-center-main"><div class="workspace-empty">Select a workflow.</div></section>
    <aside id="workflowRunInspector" class="panel workflow-run-inspector"><div class="workspace-empty">Acquire workflow details to inspect jobs, steps, artifacts and bounded logs.</div></aside>
  </div>
</section>
'''

_WORKFLOW_CSS = r'''
#githubWorkflowControlPanel{display:none!important}#workbench-workflows{gap:12px;overflow:auto}.workflow-center-head{display:flex;align-items:flex-end;justify-content:space-between;gap:20px}.workflow-center-head h1{margin:2px 0 4px;font-size:27px}.workflow-center-head p{margin:0;color:#525252}.workflow-center-head-actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap;justify-content:flex-end}.workflow-center-stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:1px;background:#c6c6c6;border:1px solid #c6c6c6}.workflow-stat{background:#fff;padding:12px 14px}.workflow-stat b{display:block;font-size:24px;font-weight:400}.workflow-stat span{font-size:11px;color:#525252}.workflow-center-layout{display:grid;grid-template-columns:minmax(250px,.72fr) minmax(430px,1.35fr) minmax(330px,.93fr);gap:12px;min-height:620px}.workflow-catalog-panel,.workflow-center-main,.workflow-run-inspector{margin:0;min-height:0;overflow:auto}.workflow-catalog-search{position:sticky;top:0;z-index:2;display:grid;grid-template-columns:minmax(0,1fr) 135px;gap:6px;padding:10px;background:#fff;border-bottom:1px solid #e0e0e0}.workflow-center-list{display:grid}.workflow-family-label{padding:9px 12px 5px;font-size:10px;font-weight:700;color:#525252;text-transform:uppercase;letter-spacing:.04em;background:#f4f4f4;border-top:1px solid #e0e0e0}.workflow-list-item{display:grid;grid-template-columns:8px minmax(0,1fr) auto;gap:9px;align-items:start;text-align:left;padding:11px 12px;border:0;border-bottom:1px solid #e0e0e0!important;background:#fff!important;color:#161616!important}.workflow-list-item:hover,.workflow-list-item.selected{background:#edf5ff!important}.workflow-list-item.selected{box-shadow:inset 3px 0 #0f62fe}.workflow-state-dot{width:8px;height:8px;margin-top:5px;border-radius:50%;background:#8d8d8d}.workflow-state-dot.healthy{background:#24a148}.workflow-state-dot.running{background:#0f62fe}.workflow-state-dot.failed{background:#da1e28}.workflow-state-dot.warning{background:#f1c21b}.workflow-list-name{font-weight:600}.workflow-list-path{font-size:10px;color:#6f6f6f;overflow-wrap:anywhere}.workflow-list-badges{display:flex;gap:3px;flex-wrap:wrap;justify-content:flex-end}.workflow-mini-badge{font-size:9px;border:1px solid #c6c6c6;padding:1px 4px;color:#525252}.workflow-mini-badge.fail{border-color:#da1e28;color:#a2191f}.workflow-main-head{padding:18px;border-bottom:1px solid #e0e0e0}.workflow-main-head h2{margin:2px 0 4px;font-size:22px}.workflow-purpose{margin-top:10px;padding:10px 12px;border-left:4px solid #0f62fe;background:#edf5ff}.workflow-facts{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));border-bottom:1px solid #e0e0e0}.workflow-fact{padding:10px 14px;border-right:1px solid #e0e0e0;border-bottom:1px solid #e0e0e0}.workflow-fact span{display:block;font-size:10px;text-transform:uppercase;color:#6f6f6f}.workflow-fact b{display:block;margin-top:3px;font-size:13px;overflow-wrap:anywhere}.workflow-actions-block{padding:15px 18px;border-bottom:1px solid #e0e0e0}.workflow-actions-block h3{margin:0 0 4px;font-size:15px}.workflow-acquire-row{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:7px;margin-top:10px}.workflow-dispatch-form{display:grid;gap:9px;margin-top:10px}.workflow-dispatch-form label{display:grid;gap:4px;font-size:11px;color:#525252}.workflow-dispatch-form input,.workflow-dispatch-form textarea,.workflow-dispatch-form select,.workflow-acquire-row input{background:#fff!important;color:#161616!important;border:1px solid #8d8d8d!important}.workflow-dispatch-actions{display:flex;gap:7px;align-items:flex-end;flex-wrap:wrap}.workflow-dispatch-actions label{min-width:190px}.workflow-plugin-resolver{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:7px;padding:10px;background:#f4f4f4;border-left:4px solid #0f62fe}.workflow-plugin-resolver .note{grid-column:1/-1;font-size:10px;color:#525252}.workflow-run-list{display:grid;border-top:1px solid #e0e0e0}.workflow-run-row{display:grid;grid-template-columns:8px minmax(0,1fr) auto;gap:9px;text-align:left;padding:11px 14px;background:#fff!important;color:#161616!important;border:0;border-bottom:1px solid #e0e0e0!important}.workflow-run-row:hover,.workflow-run-row.selected{background:#f4f4f4!important}.workflow-run-row b{font-size:12px}.workflow-run-row small{display:block;color:#6f6f6f}.workflow-run-inspector{padding:0}.workflow-run-head{padding:16px;border-bottom:1px solid #e0e0e0}.workflow-run-head h2{margin:3px 0;font-size:18px}.workflow-run-control{display:grid;gap:7px;padding:12px 16px;background:#f4f4f4;border-bottom:1px solid #e0e0e0}.workflow-run-control-row{display:flex;gap:6px}.workflow-run-control-row input{min-width:130px}.workflow-job{border-bottom:1px solid #c6c6c6}.workflow-job>summary{list-style:none;display:grid;grid-template-columns:8px minmax(0,1fr) auto;gap:9px;padding:11px 14px;cursor:pointer}.workflow-job>summary::-webkit-details-marker{display:none}.workflow-steps{display:grid;background:#f4f4f4}.workflow-step{display:grid;grid-template-columns:32px minmax(0,1fr) auto;gap:8px;padding:7px 14px;border-top:1px solid #e0e0e0;font-size:11px}.workflow-artifacts{padding:12px 14px;border-bottom:1px solid #e0e0e0}.workflow-artifact{display:flex;justify-content:space-between;gap:10px;padding:5px 0}.workflow-log{margin:0;padding:10px 12px;max-height:250px;overflow:auto;background:#161616;color:#f4f4f4;font:11px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace;white-space:pre-wrap}.workflow-empty-note{padding:16px;color:#525252}.workflow-status-message{margin-top:8px;font-size:11px;color:#525252}.workflow-status-message.fail{color:#a2191f}.workflow-status-message.pass{color:#198038}@media(max-width:1250px){.workflow-center-layout{grid-template-columns:260px minmax(0,1fr);}.workflow-run-inspector{grid-column:1/-1;min-height:340px}.workflow-center-stats{grid-template-columns:repeat(2,1fr)}}@media(max-width:800px){.workflow-center-head{align-items:flex-start;flex-direction:column}.workflow-center-layout{grid-template-columns:1fr}.workflow-run-inspector{grid-column:auto}.workflow-center-stats{grid-template-columns:1fr 1fr}.workflow-catalog-search{grid-template-columns:1fr}.workflow-facts{grid-template-columns:1fr}.workflow-acquire-row,.workflow-plugin-resolver{grid-template-columns:1fr}.workflow-plugin-resolver .note{grid-column:auto}}
'''

_WORKFLOW_JS = r'''
setTimeout(()=>{
 if(window.__deltascopeWorkflowCenterInstalled)return;window.__deltascopeWorkflowCenterInstalled=true;
 const main=document.querySelector('main');if(!main)return;
 if(!$('workbench-workflows'))main.insertAdjacentHTML('beforeend',__WORKFLOW_VIEW__);
 const style=document.createElement('style');style.textContent=__WORKFLOW_CSS__;document.head.appendChild(style);
 const operate=(perspectiveConfig.operations?.groups||[]).find(group=>group.label==='Operate');if(operate&&!operate.items.some(item=>item.view==='workflows'))operate.items.splice(1,0,{label:'GitHub Workflows',mark:'W',view:'workflows'});
 contextualDocumentationFallback.workflows={doc:'github-workflows',label:'Workflow Center docs'};
 if(currentPerspective==='operations')renderPerspectiveNav();
 const appTitle=document.querySelector('[data-app-action="github-access"] .app-switcher-title');if(appTitle)appTitle.textContent='GitHub access';
 const componentHead=$('dashboardComponents')?.querySelector('.panelhead');if(componentHead&&!componentHead.querySelector('[data-open-workflow-center]')){const open=document.createElement('button');open.dataset.openWorkflowCenter='1';open.textContent='Open Workflow Center';open.addEventListener('click',()=>{const item=(perspectiveConfig.operations?.groups||[]).flatMap(group=>group.items||[]).find(candidate=>candidate.view==='workflows');if(item)navigatePerspective(item)});componentHead.appendChild(open)}
 let center=null,selectedWorkflowId=0,selectedRunId=0,searchText='',familyFilter='';
 const stateClass=value=>['healthy','running','failed','warning','idle'].includes(String(value||''))?String(value):'unknown';
 function bytes(n){const value=Number(n||0);if(value<1024)return`${value} B`;if(value<1024*1024)return`${(value/1024).toFixed(1)} KiB`;return`${(value/1024/1024).toFixed(1)} MiB`}
 function selectedWorkflow(){return (center?.workflows||[]).find(row=>Number(row.workflowId)===Number(selectedWorkflowId))||null}
 function renderStats(){const host=$('workflowCenterStats');if(!host)return;const access=center?.access||{};host.innerHTML=`<div class=workflow-stat><b>${fmt(center?.workflowCount||0)}</b><span>visible workflows</span></div><div class=workflow-stat><b>${fmt(center?.runningCount||0)}</b><span>currently running</span></div><div class=workflow-stat><b>${fmt(center?.recentFailureCount||0)}</b><span>latest failures</span></div><div class=workflow-stat><b>${access.tokenConfigured?'CONNECTED':'PUBLIC'}</b><span>${access.tokenConfigured?'dispatch / run controls available':'read-only GitHub snapshot'}</span></div>`;$('workflowCenterSnapshot').textContent=center?.fetchedAtUtc?`Snapshot ${center.fetchedAtUtc}`:'Snapshot not acquired'}
 function renderFamilyFilter(){const select=$('workflowCenterFamily');if(!select)return;const current=select.value;select.innerHTML='<option value="">All families</option>'+[...(center?.families||[])].map(row=>`<option value="${esc(row.familyId)}">${esc(row.label)} · ${fmt(row.workflowCount)}</option>`).join('');select.value=current||familyFilter}
 function filteredRows(){const q=searchText.toLowerCase();return (center?.workflows||[]).filter(row=>(!familyFilter||row.familyId===familyFilter)&&(!q||`${row.name} ${row.path} ${row.family} ${row.purpose}`.toLowerCase().includes(q)))}
 function renderList(){const host=$('workflowCenterList');if(!host)return;const rows=filteredRows();let family='';host.innerHTML=rows.map(row=>{const prefix=family!==row.family?(family=row.family,`<div class=workflow-family-label>${esc(row.family)}</div>`):'';return prefix+`<button class="workflow-list-item ${Number(row.workflowId)===Number(selectedWorkflowId)?'selected':''}" data-workflow-id="${String(row.workflowId)}"><span class="workflow-state-dot ${stateClass(row.state)}"></span><span><span class=workflow-list-name>${esc(row.name)}</span><span class=workflow-list-path>${esc(row.filename||row.path)}</span></span><span class=workflow-list-badges>${row.runningCount?`<span class=workflow-mini-badge>${fmt(row.runningCount)} running</span>`:''}${row.recentFailureCount?`<span class="workflow-mini-badge fail">failed</span>`:''}${row.detailLoaded?'<span class=workflow-mini-badge>detail</span>':''}</span></button>`}).join('')||'<div class=workspace-empty>No workflows match this filter.</div>';host.querySelectorAll('[data-workflow-id]').forEach(button=>button.addEventListener('click',()=>selectWorkflow(Number(button.dataset.workflowId))))}
 function inputHtml(input){const name=String(input.name||''),desc=String(input.description||''),required=input.required?' *':'',value=String(input.default||'');if(input.type==='boolean')return `<label>${esc(name)}${required}<select data-wc-input="${esc(name)}"><option value="true" ${value==='true'?'selected':''}>true</option><option value="false" ${value==='false'?'selected':''}>false</option></select><span class="muted small">${esc(desc)}</span></label>`;if(input.type==='choice')return `<label>${esc(name)}${required}<select data-wc-input="${esc(name)}">${(input.options||[]).map(option=>`<option ${String(option)===value?'selected':''}>${esc(option)}</option>`).join('')}</select><span class="muted small">${esc(desc)}</span></label>`;return `<label>${esc(name)}${required}<input data-wc-input="${esc(name)}" type="${input.type==='number'?'number':'text'}" value="${esc(value)}" placeholder="${esc(desc)}"><span class="muted small">${esc(desc)}</span></label>`}
 function pluginResolverHtml(inputs){const names=new Set((inputs||[]).map(row=>String(row.name||''))),direct=['plugin_url','artifact_url','repository_url','repo_url'].find(name=>names.has(name));if(!names.has('internal_names')&&!direct)return'';return `<div class=workflow-plugin-resolver><input data-wc-plugin-url type=url placeholder="https://github.com/owner/plugin"><button data-wc-plugin-resolve>${direct?'Use plugin URL':'Resolve plugin'}</button><div class=note data-wc-plugin-status>${direct?`Populates declared ${esc(direct)}.`:'Resolves against the loaded Omega catalog and populates internal_names.'}</div></div>`}
 function renderWorkflow(){const host=$('workflowCenterMain'),row=selectedWorkflow();if(!host)return;if(!row){host.innerHTML='<div class=workspace-empty>Select a workflow.</div>';return}const last=row.activeRun||row.latestRun||{},inputs=Array.isArray(row.dispatchInputs)?row.dispatchInputs:[];host.innerHTML=`<div class=workflow-main-head><div class=eyebrow>${esc(row.family)}</div><h2>${esc(row.name)}</h2><div class="muted small">${esc(row.path)}</div><div class=workflow-purpose><b>What this workflow is for</b><div>${esc(row.purpose)}</div><div class="muted small" style="margin-top:5px"><b>Operator question:</b> ${esc(row.operatorQuestion)}</div></div></div><div class=workflow-facts><div class=workflow-fact><span>Latest state</span><b>${esc(String(row.state||'unknown').toUpperCase())}</b></div><div class=workflow-fact><span>Last branch</span><b>${esc(last.branch||row.preferredRef||'—')}</b></div><div class=workflow-fact><span>Last run</span><b>${last.runNumber?`#${fmt(last.runNumber)} · ${esc(last.title||'')}`:'Not in acquired global window'}</b></div><div class=workflow-fact><span>Detailed snapshot</span><b>${row.detailLoaded?esc(row.detailFetchedAtUtc||'loaded'):'Not acquired'}</b></div></div><div class=workflow-actions-block><h3>Acquire selected workflow</h3><div class="muted small">Explicitly fetch this workflow's YAML, recent runs, jobs, steps, artifacts and bounded newest logs. Selecting a workflow never does this automatically.</div><div class=workflow-acquire-row><input id=workflowCenterRef value="${esc(row.dispatchRef||row.preferredRef||'main')}" maxlength=255 aria-label="Branch or tag"><button id=workflowAcquireDetails>${row.detailLoaded?'Reacquire details':'Acquire details'}</button></div><div id=workflowAcquireStatus class=workflow-status-message>${row.detailLoaded?'Using the locally acquired detail snapshot.':'No workflow-specific network request has been made from this selection.'}</div></div>${row.dispatchDefinitionLoaded?`<div class=workflow-actions-block><h3>Dispatch</h3><div class="muted small">${row.dispatchable?'This workflow declares workflow_dispatch. Inputs below come from its acquired YAML definition.':'The acquired definition does not expose workflow_dispatch on this ref.'}</div>${row.dispatchable?`<div class=workflow-dispatch-form>${pluginResolverHtml(inputs)}${inputs.map(inputHtml).join('')||'<div class="muted small">No declared inputs.</div>'}<div class=workflow-dispatch-actions><label>Confirmation<input id=workflowCenterDispatchConfirm placeholder="Type DISPATCH" maxlength=16></label><button id=workflowCenterDispatch>Start workflow</button></div><div id=workflowCenterDispatchStatus class=workflow-status-message></div></div>`:''}</div>`:''}<div class=workflow-actions-block><h3>Recent runs</h3><div class="muted small">Global snapshot rows are shown immediately; acquired workflow detail adds jobs, steps, artifacts and logs.</div></div><div id=workflowCenterRunList class=workflow-run-list></div>`;wireWorkflowControls(row);renderRunList(row)}
 function combinedRuns(row){const detail=(row._detail?.history?.runs||[]),byId=new Map();for(const run of [...detail,...(row.recentRuns||[])])if(run?.runId&&!byId.has(Number(run.runId)))byId.set(Number(run.runId),run);return [...byId.values()].sort((a,b)=>String(b.createdAtUtc||'').localeCompare(String(a.createdAtUtc||'')))}
 function renderRunList(row){const host=$('workflowCenterRunList');if(!host)return;const runs=combinedRuns(row);host.innerHTML=runs.map(run=>`<button class="workflow-run-row ${Number(run.runId)===Number(selectedRunId)?'selected':''}" data-wc-run="${String(run.runId)}"><span class="workflow-state-dot ${stateClass(run.state||((run.status==='completed'&&run.conclusion==='success')?'healthy':run.status==='in_progress'?'running':run.conclusion==='failure'?'failed':'unknown'))}"></span><span><b>#${fmt(run.runNumber||0)} · ${esc(run.title||run.workflow||'Workflow run')}</b><small>${esc(run.createdAtUtc||'')} · ${esc(run.event||'')} · ${esc(run.branch||'—')}</small></span><span class=workflow-mini-badge>${esc(run.conclusion||run.status||run.state||'unknown')}</span></button>`).join('')||'<div class=workflow-empty-note>No run is present in the acquired snapshots.</div>';host.querySelectorAll('[data-wc-run]').forEach(button=>button.addEventListener('click',()=>{selectedRunId=Number(button.dataset.wcRun);renderRunList(row);renderRunInspector(row)}));if(!selectedRunId&&runs.length)selectedRunId=Number(runs[0].runId);renderRunInspector(row)}
 function runState(run){if(run.state)return run.state;if(['queued','in_progress','waiting','pending','requested'].includes(String(run.status)))return'running';if(run.conclusion==='success')return'healthy';if(['failure','timed_out','action_required','startup_failure'].includes(String(run.conclusion)))return'failed';if(['cancelled','neutral','stale'].includes(String(run.conclusion)))return'warning';return'unknown'}
 function renderRunInspector(row){const host=$('workflowRunInspector');if(!host)return;const run=combinedRuns(row).find(item=>Number(item.runId)===Number(selectedRunId));if(!run){host.innerHTML='<div class=workspace-empty>Select a run.</div>';return}const jobs=Array.isArray(run.jobs)?run.jobs:[],artifacts=Array.isArray(run.artifacts)?run.artifacts:[],access=center?.access||{},state=runState(run);host.innerHTML=`<div class=workflow-run-head><div class=eyebrow>RUN #${fmt(run.runNumber||0)} · ATTEMPT ${fmt(run.attempt||1)}</div><h2>${esc(run.title||row.name)}</h2><div><span class="topology-state ${stateClass(state)}">${esc(String(run.conclusion||run.status||state).toUpperCase())}</span></div><div class="muted small" style="margin-top:5px">${esc(run.createdAtUtc||'')} · ${esc(run.branch||'—')} · ${esc(String(run.sha||'').slice(0,12))}</div>${run.url?`<div style="margin-top:9px"><a class=button-link href="${esc(run.url)}" target=_blank rel="noopener noreferrer">Open on GitHub</a></div>`:''}</div>${access.tokenConfigured?runControlHtml(run,state):'<div class="workflow-run-control muted small">Connect GitHub workflow access from the 9-dot menu to cancel or rerun known acquired runs.</div>'}${artifacts.length?`<div class=workflow-artifacts><b>Artifacts</b>${artifacts.map(a=>`<div class=workflow-artifact><span>${esc(a.name||'artifact')}${a.expired?' · expired':''}</span><span class=muted>${bytes(a.bytes)}</span></div>`).join('')}</div>`:''}${jobs.length?jobs.map(jobHtml).join(''):`<div class=workflow-empty-note>${row.detailLoaded?'No jobs were returned for this run.':'Acquire workflow details to inspect jobs, steps, artifacts and bounded logs.'}</div>`}`;wireRunControls(run)}
 function runControlHtml(run,state){const running=state==='running',failed=state==='failed';return `<div class=workflow-run-control><b>GitHub run control</b><div class="muted small">External GitHub action only. DeltaScope keeps its current snapshot until you explicitly reacquire.</div><div class=workflow-run-control-row><input id=workflowRunActionConfirm placeholder="Type ${running?'CANCEL':'RERUN'}" maxlength=16>${running?'<button data-wc-run-action="cancel">Cancel run</button>':`<button data-wc-run-action="rerun">Rerun</button>${failed?'<button data-wc-run-action="rerun-failed">Rerun failed jobs</button>':''}`}</div><div id=workflowRunActionStatus class=workflow-status-message></div></div>`}
 function jobHtml(job){const state=job.status==='in_progress'?'running':job.conclusion==='success'?'healthy':job.conclusion==='failure'?'failed':job.conclusion==='cancelled'?'warning':'unknown',steps=Array.isArray(job.steps)?job.steps:[];return `<details class=workflow-job><summary><span class="workflow-state-dot ${stateClass(state)}"></span><span><b>${esc(job.name||'Job')}</b><small>${esc(job.startedAtUtc||'')}${job.completedAtUtc?` → ${esc(job.completedAtUtc)}`:''}</small></span><span class=workflow-mini-badge>${esc(job.conclusion||job.status||'unknown')}</span></summary>${steps.length?`<div class=workflow-steps>${steps.map(step=>`<div class=workflow-step><span>${fmt(step.number||0)}</span><span>${esc(step.name||'Step')}</span><span>${esc(step.conclusion||step.status||'')}</span></div>`).join('')}</div>`:''}${job.logPreview?`<pre class=workflow-log>${esc(job.logPreview)}</pre>`:''}</details>`}
 function gatherInputs(){const result={};document.querySelectorAll('#workflowCenterMain [data-wc-input]').forEach(field=>{result[field.dataset.wcInput]=String(field.value??'')});return result}
 function wireWorkflowControls(row){$('workflowAcquireDetails')?.addEventListener('click',async()=>{const status=$('workflowAcquireStatus'),ref=$('workflowCenterRef').value.trim();status.textContent='Acquiring selected workflow definition and bounded run detail…';try{const detail=await api('/api/operations/workflow-center/acquire',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({workflowId:row.workflowId,ref,historyLimit:6,includeLogs:true})});row._detail=detail;row.detailLoaded=!!detail.history?.available;row.detailFetchedAtUtc=detail.history?.fetchedAtUtc||'';row.dispatchDefinitionLoaded=!!detail.form?.available;row.dispatchable=!!detail.form?.dispatchable;row.dispatchInputs=detail.form?.inputs||[];row.dispatchRef=detail.form?.ref||ref;selectedRunId=Number(detail.history?.runs?.[0]?.runId||selectedRunId||0);renderWorkflow();renderList()}catch(error){status.textContent=`Acquisition failed: ${error.message}`;status.className='workflow-status-message fail'}});$('workflowCenterDispatch')?.addEventListener('click',async()=>{const status=$('workflowCenterDispatchStatus'),confirmation=$('workflowCenterDispatchConfirm').value,ref=$('workflowCenterRef').value.trim();status.textContent='Submitting explicitly confirmed workflow_dispatch…';try{const result=await api('/api/operations/dispatch',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({workflowId:row.workflowId,ref,inputs:gatherInputs(),confirmation})});$('workflowCenterDispatchConfirm').value='';status.textContent=result.accepted?'GitHub accepted the workflow dispatch. Reacquire or refresh when you want the newer run state.':'GitHub did not accept the dispatch.';status.className=`workflow-status-message ${result.accepted?'pass':'fail'}`}catch(error){status.textContent=`Dispatch failed: ${error.message}`;status.className='workflow-status-message fail'}});const resolver=document.querySelector('[data-wc-plugin-resolve]');resolver?.addEventListener('click',async()=>{const input=document.querySelector('[data-wc-plugin-url]'),message=document.querySelector('[data-wc-plugin-status]'),value=String(input?.value||'').trim(),names=new Set((row.dispatchInputs||[]).map(item=>String(item.name||''))),direct=['plugin_url','artifact_url','repository_url','repo_url'].find(name=>names.has(name));if(!value){message.textContent='Paste a plugin GitHub link first.';return}if(direct){const target=document.querySelector(`[data-wc-input="${direct}"]`);if(target){target.value=value;message.textContent=`Populated declared ${direct}.`;return}}message.textContent='Resolving against the loaded Omega catalog…';try{const resolved=await api(`/api/operations/plugin-link?url=${encodeURIComponent(value)}`);if(!resolved.matched){message.textContent=resolved.notice||'No catalog plugin matched this repository.';return}const target=document.querySelector('[data-wc-input="internal_names"]');if(!target){message.textContent='This acquired workflow definition has no compatible plugin input.';return}target.value=(resolved.internalNames||[]).join(',');message.textContent=`Resolved ${(resolved.internalNames||[]).join(', ')} through internal_names.`}catch(error){message.textContent=`Resolution failed: ${error.message}`}})}
 function wireRunControls(run){document.querySelectorAll('[data-wc-run-action]').forEach(button=>button.addEventListener('click',async()=>{const status=$('workflowRunActionStatus'),confirmation=$('workflowRunActionConfirm').value,action=button.dataset.wcRunAction;status.textContent='Submitting GitHub run control…';try{const result=await api('/api/operations/workflow-center/run-action',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({runId:run.runId,action,confirmation})});$('workflowRunActionConfirm').value='';status.textContent=result.notice||'GitHub accepted the run action.';status.className='workflow-status-message pass'}catch(error){status.textContent=`Run control failed: ${error.message}`;status.className='workflow-status-message fail'}}))}
 async function loadCenter(){try{center=await api('/api/operations/workflow-center');renderStats();renderFamilyFilter();if(!selectedWorkflowId&&center.workflows?.length)selectedWorkflowId=Number(center.workflows[0].workflowId);renderList();renderWorkflow()}catch(error){$('workflowCenterList').innerHTML=`<div class=workspace-empty>Workflow Center unavailable: ${esc(error.message)}</div>`}}
 async function selectWorkflow(id){selectedWorkflowId=Number(id);selectedRunId=0;renderList();const row=selectedWorkflow();if(!row)return;try{const detail=await api(`/api/operations/workflow-center/detail?workflow_id=${encodeURIComponent(row.workflowId)}`);row._detail=detail;row.detailLoaded=!!detail.history?.available;row.detailFetchedAtUtc=detail.history?.fetchedAtUtc||row.detailFetchedAtUtc;row.dispatchDefinitionLoaded=!!detail.form?.available;row.dispatchable=!!detail.form?.dispatchable;row.dispatchInputs=detail.form?.inputs||[];row.dispatchRef=detail.form?.ref||row.dispatchRef;selectedRunId=Number(detail.history?.runs?.[0]?.runId||row.activeRun?.runId||row.latestRun?.runId||0)}catch{}renderWorkflow()}
 $('workflowCenterSearch')?.addEventListener('input',event=>{searchText=String(event.target.value||'');renderList()});$('workflowCenterFamily')?.addEventListener('change',event=>{familyFilter=String(event.target.value||'');renderList()});$('workflowCenterRefresh')?.addEventListener('click',async()=>{const button=$('workflowCenterRefresh');button.disabled=true;button.textContent='Refreshing…';try{await api('/api/acquisition/refresh',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({source:'github-actions'})});await loadCenter()}catch(error){alert(`GitHub snapshot refresh failed: ${error.message}`)}finally{button.disabled=false;button.textContent='Refresh GitHub snapshot'}});
 const setWorkbenchViewBase=setWorkbenchView;setWorkbenchView=function(name){setWorkbenchViewBase(name);if(name==='workflows')loadCenter()};
 if(currentWorkbenchView==='workflows')loadCenter();
},0);
'''


def _patch_html(html: str) -> str:
    text = str(html)
    if 'id="workbench-workflows"' not in text:
        marker = "</main>"
        index = text.rfind(marker)
        if index < 0:
            raise RuntimeError("DeltaScope main workspace boundary was not found")
        text = text[:index] + _WORKFLOW_VIEW + text[index:]
    if "__deltascopeWorkflowCenterInstalled" not in text:
        script = _WORKFLOW_JS.replace("__WORKFLOW_VIEW__", json.dumps(_WORKFLOW_VIEW)).replace("__WORKFLOW_CSS__", json.dumps(_WORKFLOW_CSS))
        marker = "</script>"
        index = text.rfind(marker)
        if index < 0:
            raise RuntimeError("DeltaScope HTML script boundary was not found")
        text = text[:index] + "\n" + script + "\n" + text[index:]
    return text


def _read_json_body(handler: Any, *, maximum: int = 256 * 1024) -> dict[str, Any]:
    declared = max(0, int(handler.headers.get("Content-Length") or 0))
    if declared > maximum:
        raise ValueError("request body exceeds the DeltaScope local API safety bound")
    raw = handler.rfile.read(declared) if declared else b"{}"
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"request body is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("request body must be a JSON object")
    return payload


def install() -> None:
    import developer_view

    if getattr(developer_view, "_deltascope_workflow_center_installed", False):
        return
    developer_view.HTML = _patch_html(developer_view.HTML)
    original_get = developer_view.AppHandler.do_GET
    original_post = developer_view.AppHandler.do_POST

    def patched_get(self: Any) -> None:
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        try:
            if parsed.path == "/api/operations/workflow-center":
                if not getattr(self, "operations_client", None):
                    return self.json_response({"schema": WORKFLOW_CENTER_SCHEMA, "available": False, "error": "GitHub operations disabled", "workflows": []})
                return self.json_response(project_workflow_center(self.operations_client))
            if parsed.path == "/api/operations/workflow-center/detail":
                if not getattr(self, "operations_client", None):
                    raise ValueError("GitHub operations are disabled")
                workflow_id = int((query.get("workflow_id") or ["0"])[0] or 0)
                return self.json_response(workflow_detail_snapshot(self.operations_client, workflow_id))
        except (TypeError, ValueError) as exc:
            return self.json_response({"error": str(exc)}, 400)
        except Exception as exc:
            return self.json_response({"error": str(exc)}, 500)
        return original_get(self)

    def patched_post(self: Any) -> None:
        path = urllib.parse.urlparse(self.path).path
        if path not in {"/api/operations/workflow-center/acquire", "/api/operations/workflow-center/run-action"}:
            return original_post(self)
        try:
            if not getattr(self, "operations_client", None):
                raise ValueError("GitHub operations are disabled")
            payload = _read_json_body(self)
            if path.endswith("/acquire"):
                result = acquire_workflow_detail(
                    self.operations_client,
                    int(payload.get("workflowId") or 0),
                    _text(payload.get("ref")),
                    history_limit=int(payload.get("historyLimit") or 6),
                    include_logs=payload.get("includeLogs") is not False,
                )
                return self.json_response(result)
            result = run_action(
                self.operations_client,
                int(payload.get("runId") or 0),
                _text(payload.get("action")),
                _text(payload.get("confirmation")),
            )
            return self.json_response(result)
        except (TypeError, ValueError) as exc:
            return self.json_response({"error": str(exc)}, 400)
        except Exception as exc:
            return self.json_response({"error": str(exc)}, 500)

    developer_view.AppHandler.do_GET = patched_get
    developer_view.AppHandler.do_POST = patched_post
    developer_view._deltascope_workflow_center_installed = True
