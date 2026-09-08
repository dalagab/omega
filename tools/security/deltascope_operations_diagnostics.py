#!/usr/bin/env python3
"""Read-only GitHub capability and acquisition diagnostics for DeltaScope Operations.

Normal navigation projects the already-acquired live Actions snapshot only. An explicit
refresh may perform the same bounded GitHub reads used by Live Operations. Diagnostics
never perform a mutating permission probe and never return credentials or raw job logs.
"""
from __future__ import annotations

import json
import math
import time
import urllib.parse
from typing import Any, Mapping

import deltascope_live_operations as live


SCHEMA = "omega.deltascope.operations-diagnostics.v1"

_CAPABILITIES: tuple[tuple[str, str, str], ...] = (
    ("actionsRead", "Actions runs", "Read recent GitHub Actions runs."),
    ("jobsRead", "Run jobs", "Read jobs and steps for active Actions runs."),
    ("jobLogsRead", "Job logs", "Read bounded active-job telemetry or explicitly requested Workflow Center log previews."),
    ("runnerInventoryRead", "Runner inventory", "Read repository self-hosted runner inventory."),
    ("workflowDispatch", "Workflow dispatch", "Dispatch workflow_dispatch only after the existing explicit confirmation."),
    ("runControl", "Run control", "Cancel or rerun known runs only after the existing explicit confirmation."),
)
_MUTATING = {"workflowDispatch", "runControl"}


def _text(value: Any) -> str:
    return str(value or "").strip()


def _capability_row(name: str, label: str, purpose: str, raw: Mapping[str, Any], authenticated: bool) -> dict[str, Any]:
    available = raw.get("available")
    observed = bool(raw.get("observed"))
    detail = _text(raw.get("detail"))
    source = _text(raw.get("source")) or "not-observed"

    if not authenticated:
        state = "not-connected"
        explanation = "Connect GitHub access before this capability can be observed."
    elif name in _MUTATING and available is True and not observed:
        state = "configured-unverified"
        explanation = (
            "A connected token is present, but DeltaScope intentionally does not perform a mutating "
            "permission probe. Actual authorization is learned only when you explicitly confirm that "
            "operation in GitHub Workflows."
        )
    elif available is True:
        state = "available"
        explanation = detail or "GitHub accepted the bounded read used for this capability."
    elif available is False and observed:
        state = "unavailable"
        explanation = detail or "GitHub rejected or did not expose the bounded read used for this capability."
    elif available is False:
        state = "unavailable"
        explanation = detail or "This capability is not available in the current access mode."
    else:
        state = "not-observed"
        explanation = detail or "No bounded probe has observed this capability in the current process snapshot yet."

    return {
        "id": name,
        "label": label,
        "purpose": purpose,
        "state": state,
        "available": available,
        "observed": observed,
        "source": source,
        "detail": detail,
        "explanation": explanation,
        "mutating": name in _MUTATING,
    }


def _budget(rate: Mapping[str, Any]) -> dict[str, Any]:
    limit = max(0, int(rate.get("limit") or 0))
    remaining = max(0, int(rate.get("remaining") or 0))
    used = max(0, int(rate.get("used") or 0))
    percent = round((remaining * 100.0 / limit), 1) if limit else None
    if not limit:
        state = "unknown"
    elif remaining <= 0:
        state = "exhausted"
    elif remaining <= live.VERY_LOW_RATE_REMAINING:
        state = "very-low"
    elif remaining <= live.LOW_RATE_REMAINING:
        state = "low"
    else:
        state = "healthy"
    return {
        "state": state,
        "limit": limit,
        "remaining": remaining,
        "used": used,
        "remainingPercent": percent,
        "resource": _text(rate.get("resource")),
        "resetAtUtc": _text(rate.get("resetAtUtc")),
        "retryAfterSeconds": max(0, int(rate.get("retryAfterSeconds") or 0)),
    }


def _guidance(authenticated: bool, capabilities: list[dict[str, Any]], last_error: str) -> list[str]:
    rows: list[str] = []
    if not authenticated:
        rows.append("GitHub access is not connected. Public snapshots may still work, but authenticated live Actions diagnostics are disabled.")
        return rows
    lower = last_error.casefold()
    if "401" in lower:
        rows.append("GitHub rejected the credential (401). The configured token may be invalid, expired, or no longer authorized for this repository.")
    elif "403" in lower:
        rows.append("GitHub denied the last bounded read (403). The credential is connected but may not have access to that Actions or runner resource.")
    elif "404" in lower:
        rows.append("GitHub returned 404 for the last bounded read. The repository or requested Actions resource may not be visible to this credential.")
    for row in capabilities:
        if row["state"] == "unavailable" and row.get("detail"):
            rows.append(f"{row['label']}: {row['detail']}")
    if any(row["state"] == "configured-unverified" for row in capabilities):
        rows.append("Dispatch and run-control write permission is intentionally not tested by a background mutation. Use the existing explicit Workflow Center confirmation when you actually want to perform one.")
    seen: set[str] = set()
    out: list[str] = []
    for value in rows:
        if value not in seen:
            seen.add(value)
            out.append(value[:500])
    return out[:8]


def project_operations_diagnostics(client: Any, *, refresh: bool = False) -> dict[str, Any]:
    """Project GitHub access/capability health without silently performing network I/O."""
    live._ensure_state(client)
    if refresh:
        snapshot = client.live_status(foreground=True, force=True)
    else:
        with client._lock:
            cached = dict(client._live_cache) if isinstance(client._live_cache, Mapping) else None
        snapshot = cached or live._live_unavailable(
            client,
            foreground=True,
            reason=(
                "No authenticated live snapshot has been acquired yet. Refresh diagnostics to perform bounded GitHub reads."
                if getattr(client, "token", "")
                else ""
            ),
        )

    access = client.access_status()
    authenticated = bool(access.get("tokenConfigured"))
    raw_caps = snapshot.get("capabilities") if isinstance(snapshot.get("capabilities"), Mapping) else {}
    capabilities = [
        _capability_row(name, label, purpose, raw_caps.get(name) if isinstance(raw_caps.get(name), Mapping) else {}, authenticated)
        for name, label, purpose in _CAPABILITIES
    ]

    with client._lock:
        rate = dict(getattr(client, "_live_rate_limit", {}) or {})
        last_attempt = _text(getattr(client, "_live_last_attempt_utc", ""))
        last_success = _text(getattr(client, "_live_last_success_utc", ""))
        last_error = _text(getattr(client, "_live_last_error", ""))
        last_error_at = _text(getattr(client, "_live_last_error_utc", ""))
        backoff_reason = _text(getattr(client, "_live_backoff_reason", ""))
        backoff_seconds = max(0, int(math.ceil(float(getattr(client, "_live_backoff_until", 0.0) or 0.0) - time.monotonic())))

    if not last_success and snapshot.get("live"):
        last_success = _text(snapshot.get("fetchedAtUtc"))
    if not last_error:
        last_error = _text(snapshot.get("error"))
    if not rate and isinstance(snapshot.get("rateLimit"), Mapping):
        rate = dict(snapshot.get("rateLimit") or {})

    if not authenticated:
        state = "not-connected"
    elif last_error and not last_success:
        state = "unavailable"
    elif bool(snapshot.get("stale")) or last_error:
        state = "degraded"
    elif bool(snapshot.get("live")):
        state = "healthy"
    else:
        state = "not-observed"

    return {
        "schema": SCHEMA,
        "available": authenticated or bool(snapshot.get("available")),
        "state": state,
        "repository": _text(getattr(client, "repository", "")),
        "snapshotOnly": not refresh,
        "refreshPerformed": bool(refresh),
        "access": {
            "authenticated": authenticated,
            "statusMode": _text(access.get("statusMode")),
            "tokenSource": _text(access.get("tokenSource")),
            "tokenPersistence": _text(access.get("tokenPersistence")),
            "credentialProtection": _text(access.get("credentialProtection")),
            "credentialError": _text(access.get("credentialError")),
        },
        "acquisition": {
            "lastAttemptAtUtc": last_attempt,
            "lastSuccessfulAtUtc": last_success,
            "lastErrorAtUtc": last_error_at,
            "lastError": last_error[:500],
            "stale": bool(snapshot.get("stale")),
            "servedFromCache": bool(snapshot.get("servedFromCache")),
            "backoffSeconds": backoff_seconds,
            "backoffReason": backoff_reason[:500],
            "nextPollSeconds": max(0, int(snapshot.get("nextPollSeconds") or 0)),
            "fetchedAtUtc": _text(snapshot.get("fetchedAtUtc")),
        },
        "rateLimit": _budget(rate),
        "capabilities": capabilities,
        "guidance": _guidance(authenticated, capabilities, last_error),
        "readOnly": True,
        "mutationAuthority": "none",
        "securityAuthority": False,
        "permissionProbePolicy": "read-capabilities-observed; mutating-capabilities-configured-but-not-probed",
    }


_CSS = r"""
#workbench-operations-diagnostics{gap:12px;min-height:0}
.operations-diag-head{display:flex;justify-content:space-between;gap:16px;align-items:flex-start}
.operations-diag-actions{display:flex;gap:8px;align-items:center}
.operations-diag-grid{display:grid;grid-template-columns:repeat(3,minmax(220px,1fr));gap:10px}
.operations-diag-card{border:1px solid #d8dde3;background:#fff;padding:13px}
.operations-diag-card h3{margin:0 0 4px;font-size:15px}
.operations-diag-state{display:inline-flex;padding:3px 8px;border:1px solid #ccd3da;background:#f5f6f7;font-size:11px;font-weight:700;text-transform:uppercase}
.operations-diag-state.available,.operations-diag-state.healthy{border-color:#83c99e;background:#effaf3}
.operations-diag-state.unavailable,.operations-diag-state.exhausted{border-color:#e5a1a1;background:#fff3f3}
.operations-diag-state.degraded,.operations-diag-state.low,.operations-diag-state.very-low,.operations-diag-state.configured-unverified{border-color:#e2c36f;background:#fff9e7}
.operations-diag-kv{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:6px 12px;margin-top:10px;font-size:12px}
.operations-diag-kv b{font-weight:600}
.operations-diag-guidance{display:grid;gap:7px;margin:0;padding-left:20px}
.operations-diag-capabilities{display:grid;grid-template-columns:repeat(2,minmax(280px,1fr));gap:9px}
.operations-diag-cap{border:1px solid #d8dde3;background:#fff;padding:12px}
.operations-diag-cap-head{display:flex;justify-content:space-between;gap:10px;align-items:center}
.operations-diag-cap p{margin:7px 0 0}
@media(max-width:1000px){.operations-diag-grid,.operations-diag-capabilities{grid-template-columns:1fr}}
"""

_JS = r"""
setTimeout(()=>{
 if(window.__deltascopeOperationsDiagnosticsInstalled)return;window.__deltascopeOperationsDiagnosticsInstalled=true;
 const style=document.createElement('style');style.textContent=__DIAG_CSS__;document.head.appendChild(style);
 const view=document.createElement('section');view.id='workbench-operations-diagnostics';view.className='workspace-view';view.dataset.workbenchView='operations-diagnostics';
 view.innerHTML=`<div class=operations-diag-head><div><div class=eyebrow>GITHUB ACCESS · ACQUISITION</div><h1>Operations diagnostics</h1><p>Read-only capability, rate-budget and acquisition health. Opening this page uses the current snapshot; refresh performs bounded GitHub reads but never a mutating permission probe.</p></div><div class=operations-diag-actions><span id=operationsDiagSnapshot class="muted small">Snapshot not loaded</span><button id=operationsDiagRefresh>Refresh diagnostics</button></div></div><div id=operationsDiagSummary class=operations-diag-grid></div><section class=panel><div class=panelhead><div><h2>GitHub capabilities</h2><div class="muted small">Observed reads are separated from write capabilities that are configured but intentionally not tested by mutation.</div></div></div><div id=operationsDiagCapabilities class=operations-diag-capabilities></div></section><section class=panel><div class=panelhead><div><h2>Permission & acquisition guidance</h2><div class="muted small">DeltaScope never returns the credential, and these diagnostics do not become Security Evidence.</div></div></div><ul id=operationsDiagGuidance class=operations-diag-guidance></ul></section>`;
 document.querySelector('main')?.appendChild(view);
 const operate=(perspectiveConfig.operations?.groups||[]).find(group=>group.label==='Operate');
 if(operate&&!operate.items.some(item=>item.view==='operations-diagnostics'))operate.items.push({label:'Diagnostics',mark:'D',view:'operations-diagnostics'});
 contextualDocumentationFallback['operations-diagnostics']={doc:'operations',label:'Operations diagnostics docs'};
 if(currentPerspective==='operations')renderPerspectiveNav();
 let last=null,inFlight=false;
 function state(value){return `<span class="operations-diag-state ${esc(value||'unknown')}">${esc(String(value||'unknown').replaceAll('-',' '))}</span>`}
 function kv(rows){return `<div class=operations-diag-kv>${rows.map(([k,v])=>`<b>${esc(k)}</b><span>${esc(v||'—')}</span>`).join('')}</div>`}
 function render(d){last=d;const a=d.access||{},q=d.acquisition||{},rate=d.rateLimit||{};$('operationsDiagSnapshot').textContent=q.fetchedAtUtc?`${d.snapshotOnly?'Snapshot':'Refreshed'} · ${q.fetchedAtUtc}`:d.snapshotOnly?'Snapshot not acquired':'Refresh completed';$('operationsDiagSummary').innerHTML=`<article class=operations-diag-card><h3>GitHub access</h3>${state(d.state)}${kv([['Mode',a.statusMode],['Token source',a.tokenSource],['Persistence',a.tokenPersistence],['Protection',a.credentialProtection]])}</article><article class=operations-diag-card><h3>Acquisition</h3>${state(q.stale?'degraded':d.state)}${kv([['Last success',q.lastSuccessfulAtUtc],['Last attempt',q.lastAttemptAtUtc],['Backoff',q.backoffSeconds?`${fmt(q.backoffSeconds)} s`:'none'],['Reason',q.backoffReason||q.lastError]])}</article><article class=operations-diag-card><h3>GitHub rate budget</h3>${state(rate.state)}${kv([['Remaining',rate.limit?`${fmt(rate.remaining)} / ${fmt(rate.limit)}`:'not reported'],['Used',rate.limit?fmt(rate.used):'—'],['Reset',rate.resetAtUtc],['Resource',rate.resource]])}</article>`;$('operationsDiagCapabilities').innerHTML=(d.capabilities||[]).map(c=>`<article class=operations-diag-cap><div class=operations-diag-cap-head><div><b>${esc(c.label)}</b><div class="muted tiny">${esc(c.source||'')}</div></div>${state(c.state)}</div><p class="muted small">${esc(c.explanation||c.purpose||'')}</p>${c.detail?`<details><summary>GitHub detail</summary><div class="muted small">${esc(c.detail)}</div></details>`:''}</article>`).join('')||'<div class=workspace-empty>No capability observations are available.</div>';$('operationsDiagGuidance').innerHTML=(d.guidance||[]).map(x=>`<li>${esc(x)}</li>`).join('')||'<li>No permission or acquisition warning is currently recorded.</li>'}
 async function load(refresh=false){if(inFlight)return;inFlight=true;const button=$('operationsDiagRefresh');if(button)button.disabled=true;try{render(await api(`/api/operations/diagnostics${refresh?'?refresh=1':''}`))}catch(error){toniSay(`Operations diagnostics failed: ${error.message}`);$('operationsDiagGuidance').innerHTML=`<li>${esc(error.message)}</li>`}finally{inFlight=false;if(button)button.disabled=false}}
 $('operationsDiagRefresh')?.addEventListener('click',()=>load(true));
 const setWorkbenchViewBase=setWorkbenchView;setWorkbenchView=function(name){setWorkbenchViewBase(name);if(name==='operations-diagnostics')load(false)};
 window.deltaScopeOperationsDiagnostics={load,render,last:()=>last};
},0);
"""


def _patch_html(text: str) -> str:
    if "__deltascopeOperationsDiagnosticsInstalled" in text:
        return text
    script = _JS.replace("__DIAG_CSS__", json.dumps(_CSS))
    marker = "</script>"
    index = text.rfind(marker)
    if index < 0:
        raise RuntimeError("DeltaScope HTML script boundary was not found")
    return text[:index] + "\n" + script + "\n" + text[index:]


def install() -> None:
    import developer_view

    if getattr(developer_view, "_deltascope_operations_diagnostics_installed", False):
        return
    developer_view.HTML = _patch_html(developer_view.HTML)
    original_get = developer_view.AppHandler.do_GET

    def patched_get(self: Any) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/api/operations/diagnostics":
            return original_get(self)
        try:
            client = getattr(self, "operations_client", None)
            if client is None:
                return self.json_response({"schema": SCHEMA, "available": False, "error": "GitHub operations are disabled"}, 503)
            query = urllib.parse.parse_qs(parsed.query)
            refresh = str((query.get("refresh") or [""])[0]).casefold() in {"1", "true", "yes"}
            return self.json_response(project_operations_diagnostics(client, refresh=refresh))
        except Exception as exc:
            return self.json_response({"schema": SCHEMA, "available": False, "error": str(exc)}, 500)

    developer_view.AppHandler.do_GET = patched_get
    developer_view._deltascope_operations_diagnostics_installed = True
