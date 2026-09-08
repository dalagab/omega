#!/usr/bin/env python3
"""Correlate retained Omega Actions telemetry with DeltaScope investigation surfaces.

The correlation layer is intentionally presentation-only. It attaches stable navigation
identity to already-sanitized ``omega.actions.telemetry.v1`` events, exposes an exact
single-variant Detection Coverage projection, and lets the browser retain a bounded
operations-event reference in local Investigator casework. It never stores raw job logs,
changes Security Evidence, or grants operational self-reports security authority.
"""
from __future__ import annotations

import hashlib
import json
import urllib.parse
from typing import Any, Mapping

import deltascope_detection_coverage
import deltascope_operations

CORRELATION_SCHEMA = "omega.deltascope.operations-correlation.v1"


def _int(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _subject(row: Mapping[str, Any]) -> Mapping[str, Any]:
    value = row.get("subject")
    return value if isinstance(value, Mapping) else {}


def correlate_event(row: Mapping[str, Any]) -> dict[str, Any]:
    """Return bounded navigation identity for one sanitized operational event."""
    subject = _subject(row)
    identity = {
        "runId": _int(row.get("runId")),
        "jobId": _int(row.get("jobId")),
        "event": str(row.get("event") or ""),
        "emittedAtUtc": str(row.get("emittedAtUtc") or ""),
        "component": str(row.get("component") or ""),
        "stage": str(row.get("stage") or ""),
        "pluginId": _int(subject.get("pluginId")),
        "variantId": _int(subject.get("variantId")),
    }
    digest = hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:24]
    variant_id = identity["variantId"]
    retainable = bool(identity["event"] and identity["emittedAtUtc"])
    return {
        "schema": CORRELATION_SCHEMA,
        "correlationId": f"operation-{digest}",
        "runId": identity["runId"],
        "runNumber": _int(row.get("runNumber")),
        "jobId": identity["jobId"],
        "event": identity["event"],
        "emittedAtUtc": identity["emittedAtUtc"],
        "component": identity["component"],
        "stage": identity["stage"],
        "pluginId": identity["pluginId"],
        "variantId": variant_id,
        "internalName": str(subject.get("internalName") or ""),
        "version": str(subject.get("version") or ""),
        "sourceName": str(subject.get("sourceName") or ""),
        "targets": {
            "asset": bool(variant_id),
            "evidence": bool(variant_id),
            "detectionCoverage": bool(variant_id),
            "casework": retainable,
        },
        "readOnly": True,
        "mutationAuthority": "none",
        "securityAuthority": False,
    }


def correlate_activity(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Attach correlation metadata without changing the retained event payload itself."""
    result = dict(payload)
    timeline: list[dict[str, Any]] = []
    latest_by_job: dict[tuple[int, int], dict[str, Any]] = {}
    for raw in payload.get("timeline") or []:
        if not isinstance(raw, Mapping):
            continue
        row = dict(raw)
        correlation = correlate_event(row)
        row["correlation"] = correlation
        timeline.append(row)
        key = (_int(row.get("runId")), _int(row.get("jobId")))
        if key not in latest_by_job:
            latest_by_job[key] = correlation

    current: list[dict[str, Any]] = []
    for raw in payload.get("currentWork") or []:
        if not isinstance(raw, Mapping):
            continue
        row = dict(raw)
        if str(row.get("telemetrySource") or "") == "structured":
            key = (_int(row.get("runId")), _int(row.get("jobId")))
            correlation = latest_by_job.get(key)
            if correlation is not None:
                row["correlation"] = dict(correlation)
        current.append(row)

    result["timeline"] = timeline
    result["currentWork"] = current
    result["correlationSchema"] = CORRELATION_SCHEMA
    result["correlatedEventCount"] = sum(
        1 for row in timeline
        if bool((row.get("correlation") or {}).get("targets", {}).get("asset"))
    )
    return result


_CORRELATION_CSS = r'''
.operations-correlation-actions{display:flex;gap:5px;flex-wrap:wrap;margin-top:7px}.live-event summary .operations-correlation-actions{margin-top:0;justify-content:flex-end}.operations-correlation-actions button{font-size:10px;padding:4px 7px}.operations-case-pin{border-color:#8a3ffc!important;color:#491d8b!important;background:#f6f2ff!important}.operations-coverage-focus{margin:0 0 12px;border-left:4px solid #0f62fe}.operations-coverage-focus .operations-focus-head{display:flex;justify-content:space-between;gap:12px;align-items:flex-start}.operations-coverage-focus .operations-focus-actions{display:flex;gap:6px;flex-wrap:wrap}.operations-coverage-focus .operations-focus-stats{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}.operations-coverage-focus .operations-focus-stat{background:#f4f4f4;border:1px solid #e0e0e0;padding:5px 8px;font-size:10px}.operations-coverage-list{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:6px;margin-top:10px}.operations-coverage-row{border:1px solid #e0e0e0;background:#fff;padding:8px;text-align:left}.operations-coverage-row.current{border-left:4px solid #198038}.operations-coverage-row.outside-scope{border-left:4px solid #8d8d8d}.operations-coverage-row.attention,.operations-coverage-row.degraded,.operations-coverage-row.blind-spot{border-left:4px solid #da1e28}.operations-coverage-row b{display:block}.operations-coverage-row span{display:block;font-size:10px;color:#525252;margin-top:2px}@media(max-width:900px){.live-event summary .operations-correlation-actions{justify-content:flex-start}}
'''

_CORRELATION_JS = r'''
setTimeout(function(){
 if(window.__deltascopeOperationsCorrelationInstalled)return;window.__deltascopeOperationsCorrelationInstalled=true;
 var style=document.createElement('style');style.textContent=__CORRELATION_CSS__;document.head.appendChild(style);
 var correlationTimer=0,correlationInFlight=false;
 function correlationActions(row){var c=row?.correlation||{},t=c.targets||{},id=Number(c.variantId||0),parts=[];if(t.asset&&id)parts.push(`<button type=button data-operation-target=asset data-operation-variant="${id}">Asset</button>`);if(t.detectionCoverage&&id)parts.push(`<button type=button data-operation-target=coverage data-operation-variant="${id}">Coverage</button>`);if(t.evidence&&id)parts.push(`<button type=button data-operation-target=evidence data-operation-variant="${id}">Evidence</button>`);if(t.casework)parts.push(`<button type=button class=operations-case-pin data-operation-target=case data-operation-correlation="${esc(c.correlationId||'')}">Add to case</button>`);return parts.length?`<span class=operations-correlation-actions>${parts.join('')}</span>`:''}
 function caseReference(row){var c=row?.correlation||{},subject=row?.subject||{};return {operationsEventId:String(c.correlationId||''),runId:Number(c.runId||0),runNumber:Number(c.runNumber||0),jobId:Number(c.jobId||0),event:String(c.event||row?.event||''),emittedAtUtc:String(c.emittedAtUtc||row?.emittedAtUtc||''),component:String(c.component||row?.component||''),stage:String(c.stage||row?.stage||''),workerRole:String(row?.worker?.roleId||''),workerState:String(row?.worker?.state||row?.state||''),variantId:Number(c.variantId||subject.variantId||0),pluginId:Number(c.pluginId||subject.pluginId||0),internalName:String(c.internalName||subject.internalName||''),version:String(c.version||subject.version||''),sourceName:String(c.sourceName||subject.sourceName||'')}}
 async function openOperationAsset(id,tab){if(!id)return;setPerspective('investigator',{navigate:false});setWorkbenchView('assets');await loadDetail(id,tab||'overview')}
 function exactCoverageState(row){return String(row?.variantState||row?.status||'unknown')}
 function renderOperationCoverage(payload){var view=$('workbench-coverage');if(!view)return;var old=$('operationsCoverageFocus');if(old)old.remove();var identity=payload?.identity||{},summary=payload?.summary||{},rows=Array.isArray(payload?.collections)?payload.collections:[],host=document.createElement('section');host.id='operationsCoverageFocus';host.className='panel operations-coverage-focus';host.innerHTML=`<div class=detail><div class=operations-focus-head><div><div class=eyebrow>OPERATIONS CORRELATION · EXACT VARIANT</div><h2>${esc(identity.name||identity.internalName||('Variant '+identity.variantId))}</h2><div class="muted small">variant ${fmt(identity.variantId||0)}${identity.version?` · ${esc(identity.version)}`:''} · exact current-version producer coverage for the telemetry subject</div></div><div class=operations-focus-actions><button data-operation-focus-asset>Asset</button><button data-operation-focus-evidence>Evidence</button><button data-operation-focus-clear>Clear focus</button></div></div><div class=operations-focus-stats><span class=operations-focus-stat>${fmt(summary.current||0)} current</span><span class=operations-focus-stat>${fmt(summary.gaps||0)} gaps</span><span class=operations-focus-stat>${fmt(summary.outsideScope||0)} outside scope</span></div><div class=operations-coverage-list>${rows.map(r=>`<button class="operations-coverage-row ${esc(exactCoverageState(r))}" data-operation-coverage-collection="${esc(r.collection||'')}"><b>${esc(r.displayName||r.collection||'collection')}</b><span>${esc(exactCoverageState(r))} · ${esc(r.variantReason||'')}</span></button>`).join('')}</div><div class="muted small" style="margin-top:8px">This projection reuses the current Evidence-v2 producer-revision contract for exactly this variant. It is read-only and does not upgrade worker telemetry into Security Evidence.</div></div>`;var cards=$('coverageCards');if(cards)cards.insertAdjacentElement('afterend',host);else view.prepend(host);host.querySelector('[data-operation-focus-asset]')?.addEventListener('click',()=>openOperationAsset(Number(identity.variantId||0),'overview'));host.querySelector('[data-operation-focus-evidence]')?.addEventListener('click',()=>openOperationAsset(Number(identity.variantId||0),'evidence'));host.querySelector('[data-operation-focus-clear]')?.addEventListener('click',()=>host.remove());host.querySelectorAll('[data-operation-coverage-collection]').forEach(button=>button.addEventListener('click',()=>{selectedCoverageCollection=button.dataset.operationCoverageCollection;renderCoverageRows();renderCoverageDetail(selectedCoverageCollection);$('coverageDetail')?.scrollIntoView?.({block:'nearest'})}))}
 async function openOperationCoverage(id){if(!id)return;setPerspective('operations',{navigate:false});setWorkbenchView('coverage');await loadDetectionCoverage(false);var payload=await api('/api/operations/variant-coverage?variant_id='+encodeURIComponent(id));renderOperationCoverage(payload)}
 async function pinOperation(row){var c=row?.correlation||{},ref=caseReference(row),label=[ref.internalName||`Variant ${ref.variantId||'?'}`,ref.event||'operation'].filter(Boolean).join(' · ');await pinInvestigatorItem('operations-event',label,ref,'Sanitized omega.actions.telemetry.v1 operational context only; raw GitHub Actions logs are not stored in Investigator casework.')}
 function wireCorrelationActions(host,row){host.querySelectorAll('[data-operation-target]').forEach(button=>button.addEventListener('click',async event=>{event.preventDefault();event.stopPropagation();var target=button.dataset.operationTarget,id=Number(button.dataset.operationVariant||row?.correlation?.variantId||0);try{if(target==='asset')await openOperationAsset(id,'overview');else if(target==='coverage')await openOperationCoverage(id);else if(target==='evidence')await openOperationAsset(id,'evidence');else if(target==='case')await pinOperation(row)}catch(e){toniSay(`Could not open the correlated operations target: ${e.message}`)}}))}
 function decorateNode(node,row){if(!node||!row?.correlation)return;var id=String(row.correlation.correlationId||'');if(!id||node.dataset.operationsCorrelationId===id)return;node.dataset.operationsCorrelationId=id;var target=node.matches('.live-event')?node.querySelector('summary'):node;if(!target||target.querySelector('.operations-correlation-actions'))return;target.insertAdjacentHTML('beforeend',correlationActions(row));wireCorrelationActions(target,row)}
 function decorateActivity(activity){var current=Array.isArray(activity?.currentWork)?activity.currentWork:[],timeline=Array.isArray(activity?.timeline)?activity.timeline:[];document.querySelectorAll('#liveOperationsActivity .live-current-card').forEach((node,index)=>decorateNode(node,current[index]));document.querySelectorAll('#liveOperationsActivity .live-timeline .live-event').forEach((node,index)=>decorateNode(node,timeline[index]));document.querySelectorAll('#workflowLiveEvents .live-event').forEach((node,index)=>decorateNode(node,timeline[index]))}
 async function refreshCorrelation(){if(correlationInFlight)return;correlationInFlight=true;try{decorateActivity(await api('/api/operations/activity?foreground=1'))}catch(_e){}finally{correlationInFlight=false}}
 function scheduleCorrelation(){clearTimeout(correlationTimer);correlationTimer=setTimeout(refreshCorrelation,80)}
 var observer=new MutationObserver(records=>{var changed=records.some(record=>[...record.addedNodes].some(node=>{if(node?.nodeType!==1)return false;return !!(node.matches?.('.live-current-card,.live-event')||node.querySelector?.('.live-current-card,.live-event'))}));if(changed)scheduleCorrelation()});observer.observe(document.body,{childList:true,subtree:true});
 var baseOpenInvestigatorItem=openInvestigatorItem,baseInvestigatorItemOpenLabel=investigatorItemOpenLabel;
 investigatorItemOpenLabel=function(item){return item?.kind==='operations-event'?'Open operation':baseInvestigatorItemOpenLabel(item)};
 openInvestigatorItem=async function(itemId){var item=(currentInvestigatorCase?.items||[]).find(row=>row.itemId===itemId);if(item?.kind!=='operations-event')return baseOpenInvestigatorItem(itemId);var ref=item.reference||{},correlationId=String(ref.operationsEventId||'');setPerspective('operations',{navigate:false});setWorkbenchView('dashboard');try{var activity=await api('/api/operations/activity?foreground=1');decorateActivity(activity);await new Promise(resolve=>setTimeout(resolve,60));var node=[...document.querySelectorAll('[data-operations-correlation-id]')].find(candidate=>candidate.dataset.operationsCorrelationId===correlationId);if(node){if(node.tagName==='DETAILS')node.open=true;node.scrollIntoView({block:'center'});return}}catch(_e){}if(Number(ref.variantId||0)){toniSay('The exact retained operation is outside the current bounded activity view, so I opened its correlated asset instead.');await openOperationAsset(Number(ref.variantId),'overview');return}toniSay('The exact retained operation is outside the current bounded activity view. Its sanitized identity remains attached to this local case.')};
 scheduleCorrelation();
},0);
'''


def _patch_html(html: str) -> str:
    text = str(html)
    if "__deltascopeOperationsCorrelationInstalled" in text:
        return text
    script = _CORRELATION_JS.replace("__CORRELATION_CSS__", json.dumps(_CORRELATION_CSS))
    marker = "</script>"
    index = text.rfind(marker)
    if index < 0:
        raise RuntimeError("DeltaScope HTML script boundary was not found")
    return text[:index] + "\n" + script + "\n" + text[index:]


def install() -> None:
    """Install after retained operations history and the existing live-operations UI."""
    import developer_view

    if getattr(developer_view, "_deltascope_operations_correlation_installed", False):
        return

    cls = deltascope_operations.GitHubOperationsClient
    original_activity = cls.live_activity

    def correlated_activity(self: Any, *, foreground: bool = True, force: bool = False) -> dict[str, Any]:
        return correlate_activity(original_activity(self, foreground=foreground, force=force))

    cls.live_activity = correlated_activity
    developer_view.HTML = _patch_html(developer_view.HTML)
    original_get = developer_view.AppHandler.do_GET

    def patched_get(self: Any) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/api/operations/variant-coverage":
            return original_get(self)
        try:
            query = urllib.parse.parse_qs(parsed.query)
            variant_id = _int((query.get("variant_id") or [0])[0])
            if variant_id <= 0:
                raise ValueError("variant_id must be a positive integer")
            return self.json_response(
                deltascope_detection_coverage.project_variant_coverage(self.inspector, variant_id)
            )
        except ValueError as exc:
            return self.json_response({"error": str(exc)}, 400)
        except Exception as exc:
            return self.json_response({"error": str(exc)}, 500)

    developer_view.AppHandler.do_GET = patched_get
    developer_view._deltascope_operations_correlation_installed = True
