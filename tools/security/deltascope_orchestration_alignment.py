"""DeltaScope durable-work orchestration alignment.

The current Omega collection platform is queue/lease/result/settlement driven. GitHub Actions
remains useful runner diagnostics, but a workflow/job conclusion is not the authoritative health
state for a durable collector lane. This module keeps that distinction explicit without giving
DeltaScope mutation or security authority.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping, Sequence

SCHEMA = "omega.deltascope.orchestration-alignment.v1"
_INSTALLED = False

# The durable collection lanes published by security-work-state. Collector IDs are the stable
# DeltaScope/execution-topology identities; queue IDs are the orchestration identities.
QUEUE_TO_COLLECTOR: dict[str, str] = {
    "catalog-discovery": "source-discovery",
    "catalog-enrichment": "manifest-normalization",
    "catalog-scrape": "website-enrichment",
    "source-head-observation": "source-revision-observer",
    "threat-intelligence": "threat-intelligence",
    "osv-advisories": "advisory-collector",
    "secondary-security-definitions": "secondary-security-definitions",
}
COLLECTOR_TO_QUEUE = {collector: queue for queue, collector in QUEUE_TO_COLLECTOR.items()}

QUEUE_TITLES: dict[str, str] = {
    "catalog-discovery": "Catalog discovery",
    "catalog-enrichment": "Catalog enrichment",
    "catalog-scrape": "Website enrichment",
    "source-head-observation": "Source revision observation",
    "threat-intelligence": "Threat intelligence",
    "osv-advisories": "NuGet / OSV advisories",
    "secondary-security-definitions": "Secondary-security definitions",
}

QUEUE_WORKFLOWS: dict[str, str] = {
    "catalog-discovery": "catalog-discovery-worker.yml",
    "catalog-enrichment": "catalog-enrichment-worker.yml",
    "catalog-scrape": "catalog-scrape-worker.yml",
    "source-head-observation": "source-head-worker.yml",
    "threat-intelligence": "threat-intelligence-worker.yml",
    "osv-advisories": "osv-worker.yml",
    "secondary-security-definitions": "secondary-security-worker.yml",
}

# The exact current job/step names that are already part of the published topology. Empty names
# intentionally mean "do not pretend DeltaScope knows the exact runner child name"; the durable
# queue remains the health authority and Actions stay diagnostic.
COLLECTOR_CONTRACT_OVERRIDES: dict[str, dict[str, str]] = {
    "source-discovery": {
        "workflow": "catalog-discovery-worker.yml", "job": "", "step": "",
    },
    "manifest-normalization": {
        "workflow": "catalog-enrichment-worker.yml",
        "job": "Collect leased manifest enrichment working state",
        "step": "Enrich manifests from the settled discovery result",
    },
    "website-enrichment": {
        "workflow": "catalog-scrape-worker.yml", "job": "", "step": "",
    },
    "source-revision-observer": {
        "workflow": "source-head-worker.yml", "job": "", "step": "",
    },
    "threat-intelligence": {
        "workflow": "threat-intelligence-worker.yml", "job": "", "step": "",
    },
    "advisory-collector": {
        "workflow": "osv-worker.yml",
        "job": "Collect leased NuGet / OSV advisory working state",
        "step": "Query OSV for the exact retained NuGet package/version set",
    },
    "secondary-security-definitions": {
        "workflow": "secondary-security-worker.yml",
        "job": "Collect leased secondary-security working state",
        "step": "Refresh and freeze content-addressed secondary-security assets",
    },
}


def _int(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _rows(value: Any) -> list[Mapping[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return []
    return [item for item in value if isinstance(item, Mapping)]


def queue_state(queue: Mapping[str, Any]) -> dict[str, Any]:
    """Return the primary operational state of one durable queue.

    Historical completed work is healthy/settled when no active/problem work remains. A stale
    or failed Actions run cannot turn that state red; Actions are represented separately as
    diagnostic state.
    """
    counts = queue.get("counts") if isinstance(queue.get("counts"), Mapping) else {}
    terminal = _int(counts.get("terminal"))
    blocked = _int(counts.get("blocked"))
    leased = _int(counts.get("leased"))
    pending = _int(counts.get("pending"))
    completed = _int(counts.get("completed"))

    if terminal:
        state, label, explanation = (
            "failed", "terminal work",
            f"{terminal} work item(s) reached a terminal outcome and require operator review.",
        )
    elif blocked:
        state, label, explanation = (
            "warning", "blocked",
            f"{blocked} work item(s) are blocked by prerequisites or an unresolved condition.",
        )
    elif leased:
        state, label, explanation = (
            "running", "leased",
            f"{leased} work item(s) currently hold an active durable lease.",
        )
    elif pending:
        state, label, explanation = (
            "running", "queued",
            f"{pending} work item(s) are pending durable execution.",
        )
    elif completed:
        state, label, explanation = (
            "healthy", "settled",
            f"The lane is settled: {completed} completed item(s), with no pending, leased, blocked or terminal work.",
        )
    else:
        state, label, explanation = (
            "idle", "idle",
            "The durable queue currently contains no active, failed, blocked or completed work items.",
        )

    return {
        "schema": SCHEMA,
        "state": state,
        "label": label,
        "explanation": explanation,
        "counts": {
            "pending": pending, "leased": leased, "blocked": blocked,
            "completed": completed, "terminal": terminal,
        },
        "authority": "security-work-state",
    }


def work_queue_index(work_state: Mapping[str, Any] | None) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("queueId") or ""): dict(row)
        for row in _rows((work_state or {}).get("queues"))
        if str(row.get("queueId") or "")
    }


def align_collector_payload(payload: Mapping[str, Any], work_state: Mapping[str, Any] | None) -> dict[str, Any]:
    """Overlay durable queue truth on collector presentation data.

    The original runner state/trend/history are retained under ``runnerDiagnostic``. This helper
    is intentionally presentation-only and cannot alter queue/evidence state.
    """
    result = deepcopy(dict(payload))
    queues = work_queue_index(work_state)
    collectors: list[dict[str, Any]] = []
    for raw in _rows(payload.get("collectors")):
        row = deepcopy(dict(raw))
        collector_id = str(row.get("id") or "")
        queue_id = COLLECTOR_TO_QUEUE.get(collector_id, "")
        queue = queues.get(queue_id)
        if queue:
            primary = queue_state(queue)
            row["runnerDiagnostic"] = {
                "state": str(row.get("state") or "unknown"),
                "trendState": str(row.get("trendState") or "unknown"),
                "workflow": str(row.get("workflow") or ""),
                "latest": deepcopy(row.get("latest")),
                "history": deepcopy(row.get("history") or []),
                "error": str(row.get("error") or ""),
                "authority": "github-actions-diagnostic-only",
            }
            row["durableQueue"] = deepcopy(queue)
            row["state"] = primary["state"]
            row["trendState"] = primary["state"] if primary["state"] != "idle" else "healthy"
            row["stateAuthority"] = "security-work-state"
            row["stateExplanation"] = primary["explanation"]
            row["queueId"] = queue_id
            row["workflow"] = QUEUE_WORKFLOWS.get(queue_id, str(row.get("workflow") or ""))
            row["resultBranch"] = str(queue.get("resultBranch") or "")
        collectors.append(row)
    result["collectors"] = collectors
    result["healthAuthority"] = "security-work-state-when-durable-queue-exists"
    result["runnerAuthority"] = "github-actions-diagnostic-only"
    result["durableAlignedCount"] = sum(1 for row in collectors if row.get("stateAuthority") == "security-work-state")
    result["failingCount"] = sum(1 for row in collectors if row.get("state") == "failed")
    result["runningCount"] = sum(1 for row in collectors if row.get("state") == "running")
    result["unknownCount"] = sum(1 for row in collectors if row.get("state") in {"unknown", "unavailable"})
    return result


def durable_pipeline_components(work_state: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    """Project durable queues into the component shape consumed by the existing Operations UI."""
    result: list[dict[str, Any]] = []
    for raw in _rows((work_state or {}).get("queues")):
        queue = dict(raw)
        queue_id = str(queue.get("queueId") or "")
        primary = queue_state(queue)
        counts = primary["counts"]
        workflow = QUEUE_WORKFLOWS.get(queue_id, "")
        result.append({
            "componentId": f"durable:{queue_id}",
            "component": QUEUE_TITLES.get(queue_id, queue_id or "Durable work lane"),
            "state": primary["state"],
            "stateDetail": primary["explanation"],
            "runningCount": counts["leased"],
            "observed": True,
            "durable": True,
            "queueId": queue_id,
            "durableQueue": queue,
            "latestRun": {
                "workflow": workflow,
                "title": f"Durable {primary['label']} · {counts['completed']} completed · {counts['pending']} pending · {counts['blocked']} blocked",
                "branch": str(queue.get("resultBranch") or "security-work-state"),
                "createdAtUtc": str((work_state or {}).get("generatedAtUtc") or ""),
                "state": primary["state"],
                "stateDetail": primary["label"],
                "runNumber": 0,
                "sha": str(queue.get("queueRevision") or ""),
                "url": "",
                "readOnly": True,
            },
            "activeRun": None,
            "readOnly": True,
        })
    return result


def align_operations_payload(payload: Mapping[str, Any], work_state: Mapping[str, Any] | None) -> dict[str, Any]:
    result = deepcopy(dict(payload))
    durable = durable_pipeline_components(work_state)
    # Actions remain visible only as explicitly diagnostic stages. Retire the old aggregate
    # Catalog/Definitions and Source intake classifications from the primary pipeline because
    # their durable replacements are now first-class above.
    diagnostics: list[dict[str, Any]] = []
    for raw in _rows(payload.get("components")):
        component_id = str(raw.get("componentId") or "")
        if component_id in {"catalog-definitions", "source-intake"}:
            continue
        row = deepcopy(dict(raw))
        if not row.get("observed") and str(row.get("state") or "unknown") == "unknown":
            continue
        row["diagnosticOnly"] = True
        row["stateAuthority"] = "github-actions-diagnostic-only"
        label = str(row.get("component") or component_id or "Actions")
        row["component"] = f"Actions diagnostic · {label}"
        diagnostics.append(row)
    result["components"] = durable + diagnostics
    result["durableComponentCount"] = len(durable)
    result["healthAuthority"] = "security-work-state-for-collection-lanes"
    result["actionsAuthority"] = "diagnostic-only"
    return result


def apply_collector_contract_overrides(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Remove obsolete catalog-builder runner contracts from fallback/old topology rows."""
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in rows:
        row = dict(raw)
        collector_id = str(row.get("id") or "")
        override = COLLECTOR_CONTRACT_OVERRIDES.get(collector_id)
        if override:
            row.update(override)
            row["orchestrationContract"] = "durable-work-v1"
            row["queueId"] = COLLECTOR_TO_QUEUE.get(collector_id, "")
        out.append(row)
        if collector_id:
            seen.add(collector_id)

    # The stale bundled fallback predates this durable lane. Add the minimal presentation
    # contract rather than silently omitting it when published resources are unavailable.
    if "secondary-security-definitions" not in seen:
        out.append({
            "id": "secondary-security-definitions",
            "title": "Secondary-security definition refresh",
            "componentId": "omega.sigmascope",
            "cadenceMode": "scheduled",
            "docs": "collectors",
            "implementation": "tools/catalog/secondary_security_assets.py + tools/orchestration/work_result.py",
            "inputs": ["exact secondary-security durable lease", "previous frozen Definitions when available", "ClamAV update service"],
            "outputs": ["lease-bound secondary-security work result", "content-addressed ClamAV asset manifest"],
            "purpose": "Refresh secondary-security definition assets independently of catalog freeze.",
            "workflow": "secondary-security-worker.yml",
            "job": "Collect leased secondary-security working state",
            "step": "Refresh and freeze content-addressed secondary-security assets",
            "queueId": "secondary-security-definitions",
            "orchestrationContract": "durable-work-v1",
        })
    return out


def classify_current_workflow(path: str, name: str, branch: str, fallback: Any) -> tuple[str, str]:
    """Classify current workflow names before falling back to the legacy Actions classifier."""
    key = f"{path} {name}".casefold()
    mappings = (
        (("security-reconcile.yml", "security-orchestration-dispatch.yml", "security-orchestration-heartbeat.yml"), ("omega.platform.main", "Security work reconciler")),
        (("catalog-discovery-worker.yml", "catalog-discovery.yml"), ("omega.discovery", "Omega Discovery")),
        (("catalog-enrichment-worker.yml", "catalog-scrape-worker.yml", "catalog-freeze.yml", "catalog-builder.yml"), ("omega.catalog", "Catalog collection")),
        (("threat-intelligence-worker.yml",), ("omega.threat-intelligence", "Threat Intelligence")),
        (("source-head-worker.yml", "osv-worker.yml", "secondary-security-worker.yml", "sigmascope.yml", "sigmascope-parallel"), ("omega.sigmascope", "SigmaScope")),
    )
    for names, result in mappings:
        if any(value in key for value in names):
            return result
    return fallback(path, name, branch)


_CSS = r'''
.orchestration-authority-note{margin:0 20px 12px;padding:10px 12px;border-left:4px solid #0f62fe;background:#edf5ff;color:#393939;font-size:12px}
.orchestration-authority-note b{color:#161616}.orchestration-diagnostic{margin-top:12px;padding:9px 11px;border:1px solid #d8d8d8;background:#f4f4f4}
.orchestration-diagnostic.failed{border-left:4px solid #da1e28}.orchestration-diagnostic.warning{border-left:4px solid #f1c21b}.orchestration-diagnostic.healthy{border-left:4px solid #24a148}
.durable-counts{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}.durable-counts span{border:1px solid #d8d8d8;background:#fff;padding:7px 9px;font-size:11px}
.topology-node.durable::after{content:"DURABLE";font-size:9px;letter-spacing:.08em;color:#525252;margin-top:3px}.topology-node.diagnostic::after{content:"ACTIONS DIAGNOSTIC";font-size:9px;letter-spacing:.06em;color:#6f6f6f;margin-top:3px}
'''

_JS = r'''
setTimeout(()=>{
 if(window.__deltascopeOrchestrationAlignmentInstalled)return;
 window.__deltascopeOrchestrationAlignmentInstalled=true;
 const WORK_BASE='https://raw.githubusercontent.com/dalagab/omega/security-work-state/';
 const QUEUE_TO_COLLECTOR={
  'catalog-discovery':'source-discovery','catalog-enrichment':'manifest-normalization','catalog-scrape':'website-enrichment',
  'source-head-observation':'source-revision-observer','threat-intelligence':'threat-intelligence','osv-advisories':'advisory-collector',
  'secondary-security-definitions':'secondary-security-definitions'
 };
 const COLLECTOR_TO_QUEUE=Object.fromEntries(Object.entries(QUEUE_TO_COLLECTOR).map(([q,c])=>[c,q]));
 const QUEUE_TITLES={'catalog-discovery':'Catalog discovery','catalog-enrichment':'Catalog enrichment','catalog-scrape':'Website enrichment','source-head-observation':'Source revision observation','threat-intelligence':'Threat intelligence','osv-advisories':'NuGet / OSV advisories','secondary-security-definitions':'Secondary-security definitions'};
 const QUEUE_WORKFLOWS={'catalog-discovery':'catalog-discovery-worker.yml','catalog-enrichment':'catalog-enrichment-worker.yml','catalog-scrape':'catalog-scrape-worker.yml','source-head-observation':'source-head-worker.yml','threat-intelligence':'threat-intelligence-worker.yml','osv-advisories':'osv-worker.yml','secondary-security-definitions':'secondary-security-worker.yml'};
 let durableIndex=null,durableError='';
 function num(value){const n=Number(value||0);return Number.isFinite(n)?Math.max(0,n):0}
 function dstate(q){const c=q?.counts||{},terminal=num(c.terminal),blocked=num(c.blocked),leased=num(c.leased),pending=num(c.pending),completed=num(c.completed);if(terminal)return{state:'failed',label:'terminal work',detail:`${terminal} terminal work item(s) require review.`};if(blocked)return{state:'warning',label:'blocked',detail:`${blocked} work item(s) are blocked.`};if(leased)return{state:'running',label:'leased',detail:`${leased} active durable lease(s).`};if(pending)return{state:'running',label:'queued',detail:`${pending} work item(s) are pending execution.`};if(completed)return{state:'healthy',label:'settled',detail:`Settled: ${completed} completed; no pending, leased, blocked or terminal work.`};return{state:'unknown',label:'idle',detail:'No durable work has been retained for this lane yet.'}}
 async function durableWork(force=false){if(durableIndex&&!force)return durableIndex;try{const r=await fetch(WORK_BASE+'index.json',{cache:'no-store'});if(!r.ok)throw new Error(`HTTP ${r.status}`);const p=await r.json();if(p?.schema!=='omega.work-state.v1')throw new Error(`unexpected schema ${p?.schema||'unknown'}`);durableIndex=p;durableError='';return p}catch(e){durableError=String(e?.message||e);return null}}
 function queueMap(index){return new Map((index?.queues||[]).map(q=>[String(q.queueId||''),q]))}
 function alignCollectors(payload,index){if(!index)return payload;const qmap=queueMap(index),rows=(payload?.collectors||[]).map(raw=>{const c={...raw},qid=COLLECTOR_TO_QUEUE[String(c.id||'')],q=qmap.get(qid);if(!q)return c;const p=dstate(q);c.runnerDiagnostic={state:c.state||'unknown',trendState:c.trendState||'unknown',workflow:c.workflow||'',latest:c.latest||null,error:c.error||''};c.durableQueue=q;c.queueId=qid;c.state=p.state;c.trendState=p.state==='unknown'?'unknown':p.state==='running'?'healthy':p.state;c.stateAuthority='security-work-state';c.stateExplanation=p.detail;c.workflow=QUEUE_WORKFLOWS[qid]||c.workflow;c.resultBranch=q.resultBranch||'';return c});return{...payload,collectors:rows,healthAuthority:'security-work-state-when-durable-queue-exists',runnerAuthority:'github-actions-diagnostic-only'}}
 function durableComponents(index){return(index?.queues||[]).map(q=>{const p=dstate(q),c=q.counts||{},qid=String(q.queueId||'');return{componentId:'durable:'+qid,component:QUEUE_TITLES[qid]||qid,state:p.state,stateDetail:p.detail,runningCount:num(c.leased),observed:true,durable:true,queueId:qid,durableQueue:q,latestRun:{workflow:QUEUE_WORKFLOWS[qid]||'',title:`Durable ${p.label} · ${num(c.completed)} complete · ${num(c.pending)} pending · ${num(c.blocked)} blocked`,branch:q.resultBranch||'security-work-state',createdAtUtc:index.generatedAtUtc||'',state:p.state,stateDetail:p.label,runNumber:0,sha:q.queueRevision||'',url:'',readOnly:true},activeRun:null,readOnly:true}})}
 function alignOperations(payload,index){if(!index)return payload;const diagnostic=(payload?.components||[]).filter(c=>!['catalog-definitions','source-intake'].includes(String(c.componentId||''))).filter(c=>c.observed||String(c.state||'unknown')!=='unknown').map(c=>({...c,diagnosticOnly:true,stateAuthority:'github-actions-diagnostic-only',component:'Actions diagnostic · '+String(c.component||c.componentId||'Actions')}));return{...payload,components:[...durableComponents(index),...diagnostic],healthAuthority:'security-work-state-for-collection-lanes',actionsAuthority:'diagnostic-only'}}
 function countsHtml(q){const c=q?.counts||{};return `<div class=durable-counts><span><b>${fmt(num(c.completed))}</b> completed</span><span><b>${fmt(num(c.pending))}</b> pending</span><span><b>${fmt(num(c.leased))}</b> leased</span><span><b>${fmt(num(c.blocked))}</b> blocked</span><span><b>${fmt(num(c.terminal))}</b> terminal</span></div>`}
 function collectorDetail(c){const q=c?.durableQueue,primary=q?dstate(q):{state:String(c?.state||'unknown'),label:'runner-only',detail:'This stage has no mapped durable queue; GitHub runner status remains diagnostic context.'},runner=c?.runnerDiagnostic||{},runnerState=String(runner.state||'unknown');return `<div class=topology-detail-head><span class="topology-state ${esc(primary.state)}">${esc(primary.state)}</span><div><h2>${esc(c?.title||c?.id||'Collector')}</h2><p>${esc(primary.detail)}</p></div></div><div class=orchestration-authority-note><b>Health authority:</b> ${q?'durable <code>security-work-state</code> settlement. GitHub Actions is diagnostic only.':'no durable lane is mapped; this is runner diagnostic state only.'}</div>${q?countsHtml(q):''}<dl class=topology-detail-list><div><dt>Durable queue</dt><dd>${esc(c?.queueId||'—')}</dd></div><div><dt>Worker workflow</dt><dd>${esc(c?.workflow||'—')}</dd></div><div><dt>Result branch</dt><dd>${esc(c?.resultBranch||q?.resultBranch||'—')}</dd></div><div><dt>Required revision</dt><dd>${esc(q?.requiredRevision||'—')}</dd></div><div><dt>Consumes</dt><dd>${esc((c?.inputs||[]).join(', ')||'—')}</dd></div><div><dt>Produces</dt><dd>${esc((c?.outputs||[]).join(', ')||'—')}</dd></div><div><dt>Implementation</dt><dd>${esc(c?.implementation||'—')}</dd></div><div><dt>Runner diagnostic</dt><dd>${esc(runnerState)}${runner.workflow?` · ${esc(runner.workflow)}`:''}</dd></div></dl>${q&&runnerState&&runnerState!==primary.state?`<div class="orchestration-diagnostic ${esc(runnerState)}"><b>Runner diagnostic differs from durable health.</b><div class="muted small">Actions reports ${esc(runnerState)}; the durable lane reports ${esc(primary.label)}. The runner result does not override a successfully settled queue.</div></div>`:''}`}
 function renderDurableCollectorTopology(payload){const map=$('collectorTopology'),host=$('collectorTopologyNodes'),detail=$('collectorTopologyDetail'),rows=Array.isArray(payload?.collectors)?payload.collectors:[];if(!map||!host||!detail)return;const head=map.querySelector('.panelhead .muted.small');if(head)head.innerHTML='Primary health comes from durable work settlement where a queue exists. GitHub Actions remains runner diagnostics.';host.innerHTML=rows.map((c,i)=>`<button class="topology-node ${esc(String(c.state||'unknown'))} ${c.durableQueue?'durable':'diagnostic'}" data-aligned-collector="${i}"><span class="topology-state ${esc(String(c.state||'unknown'))}">${esc(String(c.state||'unknown'))}</span><b>${esc(c.title||c.id||'Collector')}</b><small>${c.durableQueue?`${esc(c.queueId||'')} · ${esc(dstate(c.durableQueue).label)}`:esc((c.outputs||[])[0]||c.workflow||'runner diagnostic')}</small></button>`).join('')||'<div class=workspace-empty>No collector definitions are registered.</div>';const show=i=>{host.querySelectorAll('[data-aligned-collector]').forEach(n=>n.classList.toggle('selected',Number(n.dataset.alignedCollector)===i));detail.innerHTML=collectorDetail(rows[i]||{})};host.querySelectorAll('[data-aligned-collector]').forEach(n=>n.addEventListener('click',()=>show(Number(n.dataset.alignedCollector))));if(rows.length)show(0)}
 function pipelineDetail(c){const q=c?.durableQueue,run=c?.activeRun||c?.latestRun||{},state=String(c?.state||'unknown');if(q){const p=dstate(q);return `<div class=topology-detail-head><span class="topology-state ${esc(state)}">${esc(state)}</span><div><h2>${esc(c.component||c.queueId||'Durable lane')}</h2><p>${esc(p.detail)}</p></div></div><div class=orchestration-authority-note><b>Primary platform state:</b> durable queue/lease/result/settlement. Actions are shown separately as diagnostics.</div>${countsHtml(q)}<dl class=topology-detail-list><div><dt>Queue</dt><dd>${esc(c.queueId||'')}</dd></div><div><dt>Worker</dt><dd>${esc(run.workflow||'—')}</dd></div><div><dt>Result branch</dt><dd>${esc(q.resultBranch||'—')}</dd></div><div><dt>Required revision</dt><dd>${esc(q.requiredRevision||'—')}</dd></div><div><dt>Queue revision</dt><dd>${esc(q.queueRevision||'—')}</dd></div><div><dt>Observed</dt><dd>${esc(run.createdAtUtc||'—')}</dd></div></dl>`}return `<div class=topology-detail-head><span class="topology-state ${esc(state)}">${esc(state)}</span><div><h2>${esc(c.component||c.componentId||'Actions diagnostic')}</h2><p>${esc(run.title||'Recent GitHub Actions observation.')}</p></div></div><div class=orchestration-authority-note><b>Diagnostic only:</b> this Actions result is useful for runner troubleshooting but does not override durable collection settlement.</div><dl class=topology-detail-list><div><dt>Workflow</dt><dd>${esc(run.workflow||'—')}</dd></div><div><dt>Result</dt><dd>${esc(run.stateDetail||run.conclusion||state)}</dd></div><div><dt>Branch</dt><dd>${esc(run.branch||'—')}</dd></div><div><dt>Observed</dt><dd>${esc(run.createdAtUtc||'—')}</dd></div></dl>${run.url?`<div class=topology-detail-actions><a class=button-link href="${esc(run.url)}" target=_blank rel="noopener noreferrer">Open GitHub diagnostic</a></div>`:''}`}
 function renderDurablePipeline(payload){const host=$('operationsTopologyNodes'),detail=$('eventCasePanel'),rows=Array.isArray(payload?.components)?payload.components:[];if(!host||!detail)return;const map=$('operationsTopology'),head=map?.querySelector('.panelhead .muted.small');if(head)head.innerHTML='Durable collection lanes are primary. GitHub Actions stages are appended as diagnostic observations.';host.innerHTML=rows.map((c,i)=>`<button class="topology-node ${esc(String(c.state||'unknown'))} ${c.durable?'durable':'diagnostic'}" data-aligned-pipeline="${i}"><span class="topology-state ${esc(String(c.state||'unknown'))}">${esc(String(c.state||'unknown'))}</span><b>${esc(c.component||c.componentId||'Stage')}</b><small>${c.durable?`${esc(c.queueId||'')} · ${esc(dstate(c.durableQueue).label)}`:esc((c.activeRun||c.latestRun||{}).workflow||'Actions diagnostic')}</small></button>`).join('')||'<div class=workspace-empty>No operational stages are available.</div>';const show=i=>{host.querySelectorAll('[data-aligned-pipeline]').forEach(n=>n.classList.toggle('selected',Number(n.dataset.alignedPipeline)===i));detail.innerHTML=pipelineDetail(rows[i]||{})};host.querySelectorAll('[data-aligned-pipeline]').forEach(n=>n.addEventListener('click',()=>show(Number(n.dataset.alignedPipeline))));if(rows.length)show(0)}
 const renderCollectorsBase=renderCollectors;
 renderCollectors=function(payload){const aligned=alignCollectors(payload,durableIndex);renderCollectorsBase(aligned);renderDurableCollectorTopology(aligned);return aligned};
 const renderOperationsBase=renderOperations;
 renderOperations=function(payload){const aligned=alignOperations(payload,durableIndex);renderOperationsBase(aligned);renderDurablePipeline(aligned);return aligned};
 const loadCollectorsBase=loadCollectors;
 loadCollectors=async function(refresh=false){await durableWork(refresh);return loadCollectorsBase(refresh)};
 const loadOperationsBase=loadOperations;
 loadOperations=async function(refresh=false){await durableWork(refresh);return loadOperationsBase(refresh)};
 const setWorkbenchViewBase=setWorkbenchView;
 setWorkbenchView=function(name){const result=setWorkbenchViewBase(name);if(currentPerspective==='operations'&&name==='queue'){const h=document.querySelector('#workbench-queue .workspace-heading p');if(h)h.textContent='Artifact/source analysis queue for plugin coverage and follow-up. This is separate from the seven generic durable collection lanes shown under Pipelines and Collectors.'}return result};
 durableWork(false).then(()=>{if(currentPerspective==='operations'){if(currentCollectors)renderCollectors(currentCollectors);if(typeof currentOperations!=='undefined'&&currentOperations)renderOperations(currentOperations)}});
},0);
'''


def _insert_before_last(text: str, marker: str, payload: str) -> str:
    index = text.rfind(marker)
    if index < 0:
        raise RuntimeError(f"DeltaScope HTML boundary not found: {marker}")
    return text[:index] + payload + text[index:]


def _install_python_alignment() -> None:
    import deltascope_collectors
    import deltascope_operations

    if not getattr(deltascope_collectors, "_orchestration_alignment_installed", False):
        base_execution_nodes = deltascope_collectors.execution_nodes

        def aligned_execution_nodes(execution_topology: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
            return apply_collector_contract_overrides(base_execution_nodes(execution_topology))

        deltascope_collectors.execution_nodes = aligned_execution_nodes
        deltascope_collectors._orchestration_alignment_installed = True

    if not getattr(deltascope_operations, "_orchestration_alignment_installed", False):
        base_component = deltascope_operations._component

        def aligned_component(path: str, name: str, branch: str) -> tuple[str, str]:
            return classify_current_workflow(path, name, branch, base_component)

        deltascope_operations._component = aligned_component
        deltascope_operations.EXPECTED_COMPONENTS = (
            ("omega.platform.main", "Security work reconciler"),
            ("omega.discovery", "Omega Discovery"),
            ("omega.catalog", "Catalog collection"),
            ("omega.sigmascope", "SigmaScope"),
            ("omega.threat-intelligence", "Threat Intelligence"),
            ("deep-scan", "Deep Scan"),
            ("deltascope", "DeltaScope"),
            ("security-regression", "Security regression"),
            ("omega-builds", "Omega builds"),
        )
        deltascope_operations._orchestration_alignment_installed = True


def install() -> None:
    global _INSTALLED
    if _INSTALLED:
        return
    _install_python_alignment()
    import developer_view

    if "__deltascopeOrchestrationAlignmentInstalled" not in developer_view.HTML:
        html = developer_view.HTML
        html = _insert_before_last(html, "</style>", "\n" + _CSS + "\n")
        html = _insert_before_last(html, "</script>", "\n" + _JS + "\n")
        developer_view.HTML = html
    _INSTALLED = True
