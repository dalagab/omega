"""Authenticated client-delivery telemetry dashboard for DeltaScope."""
from __future__ import annotations

import json
import urllib.parse
from typing import Any, Mapping

import deltascope_scan_queue

SCHEMA = "omega.deltascope.delivery-dashboard.v1"


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _revision(source: Mapping[str, Any], *names: str) -> str:
    for name in names:
        value = str(source.get(name) or "").strip()
        if value:
            return value
    return ""


def project_delivery_dashboard(client: Any, inspector: Any) -> dict[str, Any]:
    """Project acquired snapshots only; page navigation never performs remote I/O."""
    access = client.access_status()
    if not access.get("tokenConfigured"):
        return {
            "schema": SCHEMA, "available": False, "authenticated": False,
            "state": "authentication-required", "readOnly": True, "mutationAuthority": "none",
            "navigationRefresh": False, "refreshPolicy": "explicit-only", "access": access,
            "notice": "Connect GitHub access to view client release and pipeline telemetry.",
        }

    delivery = client.client_delivery(refresh=False)
    if not delivery.get("available"):
        return {
            "schema": SCHEMA, "available": False, "authenticated": True,
            "state": "unknown", "readOnly": True, "mutationAuthority": "none",
            "navigationRefresh": False, "refreshPolicy": "explicit-only", "access": access,
            "fetchedAtUtc": str(delivery.get("fetchedAtUtc") or ""),
            "error": str(delivery.get("error") or "Client delivery snapshot has not been acquired."),
        }

    summary = inspector.summary()
    counts = _mapping(summary.get("counts"))
    revisions = _mapping(summary.get("revisions") or summary.get("meta"))
    queue_state = inspector.scan_queue_state() if hasattr(inspector, "scan_queue_state") else {}
    queue = deltascope_scan_queue.project_scan_queue(
        queue_state, current_variants=int(counts.get("variants") or 0), next_limit=8,
    )
    operations = client.status(refresh=False)
    manifest = _mapping(delivery.get("manifest"))
    inputs = _mapping(manifest.get("inputs"))
    output = _mapping(manifest.get("output"))
    materialized = _mapping(manifest.get("materializedEvidence"))
    projection = _mapping(manifest.get("projectionIntegrity") or manifest.get("projection"))

    comparisons = [
        ("Catalog", _revision(revisions, "catalogDataRevision", "catalogRevision"), _revision(inputs, "catalogRevision")),
        ("Definitions", _revision(revisions, "definitionsRevision"), _revision(inputs, "definitionsRevision")),
        ("Evidence", _revision(revisions, "evidenceRevision"), _revision(inputs, "evidenceRevision")),
        ("Security", _revision(revisions, "securityRevision"), _revision(inputs, "securityRevision")),
    ]
    revision_rows = [{
        "name": name, "current": current, "client": embedded,
        "state": "match" if current and embedded and current == embedded else "different" if current and embedded else "unknown",
    } for name, current, embedded in comparisons]
    drift = [row for row in revision_rows if row["state"] == "different"]
    publisher = _mapping(delivery.get("publisherRun"))
    if publisher.get("state") == "running":
        state = "publishing"
    elif publisher.get("state") == "failed":
        state = "blocked"
    elif drift:
        state = "new-data"
    else:
        state = "ready"

    failed_runs = [
        dict(row) for row in operations.get("events") or []
        if isinstance(row, Mapping) and row.get("state") == "failed"
    ][:8]
    return {
        "schema": SCHEMA, "available": True, "authenticated": True, "state": state,
        "readOnly": True, "mutationAuthority": "none", "navigationRefresh": False,
        "refreshPolicy": "explicit-only", "access": access,
        "fetchedAtUtc": str(delivery.get("fetchedAtUtc") or ""),
        "release": dict(_mapping(delivery.get("release"))),
        "publisherRun": dict(publisher), "revisions": revision_rows,
        "newDataAvailable": bool(drift), "queue": queue,
        "operations": {
            "running": int(operations.get("actionsRunning") or 0),
            "recentFailures": int(operations.get("recentFailureCount") or 0),
            "failedRuns": failed_runs,
        },
        "build": {
            "schema": str(manifest.get("schema") or ""),
            "generatedAtUtc": str(manifest.get("generatedAtUtc") or ""),
            "variantCount": int(output.get("variantCount") or 0),
            "logicalPluginCount": int(output.get("logicalPluginCount") or 0),
            "sourceCount": int(output.get("sourceCount") or 0),
            "bundleSha256": str(output.get("bundleSha256") or ""),
            "databaseSha256": str(output.get("databaseSha256") or ""),
            "evidenceCompatible": bool(inputs.get("evidenceCompatible")),
            "currentVariantsAvailable": int(materialized.get("currentVariantsAvailable") or 0),
            "currentVariantsMaterialized": int(materialized.get("currentVariantsMaterialized") or 0),
            "materializedDatasets": dict(_mapping(materialized.get("datasets"))),
            "projectionIntegrity": dict(projection),
            "projectionStatus": "ok" if bool(inputs.get("evidenceCompatible")) and int(materialized.get("currentVariantsAvailable") or 0) == int(materialized.get("currentVariantsMaterialized") or 0) else "attention",
        },
    }


_DELIVERY_VIEW = r'''
<section id="workbench-delivery" class="workspace-view" data-workbench-view="delivery">
 <div class="delivery-head"><div><div class="eyebrow">CLIENT DATA / AUTHENTICATED TELEMETRY</div><h1>Data Delivery</h1><p>See when a new client bundle is ready, what it contains, and what remains in the pipeline.</p></div><button id="deliveryRefresh">Refresh GitHub telemetry</button></div>
 <div id="deliveryBody" class="panel"><div class="workspace-empty">Loading acquired delivery snapshot...</div></div>
</section>
<section id="workbench-contracts" class="workspace-view" data-workbench-view="contracts">
 <div class="delivery-head"><div><div class="eyebrow">VERIFIED DEFINITIONS / READ ONLY</div><h1>Contract Explorer</h1><p>Trace snapshots into definition packs, rulesets, rules, fixtures, registries, and their exact SHA-256-verified cached contents.</p></div><span class="badge ro">NO MUTATION AUTHORITY</span></div>
 <div class="contract-toolbar panel"><label>Snapshot <select id="contractSnapshot"></select></label><input id="contractSearch" type="search" placeholder="Filter packs, rules, revisions, or paths"><span id="contractSummary" class="muted small"></span></div>
 <div class="contract-layout"><aside class="panel contract-tree-panel"><div id="contractTree" class="contract-tree"><div class="workspace-empty">Loading verified inventory...</div></div></aside><section id="contractDetail" class="panel contract-detail"><div class="workspace-empty">Select a contract resource to review its exact contents.</div></section></div>
</section>
'''

_DELIVERY_CSS = r'''
#workbench-delivery{gap:12px;overflow:auto}.delivery-head{display:flex;justify-content:space-between;align-items:flex-end;gap:18px}.delivery-head h1{margin:2px 0 4px;font-size:27px}.delivery-head p{margin:0;color:#525252}.delivery-hero{padding:18px;border-left:6px solid #8d8d8d}.delivery-hero.ready{border-color:#24a148;background:#defbe6}.delivery-hero.new-data,.delivery-hero.publishing{border-color:#0f62fe;background:#edf5ff}.delivery-hero.blocked{border-color:#da1e28;background:#fff1f1}.delivery-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr))}.delivery-metric,.delivery-section{padding:13px;border:1px solid #c6c6c6}.delivery-metric b{display:block;font-size:19px;font-weight:400;overflow-wrap:anywhere}.delivery-metric span{font-size:10px;color:#525252;text-transform:uppercase}.delivery-sections{display:grid;grid-template-columns:1fr 1fr;gap:12px;padding:12px;background:#f4f4f4}.delivery-section{background:#fff}.delivery-section h3{margin:0 0 8px}.delivery-row{display:grid;grid-template-columns:100px minmax(0,1fr) minmax(0,1fr) 70px;gap:8px;padding:7px 0;border-top:1px solid #e0e0e0;font-size:11px}.delivery-row code{overflow-wrap:anywhere}.delivery-state{font-weight:700}.delivery-state.match{color:#198038}.delivery-state.different{color:#0043ce}.delivery-asset,.delivery-run{padding:7px 0;border-top:1px solid #e0e0e0}.delivery-gate{padding:30px}.security-telemetry-panel{grid-column:1/-1}.security-telemetry-grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:8px;padding:14px}.security-telemetry-card{border:1px solid #c6c6c6;padding:12px;min-width:0}.security-telemetry-card .count{font-size:24px}.security-telemetry-card code{display:block;font-size:9px;overflow-wrap:anywhere;margin-top:7px}.security-telemetry-scanner{padding:12px 14px;background:#edf5ff;border-left:4px solid #0f62fe}.security-engine-list{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}@media(max-width:1000px){.delivery-grid{grid-template-columns:repeat(2,1fr)}.security-telemetry-grid{grid-template-columns:repeat(2,1fr)}.delivery-sections{grid-template-columns:1fr}}@media(max-width:650px){.delivery-head{align-items:flex-start;flex-direction:column}.delivery-grid{grid-template-columns:1fr}.delivery-row{grid-template-columns:1fr}}
#workbench-contracts{overflow:hidden}.contract-toolbar{display:flex;align-items:center;gap:10px;padding:10px 12px;flex:0 0 auto}.contract-toolbar label{display:flex;align-items:center;gap:7px}.contract-toolbar input{flex:1;min-width:220px}.contract-layout{display:grid;grid-template-columns:minmax(330px,38%) minmax(0,1fr);gap:12px;min-height:0;flex:1}.contract-tree-panel,.contract-detail{min-height:0;overflow:auto}.contract-tree{padding:8px}.contract-group{margin-bottom:8px;border:1px solid #d9dde2}.contract-group>summary{padding:9px 10px;background:#f4f4f4}.contract-pack{margin:6px 8px;border-left:3px solid #8a3ffc;padding-left:7px}.contract-pack>summary{padding:7px}.contract-resource{display:block;width:100%;border:0;border-top:1px solid #e0e0e0;background:#fff;text-align:left;padding:8px 10px}.contract-resource:hover,.contract-resource.selected{background:#edf5ff;box-shadow:inset 3px 0 #0f62fe}.contract-resource b,.contract-resource code{display:block;overflow-wrap:anywhere}.contract-kind{font-size:9px;color:#525252;text-transform:uppercase}.contract-detail-head{padding:14px;border-bottom:1px solid #d9dde2}.contract-detail-head h2{margin:2px 0 5px}.contract-actions{display:flex;gap:7px;flex-wrap:wrap;margin-top:10px}.contract-meta{display:grid;grid-template-columns:130px minmax(0,1fr);gap:6px 10px;padding:12px 14px;border-bottom:1px solid #d9dde2}.contract-meta code{overflow-wrap:anywhere}.contract-content{margin:0;padding:14px;white-space:pre;overflow:auto;font:12px/1.5 Consolas,monospace;background:#101418;color:#f4f4f4;min-height:260px}.security-telemetry-card{cursor:pointer;text-align:left;background:#fff}.security-telemetry-card:hover{border-color:#0f62fe;background:#edf5ff}@media(max-width:900px){.contract-layout{grid-template-columns:1fr}.contract-tree-panel{max-height:38vh}}
'''

_DELIVERY_JS = r'''
setTimeout(function(){
 if(window.__deltascopeDeliveryDashboardInstalled)return;window.__deltascopeDeliveryDashboardInstalled=true;
 var main=document.querySelector('main');if(!main)return;
 if(!$('workbench-delivery'))main.insertAdjacentHTML('beforeend',__DELIVERY_VIEW__);
 var gateGrid=document.querySelector('#workbench-ops-gates .ops-page-grid');if(gateGrid&&!$('opsSecurityTelemetryPanel'))gateGrid.insertAdjacentHTML('afterbegin','<section id="opsSecurityTelemetryPanel" class="panel security-telemetry-panel"><div class="panelhead"><div><h2>Security contract inventory</h2><div class="muted small">Verified scanner, semantic-analysis, threat-intelligence, source-observation, and secondary-engine telemetry from the published Definitions trust anchor.</div></div><span class="badge ro">PUBLISHED / READ ONLY</span></div><div id="opsSecurityTelemetry"><div class="workspace-empty">Loading published security contracts...</div></div></section>');
 var style=document.createElement('style');style.textContent=__DELIVERY_CSS__;document.head.appendChild(style);
 var operate=(perspectiveConfig.operations&&perspectiveConfig.operations.groups||[]).find(function(group){return group.label==='Operate'});
 if(operate&&!operate.items.some(function(item){return item.view==='delivery'}))operate.items.unshift({label:'Data Delivery',mark:'D',view:'delivery'});
 var reference=(perspectiveConfig.operations&&perspectiveConfig.operations.groups||[]).find(function(group){return group.label==='Reference'});
 if(reference&&!reference.items.some(function(item){return item.view==='contracts'}))reference.items.unshift({label:'Contract Explorer',mark:'C',view:'contracts'});
 if(currentPerspective==='operations')renderPerspectiveNav();
 function metric(label,value){return '<div class="delivery-metric"><b>'+esc(String(value==null?'not available':value))+'</b><span>'+esc(label)+'</span></div>'}
 function title(state){return ({ready:'Client data is ready','new-data':'New data is waiting for a client bundle',publishing:'A new client bundle is publishing',blocked:'Client publication needs attention',unknown:'Delivery state is unavailable'})[state]||state}
 function render(data){
  var host=$('deliveryBody');if(!host)return;
  if(!data.authenticated){host.innerHTML='<div class="delivery-gate"><h2>GitHub authentication required</h2><p>'+esc(data.notice||'Connect GitHub access to inspect delivery telemetry.')+'</p><button data-open-github-access>Connect GitHub access</button></div>';host.querySelector('[data-open-github-access]').addEventListener('click',function(){var item=document.querySelector('[data-app-action="github-access"]');if(item)item.click()});return}
  if(!data.available){host.innerHTML='<div class="delivery-gate"><h2>Acquire delivery telemetry</h2><p>'+esc(data.error||'No client delivery snapshot is loaded.')+'</p><button data-delivery-acquire>Refresh GitHub telemetry</button></div>';host.querySelector('[data-delivery-acquire]').addEventListener('click',refresh);return}
  var b=data.build||{},q=data.queue&&data.queue.counts||{},op=data.operations||{},pub=data.publisherRun||{},release=data.release||{};
  var revisions=(data.revisions||[]).map(function(row){return '<div class="delivery-row"><b>'+esc(row.name)+'</b><code>'+esc(row.current||'not available')+'</code><code>'+esc(row.client||'not embedded')+'</code><span class="delivery-state '+esc(row.state)+'">'+esc(row.state.toUpperCase())+'</span></div>'}).join('');
  var assets=(release.assets||[]).map(function(asset){var name=asset.url?'<a href="'+esc(asset.url)+'" target="_blank" rel="noopener noreferrer">'+esc(asset.name)+'</a>':esc(asset.name);return '<div class="delivery-asset">'+name+' <span class="muted">'+fmt(asset.bytes||0)+' bytes / '+fmt(asset.downloadCount||0)+' downloads</span></div>'}).join('');
  var releaseLink=release.url?'<p><a href="'+esc(release.url)+'" target="_blank" rel="noopener noreferrer">Open catalog-latest on GitHub</a></p>':'';
  var publisher=pub.runId?'<div class="delivery-run"><a href="'+esc(pub.url||'#')+'" target="_blank" rel="noopener noreferrer">'+esc(pub.title||pub.workflow||'Client publish')+'</a><div class="muted">'+esc(pub.state||'unknown')+' / run #'+fmt(pub.runNumber||0)+' / '+esc(pub.updatedAtUtc||'')+'</div></div>':'<div class="muted">No client-publish run is present in the acquired Actions window.</div>';
  host.innerHTML='<div class="delivery-hero '+esc(data.state)+'"><h2>'+esc(title(data.state))+'</h2><div>'+(data.newDataAvailable?'Published revisions differ from the current client bundle.':'The client release matches the acquired published revisions.')+'</div><div class="muted small">Snapshot '+esc(data.fetchedAtUtc||'not available')+' / navigation never refreshes data</div></div><div class="delivery-grid">'+metric('Client release',release.publishedAtUtc||'not available')+metric('Plugins',fmt(b.logicalPluginCount||0))+metric('Variants',fmt(b.variantCount||0))+metric('Queue pending',fmt(q.pending||0))+metric('Current evidence',fmt(b.currentVariantsMaterialized||0)+' / '+fmt(b.currentVariantsAvailable||0))+metric('Actions running',fmt(op.running||0))+metric('Recent failures',fmt(op.recentFailures||0))+metric('Projection integrity',String(b.projectionStatus||'unknown').toUpperCase())+'</div><div class="delivery-sections"><section class="delivery-section"><h3>Revision readiness</h3>'+revisions+'</section><section class="delivery-section"><h3>Client release assets</h3>'+releaseLink+(assets||'<div class="muted">No release assets reported.</div>')+'</section><section class="delivery-section"><h3>Publisher</h3>'+publisher+'<p class="muted small">Use Workflow Center for jobs, steps, artifacts, logs, cancellation, or reruns.</p></section><section class="delivery-section"><h3>Queue and build telemetry</h3><div class="kv"><b>Queue mode</b><span>'+esc(data.queue.headline||'unknown')+'</span><b>First coverage</b><span>'+fmt(q.firstCoverage||0)+'</span><b>Retries</b><span>'+fmt(q.retry||0)+'</span><b>Sources</b><span>'+fmt(b.sourceCount||0)+'</span><b>Evidence compatible</b><span>'+(b.evidenceCompatible?'YES':'NO')+'</span><b>Database SHA-256</b><code>'+esc(b.databaseSha256||'not available')+'</code></div></section></div>';
 }
 var contractInventory=null,contractSelectedPath='',contractFocus='';
 function resourceButton(item){return '<button class="contract-resource'+(item.path===contractSelectedPath?' selected':'')+'" data-contract-path="'+esc(item.path)+'"><span class="contract-kind">'+esc(item.kind||'resource')+' · '+fmt(item.bytes||0)+' bytes</span><b>'+esc(item.label||item.path)+'</b><code>'+esc(item.path)+'</code></button>'}
 function renderContractTree(){var host=$('contractTree');if(!host||!contractInventory)return;var query=String($('contractSearch').value||'').toLowerCase(),groups=(contractInventory.groups||[]).filter(function(group){return !contractFocus||group.id===contractFocus});var html=groups.map(function(group){var direct=(group.resources||[]).map(resourceButton).join(''),children=(group.children||[]).map(function(child){var hay=JSON.stringify(child).toLowerCase();if(query&&hay.indexOf(query)<0)return '';return '<details class="contract-pack" open><summary><b>'+esc(child.label||child.id)+'</b><div class="muted small">'+esc(child.id||'')+' · '+esc(child.metadata&&child.metadata.trustTier||'')+' · '+(child.metadata&&child.metadata.productionEligible?'production eligible':'not production eligible')+'</div></summary>'+(child.resources||[]).map(resourceButton).join('')+'</details>'}).join('');var hay=(JSON.stringify(group.resources||[])+group.label).toLowerCase();if(query&&hay.indexOf(query)<0&&!children)return '';return '<details class="contract-group" open><summary><b>'+esc(group.label)+'</b><span class="muted small"> '+fmt((group.resources||[]).length+(group.children||[]).length)+' entries</span></summary>'+direct+children+'</details>'}).join('');host.innerHTML=html||'<div class="workspace-empty">No verified contract matches this filter.</div>';host.querySelectorAll('[data-contract-path]').forEach(function(button){button.addEventListener('click',function(){openContractResource(button.dataset.contractPath)})})}
 async function openContractResource(path){contractSelectedPath=path;renderContractTree();var host=$('contractDetail');host.innerHTML='<div class="workspace-empty">Verifying cached bytes...</div>';try{var snapshot=$('contractSnapshot').value||'',row=await api('/api/platform-contracts/resource?revision='+encodeURIComponent(snapshot)+'&path='+encodeURIComponent(path));host.innerHTML='<div class="contract-detail-head"><div class="eyebrow">VERIFIED '+esc(String(path).split('.').pop().toUpperCase())+'</div><h2>'+esc(path)+'</h2><div class="muted small">Exact cached content from '+esc(row.definitionsRevision)+'</div><div class="contract-actions"><button id="contractCopy">Copy exact content</button><button id="contractDownload">Download file</button></div></div><div class="contract-meta"><b>SHA-256</b><code>'+esc(row.sha256)+'</code><b>Bytes</b><span>'+fmt(row.bytes)+'</span><b>Integrity</b><span class="pass">VERIFIED AGAINST SNAPSHOT MANIFEST</span><b>Authority</b><span>Published / read only</span></div><pre class="contract-content">'+esc(row.content)+'</pre>';$('contractCopy').addEventListener('click',function(){navigator.clipboard.writeText(row.content)});$('contractDownload').addEventListener('click',function(){var blob=new Blob([row.content],{type:'text/plain;charset=utf-8'}),link=document.createElement('a');link.href=URL.createObjectURL(blob);link.download=String(row.path).split('/').pop()||'contract.txt';link.click();setTimeout(function(){URL.revokeObjectURL(link.href)},0)})}catch(error){host.innerHTML='<div class="delivery-gate fail">Contract could not be verified: '+esc(error.message)+'</div>'}}
 async function loadContractInventory(focus){if(focus!==undefined)contractFocus=focus||'';var snapshot=$('contractSnapshot').value||'',host=$('contractTree');host.innerHTML='<div class="workspace-empty">Loading verified inventory...</div>';try{contractInventory=await api('/api/platform-contracts/inventory?revision='+encodeURIComponent(snapshot));var select=$('contractSnapshot'),selected=snapshot;select.innerHTML=(contractInventory.snapshots||[]).map(function(row){return '<option value="'+esc(row.snapshotName)+'" '+((selected&&row.snapshotName===selected)||(!selected&&row.current)?'selected':'')+'>'+esc(row.definitionsRevision)+(row.current?' · current':'')+' · '+fmt(row.fileCount)+' files</option>'}).join('');$('contractSummary').textContent=contractInventory.definitionsRevision+' · verified immutable cache';renderContractTree();if(contractFocus){var group=(contractInventory.groups||[]).find(function(item){return item.id===contractFocus});var first=group&&group.resources&&group.resources[0];if(first)openContractResource(first.path)}}catch(error){host.innerHTML='<div class="delivery-gate fail">Contract inventory unavailable: '+esc(error.message)+'</div>'}}
 function openContractExplorer(group){contractFocus=group||'';setWorkbenchView('contracts');loadContractInventory(contractFocus)}
 function renderSecurityTelemetry(payload){var host=$('opsSecurityTelemetry');if(!host)return;var telemetry=payload&&payload.securityTelemetry;if(!payload||!payload.available||!telemetry){host.innerHTML='<div class="delivery-gate"><b>Published security contracts are unavailable.</b><div class="muted small">'+esc(payload&&payload.error||payload&&payload.warning||'Restart DeltaScope after a successful published-resource synchronization.')+'</div></div>';return}var scanner=telemetry.scanner||{},engines=(telemetry.secondaryEngines||[]).map(function(engine){return '<span class="pill '+(engine.status==='configured'?'pass':'')+'">'+esc(engine.engine||'engine')+' '+esc(engine.status||'unknown')+'</span>'}).join('');var cards=(telemetry.contracts||[]).map(function(contract){return '<button class="security-telemetry-card" data-contract-group="'+esc(contract.id)+'"><b>'+esc(contract.label||contract.id)+'</b><div class="count">'+fmt(contract.primaryCount||0)+'</div><div class="muted small">'+esc(contract.detail||'')+'</div><code>'+esc(contract.revision||'revision unavailable')+'</code></button>'}).join('');host.innerHTML='<div class="security-telemetry-scanner"><b>SigmaScope '+esc(scanner.version||'version unavailable')+'</b><div class="muted small">'+esc(scanner.revision||'scanner revision unavailable')+' / artifact '+esc(scanner.artifactAnalysisRevision||'unavailable')+' / source '+esc(scanner.sourceAnalysisRevision||'unavailable')+'</div><div class="security-engine-list">'+engines+'</div></div><div class="security-telemetry-grid">'+cards+'</div>';host.querySelectorAll('[data-contract-group]').forEach(function(button){button.addEventListener('click',function(){openContractExplorer(button.dataset.contractGroup)})})}
 async function loadSecurityTelemetry(){try{renderSecurityTelemetry(await api('/api/platform-contracts'))}catch(error){renderSecurityTelemetry({available:false,error:error.message})}}
 async function load(){try{render(await api('/api/operations/delivery-dashboard'))}catch(error){$('deliveryBody').innerHTML='<div class="delivery-gate">Delivery dashboard unavailable: '+esc(error.message)+'</div>'}}
 async function refresh(){var button=$('deliveryRefresh');if(button){button.disabled=true;button.textContent='Refreshing...'}try{await api('/api/acquisition/refresh',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({source:'github-actions'})});await load()}catch(error){alert('GitHub telemetry refresh failed: '+error.message)}finally{if(button){button.disabled=false;button.textContent='Refresh GitHub telemetry'}}}
 $('deliveryRefresh').addEventListener('click',refresh);
 $('contractSearch').addEventListener('input',renderContractTree);
 $('contractSnapshot').addEventListener('change',function(){contractSelectedPath='';contractFocus='';loadContractInventory('')});
 var setWorkbenchViewBase=setWorkbenchView;setWorkbenchView=function(name){setWorkbenchViewBase(name);if(name==='delivery')load();if(name==='ops-gates')loadSecurityTelemetry();if(name==='contracts'&&!contractInventory)loadContractInventory('')};
 if(currentWorkbenchView==='delivery')load();if(currentWorkbenchView==='ops-gates')loadSecurityTelemetry();if(currentWorkbenchView==='contracts')loadContractInventory('');
},0);
'''


def _patch_html(html: str) -> str:
    text = str(html)
    if 'id="workbench-delivery"' not in text:
        marker = "</main>"
        index = text.rfind(marker)
        if index < 0:
            raise RuntimeError("DeltaScope main workspace boundary was not found")
        text = text[:index] + _DELIVERY_VIEW + text[index:]
    if "__deltascopeDeliveryDashboardInstalled" not in text:
        script = _DELIVERY_JS.replace("__DELIVERY_VIEW__", json.dumps(_DELIVERY_VIEW)).replace("__DELIVERY_CSS__", json.dumps(_DELIVERY_CSS))
        marker = "</script>"
        index = text.rfind(marker)
        if index < 0:
            raise RuntimeError("DeltaScope HTML script boundary was not found")
        text = text[:index] + "\n" + script + "\n" + text[index:]
    return text


def install() -> None:
    import developer_view

    if getattr(developer_view, "_deltascope_delivery_dashboard_installed", False):
        return
    developer_view.HTML = _patch_html(developer_view.HTML)
    original_get = developer_view.AppHandler.do_GET

    def patched_get(self: Any) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path in {"/api/platform-contracts/inventory", "/api/platform-contracts/resource"}:
            try:
                resources = getattr(self, "platform_resources", None)
                if resources is None:
                    return self.json_response({"available": False, "error": "Published platform contracts are unavailable"}, 503)
                query = urllib.parse.parse_qs(parsed.query)
                selected = resources.select_snapshot((query.get("revision") or [""])[0])
                if parsed.path.endswith("/inventory"):
                    return self.json_response(selected.contract_inventory())
                relative = (query.get("path") or [""])[0]
                if not relative:
                    return self.json_response({"error": "path is required"}, 400)
                return self.json_response(selected.read_contract_resource(relative))
            except Exception as exc:
                return self.json_response({"error": str(exc)}, 400)
        if parsed.path != "/api/operations/delivery-dashboard":
            return original_get(self)
        try:
            if not getattr(self, "operations_client", None):
                return self.json_response({
                    "schema": SCHEMA, "available": False, "authenticated": False,
                    "state": "unknown", "error": "GitHub operations disabled",
                })
            return self.json_response(project_delivery_dashboard(self.operations_client, self.inspector))
        except Exception as exc:
            return self.json_response({"error": str(exc)}, 500)

    developer_view.AppHandler.do_GET = patched_get
    developer_view._deltascope_delivery_dashboard_installed = True
