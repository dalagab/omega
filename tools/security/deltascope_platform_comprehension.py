"""DeltaScope platform-comprehension projections and UI augmentation.

This module is deliberately a consumer-side presentation layer. It enriches already-published
DeltaScope projections with evidence-coverage and semantic-path explanations and adds a
read-only operational work-state view. It never scans plugins, writes Evidence-v2, mutates
queues, or grants repository/control-plane authority.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping, Sequence

COMPREHENSION_SCHEMA = "omega.deltascope.platform-comprehension.v1"
_INSTALLED = False

SEMANTIC_COLLECTIONS = ("sourceOperations", "sourceDataFlow", "sourceFlowEdges")
THREAT_COLLECTIONS = ("endpointDns", "endpointReputation", "endpointConnectivity")


def _text(value: Any) -> str:
    return str(value or "").strip()


def _rows(value: Any) -> list[Mapping[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return []
    return [item for item in value if isinstance(item, Mapping)]


def _first(*values: Any) -> str:
    for value in values:
        text = _text(value)
        if text:
            return text
    return ""


def _node(kind: str, label: str, detail: str = "") -> dict[str, str]:
    return {"kind": kind, "label": label, "detail": detail}


def _raw_rows(group: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    values: list[Mapping[str, Any]] = []
    for item in _rows(group.get("evidenceRows")):
        raw = item.get("row") if isinstance(item.get("row"), Mapping) else {}
        if raw:
            values.append(raw)
    return values


def semantic_chain_for_group(group: Mapping[str, Any]) -> dict[str, Any]:
    """Build a conservative, static semantic chain for one behavior group.

    Chains are descriptions of retained static/source evidence, never runtime execution claims.
    Known source-behavior rules get a stable human explanation; unknown rules fall back to
    normalized operation/service/flow fields already present in the matched evidence rows.
    """
    rule_id = _text(group.get("ruleId") or group.get("behaviorKey"))
    raw_rows = _raw_rows(group)
    nodes: list[dict[str, str]] = []

    def add(kind: str, label: str, detail: str = "") -> None:
        if not label:
            return
        key = (kind.casefold(), label.casefold(), detail.casefold())
        if any((n["kind"].casefold(), n["label"].casefold(), n["detail"].casefold()) == key for n in nodes):
            return
        nodes.append(_node(kind, label, detail))

    # Prefer explicit source-flow semantics when a retained row carries them.
    for raw in raw_rows:
        service = _first(raw.get("serviceName"), raw.get("service"), raw.get("serviceId"))
        host = _first(raw.get("host"), raw.get("domain"), raw.get("endpointHost"))
        capabilities = raw.get("serviceCapabilities") if isinstance(raw.get("serviceCapabilities"), list) else []
        if service:
            add("service", service, ", ".join(_text(x) for x in capabilities if _text(x)))
        elif host:
            add("service", host, ", ".join(_text(x) for x in capabilities if _text(x)))

        from_op = _first(raw.get("fromOperation"), raw.get("sourceOperation"))
        operation = _first(raw.get("operation"), raw.get("semanticOperation"), raw.get("toOperation"))
        to_op = _first(raw.get("toOperation"), raw.get("targetOperation"))
        relation = _first(raw.get("relation"), raw.get("edgeKind"))
        if from_op:
            add("operation", from_op)
        if relation:
            add("flow", relation, _first(raw.get("minimumDelayMs") and f"minimum delay {raw.get('minimumDelayMs')} ms"))
        if operation:
            add("operation", operation)
        if to_op and to_op != operation:
            add("operation", to_op)

    known: dict[str, tuple[str, list[dict[str, str]]]] = {
        "source-behavior.market-data-request": (
            "Static source analysis found a concrete request to a service classified as FFXIV market data.",
            [_node("service", "FFXIV market-data service"), _node("operation", "network.http.request")],
        ),
        "source-behavior.market-data-drives-purchase": (
            "Retained source value-flow connects external FFXIV market data to a market-board purchase primitive.",
            [
                _node("data", "FFXIV market data"),
                _node("flow", "value-used-by"),
                _node("operation", "game.marketboard.purchase"),
            ],
        ),
        "source-behavior.navigation-before-market-purchase": (
            "Retained source control-flow places character movement before a market-board purchase primitive.",
            [_node("operation", "game.character.move"), _node("flow", "precedes"), _node("operation", "game.marketboard.purchase")],
        ),
        "source-behavior.delay-before-market-purchase": (
            "Retained source control-flow records an explicit delay before a market-board purchase primitive.",
            [_node("operation", "time.delay"), _node("flow", "precedes"), _node("operation", "game.marketboard.purchase")],
        ),
        "source-behavior.event-triggered-market-purchase": (
            "A retained trigger edge reaches a handler whose semantic path enters a market-board purchase primitive.",
            [_node("trigger", "registered trigger"), _node("flow", "triggers"), _node("operation", "game.marketboard.purchase")],
        ),
        "source-behavior.periodic-market-purchase": (
            "A retained periodic trigger can enter a market-board purchase path after a non-zero interval.",
            [_node("trigger", "trigger.periodic"), _node("flow", "triggers"), _node("operation", "game.marketboard.purchase")],
        ),
    }
    if rule_id in known:
        summary, fallback_nodes = known[rule_id]
        observed_nodes = nodes
        nodes = deepcopy(fallback_nodes)
        # Preserve concrete retained service/host detail without losing the stable semantic
        # shape of the reviewed source-behavior rule.
        observed_service = next((item for item in observed_nodes if item.get("kind") == "service"), None)
        if observed_service:
            generic_service = next((item for item in nodes if item.get("kind") == "service"), None)
            if generic_service:
                generic_service.update(observed_service)
        for item in observed_nodes:
            key = (item.get("kind"), item.get("label"), item.get("detail"))
            if not any((n.get("kind"), n.get("label"), n.get("detail")) == key for n in nodes):
                nodes.append(item)
    else:
        summary = _text(group.get("description")) or "Retained evidence was grouped into this behavior by DeltaScope."

    return {
        "schema": COMPREHENSION_SCHEMA,
        "summary": summary,
        "nodes": nodes[:8],
        "boundary": "Static/retained evidence path; this does not assert that the path executed at runtime.",
    }


def augment_behavior_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(payload)
    cache: dict[str, dict[str, Any]] = {}

    def enrich(raw: Mapping[str, Any]) -> dict[str, Any]:
        item = dict(raw)
        key = _text(item.get("behaviorId")) or _text(item.get("behaviorKey"))
        chain = cache.get(key)
        if chain is None:
            chain = semantic_chain_for_group(item)
            if key:
                cache[key] = chain
        item["semanticChain"] = chain
        return item

    groups = [enrich(item) for item in _rows(payload.get("behaviors"))]
    if groups:
        result["behaviors"] = groups
    visible = [enrich(item) for item in _rows(payload.get("visibleBehaviors"))]
    if visible:
        result["visibleBehaviors"] = visible
    result["comprehension"] = {
        "schema": COMPREHENSION_SCHEMA,
        "semanticBehaviorCount": sum(1 for item in visible or groups if (item.get("semanticChain") or {}).get("nodes")),
        "interpretationBoundary": "Semantic chains explain retained static/source evidence and never become runtime/security authority.",
    }
    return result


def evidence_coverage(
    detail: Mapping[str, Any],
    observations: Mapping[str, Any] | None = None,
    projection_state: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    observations = observations or {}
    projection_state = projection_state or {}
    identity = detail.get("identity") if isinstance(detail.get("identity"), Mapping) else {}
    source = detail.get("sourceCoverage") if isinstance(detail.get("sourceCoverage"), Mapping) else {}
    secondary = detail.get("secondarySecurity") if isinstance(detail.get("secondarySecurity"), Mapping) else {}
    engines = _rows(secondary.get("engines"))
    projection = projection_state.get("projection") if isinstance(projection_state.get("projection"), Mapping) else {}
    reanalysis = projection_state.get("reanalysisRequest") if isinstance(projection_state.get("reanalysisRequest"), Mapping) else {}

    def count(collection: str) -> int:
        value = observations.get(collection)
        return len(value) if isinstance(value, list) else 0

    rows: list[dict[str, Any]] = []

    def add(domain: str, label: str, state: str, detail_text: str, *, target: str = "", count_value: int | None = None) -> None:
        item: dict[str, Any] = {"domain": domain, "label": label, "state": state, "detail": detail_text}
        if target:
            item["target"] = target
        if count_value is not None:
            item["count"] = count_value
        rows.append(item)

    artifact = bool(source.get("artifactAvailable")) or bool(identity.get("artifact_sha256"))
    add("artifact", "Artifact", "complete" if artifact else "not-recorded", "Exact distributed artifact identity is retained." if artifact else "No retained artifact identity is available.", target="code")

    source_available = bool(source.get("sourceCodeAvailable"))
    add(
        "source", "Source", "complete" if source_available else "not-recorded",
        "Attributed public source is retained." if source_available else "No attributable public source is retained for this variant.", target="supply",
    )

    semantic_count = sum(count(name) for name in SEMANTIC_COLLECTIONS)
    semantic_state = "observed" if semantic_count else ("not-recorded" if source_available else "not-requested")
    add(
        "source-semantics", "Source behavior semantics", semantic_state,
        f"{semantic_count} retained semantic operation/flow row(s)." if semantic_count else "No semantic operation/value/control-flow rows are retained for this variant.",
        target="behaviors", count_value=semantic_count,
    )

    endpoint_count = len(detail.get("networkEndpoints") or []) if isinstance(detail.get("networkEndpoints"), list) else count("networkEndpoints")
    endpoint_collection_retained = "networkEndpoints" in observations and isinstance(observations.get("networkEndpoints"), list)
    endpoint_state = "observed" if endpoint_count else ("complete" if endpoint_collection_retained else "not-recorded")
    endpoint_detail = (
        f"{endpoint_count} endpoint observation(s) retained." if endpoint_count else
        "The retained endpoint collection is present and empty." if endpoint_collection_retained else
        "No endpoint collection is exposed in this compact dossier; DeltaScope does not infer a clean result from scan completion alone."
    )
    add("network", "Network endpoints", endpoint_state, endpoint_detail, target="network", count_value=endpoint_count)

    dependency_count = len(detail.get("dependencies") or []) if isinstance(detail.get("dependencies"), list) else count("dependencies")
    advisory_count = len(detail.get("advisories") or []) if isinstance(detail.get("advisories"), list) else 0
    add(
        "dependencies", "Dependencies / OSV", "observed" if dependency_count or advisory_count else "not-recorded",
        f"{dependency_count} dependency row(s); {advisory_count} matched advisory row(s).", target="supply", count_value=dependency_count,
    )

    if engines:
        statuses = {_text(item.get("status")).casefold() for item in engines}
        unavailable = any(item.get("available") is False for item in engines)
        state = "unavailable" if unavailable and len(engines) == 1 else "partial" if unavailable or any(s not in {"complete", "ready"} for s in statuses) else "complete"
        detail_text = "; ".join(f"{_first(item.get('engine'), item.get('name'), 'engine')}: {_first(item.get('status'), 'unknown')}" for item in engines)
    else:
        state, detail_text = "not-recorded", "No retained secondary-engine status is exposed for this variant."
    add("secondary", "YARA / ClamAV", state, detail_text, target="malware", count_value=len(engines))

    signature_count = count("binarySignatureTrust")
    add(
        "signature", "Authenticode", "complete" if signature_count else "not-recorded",
        f"{signature_count} signature-trust observation(s) retained." if signature_count else "No binary-signature trust observation is retained for this variant.", target="evidence", count_value=signature_count,
    )

    native_count = count("elfBinaryStructure") + count("machOBinaryStructure")
    add(
        "native", "Native structure", "complete" if native_count else "not-recorded",
        f"{native_count} ELF/Mach-O structural observation(s) retained." if native_count else "No specialist ELF/Mach-O structural observation is retained.", target="code", count_value=native_count,
    )

    threat_count = sum(count(name) for name in THREAT_COLLECTIONS)
    if threat_count:
        threat_state = "complete"
        threat_detail = f"{threat_count} retained DNS/reputation/connectivity observation(s)."
    elif endpoint_count:
        threat_state = "not-linked"
        threat_detail = "Endpoints exist, but no endpoint-scoped threat-intelligence observations are linked into this variant dossier."
    else:
        threat_state = "not-requested"
        threat_detail = "No endpoint evidence exists to drive endpoint-scoped threat intelligence."
    add("threat-intelligence", "Threat intelligence", threat_state, threat_detail, target="network", count_value=threat_count)

    if reanalysis:
        srl_state = "needs-evidence"
        srl_detail = _text(reanalysis.get("reason")) or "Rule replay requires additional retained observations."
    elif projection:
        srl_state = "complete"
        srl_detail = f"Projection {_first(projection.get('projectionRevision'), 'available')} under rule set {_first(projection.get('ruleSetRevision'), projection_state.get('ruleSetRevision'), 'unknown')}."
    elif projection_state.get("available"):
        srl_state = "not-recorded"
        srl_detail = "A projection set exists, but this variant has no projection entry."
    else:
        srl_state = "not-recorded"
        srl_detail = "No retained SRL projection sidecar is available for this evidence snapshot."
    add("srl", "Stigma-1 / SRL", srl_state, srl_detail, target="findings")

    verified = bool(source.get("sourceToBinaryVerified"))
    build_state = "complete" if verified else ("not-verified" if source_available else "not-requested")
    add(
        "build-proof", "Source → artifact", build_state,
        "The published source-to-artifact relationship is verified." if verified else "Source exists, but exact reproducible source-to-distributed-artifact proof is not published." if source_available else "No source is available for source-to-artifact proof.",
        target="supply",
    )
    return rows


def augment_journey_payload(
    payload: Mapping[str, Any],
    detail: Mapping[str, Any],
    observations: Mapping[str, Any] | None = None,
    projection_state: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    observations = observations or {}
    projection_state = projection_state or {}
    result = dict(payload)
    stages = [dict(item) for item in _rows(payload.get("stages"))]
    coverage = evidence_coverage(detail, observations, projection_state)
    by_domain = {item["domain"]: item for item in coverage}

    semantic = by_domain.get("source-semantics", {})
    semantic_count = int(semantic.get("count") or 0)
    semantic_stage = {
        "stageId": "semantic-behavior",
        "title": "Semantic source behavior",
        "status": semantic.get("state") or "not-recorded",
        "summary": semantic.get("detail") or "No semantic source behavior is retained.",
        "details": [f"{name}: {len(observations.get(name) or [])}" for name in SEMANTIC_COLLECTIONS if isinstance(observations.get(name), list)],
        "evidence": "sourceOperations · sourceDataFlow · sourceFlowEdges",
        "purpose": "Translate low-level source calls and flow edges into implementation-neutral operations so a human can understand what data or action can feed another action.",
        "whyStatus": "The state is derived only from retained semantic source observation collections for this exact variant.",
        "produced": [f"{semantic_count} semantic source row(s)"] if semantic_count else [],
        "nextStep": "Inspect Behaviors for rule-backed semantic chains, then trace exact retained rows when a chain matters.",
        "actions": [{"label": "Open Behaviors", "target": "behaviors"}],
    }

    threat = by_domain.get("threat-intelligence", {})
    threat_stage = {
        "stageId": "threat-intelligence",
        "title": "Threat-intelligence enrichment",
        "status": threat.get("state") or "not-recorded",
        "summary": threat.get("detail") or "No endpoint intelligence is linked.",
        "details": [f"{name}: {len(observations.get(name) or [])}" for name in THREAT_COLLECTIONS if isinstance(observations.get(name), list)],
        "evidence": "endpointDns · endpointReputation · endpointConnectivity",
        "purpose": "Keep changing endpoint reputation/DNS/connectivity facts separate from deterministic static analysis while retaining their freshness and provenance.",
        "whyStatus": "DeltaScope only marks this complete when endpoint-scoped intelligence rows are actually retained for this variant.",
        "produced": [f"{int(threat.get('count') or 0)} endpoint-intelligence row(s)"] if threat.get("count") else [],
        "nextStep": "Inspect Network and Threat Intelligence; an unlisted endpoint is context, not a clean verdict.",
        "actions": [{"label": "Open Network", "target": "network"}],
    }

    def insert_after(stage_id: str, new_stage: dict[str, Any]) -> None:
        if any(item.get("stageId") == new_stage["stageId"] for item in stages):
            return
        for index, item in enumerate(stages):
            if item.get("stageId") == stage_id:
                stages.insert(index + 1, new_stage)
                return
        stages.append(new_stage)

    insert_after("evidence-normalization", semantic_stage)
    insert_after("semantic-behavior", threat_stage)
    result["stages"] = stages
    result["stageCount"] = len(stages)
    result["evidenceCoverage"] = coverage
    result["coverageSummary"] = {
        "complete": sum(1 for item in coverage if item["state"] in {"complete", "observed"}),
        "attention": sum(1 for item in coverage if item["state"] in {"partial", "needs-evidence", "unavailable", "not-linked", "not-verified"}),
        "missing": sum(1 for item in coverage if item["state"] in {"not-recorded"}),
        "domains": len(coverage),
    }
    result["comprehension"] = {
        "schema": COMPREHENSION_SCHEMA,
        "readOnly": True,
        "mutationAuthority": "none",
        "interpretationBoundary": "Coverage distinguishes retained evidence from absent/not-linked/not-requested data; it never converts missing evidence into a negative security result.",
    }
    return result


_CSS = r'''
/* 4.21.13 platform comprehension: light work surfaces, no new playful chrome. */
.comprehension-panel{border:1px solid #d8d8d8;background:#fff;margin:0 0 12px;padding:12px}
.comprehension-panel h4{margin:0}.comprehension-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:9px}
.comprehension-summary{display:flex;gap:6px;flex-wrap:wrap}.comprehension-summary .pill{background:#f4f4f4}
.comprehension-coverage-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:7px}
.comprehension-coverage-row{border:1px solid #e0e0e0;background:#f8f8f8;padding:9px;min-height:84px}
.comprehension-coverage-row button{margin-top:7px}.comprehension-coverage-row .state{font-size:11px;font-weight:700;letter-spacing:.04em;text-transform:uppercase}
.comprehension-coverage-row.state-complete .state,.comprehension-coverage-row.state-observed .state{color:#1f6f43}
.comprehension-coverage-row.state-partial .state,.comprehension-coverage-row.state-needs-evidence .state,.comprehension-coverage-row.state-not-linked .state,.comprehension-coverage-row.state-not-verified .state{color:#8a5a00}
.comprehension-coverage-row.state-unavailable .state,.comprehension-coverage-row.state-not-recorded .state{color:#7a2f2f}
.semantic-chain{border-top:1px solid #e0e0e0;border-bottom:1px solid #e0e0e0;background:#fafafa;padding:10px 12px;margin-top:8px}
.semantic-chain-title{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;margin-bottom:7px}
.semantic-chain-flow{display:flex;align-items:stretch;gap:6px;flex-wrap:wrap}.semantic-chain-node{border:1px solid #cfcfcf;background:#fff;padding:7px 9px;min-width:128px;max-width:240px}
.semantic-chain-node .kind{font-size:10px;text-transform:uppercase;color:#6f6f6f}.semantic-chain-arrow{display:flex;align-items:center;color:#6f6f6f;font-weight:700}
.semantic-chain-boundary{font-size:11px;color:#6f6f6f;margin-top:7px}.semantic-registry-state{font-size:11px;color:#525252;margin-top:8px}
.finding-comprehension{border-left:3px solid #c6c6c6;background:#f8f8f8;margin:8px 0 0;padding:8px 10px;font-size:12px}
.work-state-board{margin-top:12px}.work-state-grid{display:grid;grid-template-columns:minmax(0,1.25fr) minmax(280px,.75fr);gap:12px}
.work-state-list{display:grid;gap:6px}.work-state-row{width:100%;text-align:left;border:1px solid #d8d8d8;background:#fff;padding:9px;display:grid;grid-template-columns:minmax(170px,1fr) auto;gap:8px}
.work-state-row:hover{background:#f4f4f4}.work-state-row .counts{font-size:11px;color:#525252}.work-state-detail{border:1px solid #d8d8d8;background:#f8f8f8;padding:11px;min-height:180px}
.work-trace{display:flex;gap:5px;flex-wrap:wrap;align-items:center;margin:8px 0}.work-trace-step{border:1px solid #cfcfcf;background:#fff;padding:6px 8px;font-size:11px}.work-trace-arrow{color:#6f6f6f}
@media(max-width:1050px){.work-state-grid{grid-template-columns:1fr}}
'''

_JS = r'''
setTimeout(()=>{
 if(window.__deltascopePlatformComprehensionInstalled)return;
 window.__deltascopePlatformComprehensionInstalled=true;
 const SEMANTIC_BASE='https://raw.githubusercontent.com/dalagab/omega/catalog-data/definitions/';
 const WORK_BASE='https://raw.githubusercontent.com/dalagab/omega/security-work-state/';
 let semanticRegistryState={loaded:false,ok:false,error:'',definitionsRevision:'',services:null,apis:null};
 let workStateCache=null;
 const safeState=s=>String(s||'unknown').toLowerCase().replace(/[^a-z0-9-]/g,'-');
 async function sha256Hex(bytes){const digest=await crypto.subtle.digest('SHA-256',bytes);return [...new Uint8Array(digest)].map(x=>x.toString(16).padStart(2,'0')).join('')}
 async function verifiedDefinitionChild(index,key){const d=index?.[key];if(!d?.path||!d?.sha256)return null;const path=String(d.path);if(path.includes('..')||path.includes('://')||path.startsWith('/'))throw new Error(`unsafe ${key} path`);const response=await fetch(SEMANTIC_BASE+path,{cache:'no-store'});if(!response.ok)throw new Error(`${key} HTTP ${response.status}`);const bytes=new Uint8Array(await response.arrayBuffer()),actual=await sha256Hex(bytes);if(actual!==String(d.sha256).toLowerCase())throw new Error(`${key} SHA-256 mismatch`);return JSON.parse(new TextDecoder().decode(bytes))}
 async function loadSemanticRegistries(){if(semanticRegistryState.loaded)return semanticRegistryState;semanticRegistryState.loaded=true;try{const response=await fetch(SEMANTIC_BASE+'index.json',{cache:'no-store'});if(!response.ok)throw new Error(`Definitions HTTP ${response.status}`);const index=await response.json();const [services,apis]=await Promise.all([verifiedDefinitionChild(index,'serviceRegistry'),verifiedDefinitionChild(index,'semanticApiRegistry')]);semanticRegistryState={loaded:true,ok:!!services&&!!apis,error:'',definitionsRevision:String(index.definitionsRevision||''),services,apis}}catch(e){semanticRegistryState={loaded:true,ok:false,error:String(e?.message||e),definitionsRevision:'',services:null,apis:null}}return semanticRegistryState}
 function semanticRegistryStatusHtml(){const s=semanticRegistryState;if(!s.loaded)return '<div class=semantic-registry-state>Semantic dictionaries: checking published Definitions…</div>';if(!s.ok)return `<div class=semantic-registry-state>Semantic dictionaries unavailable: ${esc(s.error||'not published')}. Behavior chains still use retained operation labels.</div>`;const serviceCount=(s.services?.services||[]).length,matcherCount=(s.apis?.sourceMatchers||[]).length+(s.apis?.compiledMatchers||[]).length;return `<div class=semantic-registry-state>Semantic dictionaries verified against ${esc(s.definitionsRevision||'published Definitions')} · ${fmt(serviceCount)} services · ${fmt(matcherCount)} API matchers.</div>`}
 function serviceForHost(host){host=String(host||'').toLowerCase().replace(/^\.+|\.+$/g,'');if(!host||!semanticRegistryState.ok)return null;return (semanticRegistryState.services?.services||[]).find(s=>(s.hosts||[]).some(h=>host===String(h).toLowerCase()||host.endsWith('.'+String(h).toLowerCase())))||null}
 function semanticNodeLabel(node){let label=String(node?.label||'');if(node?.kind==='service'){const match=serviceForHost(label);if(match)label=`${match.name} · ${label}`}return label}
 function semanticChainHtml(group){const c=group?.semanticChain||{},nodes=Array.isArray(c.nodes)?c.nodes:[];if(!nodes.length)return'';return `<div class=semantic-chain><div class=semantic-chain-title>Semantic evidence path</div><div class="muted small" style="margin-bottom:7px">${esc(c.summary||'')}</div><div class=semantic-chain-flow>${nodes.map((n,i)=>`${i?'<span class=semantic-chain-arrow>→</span>':''}<div class=semantic-chain-node><div class=kind>${esc(n.kind||'step')}</div><b>${esc(semanticNodeLabel(n))}</b>${n.detail?`<div class="muted tiny">${esc(n.detail)}</div>`:''}</div>`).join('')}</div><div class=semantic-chain-boundary>${esc(c.boundary||'Static retained evidence only.')}</div></div>`}
 const behaviorCardHtmlBase=behaviorCardHtml;
 behaviorCardHtml=function(group){let html=behaviorCardHtmlBase(group),chain=semanticChainHtml(group);if(!chain)return html;if(html.includes('<div class=behavior-evidence-list>'))return html.replace('<div class=behavior-evidence-list>',chain+'<div class=behavior-evidence-list>');if(html.includes('<div class=behavior-empty>'))return html.replace('<div class=behavior-empty>',chain+'<div class=behavior-empty>');return html+chain};
 function coverageActionLabel(target){return ({behaviors:'Open behaviors',network:'Open network',supply:'Open source & build',malware:'Open malware',findings:'Open findings',code:'Open code',evidence:'Open evidence'})[target]||'Inspect'}
 function renderComprehensionCoverage(j){const host=document.querySelector('[data-comprehension-coverage]');if(!host)return;const rows=Array.isArray(j?.evidenceCoverage)?j.evidenceCoverage:[],s=j?.coverageSummary||{};host.innerHTML=`<div class=comprehension-head><div><h4>Evidence coverage</h4><div class="muted small">Positive, missing, not-linked and not-requested states stay distinct. Missing data is never treated as a clean result.</div></div><div class=comprehension-summary><span class=pill>${fmt(s.complete||0)} present</span><span class=pill>${fmt(s.attention||0)} attention</span><span class=pill>${fmt(s.missing||0)} not recorded</span></div></div><div class=comprehension-coverage-grid>${rows.map(r=>`<div class="comprehension-coverage-row state-${safeState(r.state)}"><div class=state>${esc(String(r.state||'unknown').replaceAll('-',' '))}</div><b>${esc(r.label||r.domain||'Evidence')}</b><div class="muted small">${esc(r.detail||'')}</div>${r.target?`<button data-comprehension-target="${esc(r.target)}">${esc(coverageActionLabel(r.target))}</button>`:''}</div>`).join('')||'<div class=workspace-empty>No coverage projection is available.</div>'}</div>${semanticRegistryStatusHtml()}`;host.querySelectorAll('[data-comprehension-target]').forEach(b=>b.addEventListener('click',()=>activateResearchTab(b.dataset.comprehensionTarget||'overview')))}
 async function loadComprehensionCoverage(id){const host=document.querySelector('[data-comprehension-coverage]');if(!host)return;try{const [j]=await Promise.all([api('/api/workbench/journey?variant_id='+encodeURIComponent(id)),loadSemanticRegistries()]);renderComprehensionCoverage(j)}catch(e){host.innerHTML=`<div class=research-error><b>Could not project evidence coverage</b><div>${esc(e.message)}</div></div>`}}
 const dossierOverviewHtmlBase=dossierOverviewHtml;
 dossierOverviewHtml=function(d,id){const html=dossierOverviewHtmlBase(d,id),panel='<section class="comprehension-panel" data-comprehension-coverage><span class=muted>Projecting evidence completeness across current collectors and rule inputs…</span></section>';return html.replace('<div class=dossier-overview>','<div class=dossier-overview>'+panel)};
 function annotateFindingComprehension(root){const rows=currentPluginDetail?.researcher?.findings||[];root?.querySelectorAll?.('.finding').forEach((card,index)=>{if(card.querySelector('.finding-comprehension'))return;const f=rows[index]||{},rev=f.ruleRevision||f.rule_revision||currentPluginDetail?.identity?.definitions_revision||'';const box=document.createElement('div');box.className='finding-comprehension';box.innerHTML=`<b>Evidence-bound conclusion.</b> This finding remains tied to the exact retained observations and rule/Definitions revision${rev?` <code>${esc(rev)}</code>`:''}. Use <b>Trace lineage</b> for the triggering rows. A changed artifact/rule or a replay that reports missing required observations can change the projection.`;card.appendChild(box)})}
 const wireResearchTabsBase=wireResearchTabs;
 wireResearchTabs=function(id){const result=wireResearchTabsBase(id);loadComprehensionCoverage(id);annotateFindingComprehension($('pluginDetail'));loadSemanticRegistries().then(()=>{const pane=$('pluginDetail')?.querySelector('[data-research-pane="behaviors"]');if(pane?.classList.contains('active'))loadPluginBehaviors(id,pane,false);const jhost=document.querySelector('[data-comprehension-coverage]');if(jhost)loadComprehensionCoverage(id)});return result};
 const journeyStatusLabelBase=journeyStatusLabel;
 journeyStatusLabel=function(status){const labels={observed:'observed','not-linked':'not linked','not-verified':'not verified',unavailable:'unavailable'};return labels[status]||journeyStatusLabelBase(status)};
 const journeyTargetBase=journeyTarget;
 journeyTarget=function(stage){return ({'semantic-behavior':'behaviors','threat-intelligence':'network'})[stage]||journeyTargetBase(stage)};
 function ensureWorkStatePanel(){let panel=$('workStateComprehension');if(panel)return panel;const dashboard=$('operationsDashboard');if(!dashboard)return null;panel=document.createElement('section');panel.id='workStateComprehension';panel.className='panel work-state-board';panel.innerHTML='<div class=workspace-empty>Loading orchestration work state…</div>';dashboard.appendChild(panel);return panel}
 async function workJson(path='index.json'){path=String(path||'');if(path!=='index.json'&&!/^queues\/[A-Za-z0-9._-]+\.json$/.test(path))throw new Error('unsafe work-state path');const response=await fetch(WORK_BASE+path,{cache:'no-store'});if(!response.ok)throw new Error(`work-state HTTP ${response.status}`);return response.json()}
 function queueCounts(q){const c=q?.counts||{};return `${fmt(c.pending||0)} pending · ${fmt(c.leased||0)} leased · ${fmt(c.blocked||0)} blocked · ${fmt(c.completed||0)} complete`}
 function workTraceHtml(item,q){if(!item)return '<div class=workspace-empty>Select a queue to inspect its latest retained work item.</div>';const reason=(item.reason||[]).join(', ')||'reason not retained',lease=item.lease||{},settle=item.settlement||{};return `<div><div class=eyebrow>Latest retained work item</div><h4>${esc(item.kind||q.queueId||'work')}</h4><div class="muted small"><code>${esc(item.workId||'')}</code> · ${esc(item.updatedAtUtc||'')}</div><div class=work-trace><span class=work-trace-step>${esc(reason)}</span><span class=work-trace-arrow>→</span><span class=work-trace-step>queue · ${esc(q.queueId||'unknown')}</span><span class=work-trace-arrow>→</span><span class=work-trace-step>${esc(item.state||'unknown')}</span><span class=work-trace-arrow>→</span><span class=work-trace-step>${lease.owner?`lease · ${esc(lease.owner)}`:'no active lease'}</span><span class=work-trace-arrow>→</span><span class=work-trace-step>${settle.resultRevision?`result · ${esc(settle.resultRevision)}`:'no result revision'}</span><span class=work-trace-arrow>→</span><span class=work-trace-step>${settle.outcome?`settlement · ${esc(settle.outcome)}`:'not settled'}</span></div><div class=kv><b>Component</b><span>${esc(item.component||q.component||'')}</span><b>Subject</b><span>${esc(JSON.stringify(item.subject||{}))}</span><b>Required revision</b><span>${esc(item.requiredRevision||q.requiredRevision||'')}</span><b>Attempts</b><span>${fmt(item.attempts||0)}</span><b>Result revision</b><span>${esc(settle.resultRevision||'—')}</span><b>Result SHA-256</b><span>${esc(settle.resultSha256||'—')}</span></div><div class="muted small" style="margin-top:9px">Work-state is operational lineage only. Successful worker completion does not become a security verdict; retained Evidence-v2/collector contracts remain the evidence authority.</div></div>`}
 async function openWorkQueue(q){const detail=$('workStateDetail');if(!detail)return;detail.innerHTML='<span class=muted>Loading retained queue lineage…</span>';try{const full=await workJson(q.path),items=Array.isArray(full.items)?[...full.items]:[];items.sort((a,b)=>String(b.updatedAtUtc||'').localeCompare(String(a.updatedAtUtc||'')));detail.innerHTML=workTraceHtml(items[0],{...q,...full})}catch(e){detail.innerHTML=`<div class=research-error><b>Could not load queue lineage</b><div>${esc(e.message)}</div></div>`}}
 function renderWorkState(index){const panel=ensureWorkStatePanel();if(!panel)return;const queues=Array.isArray(index?.queues)?index.queues:[],pending=queues.reduce((n,q)=>n+Number(q.counts?.pending||0),0),leased=queues.reduce((n,q)=>n+Number(q.counts?.leased||0),0),blocked=queues.reduce((n,q)=>n+Number(q.counts?.blocked||0),0);panel.innerHTML=`<div class=panelhead><div><h2>Orchestration work state</h2><div class="muted small">Reason → queue → lease → worker result → settlement, read directly from <code>security-work-state</code>. This is the durable work model behind Actions.</div></div><span class="muted small">${esc(index.generatedAtUtc||'')}</span></div><div class=cards>${card('Queues',queues.length)}${card('Pending',pending)}${card('Leased',leased)}${card('Blocked',blocked)}</div><div class=work-state-grid><div class=work-state-list>${queues.map((q,i)=>`<button class=work-state-row data-work-queue-index="${i}"><span><b>${esc(q.queueId||'queue')}</b><div class="muted small">${esc(q.component||'')} · every ${fmt(Math.round(Number(q.cadenceSeconds||0)/60))} min · result ${esc(q.resultBranch||'—')}</div></span><span class=counts>${esc(queueCounts(q))}</span></button>`).join('')||'<div class=workspace-empty>No durable work queues are published.</div>'}</div><div id=workStateDetail class=work-state-detail><div class=workspace-empty>Select a queue to inspect its latest retained work lineage.</div></div></div><div class="muted small" style="padding:8px 12px">Policy v${esc(index.policyVersion||'?')} · revision <code>${esc(index.workStateRevision||'')}</code> · publication authority ${esc(index.publicationAuthority||'none')} · security authority ${index.securityAuthority?'yes':'no'}.</div>`;panel.querySelectorAll('[data-work-queue-index]').forEach(b=>b.addEventListener('click',()=>openWorkQueue(queues[Number(b.dataset.workQueueIndex)])));if(queues.length)openWorkQueue(queues.find(q=>Number(q.counts?.pending||0)||Number(q.counts?.leased||0)||Number(q.counts?.blocked||0))||queues[0])}
 async function loadOperationalWorkState(force=false){if(currentPerspective!=='operations')return;const panel=ensureWorkStatePanel();if(!panel)return;if(workStateCache&&!force){renderWorkState(workStateCache);return}panel.innerHTML='<div class=workspace-empty>Loading durable work state from the orchestration branch…</div>';try{workStateCache=await workJson('index.json');renderWorkState(workStateCache)}catch(e){panel.innerHTML=`<div class=research-error><b>Durable work state unavailable</b><div>${esc(e.message)}</div><div class="muted small">GitHub Actions status remains available above; DeltaScope did not infer queue/settlement state from workflow names.</div></div>`}}
 const setWorkbenchViewBase=setWorkbenchView;
 setWorkbenchView=function(name){const result=setWorkbenchViewBase(name);if(currentPerspective==='operations'&&['dashboard','events'].includes(name))loadOperationalWorkState(false);return result};
 window.deltaScopeLoadOperationalWorkState=loadOperationalWorkState;
 if(currentPerspective==='operations'&&['dashboard','events'].includes(currentWorkbenchView))loadOperationalWorkState(false);
},0);
'''


def _insert_before_last(text: str, marker: str, payload: str) -> str:
    index = text.rfind(marker)
    if index < 0:
        raise RuntimeError(f"DeltaScope HTML boundary not found: {marker}")
    return text[:index] + payload + text[index:]


def install() -> None:
    """Install projection wrappers and UI augmentation into the existing DeltaScope process."""
    global _INSTALLED
    if _INSTALLED:
        return
    import developer_view
    import deltascope_behaviors
    import deltascope_workbench

    if "__deltascopePlatformComprehensionInstalled" not in developer_view.HTML:
        html = developer_view.HTML
        html = _insert_before_last(html, "</style>", "\n" + _CSS + "\n")
        html = _insert_before_last(html, "</script>", "\n" + _JS + "\n")
        developer_view.HTML = html

    original_behaviors = deltascope_behaviors.project_plugin_behaviors
    if not getattr(original_behaviors, "_deltascope_comprehension", False):
        def project_plugin_behaviors(*args: Any, **kwargs: Any) -> dict[str, Any]:
            return augment_behavior_payload(original_behaviors(*args, **kwargs))
        project_plugin_behaviors._deltascope_comprehension = True  # type: ignore[attr-defined]
        deltascope_behaviors.project_plugin_behaviors = project_plugin_behaviors

    original_journey = deltascope_workbench.project_asset_journey
    if not getattr(original_journey, "_deltascope_comprehension", False):
        def project_asset_journey(
            detail: Mapping[str, Any], observations: Mapping[str, Any] | None = None,
            projection_state: Mapping[str, Any] | None = None,
        ) -> dict[str, Any]:
            base = original_journey(detail, observations, projection_state)
            return augment_journey_payload(base, detail, observations, projection_state)
        project_asset_journey._deltascope_comprehension = True  # type: ignore[attr-defined]
        deltascope_workbench.project_asset_journey = project_asset_journey

    _INSTALLED = True
