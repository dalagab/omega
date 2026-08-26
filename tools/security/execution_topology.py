#!/usr/bin/env python3
"""Published Omega execution-topology contract.

This contract describes *where* platform work runs and how an observer can correlate a
logical execution node with GitHub Actions runner history. It is descriptive data only:
it has no launch, dispatch, security-finding, catalog-identity or Evidence-v2 authority.

DeltaScope consumes the frozen JSON projection from Definitions rather than importing
this module. New components/execution nodes can therefore become visible to DeltaScope
without a DeltaScope code change.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

import component_registry

TOPOLOGY_SCHEMA = "omega.execution-topology.v1"
NODE_SCHEMA = "omega.execution-node.v1"

EXECUTIONS: tuple[dict[str, Any], ...] = ({'id': 'source-discovery',
  'title': 'Omega Discovery / source intelligence',
  'workflow': 'catalog-discovery-worker.yml',
  'job': 'Collect leased catalog discovery working state',
  'step': 'Run typed discovery collectors for the exact durable lease',
  'purpose': 'Run the first-class Omega Discovery component: source search, project-page links, issue hints, optional '
             'web search, rotating repository-tree inspection and PluginMaster validation.',
  'inputs': ['canonical catalog-data',
             'curated/community registries',
             'Puni.sh',
             'GitHub code search',
             'canonical project-page enrichment',
             'Omega source issues',
             'optional configured web-search API'],
  'outputs': ['catalog-discovery snapshot', 'typed collector observations', 'normalized reusable novel-source shards'],
  'implementation': 'tools/catalog/catalog_discovery.py + tools/catalog/discovery_collectors.py',
  'componentId': 'omega.discovery',
  'contract': 'omega.collector-registry.v1',
  'provides': ['catalogSourceCandidates',
               'catalogPluginFacts',
               'catalogProjectLinks',
               'catalogRepositoryCandidates',
               'catalogManifestCandidates',
               'catalogIssueHints'],
  'legacyContracts': [{'workflow': 'catalog-builder.yml',
                       'job': 'Discover source feeds',
                       'step': 'Discover curated, Puni.sh and GitHub PluginMaster sources'}],
  'logParser': 'source-discovery',
  'trendMetric': 'Deduplicated sources',
  'trendPolicy': 'stable-volume',
  'cadenceMode': 'scheduled',
  'docs': 'collectors'},
 {'id': 'manifest-normalization',
  'title': 'Manifest normalization',
  'workflow': 'catalog-enrichment-worker.yml',
  'job': 'Collect leased manifest enrichment working state',
  'step': 'Enrich manifests from the settled discovery result',
  'purpose': 'Fetch discovered PluginMaster feeds and normalize plugin manifests into one catalog input model.',
  'inputs': ['catalog/raw-sources.json', 'previous catalog HTTP cache hints'],
  'outputs': ['catalog/enriched-sources.json', 'enriched-sources workflow artifact'],
  'implementation': 'tools/catalog/enrich_metadata.py',
  'logParser': 'manifest-normalization',
  'trendMetric': 'Plugins normalized',
  'trendPolicy': 'stable-volume',
  'cadenceMode': 'scheduled',
  'docs': 'collectors',
  'componentId': 'omega.catalog'},
 {'id': 'website-enrichment',
  'title': 'Website / project enrichment',
  'workflow': 'catalog-scrape-worker.yml',
  'job': 'Collect leased website scraper working state',
  'step': 'Reuse fresh page state and scrape only new/stale project pages',
  'purpose': 'Refresh bounded public project-page metadata while reusing still-fresh cached enrichment.',
  'inputs': ['catalog/enriched-sources.json', 'previous marketplace website cache hints'],
  'outputs': ['catalog/website-enrichment.json', 'website-enrichment workflow artifact'],
  'implementation': 'tools/catalog/scrape_websites_incremental.py',
  'logParser': 'website-enrichment',
  'trendMetric': 'Websites considered',
  'trendPolicy': 'stable-volume',
  'cadenceMode': 'scheduled',
  'docs': 'collectors',
  'componentId': 'omega.catalog'},
 {'id': 'source-revision-observer',
  'title': 'Source revision observer',
  'workflow': 'source-head-worker.yml',
  'job': 'Collect leased source HEAD working state',
  'step': 'Observe public source HEAD revisions without fetching source bodies',
  'purpose': 'Observe public repository HEAD revisions so source changes can invalidate attribution/source-analysis '
             'work deterministically.',
  'inputs': ['canonical catalog source inventory'],
  'outputs': ['catalog/source-revision-observations.json'],
  'implementation': 'tools/catalog/source_revision_observer.py',
  'logParser': 'source-revision-observer',
  'trendMetric': 'Observed',
  'trendPolicy': 'stable-volume',
  'cadenceMode': 'scheduled',
  'docs': 'collectors',
  'componentId': 'omega.sigmascope'},
 {'id': 'threat-intelligence',
  'title': 'Endpoint threat-intelligence collector',
  'workflow': 'threat-intelligence-worker.yml',
  'job': 'Collect leased endpoint threat-intelligence working state',
  'step': 'Collect TTL-backed endpoint threat intelligence',
  'purpose': 'Fetch frozen URL/domain/IP threat indicators, resolve currently observed endpoint hosts, and retain '
             'deterministic match provenance for SRL reprojection.',
  'inputs': ['current Evidence-v2 endpoint relationship index',
             'Feodo Tracker recommended active C2 feed',
             'optional ThreatFox recent IOC API'],
  'outputs': ['catalog/reputation-intelligence.json',
              'frozen Definitions reputation.json',
              'Evidence-v2 threat-intelligence index'],
  'implementation': 'tools/catalog/collect_reputation_intelligence.py',
  'logParser': 'threat-intelligence',
  'trendMetric': 'Indicators',
  'trendPolicy': 'stable-volume',
  'cadenceMode': 'scheduled',
  'docs': 'threat-intelligence',
  'componentId': 'omega.threat-intelligence'},
 {'id': 'advisory-collector',
  'title': 'NuGet / OSV advisory collector',
  'workflow': 'osv-worker.yml',
  'job': 'Collect leased NuGet / OSV advisory working state',
  'step': 'Query OSV for the exact retained NuGet package/version set',
  'purpose': 'Query/freeze advisory intelligence for exact NuGet package/version pairs observed in current evidence.',
  'inputs': ['Evidence-v2 NuGet package/version index', 'OSV public API'],
  'outputs': ['frozen OSV advisory data in Security Definitions'],
  'implementation': 'tools/catalog/collect_public_advisories.py + tools/catalog/definitions_snapshot.py',
  'logParser': 'advisory-collector',
  'trendMetric': 'Packages queried',
  'trendPolicy': 'stable-volume',
  'cadenceMode': 'scheduled',
  'docs': 'collectors',
  'componentId': 'omega.sigmascope'},
 {'id': 'secondary-security-definitions',
  'title': 'Secondary-security definition refresh',
  'workflow': 'secondary-security-worker.yml',
  'job': 'Collect leased secondary-security working state',
  'step': 'Refresh and freeze content-addressed secondary-security assets',
  'purpose': 'Refresh ClamAV definition assets independently of catalog freeze and retain a previous valid frozen asset when upstream refresh fails.',
  'inputs': ['exact secondary-security durable lease', 'previous frozen Definitions when available', 'ClamAV update service'],
  'outputs': ['lease-bound secondary-security work result', 'content-addressed ClamAV asset manifest'],
  'implementation': 'tools/catalog/secondary_security_assets.py + tools/orchestration/work_result.py',
  'cadenceMode': 'scheduled',
  'docs': 'collectors',
  'componentId': 'omega.sigmascope'},
 {'id': 'security-work-reconciler',
  'title': 'Security collection work reconciler',
  'workflow': 'security-reconcile.yml',
  'job': 'Settle, reconcile, lease and dispatch collector work',
  'step': 'Reconcile completed results and create exact leases',
  'purpose': 'Act as the sole durable collection-queue mutator: settle exact lease-bound results, recover expired leases, enqueue due work and dispatch newly leased workers without catalog-freeze or client-publication authority.',
  'inputs': ['orchestration work policy', 'previous security-work-state', 'independent lane result branches'],
  'outputs': ['security-work-state', 'exact worker workflow dispatches'],
  'implementation': 'tools/orchestration/reconcile_work.py + tools/orchestration/work_queue.py',
  'cadenceMode': 'scheduled',
  'docs': 'collectors',
  'componentId': 'omega.platform.main'},
 {'id': 'catalog-freeze',
  'title': 'Catalog freeze and client publication',
  'workflow': 'catalog-freeze.yml',
  'job': 'Freeze coherent state and build the Omega client DB once',
  'step': 'Validate settled lane inputs and compute semantic catalog-freeze identity',
  'purpose': 'Consume settled collection state and current Evidence-v2 at an explicit release boundary; unchanged semantic freezes are no-ops and collector activity cannot invoke this node.',
  'inputs': ['settled seven-lane work state', 'current Evidence-v2', 'digest-pinned publisher worker'],
  'outputs': ['frozen catalog-data snapshot', 'Omega marketplace database only when semantic freeze changes'],
  'implementation': 'tools/orchestration/freeze_inputs.py + tools/orchestration/catalog_freeze_identity.py + tools/catalog/catalog_state.py',
  'cadenceMode': 'manual',
  'docs': 'collectors',
  'componentId': 'omega.catalog'},
 {'id': 'sigmascope-batch',
  'title': 'SigmaScope artifact / source analysis',
  'workflow': 'sigmascope.yml',
  'job': 'Process bounded Sigmascope batch against frozen daily inputs',
  'step': 'Examine bounded due-variant batch and build Evidence v2 candidate',
  'purpose': 'Acquire due artifacts/source evidence and produce bounded immutable analyses plus current Evidence-v2 '
             'projections.',
  'inputs': ['frozen catalog', 'frozen Definitions', 'scan queue seed', 'last-known-good Evidence-v2'],
  'outputs': ['Evidence-v2 candidate', 'updated scanner queue', 'deep-scan requests where applicable'],
  'implementation': 'tools/security/production_sigmascope_v2_pipeline.py',
  'logParser': 'sigmascope-batch',
  'trendMetric': 'Completed in batch',
  'trendPolicy': 'workload-volume',
  'cadenceMode': 'continuous',
  'docs': 'collectors',
  'componentId': 'omega.sigmascope'},
 {'id': 'sigmascope-parallel-result-worker',
  'title': 'SigmaScope parallel result worker (shadow)',
  'workflow': 'sigmascope-parallel-worker.yml',
  'job': 'Run one exact persistent queue key as a result-only worker',
  'step': 'Execute exact frozen queue work and emit immutable result bundle',
  'purpose': 'Execute one exact artifact/source queue key against a frozen Definitions worker and the current Evidence-v2 head, producing a bounded content-addressed variant-local result bundle without Evidence-v2 publication authority.',
  'inputs': ['exact persistent scanner queue key', 'frozen catalog/Definitions', 'current Evidence-v2 base head', 'digest-pinned SigmaScope worker image'],
  'outputs': ['omega.sigmascope-result-bundle.v1 Actions artifact'],
  'implementation': 'tools/security/production_sigmascope_v2_pipeline.py + tools/security/sigmascope_result_bundle.py',
  'cadenceMode': 'manual-shadow',
  'docs': 'collectors',
  'componentId': 'omega.sigmascope'},
 {'id': 'sigmascope-parallel-merge-plan',
  'title': 'SigmaScope parallel merge-plan validator (shadow)',
  'workflow': 'sigmascope-parallel-shadow.yml',
  'job': 'Validate parallel result bundles against one Evidence-v2 base head',
  'step': 'Build conflict-checked non-authoritative merge plan',
  'purpose': 'Validate result-bundle integrity, exact Evidence-v2 base binding, queue-key uniqueness and variant disjointness before a future serialized Evidence-v2 merger is allowed to apply worker results.',
  'inputs': ['parallel SigmaScope result bundles', 'current Evidence-v2 base head'],
  'outputs': ['omega.sigmascope-result-merge-plan.v1 validation artifact'],
  'implementation': 'tools/security/sigmascope_result_bundle.py plan',
  'cadenceMode': 'manual-shadow',
  'docs': 'collectors',
  'componentId': 'omega.evidence-v2'},
 {'id': 'sigmascope-parallel-candidate-merger',
  'title': 'SigmaScope serialized Evidence-v2 candidate merger (shadow)',
  'workflow': 'sigmascope-parallel-shadow.yml',
  'job': 'Build validated serialized Evidence-v2 candidate without publication',
  'step': 'Apply disjoint result bundles and rebuild global Evidence-v2 projections centrally',
  'purpose': 'Apply bounded variant-local worker results over one exact Evidence-v2 base, reconstruct the working database, rebuild global indexes/SRL projections, reproduce source-followup and Deep Scan queue side effects, and intrinsically validate a candidate while retaining zero publication authority.',
  'inputs': ['conflict-checked SigmaScope result bundles', 'exact current Evidence-v2 base', 'frozen catalog/Definitions', 'previous Deep Scan state'],
  'outputs': ['validated candidate Evidence-v2 tree', 'candidate Deep Scan queue', 'source-followup projection', 'merge report'],
  'implementation': 'tools/security/sigmascope_result_merger.py',
  'cadenceMode': 'manual-shadow',
  'docs': 'collectors',
  'componentId': 'omega.evidence-v2'},
 {'id': 'sigmascope-parallel-equivalence-preflight',
  'title': 'SigmaScope serialized equivalence and publication preflight (shadow)',
  'workflow': 'sigmascope-parallel-shadow.yml',
  'job': 'Prove parallel candidate equivalence against serialized reference',
  'step': 'Compare security semantics and assemble no-authority publication-readiness gates',
  'purpose': 'Run the same exact queue assignments through a serialized reference, compare affected variant/queue/SRL/Deep Scan/source-followup semantics, then require intrinsic validation, independent developer audit and storage audit before labeling the candidate publishable. This node cannot publish Evidence-v2.',
  'inputs': ['parallel merged candidate', 'serialized reference candidate', 'developer audit', 'storage audit'],
  'outputs': ['omega.sigmascope-parallel-equivalence.v1', 'omega.sigmascope-parallel-preflight.v1'],
  'implementation': 'tools/security/sigmascope_merge_equivalence.py + tools/security/sigmascope_parallel_preflight.py',
  'cadenceMode': 'manual-shadow',
  'docs': 'collectors',
  'componentId': 'omega.evidence-v2'},
 {'id': 'sigmascope-parallel-one-writer-publisher',
  'title': 'SigmaScope parallel one-writer Evidence publication (manual cutover)',
  'workflow': 'sigmascope-parallel-publish.yml',
  'job': 'Publish authorized Evidence first, then deferred side effects',
  'step': 'Publish exact authorized Security Evidence v2 child',
  'purpose': 'Reconstruct an exact successful Phase-4B candidate under read-only authority, bind it to the still-current Evidence Git parent, then give one tiny serialized writer the ability to fast-forward Evidence-v2 before publishing Deep Scan state and reconciling source follow-up issues. The existing serialized SigmaScope worker remains the production fallback during cutover.',
  'inputs': ['successful Phase-4B shadow run artifacts', 'exact current Evidence-v2 Git head', 'digest-pinned SigmaScope/publisher images', 'frozen catalog/Definitions'],
  'outputs': ['fast-forward Security Evidence-v2 commit', 'publication receipt', 'post-Evidence Deep Scan state', 'source-followup issue reconciliation'],
  'implementation': 'tools/security/sigmascope_parallel_publish_gate.py + tools/security/publish_security_evidence_v2.py',
  'cadenceMode': 'manual-cutover',
  'docs': 'collectors',
  'componentId': 'omega.evidence-v2'},
 {'id': 'sigmascope-native-structure',
  'title': 'SigmaScope ELF / Mach-O structural analysis',
  'workflow': 'sigmascope.yml',
  'job': 'Collect exact ELF and Mach-O structural observations',
  'step': 'Collect bounded native structure observations',
  'purpose': 'Parse one exact broker-bound artifact for bounded ELF/Mach-O loader, dependency, symbol and hardening structure without executing native code.',
  'inputs': ['exact elfBinaryStructure or machOBinaryStructure analysis request', 'frozen Definitions worker', 'current Evidence-v2', 'exact artifact bytes'],
  'outputs': ['content-addressed collector result', 'ELF/Mach-O structural observations', 'collector-only Evidence-v2 update'],
  'implementation': 'tools/security/native_structure_collector.py + tools/security/collector_evidence_adapter.py',
  'provides': ['elfBinaryStructure', 'machOBinaryStructure'],
  'cadenceMode': 'event-driven',
  'docs': 'collectors',
  'componentId': 'omega.sigmascope'},
 {'id': 'sigmascope-authenticode',
  'title': 'SigmaScope Windows Authenticode validation',
  'workflow': 'sigmascope.yml',
  'job': 'Collect exact Windows Authenticode observations',
  'step': 'Collect Authenticode observations with Windows trust APIs',
  'purpose': 'Validate embedded PE Authenticode signatures for one exact broker-bound artifact on a Windows runner without executing plugin binaries.',
  'inputs': ['exact binarySignatureTrust analysis request', 'frozen Definitions worker', 'current Evidence-v2', 'exact artifact bytes'],
  'outputs': ['content-addressed collector result', 'binarySignatureTrust observation', 'collector-only Evidence-v2 update'],
  'implementation': 'tools/security/authenticode_collector.py + tools/security/authenticode_probe.ps1 + tools/security/collector_evidence_adapter.py',
  'provides': ['binarySignatureTrust'],
  'cadenceMode': 'event-driven',
  'docs': 'collectors',
  'componentId': 'omega.sigmascope'},
 {'id': 'source-followup',
  'title': 'Public source follow-up',
  'workflow': 'sigmascope.yml',
  'job': 'Process bounded Sigmascope batch against frozen daily inputs',
  'step': 'Project public-source coverage follow-ups',
  'purpose': 'Project source attribution/re-analysis follow-ups from artifact results and source-observation changes.',
  'inputs': ['current artifact analysis', 'source candidates', 'source revision observations'],
  'outputs': ['source follow-up state', 'source attribution/provenance evidence'],
  'implementation': 'source follow-up projection in the frozen SigmaScope worker',
  'cadenceMode': 'continuous',
  'docs': 'collectors',
  'componentId': 'omega.sigmascope'},
 {'id': 'evidence-publication',
  'title': 'Evidence publication',
  'workflow': 'sigmascope.yml',
  'job': 'Process bounded Sigmascope batch against frozen daily inputs',
  'step': 'Publish validated Security Evidence v2 snapshot atomically',
  'purpose': 'Publish a validated candidate as the new coherent Security Evidence v2 snapshot while preserving '
             'last-known-good state on failure.',
  'inputs': ['validated Evidence-v2 candidate'],
  'outputs': ['security-evidence-v2 branch snapshot'],
  'implementation': 'tools/security/publish_security_evidence_v2.py',
  'cadenceMode': 'continuous',
  'docs': 'collectors',
  'componentId': 'omega.evidence-v2'},
 {'id': 'deep-scan-worker',
  'title': 'Deep Scan worker',
  'workflow': 'deep-scan.yml',
  'job': '',
  'step': 'Execute selected safe deep-scan request',
  'purpose': 'Execute an approved bounded deep-analysis profile selected from the durable Stigma-1 analysis-request '
             'queue.',
  'inputs': ['durable deep-scan queue', 'frozen Definitions/worker', 'selected analysis profile'],
  'outputs': ['durable deep-scan result state', 'deep-scan diagnostics artifact'],
  'implementation': 'tools/security/deep_scan_worker.py',
  'logParser': 'deep-scan-worker',
  'cadenceMode': 'event-driven',
  'docs': 'deep-scan',
  'componentId': 'omega.sigmascope'})


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def validate_node(value: Mapping[str, Any]) -> dict[str, Any]:
    row = dict(value)
    node_id = str(row.get("id") or "")
    if not node_id or len(node_id) > 120:
        raise ValueError(f"invalid execution node id: {node_id!r}")
    workflow = str(row.get("workflow") or "")
    if not workflow.endswith(".yml") and not workflow.endswith(".yaml"):
        raise ValueError(f"execution node {node_id} must name a workflow file")
    component_id = str(row.get("componentId") or "")
    if component_id and component_id not in component_registry.component_map():
        raise ValueError(f"execution node {node_id} references unknown component {component_id!r}")
    if not str(row.get("step") or ""):
        raise ValueError(f"execution node {node_id} must name its primary workflow step")
    for key in ("inputs", "outputs", "provides", "legacyContracts"):
        if key in row and not isinstance(row.get(key), list):
            raise ValueError(f"execution node {node_id} field {key} must be a list")
    return row


def node_map() -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for raw in EXECUTIONS:
        row = validate_node(raw)
        node_id = str(row["id"])
        if node_id in result:
            raise ValueError(f"duplicate execution node id: {node_id}")
        result[node_id] = row
    return result


def topology_revision() -> str:
    semantic = {"schema": TOPOLOGY_SCHEMA, "nodes": EXECUTIONS}
    return f"execution-topology-v1-{_sha(semantic)[:20]}"


def build_topology() -> dict[str, Any]:
    nodes = node_map()
    workflows = sorted({str(row.get("workflow") or "") for row in nodes.values() if row.get("workflow")})
    by_component: dict[str, list[str]] = {}
    for node_id, row in nodes.items():
        component_id = str(row.get("componentId") or "")
        if component_id:
            by_component.setdefault(component_id, []).append(node_id)
    return {
        "schema": TOPOLOGY_SCHEMA,
        "revision": topology_revision(),
        "readOnly": True,
        "mutationAuthority": "none",
        "policyInput": False,
        "launchAuthority": False,
        "componentRegistry": {
            "schema": component_registry.REGISTRY_SCHEMA,
            "revision": component_registry.component_revision(),
        },
        "nodes": [nodes[key] for key in sorted(nodes)],
        "byId": {key: nodes[key] for key in sorted(nodes)},
        "byComponent": {key: sorted(value) for key, value in sorted(by_component.items())},
        "workflows": workflows,
        "nodeCount": len(nodes),
        "workflowCount": len(workflows),
    }
