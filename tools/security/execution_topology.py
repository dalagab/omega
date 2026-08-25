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
  'workflow': 'catalog-discovery.yml',
  'job': 'Discover new PluginMaster and plugin facts',
  'step': 'Run typed discovery collectors and validate only novel source facts',
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
  'workflow': 'catalog-builder.yml',
  'job': 'Fetch and normalize manifests',
  'step': 'Fetch PluginMaster feeds',
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
  'workflow': 'catalog-builder.yml',
  'job': 'Incrementally enrich public project pages',
  'step': 'Reuse fresh enrichment and scrape only new/stale project pages',
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
  'workflow': 'catalog-builder.yml',
  'job': 'Freeze JSON state and compile the Omega client DB',
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
  'componentId': 'omega.catalog'},
 {'id': 'threat-intelligence',
  'title': 'Endpoint threat-intelligence collector',
  'workflow': 'catalog-builder.yml',
  'job': 'Freeze JSON state and compile the Omega client DB',
  'step': 'Collect daily endpoint threat intelligence',
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
  'workflow': 'catalog-builder.yml',
  'job': 'Freeze JSON state and compile the Omega client DB',
  'step': 'Freeze daily Definitions and OSV data',
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
