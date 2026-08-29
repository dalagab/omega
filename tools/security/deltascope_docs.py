#!/usr/bin/env python3
"""Allow-listed platform documentation catalog for DeltaScope."""
from __future__ import annotations

from pathlib import Path
from typing import Any

SCHEMA = "omega.deltascope.documentation-catalog.v1"
PROJECT_ROOT = Path(__file__).resolve().parents[2]

# The order is intentional: start with purpose/audience material, then extension guides,
# then low-level references.  Development plans/handover notes are deliberately excluded.
DOCS: tuple[dict[str, str], ...] = (
    {"id": "platform", "group": "Start here", "title": "Omega security platform", "path": "docs/platform/README.md", "summary": "What the whole platform does, how data flows, and where each component's authority stops."},
    {"id": "perspectives", "group": "Start here", "title": "Choose a DeltaScope perspective", "path": "docs/DELTASCOPE-PERSPECTIVES.md", "summary": "Plugin Developer, Investigator, Security Researcher and Operations workflows over the same evidence."},
    {"id": "architecture", "group": "Start here", "title": "Security architecture", "path": "docs/platform/ARCHITECTURE.md", "summary": "Collectors, Catalog, SigmaScope, Definitions, Stigma-1, Deep Scan, Evidence-v2, DeltaScope, Rift and Alpha."},
    {"id": "discovery", "group": "Start here", "title": "Omega Discovery", "path": "docs/platform/DISCOVERY.md", "summary": "Six-hour ecosystem intelligence, first-class collector IDs, typed observations, provenance and the non-authoritative catalog handoff."},
    {"id": "component-registry", "group": "Start here", "title": "Component Registry & Analysis Broker", "path": "docs/platform/COMPONENT-REGISTRY-AND-ANALYSIS-BROKER.md", "summary": "Machine-readable service boundaries, launchability, typed provider resolution, freshness and durable generic analysis-request state."},
    {"id": "evidence-lifecycle", "group": "Start here", "title": "Evidence lifecycle & authority", "path": "docs/platform/EVIDENCE-LIFECYCLE.md", "summary": "Current versus archive versions, immutable analyses, source provenance, coverage, integrity and replay."},

    {"id": "plugin-developers", "group": "Plugin developers", "title": "Plugin Developer guide", "path": "docs/plugin-developers/README.md", "summary": "Understand findings, Journey, version changes, source/build provenance and what Omega needs from your plugin."},
    {"id": "plugin-profile", "group": "Plugin developers", "title": "Omega plugin profile", "path": "docs/OMEGA-PLUGIN-PROFILE.md", "summary": "How to write .omega/plugin.yaml and what developer declarations can and cannot influence."},
    {"id": "behavior", "group": "Plugin developers", "title": "Observed versus declared behavior", "path": "docs/BEHAVIOR-CONSISTENCY.md", "summary": "How Omega compares independent observations with developer-authored explanations."},

    {"id": "investigators", "group": "Investigators", "title": "Investigator guide", "path": "docs/investigators/README.md", "summary": "Follow a plugin from case to Journey, findings, endpoints, relationships, events and exact evidence."},
    {"id": "investigator-cases", "group": "Investigators", "title": "Local Investigator cases", "path": "docs/investigators/LOCAL-CASES.md", "summary": "Local-only notebooks for notes, bookmarks, pinned observations/findings, saved pivots and Evidence-v2 snapshot references; never security authority."},
    {"id": "finding-lineage", "group": "Investigators", "title": "Finding lineage", "path": "docs/platform/FINDING-LINEAGE.md", "summary": "Trace a current finding from collector and retained observations through Stigma-1/static evaluation into published evidence."},

    {"id": "researchers", "group": "Security researchers", "title": "Security Researcher guide", "path": "docs/security-researchers/README.md", "summary": "Corpus-wide intelligence, comparisons, raw evidence, replay and rule research."},
    {"id": "detection-systems", "group": "Security researchers", "title": "Detection systems", "path": "docs/platform/DETECTION-SYSTEMS.md", "summary": "Choose between scanner observations, Stigma-1, YARA, ClamAV, OSV and Deep Scan; add detections safely."},
    {"id": "detection-coverage", "group": "Security researchers", "title": "Detection coverage & blind spots", "path": "docs/platform/DETECTION-COVERAGE.md", "summary": "How DeltaScope measures observation-producer coverage, stale analyses, rule dependencies and rescan requirements."},
    {"id": "threat-intelligence", "group": "Security researchers", "title": "URL/domain/IP threat intelligence", "path": "docs/platform/THREAT-INTELLIGENCE.md", "summary": "Daily frozen malicious/C2 intelligence, DNS resolution, risk semantics and deterministic SRL endpoint correlation."},
    {"id": "change-attribution", "group": "Investigators", "title": "Why did a security result change?", "path": "docs/platform/CHANGE-ATTRIBUTION.md", "summary": "Distinguish plugin changes from scanner, Definitions, advisory and reputation-intelligence changes."},
    {"id": "tagging", "group": "Security researchers", "title": "Tagging & classification", "path": "docs/platform/TAGGING-AND-CLASSIFICATION.md", "summary": "Marketplace tags, profile tags, capability vocabulary, source permissions and presentation classifications."},

    {"id": "operations", "group": "Operations", "title": "Operations guide", "path": "docs/operations/README.md", "summary": "Dashboard, pipelines, collectors, queues, evidence, Definitions and production authority gates."},
    {"id": "github-workflows", "group": "Operations", "title": "GitHub Workflow Center", "path": "docs/operations/GITHUB-WORKFLOW-CENTER.md", "summary": "Workflow inventory, explicit per-workflow acquisition, guided dispatch, run/job/step/artifact/log inspection and bounded GitHub run controls."},
    {"id": "data-acquisition", "group": "Operations", "title": "Data acquisition & local snapshots", "path": "docs/operations/DATA-ACQUISITION.md", "summary": "Why navigation never refreshes remote data, how local snapshots are acquired, and where Git versus GitHub API transport fits."},
    {"id": "scan-queue", "group": "Operations", "title": "Scan queue causality", "path": "docs/operations/SCAN-QUEUE.md", "summary": "Why scanning can appear to start at A again, coverage-first lanes, queue reasons and the catalog identity baseline boundary."},
    {"id": "collectors", "group": "Operations", "title": "Collectors & data acquisition", "path": "docs/platform/COLLECTORS.md", "summary": "What every collector consumes/produces, how DeltaScope reviews recent runner history, and how to add one."},
    {"id": "platform-operations", "group": "Operations", "title": "Operational model", "path": "docs/platform/OPERATIONS.md", "summary": "How to interpret pipeline/collector failures, queues, last-known-good evidence and gates."},

    {"id": "extending", "group": "Extending Omega", "title": "Extending Omega security logic", "path": "docs/platform/EXTENDING-OMEGA.md", "summary": "Decision guide for adding collectors, observations, capabilities, tags, rules, YARA and Deep Scan logic."},
    {"id": "stigma1", "group": "Extending Omega", "title": "Stigma-1 overview", "path": "docs/STIGMA-1.md", "summary": "What Stigma-1 owns, its safety model and the fastest rule-authoring workflow."},
    {"id": "rule-author-start", "group": "Extending Omega", "title": "Start writing rules", "path": "docs/rule-authors/README.md", "summary": "When to use SRL, how to design a rule, and the quality checklist."},
    {"id": "rule-workflow", "group": "Extending Omega", "title": "DeltaScope rule workflow", "path": "docs/rule-authors/DELTASCOPE-WORKFLOW.md", "summary": "Edit, validate, dry-run, replay, fixture-test and propose a local Stigma-1 rule."},
    {"id": "rule-design", "group": "Extending Omega", "title": "Rule design guidance", "path": "docs/rule-authors/RULE-DESIGN.md", "summary": "Evidence-chain design, severity, negative fixtures, static-language discipline and Deep Scan requests."},
    {"id": "definition-packs", "group": "Extending Omega", "title": "Definition Packs", "path": "docs/DEFINITION-PACKS.md", "summary": "How reviewed rules/fixtures are grouped, compiled, frozen and separated from local/experimental rules."},
    {"id": "deep-scan", "group": "Extending Omega", "title": "Deep Scan workflow", "path": "docs/DEEP-SCAN-WORKFLOW.md", "summary": "Typed analysisRequest outcomes, durable queue semantics and code-owned bounded analysis profiles."},

    {"id": "srl-language", "group": "Reference", "title": "SRL language reference", "path": "docs/SIGMASCOPE-RULE-LANGUAGE.md", "summary": "SRL safety model, inputs, selectors, conditions, outputs and replay completeness."},
    {"id": "rule-data", "group": "Reference", "title": "Rule data reference", "path": "docs/rule-authors/DATA-REFERENCE.md", "summary": "Registered observation collections, fields, authority classes and completeness semantics."},
    {"id": "observations", "group": "Reference", "title": "Observation / projection contract", "path": "docs/OBSERVATION-PROJECTION-CONTRACT.md", "summary": "How retained primitive evidence differs from derived projections and when re-analysis is required."},
    {"id": "rule-workbench", "group": "Reference", "title": "Rule workbench architecture", "path": "docs/DELTASCOPE-RULE-WORKBENCH.md", "summary": "System Rules, My Rules, YAML/visual/test surfaces and the local/production authority boundary."},
    {"id": "deltascope", "group": "Reference", "title": "DeltaScope workbench", "path": "docs/DELTASCOPE-SECURITY-WORKBENCH.md", "summary": "Object-centric workbench, perspectives, read-only boundaries and documentation model."},
    {"id": "deltascope-separation", "group": "Reference", "title": "DeltaScope consumer separation", "path": "docs/DELTASCOPE-SEPARATION.md", "summary": "Python runtime ownership, verified published-resource sync, offline cache semantics and the boundary from SigmaScope/SRL production authority."},
    {"id": "architecture-contract", "group": "Reference", "title": "Architecture authority contract", "path": "docs/ARCHITECTURE-SECURITY-MODEL.md", "summary": "Concise component/authority and re-analysis contract."},
    {"id": "discovery-rule-example", "group": "Reference", "title": "Discovery collector rule example", "path": "docs/rule-authors/examples/catalog-discovery-rule.yaml", "summary": "Compileable rule over Omega Discovery observations with a non-executable typed observationRequest."},
    {"id": "discovery-rule-fixture", "group": "Reference", "title": "Discovery rule positive fixture", "path": "docs/rule-authors/examples/catalog-discovery-positive.fixture.yaml", "summary": "Fixture showing a newly discovered plugin requesting repository-candidate context."},
    {"id": "rule-example", "group": "Reference", "title": "Example SRL rules", "path": "docs/rule-authors/examples/process-network-rules.yaml", "summary": "Compileable observation and correlation ruleset."},
    {"id": "rule-example-positive", "group": "Reference", "title": "Example positive fixture", "path": "docs/rule-authors/examples/process-network-positive.fixture.yaml", "summary": "Positive fixture for the shipped example ruleset."},
    {"id": "rule-example-negative", "group": "Reference", "title": "Example negative fixture", "path": "docs/rule-authors/examples/process-network-negative.fixture.yaml", "summary": "Near-miss fixture showing expected non-match behavior."},
)


def catalog() -> dict[str, Any]:
    docs: list[dict[str, Any]] = []
    for item in DOCS:
        path = PROJECT_ROOT / item["path"]
        docs.append({**item, "available": path.is_file(), "bytes": path.stat().st_size if path.is_file() else 0})
    return {
        "schema": SCHEMA,
        "readOnly": True,
        "mutationAuthority": "none",
        "documents": docs,
    }


def read_document(doc_id: str) -> dict[str, Any]:
    wanted = next((item for item in DOCS if item["id"] == str(doc_id or "")), None)
    if not wanted:
        raise ValueError("unknown documentation id")
    path = (PROJECT_ROOT / wanted["path"]).resolve()
    docs_root = (PROJECT_ROOT / "docs").resolve()
    if docs_root != path and docs_root not in path.parents:
        raise ValueError("documentation path escaped docs root")
    if not path.is_file():
        raise ValueError(f"documentation file is unavailable: {wanted['path']}")
    text = path.read_text(encoding="utf-8")
    if len(text.encode("utf-8")) > 512 * 1024:
        raise ValueError("documentation file exceeds DeltaScope display bound")
    return {
        "schema": "omega.deltascope.documentation-document.v1",
        "readOnly": True,
        "mutationAuthority": "none",
        **wanted,
        "content": text,
    }
