#!/usr/bin/env python3
"""Allow-listed local documentation catalog for the DeltaScope documentation page."""
from __future__ import annotations

from pathlib import Path
from typing import Any

SCHEMA = "omega.deltascope.documentation-catalog.v1"
PROJECT_ROOT = Path(__file__).resolve().parents[2]

DOCS: tuple[dict[str, str], ...] = (
    {"id": "stigma1", "group": "Rules / Stigma-1", "title": "Stigma-1 overview", "path": "docs/STIGMA-1.md", "summary": "What Stigma-1 owns and how SigmaScope and DeltaScope use it."},
    {"id": "deep-scan", "group": "Rules / Stigma-1", "title": "Deep Scan workflow", "path": "docs/DEEP-SCAN-WORKFLOW.md", "summary": "Typed analysisRequest outcomes, durable queue semantics, executable deep-static profile and sandbox boundary."},
    {"id": "rule-author-start", "group": "Rules / Stigma-1", "title": "Start writing rules", "path": "docs/rule-authors/README.md", "summary": "Rule-author quick start and the recommended reading order."},
    {"id": "srl-language", "group": "Rules / Stigma-1", "title": "SRL v1 language reference", "path": "docs/SIGMASCOPE-RULE-LANGUAGE.md", "summary": "Schemas, selectors, conditions, operators, replay safety and examples."},
    {"id": "rule-design", "group": "Rules / Stigma-1", "title": "Rule design guidance", "path": "docs/rule-authors/RULE-DESIGN.md", "summary": "How to create useful static-security rules without overclaiming."},
    {"id": "rule-data", "group": "Rules / Stigma-1", "title": "Rule data reference", "path": "docs/rule-authors/DATA-REFERENCE.md", "summary": "Registered retained observation collections and field meanings."},
    {"id": "rule-workflow", "group": "Rules / Stigma-1", "title": "DeltaScope rule workflow", "path": "docs/rule-authors/DELTASCOPE-WORKFLOW.md", "summary": "Compile, test, replay, fork, visual authoring and candidate export."},
    {"id": "definition-packs", "group": "Rules / Stigma-1", "title": "Definition Packs", "path": "docs/DEFINITION-PACKS.md", "summary": "Pack manifests, fixtures, trust tiers, review and freezing."},
    {"id": "rule-workbench", "group": "Rules / Stigma-1", "title": "Rule workbench architecture", "path": "docs/DELTASCOPE-RULE-WORKBENCH.md", "summary": "Local-rule boundaries, graph authoring and production separation."},
    {"id": "rule-example", "group": "Rules / Stigma-1", "title": "Example SRL rules", "path": "docs/rule-authors/examples/process-network-rules.yaml", "summary": "A compileable observation + correlation ruleset."},
    {"id": "rule-example-positive", "group": "Rules / Stigma-1", "title": "Example positive fixture", "path": "docs/rule-authors/examples/process-network-positive.fixture.yaml", "summary": "Positive fixture for the shipped example ruleset."},
    {"id": "rule-example-negative", "group": "Rules / Stigma-1", "title": "Example negative fixture", "path": "docs/rule-authors/examples/process-network-negative.fixture.yaml", "summary": "Near-miss fixture showing expected non-match behavior."},
    {"id": "architecture", "group": "Security system", "title": "Security architecture and authority model", "path": "docs/ARCHITECTURE-SECURITY-MODEL.md", "summary": "Component boundaries, evidence authority and publication model."},
    {"id": "deltascope", "group": "Security system", "title": "DeltaScope workbench", "path": "docs/DELTASCOPE-SECURITY-WORKBENCH.md", "summary": "Investigation UI, read-only evidence model and workbench projections."},
    {"id": "observations", "group": "Security system", "title": "Observation projection contract", "path": "docs/OBSERVATION-PROJECTION-CONTRACT.md", "summary": "What retained evidence is replayable and when re-analysis is required."},
    {"id": "behavior", "group": "Security system", "title": "Behavior consistency", "path": "docs/BEHAVIOR-CONSISTENCY.md", "summary": "Developer declarations versus observed static behavior."},
    {"id": "plugin-profile", "group": "Plugin developers", "title": "Omega plugin profile", "path": "docs/OMEGA-PLUGIN-PROFILE.md", "summary": "Optional developer declarations and their non-authoritative role."},
    {"id": "plugin-developers", "group": "Plugin developers", "title": "Plugin developer documentation", "path": "docs/plugin-developers/README.md", "summary": "Developer-facing security metadata and transparency guidance."},
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
