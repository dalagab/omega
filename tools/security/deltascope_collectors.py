#!/usr/bin/env python3
"""Read-only collector health projection for DeltaScope Operations.

Collectors are mapped to stable GitHub Actions workflow/job/step names.  Recent runner
history is diagnostic input only; published Evidence-v2 remains the security authority.
"""
from __future__ import annotations

import re
from typing import Any, Mapping

SCHEMA = "omega.deltascope.collectors.v1"

COLLECTORS: tuple[dict[str, Any], ...] = (
    {
        "id": "source-discovery",
        "title": "Source discovery",
        "workflow": "catalog-builder.yml",
        "job": "Discover source feeds",
        "step": "Discover curated, Puni.sh and GitHub PluginMaster sources",
        "purpose": "Discover public PluginMaster/source feeds from curated, community, Puni.sh and GitHub discovery inputs.",
        "inputs": ["sources/curated-sources.json", "sources/community-sources.json", "Puni.sh publisher index", "GitHub code search"],
        "outputs": ["catalog/raw-sources.json", "raw-sources workflow artifact"],
        "implementation": "tools/catalog/collect_sources.py",
        "logParser": "source-discovery",
        "docs": "collectors",
    },
    {
        "id": "manifest-normalization",
        "title": "Manifest normalization",
        "workflow": "catalog-builder.yml",
        "job": "Fetch and normalize manifests",
        "step": "Fetch PluginMaster feeds",
        "purpose": "Fetch discovered PluginMaster feeds and normalize plugin manifests into one catalog input model.",
        "inputs": ["catalog/raw-sources.json", "previous catalog HTTP cache hints"],
        "outputs": ["catalog/enriched-sources.json", "enriched-sources workflow artifact"],
        "implementation": "tools/catalog/enrich_metadata.py",
        "logParser": "manifest-normalization",
        "docs": "collectors",
    },
    {
        "id": "website-enrichment",
        "title": "Website / project enrichment",
        "workflow": "catalog-builder.yml",
        "job": "Incrementally enrich public project pages",
        "step": "Reuse fresh enrichment and scrape only new/stale project pages",
        "purpose": "Refresh bounded public project-page metadata while reusing still-fresh cached enrichment.",
        "inputs": ["catalog/enriched-sources.json", "previous marketplace website cache hints"],
        "outputs": ["catalog/website-enrichment.json", "website-enrichment workflow artifact"],
        "implementation": "tools/catalog/scrape_websites_incremental.py",
        "logParser": "website-enrichment",
        "docs": "collectors",
    },
    {
        "id": "source-revision-observer",
        "title": "Source revision observer",
        "workflow": "catalog-builder.yml",
        "job": "Freeze JSON state and compile the Omega client DB",
        "step": "Observe public source HEAD revisions without fetching source bodies",
        "purpose": "Observe public repository HEAD revisions so source changes can invalidate attribution/source-analysis work deterministically.",
        "inputs": ["canonical catalog source inventory"],
        "outputs": ["catalog/source-revision-observations.json"],
        "implementation": "tools/catalog/source_revision_observer.py",
        "logParser": "source-revision-observer",
        "docs": "collectors",
    },
    {
        "id": "advisory-collector",
        "title": "NuGet / OSV advisory collector",
        "workflow": "catalog-builder.yml",
        "job": "Freeze JSON state and compile the Omega client DB",
        "step": "Freeze daily Definitions and OSV data",
        "purpose": "Query/freeze advisory intelligence for exact NuGet package/version pairs observed in current evidence.",
        "inputs": ["Evidence-v2 NuGet package/version index", "OSV public API"],
        "outputs": ["frozen OSV advisory data in Security Definitions"],
        "implementation": "tools/catalog/collect_public_advisories.py + tools/catalog/definitions_snapshot.py",
        "logParser": "advisory-collector",
        "docs": "collectors",
    },
    {
        "id": "sigmascope-batch",
        "title": "SigmaScope artifact / source analysis",
        "workflow": "sigmascope.yml",
        "job": "Process bounded Sigmascope batch against frozen daily inputs",
        "step": "Examine bounded due-variant batch and build Evidence v2 candidate",
        "purpose": "Acquire due artifacts/source evidence and produce bounded immutable analyses plus current Evidence-v2 projections.",
        "inputs": ["frozen catalog", "frozen Definitions", "scan queue seed", "last-known-good Evidence-v2"],
        "outputs": ["Evidence-v2 candidate", "updated scanner queue", "deep-scan requests where applicable"],
        "implementation": "tools/security/production_sigmascope_v2_pipeline.py",
        "logParser": "sigmascope-batch",
        "docs": "collectors",
    },
    {
        "id": "source-followup",
        "title": "Public source follow-up",
        "workflow": "sigmascope.yml",
        "job": "Process bounded Sigmascope batch against frozen daily inputs",
        "step": "Project public-source coverage follow-ups",
        "purpose": "Project source attribution/re-analysis follow-ups from artifact results and source-observation changes.",
        "inputs": ["current artifact analysis", "source candidates", "source revision observations"],
        "outputs": ["source follow-up state", "source attribution/provenance evidence"],
        "implementation": "source follow-up projection in the frozen SigmaScope worker",
        "docs": "collectors",
    },
    {
        "id": "evidence-publication",
        "title": "Evidence publication",
        "workflow": "sigmascope.yml",
        "job": "Process bounded Sigmascope batch against frozen daily inputs",
        "step": "Publish validated Security Evidence v2 snapshot atomically",
        "purpose": "Publish a validated candidate as the new coherent Security Evidence v2 snapshot while preserving last-known-good state on failure.",
        "inputs": ["validated Evidence-v2 candidate"],
        "outputs": ["security-evidence-v2 branch snapshot"],
        "implementation": "tools/security/publish_security_evidence_v2.py",
        "docs": "collectors",
    },
    {
        "id": "deep-scan-worker",
        "title": "Deep Scan worker",
        "workflow": "deep-scan.yml",
        "job": "",
        "step": "Execute selected safe deep-scan request",
        "purpose": "Execute an approved bounded deep-analysis profile selected from the durable Stigma-1 analysis-request queue.",
        "inputs": ["durable deep-scan queue", "frozen Definitions/worker", "selected analysis profile"],
        "outputs": ["durable deep-scan result state", "deep-scan diagnostics artifact"],
        "implementation": "tools/security/deep_scan_worker.py",
        "logParser": "deep-scan-worker",
        "docs": "deep-scan",
    },
)


def _state(status: object, conclusion: object) -> str:
    status_s = str(status or "").casefold()
    conclusion_s = str(conclusion or "").casefold()
    if status_s in {"queued", "in_progress", "waiting", "pending", "requested"}:
        return "running"
    if conclusion_s in {"failure", "timed_out", "action_required", "startup_failure"}:
        return "failed"
    if conclusion_s in {"cancelled", "neutral", "stale"}:
        return "warning"
    if conclusion_s == "success":
        return "healthy"
    if conclusion_s == "skipped":
        return "skipped"
    return "unknown"


def _find_job_step(run: Mapping[str, Any], job_name: str, step_name: str) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    jobs = [job for job in (run.get("jobs") or []) if isinstance(job, Mapping)]
    preferred = [job for job in jobs if not job_name or str(job.get("name") or "") == job_name]
    candidates = preferred or jobs
    for job in candidates:
        for step in job.get("steps") or []:
            if isinstance(step, Mapping) and str(step.get("name") or "") == step_name:
                return dict(job), dict(step)
    return (dict(preferred[0]) if preferred else None), None


def _strip_log_prefix(text: str) -> str:
    # GitHub job logs often prefix each line with an ISO timestamp.
    return re.sub(r"(?m)^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\s+", "", text or "")


def _log_metrics(kind: str, text: str) -> list[dict[str, Any]]:
    text = _strip_log_prefix(text)
    metrics: list[dict[str, Any]] = []
    def add(label: str, value: object, unit: str = "") -> None:
        metrics.append({"label": label, "value": value, "unit": unit, "source": "latest runner log"})

    if kind == "source-discovery":
        m = re.search(r"Wrote\s+\S*raw-sources\.json:\s+(\d+)\s+source\(s\).*?(\d+)\s+curated,\s+(\d+)\s+community,\s+(\d+)\s+puni\.sh,\s+(\d+)\s+github-search", text, re.I | re.S)
        if m:
            add("Deduplicated sources", int(m.group(1)))
            add("Curated", int(m.group(2)))
            add("Community", int(m.group(3)))
            add("Puni.sh", int(m.group(4)))
            add("GitHub discovery", int(m.group(5)))
    elif kind == "manifest-normalization":
        m = re.search(r"Wrote\s+\S*enriched-sources\.json:\s+(\d+)\s+plugins\s+\((\d+)\s+metadata-complete\)\s+from\s+(\d+)/(\d+)\s+source\(s\)\s+OK", text, re.I)
        if m:
            add("Plugins normalized", int(m.group(1)))
            add("Metadata complete", int(m.group(2)))
            add("Sources OK", int(m.group(3)))
            add("Sources attempted", int(m.group(4)))
    elif kind == "website-enrichment":
        m = re.search(r"Wrote\s+\S*website-enrichment\.json:\s+(\d+)\s+cached website\(s\),\s+(\d+)\s+network scrape\(s\)", text, re.I)
        if m:
            add("Cached websites reused", int(m.group(1)))
            add("Network scrapes", int(m.group(2)))
    elif kind == "source-revision-observer":
        # The observer prints JSON containing counts. Keep this intentionally narrow.
        matches = re.findall(r'"repositories"\s*:\s*(\d+).*?"observed"\s*:\s*(\d+).*?"failed"\s*:\s*(\d+)', text, re.I | re.S)
        if matches:
            repositories, observed, failed = matches[-1]
            add("Repositories", int(repositories))
            add("Observed", int(observed))
            add("Failed", int(failed))
    elif kind == "advisory-collector":
        matches = re.findall(r'"queriedPackages"\s*:\s*(\d+).*?"matchedPackages"\s*:\s*(\d+)', text, re.I | re.S)
        if matches:
            queried, matched = matches[-1]
            add("Packages queried", int(queried))
            add("Packages matched", int(matched))
    elif kind == "deep-scan-worker":
        matches = re.findall(r'"requestId"\s*:\s*"([^"]+)".*?"profile"\s*:\s*"([^"]+)".*?"depth"\s*:\s*"([^"]+)"', text, re.I | re.S)
        if matches:
            request_id, profile, depth = matches[-1]
            add("Request", request_id)
            add("Profile", profile)
            add("Depth", depth)
        elif re.search(r"No executable pending deep-scan request", text, re.I):
            add("Pending executable request", False)
    elif kind == "sigmascope-batch":
        matches = re.findall(r'"successful"\s*:\s*(\d+).*?"failedRetained"\s*:\s*(\d+).*?"queueSelected"\s*:\s*(\d+).*?"scanSelected"\s*:\s*(\d+).*?"completed"\s*:\s*(\d+).*?"failed"\s*:\s*(\d+)', text, re.I | re.S)
        if matches:
            successful, failed_retained, queue_selected, scan_selected, completed, failed = matches[-1]
            add("Successful analyses", int(successful))
            add("Failures retained", int(failed_retained))
            add("Queue selected", int(queue_selected))
            add("Scan selected", int(scan_selected))
            add("Completed in batch", int(completed))
            add("Failed in batch", int(failed))
    return metrics


def _evidence_metrics(collector_id: str, summary: Mapping[str, Any], context: Mapping[str, Any]) -> list[dict[str, Any]]:
    counts = summary.get("counts") if isinstance(summary.get("counts"), Mapping) else {}
    queue = summary.get("queueSummary") if isinstance(summary.get("queueSummary"), Mapping) else {}
    last_batch = summary.get("lastBatch") if isinstance(summary.get("lastBatch"), Mapping) else {}
    osv = summary.get("osv") if isinstance(summary.get("osv"), Mapping) else {}
    pending = queue.get("pendingByReason") if isinstance(queue.get("pendingByReason"), Mapping) else {}
    out: list[dict[str, Any]] = []
    def add(label: str, value: object, unit: str = "", source: str = "published evidence") -> None:
        if value is None or value == "":
            return
        out.append({"label": label, "value": value, "unit": unit, "source": source})

    if collector_id in {"source-discovery", "manifest-normalization", "website-enrichment"}:
        add("Current plugins", counts.get("plugins"))
        add("Current variants", counts.get("variants"))
    if collector_id == "source-revision-observer":
        add("Source-observation work pending", pending.get("source_observation_changed", 0))
        add("Source-candidate changes pending", pending.get("source_candidates_changed", 0))
    if collector_id == "advisory-collector":
        add("Observed NuGet versions", counts.get("observedNugetVersions"))
        add("OSV queried pairs", osv.get("queriedPackageVersionPairs", counts.get("osvQueriedPackages")))
        add("OSV matched pairs", osv.get("matchedPackageVersionPairs", counts.get("osvMatchedPackages")))
        add("Not covered by frozen Definitions", osv.get("notCoveredByFrozenDefinitions"))
        add("Advisory records", counts.get("advisories"))
    if collector_id == "sigmascope-batch":
        add("Last batch selected", last_batch.get("selectedCount"))
        add("Current completed scans", counts.get("completeScans"))
        add("Current failed scans", counts.get("failedScans"))
        add("Queue pending", counts.get("queuePending"))
        add("Queue retry", counts.get("queueRetry"))
    if collector_id == "source-followup":
        add("Source follow-up pending", pending.get("source_followup", 0))
        add("Source unresolved", pending.get("source_unresolved", 0))
        add("New source candidate observed", pending.get("source_candidate_observed", 0))
    if collector_id == "evidence-publication":
        add("Current variants", counts.get("variants"))
        add("Immutable analyses", counts.get("analyses"))
        add("Latest completed analysis", summary.get("latestScanUtc"), source="published evidence")
        add("Evidence generated", summary.get("generatedAtUtc"), source="published evidence")
    if collector_id == "deep-scan-worker":
        # Queue presence is intentionally generic until the publication contract exposes
        # exact deep-scan summary counts in the root index.
        rule_projection = context.get("ruleProjections") if isinstance(context.get("ruleProjections"), Mapping) else {}
        if rule_projection.get("available") is not None:
            add("Rule projection data available", bool(rule_projection.get("available")))
    return out


def _history_for_collector(definition: Mapping[str, Any], workflow_payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for run in workflow_payload.get("runs") or []:
        if not isinstance(run, Mapping):
            continue
        job, step = _find_job_step(run, str(definition.get("job") or ""), str(definition.get("step") or ""))
        state_source = step or job or run
        state = _state(state_source.get("status"), state_source.get("conclusion"))
        log_text = str((job or {}).get("logPreview") or "")
        rows.append({
            "runId": int(run.get("runId") or 0),
            "runNumber": int(run.get("runNumber") or 0),
            "createdAtUtc": str(run.get("createdAtUtc") or ""),
            "updatedAtUtc": str(run.get("updatedAtUtc") or ""),
            "state": state,
            "status": str(state_source.get("status") or ""),
            "conclusion": str(state_source.get("conclusion") or ""),
            "stepObserved": step is not None,
            "job": str((job or {}).get("name") or definition.get("job") or ""),
            "step": str((step or {}).get("name") or definition.get("step") or ""),
            "url": str((job or {}).get("url") or run.get("url") or ""),
            "artifacts": [dict(row) for row in (run.get("artifacts") or []) if isinstance(row, Mapping)],
            "metrics": _log_metrics(str(definition.get("logParser") or ""), log_text),
        })
    return rows


def project_collectors(
    workflow_histories: Mapping[str, Mapping[str, Any]],
    summary: Mapping[str, Any],
    context: Mapping[str, Any],
) -> dict[str, Any]:
    collectors: list[dict[str, Any]] = []
    for definition in COLLECTORS:
        workflow = str(definition["workflow"])
        payload = workflow_histories.get(workflow) or {}
        history = _history_for_collector(definition, payload)
        latest = history[0] if history else None
        observed = [row for row in history if row.get("state") not in {"unknown", "skipped"}]
        success = sum(1 for row in observed if row.get("state") == "healthy")
        failed = sum(1 for row in observed if row.get("state") == "failed")
        metrics = list((latest or {}).get("metrics") or []) + _evidence_metrics(str(definition["id"]), summary, context)
        # De-duplicate metric labels, preferring the runner log (more specific to the last run).
        dedup: dict[str, dict[str, Any]] = {}
        for metric in metrics:
            label = str(metric.get("label") or "")
            if label and label not in dedup:
                dedup[label] = metric
        collectors.append({
            **{key: definition[key] for key in ("id", "title", "workflow", "job", "step", "purpose", "inputs", "outputs", "implementation", "docs")},
            "available": bool(payload.get("available", False)),
            "state": str((latest or {}).get("state") or ("unavailable" if payload.get("error") else "unknown")),
            "latest": latest,
            "history": history,
            "recentObservedRuns": len(observed),
            "recentSuccesses": success,
            "recentFailures": failed,
            "recentSuccessRate": round(success * 100.0 / len(observed), 1) if observed else None,
            "metrics": list(dedup.values()),
            "error": str(payload.get("error") or ""),
            "readOnly": True,
        })
    return {
        "schema": SCHEMA,
        "readOnly": True,
        "mutationAuthority": "none",
        "policyInput": False,
        "collectors": collectors,
        "collectorCount": len(collectors),
        "failingCount": sum(1 for row in collectors if row["state"] == "failed"),
        "runningCount": sum(1 for row in collectors if row["state"] == "running"),
        "unknownCount": sum(1 for row in collectors if row["state"] in {"unknown", "unavailable"}),
    }
