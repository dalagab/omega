#!/usr/bin/env python3
"""Read-only collector health and trend projection for DeltaScope Operations.

Collectors are mapped to stable GitHub Actions workflow/job/step names. Recent runner
history is diagnostic input only; published Evidence-v2 remains the security authority.
The trend model measures operational quality (outcomes, duration, freshness and parsed
throughput) without turning runner history into policy or security evidence.
"""
from __future__ import annotations

import datetime as dt
import re
import statistics
from typing import Any, Mapping

SCHEMA = "omega.deltascope.collectors.v2"

COLLECTORS: tuple[dict[str, Any], ...] = (
    {
        "id": "source-discovery",
        "title": "Omega Discovery / source intelligence",
        "workflow": "catalog-discovery.yml",
        "job": "Discover new PluginMaster and plugin facts",
        "step": "Run typed discovery collectors and validate only novel source facts",
        "purpose": "Run the first-class Omega Discovery component: source search, project-page links, issue hints, optional web search, rotating repository-tree inspection and PluginMaster validation.",
        "inputs": ["canonical catalog-data", "curated/community registries", "Puni.sh", "GitHub code search", "canonical project-page enrichment", "Omega source issues", "optional configured web-search API"],
        "outputs": ["catalog-discovery snapshot", "typed collector observations", "normalized reusable novel-source shards"],
        "implementation": "tools/catalog/catalog_discovery.py + tools/catalog/discovery_collectors.py",
        "componentId": "omega.discovery",
        "contract": "omega.collector-registry.v1",
        "provides": ["catalogSourceCandidates", "catalogPluginFacts", "catalogProjectLinks", "catalogRepositoryCandidates", "catalogManifestCandidates", "catalogIssueHints"],
        "legacyContracts": [{
            "workflow": "catalog-builder.yml",
            "job": "Discover source feeds",
            "step": "Discover curated, Puni.sh and GitHub PluginMaster sources",
        }],
        "logParser": "source-discovery",
        "trendMetric": "Deduplicated sources",
        "trendPolicy": "stable-volume",
        "cadenceMode": "scheduled",
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
        "trendMetric": "Plugins normalized",
        "trendPolicy": "stable-volume",
        "cadenceMode": "scheduled",
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
        "trendMetric": "Websites considered",
        "trendPolicy": "stable-volume",
        "cadenceMode": "scheduled",
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
        "trendMetric": "Observed",
        "trendPolicy": "stable-volume",
        "cadenceMode": "scheduled",
        "docs": "collectors",
    },
    {
        "id": "threat-intelligence",
        "title": "Endpoint threat-intelligence collector",
        "workflow": "catalog-builder.yml",
        "job": "Freeze JSON state and compile the Omega client DB",
        "step": "Collect daily endpoint threat intelligence",
        "purpose": "Fetch frozen URL/domain/IP threat indicators, resolve currently observed endpoint hosts, and retain deterministic match provenance for SRL reprojection.",
        "inputs": ["current Evidence-v2 endpoint relationship index", "Feodo Tracker recommended active C2 feed", "optional ThreatFox recent IOC API"],
        "outputs": ["catalog/reputation-intelligence.json", "frozen Definitions reputation.json", "Evidence-v2 threat-intelligence index"],
        "implementation": "tools/catalog/collect_reputation_intelligence.py",
        "logParser": "threat-intelligence",
        "trendMetric": "Indicators",
        "trendPolicy": "stable-volume",
        "cadenceMode": "scheduled",
        "docs": "threat-intelligence",
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
        "trendMetric": "Packages queried",
        "trendPolicy": "stable-volume",
        "cadenceMode": "scheduled",
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
        "trendMetric": "Completed in batch",
        "trendPolicy": "workload-volume",
        "cadenceMode": "continuous",
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
        "cadenceMode": "continuous",
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
        "cadenceMode": "continuous",
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
        "cadenceMode": "event-driven",
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
    return re.sub(r"(?m)^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\s+", "", text or "")


def _log_metrics(kind: str, text: str) -> list[dict[str, Any]]:
    text = _strip_log_prefix(text)
    metrics: list[dict[str, Any]] = []

    def add(label: str, value: object, unit: str = "") -> None:
        metrics.append({"label": label, "value": value, "unit": unit, "source": "runner log"})

    if kind == "source-discovery":
        # Transitional compatibility: older runs logged collect_sources.py's aggregate
        # sentence, while the first-class Omega Discovery component logs the typed
        # snapshot counts as JSON.  Keep the stable metric label so historical trend
        # charts remain continuous across the workflow cutover.
        m = re.search(r"Wrote\s+\S*raw-sources\.json:\s+(\d+)\s+source\(s\).*?(\d+)\s+curated,\s+(\d+)\s+community,\s+(\d+)\s+puni\.sh,\s+(\d+)\s+github-search", text, re.I | re.S)
        if m:
            add("Deduplicated sources", int(m.group(1)))
            add("Curated", int(m.group(2)))
            add("Community", int(m.group(3)))
            add("Puni.sh", int(m.group(4)))
            add("GitHub discovery", int(m.group(5)))
        else:
            fields = (
                ("candidateSourceCount", "Deduplicated sources"),
                ("knownSourcesSkipped", "Known sources skipped"),
                ("validatedNovelSources", "Validated novel sources"),
                ("newPluginFacts", "New plugin facts"),
                ("newVariantFacts", "New variant facts"),
                ("projectLinksObserved", "Project links observed"),
                ("repositoryCandidates", "Repository candidates"),
                ("repositoryTreesInspected", "Repository trees inspected"),
                ("webSearchResults", "Web-search results"),
            )
            for field, label in fields:
                matches = re.findall(rf'"{re.escape(field)}"\s*:\s*(\d+)', text, re.I)
                if matches:
                    add(label, int(matches[-1]))
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
            cached, scraped = int(m.group(1)), int(m.group(2))
            add("Websites considered", cached + scraped)
            add("Cached websites reused", cached)
            add("Network scrapes", scraped)
    elif kind == "source-revision-observer":
        matches = re.findall(r'"repositories"\s*:\s*(\d+).*?"observed"\s*:\s*(\d+).*?"failed"\s*:\s*(\d+)', text, re.I | re.S)
        if matches:
            repositories, observed, failed = matches[-1]
            add("Repositories", int(repositories))
            add("Observed", int(observed))
            add("Failed", int(failed))
    elif kind == "threat-intelligence":
        matches = re.findall(r'"indicators"\s*:\s*(\d+).*?"matchedEndpointHosts"\s*:\s*(\d+)', text, re.I | re.S)
        if matches:
            indicators, matched_hosts = matches[-1]
            add("Indicators", int(indicators))
            add("Matched endpoint hosts", int(matched_hosts))
        feeds = re.findall(r'"activeFeeds"\s*:\s*(\d+)', text, re.I)
        if feeds:
            add("Active feeds", int(feeds[-1]))
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


def _parse_time(value: object) -> dt.datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def _duration_seconds(started: object, completed: object) -> float | None:
    start, end = _parse_time(started), _parse_time(completed)
    if not start or not end or end < start:
        return None
    return round((end - start).total_seconds(), 3)


def _numeric_metric(row: Mapping[str, Any], label: str) -> float | None:
    for metric in row.get("metrics") or []:
        if not isinstance(metric, Mapping) or str(metric.get("label") or "") != label:
            continue
        value = metric.get("value")
        if isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            return float(value)
    return None


def _median(values: list[float]) -> float | None:
    clean = [float(value) for value in values if value is not None]
    return float(statistics.median(clean)) if clean else None


def _percent_delta(latest: float | None, baseline: float | None) -> float | None:
    if latest is None or baseline is None or baseline == 0:
        return None
    return round((latest - baseline) * 100.0 / baseline, 1)


def _trend_projection(definition: Mapping[str, Any], history: list[dict[str, Any]], *, now_utc: dt.datetime) -> dict[str, Any]:
    observed = [row for row in history if row.get("state") not in {"unknown", "skipped"}]
    completed = [row for row in observed if row.get("state") not in {"running"}]
    successes = [row for row in completed if row.get("state") == "healthy"]
    failures = [row for row in completed if row.get("state") == "failed"]
    success_rate = round(len(successes) * 100.0 / len(completed), 1) if completed else None
    signals: list[dict[str, Any]] = []

    def signal(level: str, code: str, title: str, detail: str) -> None:
        signals.append({"level": level, "code": code, "title": title, "detail": detail})

    if completed and completed[0].get("state") == "failed":
        signal("degraded", "latest-failed", "Latest collector execution failed", "The collector-specific step/job failed in the newest completed run.")
    elif len(completed) >= 4 and success_rate is not None and success_rate < 75:
        signal("degraded", "low-success-rate", "Recent success rate is low", f"Only {success_rate:.1f}% of the last {len(completed)} observed executions succeeded.")
    elif len(completed) >= 4 and success_rate is not None and success_rate < 90:
        signal("warning", "success-rate-drift", "Recent failures are accumulating", f"Recent success rate is {success_rate:.1f}% across {len(completed)} observed executions.")

    durations = [float(row["durationSeconds"]) for row in successes if isinstance(row.get("durationSeconds"), (int, float))]
    latest_duration = next((float(row["durationSeconds"]) for row in completed if isinstance(row.get("durationSeconds"), (int, float))), None)
    baseline_duration_values = [float(row["durationSeconds"]) for row in successes[1:6] if isinstance(row.get("durationSeconds"), (int, float))]
    if not baseline_duration_values and len(durations) > 1:
        baseline_duration_values = durations[1:]
    baseline_duration = _median(baseline_duration_values)
    duration_delta = _percent_delta(latest_duration, baseline_duration)
    if latest_duration is not None and baseline_duration is not None and baseline_duration >= 1:
        if latest_duration >= baseline_duration * 2.5 and latest_duration - baseline_duration >= 30:
            signal("degraded", "duration-regression", "Collector duration regressed sharply", f"Latest duration is {latest_duration:.0f}s versus a {baseline_duration:.0f}s recent baseline.")
        elif latest_duration >= baseline_duration * 1.75 and latest_duration - baseline_duration >= 20:
            signal("warning", "duration-drift", "Collector is running slower", f"Latest duration is {latest_duration:.0f}s versus a {baseline_duration:.0f}s recent baseline.")

    trend_metric = str(definition.get("trendMetric") or "")
    trend_points: list[dict[str, Any]] = []
    throughput_latest: float | None = None
    throughput_baseline: float | None = None
    throughput_delta: float | None = None
    if trend_metric:
        for row in reversed(history):
            value = _numeric_metric(row, trend_metric)
            if value is None:
                continue
            trend_points.append({"runNumber": row.get("runNumber", 0), "createdAtUtc": row.get("createdAtUtc", ""), "value": value})
        current_row = history[0] if history else {}
        throughput_latest = _numeric_metric(current_row, trend_metric)
        previous = [_numeric_metric(row, trend_metric) for row in history[1:6]]
        throughput_baseline = _median([value for value in previous if value is not None])
        throughput_delta = _percent_delta(throughput_latest, throughput_baseline)
        policy = str(definition.get("trendPolicy") or "")
        if policy == "stable-volume" and throughput_latest is not None and throughput_baseline is not None and throughput_baseline > 0:
            ratio = throughput_latest / throughput_baseline
            if throughput_latest == 0:
                signal("degraded", "zero-output", f"{trend_metric} unexpectedly fell to zero", f"Recent baseline is {throughput_baseline:.1f}; a successful zero-result collection may indicate an upstream or parsing failure.")
            elif ratio < 0.6:
                signal("degraded", "throughput-drop", f"{trend_metric} dropped sharply", f"Latest value {throughput_latest:.0f} is {abs(100 - ratio * 100):.1f}% below the recent baseline {throughput_baseline:.1f}.")
            elif ratio < 0.8:
                signal("warning", "throughput-drift", f"{trend_metric} is below its recent baseline", f"Latest value {throughput_latest:.0f}; recent baseline {throughput_baseline:.1f}.")
        elif policy == "workload-volume" and definition.get("id") == "sigmascope-batch":
            queue_selected = _numeric_metric(current_row, "Queue selected")
            completed_now = _numeric_metric(current_row, "Completed in batch")
            failed_now = _numeric_metric(current_row, "Failed in batch")
            if queue_selected and queue_selected > 0 and (completed_now or 0) == 0:
                level = "degraded" if (failed_now or 0) > 0 else "warning"
                signal(level, "selected-no-completions", "Selected SigmaScope work produced no completed analyses", f"Queue selected {queue_selected:.0f} item(s), but the batch reported zero completions.")

    # Collector-specific quality ratios are used only when the runner emitted both sides
    # of the ratio. Absence of a metric is unknown, never inferred as failure.
    current_row = history[0] if history else {}
    if definition.get("id") == "manifest-normalization":
        ok = _numeric_metric(current_row, "Sources OK")
        attempted = _numeric_metric(current_row, "Sources attempted")
        if attempted and attempted > 0 and ok is not None:
            ratio = ok / attempted
            if ratio < 0.90:
                signal("degraded", "source-drop-rate", "Manifest source success rate dropped", f"Only {ok:.0f}/{attempted:.0f} source feeds normalized successfully ({ratio*100:.1f}%).")
            elif ratio < 0.98:
                signal("warning", "source-drop-rate", "Some manifest sources failed", f"{ok:.0f}/{attempted:.0f} source feeds normalized successfully ({ratio*100:.1f}%).")
    elif definition.get("id") == "source-revision-observer":
        total = _numeric_metric(current_row, "Repositories")
        observed_now = _numeric_metric(current_row, "Observed")
        failed_now = _numeric_metric(current_row, "Failed")
        if total and total > 0 and failed_now is not None and failed_now > 0:
            ratio = failed_now / total
            level = "degraded" if ratio >= 0.10 else "warning"
            signal(level, "observation-failure-rate", "Some source revisions could not be observed", f"{failed_now:.0f}/{total:.0f} repositories failed observation; {observed_now or 0:.0f} were observed.")
    elif definition.get("id") == "sigmascope-batch":
        selected_now = _numeric_metric(current_row, "Scan selected")
        completed_now = _numeric_metric(current_row, "Completed in batch")
        if selected_now and selected_now > 0 and completed_now is not None:
            ratio = completed_now / selected_now
            if ratio < 0.50:
                signal("degraded", "batch-completion-rate", "SigmaScope batch completion rate is low", f"{completed_now:.0f}/{selected_now:.0f} selected analyses completed ({ratio*100:.1f}%).")
            elif ratio < 0.90:
                signal("warning", "batch-completion-rate", "Some selected SigmaScope analyses did not complete", f"{completed_now:.0f}/{selected_now:.0f} selected analyses completed ({ratio*100:.1f}%).")

    run_times = [_parse_time(row.get("createdAtUtc")) for row in observed]
    run_times = [value for value in run_times if value is not None]
    intervals: list[float] = []
    for newer, older in zip(run_times, run_times[1:]):
        if newer >= older:
            intervals.append((newer - older).total_seconds() / 3600.0)
    expected_interval = _median(intervals[:6])
    latest_time = run_times[0] if run_times else None
    age_hours = round((now_utc - latest_time).total_seconds() / 3600.0, 2) if latest_time and now_utc >= latest_time else None
    freshness_state = "unknown"
    cadence_mode = str(definition.get("cadenceMode") or "")
    stale_after = None
    if cadence_mode == "event-driven":
        freshness_state = "event-driven"
    elif age_hours is not None and expected_interval is not None and expected_interval > 0:
        floor = 36.0 if cadence_mode == "scheduled" else 2.0
        stale_after = max(expected_interval * 2.5, floor)
        if age_hours > stale_after * 1.5:
            freshness_state = "stale"
            signal("degraded", "stale", "Collector appears stale", f"Latest observed execution is {age_hours:.1f}h old; recent cadence suggests about every {expected_interval:.1f}h.")
        elif age_hours > stale_after:
            freshness_state = "late"
            signal("warning", "late", "Collector is later than its recent cadence", f"Latest observed execution is {age_hours:.1f}h old; recent cadence suggests about every {expected_interval:.1f}h.")
        else:
            freshness_state = "fresh"
    elif latest_time:
        freshness_state = "observed"

    severity_order = {"degraded": 3, "warning": 2, "healthy": 1, "unknown": 0}
    trend_state = "healthy" if observed else "unknown"
    for item in signals:
        if severity_order.get(str(item.get("level")), 0) > severity_order.get(trend_state, 0):
            trend_state = str(item.get("level"))

    duration_points = [
        {"runNumber": row.get("runNumber", 0), "createdAtUtc": row.get("createdAtUtc", ""), "value": float(row["durationSeconds"])}
        for row in reversed(history)
        if isinstance(row.get("durationSeconds"), (int, float))
    ]
    return {
        "state": trend_state,
        "signals": signals,
        "outcomes": {
            "observedRuns": len(observed),
            "completedRuns": len(completed),
            "successes": len(successes),
            "failures": len(failures),
            "successRate": success_rate,
        },
        "duration": {
            "latestSeconds": latest_duration,
            "baselineMedianSeconds": round(baseline_duration, 3) if baseline_duration is not None else None,
            "deltaPercent": duration_delta,
            "points": duration_points,
        },
        "throughput": {
            "label": trend_metric,
            "latest": throughput_latest,
            "baselineMedian": round(throughput_baseline, 3) if throughput_baseline is not None else None,
            "deltaPercent": throughput_delta,
            "points": trend_points,
            "policy": str(definition.get("trendPolicy") or "none"),
        },
        "freshness": {
            "state": freshness_state,
            "cadenceMode": cadence_mode,
            "lastObservedUtc": latest_time.isoformat().replace("+00:00", "Z") if latest_time else "",
            "ageHours": age_hours,
            "expectedIntervalHours": round(expected_interval, 2) if expected_interval is not None else None,
            "staleAfterHours": round(stale_after, 2) if stale_after is not None else None,
        },
    }


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
        started = str(state_source.get("startedAtUtc") or (job or {}).get("startedAtUtc") or run.get("createdAtUtc") or "")
        completed = str(state_source.get("completedAtUtc") or (job or {}).get("completedAtUtc") or run.get("updatedAtUtc") or "")
        rows.append({
            "runId": int(run.get("runId") or 0),
            "runNumber": int(run.get("runNumber") or 0),
            "createdAtUtc": str(run.get("createdAtUtc") or ""),
            "updatedAtUtc": str(run.get("updatedAtUtc") or ""),
            "startedAtUtc": started,
            "completedAtUtc": completed,
            "durationSeconds": _duration_seconds(started, completed),
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
    *,
    now_utc: dt.datetime | None = None,
) -> dict[str, Any]:
    now_utc = (now_utc or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    collectors: list[dict[str, Any]] = []
    for definition in COLLECTORS:
        workflow = str(definition["workflow"])
        payload = workflow_histories.get(workflow) or {}
        active_definition: Mapping[str, Any] = definition
        if not payload:
            for legacy in definition.get("legacyContracts") or []:
                if not isinstance(legacy, Mapping):
                    continue
                legacy_payload = workflow_histories.get(str(legacy.get("workflow") or "")) or {}
                if legacy_payload:
                    active_definition = {**definition, **dict(legacy)}
                    payload = legacy_payload
                    break
        history = _history_for_collector(active_definition, payload)
        latest = history[0] if history else None
        observed = [row for row in history if row.get("state") not in {"unknown", "skipped"}]
        success = sum(1 for row in observed if row.get("state") == "healthy")
        failed = sum(1 for row in observed if row.get("state") == "failed")
        metrics = list((latest or {}).get("metrics") or []) + _evidence_metrics(str(definition["id"]), summary, context)
        dedup: dict[str, dict[str, Any]] = {}
        for metric in metrics:
            label = str(metric.get("label") or "")
            if label and label not in dedup:
                dedup[label] = metric
        trend = _trend_projection(active_definition, history, now_utc=now_utc)
        collectors.append({
            **{key: definition[key] for key in ("id", "title", "workflow", "job", "step", "purpose", "inputs", "outputs", "implementation", "docs")},
            **{key: definition[key] for key in ("componentId", "contract", "provides") if key in definition},
            "available": bool(payload.get("available", False)),
            "state": str((latest or {}).get("state") or ("unavailable" if payload.get("error") else "unknown")),
            "trendState": trend["state"],
            "trend": trend,
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
        "trendAuthority": "github-actions-runner-history-diagnostic-only",
        "collectors": collectors,
        "collectorCount": len(collectors),
        "failingCount": sum(1 for row in collectors if row["state"] == "failed"),
        "runningCount": sum(1 for row in collectors if row["state"] == "running"),
        "unknownCount": sum(1 for row in collectors if row["state"] in {"unknown", "unavailable"}),
        "degradingCount": sum(1 for row in collectors if row["trendState"] == "degraded"),
        "warningTrendCount": sum(1 for row in collectors if row["trendState"] == "warning"),
        "staleCount": sum(1 for row in collectors if str((row.get("trend") or {}).get("freshness", {}).get("state")) in {"late", "stale"}),
    }
