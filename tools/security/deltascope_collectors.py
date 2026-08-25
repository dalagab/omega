#!/usr/bin/env python3
"""Read-only collector health and trend projection for DeltaScope Operations.

Collectors are mapped to stable GitHub Actions workflow/job/step names. Recent runner
history is diagnostic input only; published Evidence-v2 remains the security authority.
The trend model measures operational quality (outcomes, duration, freshness and parsed
throughput) without turning runner history into policy or security evidence.
"""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
import re
import statistics
from typing import Any, Mapping

SCHEMA = "omega.deltascope.collectors.v2"

FALLBACK_TOPOLOGY_PATH = Path(__file__).resolve().parents[2] / "deltascope" / "execution-topology-fallback.json"


def _fallback_topology() -> dict[str, Any]:
    try:
        payload = json.loads(FALLBACK_TOPOLOGY_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"schema": "omega.execution-topology.v1", "revision": "", "nodes": [], "error": str(exc)}
    return payload if isinstance(payload, dict) else {"schema": "omega.execution-topology.v1", "revision": "", "nodes": []}


def execution_nodes(execution_topology: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
    topology = execution_topology if isinstance(execution_topology, Mapping) else _fallback_topology()
    if str(topology.get("schema") or "") != "omega.execution-topology.v1":
        topology = _fallback_topology()
    rows = [dict(row) for row in (topology.get("nodes") or []) if isinstance(row, Mapping)]
    rows.sort(key=lambda row: str(row.get("id") or "").casefold())
    return rows


def workflow_contracts(execution_topology: Mapping[str, Any] | None = None) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for row in execution_nodes(execution_topology):
        workflow = str(row.get("workflow") or "")
        if not workflow:
            continue
        result.setdefault(workflow, set())
        job = str(row.get("job") or "")
        if job:
            result[workflow].add(job)
    return result


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
    platform_registry: Mapping[str, Any] | None = None,
    execution_topology: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    now_utc = (now_utc or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    collectors: list[dict[str, Any]] = []
    definitions = execution_nodes(execution_topology)
    for definition in definitions:
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
        metrics = list((latest or {}).get("metrics") or []) + _evidence_metrics(str(definition.get("id") or ""), summary, context)
        dedup: dict[str, dict[str, Any]] = {}
        for metric in metrics:
            label = str(metric.get("label") or "")
            if label and label not in dedup:
                dedup[label] = metric
        trend = _trend_projection(active_definition, history, now_utc=now_utc)
        collectors.append({
            **{key: definition.get(key, [] if key in {"inputs", "outputs"} else "") for key in ("id", "title", "workflow", "job", "step", "purpose", "inputs", "outputs", "implementation", "docs")},
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
    registered_providers: list[dict[str, Any]] = []
    if isinstance(platform_registry, Mapping) and str(platform_registry.get("schema") or "") == "omega.collector-registry.v1":
        components = platform_registry.get("components") if isinstance(platform_registry.get("components"), Mapping) else {}
        for provider in platform_registry.get("collectors") or []:
            if not isinstance(provider, Mapping):
                continue
            component_id = str(provider.get("componentId") or "")
            component = components.get(component_id) if isinstance(components.get(component_id), Mapping) else {}
            registered_providers.append({
                "id": str(provider.get("id") or ""),
                "title": str(provider.get("title") or provider.get("id") or ""),
                "componentId": component_id,
                "component": str(component.get("name") or component_id),
                "status": str(provider.get("status") or "active"),
                "cadence": str(provider.get("cadence") or ""),
                "authority": str(provider.get("authority") or ""),
                "network": bool(provider.get("network")),
                "provides": [str(value) for value in (provider.get("provides") or [])],
            })
        registered_providers.sort(key=lambda row: (row["component"].casefold(), row["title"].casefold(), row["id"]))

    return {
        "schema": SCHEMA,
        "readOnly": True,
        "mutationAuthority": "none",
        "policyInput": False,
        "trendAuthority": "github-actions-runner-history-diagnostic-only",
        "collectors": collectors,
        "collectorCount": len(collectors),
        "executionTopologyRevision": str((execution_topology or {}).get("revision") or _fallback_topology().get("revision") or ""),
        "executionTopologyAuthority": "published" if isinstance(execution_topology, Mapping) else "bundled-fallback",
        "collectorRegistryRevision": str(platform_registry.get("revision") or "") if isinstance(platform_registry, Mapping) else "",
        "registeredProviders": registered_providers,
        "registeredProviderCount": len(registered_providers),
        "failingCount": sum(1 for row in collectors if row["state"] == "failed"),
        "runningCount": sum(1 for row in collectors if row["state"] == "running"),
        "unknownCount": sum(1 for row in collectors if row["state"] in {"unknown", "unavailable"}),
        "degradingCount": sum(1 for row in collectors if row["trendState"] == "degraded"),
        "warningTrendCount": sum(1 for row in collectors if row["trendState"] == "warning"),
        "staleCount": sum(1 for row in collectors if str((row.get("trend") or {}).get("freshness", {}).get("state")) in {"late", "stale"}),
    }
