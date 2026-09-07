"""Read-only DeltaScope projection explaining SigmaScope queue causality.

DeltaScope mirrors the published SigmaScope ordering contracts without importing or
mutating production queue code.  Both the legacy ``coverage-first-v1`` policy and the
current ``plugin-coverage-first-v2`` policy remain readable.  This module has no
scheduling, scan, policy, queue-mutation or publication authority.
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Iterable, Mapping

SCHEMA = "omega.deltascope.scan-queue-causality.v1"
LEGACY_SELECTION_POLICY = "coverage-first-v1"
PLUGIN_SELECTION_POLICY = "plugin-coverage-first-v2"
# Compatibility alias retained for callers/tests that referenced the original constant.
SELECTION_POLICY = LEGACY_SELECTION_POLICY
SUPPORTED_SELECTION_POLICIES = {LEGACY_SELECTION_POLICY, PLUGIN_SELECTION_POLICY}
SOURCE_PRIORITY_RANK = {
    "official": 0,
    "curated": 1,
    "discovered": 2,
}
MAX_NEXT_ITEMS = 40
MAX_RECENT_ITEMS = 24

REASON_EXPLANATIONS: dict[str, tuple[str, str]] = {
    "manual": ("Manual recheck", "An operator/developer explicitly requested a fresh artifact check."),
    "baseline_scan": ("Identity baseline", "The catalog identity epoch changed, so the prior variant identity map cannot be reused as current coverage."),
    "new_variant": ("New active variant", "This active catalog variant has no published current artifact scan under its present variant identity. Under plugin-coverage-first-v2 it is a first-plugin-coverage candidate only while its stable plugin identity remains uncovered."),
    "artifact_url_changed": ("Artifact URL changed", "The selected install artifact URL changed and artifact-backed observations must be refreshed."),
    "artifact_version_changed": ("Plugin version changed", "The selected artifact version changed and needs a new current artifact scan."),
    "artifact_analysis_changed": ("Artifact analysis changed", "SigmaScope's artifact-analysis revision changed; existing covered variants are queued for selective refresh."),
    "analysis_observation_requested": (
        "Broker-requested typed analysis",
        "The analysis broker requested a specific typed observation/evidence acquisition through the canonical SigmaScope queue. This is distinct from an ordinary artifact scan, source follow-up, and Stigma-1 deep-evidence acquisition.",
    ),
    "srl_observation_missing": ("Required observation missing", "An active Stigma-1 rule requires an observation collection not present at the required producer revision."),
    "advisory_changed": ("Advisories changed", "The frozen advisory revision changed; dependency/advisory projection needs deterministic refresh."),
    "source_followup": ("Source follow-up", "Artifact analysis completed and source attribution/source analysis can now be attempted."),
    "source_candidates_changed": ("Source candidates changed", "Catalog source candidates differ from the source context retained by the current scan."),
    "source_candidate_observed": ("Source became observable", "A previously unresolved source candidate now has a usable source observation."),
    "source_observation_changed": ("Observed source changed", "A tracked mutable default-branch source observation moved to a different commit."),
    "source_analysis_changed": ("Source analysis changed", "The source-analysis producer revision changed and attributable source work needs refresh."),
    "source_unresolved": ("Source unresolved", "Source attribution is still unresolved and remains eligible for bounded follow-up."),
    "failed_retry": ("Retry incomplete work", "A prior artifact attempt did not complete and is eligible under bounded retry/backoff."),
}


ARTIFACT_SCAN_REASONS = {
    "manual", "baseline_scan", "new_variant", "artifact_url_changed",
    "artifact_version_changed", "artifact_analysis_changed",
}
SOURCE_FOLLOWUP_REASONS = {
    "source_followup", "source_candidates_changed", "source_candidate_observed",
    "source_observation_changed", "source_analysis_changed", "source_unresolved",
}


def _integer(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _operational_action(primary: str, work_type: str) -> tuple[str, bool | None, str]:
    """Explain the operational work without turning a queue reason into a verdict."""
    if primary == "analysis_observation_requested":
        return (
            "Broker-requested typed analysis", None,
            "The analysis broker requested a typed observation/evidence acquisition. The requested producer owns the acquisition boundary; this queue reason is not automatically an artifact rescan, source follow-up, or Stigma-1 deep-scan request.",
        )
    if primary == "srl_observation_missing":
        return (
            "Targeted / deep evidence acquisition", True if work_type == "artifact" else None,
            "A Stigma-1 rule replay cannot be satisfied from retained observations at the required producer revision, so additional bounded evidence acquisition is justified. The producer/work type determines whether that means reopening the plugin artifact.",
        )
    if primary == "advisory_changed":
        return (
            "Re-evaluate retained dependency evidence", False,
            "Frozen advisory intelligence changed. Existing dependency evidence can normally be reprojected without reopening the plugin artifact.",
        )
    if primary in SOURCE_FOLLOWUP_REASONS or work_type == "source":
        return (
            "Source attribution / source follow-up", False,
            "This work advances the separately retained source-evidence stream; it does not imply the shipped plugin artifact needs another scan.",
        )
    if primary == "failed_retry":
        artifact = work_type == "artifact"
        return (
            "Retry artifact scan" if artifact else "Retry incomplete queue work", artifact,
            "A prior attempt did not complete. The retry preserves the original work boundary rather than creating a new security conclusion.",
        )
    if primary in ARTIFACT_SCAN_REASONS or work_type == "artifact":
        return (
            "Artifact scan / re-analysis", True,
            "The queued work needs SigmaScope to inspect the installable artifact under the current artifact-analysis contract.",
        )
    return (
        "Queued security work", None,
        "The published queue contains this work item, but DeltaScope does not classify it as an artifact scan, source follow-up, broker-requested typed analysis, or Stigma-1 deep-evidence request.",
    )


def _state(item: Mapping[str, Any]) -> str:
    return str(item.get("state") or "pending").strip().lower()


def _is_pending(item: Mapping[str, Any]) -> bool:
    return _state(item) != "complete"


def _artifact_is_uncovered(item: Mapping[str, Any]) -> bool:
    return (
        str(item.get("workType") or "") == "artifact"
        and _integer(item.get("currentScanId")) <= 0
        and not str(item.get("currentScannedAtUtc") or "").strip()
    )


def _covered_plugin_ids(items: Iterable[Mapping[str, Any]]) -> set[int]:
    """Mirror SigmaScope plugin_coverage_policy.covered_plugin_ids."""
    covered: set[int] = set()
    for item in items:
        if not isinstance(item, Mapping):
            continue
        plugin_id = _integer(item.get("pluginId"))
        if plugin_id <= 0:
            continue
        if bool(item.get("pluginHasCurrentScan")):
            covered.add(plugin_id)
            continue
        if _integer(item.get("currentScanId")) > 0 or str(item.get("currentScannedAtUtc") or "").strip():
            covered.add(plugin_id)
            continue
        if str(item.get("workType") or "") == "artifact" and _state(item) == "complete":
            covered.add(plugin_id)
    return covered


def _legacy_lane(item: Mapping[str, Any]) -> int:
    """Mirror legacy SigmaScope coverage-first-v1 lane semantics."""
    if not _artifact_is_uncovered(item):
        return 2
    return 0 if _integer(item.get("attemptCount")) <= 0 else 1


def _plugin_lane(item: Mapping[str, Any], covered_plugins: set[int] | None = None) -> int:
    """Mirror current SigmaScope plugin-coverage-first-v2 lane semantics."""
    if not _artifact_is_uncovered(item):
        return 2
    plugin_id = _integer(item.get("pluginId"))
    if plugin_id > 0 and plugin_id in (covered_plugins or set()):
        return 2
    if plugin_id > 0 and bool(item.get("pluginHasCurrentScan")):
        return 2
    return 0 if _integer(item.get("attemptCount")) <= 0 else 1


def _legacy_sort_key(item: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        _legacy_lane(item),
        -_integer(item.get("priority")),
        str(item.get("currentScannedAtUtc") or ""),
        str(item.get("internalName") or "").casefold(),
        str(item.get("sourceName") or "").casefold(),
        _integer(item.get("variantId")),
        str(item.get("workType") or ""),
    )


def _plugin_sort_key(item: Mapping[str, Any], covered_plugins: set[int] | None = None) -> tuple[Any, ...]:
    """Mirror SigmaScope plugin_coverage_policy.selection_sort_key."""
    lane = _plugin_lane(item, covered_plugins)
    source_class = str(item.get("sourcePriorityClass") or "discovered")
    source_rank = SOURCE_PRIORITY_RANK.get(source_class, SOURCE_PRIORITY_RANK["discovered"])
    channel = str(item.get("artifactChannel") or "").casefold()
    channel_rank = 0 if channel == "stable" else 1 if channel == "testing" else 2
    return (
        lane,
        source_rank if lane in (0, 1) else 3,
        channel_rank if lane in (0, 1) else 2,
        -_integer(item.get("operatorNudgeScore")),
        -_integer(item.get("priority")),
        str(item.get("currentScannedAtUtc") or ""),
        str(item.get("internalName") or "").casefold(),
        str(item.get("sourceName") or "").casefold(),
        _integer(item.get("variantId")),
        str(item.get("workType") or ""),
    )


def _ordered_with_lanes(
    items: list[Mapping[str, Any]],
    pending: list[Mapping[str, Any]],
    selection_policy: str,
) -> list[tuple[Mapping[str, Any], int]]:
    """Return the read-only projected policy order and the lane at each selection.

    V2 deliberately performs the same shadow step used by SigmaScope's parallel planner:
    after projecting one selected queue key it marks only that local copy complete, then
    recalculates plugin coverage before choosing the next key.  No caller-owned queue
    object is mutated.
    """
    if selection_policy == LEGACY_SELECTION_POLICY:
        return [(item, _legacy_lane(item)) for item in sorted(pending, key=_legacy_sort_key)]
    if selection_policy != PLUGIN_SELECTION_POLICY:
        return [(item, -1) for item in pending]

    shadow = [dict(item) for item in items]
    remaining_indices = {index for index, item in enumerate(shadow) if _is_pending(item)}
    ordered: list[tuple[Mapping[str, Any], int]] = []
    while remaining_indices:
        covered_plugins = _covered_plugin_ids(shadow)
        selected_index = min(
            remaining_indices,
            key=lambda index: _plugin_sort_key(shadow[index], covered_plugins),
        )
        selected = shadow[selected_index]
        lane = _plugin_lane(selected, covered_plugins)
        ordered.append((dict(selected), lane))
        shadow[selected_index]["state"] = "complete"
        remaining_indices.remove(selected_index)
    return ordered


def _coverage_metrics(
    items: list[Mapping[str, Any]],
    pending: list[Mapping[str, Any]],
    selection_policy: str,
) -> dict[str, int]:
    """Project current coverage metrics; published summary values may override these."""
    uncovered_variant_ids: set[int] = set()
    uncovered_retry_variant_ids: set[int] = set()
    uncovered_plugin_ids: set[int] = set()
    uncovered_retry_plugin_ids: set[int] = set()
    covered_work_pending = 0
    covered_plugins = _covered_plugin_ids(items)

    for item in pending:
        variant_id = _integer(item.get("variantId"))
        plugin_id = _integer(item.get("pluginId"))
        if _artifact_is_uncovered(item) and variant_id > 0:
            uncovered_variant_ids.add(variant_id)
            if _integer(item.get("attemptCount")) > 0:
                uncovered_retry_variant_ids.add(variant_id)

        if selection_policy == PLUGIN_SELECTION_POLICY:
            lane = _plugin_lane(item, covered_plugins)
        else:
            lane = _legacy_lane(item)
        if lane in (0, 1) and plugin_id > 0:
            uncovered_plugin_ids.add(plugin_id)
            if lane == 1:
                uncovered_retry_plugin_ids.add(plugin_id)
        elif lane == 2:
            covered_work_pending += 1

    return {
        "unscannedVariantsPending": len(uncovered_variant_ids),
        "unscannedRetryVariants": len(uncovered_retry_variant_ids),
        "unscannedPluginsPending": len(uncovered_plugin_ids),
        "unscannedRetryPlugins": len(uncovered_retry_plugin_ids),
        "coveredWorkPending": covered_work_pending,
    }


def _published_metric(summary: Mapping[str, Any], key: str, fallback: int) -> int:
    if key not in summary:
        return fallback
    return _integer(summary.get(key))


def _item_projection(
    item: Mapping[str, Any],
    *,
    exact_order: bool,
    selection_policy: str = "",
    lane_override: int | None = None,
) -> dict[str, Any]:
    if lane_override is not None:
        lane = lane_override
    elif not exact_order:
        lane = -1
    elif selection_policy == PLUGIN_SELECTION_POLICY:
        lane = _plugin_lane(item, set())
    else:
        lane = _legacy_lane(item)
    reasons = [str(value) for value in (item.get("reasons") or []) if str(value)]
    primary = str(item.get("primaryReason") or (reasons[0] if reasons else ""))
    work_type = str(item.get("workType") or "")
    action, requires_artifact_scan, action_explanation = _operational_action(primary, work_type)
    reason_details = []
    for reason in reasons or ([primary] if primary else []):
        label, explanation = REASON_EXPLANATIONS.get(
            reason,
            (reason.replace("_", " ").title(), "Published SigmaScope queue reason."),
        )
        reason_details.append({"reason": reason, "label": label, "explanation": explanation})

    plugin_first = selection_policy == PLUGIN_SELECTION_POLICY
    lane_labels = (
        {
            0: ("first-coverage", "First plugin coverage"),
            1: ("first-coverage-retry", "First-plugin coverage retry"),
            2: ("covered-refresh", "Secondary variant / covered refresh / follow-up"),
        }
        if plugin_first else
        {
            0: ("first-coverage", "First variant coverage"),
            1: ("first-coverage-retry", "First-variant coverage retry"),
            2: ("covered-refresh", "Covered refresh / follow-up"),
        }
    )
    lane_id, lane_label = lane_labels.get(lane, ("unknown", "Published order only"))
    return {
        "queueKey": str(item.get("queueKey") or ""),
        "variantId": _integer(item.get("variantId")),
        "pluginId": _integer(item.get("pluginId")),
        "internalName": str(item.get("internalName") or item.get("name") or ""),
        "name": str(item.get("name") or item.get("internalName") or ""),
        "sourceName": str(item.get("sourceName") or ""),
        "sourcePriorityClass": str(item.get("sourcePriorityClass") or ""),
        "assemblyVersion": str(item.get("assemblyVersion") or ""),
        "artifactChannel": str(item.get("artifactChannel") or ""),
        "pluginHasCurrentScan": bool(item.get("pluginHasCurrentScan")),
        "operatorNudgeScore": _integer(item.get("operatorNudgeScore")),
        "workType": work_type,
        "state": _state(item),
        "priority": _integer(item.get("priority")),
        "attemptCount": _integer(item.get("attemptCount")),
        "nextEligibleAtUtc": str(item.get("nextEligibleAtUtc") or ""),
        "currentScanId": _integer(item.get("currentScanId")),
        "currentScannedAtUtc": str(item.get("currentScannedAtUtc") or ""),
        "primaryReason": primary,
        "reasons": reasons,
        "reasonDetails": reason_details,
        "operationalAction": action,
        "operationalExplanation": action_explanation,
        "requiresArtifactScan": requires_artifact_scan,
        "lane": lane,
        "laneId": lane_id,
        "laneLabel": lane_label,
    }


def project_scan_queue(
    queue_state: Mapping[str, Any] | None,
    *,
    current_variants: int = 0,
    next_limit: int | None = None,
    published_summary: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    queue = queue_state if isinstance(queue_state, Mapping) else {}
    published_summary = published_summary if isinstance(published_summary, Mapping) else {}
    raw_items = queue.get("items") if isinstance(queue.get("items"), Mapping) else {}
    items = [value for value in raw_items.values() if isinstance(value, Mapping)]
    pending = [item for item in items if _is_pending(item)]
    selection_policy = str(queue.get("selectionPolicy") or published_summary.get("selectionPolicy") or "")
    exact_order = selection_policy in SUPPORTED_SELECTION_POLICIES
    ordered_with_lanes = _ordered_with_lanes(items, pending, selection_policy) if exact_order else [(item, -1) for item in pending]

    lane_counts = Counter(lane for _item, lane in ordered_with_lanes) if exact_order else Counter()
    states = Counter(_state(item) for item in items)
    reasons: Counter[str] = Counter()
    for item in pending:
        reason = str(item.get("primaryReason") or "")
        if not reason:
            vals = [str(v) for v in (item.get("reasons") or []) if str(v)]
            reason = vals[0] if vals else "unknown"
        reasons[reason] += 1

    reason_rows = []
    for reason, count in sorted(reasons.items(), key=lambda row: (-row[1], row[0])):
        label, explanation = REASON_EXPLANATIONS.get(
            reason,
            (reason.replace("_", " ").title(), "Published SigmaScope queue reason."),
        )
        reason_rows.append({"reason": reason, "label": label, "count": count, "explanation": explanation})

    baseline = bool(queue.get("baselineSecurityRebuild"))
    first_coverage = int(lane_counts.get(0, 0)) if exact_order else 0
    first_retry = int(lane_counts.get(1, 0)) if exact_order else 0
    covered = int(lane_counts.get(2, 0)) if exact_order else 0
    derived_metrics = _coverage_metrics(items, pending, selection_policy)
    metrics = {
        key: _published_metric(published_summary, key, value)
        for key, value in derived_metrics.items()
    }
    new_variant = int(reasons.get("new_variant", 0))
    analysis_refresh = int(reasons.get("artifact_analysis_changed", 0))
    plugin_first = selection_policy == PLUGIN_SELECTION_POLICY

    if baseline:
        headline = "Catalog identity baseline rebuild is active"
        explanation = (
            "The published queue says the catalog identity epoch changed. SigmaScope cannot treat the previous variant identity map as current coverage, "
            "so baseline artifact work is intentionally rebuilt. The published selection policy still controls deterministic ordering inside that baseline."
        )
        mode = "baseline-rebuild"
    elif plugin_first and exact_order and (first_coverage or first_retry):
        headline = "This is first-plugin-coverage work, not a scan reset"
        explanation = (
            f"SigmaScope currently has {metrics['unscannedPluginsPending']:,} uncovered plugin(s) represented in pending artifact work"
            + (f", including {metrics['unscannedRetryPlugins']:,} plugin(s) with retry candidates" if metrics["unscannedRetryPlugins"] else "")
            + ". plugin-coverage-first-v2 selects one representative artifact for an uncovered plugin before secondary variants and enrichment work. "
            "In first-coverage lanes it prefers official, then curated, then discovered sources; stable before testing; then operator nudge, normal priority, current scan time, and deterministic InternalName/source/variant tie-breaks."
        )
        mode = "first-plugin-coverage"
    elif selection_policy == LEGACY_SELECTION_POLICY and exact_order and (first_coverage or first_retry):
        headline = "This is first-variant-coverage work, not a scan reset"
        explanation = (
            f"This legacy snapshot has {first_coverage:,} untouched active variant(s) waiting for first artifact coverage"
            + (f" and {first_retry:,} uncovered retry variant(s)" if first_retry else "")
            + ". coverage-first-v1 processes uncovered variants before already-covered refresh/follow-up work and uses priority/current scan time/InternalName/source/variant deterministic ordering."
        )
        mode = "first-coverage"
    elif exact_order and covered:
        headline = "Current coverage exists; refresh/follow-up work remains"
        explanation = (
            "There is no identity baseline reset and no first-coverage lane ahead of the queue. Remaining work is secondary-variant, refresh, source, advisory, or typed analysis work according to the published compatible selection policy."
        )
        mode = "covered-refresh"
    else:
        headline = "Queue ordering is read from the published snapshot"
        explanation = (
            "DeltaScope does not recognize this queue selection policy as coverage-first-v1 or plugin-coverage-first-v2, so it will not claim the exact next-item order. Published reasons and states remain visible without mutating the queue."
        )
        mode = "unknown-policy"

    notes: list[str] = []
    if new_variant:
        notes.append(
            f"{new_variant:,} pending item(s) carry new_variant: those variants have no matching published current artifact scan. "
            + ("Only one representative remains first-plugin-coverage work at a time for each uncovered plugin." if plugin_first else "This legacy policy treats coverage at variant level.")
        )
    if analysis_refresh:
        notes.append(f"{analysis_refresh:,} pending item(s) carry artifact_analysis_changed: already-known artifacts need selective refresh under the published artifact-analysis revision.")
    if reasons.get("analysis_observation_requested"):
        notes.append(
            f"{int(reasons['analysis_observation_requested']):,} pending item(s) carry analysis_observation_requested: broker-requested typed evidence acquisition, distinct from ordinary artifact scanning, source follow-up, and Stigma-1 deep acquisition."
        )
    if not baseline:
        notes.append("baselineSecurityRebuild=false: the published queue does not describe a catalog identity reset.")

    projected_queue = [
        _item_projection(item, exact_order=exact_order, selection_policy=selection_policy, lane_override=lane)
        for item, lane in ordered_with_lanes
    ]
    for rank, row in enumerate(projected_queue, start=1):
        row["rank"] = rank if exact_order else 0
        row["isNext"] = bool(exact_order and rank == 1)
    if next_limit is None:
        preview_limit = min(MAX_NEXT_ITEMS, len(projected_queue))
    else:
        preview_limit = max(1, min(MAX_NEXT_ITEMS, int(next_limit or 1)))
    recent = [row for row in (queue.get("recentCompleted") or []) if isinstance(row, Mapping)][-MAX_RECENT_ITEMS:]
    recent.reverse()

    if plugin_first:
        lane_rows = [
            {
                "lane": 0, "id": "first-coverage", "label": "1 · First plugin coverage", "count": first_coverage,
                "description": "The next untouched representative artifact for a plugin with no current coverage. After one representative is selected in the shadow projection, sibling variants move to lane 3.",
            },
            {
                "lane": 1, "id": "first-coverage-retry", "label": "2 · First-plugin coverage retry", "count": first_retry,
                "description": "Retry/fallback artifact work selected only while that stable plugin identity is still uncovered.",
            },
            {
                "lane": 2, "id": "covered-refresh", "label": "3 · Secondary variant / refresh / follow-up", "count": covered,
                "description": "Secondary variants plus refresh, source, advisory and typed work once plugin-level first coverage is no longer ahead of them.",
            },
        ]
    else:
        lane_rows = [
            {"lane": 0, "id": "first-coverage", "label": "1 · First variant coverage", "count": first_coverage, "description": "Never-attempted artifact work with no published current scan. This legacy lane runs first."},
            {"lane": 1, "id": "first-coverage-retry", "label": "2 · First-variant coverage retry", "count": first_retry, "description": "Artifact work that was attempted but the variant is still uncovered. This legacy lane stays ahead of covered revisits."},
            {"lane": 2, "id": "covered-refresh", "label": "3 · Covered refresh / follow-up", "count": covered, "description": "Artifact re-analysis, source follow-up and advisory work for variants that already have current coverage."},
        ]

    return {
        "schema": SCHEMA,
        "readOnly": True,
        "mutationAuthority": "none",
        "policyInput": False,
        "queueMutationAuthorized": False,
        "scanExecutionAuthorized": False,
        "publicationAuthorized": False,
        "selectionPolicy": selection_policy,
        "supportedSelectionPolicies": sorted(SUPPORTED_SELECTION_POLICIES),
        "selectionOrderExact": exact_order,
        "baselineSecurityRebuild": baseline,
        "mode": mode,
        "headline": headline,
        "explanation": explanation,
        "notes": notes,
        "catalogIdentityEpoch": str(queue.get("catalogIdentityEpoch") or ""),
        "catalogRevision": str(queue.get("catalogRevision") or ""),
        "queueSeedRevision": str(queue.get("queueSeedRevision") or ""),
        "artifactAnalysisRevision": str(queue.get("artifactAnalysisRevision") or ""),
        "sourceAnalysisRevision": str(queue.get("sourceAnalysisRevision") or ""),
        "definitionsRevision": str(queue.get("definitionsRevision") or ""),
        "ruleSetRevision": str(queue.get("ruleSetRevision") or ""),
        "currentEvidenceVariants": int(current_variants or 0),
        "counts": {
            "total": len(items),
            "pending": len(pending),
            "complete": int(states.get("complete", 0)),
            "retry": int(states.get("retry", 0)),
            "firstCoverage": first_coverage,
            "firstCoverageRetry": first_retry,
            "coveredRefresh": covered,
            **metrics,
        },
        "coverageMetricsSource": "published-queue-summary" if any(key in published_summary for key in metrics) else "derived-read-only-projection",
        "lanes": lane_rows if exact_order else [],
        "reasons": reason_rows,
        "queueItems": projected_queue,
        "nextItems": projected_queue[:preview_limit],
        "rulesetScanBoundary": {
            "rulesetChangeRequiresArtifactScan": False,
            "explanation": "A Definitions/ruleset revision change is an interpretation/reprojection event, not an artifact-scan reason by itself. Broker-requested typed analysis (analysis_observation_requested) and Stigma-1 missing-observation acquisition (srl_observation_missing) remain separate queue reasons with separate provenance.",
        },
        "recentCompleted": [
            _item_projection(item, exact_order=False, selection_policy=selection_policy)
            for item in recent
        ],
    }


_INSTALLED = False
_QUEUE_UI_SCRIPT = r'''
<script id="deltascope-plugin-first-queue-ui">
(function(){
 const originalActionKind=window.queueActionKind;
 if(typeof originalActionKind==='function'){
  window.queueActionKind=function(item){
   if(String(item?.primaryReason||'')==='analysis_observation_requested')return'typed';
   return originalActionKind(item);
  };
 }
 const originalRender=window.renderScanQueue;
 if(typeof originalRender==='function'){
  window.renderScanQueue=function(queue){
   const pluginFirst=String(queue?.selectionPolicy||'')==='plugin-coverage-first-v2';
   const laneFirst=document.querySelector('#queueLaneFilter option[value="first-coverage"]');
   const laneRetry=document.querySelector('#queueLaneFilter option[value="first-coverage-retry"]');
   if(laneFirst)laneFirst.textContent=pluginFirst?'First plugin coverage':'First variant coverage';
   if(laneRetry)laneRetry.textContent=pluginFirst?'First-plugin coverage retry':'First-variant coverage retry';
   const actionFilter=document.getElementById('queueActionFilter');
   if(actionFilter&&!actionFilter.querySelector('option[value="typed"]')){
    const option=document.createElement('option');
    option.value='typed';
    option.textContent='Broker-requested typed analysis';
    actionFilter.appendChild(option);
   }
   originalRender(queue);
   if(pluginFirst){
    const counts=queue?.counts||{};
    const stats=document.getElementById('queueCompactStats');
    if(stats)stats.innerHTML=`<span class=queue-stat><b>${fmt(counts.pending||0)}</b> pending</span><span class=queue-stat><b>${fmt(counts.unscannedPluginsPending||0)}</b> first plugin coverage</span><span class=queue-stat><b>${fmt(counts.unscannedRetryPlugins||0)}</b> retry plugins</span><span class=queue-stat><b>${fmt(counts.unscannedRetryVariants||0)}</b> retry variants</span><span class=queue-stat><b>${fmt(counts.coveredRefresh||0)}</b> secondary / revisit</span>${queue?.baselineSecurityRebuild?'<span class=queue-stat><b>BASELINE</b> rebuild</span>':''}`;
   }
  };
 }
 const originalOverview=window.toniOverview;
 if(typeof originalOverview==='function'){
  window.toniOverview=function(){
   const counts=currentSummary?.counts||{},queue=currentSummary?.queueSummary||{};
   if(String(queue.selectionPolicy||'')!=='plugin-coverage-first-v2')return originalOverview();
   toniSay(`${fmt(counts.variants)} variants currently have published results. ${fmt(queue.unscannedPluginsPending||0)} plugins still need first plugin coverage across ${fmt(queue.unscannedVariantsPending||0)} uncovered variant(s); ${fmt(queue.unscannedRetryPlugins||0)} of those plugins have retry candidates. ${fmt(counts.reviewVariants)} current variants are high/critical review candidates.`);
  };
 }
 const originalQueue=window.toniQueue;
 if(typeof originalQueue==='function'){
  window.toniQueue=function(){
   const counts=currentSummary?.counts||{},queue=currentSummary?.queueSummary||{},batch=currentSummary?.lastBatch||{};
   if(String(queue.selectionPolicy||'')!=='plugin-coverage-first-v2')return originalQueue();
   toniSay(`Plugin-first queue: ${fmt(queue.unscannedPluginsPending||0)} uncovered plugins need representative coverage; ${fmt(queue.unscannedRetryPlugins||0)} plugin(s) have retry candidates across ${fmt(queue.unscannedRetryVariants||0)} retry variant(s). Secondary variants and refresh/source work follow. Current queue: ${fmt(counts.queuePending)} pending, ${fmt(counts.queueRetry)} retry. Last batch selected ${fmt(batch.selectedCount||0)} work items${batch.scanElapsedSeconds?` in ${Number(batch.scanElapsedSeconds).toFixed(1)} seconds`:''}.`);
  };
 }
})();
</script>
'''


def install() -> None:
    """Install the queue-v2 presentation shim after ``developer_view`` is loaded.

    DeltaScope historically kept the queue UI inside the monolithic Developer View HTML.
    Existing presentation extensions patch that HTML at launcher startup; keep this pass
    equally bounded instead of duplicating queue endpoints or moving queue authority.
    """
    global _INSTALLED
    if _INSTALLED:
        return
    import developer_view

    marker = "</body></html>"
    if "deltascope-plugin-first-queue-ui" not in developer_view.HTML and marker in developer_view.HTML:
        developer_view.HTML = developer_view.HTML.replace(marker, _QUEUE_UI_SCRIPT + marker, 1)
    _INSTALLED = True
