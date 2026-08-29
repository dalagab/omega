"""Read-only DeltaScope projection explaining SigmaScope queue causality.

This module deliberately mirrors the published ``coverage-first-v1`` ordering contract
without importing or mutating the production queue implementation.  DeltaScope may
explain a frozen queue state; it has no scheduling, scan, policy or publication authority.
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Mapping

SCHEMA = "omega.deltascope.scan-queue-causality.v1"
SELECTION_POLICY = "coverage-first-v1"
MAX_NEXT_ITEMS = 40
MAX_RECENT_ITEMS = 24

REASON_EXPLANATIONS: dict[str, tuple[str, str]] = {
    "manual": ("Manual recheck", "An operator/developer explicitly requested a fresh artifact check."),
    "baseline_scan": ("Identity baseline", "The catalog identity epoch changed, so the prior variant identity map cannot be reused as current coverage."),
    "new_variant": ("First coverage", "This active catalog variant has no published current artifact scan under its present variant identity."),
    "artifact_url_changed": ("Artifact URL changed", "The selected install artifact URL changed and artifact-backed observations must be refreshed."),
    "artifact_version_changed": ("Plugin version changed", "The selected artifact version changed and needs a new current artifact scan."),
    "artifact_analysis_changed": ("Artifact analysis changed", "SigmaScope's artifact-analysis revision changed; existing covered variants are queued for selective refresh."),
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


def _operational_action(primary: str, work_type: str) -> tuple[str, bool | None, str]:
    """Explain the operational work without turning a queue reason into a verdict."""
    if primary == "srl_observation_missing":
        return (
            "Targeted / deep evidence acquisition", True if work_type == "artifact" else None,
            "A rule replay cannot be satisfied from retained observations at the required producer revision, so additional bounded evidence acquisition is justified. The producer/work type determines whether that means reopening the plugin artifact.",
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
        "The published queue contains this work item, but DeltaScope does not classify it as an artifact scan or retained-evidence reprojection.",
    )


def _state(item: Mapping[str, Any]) -> str:
    return str(item.get("state") or "pending").strip().lower()


def _is_pending(item: Mapping[str, Any]) -> bool:
    return _state(item) != "complete"


def _lane(item: Mapping[str, Any]) -> int:
    """Mirror SigmaScope coverage-first-v1 lane semantics."""
    work_type = str(item.get("workType") or "")
    try:
        current_scan_id = int(item.get("currentScanId") or 0)
    except (TypeError, ValueError):
        current_scan_id = 0
    current_scanned_at = str(item.get("currentScannedAtUtc") or "").strip()
    uncovered_artifact = work_type == "artifact" and current_scan_id <= 0 and not current_scanned_at
    if not uncovered_artifact:
        return 2
    try:
        attempts = int(item.get("attemptCount") or 0)
    except (TypeError, ValueError):
        attempts = 0
    return 0 if attempts <= 0 else 1


def _sort_key(item: Mapping[str, Any]) -> tuple[Any, ...]:
    try:
        priority = int(item.get("priority") or 0)
    except (TypeError, ValueError):
        priority = 0
    try:
        variant_id = int(item.get("variantId") or 0)
    except (TypeError, ValueError):
        variant_id = 0
    return (
        _lane(item),
        -priority,
        str(item.get("currentScannedAtUtc") or ""),
        str(item.get("internalName") or "").casefold(),
        str(item.get("sourceName") or "").casefold(),
        variant_id,
        str(item.get("workType") or ""),
    )


def _item_projection(item: Mapping[str, Any], *, exact_order: bool) -> dict[str, Any]:
    lane = _lane(item) if exact_order else -1
    reasons = [str(value) for value in (item.get("reasons") or []) if str(value)]
    primary = str(item.get("primaryReason") or (reasons[0] if reasons else ""))
    work_type = str(item.get("workType") or "")
    action, requires_artifact_scan, action_explanation = _operational_action(primary, work_type)
    reason_details = []
    for reason in reasons or ([primary] if primary else []):
        label, explanation = REASON_EXPLANATIONS.get(reason, (reason.replace("_", " ").title(), "Published SigmaScope queue reason."))
        reason_details.append({"reason": reason, "label": label, "explanation": explanation})
    return {
        "queueKey": str(item.get("queueKey") or ""),
        "variantId": int(item.get("variantId") or 0),
        "pluginId": int(item.get("pluginId") or 0),
        "internalName": str(item.get("internalName") or item.get("name") or ""),
        "name": str(item.get("name") or item.get("internalName") or ""),
        "sourceName": str(item.get("sourceName") or ""),
        "assemblyVersion": str(item.get("assemblyVersion") or ""),
        "workType": work_type,
        "state": _state(item),
        "priority": int(item.get("priority") or 0),
        "attemptCount": int(item.get("attemptCount") or 0),
        "nextEligibleAtUtc": str(item.get("nextEligibleAtUtc") or ""),
        "currentScanId": int(item.get("currentScanId") or 0),
        "currentScannedAtUtc": str(item.get("currentScannedAtUtc") or ""),
        "primaryReason": primary,
        "reasons": reasons,
        "reasonDetails": reason_details,
        "operationalAction": action,
        "operationalExplanation": action_explanation,
        "requiresArtifactScan": requires_artifact_scan,
        "lane": lane,
        "laneId": {0: "first-coverage", 1: "first-coverage-retry", 2: "covered-refresh"}.get(lane, "unknown"),
        "laneLabel": {0: "First coverage", 1: "First-coverage retry", 2: "Covered refresh / follow-up"}.get(lane, "Published order only"),
    }


def project_scan_queue(queue_state: Mapping[str, Any] | None, *, current_variants: int = 0, next_limit: int | None = None) -> dict[str, Any]:
    queue = queue_state if isinstance(queue_state, Mapping) else {}
    raw_items = queue.get("items") if isinstance(queue.get("items"), Mapping) else {}
    items = [value for value in raw_items.values() if isinstance(value, Mapping)]
    pending = [item for item in items if _is_pending(item)]
    selection_policy = str(queue.get("selectionPolicy") or "")
    exact_order = selection_policy == SELECTION_POLICY
    ordered = sorted(pending, key=_sort_key) if exact_order else list(pending)

    lanes = Counter(_lane(item) for item in pending) if exact_order else Counter()
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
        label, explanation = REASON_EXPLANATIONS.get(reason, (reason.replace("_", " ").title(), "Published SigmaScope queue reason."))
        reason_rows.append({"reason": reason, "label": label, "count": count, "explanation": explanation})

    baseline = bool(queue.get("baselineSecurityRebuild"))
    first_coverage = int(lanes.get(0, 0)) if exact_order else 0
    first_retry = int(lanes.get(1, 0)) if exact_order else 0
    covered = int(lanes.get(2, 0)) if exact_order else 0
    new_variant = int(reasons.get("new_variant", 0))
    analysis_refresh = int(reasons.get("artifact_analysis_changed", 0))

    if baseline:
        headline = "Catalog identity baseline rebuild is active"
        explanation = (
            "The published queue says the catalog identity epoch changed. SigmaScope cannot treat the previous variant identity map as current coverage, "
            "so baseline artifact work is intentionally rebuilt. Under coverage-first ordering, equal-priority names are deterministically tie-broken by InternalName."
        )
        mode = "baseline-rebuild"
    elif exact_order and (first_coverage or first_retry):
        headline = "This is first-coverage work, not a scan reset"
        explanation = (
            f"SigmaScope currently has {first_coverage:,} untouched active variant(s) waiting for first artifact coverage"
            + (f" and {first_retry:,} uncovered retry variant(s)" if first_retry else "")
            + ". Coverage-first-v1 deliberately processes those before already-covered refresh/follow-up work. Within the same lane and priority, InternalName is a deterministic tie-breaker, so seeing A-name plugins again is expected and does not mean published Evidence was deleted."
        )
        mode = "first-coverage"
    elif exact_order and covered:
        headline = "Current coverage exists; refresh/follow-up work remains"
        explanation = (
            "There is no identity baseline reset and no uncovered first-coverage lane ahead of the queue. Remaining work revisits already-covered variants or source/advisory projections according to reason priority and oldest/current scan ordering."
        )
        mode = "covered-refresh"
    else:
        headline = "Queue ordering is read from the published snapshot"
        explanation = (
            "DeltaScope does not recognize this queue selection policy as coverage-first-v1, so it will not claim the exact next-item order. Published reasons and states remain visible without mutating the queue."
        )
        mode = "unknown-policy"

    notes: list[str] = []
    if new_variant:
        notes.append(f"{new_variant:,} pending item(s) carry new_variant: no matching published current artifact scan exists for that active variant identity.")
    if analysis_refresh:
        notes.append(f"{analysis_refresh:,} pending item(s) carry artifact_analysis_changed: already-known artifacts need selective refresh under the published artifact-analysis revision.")
    if not baseline:
        notes.append("baselineSecurityRebuild=false: the published queue does not describe a catalog identity reset.")

    projected_queue = [_item_projection(item, exact_order=exact_order) for item in ordered]
    for rank, row in enumerate(projected_queue, start=1):
        row["rank"] = rank if exact_order else 0
        row["isNext"] = bool(exact_order and rank == 1)
    if next_limit is None:
        preview_limit = min(MAX_NEXT_ITEMS, len(projected_queue))
    else:
        preview_limit = max(1, min(MAX_NEXT_ITEMS, int(next_limit or 1)))
    recent = [row for row in (queue.get("recentCompleted") or []) if isinstance(row, Mapping)][-MAX_RECENT_ITEMS:]
    recent.reverse()

    return {
        "schema": SCHEMA,
        "readOnly": True,
        "mutationAuthority": "none",
        "policyInput": False,
        "queueMutationAuthorized": False,
        "scanExecutionAuthorized": False,
        "publicationAuthorized": False,
        "selectionPolicy": selection_policy,
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
        },
        "lanes": [
            {"lane": 0, "id": "first-coverage", "label": "1 · First coverage", "count": first_coverage, "description": "Never-attempted artifact work with no published current scan. This lane runs first."},
            {"lane": 1, "id": "first-coverage-retry", "label": "2 · First-coverage retry", "count": first_retry, "description": "Artifact work that was attempted but the variant is still uncovered. This stays ahead of covered revisits."},
            {"lane": 2, "id": "covered-refresh", "label": "3 · Covered refresh / follow-up", "count": covered, "description": "Artifact re-analysis, source follow-up and advisory work for variants that already have current coverage."},
        ] if exact_order else [],
        "reasons": reason_rows,
        "queueItems": projected_queue,
        "nextItems": projected_queue[:preview_limit],
        "rulesetScanBoundary": {
            "rulesetChangeRequiresArtifactScan": False,
            "explanation": "A Definitions/ruleset revision change is an interpretation/reprojection event, not an artifact-scan reason by itself. Additional acquisition becomes queue-worthy only when retained evidence cannot satisfy the active rule contract (for example srl_observation_missing) or another artifact/source invalidation reason applies.",
        },
        "recentCompleted": [_item_projection(item, exact_order=False) for item in recent],
    }
