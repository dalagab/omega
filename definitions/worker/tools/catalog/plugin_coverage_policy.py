#!/usr/bin/env python3
"""Deterministic plugin-first queue scheduling helpers for SigmaScope.

This module influences work ordering only. Source provenance classes are scheduling
metadata, not trust, safety, severity, or publication authority.
"""
from __future__ import annotations

from typing import Any, Iterable


SELECTION_POLICY = "plugin-coverage-first-v2"
SOURCE_PRIORITY_RANK = {
    "official": 0,
    "curated": 1,
    "discovered": 2,
}


def source_priority_class(source: dict[str, Any] | None) -> str:
    source = source if isinstance(source, dict) else {}
    if int(source.get("is_official") or 0) == 1:
        return "official"
    if str(source.get("curated_id") or "").strip():
        return "curated"
    if str(source.get("discovered_by") or "").strip().casefold() == "curated-sources.json":
        return "curated"
    return "discovered"


def current_has_artifact_coverage(current: dict[str, Any] | None) -> bool:
    if not isinstance(current, dict) or str(current.get("status") or "") != "complete":
        return False
    return bool(
        int(current.get("scan_id") or 0) > 0
        or str(current.get("scanned_at_utc") or "").strip()
        or str(current.get("artifact_sha256") or "").strip()
    )


def artifact_is_uncovered(item: dict[str, Any]) -> bool:
    return (
        str(item.get("workType") or "") == "artifact"
        and int(item.get("currentScanId") or 0) <= 0
        and not str(item.get("currentScannedAtUtc") or "").strip()
    )


def covered_plugin_ids(items: Iterable[dict[str, Any]]) -> set[int]:
    covered: set[int] = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        plugin_id = int(item.get("pluginId") or 0)
        if plugin_id <= 0:
            continue
        if bool(item.get("pluginHasCurrentScan")):
            covered.add(plugin_id)
            continue
        if int(item.get("currentScanId") or 0) > 0 or str(item.get("currentScannedAtUtc") or "").strip():
            covered.add(plugin_id)
            continue
        if str(item.get("workType") or "") == "artifact" and str(item.get("state") or "") == "complete":
            covered.add(plugin_id)
    return covered


def selection_lane(item: dict[str, Any], covered_plugins: set[int] | None = None) -> int:
    """Return the deterministic plugin-coverage lane.

    0 = first untouched artifact candidate for a plugin with no current coverage
    1 = retry/fallback artifact work while that plugin is still uncovered
    2 = secondary variants plus all already-covered refresh/follow-up work
    """
    if not artifact_is_uncovered(item):
        return 2
    plugin_id = int(item.get("pluginId") or 0)
    if plugin_id > 0 and plugin_id in (covered_plugins or set()):
        return 2
    if plugin_id > 0 and bool(item.get("pluginHasCurrentScan")):
        return 2
    return 0 if int(item.get("attemptCount") or 0) <= 0 else 1


def selection_sort_key(item: dict[str, Any], covered_plugins: set[int] | None = None) -> tuple[Any, ...]:
    lane = selection_lane(item, covered_plugins)
    source_class = str(item.get("sourcePriorityClass") or "discovered")
    source_rank = SOURCE_PRIORITY_RANK.get(source_class, SOURCE_PRIORITY_RANK["discovered"])
    channel = str(item.get("artifactChannel") or "").casefold()
    channel_rank = 0 if channel == "stable" else 1 if channel == "testing" else 2
    return (
        lane,
        source_rank if lane in (0, 1) else 3,
        channel_rank if lane in (0, 1) else 2,
        -int(item.get("priority") or 0),
        str(item.get("currentScannedAtUtc") or ""),
        str(item.get("internalName") or "").casefold(),
        str(item.get("sourceName") or "").casefold(),
        int(item.get("variantId") or 0),
        str(item.get("workType") or ""),
    )
