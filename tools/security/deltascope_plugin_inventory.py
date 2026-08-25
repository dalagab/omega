#!/usr/bin/env python3
"""Read-only logical-plugin projection for DeltaScope's My Plugin picker.

SigmaScope security evidence is variant-oriented by design: repository/source/build variants
must remain separately inspectable.  The developer-facing plugin picker is different.  It
projects one row per Omega catalog logical plugin and carries the covered variant identities
beneath that row.  Catalog plugin_id is the authoritative grouping boundary when available;
assembly/version text is context only and is never used to merge different plugin IDs.
"""
from __future__ import annotations

import re
from typing import Any, Iterable, Mapping

SEVERITY_RANK = {
    "none": 0,
    "informational": 1,
    "low": 1,
    "caution": 2,
    "moderate": 2,
    "medium": 2,
    "high": 3,
    "critical": 4,
    "unknown": -1,
}

DEFAULT_DALAMUD_API_LEVEL = 15
CURRENT_VISIBILITY_STATES = {"current", "unknown"}
LEGACY_VISIBILITY_STATES = {"outdated", "future", "testing-current", "retired", "hidden"}



def _int(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _severity(value: Any) -> str:
    text = str(value or "none").strip().casefold()
    return text if text in SEVERITY_RANK else "none"


def _version_key(value: Any) -> tuple[Any, ...]:
    """Natural, deterministic version ordering without claiming strict SemVer compliance."""
    text = str(value or "").strip().casefold()
    if not text:
        return ((-1, 0),)
    parts = re.findall(r"\d+|[a-z]+", text)
    key: list[tuple[int, Any]] = []
    for part in parts:
        if part.isdigit():
            key.append((1, int(part)))
        else:
            # A lexical qualifier sorts below a following numeric release component.
            key.append((0, part))
    return tuple(key) or ((0, text),)


def _group_key(row: Mapping[str, Any]) -> tuple[str, Any]:
    plugin_id = _int(row.get("plugin_id") or row.get("pluginId"))
    if plugin_id:
        return ("plugin-id", plugin_id)
    internal = str(row.get("internal_name") or row.get("internalName") or "").strip().casefold()
    if internal:
        return ("internal-name", internal)
    return ("variant-id", _int(row.get("variant_id") or row.get("variantId")))


def _representative(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Choose a useful covered variant without turning the choice into identity authority."""
    if not rows:
        return {}
    return max(
        rows,
        key=lambda row: (
            _version_key(row.get("assembly_version") or row.get("version")),
            str(row.get("scanned_at_utc") or row.get("scannedAtUtc") or ""),
            -_int(row.get("variant_id") or row.get("variantId")),
        ),
    )


def group_evidence_variants(rows: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Collapse evidence rows to one logical plugin while retaining variant metadata."""
    groups: dict[tuple[str, Any], list[dict[str, Any]]] = {}
    for raw in rows:
        if not isinstance(raw, Mapping):
            continue
        row = dict(raw)
        key = _group_key(row)
        groups.setdefault(key, []).append(row)

    result: list[dict[str, Any]] = []
    for grouped in groups.values():
        rep = dict(_representative(grouped))
        variant_ids = sorted({_int(row.get("variant_id") or row.get("variantId")) for row in grouped if _int(row.get("variant_id") or row.get("variantId"))})
        versions = sorted(
            {str(row.get("assembly_version") or row.get("version") or "").strip() for row in grouped if str(row.get("assembly_version") or row.get("version") or "").strip()},
            key=_version_key,
            reverse=True,
        )
        severity = max((_severity(row.get("highest_severity") or row.get("highestSeverity")) for row in grouped), key=lambda value: SEVERITY_RANK.get(value, -1), default="none")
        statuses = {str(row.get("scan_status") or row.get("scanStatus") or "unscanned").strip().casefold() or "unscanned" for row in grouped}
        covered = [row for row in grouped if str(row.get("scan_status") or row.get("scanStatus") or "unscanned").strip().casefold() not in {"", "unscanned"}]
        rep.update({
            "plugin_id": _int(rep.get("plugin_id") or rep.get("pluginId")),
            "variant_id": _int(rep.get("variant_id") or rep.get("variantId")),
            "evidence_variant_id": _int(rep.get("variant_id") or rep.get("variantId")),
            "variant_ids": variant_ids,
            "active_variant_ids": variant_ids,
            "variant_count": len(variant_ids),
            "active_variant_count": len(variant_ids),
            "evidence_variant_count": len(covered),
            "versions": versions,
            "version_count": len(versions),
            "highest_severity": severity,
            "scan_status": "complete" if statuses == {"complete"} else "partial" if covered else "unscanned",
            "catalog_only": False,
            "logical_plugin": True,
            "grouping_basis": "catalog-plugin-id" if _int(rep.get("plugin_id") or rep.get("pluginId")) else "internal-name-fallback",
        })
        result.append(rep)
    result.sort(key=lambda row: str(row.get("canonical_name") or row.get("name") or row.get("internal_name") or "").casefold())
    return result


def _variant_api_state(row: Mapping[str, Any], current_api_level: int) -> str:
    if _int(row.get("active")) != 1:
        return "retired"
    if _int(row.get("is_hide") or row.get("isHide")) == 1:
        return "hidden"
    stable = _int(row.get("dalamud_api_level") or row.get("dalamudApiLevel"))
    testing = _int(row.get("testing_dalamud_api_level") or row.get("testingDalamudApiLevel"))
    if current_api_level <= 0 or stable <= 0:
        return "unknown"
    if stable == current_api_level:
        return "current"
    if testing == current_api_level:
        return "testing-current"
    if stable < current_api_level:
        return "outdated"
    return "future"


def _logical_compatibility(
    plugin_active: bool,
    variants: Iterable[Mapping[str, Any]],
    current_api_level: int,
) -> dict[str, Any]:
    rows = [dict(row) for row in variants if isinstance(row, Mapping)]
    active_visible = [row for row in rows if _int(row.get("active")) == 1 and _int(row.get("is_hide") or row.get("isHide")) != 1]
    states: dict[int, str] = {}
    for row in rows:
        variant_id = _int(row.get("variant_id") or row.get("variantId"))
        if variant_id:
            states[variant_id] = _variant_api_state(row, current_api_level)
    ids = lambda state: sorted(variant_id for variant_id, value in states.items() if value == state)
    stable_levels = sorted({_int(row.get("dalamud_api_level") or row.get("dalamudApiLevel")) for row in active_visible if _int(row.get("dalamud_api_level") or row.get("dalamudApiLevel"))})
    testing_levels = sorted({_int(row.get("testing_dalamud_api_level") or row.get("testingDalamudApiLevel")) for row in active_visible if _int(row.get("testing_dalamud_api_level") or row.get("testingDalamudApiLevel"))})
    if not plugin_active:
        state = "retired"
    elif not rows:
        # The compact catalog index can be newer than the retained identity map. Do not
        # hide a current catalog plugin merely because compatibility metadata is absent.
        state = "unknown"
    elif not active_visible:
        state = "hidden" if ids("hidden") else "retired"
    elif ids("current"):
        state = "current"
    elif ids("unknown"):
        # Unknown API metadata must not be silently hidden as unsupported. It remains visible
        # in the default picker with an explicit unknown badge.
        state = "unknown"
    elif ids("testing-current"):
        state = "testing-current"
    elif ids("outdated") and not ids("future"):
        state = "outdated"
    elif ids("future") and not ids("outdated"):
        state = "future"
    else:
        state = "outdated"
    return {
        "compatibility_state": state,
        "compatibility_current_api_level": int(current_api_level or 0),
        "current_api_variant_ids": ids("current"),
        "testing_current_api_variant_ids": ids("testing-current"),
        "outdated_variant_ids": ids("outdated"),
        "future_variant_ids": ids("future"),
        "unknown_api_variant_ids": ids("unknown"),
        "hidden_variant_ids": ids("hidden"),
        "retired_variant_ids": ids("retired"),
        "stable_api_levels": stable_levels,
        "testing_api_levels": testing_levels,
        "compatibility_known": bool(stable_levels) and current_api_level > 0,
    }


def merge_catalog_plugins(
    catalog_plugins: Iterable[Mapping[str, Any]],
    evidence_rows: Iterable[Mapping[str, Any]],
    *,
    catalog_revision: str = "",
    identity_epoch: str = "",
    variant_rows: Iterable[Mapping[str, Any]] = (),
    current_api_level: int = DEFAULT_DALAMUD_API_LEVEL,
    include_legacy: bool = False,
) -> list[dict[str, Any]]:
    """Project catalog logical plugins and overlay current evidence plus compatibility.

    Catalog plugin_id remains identity authority.  The compact catalog index determines
    logical membership while the retained catalog identity map supplies API/lifecycle
    metadata.  Security Evidence-v2 is only a coverage overlay.  By default the developer
    picker keeps current-compatible and API-unknown logical plugins; old/unsupported rows
    are available through ``include_legacy`` and never disappear from the underlying model.
    """
    raw_evidence_by_plugin: dict[int, list[dict[str, Any]]] = {}
    for raw in evidence_rows:
        if not isinstance(raw, Mapping):
            continue
        row = dict(raw)
        plugin_id = _int(row.get("plugin_id") or row.get("pluginId"))
        if plugin_id:
            raw_evidence_by_plugin.setdefault(plugin_id, []).append(row)

    variants_by_plugin: dict[int, list[dict[str, Any]]] = {}
    for raw in variant_rows:
        if not isinstance(raw, Mapping):
            continue
        row = dict(raw)
        plugin_id = _int(row.get("plugin_id") or row.get("pluginId"))
        if plugin_id:
            variants_by_plugin.setdefault(plugin_id, []).append(row)

    result: list[dict[str, Any]] = []
    for raw in catalog_plugins:
        if not isinstance(raw, Mapping):
            continue
        plugin_id = _int(raw.get("pluginId") or raw.get("plugin_id"))
        if not plugin_id:
            continue
        plugin_active = raw.get("active") is not False
        identity_variants = variants_by_plugin.get(plugin_id, [])
        indexed_active_ids = sorted({_int(value) for value in (raw.get("activeVariantIds") or raw.get("active_variant_ids") or []) if _int(value)})
        identity_active_ids = sorted({
            _int(row.get("variant_id") or row.get("variantId")) for row in identity_variants
            if _int(row.get("variant_id") or row.get("variantId")) and _int(row.get("active")) == 1
        })
        active_ids = indexed_active_ids or identity_active_ids
        all_identity_ids = sorted({_int(row.get("variant_id") or row.get("variantId")) for row in identity_variants if _int(row.get("variant_id") or row.get("variantId"))})
        all_ids = all_identity_ids or active_ids
        active_set = set(active_ids)
        matching_evidence = [
            row for row in raw_evidence_by_plugin.get(plugin_id, [])
            if plugin_active and (not active_set or _int(row.get("variant_id") or row.get("variantId")) in active_set)
        ]
        grouped = group_evidence_variants(matching_evidence)
        overlay = dict(grouped[0]) if grouped else {}
        evidence_ids = sorted({_int(row.get("variant_id") or row.get("variantId")) for row in matching_evidence if _int(row.get("variant_id") or row.get("variantId"))})
        compatibility = _logical_compatibility(plugin_active, identity_variants, int(current_api_level or 0))
        state = str(compatibility.get("compatibility_state") or "unknown")
        if not include_legacy and state not in CURRENT_VISIBILITY_STATES:
            continue
        current_ids = list(compatibility.get("current_api_variant_ids") or [])
        evidence_current_ids = [variant_id for variant_id in evidence_ids if variant_id in set(current_ids)]
        evidence_variant_id = evidence_current_ids[0] if evidence_current_ids else _int(overlay.get("evidence_variant_id"))
        representative_variant_id = (
            (evidence_current_ids[0] if evidence_current_ids else current_ids[0])
            if current_ids else
            (evidence_variant_id or (active_ids[0] if active_ids else (all_ids[0] if all_ids else 0)))
        )
        name = str(raw.get("name") or overlay.get("canonical_name") or overlay.get("name") or raw.get("internalName") or "")
        internal = str(raw.get("internalName") or overlay.get("internal_name") or "")
        covered_count = len(evidence_ids)
        row = {
            **overlay,
            **compatibility,
            "plugin_id": plugin_id,
            "catalog_plugin_id": plugin_id,
            "internal_name": internal,
            "canonical_name": name,
            "name": name,
            "variant_id": representative_variant_id,
            "evidence_variant_id": evidence_variant_id,
            "variant_ids": active_ids if plugin_active else all_ids,
            "all_variant_ids": all_ids,
            "active_variant_ids": active_ids,
            "evidence_variant_ids": evidence_ids,
            "variant_count": _int(raw.get("variantCount")) or len(all_ids),
            "active_variant_count": _int(raw.get("activeVariantCount")) or len(active_ids),
            "evidence_variant_count": covered_count,
            "catalog_only": evidence_variant_id <= 0,
            "catalog_active": bool(plugin_active),
            "logical_plugin": True,
            "grouping_basis": "catalog-plugin-id",
            "catalog_revision": str(catalog_revision or ""),
            "catalog_identity_epoch": str(identity_epoch or ""),
            "catalog_path": str(raw.get("path") or ""),
            "catalog_sha256": str(raw.get("sha256") or ""),
        }
        if row["catalog_only"]:
            row.update({
                "highest_severity": "none",
                "scan_status": "unscanned",
                "assembly_version": "",
                "author": "",
                "versions": [],
                "version_count": 0,
            })
        elif covered_count < max(1, len(active_ids)):
            row["scan_status"] = "partial"
        result.append(row)
    result.sort(key=lambda row: (
        0 if str(row.get("compatibility_state")) == "current" else 1 if str(row.get("compatibility_state")) == "unknown" else 2,
        str(row.get("canonical_name") or row.get("internal_name") or "").casefold(),
    ))
    return result


def compatibility_counts(rows: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    counts = {state: 0 for state in ("current", "unknown", "testing-current", "outdated", "future", "retired", "hidden")}
    for row in rows:
        state = str(row.get("compatibility_state") or "unknown")
        counts[state] = counts.get(state, 0) + 1
    return counts


def filter_inventory(rows: Iterable[Mapping[str, Any]], q: str = "", limit: int = 2000, offset: int = 0) -> list[dict[str, Any]]:
    needle = str(q or "").strip().casefold()
    selected: list[dict[str, Any]] = []
    for raw in rows:
        row = dict(raw)
        haystack = " ".join([
            str(row.get("canonical_name") or ""),
            str(row.get("internal_name") or ""),
            str(row.get("author") or ""),
            " ".join(str(value) for value in row.get("versions") or []),
        ]).casefold()
        if needle and needle not in haystack:
            continue
        selected.append(row)
    start = max(0, int(offset or 0))
    size = min(max(1, int(limit or 2000)), 5000)
    return selected[start:start + size]
