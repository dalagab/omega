"""Read-only Investigator case reference health and timeline projection for DeltaScope.

This module resolves local-only case pins against the *currently verified* evidence snapshot.
It never mutates case files, Security Evidence, Definitions, scanner queues or repository state.
Resolution is deliberately conservative: when an exact historical target cannot be proven,
the projection reports changed/unresolved rather than silently substituting current evidence.
"""
from __future__ import annotations

import datetime as dt
from typing import Any, Mapping

SCHEMA = "omega.deltascope.investigator-casework.v1"
MAX_ITEMS = 250
MAX_TIMELINE = 1000

ATTENTION_STATES = {"changed", "unresolved", "missing", "error"}


def _authority() -> dict[str, Any]:
    return {
        "readOnly": True,
        "localOnly": True,
        "mutationAuthority": "none",
        "securityAuthority": False,
        "findingAuthority": False,
        "policyInput": False,
        "productionWriteBack": False,
        "evidenceWriteBack": False,
        "definitionsWriteBack": False,
        "queueMutationAuthorized": False,
        "publicationWriteBack": False,
        "repositoryWriteBack": False,
    }


def _identity(detail: Mapping[str, Any] | None) -> dict[str, Any]:
    raw = dict((detail or {}).get("identity") or {})
    return {
        "variantId": int(raw.get("variant_id") or raw.get("variantId") or 0),
        "scanId": int(raw.get("scan_id") or raw.get("scanId") or 0),
        "version": str(raw.get("assembly_version") or raw.get("version") or ""),
        "artifactSha256": str(raw.get("artifact_sha256") or raw.get("artifactSha256") or ""),
        "pluginName": str(raw.get("canonical_name") or raw.get("name") or raw.get("internal_name") or ""),
        "internalName": str(raw.get("internal_name") or raw.get("internalName") or ""),
        "scannedAtUtc": str(raw.get("scanned_at_utc") or raw.get("scannedAtUtc") or ""),
    }


def _same_exact_reference(ref: Mapping[str, Any], identity: Mapping[str, Any]) -> bool:
    pinned_scan = int(ref.get("scanId") or 0)
    current_scan = int(identity.get("scanId") or 0)
    pinned_hash = str(ref.get("artifactSha256") or "")
    current_hash = str(identity.get("artifactSha256") or "")
    if pinned_scan and current_scan:
        return pinned_scan == current_scan
    if pinned_hash and current_hash:
        return pinned_hash == current_hash
    pinned_version = str(ref.get("version") or "")
    current_version = str(identity.get("version") or "")
    return bool(pinned_version and current_version and pinned_version == current_version)


def _snapshot_match(ref: Mapping[str, Any], snapshots: list[dict[str, Any]]) -> dict[str, Any] | None:
    scan_id = int(ref.get("scanId") or 0)
    artifact = str(ref.get("artifactSha256") or "")
    path = str(ref.get("snapshotPath") or "")
    if scan_id:
        for row in snapshots:
            if int(row.get("scanId") or row.get("scan_id") or 0) == scan_id:
                return row
    if artifact:
        for row in snapshots:
            if str(row.get("artifactSha256") or row.get("artifact_sha256") or "") == artifact:
                return row
    if path:
        for row in snapshots:
            if str(row.get("variantPath") or row.get("snapshotPath") or "") == path:
                return row
    return None


def _finding_key(row: Mapping[str, Any]) -> tuple[str, str, str]:
    return (
        str(row.get("findingId") or row.get("finding_id") or ""),
        str(row.get("ruleId") or row.get("rule_id") or ""),
        str(row.get("title") or ""),
    )


def _finding_present(ref: Mapping[str, Any], detail: Mapping[str, Any]) -> bool:
    target = (
        str(ref.get("findingId") or ""),
        str(ref.get("ruleId") or ""),
        str(ref.get("title") or ""),
    )
    rows = list((detail.get("researcher") or {}).get("findings") or detail.get("findings") or [])
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        candidate = _finding_key(row)
        if target[0] and candidate[0] == target[0]:
            return True
        if target[1] and candidate[1] == target[1] and (not target[2] or candidate[2] == target[2]):
            return True
    return False


def _pivot_present(inspector: Any, ref: Mapping[str, Any]) -> bool | None:
    if not hasattr(inspector, "workbench_relationship_index"):
        return None
    try:
        index = inspector.workbench_relationship_index() or {}
    except Exception:
        return None
    kind = str(ref.get("pivotKind") or "")
    key = str(ref.get("pivotKey") or "")
    if not kind or not key:
        return None
    collection = {"endpoint": "endpoints", "component": "components", "advisory": "advisories"}.get(kind)
    candidates = index.get(collection) if isinstance(index, Mapping) and collection else None
    if not isinstance(candidates, list):
        return None
    for row in candidates:
        if not isinstance(row, Mapping):
            continue
        if str(row.get("key") or row.get("id") or row.get("advisoryId") or "") == key:
            return True
    return False


def _resolve_item(item: Mapping[str, Any], inspector: Any, detail_cache: dict[int, Any], snapshot_cache: dict[int, list[dict[str, Any]]]) -> dict[str, Any]:
    ref = dict(item.get("reference") or {})
    kind = str(item.get("kind") or "bookmark")
    result: dict[str, Any] = {
        "itemId": str(item.get("itemId") or ""),
        "kind": kind,
        "label": str(item.get("label") or "Pinned item"),
        "state": "unresolved",
        "stateLabel": "Unresolved",
        "detail": "DeltaScope could not prove the current state of this local reference.",
        "openVariantId": int(ref.get("variantId") or 0),
        "openSnapshotPath": "",
        "currentIdentity": {},
        **_authority(),
    }

    if kind == "pivot":
        present = _pivot_present(inspector, ref)
        if present is True:
            result.update(state="current", stateLabel="Current pivot", detail="This relationship key still exists in the current published relationship index.")
        elif present is False:
            result.update(state="changed", stateLabel="Pivot changed", detail="This saved relationship key is no longer present in the current published relationship index.")
        else:
            result.update(state="unresolved", stateLabel="Pivot unresolved", detail="The current evidence transport cannot prove whether this relationship key still exists.")
        return result

    variant_id = int(ref.get("variantId") or 0)
    if not variant_id:
        result.update(state="missing", stateLabel="Reference incomplete", detail="The pin has no variant identity to resolve.")
        return result

    try:
        if variant_id not in detail_cache:
            try:
                detail_cache[variant_id] = inspector.plugin_detail(variant_id)
            except Exception as exc:
                detail_cache[variant_id] = exc
        cached_detail = detail_cache[variant_id]
        if isinstance(cached_detail, Exception):
            raise cached_detail
        detail = cached_detail
        current = _identity(detail)
        result["currentIdentity"] = current
    except Exception as exc:
        result.update(state="missing", stateLabel="Variant unavailable", detail=f"Variant {variant_id} is not available in the current verified evidence view: {exc}")
        return result

    exact_current = _same_exact_reference(ref, current)
    snapshots: list[dict[str, Any]] = []
    if hasattr(inspector, "variant_snapshots"):
        if variant_id not in snapshot_cache:
            try:
                snapshot_cache[variant_id] = [dict(x) for x in (inspector.variant_snapshots(variant_id) or []) if isinstance(x, Mapping)]
            except Exception:
                snapshot_cache[variant_id] = []
        snapshots = snapshot_cache[variant_id]
    exact_snapshot = _snapshot_match(ref, snapshots)
    if exact_snapshot:
        result["openSnapshotPath"] = str(exact_snapshot.get("variantPath") or exact_snapshot.get("snapshotPath") or "")

    if kind == "evidence-snapshot":
        if exact_current:
            result.update(state="current", stateLabel="Current evidence", detail="The exact pinned scan/artifact is still the current published evidence for this variant.")
        elif exact_snapshot:
            result.update(state="retained", stateLabel="Retained snapshot", detail="The exact pinned scan/artifact is no longer current but is still retained and resolvable.")
        else:
            result.update(state="changed", stateLabel="Snapshot no longer exact", detail="The variant has current evidence, but DeltaScope cannot resolve the exact pinned scan/artifact in retained history.")
        return result

    if kind == "finding":
        present_now = _finding_present(ref, detail)
        if exact_current and present_now:
            result.update(state="current", stateLabel="Current finding", detail="This finding still resolves on the exact pinned current scan.")
        elif present_now:
            result.update(state="reobserved", stateLabel="Re-observed", detail="The pinned scan changed, but a matching finding is present on the current scan.")
        elif exact_snapshot:
            result.update(state="retained", stateLabel="Historical finding context", detail="The exact pinned scan is retained, while the finding is not present on the current scan.")
        else:
            result.update(state="changed", stateLabel="Finding changed", detail="The variant still exists, but this finding does not resolve on current evidence and the exact old scan is not retained.")
        return result

    if kind == "observation":
        if exact_current:
            result.update(state="current", stateLabel="Current observation context", detail="The observation pin still points at the exact current scan. Row identity remains a local reference, not authoritative evidence.")
        elif exact_snapshot:
            result.update(state="retained", stateLabel="Retained observation context", detail="The exact scan containing this observation context is retained and resolvable.")
        else:
            result.update(state="changed", stateLabel="Observation context changed", detail="The variant scan changed and the exact pinned scan is not retained; DeltaScope will not substitute a current row silently.")
        return result

    # bookmark / plugin reference
    if exact_current:
        result.update(state="current", stateLabel="Current plugin", detail="This bookmark still resolves to the same current scan/artifact identity.")
    else:
        result.update(state="changed", stateLabel="Plugin evidence changed", detail="The plugin/variant still exists, but its current scan/artifact identity differs from the pinned reference.")
    return result


def _timeline(case: Mapping[str, Any], resolved: list[dict[str, Any]]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    case_id = str(case.get("caseId") or "")
    created = str(case.get("createdAtUtc") or "")
    if created:
        events.append({"atUtc": created, "kind": "case-created", "title": "Case created", "detail": str(case.get("title") or "Investigation"), "caseId": case_id})
    resolved_by_id = {str(x.get("itemId") or ""): x for x in resolved}
    for item in list(case.get("items") or [])[:MAX_ITEMS]:
        if not isinstance(item, Mapping):
            continue
        ref = dict(item.get("reference") or {})
        scanned = str(ref.get("scannedAtUtc") or "")
        if scanned:
            events.append({"atUtc": scanned, "kind": "evidence-observed", "title": str(item.get("label") or "Pinned evidence"), "detail": f"Evidence context · {item.get('kind') or 'reference'}", "itemId": str(item.get("itemId") or "")})
        at = str(item.get("createdAtUtc") or "")
        if at:
            health = resolved_by_id.get(str(item.get("itemId") or ""), {})
            events.append({"atUtc": at, "kind": "pin", "title": str(item.get("label") or "Pinned item"), "detail": str(health.get("stateLabel") or item.get("kind") or "Pinned reference"), "itemId": str(item.get("itemId") or "")})
    for note in list(case.get("notes") or []):
        if not isinstance(note, Mapping):
            continue
        at = str(note.get("createdAtUtc") or "")
        if at:
            text = str(note.get("text") or "")
            events.append({"atUtc": at, "kind": "note", "title": "Investigator note", "detail": text[:400], "noteId": str(note.get("noteId") or "")})
    events.sort(key=lambda row: (str(row.get("atUtc") or ""), str(row.get("kind") or "")), reverse=True)
    return events[:MAX_TIMELINE]


def project_casework(case: Mapping[str, Any], inspector: Any) -> dict[str, Any]:
    all_items = [x for x in list(case.get("items") or []) if isinstance(x, Mapping)]
    items = all_items[:MAX_ITEMS]
    resolved: list[dict[str, Any]] = []
    detail_cache: dict[int, Any] = {}
    snapshot_cache: dict[int, list[dict[str, Any]]] = {}
    for item in items:
        try:
            resolved.append(_resolve_item(item, inspector, detail_cache, snapshot_cache))
        except Exception as exc:  # keep a bad reference from breaking the whole local notebook
            resolved.append({
                "itemId": str(item.get("itemId") or ""), "kind": str(item.get("kind") or ""),
                "label": str(item.get("label") or "Pinned item"), "state": "error", "stateLabel": "Resolution error",
                "detail": str(exc), "openVariantId": int((item.get("reference") or {}).get("variantId") or 0),
                "openSnapshotPath": "", "currentIdentity": {}, **_authority(),
            })
    counts: dict[str, int] = {}
    for row in resolved:
        key = str(row.get("state") or "unresolved")
        counts[key] = counts.get(key, 0) + 1
    attention = sum(value for key, value in counts.items() if key in ATTENTION_STATES)
    return {
        "schema": SCHEMA,
        "caseId": str(case.get("caseId") or ""),
        "caseRevision": int(case.get("revision") or 0),
        "resolvedAtUtc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "summary": {
            "itemCount": len(resolved),
            "totalItemCount": len(all_items),
            "resolutionTruncated": len(all_items) > len(items),
            "current": counts.get("current", 0),
            "retained": counts.get("retained", 0),
            "reobserved": counts.get("reobserved", 0),
            "changed": counts.get("changed", 0),
            "unresolved": counts.get("unresolved", 0),
            "missing": counts.get("missing", 0),
            "errors": counts.get("error", 0),
            "attention": attention,
        },
        "items": resolved,
        "timeline": _timeline(case, resolved),
        **_authority(),
    }
