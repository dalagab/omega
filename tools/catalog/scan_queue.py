#!/usr/bin/env python3
"""Deterministic Sigmascope queue seed and mutable worker-state helpers.

The daily catalog/Definitions boundary publishes an immutable queue *seed* derived
from that day's canonical catalog plus the last-known-good Security Evidence v2
snapshot. Continuous workers never rewrite that seed. Their bounded operational
progress (leases, retries and recent attempts) lives with Security Evidence v2.

Queue semantics intentionally distinguish scanner-rule changes from other
Definitions changes. OSV/reputation refreshes can update derived evidence without
re-downloading every plugin artifact, while a changed ``ruleSetRevision`` makes the
affected artifact/source variants due for a real Sigmascope examination.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
from typing import Any, Iterable

SCRIPT_DIR = Path(__file__).resolve().parent
SECURITY_DIR = SCRIPT_DIR.parent / "security"
for item in (SCRIPT_DIR, SECURITY_DIR):
    if str(item) not in sys.path:
        sys.path.insert(0, str(item))

from security_evidence_v2 import iter_variant_entries  # noqa: E402

SEED_SCHEMA = "omega.sigmascope.queue-seed.v1"
STATE_SCHEMA = "omega.sigmascope.queue-state.v1"
ATTEMPT_SCHEMA = "omega.sigmascope.queue-attempt.v1"
MAX_RECENT_ATTEMPTS = 16

REASON_PRIORITIES = {
    "manual": 1000,
    "new_variant": 900,
    "artifact_changed": 850,
    "source_review_due": 800,
    "rule_set_changed": 700,
    "failed_retry": 600,
    "periodic_revalidation": 100,
}

RETRY_DELAYS_MINUTES = (60, 240, 720, 1440, 2880, 5760)


def utc_now(now: dt.datetime | None = None) -> str:
    value = now or dt.datetime.now(dt.timezone.utc)
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_utc(value: str) -> dt.datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed.astimezone(dt.timezone.utc)
    except ValueError:
        return None


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return default


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    temp.replace(path)


def _report_provenance(current: dict[str, Any]) -> dict[str, Any]:
    raw = current.get("report_json")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except Exception:
            raw = {}
    report = raw if isinstance(raw, dict) else {}
    provenance = report.get("scanProvenance")
    return provenance if isinstance(provenance, dict) else {}


def _artifact_from_variant(variant: dict[str, Any]) -> tuple[str, str, str]:
    stable = str(variant.get("download_link_install") or "").strip()
    testing = str(variant.get("download_link_testing") or "").strip()
    if stable:
        return "stable", str(variant.get("assembly_version") or ""), stable
    if testing:
        return "testing", str(variant.get("testing_assembly_version") or variant.get("assembly_version") or ""), testing
    return "", "", ""


def _source_records(catalog_root: Path) -> dict[int, dict[str, Any]]:
    index = read_json(catalog_root / "sources" / "index.json", {}) or {}
    result: dict[int, dict[str, Any]] = {}
    for entry in index.get("sources") or []:
        if not isinstance(entry, dict):
            continue
        source_id = int(entry.get("sourceId") or 0)
        path = str(entry.get("path") or "")
        payload = read_json(catalog_root / path, {}) if path else {}
        source = payload.get("source") if isinstance(payload, dict) and isinstance(payload.get("source"), dict) else {}
        if source_id > 0:
            result[source_id] = source
    return result


def catalog_variants(catalog_root: Path) -> list[dict[str, Any]]:
    plugin_index = read_json(catalog_root / "plugins" / "index.json", {}) or {}
    sources = _source_records(catalog_root)
    result: list[dict[str, Any]] = []
    for entry in plugin_index.get("plugins") or []:
        if not isinstance(entry, dict) or not entry.get("active"):
            continue
        path = str(entry.get("path") or "")
        payload = read_json(catalog_root / path, {}) if path else {}
        plugin = payload.get("plugin") if isinstance(payload, dict) and isinstance(payload.get("plugin"), dict) else {}
        for grouped in payload.get("variants") or []:
            if not isinstance(grouped, dict):
                continue
            variant = grouped.get("variant") if isinstance(grouped.get("variant"), dict) else {}
            if int(variant.get("active") or 0) != 1:
                continue
            source_id = int(variant.get("source_id") or 0)
            source = sources.get(source_id, {})
            channel, version, artifact_url = _artifact_from_variant(variant)
            if not artifact_url:
                continue
            result.append({
                "variantId": int(variant.get("variant_id") or 0),
                "pluginId": int(variant.get("plugin_id") or plugin.get("plugin_id") or 0),
                "sourceId": source_id,
                "internalName": str(plugin.get("internal_name") or ""),
                "name": str(variant.get("name") or plugin.get("canonical_name") or plugin.get("internal_name") or ""),
                "sourceName": str(source.get("name") or ""),
                "assemblyVersion": version,
                "artifactChannel": channel,
                "artifactUrl": artifact_url,
                "repositoryUrl": str(variant.get("repo_url") or ""),
                "sourceRepositoryUrl": str(source.get("source_repo_url") or ""),
            })
    return sorted(result, key=lambda row: (str(row["internalName"]).casefold(), str(row["sourceName"]).casefold(), int(row["variantId"])))


def evidence_current(evidence_root: Path) -> dict[int, dict[str, Any]]:
    if not (evidence_root / "index.json").is_file():
        return {}
    result: dict[int, dict[str, Any]] = {}
    for _entry, payload in iter_variant_entries(evidence_root):
        if not isinstance(payload, dict):
            continue
        variant_id = int(payload.get("variantId") or 0)
        current = payload.get("current") if isinstance(payload.get("current"), dict) else {}
        if variant_id > 0:
            result[variant_id] = current
    return result


def due_reasons(
    variant: dict[str, Any],
    current: dict[str, Any] | None,
    *,
    rule_set_revision: str,
    rescan_after_hours: int,
    now: dt.datetime,
    manual: bool = False,
) -> list[str]:
    reasons: list[str] = []
    if manual:
        reasons.append("manual")
    if not current:
        reasons.append("new_variant")
        return reasons

    status = str(current.get("status") or "")
    if status != "complete":
        reasons.append("failed_retry")
    if (
        str(current.get("artifact_url") or "") != str(variant.get("artifactUrl") or "")
        or str(current.get("assembly_version") or "") != str(variant.get("assemblyVersion") or "")
    ):
        reasons.append("artifact_changed")

    known_source = bool(
        str(current.get("source_repository") or "").strip()
        or str(variant.get("repositoryUrl") or "").strip()
        or str(variant.get("sourceRepositoryUrl") or "").strip()
    )
    if int(current.get("source_available") or 0) == 0 and known_source:
        reasons.append("source_review_due")

    provenance = _report_provenance(current)
    previous_rule_set = str(provenance.get("ruleSetRevision") or "")
    if rule_set_revision and previous_rule_set != rule_set_revision:
        reasons.append("rule_set_changed")

    scanned = parse_utc(str(current.get("scanned_at_utc") or ""))
    if scanned is None or (now - scanned).total_seconds() >= max(0, rescan_after_hours) * 3600:
        reasons.append("periodic_revalidation")

    # Stable de-duplication while preserving priority semantics below.
    return list(dict.fromkeys(reasons))


def _target_fingerprint(variant: dict[str, Any], current: dict[str, Any] | None, rule_set_revision: str) -> str:
    semantic = {
        "variantId": int(variant.get("variantId") or 0),
        "assemblyVersion": str(variant.get("assemblyVersion") or ""),
        "artifactUrl": str(variant.get("artifactUrl") or ""),
        "repositoryUrl": str(variant.get("repositoryUrl") or ""),
        "sourceRepositoryUrl": str(variant.get("sourceRepositoryUrl") or ""),
        "ruleSetRevision": rule_set_revision,
        # A successful scan advances currentScanId. Including that identity means a
        # future periodic/source-review queue entry for the same artifact is a new
        # target, while repeated failures that retain last-known-good current state
        # keep the same target and therefore retain retry backoff.
        "currentScanId": int((current or {}).get("scan_id") or 0),
    }
    return f"scan-target-v1-{digest(semantic)[:20]}"


def _queue_item(
    variant: dict[str, Any],
    current: dict[str, Any] | None,
    reasons: list[str],
    *,
    catalog_revision: str,
    definitions_revision: str,
    rule_set_revision: str,
    generated_at: str,
) -> dict[str, Any]:
    ordered = sorted(reasons, key=lambda reason: (-REASON_PRIORITIES.get(reason, 0), reason))
    primary = ordered[0] if ordered else ""
    return {
        "queueKey": f"variant-{int(variant.get('variantId') or 0)}",
        "targetFingerprint": _target_fingerprint(variant, current, rule_set_revision),
        "variantId": int(variant.get("variantId") or 0),
        "pluginId": int(variant.get("pluginId") or 0),
        "sourceId": int(variant.get("sourceId") or 0),
        "internalName": str(variant.get("internalName") or ""),
        "name": str(variant.get("name") or ""),
        "sourceName": str(variant.get("sourceName") or ""),
        "assemblyVersion": str(variant.get("assemblyVersion") or ""),
        "artifactChannel": str(variant.get("artifactChannel") or ""),
        "artifactUrl": str(variant.get("artifactUrl") or ""),
        "catalogRevision": catalog_revision,
        "definitionsRevision": definitions_revision,
        "ruleSetRevision": rule_set_revision,
        "reasons": ordered,
        "primaryReason": primary,
        "priority": max((REASON_PRIORITIES.get(reason, 0) for reason in ordered), default=0),
        "currentScanId": int((current or {}).get("scan_id") or 0),
        "currentScannedAtUtc": str((current or {}).get("scanned_at_utc") or ""),
        "currentArtifactSha256": str((current or {}).get("artifact_sha256") or "").strip().lower(),
        "enqueuedAtUtc": generated_at,
    }


def build_seed(
    *,
    catalog_root: Path,
    definitions_root: Path,
    evidence_root: Path,
    output: Path,
    rescan_after_hours: int = 168,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    now_dt = now or dt.datetime.now(dt.timezone.utc)
    generated = utc_now(now_dt)
    catalog_index = read_json(catalog_root / "index.json", {}) or {}
    definitions_index = read_json(definitions_root / "index.json", {}) or {}
    catalog_revision = str(catalog_index.get("catalogRevision") or "")
    definitions_revision = str(definitions_index.get("definitionsRevision") or "")
    rule_set_revision = str(definitions_index.get("ruleSetRevision") or "")
    definitions_source_commit = str(definitions_index.get("sourceCommit") or "")
    current = evidence_current(evidence_root)
    items: list[dict[str, Any]] = []
    counts = {reason: 0 for reason in REASON_PRIORITIES}
    for variant in catalog_variants(catalog_root):
        reasons = due_reasons(
            variant,
            current.get(int(variant["variantId"])),
            rule_set_revision=rule_set_revision,
            rescan_after_hours=rescan_after_hours,
            now=now_dt,
        )
        if not reasons:
            continue
        item = _queue_item(
            variant,
            current.get(int(variant["variantId"])),
            reasons,
            catalog_revision=catalog_revision,
            definitions_revision=definitions_revision,
            rule_set_revision=rule_set_revision,
            generated_at=generated,
        )
        items.append(item)
        for reason in reasons:
            counts[reason] = counts.get(reason, 0) + 1
    items.sort(key=lambda item: (-int(item["priority"]), str(item["currentScannedAtUtc"]), str(item["internalName"]).casefold(), str(item["sourceName"]).casefold(), int(item["variantId"])))
    semantic = {
        "schema": SEED_SCHEMA,
        "catalogRevision": catalog_revision,
        "definitionsRevision": definitions_revision,
        "ruleSetRevision": rule_set_revision,
        "rescanAfterHours": int(rescan_after_hours),
        "items": [
            {
                key: item[key]
                for key in ("targetFingerprint", "variantId", "assemblyVersion", "artifactUrl", "ruleSetRevision", "reasons", "priority")
            }
            for item in items
        ],
    }
    seed = {
        "schema": SEED_SCHEMA,
        "queueSeedRevision": f"queue-seed-v1-{digest(semantic)[:16]}",
        "generatedAtUtc": generated,
        "catalogRevision": catalog_revision,
        "definitionsRevision": definitions_revision,
        "definitionsSourceCommit": definitions_source_commit,
        "ruleSetRevision": rule_set_revision,
        "rescanAfterHours": int(rescan_after_hours),
        "counts": {**counts, "queued": len(items)},
        "items": items,
    }
    write_json(output, seed)
    return seed


def load_state(path: Path | None) -> dict[str, Any]:
    if path is None or not path.is_file():
        return {"schema": STATE_SCHEMA, "items": {}, "recentCompleted": []}
    doc = read_json(path, {}) or {}
    if doc.get("schema") != STATE_SCHEMA or not isinstance(doc.get("items"), dict):
        return {"schema": STATE_SCHEMA, "items": {}, "recentCompleted": []}
    return doc


def _retry_at(now: dt.datetime, attempt_count: int) -> str:
    index = min(max(0, attempt_count - 1), len(RETRY_DELAYS_MINUTES) - 1)
    return utc_now(now + dt.timedelta(minutes=RETRY_DELAYS_MINUTES[index]))


def sync_state(seed: dict[str, Any], previous: dict[str, Any] | None, *, now: dt.datetime | None = None) -> dict[str, Any]:
    now_dt = now or dt.datetime.now(dt.timezone.utc)
    previous = previous if isinstance(previous, dict) else {}
    previous_items = previous.get("items") if isinstance(previous.get("items"), dict) else {}
    items: dict[str, Any] = {}
    for seeded in seed.get("items") or []:
        if not isinstance(seeded, dict):
            continue
        key = str(seeded.get("queueKey") or "")
        if not key:
            continue
        old = previous_items.get(key) if isinstance(previous_items.get(key), dict) else {}
        same_target = str(old.get("targetFingerprint") or "") == str(seeded.get("targetFingerprint") or "")
        state = {
            **seeded,
            "state": "pending",
            "attemptCount": int(old.get("attemptCount") or 0) if same_target else 0,
            "nextEligibleAtUtc": str(old.get("nextEligibleAtUtc") or "") if same_target else "",
            "lastAttemptStatus": str(old.get("lastAttemptStatus") or "") if same_target else "",
            "lastError": str(old.get("lastError") or "")[:4096] if same_target else "",
            "recentAttempts": list(old.get("recentAttempts") or [])[-MAX_RECENT_ATTEMPTS:] if same_target else [],
        }
        if same_target and str(old.get("state") or "") == "complete":
            state["state"] = "complete"
        elif same_target and state["nextEligibleAtUtc"]:
            next_at = parse_utc(state["nextEligibleAtUtc"])
            if next_at is not None and now_dt < next_at:
                state["state"] = "retry_wait"
        items[key] = state
    same_seed = str(previous.get("queueSeedRevision") or "") == str(seed.get("queueSeedRevision") or "")
    return {
        "schema": STATE_SCHEMA,
        "queueSeedRevision": str(seed.get("queueSeedRevision") or ""),
        "catalogRevision": str(seed.get("catalogRevision") or ""),
        "definitionsRevision": str(seed.get("definitionsRevision") or ""),
        "ruleSetRevision": str(seed.get("ruleSetRevision") or ""),
        "updatedAtUtc": str(previous.get("updatedAtUtc") or "") if same_seed else utc_now(now_dt),
        "items": items,
        "recentCompleted": list(previous.get("recentCompleted") or [])[-64:],
    }


def add_manual_items_from_database(
    state: dict[str, Any],
    db: sqlite3.Connection,
    internal_names: Iterable[str],
    *,
    now: dt.datetime | None = None,
) -> None:
    names = {str(name or "").strip().casefold() for name in internal_names if str(name or "").strip()}
    if not names:
        return
    now_dt = now or dt.datetime.now(dt.timezone.utc)
    columns = {str(row[1]).casefold() for row in db.execute("PRAGMA table_info(plugin_variants)")}
    update_projection = "v.download_link_update" if "download_link_update" in columns else "'' AS download_link_update"
    rows = db.execute(f"""
        SELECT v.variant_id,v.plugin_id,v.source_id,p.internal_name,v.name,v.assembly_version,v.testing_assembly_version,
               v.download_link_install,{update_projection},v.download_link_testing,v.repo_url,
               s.name AS source_name,s.source_repo_url,sc.*
          FROM plugin_variants v
          JOIN plugins p ON p.plugin_id=v.plugin_id
          JOIN sources s ON s.source_id=v.source_id
          LEFT JOIN plugin_security_current sc ON sc.variant_id=v.variant_id
         WHERE v.active=1 AND p.active=1
         ORDER BY p.internal_name COLLATE NOCASE,s.name COLLATE NOCASE,v.variant_id
    """).fetchall()
    for row in rows:
        if str(row["internal_name"] or "").casefold() not in names:
            continue
        stable = str(row["download_link_install"] or "").strip()
        testing = str(row["download_link_testing"] or "").strip()
        if not stable and not testing:
            continue
        variant = {
            "variantId": int(row["variant_id"]),
            "pluginId": int(row["plugin_id"]),
            "sourceId": int(row["source_id"]),
            "internalName": str(row["internal_name"] or ""),
            "name": str(row["name"] or ""),
            "sourceName": str(row["source_name"] or ""),
            "assemblyVersion": str(row["assembly_version"] or "") if stable else str(row["testing_assembly_version"] or row["assembly_version"] or ""),
            "artifactChannel": "stable" if stable else "testing",
            "artifactUrl": stable or testing,
            "repositoryUrl": str(row["repo_url"] or ""),
            "sourceRepositoryUrl": str(row["source_repo_url"] or ""),
        }
        current = dict(row) if row["scan_id"] is not None else None
        reasons = due_reasons(variant, current, rule_set_revision=str(state.get("ruleSetRevision") or ""), rescan_after_hours=0, now=now_dt, manual=True)
        item = _queue_item(
            variant,
            current,
            reasons,
            catalog_revision=str(state.get("catalogRevision") or ""),
            definitions_revision=str(state.get("definitionsRevision") or ""),
            rule_set_revision=str(state.get("ruleSetRevision") or ""),
            generated_at=utc_now(now_dt),
        )
        old = (state.get("items") or {}).get(item["queueKey"])
        if isinstance(old, dict) and str(old.get("targetFingerprint") or "") == item["targetFingerprint"]:
            item["attemptCount"] = int(old.get("attemptCount") or 0)
            item["recentAttempts"] = list(old.get("recentAttempts") or [])[-MAX_RECENT_ATTEMPTS:]
        else:
            item["attemptCount"] = 0
            item["recentAttempts"] = []
        item["state"] = "pending"
        item["nextEligibleAtUtc"] = ""
        item["lastAttemptStatus"] = ""
        item["lastError"] = ""
        state.setdefault("items", {})[item["queueKey"]] = item


def lease_next(state: dict[str, Any], *, now: dt.datetime | None = None, lease_minutes: int = 70) -> dict[str, Any] | None:
    now_dt = now or dt.datetime.now(dt.timezone.utc)
    eligible: list[dict[str, Any]] = []
    for item in (state.get("items") or {}).values():
        if not isinstance(item, dict) or str(item.get("state") or "") == "complete":
            continue
        next_at = parse_utc(str(item.get("nextEligibleAtUtc") or ""))
        if next_at is not None and now_dt < next_at:
            item["state"] = "retry_wait"
            continue
        lease_expires = parse_utc(str(item.get("leaseExpiresAtUtc") or ""))
        if str(item.get("state") or "") == "leased" and lease_expires is not None and now_dt < lease_expires:
            continue
        eligible.append(item)
    if not eligible:
        return None
    eligible.sort(key=lambda item: (-int(item.get("priority") or 0), str(item.get("currentScannedAtUtc") or ""), str(item.get("internalName") or "").casefold(), str(item.get("sourceName") or "").casefold(), int(item.get("variantId") or 0)))
    item = eligible[0]
    attempt_count = int(item.get("attemptCount") or 0) + 1
    attempt_id = f"attempt-v1-{digest([item.get('targetFingerprint'), attempt_count, utc_now(now_dt)])[:16]}"
    attempt = {
        "schema": ATTEMPT_SCHEMA,
        "attemptId": attempt_id,
        "attemptNumber": attempt_count,
        "leasedAtUtc": utc_now(now_dt),
        "status": "leased",
    }
    attempts = list(item.get("recentAttempts") or [])
    attempts.append(attempt)
    item["recentAttempts"] = attempts[-MAX_RECENT_ATTEMPTS:]
    item["attemptCount"] = attempt_count
    item["state"] = "leased"
    item["leaseId"] = attempt_id
    item["leaseExpiresAtUtc"] = utc_now(now_dt + dt.timedelta(minutes=max(1, lease_minutes)))
    item["nextEligibleAtUtc"] = ""
    state["updatedAtUtc"] = utc_now(now_dt)
    return dict(item)


def finish_lease(
    state: dict[str, Any],
    leased: dict[str, Any] | None,
    *,
    status: str,
    error: str = "",
    artifact_sha256: str = "",
    scan_id: int = 0,
    now: dt.datetime | None = None,
) -> None:
    if not leased:
        return
    now_dt = now or dt.datetime.now(dt.timezone.utc)
    key = str(leased.get("queueKey") or "")
    item = (state.get("items") or {}).get(key)
    if not isinstance(item, dict):
        return
    attempt_id = str(item.get("leaseId") or "")
    attempts = list(item.get("recentAttempts") or [])
    for attempt in reversed(attempts):
        if isinstance(attempt, dict) and str(attempt.get("attemptId") or "") == attempt_id:
            attempt["status"] = status
            attempt["completedAtUtc"] = utc_now(now_dt)
            attempt["error"] = str(error or "")[:4096]
            attempt["artifactSha256"] = str(artifact_sha256 or "").strip().lower()
            attempt["scanId"] = int(scan_id or 0)
            break
    item["recentAttempts"] = attempts[-MAX_RECENT_ATTEMPTS:]
    item["lastAttemptStatus"] = status
    item["lastError"] = str(error or "")[:4096]
    item["leaseId"] = ""
    item["leaseExpiresAtUtc"] = ""
    if status == "complete":
        item["state"] = "complete"
        item["completedAtUtc"] = utc_now(now_dt)
        item["nextEligibleAtUtc"] = ""
        completed = list(state.get("recentCompleted") or [])
        completed.append({
            "variantId": int(item.get("variantId") or 0),
            "internalName": str(item.get("internalName") or ""),
            "targetFingerprint": str(item.get("targetFingerprint") or ""),
            "primaryReason": str(item.get("primaryReason") or ""),
            "completedAtUtc": utc_now(now_dt),
            "attemptCount": int(item.get("attemptCount") or 0),
        })
        state["recentCompleted"] = completed[-64:]
    else:
        item["state"] = "retry_wait"
        item["nextEligibleAtUtc"] = _retry_at(now_dt, int(item.get("attemptCount") or 1))
    state["updatedAtUtc"] = utc_now(now_dt)


def state_summary(state: dict[str, Any]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    due_by_reason: dict[str, int] = {}
    for item in (state.get("items") or {}).values():
        if not isinstance(item, dict):
            continue
        status = str(item.get("state") or "pending")
        counts[status] = counts.get(status, 0) + 1
        if status != "complete":
            reason = str(item.get("primaryReason") or "")
            due_by_reason[reason] = due_by_reason.get(reason, 0) + 1
    return {
        "schema": "omega.sigmascope.queue-summary.v1",
        "queueSeedRevision": str(state.get("queueSeedRevision") or ""),
        "catalogRevision": str(state.get("catalogRevision") or ""),
        "definitionsRevision": str(state.get("definitionsRevision") or ""),
        "ruleSetRevision": str(state.get("ruleSetRevision") or ""),
        "states": counts,
        "pendingByReason": due_by_reason,
        "total": sum(counts.values()),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build-seed")
    build.add_argument("--catalog-root", required=True, type=Path)
    build.add_argument("--definitions-root", required=True, type=Path)
    build.add_argument("--evidence-root", required=True, type=Path)
    build.add_argument("--output", required=True, type=Path)
    build.add_argument("--rescan-after-hours", type=int, default=168)
    args = parser.parse_args()
    if args.command == "build-seed":
        result = build_seed(
            catalog_root=args.catalog_root,
            definitions_root=args.definitions_root,
            evidence_root=args.evidence_root,
            output=args.output,
            rescan_after_hours=args.rescan_after_hours,
        )
        print(json.dumps({"queueSeedRevision": result["queueSeedRevision"], "queued": result["counts"]["queued"]}, indent=2))
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
